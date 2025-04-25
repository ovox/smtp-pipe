const { SMTPServer } = require("smtp-server");
const { simpleParser } = require("mailparser");
const fs = require("fs");
const path = require("path");
const { program } = require("commander");
const os = require("os");
const { Resend } = require("../resend-node/dist"); // Assuming resend-node is one level up
const net = require("net");
const tls = require('tls');
const crypto = require('crypto');
const { spawn } = require('child_process'); // Import spawn directly for clarity

// Add global error handlers to prevent crashes
process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error);
  // Log the error, but consider if you might want to restart the process
  // in some cases, depending on the error severity.
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
  // Log the error.
});

program
  .option(
    "-p, --pipe <program>",
    "Save the result in a random file and pass the filename to the shell program (optional)"
  )
  .option("-h, --host <host>", "SMTP host")
  .option("-P, --port <port>", "SMTP port", parseInt)
  .option("-c, --cer <cer>", "Path to certificate (optional)")
  .option("-k, --key <key>", "Path to key (optional)")
  .option("-ca, --ca <cer>", "Path to ca certificates (optional)")
  .option("-s, --server <server>", "SMTP server name (optional)")
  .option(
    "-fi, --insecure <insecure>",
    "Force run the server in insecure mode (optional)"
  )
  .option("-a, --cca <cca>", "Request client certificate true/false (optional)")
  .option("-aia, --aia <aia>", "Allow insecure auth (optional)")
  .option("-r --resend <resend>", "Resend via the resend api (optional)")
  .option(
    "-rk, --refresh-keys <hours>",
    "Refresh keys every X hours",
    parseInt
  );

program.parse(process.argv);
const options = program.opts();

const pipeProgram = options.pipe;
const cer = options.cer;
const key = options.key;
const ca = options.ca;
const cca = options.cca === "true";
const name = options.server ?? os.hostname();
const insecure = options.insecure === "true";
const aia = options.aia === "true";
const resendSend = options.resend === "true";
const refreshKeys = options.refreshKeys;

let enc = {};
function loadEncryptionConfig() {
  try {
    enc = {};
    if (cer && key && !insecure) {
      enc.secure = true;
      enc.key = fs.readFileSync(key); // Load key first in case cert needs it
      enc.cert = fs.readFileSync(cer);
      enc.tls = {
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        // secureProtocol: 'TLS_method', // Generally not needed unless specific protocols MUST be used
        // secureOptions: crypto.constants.SSL_OP_NO_SSLv2 | // Redundant with minVersion
        //               crypto.constants.SSL_OP_NO_SSLv3 |
        //               crypto.constants.SSL_OP_NO_TLSv1 |
        //               crypto.constants.SSL_OP_NO_TLSv1_1,
        rejectUnauthorized: false, // Be cautious with this in production
        ciphers: 'HIGH:!aNULL:!MD5:!RC4:!3DES:!DES', // Added !3DES:!DES for better security
      };
      if (cca) { // Request client cert only if TLS is active
        enc.requestCert = true;
      }
      if (ca) { // Load CA only if TLS is active
        enc.ca = fs.readFileSync(ca);
      }
      enc.allowInsecureAuth = aia; // Allow plain auth only if explicitly set (even with TLS)

    } else {
      // Not secure or forced insecure
      enc.secure = false;
      enc.allowInsecureAuth = true; // Allow plain auth if not secure
    }

    console.log(`Encryption config reloaded at ${new Date().toISOString()}`);
    console.log(`Current config: secure=${enc.secure}, allowInsecureAuth=${enc.allowInsecureAuth}, requestCert=${enc.requestCert}`);

  } catch (error) {
    console.error("Error loading encryption config:", error);
    // Fallback to default insecure config
    enc = { secure: false, allowInsecureAuth: true };
    console.warn("Falling back to insecure SMTP configuration.");
  }
}

loadEncryptionConfig();

console.log(
  `Running a ${
    enc.secure ? "secure" : "insecure"
  } SMTP server proxy target setup.`
);

function createServerInstance() {
  const serverInstance = new SMTPServer({
    ...enc, // Spread the current encryption config
    name: name,
    // Size limit (e.g., 50MB)
    size: 50 * 1024 * 1024,

    // Use onAuth for authentication logic
    onAuth(auth, session, callback) {
      console.log(`Auth attempt: User=${auth.username}, Method=${auth.method}`);
      // Implement your actual authentication logic here if needed
      // For now, we accept any credentials provided IF allowInsecureAuth is true
      // OR if the connection is already secured via STARTTLS/Implicit TLS
      if (session.secure || enc.allowInsecureAuth) {
          console.log(`Authentication successful for ${auth.username} (secure=${session.secure}, allowInsecure=${enc.allowInsecureAuth})`);
          // Pass the credentials to the session object for later use
          callback(null, {
            user: { user: auth.username, password: auth.password },
          });
      } else {
          console.warn(`Authentication failed for ${auth.username}: Insecure connection and insecure auth not allowed.`);
          callback(new Error('Authentication failed: Secure connection required or insecure auth not allowed'));
      }
    },

    // Use onMailFrom and onRcptTo for sender/recipient validation if needed
    onMailFrom(address, session, callback) {
      console.log(`MAIL FROM: ${address.address} (secure=${session.secure})`);
      // Add validation logic here if required
      callback(); // Accept the sender
    },

    onRcptTo(address, session, callback) {
      console.log(`RCPT TO: ${address.address} (secure=${session.secure})`);
      // Add validation logic here if required
      callback(); // Accept the recipient
    },

    onData(stream, session, callback) {
        console.log(`Receiving data from ${session.remoteAddress}...`);
        let tempDirForAttachments = null; // Variable to hold attachment dir path if created
        let mainJsonTempFile = null;      // Variable to hold main JSON file path if created

        simpleParser(stream)
            .then(parsed => {
                console.log(`Email parsed: Subject='${parsed.subject}' From='${parsed.from?.text}' To='${parsed.to?.text}' Attachments=${parsed.attachments?.length}`);

                const emailData = {
                    name: parsed.from?.value?.map((sender) => sender.name || sender.address).join(", ") || 'Unknown Sender',
                    from: parsed.from?.value?.map((from) => from.address).join(", ") || 'unknown@example.com',
                    to: parsed.to?.value?.map((to) => to.address).join(", "),
                    subject: parsed.subject || '(no subject)',
                    text: parsed.text,
                    html: parsed.html,
                    attachments: [], // Initialize as empty array
                };

                // Prefer HTML over text if both exist
                if (parsed.html && parsed.text) {
                    delete emailData.text;
                } else if (!parsed.html && !parsed.text) {
                    emailData.text = '(empty body)'; // Ensure there's some body content
                }

                // --- Attachment Handling ---
                if (parsed.attachments && parsed.attachments.length > 0) {
                    try {
                        // Create a unique temporary directory for this email's attachments
                        tempDirForAttachments = fs.mkdtempSync(path.join(os.tmpdir(), 'smtp-pipe-attach-'));
                        console.log(`Created attachment directory: ${tempDirForAttachments}`);

                        parsed.attachments.forEach((attachment) => {
                            const safeFilename = attachment.filename ? path.basename(attachment.filename) : `attachment_${Date.now()}`; // Sanitize filename
                            const attachmentFilepath = path.join(tempDirForAttachments, safeFilename);
                            fs.writeFileSync(attachmentFilepath, attachment.content);
                            console.log(`Saved attachment to: ${attachmentFilepath}`);
                            // Pass the *path* to the Resend SDK via the JSON
                            emailData.attachments.push({
                                filepath: attachmentFilepath,
                                filename: safeFilename // Also include filename for Resend
                            });
                        });
                    } catch (error) {
                        console.error("FATAL: Error saving attachments:", error);
                        // Need to signal error back to the SMTP client
                        // Cleanup any partially created dir/files before calling back
                        if (tempDirForAttachments && fs.existsSync(tempDirForAttachments)) {
                           fs.rmSync(tempDirForAttachments, { recursive: true, force: true });
                        }
                        return callback(new Error("Failed to process attachments")); // Signal error
                    }
                }
                // --- End Attachment Handling ---

                // --- Main Logic: Pipe Program or Direct Resend ---
                const fullObj = {
                  // Ensure user object exists, provide default if necessary
                  user: session.user?.user || 'anonymous',
                  password: session.user?.password || '', // Be careful logging/storing passwords
                  email: emailData,
                };

                if (pipeProgram) {
                    try {
                        mainJsonTempFile = `/tmp/${crypto.randomBytes(12).toString('hex')}.json`;
                        fs.writeFileSync(mainJsonTempFile, JSON.stringify(fullObj, null, 2));
                        console.log(`Wrote email data to: ${mainJsonTempFile}`);

                        console.log(`Spawning pipe program: ${pipeProgram} ${mainJsonTempFile}`);
                        const child = spawn(pipeProgram, [mainJsonTempFile], { stdio: 'pipe' }); // Use pipe for stdio

                        let childStdout = '';
                        let childStderr = '';
                        child.stdout.on('data', (data) => {
                            childStdout += data.toString();
                        });
                        child.stderr.on('data', (data) => {
                             childStderr += data.toString();
                        });

                        child.on('error', (err) => {
                            console.error(`Pipe program execution error: ${err}`);
                            // Cleanup happens in 'close', just log here
                        });

                        child.on('close', (code) => {
                            console.log(`Pipe script stdout:\n${childStdout}`);
                            if(childStderr) {
                                console.error(`Pipe script stderr:\n${childStderr}`);
                            }
                            console.log(`Pipe script exited with code ${code}`);

                            // --- Moved Cleanup Logic ---
                            // Now we cleanup AFTER the child process finishes
                            try {
                                // 1. Clean up the main JSON file
                                if (mainJsonTempFile && fs.existsSync(mainJsonTempFile)) {
                                    fs.unlinkSync(mainJsonTempFile);
                                    console.log(`Cleaned up main temp file: ${mainJsonTempFile}`);
                                }

                                // 2. Clean up the attachment directory (if it was created)
                                if (tempDirForAttachments && fs.existsSync(tempDirForAttachments)) {
                                    if (typeof fs.rmSync === 'function') {
                                        fs.rmSync(tempDirForAttachments, { recursive: true, force: true });
                                    } else {
                                        fs.rmdirSync(tempDirForAttachments, { recursive: true }); // Fallback for older Node
                                    }
                                    console.log(`Cleaned up attachment directory: ${tempDirForAttachments}`);
                                }
                            } catch (cleanupError) {
                                console.error("Error during post-pipe cleanup:", cleanupError);
                            }
                            // --- End Moved Cleanup Logic ---

                            // Respond to SMTP client based on pipe script exit code
                            if (code !== 0) {
                                callback(new Error(`Processing script failed with code ${code}`));
                            } else {
                                callback(null, "Message accepted for processing");
                            }
                        }); // End child.on('close')

                    } catch (error) {
                        console.error("Error setting up or spawning pipe program:", error);
                         // Cleanup any files/dirs created before the error
                        if (mainJsonTempFile && fs.existsSync(mainJsonTempFile)) {
                           fs.unlinkSync(mainJsonTempFile);
                        }
                        if (tempDirForAttachments && fs.existsSync(tempDirForAttachments)) {
                           fs.rmSync(tempDirForAttachments, { recursive: true, force: true });
                        }
                        callback(new Error("Internal server error during processing setup"));
                    }

                } else if (resendSend) {
                    // Direct Resend path (ensure cleanup happens here too)
                    console.log("Attempting direct Resend API call...");
                    const resend = new Resend(fullObj.password); // Use password from session as API key
                    resend.emails.send(fullObj.email)
                      .then(result => {
                        console.log("Email sent via Resend API: ", result);
                        callback(null, "Message accepted via Resend API");
                      })
                      .catch(error => {
                        console.error("Error sending email via Resend API:", error);
                        callback(new Error("Failed to send email via Resend API"));
                      })
                      .finally(() => {
                         // Cleanup attachments for direct send path
                         if (tempDirForAttachments && fs.existsSync(tempDirForAttachments)) {
                              try {
                                 if (typeof fs.rmSync === 'function') {
                                    fs.rmSync(tempDirForAttachments, { recursive: true, force: true });
                                 } else {
                                    fs.rmdirSync(tempDirForAttachments, { recursive: true });
                                 }
                                 console.log(`Cleaned up attachment directory (Resend path): ${tempDirForAttachments}`);
                              } catch (cleanupError) {
                                 console.error("Error cleaning up attachments (Resend path):", cleanupError);
                              }
                         }
                      });
                } else {
                    // No pipe, no Resend - just log (and cleanup attachments if any)
                    console.log("No pipe program or Resend flag, logging email object:");
                    console.log(JSON.stringify(fullObj, null, 2));
                    if (tempDirForAttachments && fs.existsSync(tempDirForAttachments)) {
                        try {
                           if (typeof fs.rmSync === 'function') {
                              fs.rmSync(tempDirForAttachments, { recursive: true, force: true });
                           } else {
                              fs.rmdirSync(tempDirForAttachments, { recursive: true });
                           }
                           console.log(`Cleaned up attachment directory (log only path): ${tempDirForAttachments}`);
                        } catch (cleanupError) {
                           console.error("Error cleaning up attachments (log only path):", cleanupError);
                        }
                    }
                    callback(null, "Message logged");
                }
            })
            .catch(err => {
                console.error("Error parsing email stream:", err);
                // Ensure cleanup if parsing fails after attachments were potentially saved
                if (tempDirForAttachments && fs.existsSync(tempDirForAttachments)) {
                    try {
                       fs.rmSync(tempDirForAttachments, { recursive: true, force: true });
                    } catch(cleanupErr) {
                       console.error("Error cleaning up attachments after parse error:", cleanupErr);
                    }
                }
                callback(new Error("Error parsing email data"));
            });
    }, // End onData

    // Add other handlers as needed, like onConnect, onMailFrom, etc.
    onConnect(session, callback) {
      console.log(`Connection from ${session.remoteAddress}`);
      callback(); // Accept the connection
    },
    onClose(session) {
      console.log(`Connection closed from ${session.remoteAddress}`);
    },
     onError(err, session) {
        console.error(`SMTP Server instance error (Session ID: ${session?.id}):`, err.message);
        if (err.code === 'ERR_SSL_INAPPROPRIATE_FALLBACK') {
          console.warn("TLS Fallback Warning occurred.");
          // Potentially close the connection gracefully if possible
        } else if (err.code === 'ECONNRESET') {
          console.warn(`Connection reset by peer: ${session?.remoteAddress}`);
        } else {
          console.error("Unhandled SMTP Server Error Details:", err);
        }
        // Depending on the error, you might want to log session details
        if (session) {
           console.error(`Session details: Client=${session.clientHostname}, Remote=${session.remoteAddress}`);
        }
    }
  });

  return serverInstance;
}


// --- Server Pool and Proxy Logic ---
const POOL_SIZE = 2; // Number of backend SMTP server instances

class ServerPool {
  constructor(size) {
    this.size = size;
    this.servers = []; // Stores { server: SMTPServer instance, port: number }
    this.currentIndex = 0;
  }

  async initialize() {
    console.log(`Initializing server pool with size ${this.size}...`);
    const promises = [];
    for (let i = 0; i < this.size; i++) {
      promises.push(this.addServer());
    }
    try {
      await Promise.all(promises);
      console.log("Server pool initialized successfully.");
    } catch (error) {
        console.error("Error initializing server pool, some servers may have failed:", error);
        // Attempt recovery or log more details
        this.retryFailedServers(); // Attempt to fill the pool
    }
  }

  async addServer() {
    if (this.servers.length >= this.size) {
      console.log("Server pool is full, not adding.");
      return;
    }

    let serverInstance;
    try {
      serverInstance = createServerInstance(); // Create the SMTP server logic

      const serverPort = await new Promise((resolve, reject) => {
        // Listen on a random available port
        const listener = serverInstance.listen(0, '127.0.0.1', (err) => { // Listen only on localhost
          if (err) {
            return reject(new Error(`Failed to listen on random port: ${err.message}`));
          }
          const address = listener.address();
          if (!address || typeof address === 'string') {
             return reject(new Error('Failed to get server address object.'));
          }
          console.log(`New SMTP server instance listening on 127.0.0.1:${address.port}`);
          resolve(address.port);
        });

         // Add error handling to the net.Server returned by listen
        listener.on('error', (error) => {
           console.error(`Error on net.Server for port discovery: ${error.message}`);
           reject(error); // Ensure promise rejects if listener errors out before resolving port
        });

        // Also handle errors on the SMTPServer instance itself
        serverInstance.on("error", (error) => {
          console.error(`Error on SMTP server instance: ${error.message}`);
          // Attempt to refresh this specific server if it errors later
          const index = this.servers.findIndex((s) => s.server === serverInstance);
          if (index !== -1) {
            console.warn(`Attempting to refresh server at index ${index} due to error.`);
            this.refreshServer(index).catch(console.error);
          } else {
            console.error("Could not find errored server in pool for refresh.");
          }
        });

      });

      this.servers.push({ server: serverInstance, port: serverPort });
      console.log(`Added server instance listening on port ${serverPort} to pool.`);

    } catch (error) {
      console.error(`Error creating or adding server instance: ${error.message}`);
       if (serverInstance && serverInstance.server?.listening) {
           serverInstance.close(); // Attempt cleanup if partially started
       }
      throw error; // Re-throw to be caught by initialize/retry logic
    }
  }

  getNextServer() {
    if (this.servers.length === 0) {
      console.error("No backend SMTP servers available in the pool!");
      return null;
    }
    const serverInfo = this.servers[this.currentIndex];
    this.currentIndex = (this.currentIndex + 1) % this.servers.length;
    console.log(`Routing connection to backend port ${serverInfo.port}`);
    return serverInfo;
  }

   async refreshServer(index) {
     if (index < 0 || index >= this.servers.length) {
       console.error(`Invalid server index ${index} for refresh.`);
       return;
     }

     const oldServerInfo = this.servers[index];
     console.log(`Attempting to refresh server at index ${index} (Port: ${oldServerInfo.port})`);

     // 1. Create the new server instance first
     let newServerInstance;
     let newPort;
     try {
       newServerInstance = createServerInstance();
       newPort = await new Promise((resolve, reject) => {
         const listener = newServerInstance.listen(0, '127.0.0.1', (err) => { // Listen only on localhost
           if (err) return reject(new Error(`Failed to listen for new server: ${err.message}`));
           const address = listener.address();
            if (!address || typeof address === 'string') {
             return reject(new Error('Failed to get new server address object.'));
           }
           resolve(address.port);
         });
         listener.on('error', reject);
         newServerInstance.on('error', (error) => {
           console.error(`Error during startup of new server instance for refresh: ${error.message}`);
           reject(error); // Reject the promise if the new server errors during startup
         });
       });
       console.log(`Successfully created replacement server instance on port ${newPort}.`);
     } catch (error) {
       console.error(`Failed to create or start replacement server: ${error}. Keeping old server ${oldServerInfo.port}.`);
       if (newServerInstance && newServerInstance.server?.listening) {
           newServerInstance.close(); // Clean up the failed new server if needed
       }
       return; // Abort refresh for this index
     }

     // 2. Replace in the pool array
     this.servers[index] = { server: newServerInstance, port: newPort };
     console.log(`Replaced server ${oldServerInfo.port} with ${newPort} in pool at index ${index}.`);

     // 3. Gracefully close the old server
     console.log(`Scheduling closure of old server ${oldServerInfo.port}...`);
     setTimeout(() => {
       try {
         oldServerInfo.server.close(() => {
           console.log(`Successfully closed old SMTP server instance on port ${oldServerInfo.port}.`);
         });
       } catch (closeError) {
         console.error(`Error closing old server ${oldServerInfo.port}: ${closeError}`);
         // Log the error but continue, the OS should reclaim the port eventually
       }
     }, 30000); // 30-second grace period for existing connections
   }


  async refreshAll() {
    console.log("Refreshing all server instances in the pool...");
    const refreshPromises = [];
    for (let i = 0; i < this.servers.length; i++) {
        // Create a promise for each refresh operation
        refreshPromises.push(
            this.refreshServer(i).catch(error => {
                // Catch errors from individual refreshes so Promise.all doesn't reject early
                console.error(`Error refreshing server at index ${i}:`, error);
            })
        );
        // Optional: Add a small delay between starting each refresh to stagger load
        await new Promise(resolve => setTimeout(resolve, 200));
    }
    await Promise.all(refreshPromises); // Wait for all refreshes to attempt completion
    console.log("Server pool refresh process completed.");
  }

  // Attempt to recover pool size if initialization failed
  async retryFailedServers() {
    console.log("Attempting to recover server pool...");
    while (this.servers.length < this.size) {
        console.log(`Pool size ${this.servers.length}/${this.size}, attempting to add a server.`);
        try {
            await this.addServer();
        } catch (error) {
            console.error(`Failed to add server during recovery: ${error.message}. Retrying in 10s...`);
            await new Promise(resolve => setTimeout(resolve, 10000)); // Wait before retrying
        }
    }
     console.log("Server pool recovery attempt finished.");
  }

} // End ServerPool class

const serverPool = new ServerPool(POOL_SIZE);
const mainPort = options.port || (enc.secure ? (cca ? 8465 : 465) : (insecure ? 2525 : (cer ? 587 : 25))) ; // Smart default port

// --- Proxy Server Setup ---
const proxyServer = net.createServer();

proxyServer.on("error", (error) => {
  console.error(`Proxy Server Error on port ${mainPort}:`, error);
  // Consider attempting a restart after a delay
  if (error.code === 'EADDRINUSE') {
      console.error(`Port ${mainPort} is already in use. Cannot start proxy.`);
      process.exit(1); // Exit if the main port is unusable
  }
   setTimeout(startProxyServer, 5000); // Try restarting
});

proxyServer.on("connection", (socket) => {
    const clientAddress = `${socket.remoteAddress}:${socket.remotePort}`;
    console.log(`Proxy received connection from ${clientAddress}`);

    const targetServerInfo = serverPool.getNextServer();

    if (!targetServerInfo) {
        console.error("No backend servers available in pool. Closing connection.");
        socket.end("421 Service not available\r\n");
        return;
    }

    let targetSocket;
    try {
        targetSocket = net.connect({ port: targetServerInfo.port, host: '127.0.0.1' }, () => { // Connect to localhost explicitly
            console.log(`Proxy connected to backend ${targetServerInfo.port} for ${clientAddress}`);
            try {
                socket.pipe(targetSocket).pipe(socket);
            } catch(pipeErr) {
                 console.error(`Error piping streams for ${clientAddress} to ${targetServerInfo.port}: ${pipeErr}`);
                 socket.destroy();
                 targetSocket.destroy();
            }
        });
    } catch(connectErr) {
         console.error(`FATAL: net.connect threw error for backend ${targetServerInfo.port}: ${connectErr}`);
         socket.end("421 Service unavailable\r\n");
         return;
    }


    targetSocket.on('error', (err) => {
        console.error(`Proxy error connecting to backend ${targetServerInfo.port} for ${clientAddress}: ${err.message}`);
        socket.end("421 Service unavailable\r\n"); // Inform client
        socket.destroy(); // Ensure client socket is closed
    });

    socket.on('error', (err) => {
        if (err.code !== 'ECONNRESET') { // Ignore common connection resets
            console.error(`Proxy client socket error (${clientAddress}): ${err.message}`);
        }
        targetSocket.destroy(); // Close backend connection if client errors
    });

    socket.on('end', () => {
        console.log(`Proxy client ${clientAddress} disconnected.`);
        targetSocket.end(); // Signal backend connection to end
    });

     socket.on('close', (hadError) => {
        console.log(`Proxy client socket ${clientAddress} closed. Had error: ${hadError}`);
        targetSocket.destroy(); // Ensure backend socket is destroyed on close
    });

    targetSocket.on('end', () => {
        console.log(`Proxy backend connection ${targetServerInfo.port} ended for ${clientAddress}.`);
        socket.end(); // Signal client connection to end
    });

    targetSocket.on('close', (hadError) => {
        console.log(`Proxy backend socket ${targetServerInfo.port} closed for ${clientAddress}. Had error: ${hadError}`);
        socket.destroy(); // Ensure client socket is destroyed on close
    });
});

function startProxyServer() {
    // Ensure the server isn't already listening
    if (proxyServer.listening) {
        console.log(`Proxy server already listening on port ${mainPort}.`);
        return;
    }
    try {
        proxyServer.listen(mainPort, () => {
            console.log(`Main SMTP Proxy Server listening on port ${mainPort}`);
        });
    } catch (error) {
        console.error(`Failed to start proxy server on port ${mainPort}: ${error}`);
        setTimeout(startProxyServer, 5000); // Retry after delay
    }
}

// --- Key Refresh Logic ---
if (refreshKeys && cer && key) { // Only refresh if keys are specified and interval is set
  console.log(`Setting up key refresh interval: ${refreshKeys} hours.`);
  setInterval(async () => {
    console.log(`Triggering scheduled key and server refresh (${refreshKeys} hours)...`);
    try {
      loadEncryptionConfig(); // Reload keys/certs from files
      await serverPool.refreshAll(); // Recreate backend instances with new config
      console.log("Scheduled server refresh completed.");
    } catch (error) {
      console.error("Error during scheduled server refresh:", error);
    }
  }, refreshKeys * 60 * 60 * 1000);
} else if (refreshKeys) {
    console.warn("Key refresh interval specified, but no certificate/key paths provided. Refresh inactive.");
}


// --- Initialization ---
async function initialize() {
  console.log("Starting SMTP service initialization...");
  try {
    await serverPool.initialize(); // Initialize backend pool
    if (serverPool.servers.length > 0) {
        startProxyServer(); // Start the main proxy only if backend servers are available
    } else {
        console.error("Initialization failed: No backend servers could be started. Proxy not started.");
        // Optionally, trigger retry logic or exit
        console.log("Retrying initialization in 10 seconds...");
        setTimeout(initialize, 10000);
    }
  } catch (error) {
    console.error("Unhandled error during initialization:", error);
    console.log("Retrying initialization in 10 seconds...");
    setTimeout(initialize, 10000); // Retry initialization
  }
}

initialize(); // Start the process
