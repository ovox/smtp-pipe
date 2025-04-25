const { SMTPServer } = require("smtp-server");
const { simpleParser } = require("mailparser");
const fs = require("fs");
const path = require("path");
const os = require("os");
const net = require("net");
const tls = require('tls');
const crypto = require('crypto');
const { spawn } = require('child_process');

// --- Define Constants ---
const POOL_SIZE = 2; // Number of backend SMTP server instances

// --- Argument Parsing ---
let settings = {
    port: null, // Default set later based on security
    host: undefined, // Listen on all interfaces by default
    serverName: os.hostname(),
    certPath: null,
    keyPath: null,
    caPath: null,
    forceInsecure: false, // From -fi flag (indicates STARTTLS if certs present)
    requestClientCert: false, // From -a flag
    allowInsecureAuthGlobal: false, // From -aia flag
    pipeProgram: null, // From -p flag
    resendSend: false, // From -r flag (NOTE: Placeholder)
    refreshKeys: null // From -rk flag
};

const args = process.argv.slice(2);
for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
        case '-P': case '--port': settings.port = parseInt(args[++i]); break;
        case '-h': case '--host': settings.host = args[++i]; break;
        case '-s': case '--server': settings.serverName = args[++i]; break;
        case '-c': case '--cer': settings.certPath = args[++i]; break;
        case '-k': case '--key': settings.keyPath = args[++i]; break;
        case '-ca': case '--ca': settings.caPath = args[++i]; break;
        case '-fi': case '--insecure': settings.forceInsecure = (args[++i] === 'true'); break;
        case '-a': case '--cca': settings.requestClientCert = (args[++i] === 'true'); break;
        case '-aia': case '--aia': settings.allowInsecureAuthGlobal = (args[++i] === 'true'); break;
        case '-p': case '--pipe': settings.pipeProgram = args[++i]; break;
        case '-r': case '--resend': settings.resendSend = (args[++i] === 'true'); break;
        case '-rk': case '--refresh-keys': settings.refreshKeys = parseInt(args[++i]); break;
        default:
          if (args[i].startsWith('-') && (i + 1 >= args.length || args[i+1].startsWith('-'))) {
             // Flag without value
          } else if (args[i].startsWith('-')) {
             i++; // Skip the assumed value for unknown flags
          }
          break;
    }
}
// --- End Argument Parsing ---

// --- Global Error Handlers ---
process.on("uncaughtException", (error) => {
  console.error(`[${new Date().toISOString()}] Uncaught Exception:`, error);
});
process.on("unhandledRejection", (reason, promise) => {
  console.error(`[${new Date().toISOString()}] Unhandled Rejection at:`, promise, "reason:", reason);
});
// --- End Global Error Handlers ---


// --- TLS Configuration Loading Function ---
let currentTlsConfig = {}; // Store the currently active TLS config for SMTPServer

function loadEncryptionConfigBasedOnArgs() { // Renamed function
  const newConfig = {}; // Build new config locally
  try {
    console.log(`Loading encryption config based on args: cert=${settings.certPath}, key=${settings.keyPath}, forceInsecure=${settings.forceInsecure}`);

    // *** CORRECTED LOGIC ***
    // Configure for TLS/STARTTLS if certificate and key paths are provided
    if (settings.certPath && settings.keyPath) {
      console.log("Certificate and key paths provided. Configuring secure options...");
      // These will throw an error if files don't exist or aren't readable
      newConfig.key = fs.readFileSync(settings.keyPath);
      newConfig.cert = fs.readFileSync(settings.certPath);
      console.log("Certificate and key loaded successfully.");

      // Use the forceInsecure flag (-fi) to differentiate STARTTLS from Implicit TLS
      if (settings.forceInsecure) {
          // STARTTLS mode: start insecure, then upgrade
          newConfig.secure = false; // Server starts plain text
          newConfig.starttls = true; // Advertise STARTTLS capability
          console.log(`Configured for STARTTLS (secure=false, starttls=true) because -fi was true.`);
      } else {
          // Implicit TLS mode (e.g., for port 465 if certs were passed): start secure
          newConfig.secure = true; // Connection must be TLS from the start
          newConfig.starttls = false; // STARTTLS command not used
          console.log(`Configured for Implicit TLS (secure=true, starttls=false) because -fi was not true.`);
      }

      // Common TLS settings
      newConfig.tls = {
        minVersion: 'TLSv1.2',
        rejectUnauthorized: false, // Caution! Set to true if using a proper CA for clients/servers
        ciphers: [ // Prioritize modern ciphers
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'DHE-RSA-AES256-GCM-SHA384', // Less preferred but included
            'DHE-RSA-AES128-GCM-SHA256',
            '!aNULL', '!eNULL', '!EXPORT', '!DES', '!RC4', '!MD5', '!PSK', '!SRP', '!CAMELLIA' // Exclusions
        ].join(':'),
      };

      // Client Certificate Auth handling (remains the same)
      if (settings.requestClientCert) {
          newConfig.requestCert = true;
          if (settings.caPath) {
              try {
                  newConfig.ca = fs.readFileSync(settings.caPath);
                  console.log("CA certificate loaded for client verification.");
                  newConfig.tls.rejectUnauthorized = true; // Enforce validation if CA is present
              } catch (caError) {
                 console.error(`Error loading CA file: ${caError.message}. Client cert verification may fail.`);
               }
          } else {
              console.warn("Requesting client cert but no CA path provided. Verification might not work as expected.");
               newConfig.tls.rejectUnauthorized = false; // Ensure it stays false if no CA
           }
          console.log(`Client certificate requested: ${newConfig.requestCert}, CA specified: ${!!newConfig.ca}`);
      }

      // Allow insecure auth (-aia) flag handling
      // This flag allows AUTH *before* STARTTLS (if starttls=true) or on a plain connection (if starttls=false and secure=false)
      newConfig.allowInsecureAuth = settings.allowInsecureAuthGlobal;
      console.log(`Allow insecure auth (-aia flag): ${newConfig.allowInsecureAuth}`);

    } else {
      // No cert/key provided: Plain text configuration
      newConfig.secure = false;
      newConfig.starttls = false;
      newConfig.allowInsecureAuth = true; // Allow insecure auth by default if no certs
      console.log(`Configured for Plain/Insecure (no certs). Allow insecure auth: ${newConfig.allowInsecureAuth}`);
    }
    // *** END CORRECTED LOGIC ***

    currentTlsConfig = newConfig;
    console.log(`Encryption config loaded: secure=${currentTlsConfig.secure}, starttls=${currentTlsConfig.starttls}, allowInsecureAuth=${currentTlsConfig.allowInsecureAuth}, requestCert=${currentTlsConfig.requestCert}`);

  } catch (error) {
    console.error("FATAL: Error loading/processing encryption config:", error);
    if (settings.certPath || settings.keyPath) {
        console.error("Crashing instance because required cert/key could not be loaded.");
        throw error;
    }
    console.warn("Falling back to default insecure SMTP configuration due to loading error.");
    currentTlsConfig = { secure: false, allowInsecureAuth: true, starttls: false };
  }
}
// --- End TLS Configuration Loading ---


// --- SMTPServer Instance Creation ---
function createServerInstance() {
    loadEncryptionConfigBasedOnArgs(); // Load based on current args

    const serverInstance = new SMTPServer({
        // TLS settings from dynamic config
        secure: currentTlsConfig.secure,
        key: currentTlsConfig.key,
        cert: currentTlsConfig.cert,
        ca: currentTlsConfig.ca,
        starttls: currentTlsConfig.starttls,
        requestCert: currentTlsConfig.requestCert,
        allowInsecureAuth: currentTlsConfig.allowInsecureAuth,
        tls: currentTlsConfig.tls,

        // Other server settings
        name: settings.serverName,
        size: 50 * 1024 * 1024, // 50MB limit
        authOptional: true, // Allows connections without AUTH attempt

        // Handlers
        onAuth(auth, session, callback) {
            console.log(`Auth attempt: User=${auth.username}, Method=${auth.method}, Session Secure=${session.secure}`);
            // Check if session is secure (either implicit TLS or STARTTLS completed)
            const isSecureNow = session.secure;
            // Allow auth if the session is secure OR if insecure auth is explicitly allowed by config
            const allowAuth = isSecureNow || currentTlsConfig.allowInsecureAuth;

            if (allowAuth) {
                console.log(`Authentication successful for ${auth.username} (secure=${isSecureNow}, allowInsecureCfg=${currentTlsConfig.allowInsecureAuth})`);
                callback(null, { user: { user: auth.username, password: auth.password } });
            } else {
                console.warn(`Authentication failed for ${auth.username}: Insecure connection (secure=${isSecureNow}) and secure auth required (allowInsecureCfg=${currentTlsConfig.allowInsecureAuth}).`);
                callback(new Error('530 5.7.0 Authentication required (must issue STARTTLS command first)'));
            }
        },

        onMailFrom(address, session, callback) {
            // console.log(`MAIL FROM: ${address.address} (AuthUser: ${session.user?.user || 'none'}, Secure=${session.secure})`); // Verbose
            callback();
        },

        onRcptTo(address, session, callback) {
            // console.log(`RCPT TO: ${address.address} (AuthUser: ${session.user?.user || 'none'}, Secure=${session.secure})`); // Verbose
            callback();
        },

        onData(stream, session, callback) {
            const remoteInfo = `${session.remoteAddress}:${session.remotePort}`;
            console.log(`Receiving data from ${remoteInfo} (Session ID: ${session.id})...`);
            let tempDirForAttachments = null;
            let mainJsonTempFile = null;

            simpleParser(stream)
                .then(parsed => {
                    // console.log(`Email parsed: Subject='${parsed.subject}' From='${parsed.from?.text}' To='${parsed.to?.text}' Attachments=${parsed.attachments?.length}`); // Verbose

                    const emailDataAttachments = [];
                    if (parsed.attachments && parsed.attachments.length > 0) {
                        try {
                            tempDirForAttachments = fs.mkdtempSync(path.join(os.tmpdir(), 'smtp-pipe-attach-'));
                            console.log(`Created attachment directory: ${tempDirForAttachments}`);
                            parsed.attachments.forEach((attachment, index) => {
                                const safeFilename = attachment.filename ? path.basename(attachment.filename) : `attachment_${index + 1}_${Date.now()}`;
                                const attachmentFilepath = path.join(tempDirForAttachments, safeFilename);
                                fs.writeFileSync(attachmentFilepath, attachment.content);
                                // console.log(`Saved attachment ${index + 1} to: ${attachmentFilepath}`); // Verbose
                                emailDataAttachments.push({ filepath: attachmentFilepath, filename: safeFilename });
                            });
                        } catch (error) {
                            console.error(`FATAL: Error saving attachments for email from ${remoteInfo}:`, error);
                            if (tempDirForAttachments && fs.existsSync(tempDirForAttachments)) try { fs.rmSync(tempDirForAttachments, { recursive: true, force: true }); } catch(e){}
                            return callback(new Error("554 Transaction failed: Error processing attachments"));
                        }
                    }

                    const emailData = {
                        name: parsed.from?.value?.map((sender) => sender.name || sender.address).join(", ") || 'Unknown Sender',
                        from: parsed.from?.value?.map((from) => from.address).join(", ") || 'unknown@example.com',
                        to: parsed.to?.value?.map((to) => to.address).join(", "),
                        subject: parsed.subject || '(no subject)',
                        text: parsed.text,
                        html: parsed.html,
                        attachments: emailDataAttachments,
                    };
                    if (parsed.html && parsed.text) delete emailData.text;
                    else if (!parsed.html && !parsed.text) emailData.text = '(empty body)';

                    const fullObj = {
                        user: session.user?.user || 'anonymous',
                        password: session.user?.password || '', // WARNING: Avoid logging this object if sensitive
                        email: emailData,
                    };

                    if (settings.pipeProgram) {
                        try {
                            mainJsonTempFile = `/tmp/${crypto.randomBytes(12).toString('hex')}.json`;
                            fs.writeFileSync(mainJsonTempFile, JSON.stringify(fullObj, null, 2));
                            // console.log(`Wrote email data for pipe to: ${mainJsonTempFile}`); // Verbose

                            console.log(`Spawning pipe program: ${settings.pipeProgram} ${mainJsonTempFile}`);
                            const child = spawn(settings.pipeProgram, [mainJsonTempFile], { stdio: 'pipe' });

                            let childStdout = '';
                            let childStderr = '';
                            child.stdout.on('data', (data) => { childStdout += data.toString(); });
                            child.stderr.on('data', (data) => { childStderr += data.toString(); });
                            child.on('error', (err) => { console.error(`Pipe program ${settings.pipeProgram} spawn error: ${err}`); });

                            child.on('close', (code) => {
                                if (childStdout) console.log(`Pipe script stdout:\n${childStdout}`);
                                if (childStderr) console.error(`Pipe script stderr:\n${childStderr}`);
                                console.log(`Pipe script ${settings.pipeProgram} exited with code ${code}`);

                                // --- Cleanup inside 'close' ---
                                try {
                                    if (mainJsonTempFile && fs.existsSync(mainJsonTempFile)) {
                                        fs.unlinkSync(mainJsonTempFile);
                                        // console.log(`Cleaned up main temp file: ${mainJsonTempFile}`); // Verbose
                                    }
                                    if (tempDirForAttachments && fs.existsSync(tempDirForAttachments)) {
                                        fs.rmSync(tempDirForAttachments, { recursive: true, force: true });
                                        // console.log(`Cleaned up attachment directory: ${tempDirForAttachments}`); // Verbose
                                    }
                                } catch (cleanupError) {
                                    console.error("Error during post-pipe cleanup:", cleanupError);
                                }
                                // --- End Cleanup ---

                                if (code !== 0) {
                                    callback(new Error(`554 Transaction failed: Processing script failed with code ${code}`));
                                } else {
                                    callback(null, "250 OK: Message accepted for processing via pipe");
                                }
                            });

                        } catch (error) {
                            console.error(`Error setting up pipe program ${settings.pipeProgram}:`, error);
                            if (mainJsonTempFile && fs.existsSync(mainJsonTempFile)) try {fs.unlinkSync(mainJsonTempFile);} catch(e){}
                            if (tempDirForAttachments && fs.existsSync(tempDirForAttachments)) try {fs.rmSync(tempDirForAttachments, { recursive: true, force: true });} catch(e){}
                            callback(new Error("554 Transaction failed: Internal server error during pipe setup"));
                        }
                    } else if (settings.resendSend) {
                       console.error("Direct Resend (-r flag) logic not implemented.");
                       if (tempDirForAttachments && fs.existsSync(tempDirForAttachments)) try {fs.rmSync(tempDirForAttachments, { recursive: true, force: true });} catch(e){}
                       callback(new Error("500 Internal Error: Direct Resend not implemented"));
                    } else {
                        console.log("No pipe program or Resend flag. Cleanup attachments only.");
                        // console.log(JSON.stringify(fullObj, null, 2)); // Avoid logging potentially sensitive data
                         if (tempDirForAttachments && fs.existsSync(tempDirForAttachments)) {
                             try {
                                 fs.rmSync(tempDirForAttachments, { recursive: true, force: true });
                                 // console.log(`Cleaned up attachment directory (log only path): ${tempDirForAttachments}`); // Verbose
                             } catch (cleanupError) {
                                 console.error("Error cleaning up attachments (log only path):", cleanupError);
                             }
                         }
                        callback(null, "250 OK: Message logged (no processing)");
                    }
                })
                .catch(err => {
                    console.error(`Error parsing email stream from ${remoteInfo}:`, err);
                    if (tempDirForAttachments && fs.existsSync(tempDirForAttachments)) try { fs.rmSync(tempDirForAttachments, { recursive: true, force: true }); } catch(e) {}
                    callback(new Error("451 Requested action aborted: error processing email data"));
                });
        }, // End onData

        onConnect(session, callback) {
          // console.log(`Connection from ${session.remoteAddress} (ID: ${session.id})`); // Verbose
          callback();
        },
        onClose(session) {
          // console.log(`Connection closed from ${session.remoteAddress} (ID: ${session.id})`); // Verbose
        },
        onError(err, session) {
            console.error(`SMTP Server instance error (Session ID: ${session?.id || 'N/A'}, Client: ${session?.clientHostname || 'N/A'}@${session?.remoteAddress || 'N/A'}):`, err.message);
            if (err.code === 'ERR_SSL_INAPPROPRIATE_FALLBACK') console.warn("TLS Fallback Warning occurred.");
            else if (err.code === 'ECONNRESET') console.warn(`Connection reset by peer.`);
            // else console.error("Unhandled SMTP Server Error Details:", err); // Can be too verbose
        }
    }); // End new SMTPServer

    return serverInstance;
}
// --- End SMTPServer Instance Creation ---


// --- Server Pool Class ---
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
      promises.push(this.addServer().catch(e => {
        console.error(`Failed to initialize server instance ${i + 1}: ${e.message}`);
        return null;
      }));
    }
    await Promise.all(promises);
    const successfulServers = this.servers.length;
    console.log(`Server pool initialization attempt finished. ${successfulServers}/${this.size} servers started.`);
    if (successfulServers < this.size) {
        console.log("Attempting recovery for failed servers...");
        this.retryFailedServers();
    }
  }

  async addServer() {
    if (this.servers.length >= this.size) return;
    let serverInstance;
    try {
      serverInstance = createServerInstance();
      const serverPort = await new Promise((resolve, reject) => {
        const listener = serverInstance.listen(0, '127.0.0.1', (err) => {
          if (err) return reject(new Error(`Listen failed: ${err.message}`));
          const address = listener.address();
          if (!address || typeof address === 'string') return reject(new Error('Failed to get server address.'));
          resolve(address.port);
        });
        listener.on('error', (error) => {
           console.error(`net.Server listen error for pool instance: ${error.message}`);
           reject(error);
        });
      });
      this.servers.push({ server: serverInstance, port: serverPort });
      console.log(`Added server instance listening on 127.0.0.1:${serverPort} to pool.`);
    } catch (error) {
      console.error(`Error creating/adding server instance: ${error.message}`);
       if (serverInstance && serverInstance.server?.listening) try { serverInstance.close(); } catch(e){}
      throw error;
    }
  }

  getNextServer() {
    if (this.servers.length === 0) { console.error("POOL ERROR: No backend servers available!"); return null; }
    const serverInfo = this.servers[this.currentIndex];
    this.currentIndex = (this.currentIndex + 1) % this.servers.length;
    // console.log(`Routing connection to backend port ${serverInfo.port}`); // Verbose
    return serverInfo;
  }

  async refreshServer(index) {
     if (index < 0 || index >= this.servers.length) { console.error(`Invalid server index ${index} for refresh.`); return; }
     const oldServerInfo = this.servers[index];
     console.log(`Attempting to refresh server at index ${index} (Old Port: ${oldServerInfo.port})`);
     let newServerInstance;
     let newPort;
     try {
       newServerInstance = createServerInstance();
       newPort = await new Promise((resolve, reject) => {
         const listener = newServerInstance.listen(0, '127.0.0.1', (err) => {
           if (err) return reject(new Error(`Listen failed for refresh: ${err.message}`));
           const address = listener.address();
           if (!address || typeof address === 'string') return reject(new Error('Failed to get new server address.'));
           resolve(address.port);
         });
         listener.on('error', reject);
       });
       console.log(`Created replacement server instance on port ${newPort}.`);
     } catch (error) {
       console.error(`Failed to create replacement server: ${error}. Keeping old server ${oldServerInfo.port}.`);
       if (newServerInstance && newServerInstance.server?.listening) try { newServerInstance.close(); } catch(e){}
       return;
     }
     this.servers[index] = { server: newServerInstance, port: newPort };
     console.log(`Replaced server ${oldServerInfo.port} with ${newPort} in pool at index ${index}.`);
     setTimeout(() => {
       try {
         oldServerInfo.server.close(() => { console.log(`Successfully closed old SMTP server instance on port ${oldServerInfo.port}.`); });
       } catch (closeError) { console.error(`Error closing old server ${oldServerInfo.port}: ${closeError}`); }
     }, 30000);
   }

  async refreshAll() {
    console.log("Refreshing all server instances in the pool with new config...");
    loadEncryptionConfigBasedOnArgs(); // Load latest config first
    const refreshPromises = [];
    for (let i = 0; i < this.servers.length; i++) {
        refreshPromises.push(this.refreshServer(i).catch(error => { console.error(`Error refreshing server at index ${i}:`, error); }));
        await new Promise(resolve => setTimeout(resolve, 200)); // Stagger
    }
    await Promise.all(refreshPromises);
    console.log("Server pool refresh process completed.");
  }

  async retryFailedServers() {
    console.log("Attempting pool recovery...");
    let attempts = 0;
    const maxAttempts = 5;
    while (this.servers.length < this.size && attempts < maxAttempts) {
        attempts++;
        console.log(`Pool recovery attempt ${attempts}: ${this.servers.length}/${this.size} servers active.`);
        try { await this.addServer(); } catch (error) {
            console.error(`Failed recovery attempt ${attempts}: ${error.message}. Retrying in 15s...`);
            await new Promise(resolve => setTimeout(resolve, 15000));
        }
    }
    if(this.servers.length < this.size) console.error(`Pool recovery failed after ${attempts} attempts.`);
    else console.log("Server pool recovery successful.");
  }
}
// --- End Server Pool Class ---

// --- Proxy Server Logic ---
const mainProxyPort = settings.port; // Use the port passed via -P
if (!mainProxyPort) {
    console.error("FATAL: No port specified via -P argument.");
    process.exit(1);
}

const proxyServer = net.createServer();

proxyServer.on("error", (error) => {
  console.error(`Proxy Server Error on port ${mainProxyPort}:`, error);
  if (error.code === 'EADDRINUSE') { console.error(`Port ${mainProxyPort} is in use. Exiting.`); process.exit(1); }
  setTimeout(startProxyServer, 5000);
});

proxyServer.on("connection", (socket) => {
    const clientAddress = `${socket.remoteAddress}:${socket.remotePort}`;
    const targetServerInfo = serverPool.getNextServer();
    if (!targetServerInfo) {
        console.error("No backend servers available. Closing connection.");
        socket.end("421 Service temporarily unavailable\r\n");
        socket.destroy();
        return;
    }
    let targetSocket;
    try {
        targetSocket = net.connect({ port: targetServerInfo.port, host: '127.0.0.1' }, () => {
            try { socket.pipe(targetSocket).pipe(socket); } catch(pipeErr) {
                 console.error(`Error piping streams for ${clientAddress} <-> ${targetServerInfo.port}: ${pipeErr}`);
                 socket.destroy(); targetSocket.destroy();
            }
        });
        targetSocket.on('error', (err) => {
            console.error(`Proxy error connecting to backend ${targetServerInfo.port} for ${clientAddress}: ${err.message} (Code: ${err.code})`);
            if (!socket.destroyed) { socket.end("421 Service unavailable\r\n"); socket.destroy(); }
        });
        socket.on('error', (err) => {
            if (err.code !== 'ECONNRESET') console.error(`Proxy client socket error (${clientAddress}): ${err.message}`);
            if (!targetSocket.destroyed) targetSocket.destroy();
        });
        socket.on('close', (hadError) => { if (!targetSocket.destroyed) targetSocket.destroy(); });
        targetSocket.on('close', (hadError) => { if (!socket.destroyed) socket.destroy(); });
    } catch(connectErr) {
         console.error(`FATAL: net.connect failed for backend ${targetServerInfo.port}: ${connectErr}`);
         if (!socket.destroyed) { socket.end("421 Service unavailable\r\n"); socket.destroy(); }
    }
});

function startProxyServer() {
    if (proxyServer.listening) return;
    try {
        proxyServer.listen(mainProxyPort, settings.host, () => {
            const listenAddress = settings.host || '0.0.0.0';
            console.log(`Main SMTP Proxy Server listening on ${listenAddress}:${mainProxyPort}`);
        });
    } catch (error) {
        console.error(`Failed to start proxy server on port ${mainProxyPort}: ${error}`);
        setTimeout(startProxyServer, 5000);
    }
}
// --- End Proxy Server Logic ---

// --- Key Refresh Setup ---
if (settings.refreshKeys && settings.certPath && settings.keyPath) {
  console.log(`Setting up key refresh interval: ${settings.refreshKeys} hours.`);
  setInterval(async () => {
    console.log(`Triggering scheduled key and server refresh (${settings.refreshKeys} hours)...`);
    try {
      // loadEncryptionConfigBasedOnArgs(); // Config is reloaded inside refreshServer -> createServerInstance
      await serverPool.refreshAll();
      console.log("Scheduled server refresh completed.");
    } catch (error) {
      console.error("Error during scheduled server refresh:", error);
    }
  }, settings.refreshKeys * 60 * 60 * 1000);
} else if (settings.refreshKeys) {
    console.warn("Key refresh interval specified (-rk), but no certificate (-c) / key (-k) paths provided. Refresh inactive.");
}
// --- End Key Refresh ---

// --- Main Initialization ---
const serverPool = new ServerPool(POOL_SIZE);

async function initialize() {
  console.log("Starting SMTP service initialization...");
  try {
    await serverPool.initialize();
    if (serverPool.servers.length > 0) {
        startProxyServer();
    } else {
        console.error("Initialization failed: No backend servers available. Proxy not started.");
        console.log("Retrying initialization in 15 seconds...");
        setTimeout(initialize, 15000);
    }
  } catch (error) {
    console.error("Unhandled error during initialization sequence:", error);
    console.log("Retrying initialization in 15 seconds...");
    setTimeout(initialize, 15000);
  }
}

initialize(); // Start the application
