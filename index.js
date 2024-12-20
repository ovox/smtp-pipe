const { SMTPServer } = require("smtp-server");
const { simpleParser } = require("mailparser");
const fs = require("fs");
const path = require("path");
const { program } = require("commander");
const os = require("os");
const { Resend } = require("../resend-node/dist");
const net = require("net");
const tls = require('tls');

// Add global error handlers to prevent crashes
process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error);
  // Don't exit the process, just log the error
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
  // Don't exit the process, just log the error
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
const name = options.server ?? os.hostname;
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
      // Add explicit TLS options to handle protocol fallback
      enc.tls = {
        minVersion: 'TLSv1.2',
        maxVersion: 'TLSv1.3',
        secureProtocol: 'TLS_method',
        secureOptions: tls.constants.SSL_OP_NO_SSLv2 | 
                      tls.constants.SSL_OP_NO_SSLv3 |
                      tls.constants.SSL_OP_NO_TLSv1 |
                      tls.constants.SSL_OP_NO_TLSv1_1,
        rejectUnauthorized: false, // Allow self-signed certificates
        ciphers: 'HIGH:!aNULL:!MD5:!RC4', // Strong ciphers only
      };
    }
    if (cer && key && cca) {
      enc.requestCert = true;
    }
    if (cer && key) {
      enc.key = fs.readFileSync(key);
      enc.cert = fs.readFileSync(cer);
    }
    if (ca) {
      enc.ca = fs.readFileSync(ca);
    }
    if ((!enc.secure && !enc.key) || aia) {
      enc.allowInsecureAuth = true;
    }
    console.log(`Encryption config reloaded at ${new Date().toISOString()}`);
  } catch (error) {
    console.error("Error loading encryption config:", error);
    // Use default insecure config as fallback
    enc = { allowInsecureAuth: true };
  }
}

loadEncryptionConfig();

console.log(
  `Running a ${
    cer && key && !insecure ? "secure" : "insecure"
  } SMTP server on port ${options.port}`
);

function createServer() {
  const server = new SMTPServer({
    ...enc,
    name: name,
    // Add TLS-specific handlers
    onConnect(session, callback) {
      callback(); // Accept the connection
    },
    onSecure(socket, session, callback) {
      callback(null); // Accept the TLS connection
    },
    onData(stream, session, callback) {
      simpleParser(stream, async (err, parsed) => {
        try {
          if (err) {
            console.error(err);
            callback(err);
            return;
          }

          if (resendSend) {
            const resend = new Resend(session.user.password);
            const fp = path.join(
              "/tmp",
              Math.random().toString(36).substring(2)
            );
            if (parsed.attachments.length > 0) {
              try {
                fs.mkdirSync(fp, { recursive: true });
                parsed.attachments.forEach((attachment) => {
                  const filepath = path.join(fp, attachment.filename);
                  fs.writeFileSync(filepath, attachment.content);
                  attachment.filepath = filepath;
                });
              } catch (error) {
                console.error("Error handling attachments:", error);
                callback(error);
                return;
              }
            }
            const emailData = {
              name: parsed.from.value.map((sender) => sender.name).join(", "),
              from: parsed.from.value.map((from) => from.address).join(", "),
              to: parsed.to.value.map((to) => to.address).join(", "),
              subject: parsed.subject,
              text: parsed.text,
              html: parsed.html,
              attachments: parsed.attachments.map((attachment) => ({
                filepath: attachment.filepath,
              })),
            };

            if (parsed.text && parsed.html) {
              delete emailData.text;
            } else if (parsed.text) {
              delete emailData.html;
            }

            try {
              const result = await resend.emails.send(emailData);
              console.log("Email sent ", result);
            } catch (error) {
              console.error("Error sending email:", error);
              // Don't throw, just log the error
            }

            if (parsed.attachments.length > 0) {
              try {
                fs.rmdirSync(fp, { recursive: true });
              } catch (error) {
                console.error("Error cleaning up attachments:", error);
                // Don't throw, just log the error
              }
            }
          } else {
            const fp = path.join(
              "/tmp",
              Math.random().toString(36).substring(2)
            );
            if (parsed.attachments.length > 0) {
              try {
                fs.mkdirSync(fp, { recursive: true });
                parsed.attachments.forEach((attachment) => {
                  const filepath = path.join(fp, attachment.filename);
                  fs.writeFileSync(filepath, attachment.content);
                  attachment.filepath = filepath;
                });
              } catch (error) {
                console.error("Error handling attachments:", error);
                callback(error);
                return;
              }
            }

            const emailData = {
              name: parsed.from.value.map((sender) => sender.name).join(", "),
              from: parsed.from.value.map((from) => from.address).join(", "),
              to: parsed.to.value.map((to) => to.address).join(", "),
              subject: parsed.subject,
              text: parsed.text,
              html: parsed.html,
              attachments: parsed.attachments.map((attachment) => ({
                filepath: attachment.filepath,
              })),
            };

            if (parsed.text && parsed.html) {
              delete emailData.text;
            } else if (parsed.text) {
              delete emailData.html;
            }

            const fullObj = {
              user: session.user.user,
              password: session.user.password,
              email: emailData,
            };

            if (pipeProgram) {
              try {
                const rf = `/tmp/${Math.random()
                  .toString(36)
                  .substring(2)}.json`;
                fs.writeFileSync(rf, JSON.stringify(fullObj, null, 2));
                const childProcess = require("child_process");
                const child = childProcess.spawn(pipeProgram, [rf]);

                child.on("error", (err) => {
                  console.error("Error executing the program", err);
                  // Don't throw, just log the error
                });

                child.stdout.on("data", (data) => {
                  console.log(`${data}`);
                });

                // Clean up the temp file after the child process exits
                child.on("exit", () => {
                  try {
                    fs.unlinkSync(rf);
                  } catch (error) {
                    console.error("Error cleaning up temp file:", error);
                  }
                });
              } catch (error) {
                console.error("Error in pipe program execution:", error);
                // Don't throw, just log the error
              }
            } else {
              console.log(JSON.stringify(fullObj, null, 2));
            }

            if (parsed.attachments.length > 0) {
              try {
                fs.rmdirSync(fp, { recursive: true });
              } catch (error) {
                console.error("Error cleaning up attachments:", error);
                // Don't throw, just log the error
              }
            }
          }

          callback(null, "Message queued as shoutbox");
        } catch (e) {
          console.error("Error in onData handler:", e);
          callback(e);
        }
      });
    },

    onAuth(auth, session, callback) {
      try {
        callback(null, {
          user: { user: auth.username, password: auth.password },
        });
      } catch (error) {
        console.error("Error in authentication:", error);
        callback(error);
      }
    },
  });

  // Add specific handler for TLS-related errors
  server.on("error", (err) => {
    if (err.code === "ERR_SSL_INAPPROPRIATE_FALLBACK") {
      console.warn("TLS Fallback Warning:", err.message);
      // Don't crash the server, just log the warning
    } else {
      console.error("SMTP Server Error:", err);
    }
  });

  return server;
}

let server = createServer();

const port = options.port || 25;
const POOL_SIZE = 2;

const proxyServer = net.createServer();

// Add error handler for proxy server
proxyServer.on("error", (error) => {
  console.error("Proxy server error:", error);
  // Don't crash, attempt to recover
  setTimeout(() => {
    try {
      proxyServer.close(() => {
        startProxyServer();
      });
    } catch (e) {
      console.error("Error recovering proxy server:", e);
    }
  }, 5000);
});

let activeServer = createServer();
let standbyServer = null;
let activePort = null;

function startProxyServer() {
  try {
    proxyServer.listen(port, () => {
      console.log(`Proxy server listening on port ${port}`);
    });
  } catch (error) {
    console.error("Error starting proxy server:", error);
    // Attempt to restart after delay
    setTimeout(startProxyServer, 5000);
  }
}

function handleProxyConnection(socket) {
  try {
    const serverInfo = serverPool.getNextServer();
    if (!serverInfo) {
      console.error("No SMTP servers available");
      socket.end("421 Service not available, closing transmission channel\r\n");
      return;
    }

    const target = net.connect({ port: serverInfo.port }, () => {
      console.log(`Connected to SMTP server on port ${serverInfo.port}`);
      socket.pipe(target).pipe(socket);
    });

    target.on("error", (err) => {
      console.error(
        `Error connecting to SMTP server on port ${serverInfo.port}:`,
        err
      );
      socket.end("421 Service not available, closing transmission channel\r\n");
    });

    socket.on("error", (err) => {
      if (err.code !== "ECONNRESET") {
        console.error("Client socket error:", err);
      }
      target.destroy();
    });

    socket.on("end", () => {
      target.end();
    });

    target.on("end", () => {
      socket.end();
    });
  } catch (error) {
    console.error("Error in proxy connection handler:", error);
    socket.end("421 Service not available, closing transmission channel\r\n");
  }
}

proxyServer.on("connection", handleProxyConnection);

class ServerPool {
  constructor(size) {
    this.size = size;
    this.servers = [];
    this.currentIndex = 0;
  }

  async initialize() {
    try {
      for (let i = 0; i < this.size; i++) {
        await this.addServer();
      }
    } catch (error) {
      console.error("Error initializing server pool:", error);
      // Attempt recovery by retrying failed servers
      this.retryFailedServers();
    }
  }

  async retryFailedServers() {
    while (this.servers.length < this.size) {
      try {
        await this.addServer();
      } catch (error) {
        console.error("Error adding server during retry:", error);
        await new Promise((resolve) => setTimeout(resolve, 5000));
      }
    }
  }

  async addServer() {
    if (this.servers.length >= this.size) {
      console.log(
        "Server pool is already at maximum capacity. Not adding a new server."
      );
      return;
    }

    try {
      const server = createServer();
      const serverPort = await new Promise((resolve, reject) => {
        server.listen(0, (err) => {
          if (err) {
            reject(err);
          } else {
            resolve(server.server.address().port);
          }
        });

        // Add error handler for the server
        server.on("error", (error) => {
          console.error("SMTP server error:", error);
          // Attempt to refresh this server
          const index = this.servers.findIndex((s) => s.server === server);
          if (index !== -1) {
            this.refreshServer(index).catch(console.error);
          }
        });
      });

      this.servers.push({ server, port: serverPort });
      console.log(`Added new SMTP server on port ${serverPort}`);
    } catch (error) {
      console.error("Error adding server:", error);
      throw error; // Propagate error for retry mechanism
    }
  }

  getNextServer() {
    if (this.servers.length === 0) return null;
    const server = this.servers[this.currentIndex];
    this.currentIndex = (this.currentIndex + 1) % this.servers.length;
    return server;
  }

  async refreshServer(index) {
    if (index < 0 || index >= this.servers.length) {
      console.error("Invalid server index for refresh");
      return;
    }

    const oldServer = this.servers[index];

    try {
      const newServer = createServer();
      const newPort = await new Promise((resolve, reject) => {
        newServer.listen(0, (err) => {
          if (err) {
            reject(err);
          } else {
            resolve(newServer.server.address().port);
          }
        });
      });

      console.log(`Created new SMTP server on port ${newPort}`);

      // Replace the old server with the new one
      this.servers[index] = { server: newServer, port: newPort };

      // Close the old server after a grace period
      setTimeout(() => {
        try {
          oldServer.server.close(() => {
            console.log(`Closed old SMTP server on port ${oldServer.port}`);
          });
        } catch (error) {
          console.error("Error closing old server:", error);
        }
      }, 30000); // 30 seconds grace period
    } catch (error) {
      console.error("Error creating new server during refresh:", error);
      // Keep the old server running if refresh failed
      console.log("Keeping old server running due to refresh failure");
    }
  }

  async refreshAll() {
    console.log("Refreshing all servers...");
    for (let i = 0; i < this.servers.length; i++) {
      try {
        await this.refreshServer(i);
        // Add delay between refreshes to prevent overwhelming the system
        await new Promise((resolve) => setTimeout(resolve, 1000));
      } catch (error) {
        console.error(`Error refreshing server ${i}:`, error);
      }
    }
    console.log("All servers refreshed");
  }
}

const serverPool = new ServerPool(POOL_SIZE);

async function refreshServer() {
  console.log("Refreshing servers with new encryption config...");
  try {
    loadEncryptionConfig();
    await serverPool.refreshAll();
    console.log("Server refresh completed successfully");
  } catch (error) {
    console.error("Error during server refresh:", error);
  }
}

if (refreshKeys) {
  setInterval(async () => {
    try {
      await refreshServer();
    } catch (error) {
      console.error("Error refreshing server:", error);
    }
  }, refreshKeys * 60 * 60 * 1000);
}

async function initialize() {
  try {
    await serverPool.initialize();
    proxyServer.listen(port, () => {
      console.log(`Proxy server listening on port ${port}`);
    });
  } catch (error) {
    console.error("Error initializing servers:", error);
    // Instead of exiting, attempt recovery
    console.log("Attempting to recover from initialization failure...");
    setTimeout(initialize, 5000);
  }
}

initialize();
