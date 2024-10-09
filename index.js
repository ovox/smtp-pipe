const { SMTPServer } = require("smtp-server");
const { simpleParser } = require("mailparser");
const fs = require("fs");
const path = require("path");
const { program } = require("commander");
const os = require("os");
const { Resend } = require("../resend-node/dist");
const net = require("net");

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
  enc = {};
  if (cer && key && !insecure) {
    enc.secure = true;
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
}

loadEncryptionConfig();

console.log(
  `Running a ${
    cer && key && !insecure ? "secure" : "insecure"
  } SMTP server on port ${options.port}`
);

function createServer() {
  return new SMTPServer({
    ...enc,
    name: name,
    onData(stream, session, callback) {
      simpleParser(stream, async (err, parsed) => {
        try {
          if (err) {
            console.error(err);
            callback(err);
            return;
          }

          //   console.log("parsed", parsed, session);

          if (resendSend) {
            const resend = new Resend(session.user.password);
            const fp = path.join(
              "/tmp",
              Math.random().toString(36).substring(2)
            );
            if (parsed.attachments.length > 0) {
              // iterate over the attachments, write them in a /tmp random file and replace the attachment.filename with the real actual pathp;
              // create the directory fp
              fs.mkdirSync(fp, { recursive: true });
              parsed.attachments.forEach((attachment) => {
                const filepath = path.join(fp, attachment.filename);
                //console.log("found attachment " + filepath);
                fs.writeFileSync(filepath, attachment.content);
                attachment.filepath = filepath;
              });
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

            resend.emails.send(emailData).then((yes, no) => {
              if (no) {
                console.error(no);
              } else {
                console.log("Email sent ", yes);
              }
            });

            if (parsed.attachments.length > 0) {
              fs.rmdirSync(fp, { recursive: true });
            }
          } else {
            const fp = path.join(
              "/tmp",
              Math.random().toString(36).substring(2)
            );
            if (parsed.attachments.length > 0) {
              // iterate over the attachments, write them in a /tmp random file and replace the attachment.filename with the real actual pathp;
              fs.mkdirSync(fp, { recursive: true });
              parsed.attachments.forEach((attachment) => {
                const filepath = path.join(fp, attachment.filename);
                // console.log("found attachment " + filepath);
                fs.writeFileSync(filepath, attachment.content);
                attachment.filepath = filepath;
              });
            }

            // Construct the JSON object from the parsed email
            const emailData = {
              name: parsed.from.value.map((sender) => sender.name).join(", "),
              from: parsed.from.value.map((from) => from.address).join(", "),
              to: parsed.to.value.map((to) => to.address).join(", "),
              subject: parsed.subject,
              text: parsed.text,
              html: parsed.html,
              attachments: parsed.attachments.map((attachment) => ({
                filepath: attachment.filepath,
                // filename: attachment.filename,
              })),
            };

            if (parsed.text && parsed.html) {
              delete emailData.text;
            } else if (parsed.text) {
              delete emailData.html;
            }

            // console.log(emailData);

            const fullObj = {
              user: session.user.user,
              password: session.user.password,
              email: emailData,
            };

            if (pipeProgram) {
              // write the fullObj to a random file in /tmp and pass the filename to the shell program
              const rf = `/tmp/${Math.random().toString(36).substring(2)}.json`;
              fs.writeFileSync(rf, JSON.stringify(fullObj, null, 2));
              const childProcess = require("child_process");
              // console.log("Executing the program", pipeProgram, rf);
              const child = childProcess.spawn(pipeProgram, [rf]);
              child.on("error", (err) => {
                console.error("Error executing the program", err);
              });
              child.stdout.on("data", (data) => {
                console.log(`${data}`);
              });
            } else {
              console.log(JSON.stringify(fullObj, null, 2));
            }
            if (parsed.attachments.length > 0) {
              fs.rmdirSync(fp, { recursive: true });
            }
          }

          callback(null, "Message queued as shoutbox");
        } catch (e) {
          console.error(e);
          callback(e);
        }
      });
    },

    // Simple Authentication setup (modify as needed)
    onAuth(auth, session, callback) {
      // Example: Allow all users (for testing purposes)
      callback(null, {
        user: { user: auth.username, password: auth.password },
      });
    },
  });
}

let server = createServer();

const port = options.port || 25;
// const host = options.host || "127.0.0.1";
const POOL_SIZE = 2;

// Create a TCP proxy server
const proxyServer = net.createServer();

let activeServer = createServer();
let standbyServer = null;
let activePort = null;

function startProxyServer() {
  proxyServer.listen(port, () => {
    console.log(`Proxy server listening on port ${port}`);
  });
}

function handleProxyConnection(socket) {
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
}
proxyServer.on("connection", handleProxyConnection);

class ServerPool {
  constructor(size) {
    this.size = size;
    this.servers = [];
    this.currentIndex = 0;
  }

  async initialize() {
    for (let i = 0; i < this.size; i++) {
      await this.addServer();
    }
  }

  async addServer() {
    if (this.servers.length >= this.size) {
      console.log(
        "Server pool is already at maximum capacity. Not adding a new server."
      );
      return;
    }

    const server = createServer();
    const serverPort = await new Promise((resolve, reject) => {
      server.listen(0, (err) => {
        if (err) {
          reject(err);
        } else {
          resolve(server.server.address().port);
        }
      });
    });

    this.servers.push({ server, port: serverPort });
    console.log(`Added new SMTP server on port ${serverPort}`);
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
        oldServer.server.close(() => {
          console.log(`Closed old SMTP server on port ${oldServer.port}`);
        });
      }, 30000); // 30 seconds grace period
    } catch (error) {
      console.error("Error creating new server during refresh:", error);
    }
  }

  async refreshAll() {
    console.log("Refreshing all servers...");
    for (let i = 0; i < this.servers.length; i++) {
      await this.refreshServer(i);
    }
    console.log("All servers refreshed");
  }
}

const serverPool = new ServerPool(POOL_SIZE);

function startSMTPServer(server) {
  return new Promise((resolve, reject) => {
    server.listen(0, () => {
      // Use port 0 to let the OS assign a random available port
      const port = server.server.address().port;
      console.log(`SMTP server listening on port ${port}`);
      resolve(port);
    });
  });
}

async function refreshServer() {
  console.log("Refreshing servers with new encryption config...");
  loadEncryptionConfig();

  try {
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
  } catch (e) {
    console.error("Error initializing servers:", e);
    process.exit(1);
  }
}

initialize();
