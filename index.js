const { SMTPServer } = require("smtp-server");
const { simpleParser } = require("mailparser");
const fs = require("fs");
const path = require("path");
const { program } = require("commander");
const os = require("os");

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
  .option("-aia, --aia <aia>", "Allow insecure auth (optional)");

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

const enc = {};

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

// This is what you want on port :25 probably
if ((!enc.secure && !enc.key) || aia) {
  enc.allowInsecureAuth = true;
}

console.log(
  `Running a ${
    cer && key && !insecure ? "secure" : "insecure"
  } SMTP server on port ${options.port}`
);

const server = new SMTPServer({
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

        if (parsed.attachments.length > 0) {
          // iterate over the attachments, write them in a /tmp random file and replace the attachment.filename with the real actual pathp;
          parsed.attachments.forEach((attachment) => {
            const filepath = path.join(
              "/tmp",
              Math.random().toString(36).substring(2)
            );
            console.log('found attachment '+filepath);
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
            filename: attachment.filename,
          })),
        };
        

        if (parsed.text && parsed.html) {
          delete emailData.text;
        } else if (parsed.text) {
          delete emailData.html;
        }

        console.log(emailData);

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
    callback(null, { user: { user: auth.username, password: auth.password } });
  },
});

const port = options.port || 25;
// const host = options.host || "127.0.0.1";

// Let's make sure we never 'crash'
process.on("uncaughtException", function (err) {
  console.error("Uncaught detected exception", err);
});

try {
  server.listen(port, () => {
    console.log(`SMTP server listening on ${port}`);
  });
} catch (e) {
  console.error(e);
}
