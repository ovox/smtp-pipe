const { SMTPServer } = require("smtp-server");
const { simpleParser } = require("mailparser");
const fs = require("fs");
const path = require("path");
const { program } = require("commander");

program
  .option(
    "-p, --pipe <program>",
    "Save the result in a random file and pass the filename to the shell program (optional)"
  )
  .option("-h, --host <host>", "SMTP host")
  .option("-P, --port <port>", "SMTP port", parseInt)
  .option("-c, --cer <cer>", "Path to certificate (optional)")
  .option("-k, --key <key>", "Path to key (optional)");

program.parse(process.argv);
const options = program.opts();

const pipeProgram = options.pipe;
const cer = options.cer;
const key = options.key;

const server = new SMTPServer({
  secure: cer && key ? true : false,
  key: key ? fs.readFileSync(key) : undefined,
  cert: cer ? fs.readFileSync(cer) : undefined,
  onData(stream, session, callback) {
    simpleParser(stream, async (err, parsed) => {
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

      const fullObj = { user: session.user, email: emailData };

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

      callback();
    });
  },

  // Simple Authentication setup (modify as needed)
  onAuth(auth, session, callback) {
    // Example: Allow all users (for testing purposes)
    callback(null, { user: auth.username });
  },
});

const port = options.port || 25;
// const host = options.host || "127.0.0.1";

server.listen(port, () => {
  console.log(`SMTP server listening on ${port}`);
});
