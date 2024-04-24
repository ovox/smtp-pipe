const { SMTPServer } = require("smtp-server");
const { simpleParser } = require("mailparser");
const fs = require("fs");
const path = require("path");

const server = new SMTPServer({
  secure: false,
  onData(stream, session, callback) {
    simpleParser(stream, async (err, parsed) => {
      if (err) {
        console.error(err);
        callback(err);
        return;
      }

      console.log("parsed", parsed);

      if (parsed.attachments.length > 0) {
        // iterate over the attachments, write them in a /tmp random file and replace the attachment.filename with the real actual pathp;
        parsed.attachments.forEach((attachment) => {
          const filepath = path.join(
            "/tmp",
            Math.random().toString(36).substring(7)
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

      console.log(JSON.stringify(emailData, null, 2));
      callback();
    });
  },

  // Simple Authentication setup (modify as needed)
  onAuth(auth, session, callback) {
    // Example: Allow all users (for testing purposes)
    callback(null, { user: auth.username });
  },
});

server.listen(25, () => {
  console.log("SMTP server listening on port 25");
});
