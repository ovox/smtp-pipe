const nodemailer = require("nodemailer");
const { program } = require("commander");
const { faker } = require("@faker-js/faker"); // Update the import to use @faker-js/faker

program
  .option("-h, --host <host>", "SMTP host")
  .option("-p, --port <port>", "SMTP port", parseInt)
  .option("-u, --user <user>", "SMTP user (optional)")
  .option("-P, --password <password>", "SMTP password (optional)")
  .option("-t --to <to>", "Email recipient (optional)")
  .option("-f --from <from>", "Email sender (optional)");

program.parse(process.argv);
const options = program.opts();

const transporter = nodemailer.createTransport({
  host: options.host,
  port: options.port,
  secure: options.port === 465, // True if port is 465, false for other ports
  ignoreTLS: options.port === 587, // True if port is 587, false for other ports
  auth: {
    user: options.user ?? "test",
    pass: options.password ?? "test",
  },
  tls: {
    rejectUnauthorized: false, // Ignore TLS/SSL certificate errors
  },
});

function getRandomEmailOptions() {
  let sendText = Math.random() > 0.5;
  let sendHtml = Math.random() > 0.5;
  const addAttachment = Math.random() > 0.5;

  if (!sendText && !sendHtml) {
    sendHtml = true;
  }

  if (sendText && sendHtml) {
    sendHtml = false;
  }

  const emailOptions = {
    from: `"${faker.person.fullName()}" <${
      options.from ?? faker.internet.email()
    }>`,
    to: `${options.to ?? faker.internet.email()}`,
    subject: faker.lorem.sentence(),
    text: sendText ? faker.lorem.paragraph() : undefined,
    html: sendHtml ? `<p>${faker.lorem.paragraphs()}</p>` : undefined,
    attachments: [],
  };

  if (!sendText) {
    delete emailOptions.text;
  }

  if (!sendHtml) {
    delete emailOptions.html;
  }

  if (addAttachment) {
    for (let i = 0; i < Math.floor(Math.random() * 3) + 1; i++) {
      emailOptions.attachments.push({
        filename: `${Math.random().toString(36).substring(2)}.txt`,
        content:
          "This is a sample attachment with random text: " +
          faker.lorem.sentence(),
      });
    }
  }

  return emailOptions;
}

const emailOptions = getRandomEmailOptions();
console.log(emailOptions);
transporter.sendMail(emailOptions, (error, info) => {
  if (error) {
    console.log("Error sending email:", error);
  } else {
    console.log("Email sent: " + info.response);
  }
});
