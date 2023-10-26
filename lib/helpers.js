import nodemailer from "nodemailer";
import crypto from "crypto";

// Send Email
export const sendMail = async (mailOptions) => {
  try {
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.GMAIL_ID,
        pass: process.env.GMAIL_APP_PASS,
      },
      tls: {
        rejectUnauthorized: false,
      },
    });

    const info = await transporter.sendMail(mailOptions);
    console.log(info);
    return info;
  } catch (error) {
    return error.message;
  }
};

export const generateSecretKey = () => {
  const secret = crypto.randomBytes(64).toString("hex");
  return secret;
};
