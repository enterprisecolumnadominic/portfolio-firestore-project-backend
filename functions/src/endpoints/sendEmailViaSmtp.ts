import * as functions from "firebase-functions";
import * as jwt from "jsonwebtoken";
import * as nodemailer from "nodemailer";
import {applyCors} from "../utils/cors";

const JWT_SECRET =
  process.env.JWT_SECRET || "fallback-local-dev-secret-key-12345";
const ONE_HOUR_MS = 60 * 60 * 1000;
const MAX_EMAILS_PER_HOUR = 3;

interface TokenPayload {
  visitorId: string;
  timestamps: number[];
}

interface EmailRequestBody {
  name: string;
  email: string;
  message: string;
}

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.SMTP_EMAIL || "enterprise.columna.dominic@gmail.com",
    pass: process.env.SMTP_PASSWORD || "whgyhpetbzoilazu",
  },
});

export const sendEmailViaSmtp = functions.https.onRequest(async (req, res) => {
  // One line handles all CORS and Preflight checks cleanly!
  if (applyCors(req, res)) return;

  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res
        .status(401)
        .json({error: "Unauthorized", message: "Missing tracking token."});
      return;
    }

    const tokenString = authHeader.split(" ")[1];
    let decoded: TokenPayload;

    try {
      decoded = jwt.verify(tokenString, JWT_SECRET) as TokenPayload;
    } catch (err) {
      res.status(403).json({
        error: "Forbidden",
        message: "Invalid or expired session token.",
      });
      return;
    }

    const now = Date.now();
    const emailTimestamps = (decoded.timestamps || []).filter(
      (ts) => now - ts < ONE_HOUR_MS,
    );

    if (emailTimestamps.length >= MAX_EMAILS_PER_HOUR) {
      res.status(429).json({
        error: "Too Many Requests",
        message:
          "Email threshold reached. You can only send 3 messages per hour.",
      });
      return;
    }

    const {name, email, message} = req.body as EmailRequestBody;
    if (!name || !email || !message) {
      res.status(400).json({
        error: "Bad Request",
        message: "All form fields are mandatory.",
      });
      return;
    }

    // 4. Fire the email out through Gmail SMTP
    const senderEmail =
      process.env.SMTP_EMAIL || "enterprise.columna.dominic@gmail.com";
    const targetEmail =
      process.env.SMTP_EMAIL || "enterprise.columna.dominic@gmail.com";

    await transporter.sendMail({
      from: `"Portfolio Contact Form" <${senderEmail}>`,
      to: targetEmail, // Sends the message straight to your inbox
      replyTo: email,
      subject: `New Message from ${name} via Portfolio`,
      text: `Name: ${name}\nEmail: ${email}\n\nMessage:\n${message}`,
    });

    emailTimestamps.push(now);
    const updatedToken = jwt.sign(
      {visitorId: decoded.visitorId, timestamps: emailTimestamps},
      JWT_SECRET,
      {expiresIn: "7d"},
    );

    res.status(200).json({
      status: "success",
      message: "Email dispatched safely.",
      token: updatedToken,
      emailsRemainingInHour: Math.max(
        0,
        MAX_EMAILS_PER_HOUR - emailTimestamps.length,
      ),
    });
  } catch (error) {
    console.error("Mail server error:", error);
    res.status(500).send("Internal validation anomaly.");
  }
});
