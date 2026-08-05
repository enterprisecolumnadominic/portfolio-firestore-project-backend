import { onRequest } from "firebase-functions/v2/https";
import * as jwt from "jsonwebtoken";
import * as nodemailer from "nodemailer";
import { applyCors } from "../utils/cors";
import { TokenPayload } from "../types/auth";

const JWT_SECRET = process.env.JWT_SECRET;
const MAX_EMAILS_PER_HOUR = 3; // Strict limit: max 3 emails per hour
const ONE_HOUR_MS = 60 * 60 * 1000;

interface EmailRequestBody {
  name: string;
  email: string;
  message: string;
}

export const sendEmailViaSmtp = onRequest(
  { secrets: ["SMTP_EMAIL", "SMTP_PASSWORD"] },
  async (req, res) => {
    if (applyCors(req, res)) return;

    try {
      const senderEmail = process.env.SMTP_EMAIL;
      const smtpPassword = process.env.SMTP_PASSWORD;

      if (!senderEmail || !smtpPassword) {
        throw new Error("Missing cloud environment SMTP secrets.");
      }

      // 1. Verify Authorization Token
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res
          .status(401)
          .json({ error: "Unauthorized", message: "Missing session token." });
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

      // 2. Filter email timestamps within the past hour
      const now = Date.now();
      const emailTimestamps = (decoded.emailTimestamps || []).filter(
        (ts) => now - ts < ONE_HOUR_MS,
      );

      if (emailTimestamps.length >= MAX_EMAILS_PER_HOUR) {
        res.status(429).json({
          error: "Too Many Requests",
          message:
            "Email limit reached. You can only send 3 messages per hour.",
        });
        return;
      }

      // 3. Validate form inputs
      const { name, email, message } = req.body as EmailRequestBody;
      if (!name || !email || !message) {
        res.status(400).json({
          error: "Bad Request",
          message: "All fields (name, email, message) are required.",
        });
        return;
      }

      // 4. Send email via SMTP
      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: { user: senderEmail, pass: smtpPassword },
      });

      await transporter.sendMail({
        from: `"Portfolio Contact" <${senderEmail}>`,
        to: senderEmail,
        replyTo: email,
        subject: `New Message from ${name}`,
        text: `Name: ${name}\nEmail: ${email}\n\nMessage:\n${message}`,
      });

      // 5. Add new email timestamp & re-sign JWT keeping session history intact
      emailTimestamps.push(now);

      const updatedToken = jwt.sign(
        {
          visitorId: decoded.visitorId,
          sessionTimestamps: decoded.sessionTimestamps || [],
          emailTimestamps,
        },
        JWT_SECRET,
        { expiresIn: "7d" },
      );

      res.status(200).json({
        status: "success",
        message: "Email sent successfully!",
        token: updatedToken,
        emailsRemainingInHour: Math.max(
          0,
          MAX_EMAILS_PER_HOUR - emailTimestamps.length,
        ),
      });
    } catch (error) {
      console.error("Mail dispatch error:", error);
      res.status(500).send("Internal server error.");
    }
  },
);
