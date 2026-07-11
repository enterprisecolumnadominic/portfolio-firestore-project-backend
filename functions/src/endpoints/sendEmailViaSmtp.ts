import { onRequest } from "firebase-functions/v2/https";
import * as jwt from "jsonwebtoken";
import * as nodemailer from "nodemailer";
import { Request, Response } from "express";
import { applyCorsMiddleware } from "../utils/cors";
import { validateRecaptcha } from "../utils/validateRecaptcha";

const JWT_SECRET = process.env.JWT_SECRET || "fallback-local-dev-secret-key-12345";
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
  recaptchaToken?: string; // Appended by the frontend reCAPTCHA composable
}

export const sendEmailViaSmtp = onRequest(
  { secrets: ["SMTP_EMAIL", "SMTP_PASSWORD", "RECAPTCHA_SECRET_KEY"] },
  async (req: Request, res: Response) => {
    
    // 1. Fire our clean, separate official CORS middleware handler
    await applyCorsMiddleware(req, res);
    
    // Stop processing if this was an OPTIONS preflight request handled by middleware
    if (req.method === "OPTIONS") return;

    try {
      // 2. Runtime config validation guard
      const senderEmail = process.env.SMTP_EMAIL;
      const smtpPassword = process.env.SMTP_PASSWORD;

      if (!senderEmail || !smtpPassword) {
        throw new Error("Missing cloud environment SMTP configurations.");
      }

      // 3. CHECKPOINT 1: Authorization Header Validation
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res.status(401).json({ error: "Unauthorized", message: "Missing tracking token." });
        return;
      }

      const tokenString = authHeader.split(" ")[1];
      let decoded: TokenPayload;

      try {
        decoded = jwt.verify(tokenString, JWT_SECRET) as TokenPayload;
      } catch (err) {
        res.status(403).json({ error: "Forbidden", message: "Invalid or expired session token." });
        return;
      }

      // 4. CHECKPOINT 2: Token-Based Rate Limiting Check
      const now = Date.now();
      const emailTimestamps = (decoded.timestamps || []).filter(
        (ts) => now - ts < ONE_HOUR_MS,
      );

      if (emailTimestamps.length >= MAX_EMAILS_PER_HOUR) {
        res.status(429).json({
          error: "Too Many Requests",
          message: "Email threshold reached. You can only send 3 messages per hour.",
        });
        return;
      }

      // 5. Input Field Presence Validation
      const { name, email, message, recaptchaToken } = req.body as EmailRequestBody;
      if (!name || !email || !message) {
        res.status(400).json({ error: "Bad Request", message: "All form fields are mandatory." });
        return;
      }

      // 6. CHECKPOINT 3: Server-Side reCAPTCHA Anti-Bot Verification Guard
      if (!recaptchaToken) {
        res.status(400).json({ error: "Bad Request", message: "Missing anti-bot token payload." });
        return;
      }

      const isHumanVerified = await validateRecaptcha(recaptchaToken);
      if (!isHumanVerified) {
        res.status(403).json({ error: "Forbidden", message: "Automated activity pattern detected." });
        return;
      }

      // 7. Action Execution: Initialize Nodemailer and Send Email
      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: senderEmail,
          pass: smtpPassword,
        },
      });

      await transporter.sendMail({
        from: `"Portfolio Contact Form" <${senderEmail}>`,
        to: senderEmail,
        replyTo: email,
        subject: `New Message from ${name} via Portfolio`,
        text: `Name: ${name}\nEmail: ${email}\n\nMessage:\n${message}`,
      });

      // 8. Sign Updated Token State and Respond
      emailTimestamps.push(now);
      const updatedToken = jwt.sign(
        { visitorId: decoded.visitorId, timestamps: emailTimestamps },
        JWT_SECRET,
        { expiresIn: "7d" },
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
  }
);