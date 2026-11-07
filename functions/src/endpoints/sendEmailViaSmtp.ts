import { onRequest } from "firebase-functions/v2/https";
import { defineSecret } from "firebase-functions/params";
import * as jwt from "jsonwebtoken";
import * as nodemailer from "nodemailer";
import { applyCors } from "../utils/cors";
import { validateRecaptcha, recaptchaSecret } from "../utils/validateRecaptcha";
import { TokenPayload } from "../types/auth";

// 1. Declare all required secrets via Firebase Cloud Secret Manager
const jwtSecret = defineSecret("JWT_SECRET");
const smtpEmailSecret = defineSecret("SMTP_EMAIL");
const smtpPasswordSecret = defineSecret("SMTP_PASSWORD");

const MAX_EMAILS_PER_HOUR = 3; // Limit: max 3 emails per hour
const ONE_HOUR_MS = 60 * 60 * 1000;

interface EmailRequestBody {
  name: string;
  email: string;
  message: string;
  recaptchaToken: string;
}

export const sendEmailViaSmtp = onRequest(
  {
    secrets: [jwtSecret, smtpEmailSecret, smtpPasswordSecret, recaptchaSecret],
  },
  async (req, res) => {
    // Apply CORS preflight check
    if (applyCors(req, res)) return;

    try {
      // 2. Validate reCAPTCHA token before processing anything else
      const recaptchaToken = req.body?.recaptchaToken;
      if (!recaptchaToken) {
        res.status(403).json({
          error: "Forbidden",
          message: "Missing reCAPTCHA token.",
        });
        return;
      }

      const isHuman = await validateRecaptcha(recaptchaToken);
      if (!isHuman) {
        res.status(403).json({
          error: "Forbidden",
          message:
            "reCAPTCHA verification failed. Request rejected as potential bot traffic.",
        });
        return;
      }

      // 3. Safely retrieve secret values as guaranteed strings
      const secretKey = jwtSecret.value() || process.env.JWT_SECRET || "";
      const senderEmail =
        smtpEmailSecret.value() || process.env.SMTP_EMAIL || "";
      const smtpPassword =
        smtpPasswordSecret.value() || process.env.SMTP_PASSWORD || "";

      if (!secretKey || !senderEmail || !smtpPassword) {
        console.error("Missing cloud environment secrets.");
        res.status(500).json({
          error: "Internal Server Error",
          message: "Server environment secret configuration is missing.",
        });
        return;
      }

      // 4. Verify Authorization Header & Session Token
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res.status(401).json({
          error: "Unauthorized",
          message: "Missing session token.",
        });
        return;
      }

      const tokenString = authHeader.split(" ")[1];
      let decoded: TokenPayload;

      try {
        // Double cast (as unknown as TokenPayload) prevents TS2352 compiler error
        decoded = jwt.verify(tokenString, secretKey) as unknown as TokenPayload;
      } catch (err) {
        res.status(403).json({
          error: "Forbidden",
          message: "Invalid or expired session token.",
        });
        return;
      }

      // 5. Rate-limiting check: Filter email timestamps within the past hour
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

      // 6. Validate form body inputs
      const { name, email, message } = req.body as EmailRequestBody;
      if (!name || !email || !message) {
        res.status(400).json({
          error: "Bad Request",
          message: "All fields (name, email, message) are required.",
        });
        return;
      }

      // 7. Configure Nodemailer transport & send mail
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

      // 8. Update timestamp list and issue a refreshed JWT
      emailTimestamps.push(now);

      const updatedToken = jwt.sign(
        {
          visitorId: decoded.visitorId,
          sessionTimestamps: decoded.sessionTimestamps || [],
          emailTimestamps,
        },
        secretKey,
        { expiresIn: "1d" },
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
