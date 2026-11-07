import {onRequest} from "firebase-functions/v2/https";
import {defineSecret} from "firebase-functions/params";
import * as jwt from "jsonwebtoken";
import * as nodemailer from "nodemailer";

const jwtSecret = defineSecret("JWT_SECRET");
const smtpEmailSecret = defineSecret("SMTP_EMAIL");
const smtpPasswordSecret = defineSecret("SMTP_PASSWORD");

const MAX_EMAILS = 3;
const WINDOW_MS = 2 * 60 * 60 * 1000; // 2 hours

export const sendEmailViaSmtp = onRequest(
  {secrets: [jwtSecret, smtpEmailSecret, smtpPasswordSecret]},
  async (req, res) => {
    // 1. Handle CORS Preflight
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    if (req.method === "OPTIONS") {
      res.status(204).send("");
      return;
    }

    try {
      const secretKey = jwtSecret.value();
      const authHeader = req.headers.authorization;

      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        res.status(401).json({success: false, error: "Unauthorized: Missing token"});
        return;
      }

      const token = authHeader.split(" ")[1];
      let decoded: any;

      try {
        decoded = jwt.verify(token, secretKey);
      } catch (err) {
        res.status(401).json({success: false, error: "Invalid or expired session token"});
        return;
      }

      // 2. Check 2-hour email window and usage count
      // 2. Check 2-hour email window and usage count
      const now = Date.now();
      let windowStart = decoded.emailWindowStart || decoded.createdAt || now;
      let emailsSent = decoded.emailsSent || 0;

      if (now - windowStart > WINDOW_MS) {
        // Reset window if 2 hours have passed
        windowStart = now;
        emailsSent = 0;
      }

      if (emailsSent >= MAX_EMAILS) {
        res.status(429).json({
          success: false,
          error: "Rate limit exceeded: You can only send up to 3 emails per 2 hours.",
        });
        return;
      }

      // 3. Extract request body
      const {name, email, message} = req.body;
      if (!name || !email || !message) {
        res.status(400).json({success: false, error: "Missing required fields"});
        return;
      }

      // 4. Send Email via Nodemailer
      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: smtpEmailSecret.value(),
          pass: smtpPasswordSecret.value(),
        },
      });

      await transporter.sendMail({
        from: `"${name}" <${email}>`,
        to: smtpEmailSecret.value(),
        subject: `Portfolio Contact Form: Message from ${name}`,
        text: `From: ${name} (${email})\n\nMessage:\n${message}`,
      });

      // 5. Increment email count and issue an updated token preserving the window state
      emailsSent += 1;
      const updatedToken = jwt.sign(
        {
          visitorId: decoded.visitorId,
          createdAt: decoded.createdAt,
          usageCount: decoded.usageCount,
          emailWindowStart: windowStart,
          emailsSent: emailsSent,
        },
        secretKey,
        {expiresIn: "2h"}
      );

      res.status(200).json({
        success: true,
        message: "Email sent successfully",
        token: updatedToken,
        emailsRemainingInWindow: MAX_EMAILS - emailsSent,
      });
    } catch (error: any) {
      console.error("Mail dispatch error:", error);
      res.status(500).json({success: false, error: error.message || "Internal server error"});
    }
  }
);
