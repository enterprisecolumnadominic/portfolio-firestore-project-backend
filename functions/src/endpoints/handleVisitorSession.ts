import { onRequest } from "firebase-functions/v2/https";
import { defineSecret } from "firebase-functions/params";
import * as jwt from "jsonwebtoken";
import { randomUUID } from "crypto";
import { applyCors } from "../utils/cors";
import { validateRecaptcha, recaptchaSecret } from "../utils/validateRecaptcha";
import { TokenPayload } from "../types/auth";

// 1. Define the secret key parameters via Firebase Secret Manager
const jwtSecret = defineSecret("JWT_SECRET");

const MAX_REFRESHES_PER_HOUR = 20; // Allow 20 page refreshes per hour
const ONE_HOUR_MS = 60 * 60 * 1000;

// 2. Attach all required secrets to the Cloud Function options
export const handleVisitorSession = onRequest(
  { secrets: [jwtSecret, recaptchaSecret] },
  async (req, res) => {
    // Preflight CORS check
    if (applyCors(req, res)) return;

    try {
      // 3. Validate reCAPTCHA token from request body before doing anything else
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

      // 4. Access the JWT secret value securely at runtime
      const secretKey = jwtSecret.value();

      let visitorId: string;
      let sessionTimestamps: number[] = [];
      let emailTimestamps: number[] = [];
      let existingToken: string | undefined;

      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        existingToken = authHeader.split(" ")[1];
      }

      const now = Date.now();

      if (existingToken) {
        try {
          // Verify token using the secret retrieved from Secret Manager
          const decoded = jwt.verify(existingToken, secretKey) as TokenPayload;
          visitorId = decoded.visitorId;

          // Keep email history untouched, filter out timestamps older than 1 hour
          emailTimestamps = (decoded.emailTimestamps || []).filter(
            (ts) => now - ts < ONE_HOUR_MS,
          );
          sessionTimestamps = (decoded.sessionTimestamps || []).filter(
            (ts) => now - ts < ONE_HOUR_MS,
          );
        } catch (err) {
          // Invalid or expired token -> create fresh session
          visitorId = randomUUID();
          sessionTimestamps = [];
          emailTimestamps = [];
        }
      } else {
        visitorId = randomUUID();
        sessionTimestamps = [];
        emailTimestamps = [];
      }

      // Enforce session refresh rate limit
      if (sessionTimestamps.length >= MAX_REFRESHES_PER_HOUR) {
        res.status(429).json({
          error: "Too Many Requests",
          message:
            "Session refresh limit reached. Please try again in an hour.",
        });
        return;
      }

      // Record this session refresh
      sessionTimestamps.push(now);

      // 5. Issue updated JWT signed with the secret key
      const token = jwt.sign(
        { visitorId, sessionTimestamps, emailTimestamps },
        secretKey,
        { expiresIn: "7d" },
      );

      res.status(200).json({
        status: "authenticated",
        visitorId,
        token,
        requestsRemainingInHour: Math.max(
          0,
          MAX_REFRESHES_PER_HOUR - sessionTimestamps.length,
        ),
      });
    } catch (error) {
      console.error("Session handler error:", error);
      res.status(500).send("Internal server error.");
    }
  },
);
