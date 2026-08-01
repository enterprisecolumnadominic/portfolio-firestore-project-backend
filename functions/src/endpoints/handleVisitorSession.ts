import {onRequest} from "firebase-functions/v2/https";
import * as jwt from "jsonwebtoken";
import {randomUUID} from "crypto";
import {applyCors} from "../utils/cors";
import {TokenPayload} from "../types/auth";

const JWT_SECRET =
  process.env.JWT_SECRET || "fallback-local-dev-secret-key-12345";
const MAX_REFRESHES_PER_HOUR = 20; // Allow 20 page refreshes per hour
const ONE_HOUR_MS = 60 * 60 * 1000;

export const handleVisitorSession = onRequest(async (req, res) => {
  // 1. Preflight CORS check
  if (applyCors(req, res)) return;

  try {
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
        const decoded = jwt.verify(existingToken, JWT_SECRET) as TokenPayload;
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

    // 2. Enforce session refresh rate limit
    if (sessionTimestamps.length >= MAX_REFRESHES_PER_HOUR) {
      res.status(429).json({
        error: "Too Many Requests",
        message: "Session refresh limit reached. Please try again in an hour.",
      });
      return;
    }

    // Record this session refresh
    sessionTimestamps.push(now);

    // 3. Issue updated JWT containing both independent arrays
    const token = jwt.sign(
      {visitorId, sessionTimestamps, emailTimestamps},
      JWT_SECRET,
      {expiresIn: "7d"},
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
});
