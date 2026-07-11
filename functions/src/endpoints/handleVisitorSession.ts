import { onRequest } from "firebase-functions/v2/https";
import * as jwt from "jsonwebtoken";
import { randomUUID } from "crypto";
import { Request, Response } from "express";
import { applyCorsMiddleware } from "../utils/cors";

const JWT_SECRET = process.env.JWT_SECRET || "fallback-local-dev-secret-key-12345";
const MAX_REFRESHES_PER_HOUR = 20;
const ONE_HOUR_MS = 60 * 60 * 1000;

interface TokenPayload {
  visitorId: string;
  timestamps: number[];
}

export const handleVisitorSession = onRequest(
  async (req: Request, res: Response) => {
    
    // 1. Execute our clean, separate official CORS middleware handler
    await applyCorsMiddleware(req, res);
    
    // Stop processing if this was an OPTIONS preflight request handled by middleware
    if (req.method === "OPTIONS") return;

    try {
      let visitorId: string;
      let timestamps: number[] = [];
      let existingToken: string | undefined;

      // 2. Extract authorization header if present
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        existingToken = authHeader.split(" ")[1];
      }

      const now = Date.now();

      // 3. Handle existing token validation or issue a fresh visitor identity
      if (existingToken) {
        try {
          const decoded = jwt.verify(existingToken, JWT_SECRET) as TokenPayload;
          visitorId = decoded.visitorId;

          // Filter out timestamps older than one hour
          timestamps = (decoded.timestamps || []).filter(
            (ts) => now - ts < ONE_HOUR_MS,
          );
        } catch (err) {
          // Fallback if the token was tampered with or expired
          visitorId = randomUUID();
          timestamps = [];
        }
      } else {
        // Brand new visitor profile
        visitorId = randomUUID();
        timestamps = [];
      }

      // 4. Rate limiting verification guard
      if (timestamps.length >= MAX_REFRESHES_PER_HOUR) {
        res.status(429).json({
          error: "Too Many Requests",
          message: `Rate limit exceeded. Capped at ${MAX_REFRESHES_PER_HOUR} requests per hour.`,
        });
        return;
      }

      // 5. Commit timestamp and sign a fresh token state
      timestamps.push(now);

      const token = jwt.sign({ visitorId, timestamps }, JWT_SECRET, {
        expiresIn: "7d",
      });

      res.status(200).json({
        status: "authenticated",
        visitorId,
        token,
        requestsRemainingInHour: Math.max(
          0,
          MAX_REFRESHES_PER_HOUR - timestamps.length,
        ),
      });
    } catch (error) {
      console.error("Security pipeline crash:", error);
      res.status(500).send("Internal validation anomaly.");
    }
  }
);