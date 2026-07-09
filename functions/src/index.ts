import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import * as jwt from "jsonwebtoken";
import { randomUUID } from "crypto";

admin.initializeApp();

const JWT_SECRET =
  process.env.JWT_SECRET || "fallback-local-dev-secret-key-12345";
const MAX_REFRESHES_PER_HOUR = 3;
const ONE_HOUR_MS = 60 * 60 * 1000;

interface TokenPayload {
  visitorId: string;
  timestamps: number[];
}

export const handleVisitorSession = functions.https.onRequest(
  async (req, res) => {
    const allowedOrigins = [
      "http://localhost:4000",
      "https://profile-dominiccolumna.firebaseapp.com",
      "https://profile-dominiccolumna.web.app",
    ];

    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
      res.set("Access-Control-Allow-Origin", origin);
    }
    res.set("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") {
      res.set("Access-Control-Allow-Methods", "GET, POST");
      res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
      res.status(204).send("");
      return;
    }

    try {
      let visitorId: string;
      let timestamps: number[] = [];
      let existingToken: string | undefined;

      // 1. Extract standard Bearer Token from headers
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        existingToken = authHeader.split(" ")[1];
      }

      const now = Date.now();

      // 2. Decode token and unpack sliding window telemetry
      if (existingToken) {
        try {
          const decoded = jwt.verify(existingToken, JWT_SECRET) as TokenPayload;
          visitorId = decoded.visitorId;

          // Filter out timestamps older than 1 hour (Sliding Window Core Logic)
          timestamps = (decoded.timestamps || []).filter(
            (ts) => now - ts < ONE_HOUR_MS,
          );
        } catch (err) {
          // Bad or expired token -> Initialize brand new session
          visitorId = randomUUID();
          timestamps = [];
        }
      } else {
        // No token -> Initialize brand new session
        visitorId = randomUUID();
        timestamps = [];
      }

      // 3. Evaluate Rate Limit Threshold
      if (timestamps.length >= MAX_REFRESHES_PER_HOUR) {
        res.status(429).json({
          error: "Too Many Requests",
          message: "Rate limit exceeded. Capped at 50 requests per hour.",
        });
        return;
      }

      // 4. Log the current valid access event into the array
      timestamps.push(now);

      // 5. Pack data back into a refreshed Bearer Token string
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
  },
);
