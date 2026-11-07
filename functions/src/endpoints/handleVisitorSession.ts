import {onRequest} from "firebase-functions/v2/https";
import {defineSecret} from "firebase-functions/params";
import * as jwt from "jsonwebtoken";
import * as crypto from "crypto";

const jwtSecret = defineSecret("JWT_SECRET");

const MAX_REQUESTS = 20;

export const handleVisitorSession = onRequest(
  {secrets: [jwtSecret]},
  async (req, res) => {
    // 1. Handle CORS Preflight
    res.set("Access-Control-Allow-Origin", "*");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    if (req.method === "OPTIONS") {
      res.status(204).send("");
      return;
    }

    const secretKey = jwtSecret.value();
    const authHeader = req.headers.authorization;

    // 2. If user already has a token, verify and increment the counter
    if (authHeader && authHeader.startsWith("Bearer ")) {
      const existingToken = authHeader.split(" ")[1];
      try {
        const decoded: any = jwt.verify(existingToken, secretKey);

        const usedRequests: number = decoded.usedRequests ?? 0;
        const newUsedRequests = usedRequests + 1;
        const remaining = MAX_REQUESTS - newUsedRequests;

        if (remaining < 0) {
          res.status(429).json({success: false, error: "Rate limit exceeded"});
          return;
        }

        // Re-sign a new token carrying the updated counter,
        // preserving the original expiry by keeping the same createdAt
        const updatedToken = jwt.sign(
          {
            visitorId: decoded.visitorId,
            createdAt: decoded.createdAt,
            usedRequests: newUsedRequests,
            emailsSent: decoded.emailsSent ?? 0,
            emailWindowStart: decoded.emailWindowStart,
          },
          secretKey,
          {expiresIn: "1h"}
        );

        res.status(200).json({
          message: "Session verified",
          token: updatedToken, // ← client must save this new token
          requestsRemainingInHour: remaining,
        });
        return;
      } catch (err) {
        // Token expired/invalid, fall through to issue a fresh one
      }
    }

    // 3. Issue a new visitor token with counter starting at 0
    const newToken = jwt.sign(
      {
        visitorId: crypto.randomUUID(),
        createdAt: Date.now(),
        usedRequests: 0,
      },
      secretKey,
      {expiresIn: "1h"}
    );

    res.status(200).json({
      message: "New session created",
      token: newToken,
      requestsRemainingInHour: MAX_REQUESTS,
    });
  }
);
