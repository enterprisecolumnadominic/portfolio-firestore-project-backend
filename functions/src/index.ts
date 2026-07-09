import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import * as jwt from "jsonwebtoken";
import { randomUUID } from "crypto";

admin.initializeApp();

const JWT_SECRET =
  process.env.JWT_SECRET || "fallback-local-dev-secret-key-12345";

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

    // Adjusting CORS headers to allow standard Authorization Bearer headers
    res.set("Access-Control-Allow-Credentials", "true");

    if (req.method === "OPTIONS") {
      res.set("Access-Control-Allow-Methods", "GET, POST");
      res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
      res.status(204).send("");
      return;
    }

    try {
      let visitorId: string;
      let existingToken: string | undefined;

      // 1. Extract the token from the "Authorization: Bearer <token>" header
      const authHeader = req.headers.authorization;
      if (authHeader && authHeader.startsWith("Bearer ")) {
        existingToken = authHeader.split(" ")[1];
      }

      // 2. Verify or Generate the identity statelessly
      if (existingToken) {
        try {
          // eslint-disable-next-line object-curly-spacing
          const decoded = jwt.verify(existingToken, JWT_SECRET) as {
            visitorId: string;
          };
          visitorId = decoded.visitorId;
        } catch (err) {
          // Token is expired or invalid -> Issue a fresh one
          visitorId = randomUUID();
        }
      } else {
        // No Bearer token provided -> Brand new visitor
        visitorId = randomUUID();
      }

      // 3. Sign a fresh token
      // eslint-disable-next-line object-curly-spacing
      const token = jwt.sign({ visitorId }, JWT_SECRET, { expiresIn: "7d" });

      // 4. Return the token directly in the JSON response payload
      res.status(200).json({
        status: "authenticated",
        visitorId,
        token, // Your frontend will grab this token string and save it
      });
    } catch (error) {
      console.error("Security pipeline crash:", error);
      res.status(500).send("Internal validation anomaly.");
    }
  },
);
