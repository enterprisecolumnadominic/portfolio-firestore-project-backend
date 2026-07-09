import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import * as jwt from "jsonwebtoken";

admin.initializeApp();
const db = admin.firestore();

const JWT_SECRET =
  process.env.JWT_SECRET || "fallback-local-dev-secret-key-12345";
const COOKIE_NAME = "visitor_auth";
const MAX_REFRESHES = 100;

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
      let currentRefreshes = 0;

      const cookiesRaw = req.headers.cookie || "";
      const parsedCookies = Object.fromEntries(
        cookiesRaw.split("; ").map((c) => c.split("=")),
      );
      const existingToken = parsedCookies[COOKIE_NAME];

      if (existingToken) {
        try {
          // eslint-disable-next-line object-curly-spacing
          const decoded = jwt.verify(existingToken, JWT_SECRET) as {
            visitorId: string;
          };
          visitorId = decoded.visitorId;
        } catch (err) {
          visitorId = admin.firestore().collection("visitors").doc().id;
        }
      } else {
        visitorId = admin.firestore().collection("visitors").doc().id;
      }

      const rateLimitRef = db.collection("visitor_rate_limits").doc(visitorId);

      await db.runTransaction(async (transaction) => {
        const doc = await transaction.get(rateLimitRef);
        const now = Date.now();

        if (!doc.exists) {
          transaction.set(rateLimitRef, {
            count: 1,
            createdAt: now,
            lastRefreshedAt: now,
          });
          currentRefreshes = 1;
        } else {
          const data = doc.data();
          if (data) {
            const dayInMs = 24 * 60 * 60 * 1000;
            if (now - data.createdAt > dayInMs) {
              transaction.update(rateLimitRef, {
                count: 1,
                createdAt: now,
                lastRefreshedAt: now,
              });
              currentRefreshes = 1;
            } else {
              currentRefreshes = data.count + 1;
              transaction.update(rateLimitRef, {
                count: currentRefreshes,
                lastRefreshedAt: now,
              });
            }
          }
        }
      });

      if (currentRefreshes > MAX_REFRESHES) {
        res.status(429).json({
          error: "Too many requests.",
          message: "Refresh allowance capped at 100.",
        });
        return;
      }

      // eslint-disable-next-line object-curly-spacing
      const token = jwt.sign({ visitorId }, JWT_SECRET, { expiresIn: "7d" });

      res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });

      res.status(200).json({
        status: "authenticated",
        visitorId,
        refreshesRemaining: Math.max(0, MAX_REFRESHES - currentRefreshes),
      });
    } catch (error) {
      console.error("Security pipeline crash:", error);
      res.status(500).send("Internal validation anomaly.");
    }
  },
);
