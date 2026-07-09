import * as functions from "firebase-functions";
import * as admin from "firebase-admin";
import * as jwt from "jsonwebtoken";

admin.initializeApp();
const db = admin.firestore();

// Secret encryption key configuration (Set this using firebase functions:config:set jwt.secret="your_secret")
const JWT_SECRET =
  process.env.JWT_SECRET || "fallback-local-dev-secret-key-12345";
const COOKIE_NAME = "visitor_auth";
const MAX_REFRESHES = 100;

export const handleVisitorSession = functions.https.onRequest(
  async (req, res) => {
    // 1. Dynamic CORS handling for multiple origins (No trailing slashes!)
    const allowedOrigins = [
      "http://localhost:4000",
      "https://profile-dominiccolumna.firebaseapp.com",
      "https://profile-dominiccolumna.web.app", // Optional: Firebase's alternative default domain
    ];

    const origin = req.headers.origin;

    // If the incoming request matches an allowed domain, set it explicitly
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

      // 2. Extract existing Cookie payload header string
      const cookiesRaw = req.headers.cookie || "";
      const parsedCookies = Object.fromEntries(
        cookiesRaw.split("; ").map((c) => c.split("=")),
      );
      const existingToken = parsedCookies[COOKIE_NAME];

      if (existingToken) {
        try {
          // Decode JWT token payload
          const decoded = jwt.verify(existingToken, JWT_SECRET) as {
            visitorId: string;
          };
          visitorId = decoded.visitorId;
        } catch (err) {
          // Token corrupted/expired - generate a new fallback ID
          visitorId = admin.firestore().collection("visitors").doc().id;
        }
      } else {
        // No token present - generate initial unique sequence ID
        visitorId = admin.firestore().collection("visitors").doc().id;
      }

      // 3. Security Tracking: Firestore Distributed Rate-Limiter Transaction
      const rateLimitRef = db.collection("visitor_rate_limits").doc(visitorId);

      await db.runTransaction(async (transaction) => {
        const doc = await transaction.get(rateLimitRef);
        const now = Date.now();

        if (!doc.exists) {
          // Create initial security record tracking lifecycle
          transaction.set(rateLimitRef, {
            count: 1,
            createdAt: now,
            lastRefreshedAt: now,
          });
          currentRefreshes = 1;
        } else {
          const data = doc.data()!;

          // Optional: Reset count if older than 24 hours (Window clearance)
          const dayInMs = 24 * 60 * 60 * 1000;
          if (now - data.createdAt > dayInMs) {
            transaction.update(rateLimitRef, {
              count: 1,
              createdAt: now,
              lastRefreshedAt: now,
            });
            currentRefreshes = 1;
          } else {
            // Increment tracking iteration count inside window
            currentRefreshes = data.count + 1;
            transaction.update(rateLimitRef, {
              count: currentRefreshes,
              lastRefreshedAt: now,
            });
          }
        }
      });

      // 4. Rate-Limiting Threshold Evaluation
      if (currentRefreshes > MAX_REFRESHES) {
        res.status(429).json({
          error: "Too many requests.",
          message:
            "Security threshold exceeded. Refresh allowance capped at 100.",
        });
        return;
      }

      // 5. Build fresh signed JWT token
      const token = jwt.sign({ visitorId }, JWT_SECRET, { expiresIn: "7d" });

      // 6. Serialize and set HttpOnly cookie
      // HttpOnly prevents client-side XSS malicious scripts from reading the identity key
      res.cookie(COOKIE_NAME, token, {
        httpOnly: true,
        secure: true, // Requires HTTPS (Crucial for production deployment architectures)
        sameSite: "none", // Crucial across serverless vs front-end origin splits
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days matching token validation footprint
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
