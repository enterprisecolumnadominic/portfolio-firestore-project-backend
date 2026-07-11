import cors from "cors";
import { Request, Response } from "express";

const ALLOWED_ORIGINS = [
  "http://localhost:4000",
  "https://profile-dominiccolumna.firebaseapp.com",
  "https://profile-dominiccolumna.web.app",
];

// Configure the official cors handler package instance
const corsHandler = cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like server-to-server or curl) or matching portfolio domains
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Blocked by secure CORS configuration."));
    }
  },
  credentials: true,
  methods: ["POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
});


export function applyCorsMiddleware(req: Request, res: Response): Promise<void> {
  return new Promise((resolve) => {
    corsHandler(req, res, () => {
      resolve();
    });
  });
}