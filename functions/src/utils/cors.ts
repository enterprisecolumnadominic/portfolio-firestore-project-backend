import * as functions from "firebase-functions";
import { Response } from "express"; // Import the clean Express type directly

const ALLOWED_ORIGINS = [
  "http://localhost:4000",
  "https://profile-dominiccolumna.firebaseapp.com",
  "https://profile-dominiccolumna.web.app",
];

export function applyCors(
  req: functions.https.Request,
  res: Response,
): boolean {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.set("Access-Control-Allow-Origin", origin);
  }
  res.set("Access-Control-Allow-Credentials", "true");

  if (req.method === "OPTIONS") {
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
    res.status(204).send("");
    return true; // Handled the preflight request
  }

  return false; // Not an OPTIONS request, proceed with execution
}
