import * as functions from "firebase-functions";
import {Response} from "express";

const ALLOWED_ORIGINS = [
  "http://localhost:4000",
  "https://profile-dominiccolumna.firebaseapp.com",
  "https://profile-dominiccolumna.web.app",
];

/**
 * Handles CORS configurations and preflight requests.
 * @param {functions.https.Request} req - Incoming Firebase HTTPS request.
 * @param {Response} res - Express response object used to set headers.
 * @return {boolean} True if OPTIONS preflight request, false otherwise.
 */
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
    return true;
  }

  return false;
}
