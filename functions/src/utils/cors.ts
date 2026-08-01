<<<<<<< HEAD
import cors from "cors";
import {Request, Response} from "express";
=======
import { Request, Response } from "express";
>>>>>>> 11a332a (updated the function to v2 and improve api calls)

const ALLOWED_ORIGINS = [
  "http://localhost:4000",
  "https://profile-dominiccolumna.firebaseapp.com",
  "https://profile-dominiccolumna.web.app",
];

// Configure the official cors handler package instance
const corsHandler = cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (like server-to-server or curl)
    // or matching portfolio domains
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

/**
<<<<<<< HEAD
 * Express middleware wrapper to apply standard CORS configurations.
 * @param {Request} req - The incoming Express request object.
 * @param {Response} res - The outgoing Express response object.
 * @return {Promise<void>} Resolves when the CORS processing finishes.
 */
export function applyCorsMiddleware(
  req: Request,
  res: Response
): Promise<void> {
  return new Promise((resolve) => {
    corsHandler(req, res, () => {
      resolve();
    });
  });
=======
 * Handles CORS configurations and preflight OPTIONS requests.
 *
 * @param req - Incoming Express Request object from Firebase v2 HTTP trigger
 * @param res - Express Response object used to set headers
 * @returns boolean - True if request was an OPTIONS preflight, false otherwise
 */
export function applyCors(req: Request, res: Response): boolean {
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
>>>>>>> 11a332a (updated the function to v2 and improve api calls)
}
