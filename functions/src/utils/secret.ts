import {defineSecret} from "firebase-functions/params";

export const jwtSecret = defineSecret("JWT_SECRET");
