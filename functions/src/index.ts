import * as admin from "firebase-admin";

// Initialize core Firebase Admin instance once globally during warm-up phase
admin.initializeApp();

// Import individual v2 serverless endpoints
import {handleVisitorSession} from "./endpoints/handleVisitorSession";
import {sendEmailViaSmtp} from "./endpoints/sendEmailViaSmtp";

// Export endpoints for Firebase Cloud Functions v2 registration
export {handleVisitorSession, sendEmailViaSmtp};
