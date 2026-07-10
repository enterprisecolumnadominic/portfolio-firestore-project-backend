import * as admin from "firebase-admin";

// Initialize core Firebase Admin instance once globally
admin.initializeApp();

// Import individual serverless endpoints from your source tree
import {handleVisitorSession} from "./endpoints/handleVisitorSession";
import {sendEmailViaSmtp} from "./endpoints/sendEmailViaSmtp";

// Export them so Firebase Cloud can register and expose them via URLs
export {handleVisitorSession, sendEmailViaSmtp};
