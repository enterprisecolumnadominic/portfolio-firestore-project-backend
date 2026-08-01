/**
 * Shared JWT Token Payload structure carried across both endpoints
 */
export interface TokenPayload {
  visitorId: string;
  sessionTimestamps?: number[];
  emailTimestamps?: number[];
}
