import * as functions from "firebase-functions";

export const helloWorld = functions.https.onRequest((req, res) => {
  res.status(200).send("Hello from Firebase and GitHub Actions!");
});