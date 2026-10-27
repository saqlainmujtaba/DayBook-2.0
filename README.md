# Daybook Next.js

This folder contains the complete Daybook Next.js App Router app. The UI and API now run in Next.js route handlers; there is no Python runtime or separate API service dependency. The API uses the same MongoDB collections and document formats as the original Python service, so it can work with the existing Daybook database.

## Run locally

1. Copy `.env.example` to `.env.local` and set `MONGODB_URI` to your MongoDB Atlas connection string. `MONGODB_DB` defaults to `daybook`.
2. For email registration, configure `SMTP_EMAIL`, `SMTP_APP_PASSWORD`, and a private `OTP_SECRET` with at least 32 characters. For Google and phone sign-in, set the four Firebase web app values.
3. Install Node.js 20.9+ and run:

   ```powershell
   npm install
   npm run dev
   ```

4. Open <http://localhost:3000>.

The Next.js API provides email OTP registration, password sign-in, Google and phone verification, HTTP-only sessions, prayer and Quran record storage, profile updates, export, and reset. Database, mail, OTP, and Firebase settings are read only by the server.

## Deploy

Deploy this folder as the Next.js project root and configure the environment variables from `.env.example` in the hosting provider. No Python deployment is required.
