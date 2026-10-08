# Attendance Tracker — Email OTP Login

This version keeps the existing attendance tracker and adds a server-side OTP login.

## Files

- `index.html` — login page + attendance tracker UI
- `script.js` — attendance logic + OTP login flow
- `style.css` — tracker and login styling
- `server.js` — Express backend, OTP generation/verification, session cookie, Resend email sending
- `package.json` — Node dependencies
- `.env.example` — environment-variable template
- `.gitignore` — keeps the private `.env` and `node_modules` out of Git


## Deploy on Render

This project is a **Node/Express Web Service**, not a Static Site, because OTP login uses server-side `/api/*` routes.

In Render create **New → Web Service** and use:

- **Root Directory:** `attendance_tracker_resend_otp` if this folder is inside a larger repository; otherwise leave blank.
- **Runtime:** Node
- **Build Command:** `npm ci`
- **Start Command:** `npm start`
- **Health Check Path:** `/health`

Add these environment variables in Render (do **not** upload `.env`):

- `RESEND_API_KEY` — your Resend API key
- `RESEND_FROM` — a sender allowed by Resend (for testing, `Attendance Tracker <onboarding@resend.dev>` if your Resend account allows it; production should use a verified domain)
- `ADMIN_EMAIL` — your email address that should receive verified student details and attendance reports
- `SESSION_SECRET` — a long random secret, at least 32 characters

Render web services must listen on `0.0.0.0` and the Render `PORT`; this server already does both.

If you previously exposed the API key from `.env` to GitHub or anywhere public, revoke/rotate that Resend key and create a new one.

Students enter their phone number and email address. The phone number is stored with their account details, while the OTP is sent to the student email address using Resend. After successful verification, the submitted name, roll number, phone number and email are emailed to `ADMIN_EMAIL`.

## Setup

1. Install Node.js 18 or newer.
2. Open a terminal in this folder.
3. Run:

   `npm install`

4. Copy `.env.example` to a new file named `.env`.
5. Put your Resend API key in `.env`:

   `RESEND_API_KEY=re_...`

6. Keep the sender as `onboarding@resend.dev` for initial testing if your Resend account permits it. For production sending, verify a domain in Resend and change `RESEND_FROM` to that verified sender.
7. Create a long random value for `SESSION_SECRET`.
8. Start the app:

   `npm start`

9. Open `http://localhost:3000`.


## Local OTP testing

When running locally (without `NODE_ENV=production`), the server prints every generated OTP in the VS Code terminal. This is intentional for development and lets you test the login flow even when Resend email delivery is not configured yet.

Example terminal output:

```text
[LOCAL OTP DEBUG] Student Name (ROLL123) -> 123456
```

If Resend rejects the email while running locally, the server keeps the OTP challenge active so you can enter the terminal OTP and continue testing. Render is configured with `NODE_ENV=production`, so OTPs are not printed there and Resend failures remain errors.

## OTP behavior

- OTP is generated on the server with a cryptographically secure random generator.
- OTP is stored only as a SHA-256 hash.
- OTP expires after 60 seconds.
- A challenge is limited to 5 verification attempts.
- A new OTP request is rate-limited to once every 30 seconds per client IP.
- Successful verification creates an HttpOnly session cookie.
- The Resend API key is never sent to the browser.

## Important

The attendance records remain in browser `localStorage`, just as in the original tracker. The OTP protects access to the web interface, but it does not turn localStorage into a server-side multi-user database.

For a production multi-user system, move attendance records to a database and associate them with the authenticated user.

## Email OTP setup

This version keeps the phone-number field but sends the login OTP to the student's email address using Resend. After successful verification, the student's submitted details are emailed to `ADMIN_EMAIL`. The attendance report is also emailed when the tracker sends its report.

Required environment variables: `RESEND_API_KEY`, `RESEND_FROM`, `ADMIN_EMAIL`, and `SESSION_SECRET`.
