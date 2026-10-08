# Attendance Tracker — Gmail SMTP Email OTP

This version keeps the existing attendance tracker and uses Gmail SMTP for OTP email and administrator email. No Resend account or custom domain is required.

## Files

- `index.html` — login page + attendance tracker UI
- `script.js` — attendance logic + OTP login flow
- `style.css` — tracker and login styling
- `server.js` — Express backend, OTP generation/verification, session cookie, Gmail SMTP email sending
- `package.json` — Node dependencies
- `.env.example` — environment-variable template
- `.gitignore` — keeps the private `.env` and `node_modules` out of Git

## Gmail setup

Gmail SMTP uses an **App Password**, not your normal Gmail password. Google requires 2-Step Verification to be enabled before an App Password can be created.

1. Sign in to the Gmail account that will send the emails.
2. Turn on Google 2-Step Verification if it is not already enabled.
3. Open your Google Account's **App Passwords** page.
4. Create a new App Password for this attendance tracker.
5. Google will show a 16-character App Password. Copy it once and keep it private.
6. Do not put the normal Gmail password in the project.

## Deploy on Render

This project is a **Node/Express Web Service**, not a Static Site.

In Render create **New → Web Service** and use:

- **Runtime:** Node
- **Branch:** `main`
- **Build Command:** `npm ci`
- **Start Command:** `npm start`
- **Health Check Path:** `/health`
- **Plan:** Free

Add these environment variables in Render. Do not upload `.env`.

- `GMAIL_USER` — the Gmail account used to send OTP emails, for example `yourname@gmail.com`
- `GMAIL_APP_PASSWORD` — the 16-character Google App Password, without spaces
- `ADMIN_EMAIL` — the Gmail address that should receive verified student details and attendance reports
- `SESSION_SECRET` — a long random secret, at least 32 characters

Do **not** add `PORT`; Render supplies it automatically.

Do **not** add `RESEND_API_KEY`, `RESEND_FROM`, `OTP_EMAIL`, or MSG91 variables.

## Email flow

1. Student enters name, roll number, phone number, and email.
2. The server creates a 6-digit OTP.
3. Gmail SMTP sends the OTP to the student's entered email address.
4. The page displays a message such as `OTP sent to xx***@gmail.com. Please check your inbox.`
5. Student enters the OTP.
6. After successful verification, the server sends the student's complete submitted details to `ADMIN_EMAIL`.
7. The attendance tracker opens for the verified student.
8. When the attendance report is sent, the report is also emailed to `ADMIN_EMAIL`.

## Local setup

1. Install Node.js 18 or newer.
2. Open a terminal in this folder.
3. Run:

   `npm install`

4. Copy `.env.example` to `.env`.
5. Fill in the four Gmail/session variables.
6. Start the app:

   `npm start`

7. Open `http://localhost:3000`.

When running locally without `NODE_ENV=production`, the server prints the generated OTP in the terminal as a development aid. Render is normally configured as production, so OTPs are not printed there.

## OTP security

- OTPs are generated with Node's cryptographically secure random generator.
- Only a SHA-256 hash of the OTP is stored.
- OTPs expire after 60 seconds.
- A challenge allows at most 5 incorrect attempts.
- New OTP requests are rate-limited to once every 30 seconds per client IP.
- Successful verification creates an HttpOnly session cookie.
- Gmail credentials are never sent to the browser.

## Important

Attendance records remain in browser `localStorage`, as in the original tracker. OTP verification protects access to the web interface, but attendance data is not stored in a server-side database.
