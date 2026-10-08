import express from 'express';
import dotenv from 'dotenv';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const BREVO_API_KEY = process.env.BREVO_API_KEY;
const BREVO_SENDER_EMAIL = process.env.BREVO_SENDER_EMAIL;
const BREVO_SENDER_NAME = process.env.BREVO_SENDER_NAME || 'Attendance Tracker';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

// Local development: print the OTP in the terminal so email delivery is not
// required just to test the login flow. Render is marked as production below.
const OTP_DEBUG = !IS_PRODUCTION;

if (!BREVO_API_KEY || !BREVO_SENDER_EMAIL || !SESSION_SECRET || !ADMIN_EMAIL) {
  console.warn('\nMissing one or more required environment variables: BREVO_API_KEY, BREVO_SENDER_EMAIL, ADMIN_EMAIL or SESSION_SECRET.\n');
}

if (SESSION_SECRET && SESSION_SECRET.length < 32) {
  console.warn('\nSESSION_SECRET is short. Use a random 64-character value (see README).\n');
}

const challenges = new Map();
const sessions = new Map();
const requestCooldown = new Map();

// Brevo Free allows 300 email sends per day. This counter is intentionally
// kept in memory so the app can warn/block before making another API call.
// It resets at midnight IST. Brevo remains the final authority on delivery.
const DAILY_EMAIL_LIMIT = 300;
const EMAIL_WARNING_1 = 250;
const EMAIL_WARNING_2 = 280;

let emailUsage = { date: istDateKey(), sent: 0 };

app.disable('x-powered-by');

app.set('trust proxy', 1);

app.use(express.json({ limit: '20kb' }));

// Serve ONLY the three public front-end files.
const PUBLIC_FILES = {
  '/': 'index.html',
  '/index.html': 'index.html',
  '/script.js': 'script.js',
  '/style.css': 'style.css'
};

app.get(Object.keys(PUBLIC_FILES), (req, res) => {
  res.sendFile(path.join(__dirname, PUBLIC_FILES[req.path]));
});

// Render health check endpoint.
app.get('/health', (req, res) => {
  res.status(200).json({ ok: true });
});

function cleanText(value, max) {
  return String(value ?? '')
    .trim()
    .replace(/[<>]/g, '')
    .slice(0, max);
}

function hashOtp(otp) {
  return crypto
    .createHash('sha256')
    .update(otp)
    .digest('hex');
}

function newToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function signSession(sessionId) {
  const signature = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(sessionId)
    .digest('hex');

  return `${sessionId}.${signature}`;
}

function verifySessionToken(token) {
  if (!token || !SESSION_SECRET) return null;

  const dot = token.lastIndexOf('.');

  if (dot < 1) return null;

  const sessionId = token.slice(0, dot);
  const signature = token.slice(dot + 1);

  const expected = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(sessionId)
    .digest('hex');

  if (signature.length !== expected.length) return null;

  if (
    !crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    )
  ) {
    return null;
  }

  return sessionId;
}

function getCookie(req, name) {
  const raw = req.headers.cookie || '';

  const pair = raw
    .split(';')
    .map(x => x.trim())
    .find(x => x.startsWith(`${name}=`));

  return pair
    ? decodeURIComponent(pair.slice(name.length + 1))
    : '';
}

function setSessionCookie(res, token) {
  const forwardedProto = String(
    res.req?.headers?.['x-forwarded-proto'] || ''
  )
    .split(',')[0]
    .trim();

  const secure =
    res.req?.secure ||
    forwardedProto === 'https' ||
    process.env.NODE_ENV === 'production'
      ? '; Secure'
      : '';

  res.setHeader(
    'Set-Cookie',
    `attendance_session=${encodeURIComponent(
      token
    )}; HttpOnly; Path=/; SameSite=Lax; Max-Age=86400${secure}`
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    'Set-Cookie',
    'attendance_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0'
  );
}

function authenticatedUser(req) {
  const token = getCookie(req, 'attendance_session');
  const sessionId = verifySessionToken(token);

  if (!sessionId) return null;

  const session = sessions.get(sessionId);

  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(sessionId);
    return null;
  }

  return session;
}

function cleanup() {
  const now = Date.now();

  for (const [id, c] of challenges) {
    if (c.expiresAt < now) {
      challenges.delete(id);
    }
  }

  for (const [id, s] of sessions) {
    if (s.expiresAt < now) {
      sessions.delete(id);
    }
  }

  for (const [ip, t] of requestCooldown) {
    if (t + 30_000 < now) {
      requestCooldown.delete(ip);
    }
  }
}

setInterval(cleanup, 30_000).unref();


// ============================================================
// SEND OTP
// ============================================================

app.post('/api/send-otp', async (req, res) => {
  if (
    !BREVO_API_KEY ||
    !BREVO_SENDER_EMAIL ||
    !SESSION_SECRET ||
    !ADMIN_EMAIL
  ) {
    return res.status(500).json({
      error:
        'Server is not configured. Add BREVO_API_KEY, BREVO_SENDER_EMAIL, ADMIN_EMAIL and SESSION_SECRET.'
    });
  }

  const usageBeforeSend = getEmailUsage();

  if (usageBeforeSend.sent >= DAILY_EMAIL_LIMIT) {
    return res.status(429).json({
      error: `🚫 Daily email limit reached (${DAILY_EMAIL_LIMIT}/${DAILY_EMAIL_LIMIT}). New OTP emails cannot be sent right now. Please try again after today’s Brevo limit resets.`,
      emailUsage: usageBeforeSend
    });
  }

  const ip = req.ip || 'unknown';
  const lastRequest = requestCooldown.get(ip) || 0;

  if (Date.now() - lastRequest < 30_000) {
    return res.status(429).json({
      error: 'Please wait 30 seconds before requesting another OTP.'
    });
  }

  const name = cleanText(req.body?.name, 80);
  const rollNumber = cleanText(req.body?.rollNumber, 40);
  const phoneRaw = cleanText(req.body?.phone, 20);
  const phone = normalizeIndianPhone(phoneRaw);
  const email = cleanEmail(req.body?.email);

  if (
    name.length < 2 ||
    rollNumber.length < 1 ||
    !phone ||
    !email
  ) {
    return res.status(400).json({
      error:
        'Enter a valid name, roll number, 10-digit Indian phone number and email address.'
    });
  }

  const otp = String(
    crypto.randomInt(100000, 1000000)
  );

  const challengeId = newToken(24);

  if (OTP_DEBUG) {
    console.log(
      `\n[LOCAL OTP DEBUG] ${name} (${rollNumber}, ${phone}, ${email}) -> ${otp}\n`
    );
  }

  challenges.set(challengeId, {
    otpHash: hashOtp(otp),
    name,
    rollNumber,
    phone,
    email,

    // OTP VALID FOR 2 MINUTES
    expiresAt: Date.now() + 120_000,

    attempts: 0
  });

  requestCooldown.set(ip, Date.now());

  try {
    // Put the warning INSIDE the normal OTP email when we are approaching
    // the daily limit. This does not create another email.
    const projectedSendCount =
      getEmailUsage().sent + 1;

    const emailWarning =
      emailLimitWarning(projectedSendCount);

    const warningHtml = emailWarning
      ? `<div style="margin-top:18px;padding:14px 16px;border-radius:10px;background:#fff7ed;border:1px solid #fed7aa;color:#9a3412"><strong>${escapeHtml(
          emailWarning
        )}</strong></div>`
      : '';

    await sendBrevoEmail({
      to: email,
      subject: 'Attendance Tracker - Your OTP',

      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:28px;color:#172033;background:#ffffff">

          <h2 style="margin:0 0 14px">
            Attendance Tracker — OTP Verification
          </h2>

          <p>Hello ${escapeHtml(name)},</p>

          <p>Your verification OTP is:</p>

          <div style="font-size:30px;font-weight:800;letter-spacing:8px;text-align:center;padding:18px;background:#f4f7fb;border-radius:12px">
            ${otp}
          </div>

          <p>
            This OTP expires in <strong>2 minutes</strong>.
            If you did not request it, you can ignore this email.
          </p>

          ${warningHtml}

        </div>
      `
    });

    const usage = getEmailUsage();
    const warning = emailLimitWarning(usage.sent);

    return res.json({
      success: true,
      challengeId,

      // FRONTEND COUNTDOWN = 2 MINUTES
      expiresIn: 120,

      message: warning
        ? `OTP sent to ${maskEmail(
            email
          )}. Please check your inbox.\n\n${warning}`
        : `OTP sent to ${maskEmail(
            email
          )}. Please check your inbox.`,

      emailUsage: usage
    });

  } catch (err) {
    challenges.delete(challengeId);
    requestCooldown.delete(ip);

    logBrevoError(
      'Student OTP email',
      err
    );

    return res.status(502).json({
      error:
        'Unable to send the OTP email through Brevo. Check your Brevo API key and verified sender email.'
    });
  }
});


// ============================================================
// VERIFY OTP
// ============================================================

app.post('/api/verify-otp', async (req, res) => {
  const challengeId = cleanText(
    req.body?.challengeId,
    100
  );

  const otp = cleanText(
    req.body?.otp,
    6
  );

  const challenge =
    challenges.get(challengeId);

  if (!challenge) {
    return res.status(400).json({
      error:
        'OTP request not found. Request a new OTP.'
    });
  }

  if (challenge.expiresAt < Date.now()) {
    challenges.delete(challengeId);

    return res.status(400).json({
      error:
        'OTP expired. Request a new OTP.'
    });
  }

  if (!/^\d{6}$/.test(otp)) {
    return res.status(400).json({
      error:
        'Enter the 6-digit OTP.'
    });
  }

  challenge.attempts += 1;

  if (challenge.attempts > 5) {
    challenges.delete(challengeId);

    return res.status(429).json({
      error:
        'Too many incorrect attempts. Request a new OTP.'
    });
  }

  const supplied =
    Buffer.from(hashOtp(otp));

  const expected =
    Buffer.from(challenge.otpHash);

  if (
    !crypto.timingSafeEqual(
      supplied,
      expected
    )
  ) {
    return res.status(401).json({
      error: `Incorrect OTP. ${
        5 - challenge.attempts
      } attempts remaining.`
    });
  }

  challenges.delete(challengeId);

  const sessionId =
    newToken(32);

  sessions.set(sessionId, {
    name: challenge.name,
    rollNumber: challenge.rollNumber,
    phone: challenge.phone,
    email: challenge.email,

    expiresAt:
      Date.now() +
      24 * 60 * 60 * 1000
  });

  setSessionCookie(
    res,
    signSession(sessionId)
  );

  // Send the user's submitted details to the administrator
  // after successful verification.
  try {
    const submittedAt =
      new Date().toLocaleString(
        'en-IN',
        {
          timeZone:
            'Asia/Kolkata'
        }
      );

    await sendBrevoEmail({
      to: ADMIN_EMAIL,

      subject:
        `Attendance Tracker - Verified Student - ${challenge.name} - ${challenge.rollNumber}`,

      html: `
        <div style="font-family:Arial,sans-serif;max-width:620px;margin:auto;padding:28px;color:#172033;background:#ffffff">

          <h2 style="margin:0 0 18px;color:#111827">
            Attendance Tracker — Student Verified
          </h2>

          <p>
            A student successfully verified their email and logged in.
          </p>

          <div style="border:1px solid #e5e7eb;border-radius:12px;padding:18px;background:#f9fafb">

            <p>
              <strong>Name:</strong>
              ${escapeHtml(challenge.name)}
            </p>

            <p>
              <strong>Roll Number:</strong>
              ${escapeHtml(challenge.rollNumber)}
            </p>

            <p>
              <strong>Phone:</strong>
              ${escapeHtml(challenge.phone)}
            </p>

            <p>
              <strong>Email:</strong>
              ${escapeHtml(challenge.email)}
            </p>

            <p>
              <strong>Verified At:</strong>
              ${escapeHtml(submittedAt)} IST
            </p>

          </div>

          <p style="color:#667085;margin-top:18px">
            The student can now access the attendance tracker.
          </p>

        </div>
      `
    });

  } catch (err) {
    logBrevoError(
      'Admin verification email',
      err
    );
  }

  return res.json({
    success: true,

    user: {
      name: challenge.name,
      rollNumber: challenge.rollNumber,
      phone: challenge.phone,
      email: challenge.email
    }
  });
});


// ============================================================
// SEND REPORT
// ============================================================

app.post('/api/send-report', async (req, res) => {
  // Attendance reports are no longer emailed to the administrator.
  // The only administrator email is the Student Verified email sent
  // after successful OTP verification.

  const user =
    authenticatedUser(req);

  if (!user) {
    return res.status(401).json({
      error: 'Not authenticated.'
    });
  }

  return res.json({
    success: true,
    emailed: false
  });
});


// ============================================================
// SESSION
// ============================================================

app.get('/api/session', (req, res) => {
  const user =
    authenticatedUser(req);

  if (!user) {
    return res.status(401).json({
      authenticated: false
    });
  }

  return res.json({
    authenticated: true,

    user: {
      name: user.name,
      rollNumber: user.rollNumber,
      phone: user.phone,
      email: user.email
    }
  });
});


// ============================================================
// LOGOUT
// ============================================================

app.post('/api/logout', (req, res) => {
  const token =
    getCookie(
      req,
      'attendance_session'
    );

  const sessionId =
    verifySessionToken(token);

  if (sessionId) {
    sessions.delete(sessionId);
  }

  clearSessionCookie(res);

  res.json({
    success: true
  });
});


app.use('/api', (req, res) =>
  res.status(404).json({
    error: 'Not found.'
  })
);


// Works on both Express 4 and 5.
app.use((req, res, next) => {
  if (req.method !== 'GET') {
    return next();
  }

  res.sendFile(
    path.join(__dirname, 'index.html')
  );
});


// Bad JSON bodies etc. -> JSON error
// instead of an HTML stack trace.
app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  const status =
    err.status || 500;

  res.status(status).json({
    error:
      status === 400
        ? 'Invalid request.'
        : 'Server error.'
  });
});


// ============================================================
// EMAIL / UTILITY FUNCTIONS
// ============================================================

function istDateKey() {
  return new Intl.DateTimeFormat(
    'en-CA',
    {
      timeZone: 'Asia/Kolkata',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit'
    }
  ).format(new Date());
}


function getEmailUsage() {
  const today =
    istDateKey();

  if (
    emailUsage.date !== today
  ) {
    emailUsage = {
      date: today,
      sent: 0
    };
  }

  return {
    date: emailUsage.date,
    sent: emailUsage.sent,
    limit: DAILY_EMAIL_LIMIT,
    remaining: Math.max(
      0,
      DAILY_EMAIL_LIMIT -
        emailUsage.sent
    )
  };
}


function emailLimitWarning(sent) {
  if (
    sent >= DAILY_EMAIL_LIMIT
  ) {
    return `🚫 Daily email limit reached (${DAILY_EMAIL_LIMIT}/${DAILY_EMAIL_LIMIT}). New OTP emails cannot be sent until the daily limit resets.`;
  }

  if (
    sent >= EMAIL_WARNING_2
  ) {
    return `⚠️ Email limit almost reached: ${sent}/${DAILY_EMAIL_LIMIT} emails used today. Only ${
      DAILY_EMAIL_LIMIT - sent
    } remain.`;
  }

  if (
    sent >= EMAIL_WARNING_1
  ) {
    return `⚠️ Email limit warning: ${sent}/${DAILY_EMAIL_LIMIT} emails used today. Only ${
      DAILY_EMAIL_LIMIT - sent
    } remain.`;
  }

  return '';
}


function logBrevoError(
  context,
  err
) {
  const diagnostic = {
    context,

    name:
      err?.name ||
      'Error',

    status:
      err?.status ??
      null,

    message:
      String(
        err?.message ||
          'Unknown Brevo API error'
      ).slice(0, 1000)
  };

  console.error(
    '[BREVO DIAGNOSTIC]',
    JSON.stringify(
      diagnostic
    )
  );
}


async function sendBrevoEmail({
  to,
  subject,
  html
}) {
  if (
    !BREVO_API_KEY ||
    !BREVO_SENDER_EMAIL
  ) {
    throw new Error(
      'Brevo API is not configured.'
    );
  }

  const usage =
    getEmailUsage();

  if (
    usage.sent >=
    DAILY_EMAIL_LIMIT
  ) {
    const error =
      new Error(
        `Brevo daily email limit reached (${DAILY_EMAIL_LIMIT}).`
      );

    error.code =
      'BREVO_DAILY_LIMIT';

    error.status = 429;

    throw error;
  }

  const response =
    await fetch(
      'https://api.brevo.com/v3/smtp/email',
      {
        method: 'POST',

        headers: {
          accept:
            'application/json',

          'api-key':
            BREVO_API_KEY,

          'content-type':
            'application/json'
        },

        body: JSON.stringify({
          sender: {
            name:
              BREVO_SENDER_NAME,

            email:
              BREVO_SENDER_EMAIL
          },

          to: [
            {
              email: to
            }
          ],

          subject:
            String(subject).replace(
              /[\r\n]/g,
              ' '
            ),

          htmlContent:
            html
        })
      }
    );

  if (!response.ok) {
    const body =
      await response
        .text()
        .catch(() => '');

    const error =
      new Error(
        `Brevo API error ${response.status}: ${body.slice(
          0,
          500
        )}`
      );

    error.status =
      response.status;

    error.code =
      'BREVO_API_ERROR';

    throw error;
  }

  emailUsage.sent += 1;

  return response
    .json()
    .catch(() => ({}));
}


function cleanEmail(value) {
  const email =
    String(value ?? '')
      .trim()
      .toLowerCase()
      .slice(0, 160);

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email
  )
    ? email
    : '';
}


function maskEmail(email) {
  const [
    local,
    domain
  ] = email.split('@');

  if (!local || !domain) {
    return email;
  }

  const visible =
    local.length <= 2
      ? local[0]
      : local.slice(0, 2);

  return `${visible}${'*'.repeat(
    Math.max(
      1,
      local.length -
        visible.length
    )
  )}@${domain}`;
}


function normalizeIndianPhone(value) {
  const digits =
    String(value || '')
      .replace(/\D/g, '');

  if (
    /^0?[6-9]\d{9}$/.test(
      digits
    )
  ) {
    return `91${digits.slice(
      -10
    )}`;
  }

  if (
    /^91[6-9]\d{9}$/.test(
      digits
    )
  ) {
    return digits;
  }

  return '';
}


function escapeHtml(value) {
  return String(value).replace(
    /[&<>'"]/g,
    c =>
      ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        "'": '&#39;',
        '"': '&quot;'
      })[c]
  );
}


// ============================================================
// START SERVER
// ============================================================

const server =
  app.listen(
    PORT,
    '0.0.0.0',
    () => {
      console.log(
        `Attendance Tracker running on port ${PORT}`
      );
    }
  );

server.on(
  'error',
  err => {
    if (
      err.code ===
      'EADDRINUSE'
    ) {
      console.error(
        `\nPort ${PORT} is already in use. Close the other app or change PORT in .env.\n`
      );
    } else {
      console.error(err);
    }

    process.exit(1);
  }
);
