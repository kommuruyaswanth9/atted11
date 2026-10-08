import express from 'express';
import dotenv from 'dotenv';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import tls from 'node:tls';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = Number(process.env.PORT || 3000);
const GMAIL_USER = process.env.GMAIL_USER;
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || GMAIL_USER;
const SESSION_SECRET = process.env.SESSION_SECRET;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
// Local development: print the OTP in the terminal so email delivery is not
// required just to test the login flow. Render is marked as production below.
const OTP_DEBUG = !IS_PRODUCTION;

if (!GMAIL_USER || !GMAIL_APP_PASSWORD || !SESSION_SECRET || !ADMIN_EMAIL) {
  console.warn('\nMissing one or more required environment variables: GMAIL_USER, GMAIL_APP_PASSWORD, ADMIN_EMAIL or SESSION_SECRET.\n');
}
if (SESSION_SECRET && SESSION_SECRET.length < 32) {
  console.warn('\nSESSION_SECRET is short. Use a random 64-character value (see README).\n');
}

const challenges = new Map();
const sessions = new Map();
const requestCooldown = new Map();

app.disable('x-powered-by');
app.set('trust proxy', 1); // correct client IP + secure cookies behind Render/Railway/Nginx etc.
app.use(express.json({ limit: '20kb' }));

// Serve ONLY the three public front-end files. (Previously the whole project
// folder was public, which exposed server.js, package.json, README, etc.)
const PUBLIC_FILES = { '/': 'index.html', '/index.html': 'index.html', '/script.js': 'script.js', '/style.css': 'style.css' };
app.get(Object.keys(PUBLIC_FILES), (req, res) => {
  res.sendFile(path.join(__dirname, PUBLIC_FILES[req.path]));
});

// Render health check endpoint.
app.get('/health', (req, res) => {
  res.status(200).json({ ok: true });
});

function cleanText(value, max) {
  return String(value ?? '').trim().replace(/[<>]/g, '').slice(0, max);
}

function hashOtp(otp) {
  return crypto.createHash('sha256').update(otp).digest('hex');
}

function newToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('hex');
}

function signSession(sessionId) {
  const signature = crypto.createHmac('sha256', SESSION_SECRET).update(sessionId).digest('hex');
  return `${sessionId}.${signature}`;
}

function verifySessionToken(token) {
  if (!token || !SESSION_SECRET) return null;
  const dot = token.lastIndexOf('.');
  if (dot < 1) return null;
  const sessionId = token.slice(0, dot);
  const signature = token.slice(dot + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(sessionId).digest('hex');
  if (signature.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  return sessionId;
}

function getCookie(req, name) {
  const raw = req.headers.cookie || '';
  const pair = raw.split(';').map(x => x.trim()).find(x => x.startsWith(`${name}=`));
  return pair ? decodeURIComponent(pair.slice(name.length + 1)) : '';
}

function setSessionCookie(res, token) {
  // Render terminates HTTPS at its proxy and forwards the request to Node over HTTP.
  // Use the forwarded protocol so the session cookie is Secure in production.
  const forwardedProto = String(res.req?.headers?.['x-forwarded-proto'] || '').split(',')[0].trim();
  const secure = res.req?.secure || forwardedProto === 'https' || process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `attendance_session=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=86400${secure}`);
}

function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'attendance_session=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0');
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
  for (const [id, c] of challenges) if (c.expiresAt < now) challenges.delete(id);
  for (const [id, s] of sessions) if (s.expiresAt < now) sessions.delete(id);
  for (const [ip, t] of requestCooldown) if (t + 30_000 < now) requestCooldown.delete(ip);
}
setInterval(cleanup, 30_000).unref();

app.post('/api/send-otp', async (req, res) => {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD || !SESSION_SECRET || !ADMIN_EMAIL) {
    return res.status(500).json({ error: 'Server is not configured. Add GMAIL_USER, GMAIL_APP_PASSWORD, ADMIN_EMAIL and SESSION_SECRET.' });
  }

  const ip = req.ip || 'unknown';
  const lastRequest = requestCooldown.get(ip) || 0;
  if (Date.now() - lastRequest < 30_000) {
    return res.status(429).json({ error: 'Please wait 30 seconds before requesting another OTP.' });
  }

  const name = cleanText(req.body?.name, 80);
  const rollNumber = cleanText(req.body?.rollNumber, 40);
  const phoneRaw = cleanText(req.body?.phone, 20);
  const phone = normalizeIndianPhone(phoneRaw);
  const email = cleanEmail(req.body?.email);
  if (name.length < 2 || rollNumber.length < 1 || !phone || !email) {
    return res.status(400).json({ error: 'Enter a valid name, roll number, 10-digit Indian phone number and email address.' });
  }

  const otp = String(crypto.randomInt(100000, 1000000));
  const challengeId = newToken(24);

  if (OTP_DEBUG) console.log(`\n[LOCAL OTP DEBUG] ${name} (${rollNumber}, ${phone}, ${email}) -> ${otp}\n`);

  challenges.set(challengeId, {
    otpHash: hashOtp(otp),
    name,
    rollNumber,
    phone,
    email,
    expiresAt: Date.now() + 60_000,
    attempts: 0
  });
  requestCooldown.set(ip, Date.now());

  try {
    await sendGmail({
      to: email,
      subject: 'Attendance Tracker - Your OTP',
      html: `
        <div style="font-family:Arial,sans-serif;max-width:560px;margin:auto;padding:28px;color:#172033;background:#ffffff">
          <h2 style="margin:0 0 14px">Attendance Tracker — OTP Verification</h2>
          <p>Hello ${escapeHtml(name)},</p>
          <p>Your verification OTP is:</p>
          <div style="font-size:30px;font-weight:800;letter-spacing:8px;text-align:center;padding:18px;background:#f4f7fb;border-radius:12px">${otp}</div>
          <p>This OTP expires in <strong>1 minute</strong>. If you did not request it, you can ignore this email.</p>
        </div>`
    });

    return res.json({ success: true, challengeId, expiresIn: 60, message: `OTP sent to ${maskEmail(email)}. Please check your inbox.` });
  } catch (err) {
    challenges.delete(challengeId);
    requestCooldown.delete(ip);
    console.error('Student OTP email exception:', err);
    return res.status(502).json({ error: err.message || 'Unable to send the OTP email. Check your Gmail SMTP settings.' });
  }
});

app.post('/api/verify-otp', async (req, res) => {
  const challengeId = cleanText(req.body?.challengeId, 100);
  const otp = cleanText(req.body?.otp, 6);
  const challenge = challenges.get(challengeId);

  if (!challenge) return res.status(400).json({ error: 'OTP request not found. Request a new OTP.' });
  if (challenge.expiresAt < Date.now()) {
    challenges.delete(challengeId);
    return res.status(400).json({ error: 'OTP expired. Request a new OTP.' });
  }
  if (!/^\d{6}$/.test(otp)) return res.status(400).json({ error: 'Enter the 6-digit OTP.' });

  challenge.attempts += 1;
  if (challenge.attempts > 5) {
    challenges.delete(challengeId);
    return res.status(429).json({ error: 'Too many incorrect attempts. Request a new OTP.' });
  }

  const supplied = Buffer.from(hashOtp(otp));
  const expected = Buffer.from(challenge.otpHash);
  if (!crypto.timingSafeEqual(supplied, expected)) {
    return res.status(401).json({ error: `Incorrect OTP. ${5 - challenge.attempts} attempts remaining.` });
  }

  challenges.delete(challengeId);
  const sessionId = newToken(32);
  sessions.set(sessionId, {
    name: challenge.name,
    rollNumber: challenge.rollNumber,
    phone: challenge.phone,
    email: challenge.email,
    expiresAt: Date.now() + 24 * 60 * 60 * 1000
  });
  setSessionCookie(res, signSession(sessionId));

  // Send the user's submitted details to the administrator after successful verification.
  try {
    const submittedAt = new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' });
    await sendGmail({
      to: ADMIN_EMAIL,
      subject: `Attendance Tracker - Verified Student - ${challenge.name} - ${challenge.rollNumber}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:620px;margin:auto;padding:28px;color:#172033;background:#ffffff">
          <h2 style="margin:0 0 18px;color:#111827">Attendance Tracker — Student Verified</h2>
          <p>A student successfully verified their email and logged in.</p>
          <div style="border:1px solid #e5e7eb;border-radius:12px;padding:18px;background:#f9fafb">
            <p><strong>Name:</strong> ${escapeHtml(challenge.name)}</p>
            <p><strong>Roll Number:</strong> ${escapeHtml(challenge.rollNumber)}</p>
            <p><strong>Phone:</strong> ${escapeHtml(challenge.phone)}</p>
            <p><strong>Email:</strong> ${escapeHtml(challenge.email)}</p>
            <p><strong>Verified At:</strong> ${escapeHtml(submittedAt)} IST</p>
          </div>
          <p style="color:#667085;margin-top:18px">The student can now access the attendance tracker.</p>
        </div>`
    });
  } catch (err) {
    console.error('Admin email exception:', err);
  }

  return res.json({ success: true, user: { name: challenge.name, rollNumber: challenge.rollNumber, phone: challenge.phone, email: challenge.email } });
});

app.post('/api/send-report', async (req, res) => {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD || !ADMIN_EMAIL) return res.status(500).json({ error: 'Email reporting is not configured.' });
  const user = authenticatedUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated.' });

  const attendance = req.body?.attendance;
  if (!attendance || typeof attendance !== 'object') {
    return res.status(400).json({ error: 'Attendance report data is missing.' });
  }

  const rows = [];
  let present = 0, absent = 0, holidays = 0;
  for (const [date, entries] of Object.entries(attendance)) {
    if (!entries || typeof entries !== 'object') continue;
    for (const [session, status] of Object.entries(entries)) {
      const safeStatus = cleanText(status, 20);
      if (!['present','absent','holiday'].includes(safeStatus)) continue;
      if (safeStatus === 'present') present++;
      else if (safeStatus === 'absent') absent++;
      else holidays++;
      rows.push(`<tr><td>${escapeHtml(date)}</td><td>${escapeHtml(session)}</td><td>${escapeHtml(safeStatus)}</td></tr>`);
    }
  }

  try {
    await sendGmail({
      to: ADMIN_EMAIL,
      subject: `Attendance Report - ${user.name} - ${user.rollNumber}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:760px;margin:auto;padding:28px;color:#172033">
          <h2>Attendance Tracker — Complete Report</h2>
          <p><strong>Name:</strong> ${escapeHtml(user.name)}<br><strong>Roll Number:</strong> ${escapeHtml(user.rollNumber)}<br><strong>Phone:</strong> ${escapeHtml(user.phone)}<br><strong>Email:</strong> ${escapeHtml(user.email || "")}</p>
          <p><strong>Present:</strong> ${present} &nbsp; <strong>Absent:</strong> ${absent} &nbsp; <strong>Holidays:</strong> ${holidays}</p>
          <table style="border-collapse:collapse;width:100%"><thead><tr><th style="border:1px solid #ddd;padding:8px;text-align:left">Date</th><th style="border:1px solid #ddd;padding:8px;text-align:left">Session</th><th style="border:1px solid #ddd;padding:8px;text-align:left">Status</th></tr></thead><tbody>${rows.join('') || '<tr><td colspan="3" style="padding:8px">No attendance records have been saved yet.</td></tr>'}</tbody></table>
        </div>`
    });
    return res.json({ success: true });
  } catch (err) {
    console.error('Attendance report email error:', err);
    return res.status(502).json({ error: 'Could not send the attendance report.' });
  }
});

app.get('/api/session', (req, res) => {
  const user = authenticatedUser(req);
  if (!user) return res.status(401).json({ authenticated: false });
  return res.json({ authenticated: true, user: { name: user.name, rollNumber: user.rollNumber, phone: user.phone, email: user.email } });
});

app.post('/api/logout', (req, res) => {
  const token = getCookie(req, 'attendance_session');
  const sessionId = verifySessionToken(token);
  if (sessionId) sessions.delete(sessionId);
  clearSessionCookie(res);
  res.json({ success: true });
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Not found.' }));

// Works on both Express 4 and 5 (the '*' route string crashes on 5, '/{*splat}' fails on 4)
app.use((req, res, next) => {
  if (req.method !== 'GET') return next();
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Bad JSON bodies etc. -> JSON error instead of an HTML stack trace
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = err.status || 500;
  res.status(status).json({ error: status === 400 ? 'Invalid request.' : 'Server error.' });
});


async function sendGmail({ to, subject, html }) {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) throw new Error('Gmail SMTP is not configured.');
  const password = GMAIL_APP_PASSWORD.replace(/\s+/g, '');
  const socket = tls.connect({ host: 'smtp.gmail.com', port: 465, servername: 'smtp.gmail.com' });
  let buffer = '';
  let pending = null;
  const waiters = [];

  const getResponse = () => new Promise((resolve, reject) => {
    waiters.push({ resolve, reject });
    processBuffer();
  });

  const processBuffer = () => {
    while (pending === null && waiters.length && buffer.includes('\r\n')) {
      const lines = buffer.split('\r\n');
      const complete = lines.slice(0, -1);
      buffer = lines[lines.length - 1];
      if (!complete.length) continue;
      const last = complete[complete.length - 1];
      const match = last.match(/^(\d{3})([ -])/);
      if (!match) continue;
      const code = Number(match[1]);
      if (match[2] === '-') continue;
      const waiter = waiters.shift();
      waiter.resolve({ code, text: complete.join('\n') });
    }
  };

  const failAll = err => {
    while (waiters.length) waiters.shift().reject(err);
  };

  socket.setEncoding('utf8');
  socket.on('data', chunk => { buffer += chunk; processBuffer(); });
  const connected = new Promise((resolve, reject) => {
    socket.once('secureConnect', resolve);
    socket.once('error', reject);
  });
  socket.on('error', failAll);

  const command = async (cmd, expected) => {
    socket.write(cmd + '\r\n');
    const response = await getResponse();
    if (!expected.includes(response.code)) {
      throw new Error(`Gmail SMTP error ${response.code}: ${response.text}`);
    }
    return response;
  };

  try {
    await connected;
    let response = await getResponse();
    if (response.code !== 220) throw new Error(`Gmail SMTP greeting error ${response.code}: ${response.text}`);
    await command(`EHLO attendance-tracker.local`, [250]);
    await command('AUTH LOGIN', [334]);
    await command(Buffer.from(GMAIL_USER).toString('base64'), [334]);
    await command(Buffer.from(password).toString('base64'), [235]);
    await command(`MAIL FROM:<${GMAIL_USER}>`, [250]);
    await command(`RCPT TO:<${to}>`, [250, 251]);

    const safeSubject = String(subject).replace(/[\r\n]/g, ' ');
    const message = [
      `From: Attendance Tracker <${GMAIL_USER}>`,
      `To: ${to}`,
      `Subject: ${safeSubject}`,
      'MIME-Version: 1.0',
      'Content-Type: text/html; charset=UTF-8',
      'Content-Transfer-Encoding: 8bit',
      '',
      html
    ].join('\r\n').replace(/^\./gm, '..');

    socket.write(`DATA\r\n`);
    response = await getResponse();
    if (response.code !== 354) throw new Error(`Gmail SMTP DATA error ${response.code}: ${response.text}`);
    socket.write(message + '\r\n.\r\n');
    response = await getResponse();
    if (response.code !== 250) throw new Error(`Gmail SMTP send error ${response.code}: ${response.text}`);
    socket.write('QUIT\r\n');
  } finally {
    setTimeout(() => { try { socket.end(); } catch {} }, 100);
  }
}

function cleanEmail(value) {
  const email = String(value ?? '').trim().toLowerCase().slice(0, 160);
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ? email : '';
}

function maskEmail(email) {
  const [local, domain] = email.split('@');
  if (!local || !domain) return email;
  const visible = local.length <= 2 ? local[0] : local.slice(0, 2);
  return `${visible}${'*'.repeat(Math.max(1, local.length - visible.length))}@${domain}`;
}

function normalizeIndianPhone(value) {
  const digits = String(value || '').replace(/\D/g, '');
  if (/^0?[6-9]\d{9}$/.test(digits)) return `91${digits.slice(-10)}`;
  if (/^91[6-9]\d{9}$/.test(digits)) return digits;
  return '';
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, c => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' }[c]));
}

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`Attendance Tracker running on port ${PORT}`);
});
server.on('error', err => {
  if (err.code === 'EADDRINUSE') console.error(`\nPort ${PORT} is already in use. Close the other app or change PORT in .env.\n`);
  else console.error(err);
  process.exit(1);
});
