import express from 'express';
import QRCode from 'qrcode';
import { db } from '../db.js';
import {
  verifyPassword,
  generateTotpSecret,
  verifyTotp,
  generateRecoveryCodes,
  verifyRecoveryCode,
  encryptAtRest,
  decryptAtRest
} from '../crypto.js';

export const authRouter = express.Router();

// Simple in-memory rate limiter for auth endpoints
const loginAttempts = new Map(); // key -> { count, resetAt }

function checkRateLimit(key, maxAttempts = 5, windowMs = 5 * 60 * 1000) {
  const now = Date.now();
  const record = loginAttempts.get(key);
  if (!record || now > record.resetAt) {
    loginAttempts.set(key, { count: 1, resetAt: now + windowMs });
    return { limited: false };
  }
  if (record.count >= maxAttempts) {
    const waitSeconds = Math.ceil((record.resetAt - now) / 1000);
    return { limited: true, waitSeconds };
  }
  record.count++;
  return { limited: false };
}

function clearRateLimit(key) {
  loginAttempts.delete(key);
}

// Authentication Middleware
export function requireAuth(req, res, next) {
  const token =
    req.cookies?.spectra_session ||
    req.headers['x-session-id'] ||
    (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
      ? req.headers.authorization.substring(7)
      : null);

  if (!token) {
    return res.status(401).json({ error: 'Authentication required. No session token provided.' });
  }

  const session = db.findSession(token);
  if (!session) {
    return res.status(401).json({ error: 'Session expired or invalid. Please sign in again.' });
  }

  const user = db.findUserById(session.userId);
  if (!user) {
    return res.status(401).json({ error: 'User record not found.' });
  }

  // If user has 2FA enabled, session MUST be 2FA verified
  if (user.totpEnabled && !session.is2FAVerified) {
    return res.status(403).json({
      error: 'Two-factor authentication required for this session.',
      require2FA: true,
      sessionId: session.id
    });
  }

  req.user = user;
  req.session = session;
  next();
}

// POST /api/auth/register
authRouter.post('/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username and password are required.' });
  }

  const cleanUser = username.trim();
  if (cleanUser.length < 3 || cleanUser.length > 32) {
    return res.status(400).json({ error: 'Username must be between 3 and 32 characters.' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
  }

  try {
    const newUser = db.createUser(cleanUser, password);
    const session = db.createSession(newUser.id, true, req.ip, req.headers['user-agent']);

    res.cookie('spectra_session', session.id, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 24 * 3600 * 1000
    });

    return res.status(201).json({
      success: true,
      message: 'Account created successfully.',
      sessionId: session.id,
      user: {
        id: newUser.id,
        username: newUser.username,
        totpEnabled: false
      }
    });
  } catch (e) {
    return res.status(409).json({ error: 'Username already in use.' });
  }
});

// POST /api/auth/login
authRouter.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required.' });
  }

  const clientKey = `${req.ip}_${username.toLowerCase()}`;
  const rate = checkRateLimit(clientKey, 5, 5 * 60 * 1000);
  if (rate.limited) {
    return res.status(429).json({
      error: `Too many failed attempts. Rate limit triggered. Please wait ${rate.waitSeconds} seconds.`
    });
  }

  const user = db.findUserByUsername(username);
  if (!user || !verifyPassword(password, user.passwordHash, user.salt)) {
    return res.status(401).json({ error: 'Invalid administrator or user credentials.' });
  }

  clearRateLimit(clientKey);

  // If 2FA enabled, generate partial session requiring 2FA step
  if (user.totpEnabled) {
    const partialSession = db.createSession(user.id, false, req.ip, req.headers['user-agent']);
    return res.json({
      success: true,
      require2FA: true,
      sessionId: partialSession.id,
      user: {
        id: user.id,
        username: user.username,
        totpEnabled: true
      }
    });
  }

  // Normal login without 2FA
  const session = db.createSession(user.id, true, req.ip, req.headers['user-agent']);
  res.cookie('spectra_session', session.id, {
    httpOnly: true,
    sameSite: 'lax',
    maxAge: 24 * 3600 * 1000
  });

  return res.json({
    success: true,
    require2FA: false,
    sessionId: session.id,
    user: {
      id: user.id,
      username: user.username,
      totpEnabled: false
    }
  });
});

// POST /api/auth/2fa/setup (Requires active session)
authRouter.post('/2fa/setup', requireAuth, async (req, res) => {
  const user = req.user;
  const { secret, uri } = generateTotpSecret(user.username);

  // Store temporary unconfirmed secret in session
  db.updateSession(req.session.id, { pendingTotpSecret: secret });

  try {
    const qrDataUrl = await QRCode.toDataURL(uri, {
      margin: 2,
      color: { dark: '#03050B', light: '#FFFFFF' }
    });

    return res.json({
      success: true,
      secret: secret,
      uri: uri,
      qrCode: qrDataUrl
    });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to generate QR code.' });
  }
});

// POST /api/auth/2fa/verify-setup
authRouter.post('/2fa/verify-setup', requireAuth, (req, res) => {
  const { token } = req.body || {};
  const secret = req.session.pendingTotpSecret;

  if (!secret) {
    return res.status(400).json({ error: 'No pending 2FA setup found. Please initiate setup again.' });
  }

  if (!token || !verifyTotp(token, secret)) {
    return res.status(400).json({ error: 'Invalid 6-digit verification code.' });
  }

  // Encrypt TOTP secret at rest with AES-256-GCM
  const encryptedSecret = encryptAtRest(secret);
  const { plain: recoveryCodes, hashed: recoveryHashed } = generateRecoveryCodes(10);

  db.updateUser(req.user.id, {
    totpSecretEncrypted: encryptedSecret,
    totpEnabled: true,
    recoveryCodesHashed: recoveryHashed
  });

  db.updateSession(req.session.id, {
    is2FAVerified: true,
    pendingTotpSecret: null
  });

  return res.json({
    success: true,
    message: 'Two-Factor Authentication activated.',
    recoveryCodes: recoveryCodes
  });
});

// POST /api/auth/2fa/authenticate (For logging in)
authRouter.post('/2fa/authenticate', (req, res) => {
  const { sessionId, token, recoveryCode } = req.body || {};
  if (!sessionId) {
    return res.status(400).json({ error: 'Session ID required.' });
  }

  const session = db.findSession(sessionId);
  if (!session) {
    return res.status(401).json({ error: 'Session expired or invalid.' });
  }

  const user = db.findUserById(session.userId);
  if (!user || !user.totpEnabled || !user.totpSecretEncrypted) {
    return res.status(400).json({ error: '2FA is not configured for this account.' });
  }

  const clientKey = `2fa_${req.ip}_${user.id}`;
  const rate = checkRateLimit(clientKey, 5, 5 * 60 * 1000);
  if (rate.limited) {
    return res.status(429).json({
      error: `Too many 2FA verification attempts. Please wait ${rate.waitSeconds} seconds.`
    });
  }

  // Check Recovery Code if provided
  if (recoveryCode) {
    const { valid, index } = verifyRecoveryCode(recoveryCode, user.recoveryCodesHashed);
    if (valid) {
      clearRateLimit(clientKey);
      // Consume recovery code
      user.recoveryCodesHashed.splice(index, 1);
      db.updateUser(user.id, { recoveryCodesHashed: user.recoveryCodesHashed });
      db.updateSession(sessionId, { is2FAVerified: true });

      res.cookie('spectra_session', sessionId, {
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 24 * 3600 * 1000
      });

      return res.json({
        success: true,
        message: 'Recovery code verified.',
        remainingRecoveryCodes: user.recoveryCodesHashed.length,
        user: { id: user.id, username: user.username, totpEnabled: true }
      });
    }
  }

  // Verify TOTP code
  try {
    const plainSecret = decryptAtRest(user.totpSecretEncrypted);
    if (!token || !verifyTotp(token, plainSecret)) {
      return res.status(401).json({ error: 'Invalid or expired 6-digit TOTP code.' });
    }

    clearRateLimit(clientKey);
    db.updateSession(sessionId, { is2FAVerified: true });

    res.cookie('spectra_session', sessionId, {
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 24 * 3600 * 1000
    });

    return res.json({
      success: true,
      message: '2FA verification successful.',
      user: { id: user.id, username: user.username, totpEnabled: true }
    });
  } catch (e) {
    return res.status(500).json({ error: 'Cryptographic failure during 2FA verification.' });
  }
});

// POST /api/auth/2fa/revoke (Disable 2FA)
authRouter.post('/2fa/revoke', requireAuth, (req, res) => {
  const { password } = req.body || {};
  if (!password || !verifyPassword(password, req.user.passwordHash, req.user.salt)) {
    return res.status(401).json({ error: 'Password confirmation required to disable 2FA.' });
  }

  db.updateUser(req.user.id, {
    totpSecretEncrypted: null,
    totpEnabled: false,
    recoveryCodesHashed: []
  });

  return res.json({ success: true, message: 'Two-Factor Authentication disabled.' });
});

// GET /api/auth/me
authRouter.get('/me', (req, res) => {
  const token =
    req.cookies?.spectra_session ||
    req.headers['x-session-id'] ||
    (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
      ? req.headers.authorization.substring(7)
      : null);

  if (!token) {
    return res.json({ authenticated: false });
  }

  const session = db.findSession(token);
  if (!session) {
    return res.json({ authenticated: false });
  }

  const user = db.findUserById(session.userId);
  if (!user) {
    return res.json({ authenticated: false });
  }

  const devices = db.getUserDevices(user.id);

  return res.json({
    authenticated: true,
    is2FAVerified: session.is2FAVerified,
    user: {
      id: user.id,
      username: user.username,
      totpEnabled: user.totpEnabled,
      createdAt: user.createdAt
    },
    devicesCount: devices.filter(d => d.trustStatus === 'active').length,
    devices: devices
  });
});

// POST /api/auth/logout
authRouter.post('/logout', (req, res) => {
  const token =
    req.cookies?.spectra_session ||
    req.headers['x-session-id'] ||
    (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
      ? req.headers.authorization.substring(7)
      : null);

  if (token) {
    db.deleteSession(token);
  }
  res.clearCookie('spectra_session');
  return res.json({ success: true, message: 'Signed out.' });
});
