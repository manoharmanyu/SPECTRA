import express from 'express';
import QRCode from 'qrcode';
import fs from 'fs';
import path from 'path';
import { db } from '../db.js';
import { config } from '../config.js';
import {
  hashPassword,
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

// Strict Administrator Role Enforcement Middleware
export function requireAdmin(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user || req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Administrative privilege required. Access denied.' });
    }
    next();
  });
}

// Optional or Automatic Session Provisioning for Interactive Features (Pairing, 2FA, Forensics)
// Guarantees unique isolated context for every visitor without a shared global investigator account
export function optionalOrAutoAuth(req, res, next) {
  const token =
    req.cookies?.spectra_session ||
    req.headers['x-session-id'] ||
    (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
      ? req.headers.authorization.substring(7)
      : null);

  if (token) {
    const session = db.findSession(token);
    if (session) {
      const user = db.findUserById(session.userId);
      if (user) {
        req.user = user;
        req.session = session;
        return next();
      }
    }
  }

  // Provision unique, isolated guest user context per visitor
  const guestUser = db.createGuestUser();
  const newSession = db.createSession(guestUser.id, true, req.ip, req.headers['user-agent']);
  res.cookie('spectra_session', newSession.id, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 24 * 3600 * 1000
  });

  req.user = guestUser;
  req.session = newSession;
  next();
}

// POST /api/auth/quick-session (Ensures an isolated active session for current visitor)
authRouter.post('/quick-session', optionalOrAutoAuth, (req, res) => {
  return res.json({
    success: true,
    authenticated: true,
    sessionId: req.session.id,
    user: {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role || 'guest',
      totpEnabled: Boolean(req.user.totpEnabled)
    }
  });
});

// GET /api/admin/audit-logs (Centralized Server-Side Audit Records for Administrator Command Center)
authRouter.get('/admin/audit-logs', requireAdmin, (req, res) => {
  const allJobs = db.data.jobs || [];

  let imageCount = 0;
  let audioCount = 0;
  let videoCount = 0;
  let deepfakesCount = 0;
  let audioClonesCount = 0;
  let authenticCount = 0;
  let failedCount = 0;

  const logs = allJobs.map(j => {
    const report = j.forensicReport || {};
    const mediaType = (j.mediaCategory || 'IMAGE').toUpperCase();
    if (mediaType === 'IMAGE') imageCount++;
    else if (mediaType === 'AUDIO') audioCount++;
    else if (mediaType === 'VIDEO') videoCount++;

    const verdict = report.verdict || (j.status === 'failed' ? 'FAILED ANALYSIS' : 'PENDING');
    const isAlert = Boolean(report.isAlert || verdict.includes('MANIPULATED') || verdict.includes('SYNTHETIC'));

    if (j.status === 'failed') failedCount++;
    else if (isAlert && (mediaType === 'AUDIO' || verdict.includes('VOICE') || verdict.includes('AUDIO'))) audioClonesCount++;
    else if (isAlert) deepfakesCount++;
    else authenticCount++;

    return {
      id: j.id,
      timestamp: j.createdAt,
      fileName: j.originalFilename || 'Media_Artifact',
      fileType: mediaType === 'AUDIO' ? 'Audio' : (mediaType === 'IMAGE' ? 'Image' : 'Video'),
      fileSize: j.sizeBytes ? `${Math.round(j.sizeBytes / 1024)} KB` : 'N/A',
      sizeBytes: j.sizeBytes,
      sha256: j.sha256 || 'Pending',
      status: j.status,
      verdict: verdict,
      risk: isAlert ? (report.risk || 'High Risk Synthetic') : (report.risk || 'Low Risk Verified'),
      indicator: report.primaryIndicator || report.indicator || 'Optical flow & biological sensor evaluation',
      hash: j.sha256 ? j.sha256.substring(0, 16) + '...' : 'Calculating...',
      detectorName: report.detectorName || 'SPECTRA-MultiModal-Engine',
      modelVersion: report.modelVersion || 'v2.2-Production',
      errorMessage: j.error,
      report: report
    };
  });

  return res.json({
    success: true,
    total: allJobs.length,
    kpis: {
      totalInvocations: allJobs.length,
      imageAnalyses: imageCount,
      audioAnalyses: audioCount,
      videoAnalyses: videoCount,
      deepfakesFlagged: deepfakesCount,
      audioClonesFlagged: audioClonesCount,
      authenticVerified: authenticCount,
      failedJobs: failedCount
    },
    logs: logs
  });
});

// POST /api/admin/clear-logs (Purge forensic audit logs - Administrator restricted)
authRouter.post('/admin/clear-logs', requireAdmin, (req, res) => {
  const count = db.data.jobs.length;
  db.data.jobs = [];
  db.save();
  return res.json({ success: true, message: `Cleared ${count} audit records.` });
});

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
      mustChangePassword: Boolean(user.mustChangePassword),
      sessionId: partialSession.id,
      user: {
        id: user.id,
        username: user.username,
        totpEnabled: true,
        mustChangePassword: Boolean(user.mustChangePassword)
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
    mustChangePassword: Boolean(user.mustChangePassword),
    sessionId: session.id,
    user: {
      id: user.id,
      username: user.username,
      totpEnabled: false,
      mustChangePassword: Boolean(user.mustChangePassword)
    }
  });
});

// POST /api/auth/change-password (Secure password replacement)
authRouter.post('/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current password and new password are required.' });
  }

  const user = db.findUserById(req.user.id);
  if (!user || !verifyPassword(currentPassword, user.passwordHash, user.salt)) {
    return res.status(401).json({ error: 'Current password verification failed.' });
  }

  if (typeof newPassword !== 'string' || newPassword.length < 10) {
    return res.status(400).json({ error: 'New password must be at least 10 characters long.' });
  }

  // Strong password requirements
  const hasUpper = /[A-Z]/.test(newPassword);
  const hasLower = /[a-z]/.test(newPassword);
  const hasDigit = /[0-9]/.test(newPassword);
  const hasSpecial = /[^A-Za-z0-9]/.test(newPassword);

  if (!hasUpper || !hasLower || !hasDigit || !hasSpecial) {
    return res.status(400).json({
      error: 'New password must contain uppercase, lowercase, numbers, and special characters.'
    });
  }

  const { hash, salt } = hashPassword(newPassword);
  db.updateUser(user.id, {
    passwordHash: hash,
    salt: salt,
    mustChangePassword: false,
    passwordChangedAt: new Date().toISOString()
  });

  // Clean up initial one-time credential file if present
  try {
    const initCredPath = path.join(config.dataDir, '.initial_admin_credential');
    if (fs.existsSync(initCredPath)) {
      fs.unlinkSync(initCredPath);
    }
  } catch (e) {}

  return res.json({
    success: true,
    message: 'Password successfully changed and updated.'
  });
});

// POST /api/auth/2fa/setup (Auto-provisions session if needed)
authRouter.post('/2fa/setup', optionalOrAutoAuth, async (req, res) => {
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
authRouter.post('/2fa/verify-setup', optionalOrAutoAuth, (req, res) => {
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
      mustChangePassword: Boolean(user.mustChangePassword),
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
