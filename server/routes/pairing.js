import express from 'express';
import QRCode from 'qrcode';
import { db } from '../db.js';
import { requireAuth } from './auth.js';
import { generatePairingCode, generateDeviceToken, verifyTotp, decryptAtRest } from '../crypto.js';
import { getLocalIpAddress, config } from '../config.js';
import { wsHub } from '../ws.js';

export const pairingRouter = express.Router();

// POST /api/pairing/generate (Desktop initiates pairing)
pairingRouter.post('/generate', requireAuth, async (req, res) => {
  const code = generatePairingCode();
  const pairing = db.createPairingCode(req.user.id, req.session.id, code);

  const lanIp = getLocalIpAddress();
  const mobileUrl = `http://${lanIp}:${config.vitePort}/mobile.html?code=${pairing.code}`;

  let qrCodeDataUrl = null;
  try {
    qrCodeDataUrl = await QRCode.toDataURL(mobileUrl, {
      margin: 2,
      color: { dark: '#03050B', light: '#FFFFFF' }
    });
  } catch (e) {
    console.error('Failed to create pairing QR code:', e);
  }

  // Notify WebSocket listeners
  wsHub.broadcastToUser(req.user.id, 'pairing:initiated', {
    code: pairing.displayCode,
    expiresAt: pairing.expiresAt
  });

  return res.json({
    success: true,
    code: pairing.displayCode,
    cleanCode: pairing.code,
    expiresAt: pairing.expiresAt,
    ttlSeconds: config.pairingCodeTtlMs / 1000,
    mobileUrl: mobileUrl,
    qrCode: qrCodeDataUrl,
    lanIp: lanIp
  });
});

// GET /api/pairing/status/:code (Check pairing code state)
pairingRouter.get('/status/:code', (req, res) => {
  const pairing = db.findPairingCode(req.params.code);
  if (!pairing) {
    return res.status(404).json({ error: 'Pairing code not found or invalid.' });
  }

  return res.json({
    code: pairing.displayCode,
    status: pairing.status,
    expiresAt: pairing.expiresAt,
    proposedDeviceName: pairing.proposedDeviceName,
    isExpired: new Date(pairing.expiresAt).getTime() < Date.now()
  });
});

// POST /api/pairing/claim (Phone connects and submits code + device name + 2FA)
pairingRouter.post('/claim', (req, res) => {
  const { code, deviceName, totpToken } = req.body || {};
  if (!code || !deviceName) {
    return res.status(400).json({ error: 'Pairing code and device name are required.' });
  }

  const pairing = db.findPairingCode(code);
  if (!pairing) {
    return res.status(404).json({ error: 'Invalid pairing code.' });
  }

  if (pairing.status !== 'pending') {
    return res.status(400).json({ error: `Pairing code is already ${pairing.status}.` });
  }

  if (new Date(pairing.expiresAt).getTime() < Date.now()) {
    db.updatePairingCode(code, { status: 'expired' });
    return res.status(410).json({ error: 'Pairing code has expired. Please generate a new code on desktop.' });
  }

  if (pairing.attempts >= config.maxPairingAttempts) {
    db.updatePairingCode(code, { status: 'revoked' });
    return res.status(429).json({ error: 'Maximum attempts exceeded for this pairing code.' });
  }

  const user = db.findUserById(pairing.userId);
  if (!user) {
    return res.status(404).json({ error: 'Associated user account not found.' });
  }

  // If user has 2FA enabled, phone MUST provide genuine 2FA TOTP code!
  if (user.totpEnabled) {
    if (!totpToken) {
      return res.status(403).json({
        error: 'Two-Factor Authentication required. Please enter 6-digit authenticator code from your phone app.',
        require2FA: true
      });
    }

    try {
      const plainSecret = decryptAtRest(user.totpSecretEncrypted);
      if (!verifyTotp(totpToken, plainSecret)) {
        pairing.attempts++;
        db.updatePairingCode(code, { attempts: pairing.attempts });
        return res.status(401).json({
          error: 'Invalid 2FA code. Device pairing rejected.',
          attemptsRemaining: config.maxPairingAttempts - pairing.attempts
        });
      }
    } catch (e) {
      return res.status(500).json({ error: '2FA verification error.' });
    }
  }

  // Generate secure device-bound credential token
  const { token, tokenHash } = generateDeviceToken();

  // Create device record
  const device = db.createDevice(user.id, deviceName, tokenHash);

  // Consume code atomically
  db.updatePairingCode(code, {
    status: 'consumed',
    proposedDeviceName: deviceName,
    deviceTokenHash: tokenHash,
    deviceId: device.id,
    consumedAt: new Date().toISOString()
  });

  // Notify desktop session over WebSocket
  wsHub.broadcastToUser(user.id, 'pairing:approved', {
    deviceId: device.id,
    deviceName: device.deviceName,
    timestamp: device.pairingTimestamp
  });

  wsHub.broadcastPairingUpdate(code, 'pairing:success', {
    deviceId: device.id,
    deviceName: device.deviceName
  });

  return res.json({
    success: true,
    message: 'Device successfully paired to SPECTRA.',
    device: {
      id: device.id,
      name: device.deviceName,
      owner: user.username,
      pairingTimestamp: device.pairingTimestamp
    },
    deviceToken: token // Delivered securely to phone for subsequent upload authorizations
  });
});

// GET /api/devices (List user's paired devices)
pairingRouter.get('/devices', requireAuth, (req, res) => {
  const devices = db.getUserDevices(req.user.id);
  return res.json({
    success: true,
    devices: devices
  });
});

// POST /api/devices/:deviceId/revoke (Revoke trusted device)
pairingRouter.post('/devices/:deviceId/revoke', requireAuth, (req, res) => {
  const { deviceId } = req.params;
  const revoked = db.revokeDevice(deviceId, req.user.id);
  if (!revoked) {
    return res.status(404).json({ error: 'Device not found or not owned by user.' });
  }

  // Broadcast revocation immediately over WebSocket
  wsHub.broadcastToUser(req.user.id, 'device:revoked', {
    deviceId: revoked.id,
    deviceName: revoked.deviceName,
    revokedAt: revoked.revokedAt
  });

  return res.json({
    success: true,
    message: `Trust revoked for device "${revoked.deviceName}".`,
    device: revoked
  });
});
