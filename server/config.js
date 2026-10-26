import path from 'path';
import { fileURLToPath } from 'url';
import os from 'os';
import crypto from 'crypto';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export function getLocalIpAddress() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      // Skip internal and non-IPv4 addresses
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1';
}

export const config = {
  port: parseInt(process.env.PORT || '3001', 10),
  host: process.env.HOST || '0.0.0.0',
  vitePort: parseInt(process.env.VITE_PORT || '5173', 10),
  dataDir: path.resolve(__dirname, '../data'),
  uploadsDir: path.resolve(__dirname, '../uploads'),
  sessionSecret: process.env.SESSION_SECRET || 'spectra_sec_session_32_bytes_token_key_auth',
  // 32-byte key for AES-256-GCM encryption of TOTP secrets at rest
  encryptionKey: crypto.createHash('sha256').update(process.env.ENCRYPTION_SECRET || 'spectra_totp_aes_master_secret').digest(),
  pairingCodeTtlMs: 5 * 60 * 1000, // 5 minutes
  maxPairingAttempts: 5,
  sessionTtlMs: 24 * 60 * 60 * 1000, // 24 hours
  maxUploadSizeBytes: 15 * 1024 * 1024, // 15MB
};
