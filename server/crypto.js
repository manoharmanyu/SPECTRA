import crypto from 'crypto';
import { config } from './config.js';

// Base32 RFC 4648 alphabet for standard TOTP keys
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_CHARS[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_CHARS[(value << (5 - bits)) & 31];
  }

  return output;
}

export function base32Decode(base32Str) {
  const cleaned = base32Str.toUpperCase().replace(/=+$/, '').replace(/\s+/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < cleaned.length; i++) {
    const val = BASE32_CHARS.indexOf(cleaned[i]);
    if (val === -1) {
      throw new Error(`Invalid base32 character: ${cleaned[i]}`);
    }
    value = (value << 5) | val;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

// RFC 6238 TOTP generator
export function generateTotp(secretBase32, timeStepSeconds = 30, epochTimeMs = Date.now()) {
  const secretKey = base32Decode(secretBase32);
  const counter = Math.floor(epochTimeMs / 1000 / timeStepSeconds);
  
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));

  const hmac = crypto.createHmac('sha1', secretKey);
  hmac.update(counterBuffer);
  const digest = hmac.digest();

  // Dynamic Truncation
  const offset = digest[digest.length - 1] & 0x0f;
  const binary =
    ((digest[offset] & 0x7f) << 24) |
    ((digest[offset + 1] & 0xff) << 16) |
    ((digest[offset + 2] & 0xff) << 8) |
    (digest[offset + 3] & 0xff);

  const otp = (binary % 1000000).toString().padStart(6, '0');
  return otp;
}

// Verify TOTP allowing window drift (-1, 0, +1)
export function verifyTotp(token, secretBase32, window = 1) {
  if (!token || typeof token !== 'string') return false;
  const sanitized = token.trim();
  if (!/^\d{6}$/.test(sanitized)) return false;

  const now = Date.now();
  const step = 30 * 1000;

  for (let i = -window; i <= window; i++) {
    const checkTime = now + i * step;
    const expected = generateTotp(secretBase32, 30, checkTime);
    if (crypto.timingSafeEqual(Buffer.from(sanitized), Buffer.from(expected))) {
      return true;
    }
  }
  return false;
}

// Generate new TOTP setup data
export function generateTotpSecret(username) {
  const rawBytes = crypto.randomBytes(20);
  const secret = base32Encode(rawBytes);
  const issuer = 'SPECTRA';
  const uri = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(username)}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
  return { secret, uri };
}

// Generate single-use recovery codes
export function generateRecoveryCodes(count = 10) {
  const plain = [];
  const hashed = [];

  for (let i = 0; i < count; i++) {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase(); // 8 chars e.g. 4F9B2C1A
    plain.push(code);
    hashed.push(crypto.createHash('sha256').update(code).digest('hex'));
  }

  return { plain, hashed };
}

export function verifyRecoveryCode(inputCode, hashedList) {
  const normalized = inputCode.trim().toUpperCase().replace(/[^A-F0-9]/g, '');
  const testHash = crypto.createHash('sha256').update(normalized).digest('hex');
  const index = hashedList.findIndex(h => h === testHash);
  if (index !== -1) {
    return { valid: true, index };
  }
  return { valid: false, index: -1 };
}

// AES-256-GCM Encryption at rest for secrets
export function encryptAtRest(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', config.encryptionKey, iv);
  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return {
    iv: iv.toString('hex'),
    ciphertext: encrypted,
    tag: tag
  };
}

export function decryptAtRest(encryptedObj) {
  if (!encryptedObj || !encryptedObj.iv || !encryptedObj.ciphertext || !encryptedObj.tag) {
    throw new Error('Malformed encrypted payload');
  }
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    config.encryptionKey,
    Buffer.from(encryptedObj.iv, 'hex')
  );
  decipher.setAuthTag(Buffer.from(encryptedObj.tag, 'hex'));
  let decrypted = decipher.update(encryptedObj.ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Password hashing with scrypt
export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derivedKey = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 });
  return {
    hash: derivedKey.toString('hex'),
    salt: salt
  };
}

export function verifyPassword(password, storedHash, storedSalt) {
  if (!password || !storedHash || !storedSalt) return false;
  try {
    const testKey = crypto.scryptSync(password, storedSalt, 64, { N: 16384, r: 8, p: 1 });
    const storedBuf = Buffer.from(storedHash, 'hex');
    if (testKey.length !== storedBuf.length) return false;
    return crypto.timingSafeEqual(testKey, storedBuf);
  } catch (e) {
    return false;
  }
}

// Temporary, unpredictable pairing code generator
// 8 uppercase characters, avoiding easily confused letters (0, O, 1, I)
const PAIRING_CHARS = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';
export function generatePairingCode() {
  const bytes = crypto.randomBytes(8);
  let code = '';
  for (let i = 0; i < 8; i++) {
    code += PAIRING_CHARS[bytes[i] % PAIRING_CHARS.length];
    if (i === 3) code += '-'; // Format: ABCD-EFGH for readability
  }
  return code;
}

// Device-bound authentication token
export function generateDeviceToken() {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  return { token, tokenHash };
}
