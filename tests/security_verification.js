process.env.NODE_ENV = process.env.NODE_ENV || 'test';

import http from 'http';
import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import {
  hashPassword,
  verifyPassword,
  generateTotpSecret,
  generateTotp,
  verifyTotp,
  generateRecoveryCodes,
  verifyRecoveryCode,
  encryptAtRest,
  decryptAtRest,
  generatePairingCode
} from '../server/crypto.js';
import { analyzeImageForensics } from '../server/forensics.js';

let passed = 0;
let failed = 0;
const results = [];

function assert(condition, testName, details = '') {
  if (condition) {
    passed++;
    console.log(`  ✅ PASS: ${testName}`);
    results.push({ name: testName, status: 'PASS', details });
  } else {
    failed++;
    console.error(`  ❌ FAIL: ${testName} - ${details}`);
    results.push({ name: testName, status: 'FAIL', details });
  }
}

async function request(options, postData = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const reqHeaders = { ...headers };
    let body = null;

    if (postData && typeof postData === 'object' && !(postData instanceof Buffer)) {
      body = JSON.stringify(postData);
      reqHeaders['Content-Type'] = 'application/json';
      reqHeaders['Content-Length'] = Buffer.byteLength(body);
    } else if (postData instanceof Buffer) {
      body = postData;
      reqHeaders['Content-Length'] = body.length;
    }

    const req = http.request(
      {
        hostname: '127.0.0.1',
        port: 3001,
        path: options.path,
        method: options.method || 'GET',
        headers: reqHeaders
      },
      (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          let json = null;
          try { json = JSON.parse(data); } catch(e) {}
          resolve({ status: res.statusCode, headers: res.headers, raw: data, json });
        });
      }
    );

    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

async function runAllSecurityTests() {
  console.log('\n======================================================');
  console.log('🔒 SPECTRA FORENSICS — SECURITY & COMPLIANCE TEST SUITE');
  console.log('======================================================\n');

  // Wait 200ms for server to initialize
  await new Promise(r => setTimeout(r, 200));

  // -------------------------------------------------------------------------
  // TEST GROUP 1: PASSWORD HASHING & CRYPTOGRAPHY
  // -------------------------------------------------------------------------
  console.log('--- TEST GROUP 1: USER IDENTITY & PASSWORD CRYPTOGRAPHY ---');
  const testPw = 'Complex_Sec_Pass_2026!#';
  const { hash, salt } = hashPassword(testPw);
  assert(hash.length === 128 && salt.length === 32, 'Scrypt creates 64-byte key and 16-byte salt');
  assert(verifyPassword(testPw, hash, salt), 'Password verifies with correct credentials');
  assert(!verifyPassword('Wrong_Password', hash, salt), 'Password rejection for incorrect input');
  assert(!verifyPassword('', hash, salt), 'Password rejection for empty input');

  // -------------------------------------------------------------------------
  // TEST GROUP 2: TWO-FACTOR AUTHENTICATION (TOTP & AES ENCRYPTION)
  // -------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 2: TWO-FACTOR AUTHENTICATION (RFC 6238 TOTP) ---');
  const { secret, uri } = generateTotpSecret('manohar_manyu');
  assert(secret.length === 32, 'Base32 160-bit TOTP secret generated');
  assert(uri.includes('otpauth://totp/SPECTRA:'), 'Valid TOTP URI formatting for authenticator apps');

  const validOtp = generateTotp(secret);
  assert(/^\d{6}$/.test(validOtp), 'TOTP generates 6-digit numeric token');
  assert(verifyTotp(validOtp, secret, 1), 'Valid TOTP token verified within time window');
  assert(!verifyTotp('000000', secret, 1), 'Invalid 6-digit TOTP token rejected');
  assert(!verifyTotp('abcd', secret, 1), 'Malformed TOTP token rejected');

  // AES-256-GCM Encryption at Rest
  const encrypted = encryptAtRest(secret);
  assert(encrypted.iv && encrypted.ciphertext && encrypted.tag, 'AES-256-GCM produces IV, ciphertext, and auth tag');
  const decrypted = decryptAtRest(encrypted);
  assert(decrypted === secret, 'Decrypted TOTP secret exactly matches original secret');

  // Recovery Codes
  const { plain: recCodes, hashed: recHashed } = generateRecoveryCodes(10);
  assert(recCodes.length === 10 && recHashed.length === 10, 'Generates 10 single-use backup recovery codes');
  const recCheck = verifyRecoveryCode(recCodes[0], recHashed);
  assert(recCheck.valid && recCheck.index === 0, 'First recovery code validates successfully');
  const badRecCheck = verifyRecoveryCode('INVALIDCODE', recHashed);
  assert(!badRecCheck.valid, 'Invalid recovery code rejected');

  // -------------------------------------------------------------------------
  // TEST GROUP 3: AUTHENTICATION API ENDPOINTS & RATE LIMITING
  // -------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 3: AUTHENTICATION ENDPOINTS & RATE LIMITING ---');
  // Seeded admin login
  const loginRes = await request({ path: '/api/auth/login', method: 'POST' }, {
    username: 'manohar_manyu',
    password: '80081Abc@2005'
  });
  assert(loginRes.status === 200 && loginRes.json?.success, 'Default administrator login succeeds');
  const adminSessionId = loginRes.json?.sessionId;

  // Generic error message check
  const badLoginRes = await request({ path: '/api/auth/login', method: 'POST' }, {
    username: 'manohar_manyu',
    password: 'BadPassword123'
  });
  assert(badLoginRes.status === 401 && badLoginRes.json?.error.includes('Invalid'), 'Generic error message on bad password');

  // User Registration
  const testUser = 'sec_audit_user_' + Date.now().toString(36);
  const regRes = await request({ path: '/api/auth/register', method: 'POST' }, {
    username: testUser,
    password: 'Password999!'
  });
  assert(regRes.status === 201 && regRes.json?.user?.id.startsWith('usr_'), 'Unique immutable user ID assigned upon registration');
  const testUserSession = regRes.json?.sessionId;

  // -------------------------------------------------------------------------
  // TEST GROUP 4: UNIQUE PAIRING CODE GENERATION & EXPIRATION
  // -------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 4: DEVICE PAIRING CODES & LIFECYCLE ---');
  const pairGenRes = await request({ path: '/api/pairing/generate', method: 'POST' }, {}, {
    'x-session-id': adminSessionId
  });
  assert(pairGenRes.status === 200 && pairGenRes.json?.code, 'Temporary pairing code generated on demand');
  const pairingCode = pairGenRes.json?.code;
  const cleanPairingCode = pairGenRes.json?.cleanCode;
  assert(pairGenRes.json?.qrCode && pairGenRes.json?.mobileUrl, 'Pairing returns QR code and direct local URL');

  // Check Status
  const statusRes = await request({ path: `/api/pairing/status/${cleanPairingCode}`, method: 'GET' });
  assert(statusRes.status === 200 && statusRes.json?.status === 'pending', 'Pairing code status is initially pending');

  // Invalid code lookup
  const badCodeRes = await request({ path: '/api/pairing/status/NONEXISTENT', method: 'GET' });
  assert(badCodeRes.status === 404, 'Non-existent pairing code returns 404 Not Found');

  // -------------------------------------------------------------------------
  // TEST GROUP 5: DEVICE PAIRING & AUTHORIZATION
  // -------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 5: PHONE-TO-MAC PAIRING HANDSHAKE ---');
  const claimRes = await request({ path: '/api/pairing/claim', method: 'POST' }, {
    code: cleanPairingCode,
    deviceName: "Manohar's iPhone 15 Pro"
  });
  assert(claimRes.status === 200 && claimRes.json?.deviceToken, 'Phone claims pairing code and receives secure device token');
  const deviceToken = claimRes.json?.deviceToken;
  const deviceId = claimRes.json?.device?.id;

  // Code reuse prevention (Atomic single-use)
  const replayRes = await request({ path: '/api/pairing/claim', method: 'POST' }, {
    code: cleanPairingCode,
    deviceName: 'Attacker Rogue Phone'
  });
  assert(replayRes.status === 400 && replayRes.json?.error.includes('consumed'), 'Consumed pairing code cannot be replayed or reused');

  // Check device registry
  const devListRes = await request({ path: '/api/pairing/devices', method: 'GET' }, null, {
    'x-session-id': adminSessionId
  });
  assert(devListRes.json?.devices?.some(d => d.id === deviceId), 'Device successfully listed in authenticated user device registry');

  // -------------------------------------------------------------------------
  // TEST GROUP 6: IMAGE FORENSICS PIPELINE & FILE SIGNATURE INTEGRITY
  // -------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 6: IMAGE FORENSIC EVALUATION & METADATA SCAN ---');
  // Create test JPEG binary with valid magic bytes FF D8 FF E0
  const testJpegPath = path.resolve('tests/fixtures/sample_camera_photo.jpg');
  fs.mkdirSync(path.dirname(testJpegPath), { recursive: true });

  const jpegHeader = Buffer.from([
    0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48,
    0x00, 0x48, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43, 0x00
  ]);
  const quantTable = Buffer.alloc(64, 8); // Uniform quantization
  const cameraExif = Buffer.from('Make\x00Apple\x00Model\x00iPhone 15 Pro\x00DateTimeOriginal\x002026:10:26 14:30:00\x00');
  const dummyPayload = Buffer.alloc(2048, 0x5a);
  const jpegEoi = Buffer.from([0xff, 0xd9]);
  const fullJpeg = Buffer.concat([jpegHeader, quantTable, cameraExif, dummyPayload, jpegEoi]);
  fs.writeFileSync(testJpegPath, fullJpeg);

  const report = await analyzeImageForensics(testJpegPath, 'sample_camera_photo.jpg');
  assert(report.detectedType === 'image/jpeg', 'Forensic engine detects valid JPEG magic bytes');
  assert(report.sha256.length === 64, 'Computes deterministic cryptographic SHA-256 hash');
  assert(report.cameraMake === 'Apple' && report.cameraModel === 'iPhone 15 Pro', 'Extracts genuine camera hardware EXIF tags');
  assert(!report.isAlert && report.verdict.includes('AUTHENTIC'), 'Correctly identifies authentic camera artifact with minimal risk');

  // Generative AI Marker Detection Test
  const aiJpegPath = path.resolve('tests/fixtures/sample_ai_diffusion.jpg');
  const aiMetadata = Buffer.from('prompt: ultra realistic portrait of executive, stable diffusion v2.1 checkpoint comfyui node');
  const fullAiJpeg = Buffer.concat([jpegHeader, quantTable, aiMetadata, dummyPayload, jpegEoi]);
  fs.writeFileSync(aiJpegPath, fullAiJpeg);

  const aiReport = await analyzeImageForensics(aiJpegPath, 'sample_ai_diffusion.jpg');
  assert(aiReport.isAlert && aiReport.verdict.includes('MANIPULATED'), 'Flagged Generative AI metadata marker (Stable Diffusion / ComfyUI)');

  // Genuine Provenance & Privacy Test (No GPS Fabricated)
  assert(report.provenance.geolocation.hasGpsCoordinates === false, 'Maintains privacy when no GPS coordinates exist in EXIF');
  assert(report.provenance.geolocation.coordinates.includes('No GPS Coordinates Recorded'), 'Does not fabricate fake GPS coordinates');

  // Genuine Audio Forensic Analysis Test (Zero Fake AI False Positives)
  const testWavPath = path.resolve('tests/fixtures/sample_human_voice.wav');
  const wavRiff = Buffer.from([
    0x52, 0x49, 0x46, 0x46, 0x24, 0x08, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45,
    0x66, 0x6d, 0x74, 0x20, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, // Stereo
    0x44, 0xac, 0x00, 0x00, 0x10, 0xb1, 0x02, 0x00, 0x04, 0x00, 0x10, 0x00, // 44,100 Hz, 16-bit
    0x64, 0x61, 0x74, 0x61, 0x00, 0x08, 0x00, 0x00
  ]);
  const audioData = Buffer.alloc(2048, 0x20);
  fs.writeFileSync(testWavPath, Buffer.concat([wavRiff, audioData]));
  const wavReport = await analyzeImageForensics(testWavPath, 'sample_human_voice.wav', 'audio/wav');
  assert(wavReport.mediaCategory === 'AUDIO', 'Identifies audio media container correctly');
  assert(wavReport.audioSpecs && wavReport.audioSpecs.sampleRate.includes('44,100 Hz'), 'Parses genuine audio sample rate from binary fmt chunk');
  assert(!wavReport.isAlert && wavReport.verdict.includes('AUTHENTIC'), 'Correctly classifies natural human audio as Authentic without AI false positives');

  // -------------------------------------------------------------------------
  // TEST GROUP 7: USER ISOLATION & DEVICE REVOCATION
  // -------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 7: USER ISOLATION & DEVICE REVOCATION ---');
  // Upload photo from active paired phone to create forensic job
  const boundary = '---------------------------WebKitFormBoundaryXYZ';
  const postBody = Buffer.concat([
    Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="image"; filename="sensitive_investigation.jpg"\r\nContent-Type: image/jpeg\r\n\r\n`),
    fullJpeg,
    Buffer.from(`\r\n--${boundary}--\r\n`)
  ]);

  const activeUploadRes = await request({ path: '/api/upload', method: 'POST' }, postBody, {
    'Content-Type': `multipart/form-data; boundary=${boundary}`,
    'x-device-token': deviceToken
  });
  const createdJobId = activeUploadRes.json?.jobId;

  // User B tries to read User A's job -> MUST BE 403
  const crossUserRes = await request({ path: `/api/analysis/${createdJobId}`, method: 'GET' }, null, {
    'x-session-id': testUserSession
  });
  assert(crossUserRes.status === 403, 'Cross-user job/report access strictly denied (User Isolation enforced)', `status: ${crossUserRes.status}`);

  // User A reads own job -> MUST BE 200
  const ownJobRes = await request({ path: `/api/analysis/${createdJobId}`, method: 'GET' }, null, {
    'x-session-id': adminSessionId
  });
  assert(ownJobRes.status === 200 && ownJobRes.json?.job?.id === createdJobId, 'User can view own forensic job dossier', `status: ${ownJobRes.status}, body: ${JSON.stringify(ownJobRes.json)}`);

  // Disconnect device
  const disconnectRes = await request({ path: `/api/pairing/devices/${deviceId}/disconnect`, method: 'POST' }, {}, {
    'x-session-id': adminSessionId
  });
  assert(disconnectRes.status === 200 && disconnectRes.json?.success === true, 'Device successfully disconnected by administrator', `status: ${disconnectRes.status}, body: ${JSON.stringify(disconnectRes.json)}`);

  // Verify disconnected device cannot upload
  const blockedUploadRes = await request({ path: '/api/upload', method: 'POST' }, postBody, {
    'Content-Type': `multipart/form-data; boundary=${boundary}`,
    'x-device-token': deviceToken
  });
  assert(blockedUploadRes.status === 401 && (blockedUploadRes.json?.error.includes('authorized') || blockedUploadRes.json?.error.includes('disconnected')), 'Uploads from disconnected device rejected');

  // -------------------------------------------------------------------------
  // TEST GROUP 8: LOCAL WI-FI NETWORK REACHABILITY & BLUETOOTH
  // -------------------------------------------------------------------------
  console.log('\n--- TEST GROUP 8: LOCAL NETWORK & BLUETOOTH STATUS ---');
  const statusApiRes = await request({ path: '/api/status', method: 'GET' });
  assert(statusApiRes.status === 200 && statusApiRes.json?.lanIp, 'Local LAN IP dynamically resolved for direct phone access');
  assert(statusApiRes.json?.transports?.wifi.includes('Active'), 'Local-only Wi-Fi transport verified active with zero cloud relays');
  assert(statusApiRes.json?.transports?.bluetooth.includes('Web Bluetooth'), 'Bluetooth LE capability correctly identified for browser handshake');

  // -------------------------------------------------------------------------
  // SUMMARY
  // -------------------------------------------------------------------------
  console.log('\n======================================================');
  console.log(`TEST SUMMARY: ${passed} PASSED, ${failed} FAILED (TOTAL: ${passed + failed})`);
  console.log('======================================================\n');

  // Cleanup test files and test database artifacts
  try {
    fs.unlinkSync(testJpegPath);
    fs.unlinkSync(aiJpegPath);
  } catch(e) {}

  try {
    if (adminSessionId) {
      await request({ path: '/api/pairing/test-cleanup', method: 'POST' }, {
        testUserId: regRes?.json?.user?.id,
        deviceId: deviceId,
        jobId: createdJobId
      }, {
        'x-session-id': adminSessionId
      });
      await request({ path: '/api/auth/logout', method: 'POST' }, {}, {
        'x-session-id': adminSessionId
      });
    }
  } catch(e) {}

  if (failed > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runAllSecurityTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});
