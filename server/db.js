import fs from 'fs';
import path from 'path';
import { config } from './config.js';
import { hashPassword } from './crypto.js';

const DB_FILE = process.env.SPECTRA_DB_FILE || (process.env.NODE_ENV === 'test' 
  ? path.join(config.dataDir, 'spectra_test.json') 
  : path.join(config.dataDir, 'spectra.json'));

function ensureDirectories() {
  try {
    if (!fs.existsSync(config.dataDir)) {
      fs.mkdirSync(config.dataDir, { recursive: true });
    }
    if (!fs.existsSync(config.uploadsDir)) {
      fs.mkdirSync(config.uploadsDir, { recursive: true });
    }
  } catch (e) {
    console.warn('Directory creation notice:', e.message);
  }
}

class SpectraDB {
  constructor() {
    ensureDirectories();
    this.data = {
      users: [],
      sessions: [],
      pairingCodes: [],
      devices: [],
      jobs: []
    };
    this.load();
    this.initDefaultUsers();
  }

  load() {
    try {
      if (fs.existsSync(DB_FILE)) {
        const raw = fs.readFileSync(DB_FILE, 'utf8');
        this.data = JSON.parse(raw);
      } else {
        // Fallback to bundled repo DB if running in ephemeral /tmp
        const bundledDb = path.resolve(__dirname, '../data/spectra.json');
        if (fs.existsSync(bundledDb)) {
          const raw = fs.readFileSync(bundledDb, 'utf8');
          this.data = JSON.parse(raw);
          this.save();
        } else {
          this.save();
        }
      }
      if (!this.data.users) this.data.users = [];
      if (!this.data.sessions) this.data.sessions = [];
      if (!this.data.pairingCodes) this.data.pairingCodes = [];
      if (!this.data.devices) this.data.devices = [];
      if (!this.data.jobs) this.data.jobs = [];
    } catch (e) {
      console.error('Error loading database, initializing fresh state:', e);
      this.save();
    }
  }

  save() {
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(this.data, null, 2), 'utf8');
    } catch (e) {
      console.error('Failed to save database:', e);
    }
  }

  initDefaultUsers() {
    // Seed default administrator if not present
    const existing = this.findUserByUsername('manohar_manyu');
    if (!existing) {
      const { hash, salt } = hashPassword('80081Abc@2005');
      const adminUser = {
        id: 'usr_manohar_manyu',
        username: 'manohar_manyu',
        passwordHash: hash,
        salt: salt,
        totpSecretEncrypted: null,
        totpEnabled: false,
        recoveryCodesHashed: [],
        createdAt: new Date().toISOString()
      };
      this.data.users.push(adminUser);
      this.save();
    }
  }

  // --- Users ---
  findUserById(id) {
    return this.data.users.find(u => u.id === id);
  }

  findUserByUsername(username) {
    if (!username) return null;
    const lower = username.toLowerCase().trim();
    return this.data.users.find(u => u.username.toLowerCase() === lower);
  }

  createUser(username, password) {
    const existing = this.findUserByUsername(username);
    if (existing) {
      throw new Error('User already exists');
    }
    const { hash, salt } = hashPassword(password);
    const user = {
      id: 'usr_' + Date.now().toString(36) + Math.random().toString(36).substring(2, 6),
      username: username.trim(),
      passwordHash: hash,
      salt: salt,
      totpSecretEncrypted: null,
      totpEnabled: false,
      recoveryCodesHashed: [],
      createdAt: new Date().toISOString()
    };
    this.data.users.push(user);
    this.save();
    return user;
  }

  updateUser(id, updates) {
    const idx = this.data.users.findIndex(u => u.id === id);
    if (idx !== -1) {
      this.data.users[idx] = { ...this.data.users[idx], ...updates };
      this.save();
      return this.data.users[idx];
    }
    return null;
  }

  // --- Sessions ---
  createSession(userId, is2FAVerified = false, ip = '', userAgent = '') {
    // Remove expired sessions periodically
    const now = Date.now();
    this.data.sessions = this.data.sessions.filter(s => new Date(s.expiresAt).getTime() > now);

    const sessionId = 'ses_' + Math.random().toString(36).substring(2, 10) + Date.now().toString(36);
    const session = {
      id: sessionId,
      userId,
      is2FAVerified,
      ip,
      userAgent,
      expiresAt: new Date(now + config.sessionTtlMs).toISOString(),
      createdAt: new Date().toISOString()
    };
    this.data.sessions.push(session);
    this.save();
    return session;
  }

  findSession(sessionId) {
    if (!sessionId) return null;
    const session = this.data.sessions.find(s => s.id === sessionId);
    if (!session) return null;
    if (new Date(session.expiresAt).getTime() < Date.now()) {
      this.deleteSession(sessionId);
      return null;
    }
    return session;
  }

  updateSession(sessionId, updates) {
    const idx = this.data.sessions.findIndex(s => s.id === sessionId);
    if (idx !== -1) {
      this.data.sessions[idx] = { ...this.data.sessions[idx], ...updates };
      this.save();
      return this.data.sessions[idx];
    }
    return null;
  }

  deleteSession(sessionId) {
    this.data.sessions = this.data.sessions.filter(s => s.id !== sessionId);
    this.save();
  }

  // --- Pairing Codes ---
  createPairingCode(userId, sessionId, code) {
    const cleanCode = code.replace(/[^A-Z0-9]/gi, '').toUpperCase();
    const pairing = {
      code: cleanCode,
      displayCode: code,
      userId,
      sessionId,
      attempts: 0,
      status: 'pending', // pending, claimed, confirmed, expired, revoked
      proposedDeviceName: null,
      deviceTokenHash: null,
      deviceId: null,
      expiresAt: new Date(Date.now() + config.pairingCodeTtlMs).toISOString(),
      createdAt: new Date().toISOString()
    };
    this.data.pairingCodes.push(pairing);
    this.save();
    return pairing;
  }

  findPairingCode(code) {
    if (!code) return null;
    const clean = code.replace(/[^A-Z0-9]/gi, '').toUpperCase();
    const found = this.data.pairingCodes.find(p => p.code === clean);
    if (!found) return null;
    if (new Date(found.expiresAt).getTime() < Date.now() && found.status === 'pending') {
      found.status = 'expired';
      this.save();
    }
    return found;
  }

  updatePairingCode(code, updates) {
    const clean = code.replace(/[^A-Z0-9]/gi, '').toUpperCase();
    const idx = this.data.pairingCodes.findIndex(p => p.code === clean);
    if (idx !== -1) {
      this.data.pairingCodes[idx] = { ...this.data.pairingCodes[idx], ...updates };
      this.save();
      return this.data.pairingCodes[idx];
    }
    return null;
  }

  // --- Devices ---
  createDevice(userId, deviceName, tokenHash, capabilities = ['capture', 'upload', 'sync']) {
    const device = {
      id: 'dev_' + Date.now().toString(36) + Math.random().toString(36).substring(2, 6),
      userId,
      deviceName: deviceName.trim(),
      tokenHash,
      trustStatus: 'active', // active, revoked
      pairingTimestamp: new Date().toISOString(),
      lastSeenTimestamp: new Date().toISOString(),
      revokedAt: null,
      capabilities
    };
    this.data.devices.push(device);
    this.save();
    return device;
  }

  findDeviceById(deviceId) {
    return this.data.devices.find(d => d.id === deviceId);
  }

  findDeviceByTokenHash(tokenHash) {
    return this.data.devices.find(d => d.tokenHash === tokenHash);
  }

  getUserDevices(userId) {
    return this.data.devices
      .filter(d => d.userId === userId)
      .map(d => ({
        id: d.id,
        deviceName: d.deviceName,
        trustStatus: 'active',
        pairingTimestamp: d.pairingTimestamp,
        lastSeenTimestamp: d.lastSeenTimestamp,
        revokedAt: null,
        capabilities: d.capabilities
      }));
  }

  disconnectDevice(deviceId, userId) {
    const idx = this.data.devices.findIndex(d => d.id === deviceId && (!userId || d.userId === userId));
    if (idx !== -1) {
      const removed = this.data.devices.splice(idx, 1)[0];
      this.save();
      return removed;
    }
    return null;
  }

  revokeDevice(deviceId, userId) {
    return this.disconnectDevice(deviceId, userId);
  }

  deleteDevice(deviceId, userId) {
    const idx = this.data.devices.findIndex(d => d.id === deviceId && (!userId || d.userId === userId));
    if (idx !== -1) {
      const removed = this.data.devices.splice(idx, 1)[0];
      this.save();
      return removed;
    }
    return null;
  }

  deleteJob(jobId) {
    const idx = this.data.jobs.findIndex(j => j.id === jobId);
    if (idx !== -1) {
      const removed = this.data.jobs.splice(idx, 1)[0];
      this.save();
      return removed;
    }
    return null;
  }

  deleteUser(userId) {
    const idx = this.data.users.findIndex(u => u.id === userId);
    if (idx !== -1) {
      const removed = this.data.users.splice(idx, 1)[0];
      this.save();
      return removed;
    }
    return null;
  }

  deleteSession(sessionId) {
    const idx = this.data.sessions.findIndex(s => s.id === sessionId);
    if (idx !== -1) {
      this.data.sessions.splice(idx, 1);
      this.save();
    }
  }

  updateDeviceActivity(deviceId) {
    const dev = this.data.devices.find(d => d.id === deviceId);
    if (dev) {
      dev.lastSeenTimestamp = new Date().toISOString();
      this.save();
    }
  }

  // --- Jobs / Forensic Artifacts ---
  createJob(jobData) {
    const job = {
      id: 'job_' + Date.now().toString(36) + Math.random().toString(36).substring(2, 8),
      uploadId: 'upl_' + Date.now().toString(36) + Math.random().toString(36).substring(2, 6),
      status: 'pending',
      progressPct: 0,
      createdAt: new Date().toISOString(),
      ...jobData
    };
    this.data.jobs.unshift(job);
    this.save();
    return job;
  }

  findJob(jobId) {
    this.load();
    return this.data.jobs.find(j => j.id === jobId);
  }

  getUserJobs(userId) {
    this.load();
    return this.data.jobs.filter(j => j.userId === userId);
  }

  updateJob(jobId, updates) {
    const idx = this.data.jobs.findIndex(j => j.id === jobId);
    if (idx !== -1) {
      this.data.jobs[idx] = { ...this.data.jobs[idx], ...updates };
      this.save();
      return this.data.jobs[idx];
    }
    return null;
  }
}

export const db = new SpectraDB();
