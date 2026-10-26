import express from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { db } from '../db.js';
import { config } from '../config.js';
import { wsHub } from '../ws.js';
import { analyzeImageForensics } from '../forensics.js';
import { requireAuth } from './auth.js';

export const uploadRouter = express.Router();

// Device authentication middleware for mobile upload
export function requireDeviceOrSession(req, res, next) {
  const deviceToken = req.headers['x-device-token'];
  const sessionToken =
    req.cookies?.spectra_session ||
    req.headers['x-session-id'] ||
    (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
      ? req.headers.authorization.substring(7)
      : null);

  // 1. Try Device Token
  if (deviceToken) {
    const tokenHash = crypto.createHash('sha256').update(deviceToken).digest('hex');
    const device = db.findDeviceByTokenHash(tokenHash);
    if (!device || device.trustStatus !== 'active') {
      return res.status(401).json({ error: 'Device is not authorized or trust has been revoked.' });
    }
    const user = db.findUserById(device.userId);
    if (!user) {
      return res.status(401).json({ error: 'Associated user account not found.' });
    }
    db.updateDeviceActivity(device.id);
    req.device = device;
    req.user = user;
    return next();
  }

  // 2. Try User Session
  if (sessionToken) {
    const session = db.findSession(sessionToken);
    if (session && (!session.is2FAVerified && db.findUserById(session.userId)?.totpEnabled)) {
      return res.status(403).json({ error: 'Two-factor authentication required.' });
    }
    if (session) {
      const user = db.findUserById(session.userId);
      if (user) {
        req.user = user;
        req.device = { id: 'web_desktop', deviceName: 'Desktop Web Client' };
        return next();
      }
    }
  }

  return res.status(401).json({ error: 'Authentication required. Missing device token or session.' });
}

// Multer Storage Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (!fs.existsSync(config.uploadsDir)) {
      fs.mkdirSync(config.uploadsDir, { recursive: true });
    }
    cb(null, config.uploadsDir);
  },
  filename: (req, file, cb) => {
    const randomHex = crypto.randomBytes(8).toString('hex');
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `spectra_${Date.now()}_${randomHex}${ext}`);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedExts = ['.jpg', '.jpeg', '.png', '.webp'];
  const ext = path.extname(file.originalname).toLowerCase();
  const allowedMimes = ['image/jpeg', 'image/png', 'image/webp'];

  if (allowedExts.includes(ext) && allowedMimes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file type. Only JPEG, PNG, and WebP images are permitted.'));
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: config.maxUploadSizeBytes },
  fileFilter: fileFilter
});

// POST /api/upload
uploadRouter.post('/upload', requireDeviceOrSession, upload.single('image'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No image file uploaded.' });
  }

  const user = req.user;
  const device = req.device;
  const filePath = req.file.path;
  const originalFilename = path.basename(req.file.originalname).replace(/[^a-zA-Z0-9._-]/g, '_');

  // Create Job Record
  const job = db.createJob({
    userId: user.id,
    deviceId: device.id,
    deviceName: device.deviceName,
    originalFilename: originalFilename,
    storedFilename: req.file.filename,
    storedPath: filePath,
    mimeType: req.file.mimetype,
    sizeBytes: req.file.size,
    status: 'analyzing',
    progressPct: 15
  });

  const imageUrl = `/uploads/${req.file.filename}`;

  // Notify desktop immediately over WebSocket: upload received!
  wsHub.broadcastToUser(user.id, 'sync:image_received', {
    jobId: job.id,
    uploadId: job.uploadId,
    deviceName: device.deviceName,
    fileName: originalFilename,
    fileSize: req.file.size,
    imageUrl: imageUrl,
    timestamp: job.createdAt
  });

  // Run Real Forensic Pipeline Asynchronously with incremental progress updates
  (async () => {
    try {
      wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 35, stage: 'Parsing file signatures & EXIF metadata' });
      await new Promise(r => setTimeout(r, 400));

      wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 65, stage: 'Evaluating quantization tables & frequency entropy' });
      await new Promise(r => setTimeout(r, 450));

      wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 85, stage: 'Scanning generative AI markers & neural noise signatures' });
      await new Promise(r => setTimeout(r, 350));

      const report = await analyzeImageForensics(filePath, originalFilename);

      // Save completed job in DB
      db.updateJob(job.id, {
        status: 'completed',
        progressPct: 100,
        sha256: report.sha256,
        forensicReport: report,
        completedAt: new Date().toISOString()
      });

      // Push final report to desktop session without page refresh
      wsHub.broadcastToUser(user.id, 'sync:analysis_complete', {
        jobId: job.id,
        uploadId: job.uploadId,
        fileName: originalFilename,
        imageUrl: imageUrl,
        deviceName: device.deviceName,
        report: report
      });
    } catch (err) {
      console.error('Forensic analysis error:', err);
      db.updateJob(job.id, { status: 'failed', error: err.message });
      wsHub.broadcastToUser(user.id, 'sync:failed', {
        jobId: job.id,
        error: 'Forensic analysis processing failed.'
      });
    }
  })();

  return res.json({
    success: true,
    message: 'Image uploaded and queued for real-time forensic analysis.',
    jobId: job.id,
    uploadId: job.uploadId,
    fileName: originalFilename,
    imageUrl: imageUrl
  });
});

// GET /api/analysis/:jobId (Retrieve analysis report - strictly scoped to user!)
uploadRouter.get('/analysis/:jobId', requireAuth, (req, res) => {
  const job = db.findJob(req.params.jobId);
  if (!job) {
    return res.status(404).json({ error: 'Forensic job record not found.' });
  }

  // Enforce User Isolation!
  if (job.userId !== req.user.id) {
    return res.status(403).json({ error: 'Access denied. You do not have permission to view this forensic dossier.' });
  }

  return res.json({
    success: true,
    job: {
      id: job.id,
      uploadId: job.uploadId,
      originalFilename: job.originalFilename,
      imageUrl: `/uploads/${job.storedFilename}`,
      status: job.status,
      deviceName: job.deviceName,
      createdAt: job.createdAt,
      forensicReport: job.forensicReport
    }
  });
});

// GET /api/jobs (List analyses for current user)
uploadRouter.get('/jobs', requireAuth, (req, res) => {
  const jobs = db.getUserJobs(req.user.id).map(j => ({
    id: j.id,
    uploadId: j.uploadId,
    originalFilename: j.originalFilename,
    imageUrl: `/uploads/${j.storedFilename}`,
    status: j.status,
    deviceName: j.deviceName,
    createdAt: j.createdAt,
    verdict: j.forensicReport?.verdict || 'PENDING',
    probability: j.forensicReport?.probability || 'Processing...',
    isAlert: j.forensicReport?.isAlert || false
  }));

  return res.json({
    success: true,
    jobs: jobs
  });
});
