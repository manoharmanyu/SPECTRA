import express from 'express';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { db } from '../db.js';
import { config } from '../config.js';
import { wsHub } from '../ws.js';
import { analyzeMediaForensics, analyzeImageForensics } from '../forensics.js';
import { requireAuth } from './auth.js';

export const uploadRouter = express.Router();

// Device authentication middleware for mobile upload
export function requireDeviceOrSession(req, res, next) {
  const deviceToken = req.headers['x-device-token'] || req.query.deviceToken;
  const sessionToken =
    req.cookies?.spectra_session ||
    req.headers['x-session-id'] ||
    (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')
      ? req.headers.authorization.substring(7)
      : null);

  // 1. Try Device Token
  if (deviceToken) {
    const tokenHash = crypto.createHash('sha256').update(deviceToken).digest('hex');
    const device = db.findDeviceByTokenHash(tokenHash) || db.data.devices.find(d => d.id === deviceToken || d.tokenHash === deviceToken);
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

// Universal File Filter: Image, Video, and Audio media
const fileFilter = (req, file, cb) => {
  const allowedExts = [
    // Images
    '.jpg', '.jpeg', '.png', '.webp', '.gif', '.bmp', '.tiff', '.heic',
    // Videos
    '.mp4', '.mov', '.avi', '.webm', '.mkv',
    // Audio
    '.mp3', '.wav', '.m4a', '.aac', '.flac', '.ogg'
  ];
  const ext = path.extname(file.originalname).toLowerCase();

  const isImage = file.mimetype.startsWith('image/') || allowedExts.slice(0, 8).includes(ext);
  const isVideo = file.mimetype.startsWith('video/') || allowedExts.slice(8, 13).includes(ext);
  const isAudio = file.mimetype.startsWith('audio/') || allowedExts.slice(13).includes(ext);
  const isOctet = file.mimetype === 'application/octet-stream' && allowedExts.includes(ext);

  if (isImage || isVideo || isAudio || isOctet || allowedExts.includes(ext)) {
    cb(null, true);
  } else {
    cb(new Error('Invalid file format. Supported formats: Images (JPEG, PNG, WebP), Videos (MP4, MOV, WebM), and Audio (MP3, WAV, M4A, FLAC).'));
  }
};

const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB max upload
  fileFilter: fileFilter
});

// Middleware to extract single file from multiple possible field names
const handleUploadFields = upload.any();

// POST /api/upload (Universal Image, Video, Audio Intake & Synchronization)
uploadRouter.post('/upload', requireDeviceOrSession, handleUploadFields, async (req, res) => {
  const uploadedFile = req.file || (req.files && req.files.length > 0 ? req.files[0] : null);

  if (!uploadedFile) {
    return res.status(400).json({ error: 'No media file received. Please provide an image, video, or audio file.' });
  }

  const user = req.user;
  const device = req.device;
  const filePath = uploadedFile.path;
  const originalFilename = path.basename(uploadedFile.originalname).replace(/[^a-zA-Z0-9._-]/g, '_');
  const ext = path.extname(originalFilename).toLowerCase();

  // Detect media type
  let mediaCategory = 'IMAGE';
  if (['.mp4', '.mov', '.avi', '.webm', '.mkv'].includes(ext) || uploadedFile.mimetype.startsWith('video/')) {
    mediaCategory = 'VIDEO';
  } else if (['.mp3', '.wav', '.m4a', '.aac', '.flac', '.ogg'].includes(ext) || uploadedFile.mimetype.startsWith('audio/')) {
    mediaCategory = 'AUDIO';
  }

  // Create Job Record
  const job = db.createJob({
    userId: user.id,
    deviceId: device.id,
    deviceName: device.deviceName,
    originalFilename: originalFilename,
    storedFilename: uploadedFile.filename,
    storedPath: filePath,
    mimeType: uploadedFile.mimetype,
    sizeBytes: uploadedFile.size,
    mediaCategory: mediaCategory,
    status: 'analyzing',
    progressPct: 15
  });

  const mediaUrl = `/uploads/${uploadedFile.filename}`;

  // Notify desktop immediately over WebSocket: media received!
  const syncIngestPayload = {
    jobId: job.id,
    uploadId: job.uploadId,
    deviceName: device.deviceName,
    fileName: originalFilename,
    fileSize: uploadedFile.size,
    mediaCategory: mediaCategory,
    imageUrl: mediaUrl,
    mediaUrl: mediaUrl,
    timestamp: job.createdAt
  };

  wsHub.broadcastToUser(user.id, 'sync:image_received', syncIngestPayload);
  wsHub.broadcastToUser(user.id, 'sync:media_received', syncIngestPayload);

  // Run Real Forensic Pipeline Asynchronously with incremental progress updates
  (async () => {
    try {
      if (mediaCategory === 'VIDEO') {
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 30, stage: 'Parsing MP4/MOV container atoms & video tracks' });
        await new Promise(r => setTimeout(r, 250));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 55, stage: 'Evaluating inter-frame GOP cadence & optical flow motion vectors' });
        await new Promise(r => setTimeout(r, 300));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 75, stage: 'Scanning 68-point 3D facial landmarks & A/V lip-sync drift' });
        await new Promise(r => setTimeout(r, 250));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 90, stage: 'Executing Agent-Reach multi-platform dissemination scan' });
      } else if (mediaCategory === 'AUDIO') {
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 30, stage: 'Extracting audio frequency spectrum & sample rate' });
        await new Promise(r => setTimeout(r, 250));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 55, stage: 'Evaluating neural vocoder ceiling & high-frequency shelf' });
        await new Promise(r => setTimeout(r, 300));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 75, stage: 'Testing phoneme naturalness & breath micro-dynamics' });
        await new Promise(r => setTimeout(r, 250));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 90, stage: 'Executing Agent-Reach multi-platform dissemination scan' });
      } else {
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 35, stage: 'Parsing file signatures & EXIF hardware metadata' });
        await new Promise(r => setTimeout(r, 250));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 60, stage: 'Evaluating quantization tables & spatial entropy' });
        await new Promise(r => setTimeout(r, 300));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 80, stage: 'Scanning generative AI markers & neural noise signatures' });
        await new Promise(r => setTimeout(r, 250));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 92, stage: 'Executing Agent-Reach multi-platform dissemination scan' });
      }

      const report = await analyzeMediaForensics(filePath, originalFilename, uploadedFile.mimetype);

      // Save completed job in DB
      db.updateJob(job.id, {
        status: 'completed',
        progressPct: 100,
        sha256: report.sha256,
        forensicReport: report,
        completedAt: new Date().toISOString()
      });

      // Push final report to desktop session without page refresh
      const completePayload = {
        jobId: job.id,
        uploadId: job.uploadId,
        fileName: originalFilename,
        mediaCategory: mediaCategory,
        imageUrl: mediaUrl,
        mediaUrl: mediaUrl,
        deviceName: device.deviceName,
        report: report
      };

      wsHub.broadcastToUser(user.id, 'sync:analysis_complete', completePayload);
      wsHub.broadcastToUser(user.id, 'sync:media_complete', completePayload);
    } catch (err) {
      console.error('Forensic analysis error:', err);
      db.updateJob(job.id, { status: 'failed', error: err.message });
      wsHub.broadcastToUser(user.id, 'sync:failed', {
        jobId: job.id,
        error: 'Forensic analysis processing failed.'
      });
    }
  })();

  // Synchronous response: immediate confirmation + quick execution report
  return res.json({
    success: true,
    message: `${mediaCategory} intake acknowledged. Analysis pipeline executing.`,
    jobId: job.id,
    uploadId: job.uploadId,
    fileName: originalFilename,
    mediaCategory: mediaCategory,
    mediaUrl: mediaUrl,
    imageUrl: mediaUrl
  });
});

// GET /api/analysis/:jobId (Retrieve analysis report - strictly scoped to user)
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
      mediaCategory: job.mediaCategory || 'IMAGE',
      imageUrl: `/uploads/${job.storedFilename}`,
      mediaUrl: `/uploads/${job.storedFilename}`,
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
    mediaCategory: j.mediaCategory || 'IMAGE',
    imageUrl: `/uploads/${j.storedFilename}`,
    mediaUrl: `/uploads/${j.storedFilename}`,
    status: j.status,
    deviceName: j.deviceName,
    createdAt: j.createdAt,
    verdict: j.forensicReport?.verdict || 'PENDING',
    probability: j.forensicReport?.probability || 'Processing...',
    isAlert: j.forensicReport?.isAlert || false,
    forensicReport: j.forensicReport
  }));

  return res.json({
    success: true,
    jobs: jobs
  });
});

// GET /api/jobs/latest (Quick synchronization endpoint for active paired capture)
uploadRouter.get('/jobs/latest', requireAuth, (req, res) => {
  const jobs = db.getUserJobs(req.user.id);
  // Sort descending by creation date to guarantee newest job is selected
  const latest = jobs.length > 0 ? jobs.slice().sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))[0] : null;

  if (!latest) {
    return res.json({ success: true, job: null });
  }

  return res.json({
    success: true,
    job: {
      id: latest.id,
      uploadId: latest.uploadId,
      originalFilename: latest.originalFilename,
      mediaCategory: latest.mediaCategory || 'IMAGE',
      imageUrl: `/uploads/${latest.storedFilename}`,
      mediaUrl: `/uploads/${latest.storedFilename}`,
      status: latest.status,
      deviceName: latest.deviceName,
      createdAt: latest.createdAt,
      forensicReport: latest.forensicReport
    }
  });
});

// POST /api/upload/simulate-paired-capture (Simulate real phone capture for testing/demo across Image, Video, and Audio)
uploadRouter.post('/upload/simulate-paired-capture', requireAuth, async (req, res) => {
  const user = req.user;
  const userDevices = db.getUserDevices(user.id).filter(d => d.trustStatus === 'active');
  const activeDevice = userDevices[0] || { id: 'dev_iphone_active', deviceName: "Manohar's iPhone 15 Pro" };

  const mode = req.body?.mode || 'camera'; // 'camera', 'ai', 'video', 'audio'
  let originalFilename = 'IMG_2026_OPTICAL_CAPTURE.jpg';
  let mediaCategory = 'IMAGE';
  let mimeType = 'image/jpeg';
  let fileBuffer = null;

  if (mode === 'video-ai') {
    originalFilename = 'INTERVIEW_LIVESTREAM_SURVEILLANCE.mp4';
    mediaCategory = 'VIDEO';
    mimeType = 'video/mp4';
    // Valid MP4 container header fixture with synthetic deepfake markers
    const ftyp = Buffer.from([
      0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d,
      0x00, 0x00, 0x02, 0x00, 0x69, 0x73, 0x6f, 0x6d, 0x69, 0x73, 0x6f, 0x32,
      0x61, 0x76, 0x63, 0x31, 0x6d, 0x70, 0x34, 0x31
    ]);
    const videoMetadata = Buffer.from('moov\x00mvhd\x00tkhd\x00avc1\x00deepfacelab facefusion optical flow temporal desync liveportrait');
    const dummyVideo = Buffer.alloc(8192, 0x41);
    fileBuffer = Buffer.concat([ftyp, videoMetadata, dummyVideo]);
  } else if (mode === 'video') {
    originalFilename = 'AUTHENTIC_PHONE_RECORDING.mp4';
    mediaCategory = 'VIDEO';
    mimeType = 'video/mp4';
    // Authentic camera MP4 container header with standard Apple QuickTime atoms
    const ftyp = Buffer.from([
      0x00, 0x00, 0x00, 0x20, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d,
      0x00, 0x00, 0x02, 0x00, 0x69, 0x73, 0x6f, 0x6d, 0x69, 0x73, 0x6f, 0x32,
      0x61, 0x76, 0x63, 0x31, 0x6d, 0x70, 0x34, 0x31
    ]);
    const videoMetadata = Buffer.from('moov\x00mvhd\x00tkhd\x00avc1\x00Apple QuickTime Movie H.264 High@L4.1 29.97fps');
    const dummyVideo = Buffer.alloc(8192, 0x41);
    fileBuffer = Buffer.concat([ftyp, videoMetadata, dummyVideo]);
  } else if (mode === 'audio-ai') {
    originalFilename = 'SYNTHETIC_VOICE_CLONE.wav';
    mediaCategory = 'AUDIO';
    mimeType = 'audio/wav';
    // Valid WAV/RIFF header fixture with synthetic neural vocoder tags
    const riff = Buffer.from([
      0x52, 0x49, 0x46, 0x46, 0x24, 0x08, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45,
      0x66, 0x6d, 0x74, 0x20, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
      0x44, 0xac, 0x00, 0x00, 0x88, 0x58, 0x01, 0x00, 0x02, 0x00, 0x10, 0x00,
      0x64, 0x61, 0x74, 0x61, 0x00, 0x08, 0x00, 0x00
    ]);
    const audioMetadata = Buffer.from('elevenlabs tortoise-tts rvc_v2 neural voice clone synthesis');
    const dummyAudio = Buffer.alloc(4096, 0x60);
    fileBuffer = Buffer.concat([riff, audioMetadata, dummyAudio]);
  } else if (mode === 'audio') {
    originalFilename = 'HUMAN_SPEECH_VOICENOTE.wav';
    mediaCategory = 'AUDIO';
    mimeType = 'audio/wav';
    // Clean PCM audio WAV from phone microphone (genuine human speaker)
    const riff = Buffer.from([
      0x52, 0x49, 0x46, 0x46, 0x24, 0x08, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45,
      0x66, 0x6d, 0x74, 0x20, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
      0x44, 0xac, 0x00, 0x00, 0x88, 0x58, 0x01, 0x00, 0x02, 0x00, 0x10, 0x00,
      0x64, 0x61, 0x74, 0x61, 0x00, 0x08, 0x00, 0x00
    ]);
    const audioMetadata = Buffer.from('LPCM 24-bit 48kHz Stereo Microphone Capture Linear PCM');
    const dummyAudio = Buffer.alloc(4096, 0x30);
    fileBuffer = Buffer.concat([riff, audioMetadata, dummyAudio]);
  } else {
    const isAi = mode === 'ai';
    originalFilename = isAi ? 'synthetic_concept_render.jpg' : 'IMG_2026_OPTICAL_CAPTURE.jpg';
    mediaCategory = 'IMAGE';
    mimeType = 'image/jpeg';
    const jpegHeader = Buffer.from([
      0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00, 0x01, 0x01, 0x01, 0x00, 0x48,
      0x00, 0x48, 0x00, 0x00, 0xff, 0xdb, 0x00, 0x43, 0x00
    ]);
    const quantTable = Buffer.alloc(64, isAi ? 16 : 8);
    const metadataBuffer = Buffer.from(
      isAi
        ? 'prompt: ultra realistic portrait of executive, stable diffusion v2.1 checkpoint comfyui node latent diffusion'
        : 'Make\x00Apple\x00Model\x00iPhone 15 Pro\x00Software\x00iOS 17.5.1\x00LensModel\x00iPhone 15 Pro back triple camera 24mm f/1.78\x00DateTimeOriginal\x002026:10:26 15:30:00\x00GPSLatitude\x0017.3850\x00GPSLongitude\x0078.4867\x00'
    );
    const payload = Buffer.alloc(4096, 0x7c);
    const jpegEoi = Buffer.from([0xff, 0xd9]);
    fileBuffer = Buffer.concat([jpegHeader, quantTable, metadataBuffer, payload, jpegEoi]);
  }

  const storedFilename = `${Date.now()}-${originalFilename}`;
  const storedPath = path.join(config.uploadsDir, storedFilename);
  fs.writeFileSync(storedPath, fileBuffer);

  const job = db.createJob({
    userId: user.id,
    deviceId: activeDevice.id,
    deviceName: activeDevice.deviceName,
    originalFilename: originalFilename,
    storedFilename: storedFilename,
    storedPath: storedPath,
    mimeType: mimeType,
    mediaCategory: mediaCategory,
    sizeBytes: fileBuffer.length,
    status: 'analyzing',
    progressPct: 20
  });

  const mediaUrl = `/uploads/${storedFilename}`;

  // Broadcast immediate ingestion notification
  const syncIngestPayload = {
    jobId: job.id,
    uploadId: job.uploadId,
    deviceName: activeDevice.deviceName,
    fileName: originalFilename,
    fileSize: fileBuffer.length,
    mediaCategory: mediaCategory,
    imageUrl: mediaUrl,
    mediaUrl: mediaUrl,
    timestamp: job.createdAt
  };

  wsHub.broadcastToUser(user.id, 'sync:image_received', syncIngestPayload);
  wsHub.broadcastToUser(user.id, 'sync:media_received', syncIngestPayload);

  // Async pipeline with progress
  (async () => {
    try {
      if (mediaCategory === 'VIDEO') {
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 30, stage: 'Parsing MP4/MOV container atoms & video tracks' });
        await new Promise(r => setTimeout(r, 200));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 55, stage: 'Evaluating inter-frame GOP cadence & optical flow motion vectors' });
        await new Promise(r => setTimeout(r, 250));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 75, stage: 'Scanning 68-point 3D facial landmarks & A/V lip-sync drift' });
        await new Promise(r => setTimeout(r, 200));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 90, stage: 'Executing Agent-Reach multi-platform dissemination scan' });
      } else if (mediaCategory === 'AUDIO') {
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 30, stage: 'Extracting audio frequency spectrum & sample rate' });
        await new Promise(r => setTimeout(r, 200));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 55, stage: 'Evaluating neural vocoder ceiling & high-frequency shelf' });
        await new Promise(r => setTimeout(r, 250));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 75, stage: 'Testing phoneme naturalness & breath micro-dynamics' });
        await new Promise(r => setTimeout(r, 200));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 90, stage: 'Executing Agent-Reach multi-platform dissemination scan' });
      } else {
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 35, stage: 'Parsing file signatures & EXIF hardware metadata' });
        await new Promise(r => setTimeout(r, 200));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 60, stage: 'Evaluating quantization tables & spatial entropy' });
        await new Promise(r => setTimeout(r, 250));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 80, stage: 'Scanning generative AI markers & neural noise signatures' });
        await new Promise(r => setTimeout(r, 200));
        wsHub.broadcastToUser(user.id, 'sync:progress', { jobId: job.id, progress: 92, stage: 'Executing Agent-Reach multi-platform dissemination scan' });
      }

      const report = await analyzeMediaForensics(storedPath, originalFilename, mimeType);

      db.updateJob(job.id, {
        status: 'completed',
        progressPct: 100,
        sha256: report.sha256,
        forensicReport: report,
        completedAt: new Date().toISOString()
      });

      const completePayload = {
        jobId: job.id,
        uploadId: job.uploadId,
        fileName: originalFilename,
        mediaCategory: mediaCategory,
        imageUrl: mediaUrl,
        mediaUrl: mediaUrl,
        deviceName: activeDevice.deviceName,
        report: report
      };

      wsHub.broadcastToUser(user.id, 'sync:analysis_complete', completePayload);
      wsHub.broadcastToUser(user.id, 'sync:media_complete', completePayload);
    } catch (err) {
      console.error('Simulation error:', err);
    }
  })();

  return res.json({
    success: true,
    message: `Simulated ${mediaCategory} capture from paired phone initiated.`,
    jobId: job.id,
    mediaCategory: mediaCategory,
    fileName: originalFilename
  });
});
