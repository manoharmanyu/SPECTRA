import fs from 'fs';
import path from 'path';
import { config } from './config.js';
import { db } from './db.js';

const ONE_WEEK_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Spectra Cache & Ephemeral Storage Cleaner
 * Automatically purges stale uploads, expired jobs, pairing codes, and sessions
 * older than 1 week (7 days) to ensure zero disk bloating and optimal performance.
 */
export function runWeeklyCacheCleanup(maxAgeDays = 7) {
  const maxAgeMs = maxAgeDays * 24 * 60 * 60 * 1000;
  const cutoffTime = Date.now() - maxAgeMs;
  const cutoffDate = new Date(cutoffTime).toISOString();

  let filesRemoved = 0;
  let bytesFreed = 0;
  let jobsRemoved = 0;
  let pairingsRemoved = 0;
  let sessionsRemoved = 0;

  // 1. Purge physical files in uploads directory older than 1 week
  try {
    if (fs.existsSync(config.uploadsDir)) {
      const files = fs.readdirSync(config.uploadsDir);
      for (const file of files) {
        if (file.startsWith('.')) continue; // Keep .gitkeep / hidden
        const fullPath = path.join(config.uploadsDir, file);
        try {
          const stat = fs.statSync(fullPath);
          if (stat.isFile() && stat.mtimeMs < cutoffTime) {
            bytesFreed += stat.size;
            fs.unlinkSync(fullPath);
            filesRemoved++;
          }
        } catch (fileErr) {
          // Ignore transient file lock
        }
      }
    }
  } catch (err) {
    console.warn('[CacheCleaner] Uploads directory scan warning:', err.message);
  }

  // 2. Purge stale jobs older than 1 week
  db.load();
  if (Array.isArray(db.data.jobs)) {
    const initialJobs = db.data.jobs.length;
    db.data.jobs = db.data.jobs.filter(job => {
      const created = new Date(job.createdAt || 0).getTime();
      return created >= cutoffTime;
    });
    jobsRemoved = initialJobs - db.data.jobs.length;
  }

  // 3. Purge expired pairing codes older than 1 week
  if (Array.isArray(db.data.pairingCodes)) {
    const initialPairings = db.data.pairingCodes.length;
    db.data.pairingCodes = db.data.pairingCodes.filter(p => {
      const created = new Date(p.createdAt || 0).getTime();
      return created >= cutoffTime;
    });
    pairingsRemoved = initialPairings - db.data.pairingCodes.length;
  }

  // 4. Purge stale expired sessions older than 1 week
  if (Array.isArray(db.data.sessions)) {
    const initialSessions = db.data.sessions.length;
    db.data.sessions = db.data.sessions.filter(s => {
      const created = new Date(s.createdAt || 0).getTime();
      return created >= cutoffTime;
    });
    sessionsRemoved = initialSessions - db.data.sessions.length;
  }

  // Save cleaned database
  db.save();

  const report = {
    success: true,
    executionTimestamp: new Date().toISOString(),
    cutoffDate,
    maxAgeDays,
    metrics: {
      filesRemoved,
      bytesFreed,
      bytesFreedFormatted: `${(bytesFreed / (1024 * 1024)).toFixed(2)} MB`,
      jobsRemoved,
      pairingsRemoved,
      sessionsRemoved
    }
  };

  return report;
}

/**
 * Return current cache statistics
 */
export function getCacheStatus() {
  let totalFiles = 0;
  let totalBytes = 0;
  let oldestFileTimestamp = null;

  try {
    if (fs.existsSync(config.uploadsDir)) {
      const files = fs.readdirSync(config.uploadsDir);
      for (const file of files) {
        if (file.startsWith('.')) continue;
        const fullPath = path.join(config.uploadsDir, file);
        try {
          const stat = fs.statSync(fullPath);
          if (stat.isFile()) {
            totalFiles++;
            totalBytes += stat.size;
            if (!oldestFileTimestamp || stat.mtimeMs < oldestFileTimestamp) {
              oldestFileTimestamp = stat.mtimeMs;
            }
          }
        } catch (e) {}
      }
    }
  } catch (e) {}

  db.load();
  return {
    status: 'optimal',
    schedule: 'Weekly (Every 7 Days)',
    totalCachedFiles: totalFiles,
    totalCachedBytes: totalBytes,
    totalCachedFormatted: `${(totalBytes / (1024 * 1024)).toFixed(2)} MB`,
    totalJobsRecorded: db.data.jobs?.length || 0,
    totalActiveDevices: db.data.devices?.length || 0,
    oldestFileDate: oldestFileTimestamp ? new Date(oldestFileTimestamp).toISOString() : null
  };
}

/**
 * Start background timer to run weekly cache cleanup periodically
 */
export function initWeeklyCacheScheduler() {
  // Run once on startup (cleans anything > 7 days old)
  try {
    const startupReport = runWeeklyCacheCleanup(7);
    if (startupReport.metrics.filesRemoved > 0 || startupReport.metrics.jobsRemoved > 0) {
      console.log(`[CacheCleaner] Startup 1-week cleanup freed ${startupReport.metrics.bytesFreedFormatted} (${startupReport.metrics.filesRemoved} files, ${startupReport.metrics.jobsRemoved} stale jobs).`);
    }
  } catch (e) {
    console.warn('[CacheCleaner] Initial cleanup error:', e.message);
  }

  // Schedule recurring check every 24 hours
  const interval = setInterval(() => {
    try {
      runWeeklyCacheCleanup(7);
    } catch (e) {
      console.warn('[CacheCleaner] Scheduled cleanup warning:', e.message);
    }
  }, 24 * 60 * 60 * 1000);

  // Unref so it does not block clean Node process exit
  if (interval.unref) interval.unref();
}
