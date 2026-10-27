import http from 'http';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { config, getLocalIpAddress } from './config.js';
import { wsHub } from './ws.js';
import { authRouter } from './routes/auth.js';
import { pairingRouter } from './routes/pairing.js';
import { uploadRouter } from './routes/upload.js';
import { initWeeklyCacheScheduler, runWeeklyCacheCleanup, getCacheStatus } from './cleaner.js';

const app = express();
const server = http.createServer(app);

// Initialize WebSocket Hub on same HTTP server
wsHub.init(server);

// Start Automated 1-Week Cache & Storage Maintenance Scheduler
initWeeklyCacheScheduler();

// Middleware
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow local development origins (localhost, 127.0.0.1, LAN IP)
      callback(null, true);
    },
    credentials: true
  })
);

app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static route for uploaded images
app.use('/uploads', express.static(config.uploadsDir));

// API Routes (Mounted both with and without /api prefix for local and Vercel Serverless Function rewrites)
app.use('/api/auth', authRouter);
app.use('/auth', authRouter);
app.use('/api/pairing', pairingRouter);
app.use('/pairing', pairingRouter);
app.use('/api', uploadRouter);
app.use('/', uploadRouter);

// System Status Endpoint
const statusHandler = (req, res) => {
  const lanIp = getLocalIpAddress();
  res.json({
    name: 'SPECTRA Local Secure Forensic Server',
    status: 'online',
    lanIp: lanIp,
    port: config.port,
    vitePort: config.vitePort,
    mobilePairingUrl: `http://${lanIp}:${config.vitePort}/mobile.html`,
    transports: {
      wifi: 'Active (Same Local Network)',
      bluetooth: 'Supported for Web Bluetooth API pairing handshake on Chrome / Android & Mac'
    },
    timestamp: new Date().toISOString()
  });
};

app.get('/api/status', statusHandler);
app.get('/status', statusHandler);

// Cache & Maintenance Endpoints (Purges files & records older than 1 week)
const cacheStatusHandler = (req, res) => {
  res.json({ success: true, cache: getCacheStatus() });
};
const clearCacheHandler = (req, res) => {
  const days = parseInt(req.body?.maxAgeDays || '7', 10);
  const result = runWeeklyCacheCleanup(days);
  res.json({
    success: true,
    message: `Weekly cache purge executed. Storage optimized (Retaining items under ${days} days).`,
    ...result
  });
};

app.get('/api/maintenance/cache-status', cacheStatusHandler);
app.get('/maintenance/cache-status', cacheStatusHandler);
app.post('/api/maintenance/clear-cache', clearCacheHandler);
app.post('/maintenance/clear-cache', clearCacheHandler);

// Start Server if not imported as module in test and not running in Vercel Serverless Function
if (process.env.NODE_ENV !== 'test' && !process.env.VERCEL) {
  server.listen(config.port, config.host, () => {
    const lanIp = getLocalIpAddress();
    console.log(`\n======================================================`);
    console.log(`🔒 SPECTRA SECURE LOCAL BACKEND ONLINE`);
    console.log(`======================================================`);
    console.log(`📡 Local Host:       http://localhost:${config.port}`);
    console.log(`📶 LAN Access:       http://${lanIp}:${config.port}`);
    console.log(`⚡ WebSocket URL:    ws://${lanIp}:${config.port}/ws`);
    console.log(`📱 Mobile Portal:    http://${lanIp}:${config.vitePort}/mobile.html`);
    console.log(`======================================================\n`);
  });
}

export { app, server };
