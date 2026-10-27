import crypto from 'crypto';
import { WebSocketServer, WebSocket } from 'ws';
import { db } from './db.js';

class WebSocketHub {
  constructor() {
    this.wss = null;
    // Map: userId -> Set of WebSocket clients
    this.userSockets = new Map();
  }

  init(server) {
    this.wss = new WebSocketServer({ server, path: '/ws' });

    this.wss.on('connection', (ws, req) => {
      const url = new URL(req.url, 'http://localhost');
      const token = url.searchParams.get('token') || url.searchParams.get('sessionId') || '';
      const deviceToken = url.searchParams.get('deviceToken') || '';

      let authenticatedUser = null;
      let authenticatedDevice = null;

      // 1. Check User Session Token
      if (token) {
        const session = db.findSession(token);
        if (session) {
          authenticatedUser = db.findUserById(session.userId);
        }
      }

      // 2. Check Device Token (Hash with SHA-256 for secure registry match)
      if (!authenticatedUser && deviceToken) {
        const tokenHash = crypto.createHash('sha256').update(deviceToken).digest('hex');
        const device = db.findDeviceByTokenHash(tokenHash) || db.data.devices.find(d => d.id === deviceToken || d.tokenHash === deviceToken);
        if (device && device.trustStatus === 'active') {
          authenticatedDevice = device;
          authenticatedUser = db.findUserById(device.userId);
        }
      }

      // If pairing channel listener
      const isPairingChannel = url.searchParams.get('channel') === 'pairing';
      const pairingCode = url.searchParams.get('code') || '';

      ws.userId = authenticatedUser ? authenticatedUser.id : null;
      ws.deviceId = authenticatedDevice ? authenticatedDevice.id : null;
      ws.isAlive = true;
      ws.pairingCode = pairingCode;

      if (ws.userId) {
        if (!this.userSockets.has(ws.userId)) {
          this.userSockets.set(ws.userId, new Set());
        }
        this.userSockets.get(ws.userId).add(ws);
        ws.send(JSON.stringify({
          type: 'connected',
          userId: ws.userId,
          deviceId: ws.deviceId,
          timestamp: Date.now()
        }));
      } else if (isPairingChannel && pairingCode) {
        ws.send(JSON.stringify({ type: 'pairing_listener_ready', code: pairingCode }));
      }

      ws.on('pong', () => {
        ws.isAlive = true;
      });

      ws.on('message', (data) => {
        try {
          const parsed = JSON.parse(data.toString());
          this.handleClientMessage(ws, parsed);
        } catch (e) {
          console.error('Invalid WS payload received:', e.message);
        }
      });

      ws.on('close', () => {
        if (ws.userId && this.userSockets.has(ws.userId)) {
          this.userSockets.get(ws.userId).delete(ws);
          if (this.userSockets.get(ws.userId).size === 0) {
            this.userSockets.delete(ws.userId);
          }
        }
      });
    });

    // Heartbeat every 30 seconds
    setInterval(() => {
      if (!this.wss) return;
      this.wss.clients.forEach((ws) => {
        if (!ws.isAlive) return ws.terminate();
        ws.isAlive = false;
        ws.ping();
      });
    }, 30000);
  }

  handleClientMessage(ws, msg) {
    if (msg.type === 'auth') {
      const token = msg.token || msg.sessionId;
      const deviceToken = msg.deviceToken;

      let authenticatedUser = null;
      let authenticatedDevice = null;

      if (token) {
        const session = db.findSession(token);
        if (session) {
          authenticatedUser = db.findUserById(session.userId);
        }
      }

      if (!authenticatedUser && deviceToken) {
        const tokenHash = crypto.createHash('sha256').update(deviceToken).digest('hex');
        const device = db.findDeviceByTokenHash(tokenHash) || db.data.devices.find(d => d.id === deviceToken || d.tokenHash === deviceToken);
        if (device && device.trustStatus === 'active') {
          authenticatedDevice = device;
          authenticatedUser = db.findUserById(device.userId);
        }
      }

      if (authenticatedUser) {
        ws.userId = authenticatedUser.id;
        ws.deviceId = authenticatedDevice ? authenticatedDevice.id : null;
        if (!this.userSockets.has(ws.userId)) {
          this.userSockets.set(ws.userId, new Set());
        }
        this.userSockets.get(ws.userId).add(ws);
        ws.send(JSON.stringify({
          type: 'authenticated',
          userId: authenticatedUser.id,
          deviceId: ws.deviceId
        }));
      }
    }
  }

  broadcastToUser(userId, eventType, payload) {
    if (!userId || !this.userSockets.has(userId)) return;
    const message = JSON.stringify({
      type: eventType,
      data: payload,
      timestamp: Date.now()
    });

    for (const client of this.userSockets.get(userId)) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(message);
      }
    }
  }

  broadcastPairingUpdate(code, eventType, payload) {
    const clean = code.replace(/[^A-Z0-9]/gi, '').toUpperCase();
    const message = JSON.stringify({
      type: eventType,
      code: clean,
      data: payload,
      timestamp: Date.now()
    });

    if (!this.wss) return;
    this.wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN && client.pairingCode === clean) {
        client.send(message);
      }
    });
  }
}

export const wsHub = new WebSocketHub();
