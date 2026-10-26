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
      const token = url.searchParams.get('token') || '';
      const deviceToken = url.searchParams.get('deviceToken') || '';

      let authenticatedUser = null;
      let authenticatedDevice = null;

      // 1. Check Session Token
      if (token) {
        const session = db.findSession(token);
        if (session) {
          authenticatedUser = db.findUserById(session.userId);
        }
      }

      // 2. Check Device Token
      if (!authenticatedUser && deviceToken) {
        const crypto = req.socket.server._crypto;
        // Search device by token hash
        const devices = db.data.devices.filter(d => d.trustStatus === 'active');
        for (const dev of devices) {
          // If token matches
          if (dev.tokenHash === deviceToken || dev.id === deviceToken) {
            authenticatedDevice = dev;
            authenticatedUser = db.findUserById(dev.userId);
            break;
          }
        }
      }

      // If neither is valid, allow connection initially for pairing handshake if token='pairing'
      const isPairingChannel = url.searchParams.get('channel') === 'pairing';
      const pairingCode = url.searchParams.get('code') || '';

      ws.userId = authenticatedUser ? authenticatedUser.id : null;
      ws.isAlive = true;
      ws.pairingCode = pairingCode;

      if (ws.userId) {
        if (!this.userSockets.has(ws.userId)) {
          this.userSockets.set(ws.userId, new Set());
        }
        this.userSockets.get(ws.userId).add(ws);
        ws.send(JSON.stringify({ type: 'connected', userId: ws.userId, timestamp: Date.now() }));
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
      const session = db.findSession(msg.token);
      if (session) {
        const user = db.findUserById(session.userId);
        if (user) {
          ws.userId = user.id;
          if (!this.userSockets.has(ws.userId)) {
            this.userSockets.set(ws.userId, new Set());
          }
          this.userSockets.get(ws.userId).add(ws);
          ws.send(JSON.stringify({ type: 'authenticated', userId: user.id }));
        }
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
