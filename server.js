/**
 * HomeCam Lite - Production WebSocket Signaling Server
 * 
 * Purpose:
 *   Routes WebRTC SDP Offer, SDP Answer, and ICE candidates between
 *   one Camera Phone and one Viewer Phone per room.
 * 
 * Security & Constraints:
 *   - Max 1 Camera and 1 Viewer per room.
 *   - Ephemeral in-memory sessions; zero media storage (no video/audio touches the server).
 *   - Cryptographically secure session tokens.
 *   - Automatic cleanup on disconnect and heartbeat ping-pong timeouts.
 */

const http = require('http');
const WebSocket = require('ws');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;

// Health-check HTTP server (needed for cloud host health checks)
const server = http.createServer((req, res) => {
  if (req.url === '/health' || req.url === '/') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'HomeCam Lite Signaling', timestamp: Date.now() }));
  } else {
    res.writeHead(404);
    res.end();
  }
});

const wss = new WebSocket.Server({ server });

/**
 * In-memory room store.
 * Structure:
 * roomId -> {
 *   roomId: string,
 *   token: string,
 *   camera: WebSocket | null,
 *   viewer: WebSocket | null,
 *   createdAt: number
 * }
 */
const rooms = new Map();

function sendJson(ws, obj) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

function generateSecureToken() {
  return crypto.randomBytes(16).toString('hex');
}

// Periodic cleanup of stale rooms (older than 24 hours)
setInterval(() => {
  const now = Date.now();
  for (const [roomId, room] of rooms.entries()) {
    if (now - room.createdAt > 24 * 60 * 60 * 1000 && !room.camera && !room.viewer) {
      rooms.delete(roomId);
    }
  }
}, 60 * 60 * 1000);

wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.roomId = null;
  ws.role = null;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  ws.on('message', (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch (err) {
      sendJson(ws, { type: 'error', message: 'Invalid JSON payload' });
      return;
    }

    const { type, roomId, token, sdp, candidate } = msg;

    switch (type) {
      // 1. Camera creates or re-registers a room
      case 'create_room': {
        if (!roomId || typeof roomId !== 'string' || roomId.trim().length === 0) {
          sendJson(ws, { type: 'error', message: 'Invalid roomId' });
          return;
        }

        const cleanRoomId = roomId.trim();
        let room = rooms.get(cleanRoomId);

        if (room && room.camera && room.camera !== ws && room.camera.readyState === WebSocket.OPEN) {
          sendJson(ws, { type: 'error', message: 'Room already has an active camera session' });
          return;
        }

        const roomToken = room ? room.token : generateSecureToken();
        room = {
          roomId: cleanRoomId,
          token: roomToken,
          camera: ws,
          viewer: room ? room.viewer : null,
          createdAt: room ? room.createdAt : Date.now()
        };
        rooms.set(cleanRoomId, room);

        ws.roomId = cleanRoomId;
        ws.role = 'camera';

        sendJson(ws, {
          type: 'room_created',
          roomId: cleanRoomId,
          token: roomToken,
          message: 'Camera registered successfully'
        });

        // Notify viewer if already waiting
        if (room.viewer && room.viewer.readyState === WebSocket.OPEN) {
          sendJson(room.viewer, { type: 'camera_online' });
          sendJson(ws, { type: 'viewer_online' });
        }
        break;
      }

      // 2. Viewer joins an existing room using pairing code
      case 'join_room': {
        if (!roomId || typeof roomId !== 'string') {
          sendJson(ws, { type: 'error', message: 'Invalid roomId' });
          return;
        }

        const cleanRoomId = roomId.trim();
        const room = rooms.get(cleanRoomId);

        if (!room) {
          sendJson(ws, { type: 'error', message: 'Room not found. Ensure camera phone is online.' });
          return;
        }

        // Token verification if token enforcement is requested
        if (token && room.token !== token) {
          sendJson(ws, { type: 'error', message: 'Invalid room security token' });
          return;
        }

        if (room.viewer && room.viewer !== ws && room.viewer.readyState === WebSocket.OPEN) {
          sendJson(ws, { type: 'error', message: 'Only one viewer permitted per room' });
          return;
        }

        room.viewer = ws;
        ws.roomId = cleanRoomId;
        ws.role = 'viewer';

        sendJson(ws, {
          type: 'room_joined',
          roomId: cleanRoomId,
          token: room.token,
          cameraOnline: !!(room.camera && room.camera.readyState === WebSocket.OPEN)
        });

        // If camera is ready, alert both parties to start WebRTC negotiation
        if (room.camera && room.camera.readyState === WebSocket.OPEN) {
          sendJson(room.camera, { type: 'viewer_online' });
          sendJson(ws, { type: 'camera_online' });
        }
        break;
      }

      // 3. Forward SDP Offer (typically from Camera or Caller)
      case 'sdp_offer': {
        const room = rooms.get(ws.roomId);
        if (!room) return;

        const target = ws.role === 'camera' ? room.viewer : room.camera;
        if (target && target.readyState === WebSocket.OPEN) {
          sendJson(target, { type: 'sdp_offer', sdp });
        }
        break;
      }

      // 4. Forward SDP Answer (typically from Viewer or Callee)
      case 'sdp_answer': {
        const room = rooms.get(ws.roomId);
        if (!room) return;

        const target = ws.role === 'viewer' ? room.camera : room.viewer;
        if (target && target.readyState === WebSocket.OPEN) {
          sendJson(target, { type: 'sdp_answer', sdp });
        }
        break;
      }

      // 5. Forward ICE Candidate
      case 'ice_candidate': {
        const room = rooms.get(ws.roomId);
        if (!room) return;

        const target = ws.role === 'camera' ? room.viewer : room.camera;
        if (target && target.readyState === WebSocket.OPEN) {
          sendJson(target, { type: 'ice_candidate', candidate });
        }
        break;
      }

      // 6. Explicit session close
      case 'leave_room': {
        cleanupSession(ws);
        break;
      }

      default:
        sendJson(ws, { type: 'error', message: `Unknown message type: ${type}` });
    }
  });

  ws.on('close', () => {
    cleanupSession(ws);
  });

  ws.on('error', () => {
    cleanupSession(ws);
  });
});

function cleanupSession(ws) {
  if (!ws.roomId) return;
  const room = rooms.get(ws.roomId);
  if (!room) return;

  if (ws.role === 'camera') {
    room.camera = null;
    if (room.viewer && room.viewer.readyState === WebSocket.OPEN) {
      sendJson(room.viewer, { type: 'camera_disconnected', message: 'Camera phone disconnected' });
    }
  } else if (ws.role === 'viewer') {
    room.viewer = null;
    if (room.camera && room.camera.readyState === WebSocket.OPEN) {
      sendJson(room.camera, { type: 'viewer_disconnected', message: 'Viewer disconnected' });
    }
  }

  // Delete empty room
  if (!room.camera && !room.viewer) {
    rooms.delete(ws.roomId);
  }

  ws.roomId = null;
  ws.role = null;
}

// Heartbeat ping interval to keep cloud proxies and mobile connections alive
const interval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) {
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

wss.on('close', () => {
  clearInterval(interval);
});

server.listen(PORT, () => {
  console.log(`HomeCam Lite Signaling Server listening on port ${PORT}`);
});
