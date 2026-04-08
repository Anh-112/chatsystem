#!/usr/bin/env python3
"""
web_gateway.py
Flask + Flask-SocketIO web gateway that bridges the browser
to the C chat server over TCP sockets.

  Browser  <──WS──>  web_gateway.py  <──TCP──>  chat_server (C)
"""

import os
import sys
import json
import socket
import threading
import hashlib
import time
from flask import Flask, render_template_string, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room, leave_room

# ── config ──────────────────────────────────────────────────────
C_SERVER_HOST = "127.0.0.1"
C_SERVER_PORT = 9000
WEB_PORT      = 5001
CIPHER_KEY    = 42

app = Flask(__name__)
app.config['SECRET_KEY'] = 'chatkey2024'
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# ── Substitution cipher (mirrors kernel driver logic) ───────────
SUBST_TABLE = [
    73, 14, 61, 37, 88, 22, 51, 79,  4, 43,
    92, 18, 65, 30, 84, 11, 56, 70,  2, 47,
    91, 25, 63, 38, 82, 17, 54, 78,  8, 41,
    90, 20, 67, 33, 86, 13, 58, 72,  6, 45,
    94, 27, 60, 36, 80, 15, 52, 76, 10, 39,
    89, 23, 62, 34, 85, 19, 55, 71,  3, 44,
    93, 28, 64, 32, 83, 16, 53, 77,  9, 40,
    87, 21, 66, 31, 81, 12, 57, 75,  7, 42,
     0, 26, 59, 35, 87 % 95, 24, 50, 74,  5, 46,
     1, 29, 68, 48,  0
]
REVERSE_TABLE = [0] * 95
for i, v in enumerate(SUBST_TABLE):
    REVERSE_TABLE[v] = i

def subst_encrypt(text, key=CIPHER_KEY):
    out = []
    for c in text:
        o = ord(c)
        if 32 <= o <= 126:
            idx = ((o - 32) + key) % 95
            out.append(chr(SUBST_TABLE[idx] + 32))
        else:
            out.append(c)
    return ''.join(out)

def subst_decrypt(text, key=CIPHER_KEY):
    out = []
    for c in text:
        o = ord(c)
        if 32 <= o <= 126:
            rev = REVERSE_TABLE[o - 32]
            idx = ((rev - key) % 95 + 95) % 95
            out.append(chr(idx + 32))
        else:
            out.append(c)
    return ''.join(out)

def sha1_hash(password):
    return hashlib.sha1(password.encode()).hexdigest()

# ── Per-browser-session TCP connection to C server ──────────────
class ChatConnection:
    def __init__(self, sid):
        self.sid = sid
        self.sock = None
        self.token = ""
        self.username = ""
        self._buf = ""
        self._thread = None
        self._refresh_thread = None
        self._running = False

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((C_SERVER_HOST, C_SERVER_PORT))
            self._running = True
            self._thread = threading.Thread(target=self._recv_loop, daemon=True)
            self._thread.start()
            self._refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
            self._refresh_thread.start()
            return True
        except Exception as e:
            print(f"[GW] Cannot connect to C server: {e}")
            return False

    def disconnect(self):
        self._running = False
        if self.sock:
            try: self.sock.close()
            except: pass

    def send_pkt(self, pkt_type, from_u="", to_u="", target_type=0,
                 content="", token="", extra=""):
        pkt = json.dumps({
            "type": pkt_type, "from": from_u, "to": to_u,
            "target_type": target_type, "content": content,
            "token": token, "extra": extra
        }) + "\n"
        try:
            self.sock.sendall(pkt.encode())
        except Exception as e:
            print(f"[GW] send error: {e}")

    def _refresh_loop(self):
        """Auto-refresh users & rooms list every 2 seconds"""
        while self._running:
            time.sleep(2)
            if self.token and self.username:
                self.send_pkt(9, from_u=self.username, token=self.token)  # list users
                self.send_pkt(10, from_u=self.username, token=self.token)  # list rooms

    def _recv_loop(self):
        while self._running:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                self._buf += data.decode(errors='replace')
                while '\n' in self._buf:
                    line, self._buf = self._buf.split('\n', 1)
                    if line.strip():
                        self._handle_pkt(line.strip())
            except Exception as e:
                if self._running:
                    print(f"[GW] recv error: {e}")
                break

    def _handle_pkt(self, raw):
        try:
            pkt = json.loads(raw)
        except Exception as e:
            print(f"[GW] JSON parse error: {e}, raw: {raw[:200]}...")
            return
        ptype = pkt.get("type")

        # PKT_RECV_MSG = 5 → decrypt and forward to browser
        if ptype == 5:
            cipher = pkt.get("content", "")
            plain  = subst_decrypt(cipher)
            pkt["content"] = plain
            pkt["encrypted_content"] = cipher
            print(f"[GW] Forwarding message: {plain[:50]}...")
            socketio.emit("message", pkt, room=self.sid)

        # PKT_OK = 20
        elif ptype == 20:
            extra = pkt.get("extra", "")
            # Parse pipe-separated user/room list and convert to JSON array for browser
            if extra == "users":
                content = pkt.get("content", "")
                users = content.split("|") if content else []
                pkt["content"] = users
            elif extra == "rooms":
                content = pkt.get("content", "")
                rooms = content.split("|") if content else []
                pkt["content"] = rooms
            socketio.emit("server_response", pkt, room=self.sid)

        # PKT_ERROR = 21
        elif ptype == 21:
            socketio.emit("server_error", pkt, room=self.sid)

        else:
            socketio.emit("server_response", pkt, room=self.sid)

# ── connection registry ──────────────────────────────────────────
connections = {}   # sid -> ChatConnection
conn_lock = threading.Lock()

# ── SocketIO events ──────────────────────────────────────────────
@socketio.on('connect')
def on_connect():
    sid = request.sid
    print(f"[GW] Browser connected: {sid}")
    conn = ChatConnection(sid)
    if not conn.connect():
        emit("server_error", {"content": "Cannot reach chat server"})
        return
    with conn_lock:
        connections[sid] = conn
    emit("connected", {"message": "Connected to chat server"})

@socketio.on('disconnect')
def on_disconnect():
    sid = request.sid
    with conn_lock:
        conn = connections.pop(sid, None)
    if conn:
        conn.disconnect()
    print(f"[GW] Browser disconnected: {sid}")

@socketio.on('register')
def on_register(data):
    sid = request.sid
    conn = connections.get(sid)
    if not conn: return
    # Password is hashed client-side via SHA1; double-hash server-side
    # Actually we send raw password, C server does SHA1 internally
    conn.send_pkt(1, from_u=data['username'], content=data['password'])

@socketio.on('login')
def on_login(data):
    sid = request.sid
    conn = connections.get(sid)
    if not conn: return
    conn.username = data['username']
    conn.send_pkt(2, from_u=data['username'], content=data['password'])

@socketio.on('login_success')
def on_login_success(data):
    sid = request.sid
    conn = connections.get(sid)
    if conn:
        conn.token = data.get('token', '')
        # Request initial user/room list
        conn.send_pkt(9, from_u=conn.username, token=conn.token)
        conn.send_pkt(10, from_u=conn.username, token=conn.token)

@socketio.on('send_message')
def on_send_message(data):
    sid = request.sid
    conn = connections.get(sid)
    if not conn: return
    plain = data.get('content', '')
    cipher = subst_encrypt(plain)
    print(f"[GW] Send message: plain='{plain}', cipher='{cipher[:50]}...'")
    conn.send_pkt(4, from_u=conn.username, to_u=data['to'],
                  target_type=data.get('target_type', 1),
                  content=cipher, token=conn.token)

@socketio.on('create_room')
def on_create_room(data):
    sid = request.sid
    conn = connections.get(sid)
    if not conn: return
    conn.send_pkt(6, from_u=conn.username, content=data['room'], token=conn.token)

@socketio.on('join_room_req')
def on_join_room(data):
    sid = request.sid
    conn = connections.get(sid)
    if not conn: return
    conn.send_pkt(7, from_u=conn.username, content=data['room'], token=conn.token)

@socketio.on('leave_room_req')
def on_leave_room(data):
    sid = request.sid
    conn = connections.get(sid)
    if not conn: return
    conn.send_pkt(8, from_u=conn.username, content=data['room'], token=conn.token)

@socketio.on('list_users')
def on_list_users(data):
    sid = request.sid
    conn = connections.get(sid)
    if not conn: return
    conn.send_pkt(9, from_u=conn.username, token=conn.token)

@socketio.on('list_rooms')
def on_list_rooms(data):
    sid = request.sid
    conn = connections.get(sid)
    if not conn: return
    conn.send_pkt(10, from_u=conn.username, token=conn.token)

@socketio.on('update_token')
def on_update_token(data):
    sid = request.sid
    conn = connections.get(sid)
    if conn:
        conn.token = data.get('token', '')

# ── serve frontend ───────────────────────────────────────────────
WEB_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/')
def index():
    return send_from_directory(WEB_DIR, 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory(WEB_DIR, filename)

if __name__ == '__main__':
    print(f"[GW] Web gateway starting on http://0.0.0.0:{WEB_PORT}")
    print(f"[GW] Bridging to C server at {C_SERVER_HOST}:{C_SERVER_PORT}")
    socketio.run(app, host='0.0.0.0', port=WEB_PORT, debug=False)
