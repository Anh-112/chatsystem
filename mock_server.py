#!/usr/bin/env python3
"""
Mock C server for testing - simulates the C chat server behavior
"""

import socket
import json
import threading
import time

# Mock crypto functions (simplified)
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

def subst_encrypt(text, key=42):
    out = []
    for c in text:
        o = ord(c)
        if 32 <= o <= 126:
            idx = ((o - 32) + key) % 95
            out.append(chr(SUBST_TABLE[idx] + 32))
        else:
            out.append(c)
    return ''.join(out)

def subst_decrypt(text, key=42):
    REVERSE_TABLE = [0] * 95
    for i, v in enumerate(SUBST_TABLE):
        REVERSE_TABLE[v] = i

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

# Mock clients
clients = {}
rooms = {}

def handle_client(client_sock, addr):
    print(f"[MOCK] New client: {addr}")
    buffer = ""

    while True:
        try:
            data = client_sock.recv(4096)
            if not data:
                break
            buffer += data.decode(errors='replace')

            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if line.strip():
                    try:
                        pkt = json.loads(line.strip())
                        print(f"[MOCK] Received: {pkt}")

                        # Handle different packet types
                        ptype = pkt.get('type')

                        if ptype == 4:  # PKT_SEND_MSG
                            from_u = pkt.get('from', '')
                            to = pkt.get('to', '')
                            tt = pkt.get('target_type', 1)
                            cipher = pkt.get('content', '')
                            token = pkt.get('token', '')

                            # Decrypt
                            plain = subst_decrypt(cipher)
                            print(f"[MOCK] Decrypted message: '{plain}' from {from_u} to {to}")

                            # Create response packet
                            response = {
                                "type": 5,  # PKT_RECV_MSG
                                "from": from_u,
                                "to": to,
                                "target_type": tt,
                                "content": cipher,  # Send back encrypted
                                "token": "",
                                "extra": ""
                            }

                            response_json = json.dumps(response) + "\n"
                            print(f"[MOCK] Sending response: {response_json.strip()}")

                            # Send to all clients (simplified)
                            for sock in clients.values():
                                try:
                                    sock.sendall(response_json.encode())
                                except:
                                    pass

                        elif ptype == 2:  # Login
                            username = pkt.get('from', '')
                            clients[client_sock] = username
                            response = {"type": 20, "content": "logged_in", "token": "mock_token"}
                            client_sock.sendall((json.dumps(response) + "\n").encode())

                        elif ptype == 9:  # List users
                            users = "|".join(clients.values())
                            response = {"type": 20, "content": users, "extra": "users"}
                            client_sock.sendall((json.dumps(response) + "\n").encode())

                        else:
                            # Echo back for other packets
                            response = {"type": 20, "content": "ok"}
                            client_sock.sendall((json.dumps(response) + "\n").encode())

                    except json.JSONDecodeError as e:
                        print(f"[MOCK] JSON error: {e}, line: {line}")

        except Exception as e:
            print(f"[MOCK] Error: {e}")
            break

    if client_sock in clients:
        del clients[client_sock]
    client_sock.close()
    print(f"[MOCK] Client {addr} disconnected")

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('127.0.0.1', 9000))
    server.listen(5)

    print("[MOCK] Mock C server listening on port 9000...")

    while True:
        client_sock, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client_sock, addr))
        thread.daemon = True
        thread.start()

if __name__ == '__main__':
    main()