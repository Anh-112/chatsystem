# 🔐 CryptoChat

**Hệ thống chat có mã hóa end-to-end, xác thực SHA1, và kernel driver trên Linux**

```
Browser (WebSocket)
       │
       ▼
web_gateway.py  ──TCP──▶  chat_server (C)  ──IOCTL──▶  /dev/crypto_chat (Kernel Driver)
                                                              │
                                                    ┌─────────────────┐
                                                    │  SHA1 (kernel)  │
                                                    │  Subst Cipher   │
                                                    └─────────────────┘
```

---

## Kiến trúc

| Thành phần | Ngôn ngữ | Mô tả |
|---|---|---|
| `kernel_module/crypto_driver.c` | C (kernel) | Character device `/dev/crypto_chat`, xử lý SHA1 + Substitution Cipher qua IOCTL |
| `server/chat_server.c` | C | TCP socket server, quản lý client, phòng chat, routing tin nhắn |
| `server/crypto_lib.c` | C | Userspace wrapper gọi kernel driver qua IOCTL; fallback pure-C nếu module chưa load |
| `server/chat_client.c` | C | Terminal client đầy đủ tính năng |
| `web/web_gateway.py` | Python | Flask + Socket.IO bridge, dịch WebSocket ↔ TCP |
| `web/index.html` | HTML/JS | Giao diện Messenger-style |

---

## Luồng xác thực

```
Client nhập password
       │
       ▼  (client-side)
   raw password ──────────────────────────────▶ C server
                                                      │
                                                      ▼  (kernel driver / fallback)
                                               SHA1(password) = 40-char hex
                                                      │
                                                      ▼
                                               So sánh với stored hash trong users.db
                                                      │
                                               ┌──────┴──────┐
                                             match          no match
                                               │                │
                                         session token      PKT_ERROR
                                         (32-char random)
```

## Luồng tin nhắn

```
Client A nhập "Xin chào"
       │
       ▼  (web gateway / chat_client)
Substitution Cipher encrypt("Xin chào", key=42) → ciphertext
       │
       ▼  TCP → C server
Server nhận ciphertext
       │  decrypt → lưu history.db (plaintext)
       ▼  encrypt lại → gửi tới Client B
Client B nhận ciphertext
       │
       ▼  decrypt → hiển thị "Xin chào"
```

## Thuật toán mã hóa (Substitution Cipher)

Mỗi ký tự in được (ASCII 32-126, tức 95 ký tự) được ánh xạ qua bảng hoán vị 95 phần tử cố định, kết hợp với key dịch chuyển:

```
encrypt(c):
  idx = (c - 32 + key) % 95
  out = SUBST_TABLE[idx] + 32

decrypt(c):
  rev = REVERSE_TABLE[c - 32]
  idx = (rev - key + 95) % 95
  out = idx + 32
```

Bảng `SUBST_TABLE[95]` là hoán vị tùy chỉnh (không phải Caesar đơn giản).  
Key mặc định = **42**.

---

## Cài đặt

### Yêu cầu
- Ubuntu 20.04+ / Debian
- `gcc`, `make`, `python3`, `pip3`
- (Tùy chọn) `linux-headers-$(uname -r)` để build kernel module

### Cài đặt nhanh

```bash
git clone <repo> cryptochat && cd cryptochat
chmod +x install.sh
./install.sh
```

### Build thủ công

```bash
# 1. Build C server + client
cd server
make
# → chat_server, chat_client

# 2. (Tùy chọn) Build kernel module
cd ../kernel_module
sudo apt install linux-headers-$(uname -r)
make
sudo insmod crypto_driver.ko
sudo chmod 666 /dev/crypto_chat

# 3. Python gateway
pip3 install flask flask-socketio eventlet
```

---

## Chạy

### Tất cả cùng lúc
```bash
./scripts/start.sh
# Mở trình duyệt: http://localhost:5000
```

### Thủ công

**Terminal 1 – C server:**
```bash
cd server
./chat_server
# [SERVER] Crypto driver: KERNEL   (nếu module đã load)
# [SERVER] Crypto driver: fallback (nếu chưa load)
# [SERVER] Chat server listening on port 9000
```

**Terminal 2 – Web gateway:**
```bash
cd web
python3 web_gateway.py
# [GW] Web gateway starting on http://0.0.0.0:5000
```

**Terminal 3 – Web UI:**
```
Mở http://localhost:5000
```

**Hoặc Terminal client:**
```bash
cd server
./chat_client [host] [port]
# Mặc định: 127.0.0.1:9000
```

---

## Terminal client – Lệnh

| Lệnh | Mô tả |
|---|---|
| `/register <user>` | Đăng ký tài khoản (nhập password ẩn) |
| `/login <user>` | Đăng nhập |
| `/dm <user>` | Chọn chat riêng với user |
| `/room <room>` | Chọn nhóm chat (tự tạo nếu chưa có) |
| `/create <room>` | Tạo nhóm mới |
| `/join <room>` | Vào nhóm |
| `/leave` | Rời nhóm hiện tại |
| `/users` | Danh sách user đang online |
| `/rooms` | Danh sách nhóm |
| `/help` | Hiển thị trợ giúp |
| `/quit` | Thoát |
| `<text>` | Gửi tin nhắn (tự động mã hóa) |

### Ví dụ phiên làm việc
```
[no target] > /register alice
Password: ****
[✓] Đăng ký thành công!

[no target] > /login alice
Password: ****
[✓] Đăng nhập thành công! Token: 3f9a2b1c...

[no target] > /dm bob
[→] Chat riêng với: bob

[→bob] > Xin chào Bob!
  └── sent encrypted: r{bH|{_JG?

[→bob] > /create devteam
[OK] room_created

[→bob] > /room devteam
[→] Chat nhóm: devteam

[→devteam] > Hello mọi người!
  └── sent encrypted: p>??_U$V^T=_U?
```

---

## Kernel module – IOCTL API

```c
#define IOCTL_SHA1_HASH     _IOWR('K', 1, struct crypto_request)
#define IOCTL_ENCRYPT_MSG   _IOWR('K', 2, struct crypto_request)
#define IOCTL_DECRYPT_MSG   _IOWR('K', 3, struct crypto_request)

struct crypto_request {
    char input[4096];
    char output[4096];
    int  input_len;
    int  output_len;
    int  key;          // shift key cho Substitution Cipher
};
```

Ví dụ gọi từ userspace:
```c
int fd = open("/dev/crypto_chat", O_RDWR);

struct crypto_request req = {0};
strcpy(req.input, "mypassword");
ioctl(fd, IOCTL_SHA1_HASH, &req);
printf("SHA1: %s\n", req.output);   // 40-char hex

strcpy(req.input, "Hello World");
req.key = 42;
ioctl(fd, IOCTL_ENCRYPT_MSG, &req);
printf("Encrypted: %s\n", req.output);
```

---

## Cấu trúc file

```
cryptochat/
├── install.sh
├── scripts/
│   ├── start.sh
│   └── stop.sh
├── kernel_module/
│   ├── crypto_driver.c     # Kernel module (SHA1 + Substitution Cipher)
│   └── Makefile
├── server/
│   ├── chat_server.h       # Shared types, constants, protocol
│   ├── chat_server.c       # C TCP server
│   ├── chat_client.c       # C terminal client
│   ├── crypto_lib.h        # Crypto API header
│   ├── crypto_lib.c        # Kernel driver wrapper + pure-C fallback
│   └── Makefile
└── web/
    ├── web_gateway.py      # Python Flask + Socket.IO bridge
    └── index.html          # Messenger-style web UI
```

---

## Giao thức JSON

Mọi gói tin đều là JSON object, kết thúc bằng `\n`:

```json
{
  "type": 4,
  "from": "alice",
  "to": "bob",
  "target_type": 1,
  "content": "r{bH|{_JG?",
  "token": "3f9a2b1c...",
  "extra": ""
}
```

| `type` | Ý nghĩa |
|---|---|
| 1 | REGISTER |
| 2 | LOGIN |
| 4 | SEND_MSG (encrypted) |
| 5 | RECV_MSG (server→client, encrypted) |
| 6 | CREATE_ROOM |
| 7 | JOIN_ROOM |
| 8 | LEAVE_ROOM |
| 9 | LIST_USERS |
| 10 | LIST_ROOMS |
| 20 | OK |
| 21 | ERROR |

`target_type`: 1 = DM (tin nhắn riêng), 2 = ROOM (nhóm)

---

## Bảo mật

- **Mật khẩu** không bao giờ lưu dạng plaintext – chỉ lưu SHA1 hash trong `users.db`
- **Tin nhắn** được mã hóa bằng Substitution Cipher trước khi truyền qua mạng
- **Session token** ngẫu nhiên 32 ký tự, cấp mới mỗi lần đăng nhập
- **Xác thực token** trên mọi request sau khi đăng nhập

> **Lưu ý học thuật:** Đây là dự án demo cho môn học. SHA1 không được khuyến nghị cho production mật khẩu thực tế (nên dùng bcrypt/argon2). Substitution Cipher cũng không đủ mạnh cho bảo mật thực (cần AES-256). Kernel module được yêu cầu theo đề bài.
