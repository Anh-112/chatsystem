#!/usr/bin/env python3
"""
Test JSON parsing like C server
"""

# Test substitution cipher
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

# Test JSON parsing like C server
def jget_str(j, k):
    s = f'"{k}":'
    p = j.find(s)
    if p == -1:
        return None
    p += len(s)
    while p < len(j) and j[p] == ' ':
        p += 1
    if p >= len(j) or j[p] != '"':
        return None
    p += 1
    out = []
    while p < len(j) and j[p] != '"':
        if j[p] == '\\':
            p += 1
            if p >= len(j):
                break
            if j[p] == '"':
                out.append('"')
            elif j[p] == '\\':
                out.append('\\')
            elif j[p] == '/':
                out.append('/')
            elif j[p] == 'b':
                out.append('\b')
            elif j[p] == 'f':
                out.append('\f')
            elif j[p] == 'n':
                out.append('\n')
            elif j[p] == 'r':
                out.append('\r')
            elif j[p] == 't':
                out.append('\t')
            elif j[p] == 'u':
                # Skip unicode
                p += 4
                continue
            p += 1
        else:
            out.append(j[p])
            p += 1
    return ''.join(out)

# Test JSON escaping
def json_escape(in_str):
    out = []
    for c in in_str:
        if c == '"':
            out.append('\\"')
        elif c == '\\':
            out.append('\\\\')
        elif c == '\n':
            out.append('\\n')
        elif c == '\r':
            out.append('\\r')
        elif c == '\t':
            out.append('\\t')
        elif ord(c) < 32:
            out.append(f'\\u{ord(c):04x}')
        else:
            out.append(c)
    return ''.join(out)

# Test packet creation
def mkpkt(type, from_u, to, tt, content, tok, ex):
    ef = json_escape(from_u or "")
    et = json_escape(to or "")
    ec = json_escape(content or "")
    etok = json_escape(tok or "")
    eex = json_escape(ex or "")
    pkt = f'{{"type":{type},"from":"{ef}","to":"{et}","target_type":{tt},"content":"{ec}","token":"{etok}","extra":"{eex}"}}\n'
    return pkt

# Test
if __name__ == '__main__':
    print("Testing chat message flow...")

    # Test message
    plain = "Hello world! Đây là tin nhắn test với ký tự đặc biệt: @#$%^&*()"
    print(f"Original: {plain}")

    # Encrypt
    cipher = subst_encrypt(plain)
    print(f"Encrypted: {cipher}")

    # Create packet
    pkt = mkpkt(4, "user1", "user2", 1, cipher, "token123", "")
    print(f"Packet: {pkt}")

    # Test parsing like C server
    parsed_content = jget_str(pkt, "content")
    print(f"Parsed content: '{parsed_content}'")

    # Decrypt
    decrypted = subst_decrypt(parsed_content)
    print(f"Decrypted: '{decrypted}'")

    if decrypted == plain:
        print("✅ Test passed!")
    else:
        print("❌ Test failed!")