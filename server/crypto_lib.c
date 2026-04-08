/*
 * crypto_lib.c
 * Userspace wrapper around /dev/crypto_chat driver.
 * Falls back to pure-C implementations when module is not loaded.
 */

#include "crypto_lib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdint.h>

#define DEVICE_PATH "/dev/crypto_chat"

/* ════════════════════════════════════════════════════════════
 *  Kernel driver wrappers
 * ════════════════════════════════════════════════════════════ */

int crypto_open(void)
{
    int fd = open(DEVICE_PATH, O_RDWR);
    if (fd < 0)
        perror("crypto_open: /dev/crypto_chat");
    return fd;
}

void crypto_close(int fd)
{
    if (fd >= 0) close(fd);
}

int crypto_sha1(int fd, const char *password, char *out)
{
    struct crypto_request req;
    memset(&req, 0, sizeof(req));
    strncpy(req.input, password, MAX_BUF_SIZE - 1);

    if (ioctl(fd, IOCTL_SHA1_HASH, &req) < 0)
        return -1;

    memcpy(out, req.output, SHA1_HEX_SIZE);
    return 0;
}

int crypto_encrypt(int fd, const char *plain, char *cipher, int key)
{
    struct crypto_request req;
    memset(&req, 0, sizeof(req));
    strncpy(req.input, plain, MAX_BUF_SIZE - 1);
    req.key = key;

    if (ioctl(fd, IOCTL_ENCRYPT_MSG, &req) < 0)
        return -1;

    memcpy(cipher, req.output, req.output_len + 1);
    return req.output_len;
}

int crypto_decrypt(int fd, const char *cipher_in, char *plain, int key)
{
    struct crypto_request req;
    memset(&req, 0, sizeof(req));
    strncpy(req.input, cipher_in, MAX_BUF_SIZE - 1);
    req.key = key;

    if (ioctl(fd, IOCTL_DECRYPT_MSG, &req) < 0)
        return -1;

    memcpy(plain, req.output, req.output_len + 1);
    return req.output_len;
}

/* ════════════════════════════════════════════════════════════
 *  Pure-C fallback SHA1
 *  Reference: RFC 3174
 * ════════════════════════════════════════════════════════════ */

#define ROL32(n,b) (((n)<<(b))|((n)>>(32-(b))))

static void sha1_process_block(uint32_t *H, const uint8_t *block)
{
    uint32_t W[80], a, b, c, d, e, f, k, tmp;
    int t;

    for (t = 0; t < 16; t++) {
        W[t]  = ((uint32_t)block[t*4  ] << 24)
              | ((uint32_t)block[t*4+1] << 16)
              | ((uint32_t)block[t*4+2] <<  8)
              | ((uint32_t)block[t*4+3]);
    }
    for (t = 16; t < 80; t++)
        W[t] = ROL32(W[t-3]^W[t-8]^W[t-14]^W[t-16], 1);

    a = H[0]; b = H[1]; c = H[2]; d = H[3]; e = H[4];

    for (t = 0; t < 80; t++) {
        if      (t < 20) { f = (b & c) | (~b & d); k = 0x5A827999; }
        else if (t < 40) { f = b ^ c ^ d;           k = 0x6ED9EBA1; }
        else if (t < 60) { f = (b&c)|(b&d)|(c&d);  k = 0x8F1BBCDC; }
        else             { f = b ^ c ^ d;           k = 0xCA62C1D6; }

        tmp = ROL32(a,5) + f + e + k + W[t];
        e = d; d = c; c = ROL32(b,30); b = a; a = tmp;
    }
    H[0]+=a; H[1]+=b; H[2]+=c; H[3]+=d; H[4]+=e;
}

void fallback_sha1(const char *input, char *hex_out)
{
    size_t len = strlen(input);
    size_t bit_len = len * 8;

    /* padded message length */
    size_t padded = ((len + 9 + 63) / 64) * 64;
    uint8_t *msg = (uint8_t *)calloc(padded, 1);
    if (!msg) { strcpy(hex_out, "0000000000000000000000000000000000000000"); return; }

    memcpy(msg, input, len);
    msg[len] = 0x80;

    /* append length in bits as big-endian 64-bit */
    for (int i = 0; i < 8; i++)
        msg[padded - 1 - i] = (uint8_t)(bit_len >> (i * 8));

    uint32_t H[5] = {
        0x67452301, 0xEFCDAB89, 0x98BADCFE,
        0x10325476, 0xC3D2E1F0
    };

    for (size_t off = 0; off < padded; off += 64)
        sha1_process_block(H, msg + off);

    free(msg);

    for (int i = 0; i < 5; i++)
        snprintf(hex_out + i*8, 9, "%08x", H[i]);
    hex_out[40] = '\0';
}

/* ════════════════════════════════════════════════════════════
 *  Pure-C substitution cipher fallback (same tables as kernel)
 * ════════════════════════════════════════════════════════════ */

static const unsigned char SUBST_TABLE[95] = {
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
};

static unsigned char REV_TABLE[95];
static int rev_built = 0;

static void build_rev(void)
{
    if (rev_built) return;
    for (int i = 0; i < 95; i++)
        REV_TABLE[SUBST_TABLE[i]] = (unsigned char)i;
    rev_built = 1;
}

void fallback_encrypt(const char *in, char *out, int len, int key)
{
    build_rev();
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c >= 32 && c <= 126) {
            int idx = ((c - 32) + key) % 95;
            out[i] = (char)(SUBST_TABLE[idx] + 32);
        } else {
            out[i] = in[i];
        }
    }
    out[len] = '\0';
}

void fallback_decrypt(const char *in, char *out, int len, int key)
{
    build_rev();
    for (int i = 0; i < len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c >= 32 && c <= 126) {
            int rev = REV_TABLE[c - 32];
            int idx = ((rev - key) % 95 + 95) % 95;
            out[i] = (char)(idx + 32);
        } else {
            out[i] = in[i];
        }
    }
    out[len] = '\0';
}
