#ifndef CRYPTO_LIB_H
#define CRYPTO_LIB_H

#include <stddef.h>

/* ─── IOCTL definitions (must match kernel module) ─────────── */
#define CRYPTO_MAGIC        'K'
#define IOCTL_SHA1_HASH     _IOWR(CRYPTO_MAGIC, 1, struct crypto_request)
#define IOCTL_ENCRYPT_MSG   _IOWR(CRYPTO_MAGIC, 2, struct crypto_request)
#define IOCTL_DECRYPT_MSG   _IOWR(CRYPTO_MAGIC, 3, struct crypto_request)

#define MAX_BUF_SIZE        4096
#define SHA1_HEX_SIZE       41

struct crypto_request {
    char input[MAX_BUF_SIZE];
    char output[MAX_BUF_SIZE];
    int  input_len;
    int  output_len;
    int  key;
};

/* ─── API ────────────────────────────────────────────────────── */
int  crypto_open(void);          /* open /dev/crypto_chat, return fd */
void crypto_close(int fd);

/* hash password → 40-char hex SHA1 stored in out (must be ≥41 bytes) */
int  crypto_sha1(int fd, const char *password, char *out);

/* encrypt/decrypt in-place; key is 0-94 */
int  crypto_encrypt(int fd, const char *plain,  char *cipher, int key);
int  crypto_decrypt(int fd, const char *cipher, char *plain,  int key);

/* ─── Fallback (pure-C) used when driver not loaded ─────────── */
void fallback_sha1(const char *input, char *hex_out);
void fallback_encrypt(const char *in, char *out, int len, int key);
void fallback_decrypt(const char *in, char *out, int len, int key);

#endif /* CRYPTO_LIB_H */
