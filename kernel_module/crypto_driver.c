/*
 * crypto_driver.c - Kernel module for chat encryption
 * Implements:
 *   1. SHA1 hashing (for password authentication)
 *   2. Substitution cipher (for message encryption/decryption)
 *
 * Device: /dev/crypto_chat
 * IOCTL commands:
 *   IOCTL_SHA1_HASH    - hash a password
 *   IOCTL_ENCRYPT_MSG  - encrypt a message
 *   IOCTL_DECRYPT_MSG  - decrypt a message
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <linux/err.h>
#include <crypto/hash.h>

#define DEVICE_NAME     "crypto_chat"
#define CLASS_NAME      "crypto"
#define MAX_BUF_SIZE    4096
#define SHA1_HEX_SIZE   41   /* 40 hex chars + null */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ChatSystem");
MODULE_DESCRIPTION("Crypto driver: SHA1 + Substitution Cipher");
MODULE_VERSION("1.0");

/* ─── IOCTL definitions ─────────────────────────────────────── */
#define CRYPTO_MAGIC    'K'
#define IOCTL_SHA1_HASH     _IOWR(CRYPTO_MAGIC, 1, struct crypto_request)
#define IOCTL_ENCRYPT_MSG   _IOWR(CRYPTO_MAGIC, 2, struct crypto_request)
#define IOCTL_DECRYPT_MSG   _IOWR(CRYPTO_MAGIC, 3, struct crypto_request)

struct crypto_request {
    char input[MAX_BUF_SIZE];
    char output[MAX_BUF_SIZE];
    int  input_len;
    int  output_len;
    int  key;            /* shift key for substitution cipher */
};

/* ─── Substitution cipher tables ───────────────────────────── */
/*
 * Custom substitution alphabet (printable ASCII 32-126)
 * We use a keyed permutation: for each printable char c,
 *   encrypt(c) = SUBST_TABLE[(c - 32 + key) % 95] + 32
 *   decrypt(c) = reverse lookup
 *
 * The SUBST_TABLE below is a fixed permutation of 0..94
 * chosen to look non-trivial (not simple Caesar shift).
 */
static const unsigned char SUBST_TABLE[95] = {
    73, 14, 61, 37, 88, 22, 51, 79,  4, 43,
    92, 18, 65, 30, 84, 11, 56, 70,  2, 47,
    91, 25, 63, 38, 82, 17, 54, 78,  8, 41,
    90, 20, 67, 33, 86, 13, 58, 72,  6, 45,
    94, 27, 60, 36, 80, 15, 52, 76, 10, 39,
    89, 23, 62, 34, 85, 19, 55, 71,  3, 44,
    93, 28, 64, 32, 83, 16, 53, 77,  9, 40,
    87, 21, 66, 31, 81, 12, 57, 75,  7, 42,
    95 % 95, 26, 59, 35, 87 % 95, 24, 50, 74,  5, 46,
    1, 29, 68, 48, 0
};

static unsigned char REVERSE_TABLE[95];

static void build_reverse_table(void)
{
    int i;
    for (i = 0; i < 95; i++)
        REVERSE_TABLE[SUBST_TABLE[i]] = (unsigned char)i;
}

/* ─── Substitution encrypt ──────────────────────────────────── */
static void subst_encrypt(const char *in, char *out, int len, int key)
{
    int i;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c >= 32 && c <= 126) {
            int idx = ((c - 32) + key) % 95;
            out[i] = (char)(SUBST_TABLE[idx] + 32);
        } else {
            out[i] = in[i]; /* keep non-printable as-is */
        }
    }
    out[len] = '\0';
}

/* ─── Substitution decrypt ──────────────────────────────────── */
static void subst_decrypt(const char *in, char *out, int len, int key)
{
    int i;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c >= 32 && c <= 126) {
            int rev = REVERSE_TABLE[c - 32];
            int idx = ((rev - key) % 95 + 95) % 95;
            out[i] = (char)(idx + 32);
        } else {
            out[i] = in[i];
        }
    }
    out[len] = '\0';
}

/* ─── SHA1 via kernel crypto API ────────────────────────────── */
static int kernel_sha1(const char *data, unsigned int len, char *hex_out)
{
    struct crypto_shash *tfm;
    struct shash_desc   *desc;
    unsigned char        digest[20];
    int                  ret, i;
    size_t               desc_size;

    tfm = crypto_alloc_shash("sha1", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("crypto_chat: failed to alloc sha1: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    desc_size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm);
    desc = kmalloc(desc_size, GFP_KERNEL);
    if (!desc) {
        crypto_free_shash(tfm);
        return -ENOMEM;
    }
    desc->tfm = tfm;

    ret = crypto_shash_digest(desc, data, len, digest);
    kfree(desc);
    crypto_free_shash(tfm);

    if (ret) {
        pr_err("crypto_chat: sha1 digest failed: %d\n", ret);
        return ret;
    }

    /* convert to hex string */
    for (i = 0; i < 20; i++)
        snprintf(hex_out + i * 2, 3, "%02x", digest[i]);
    hex_out[40] = '\0';

    return 0;
}

/* ─── Driver globals ────────────────────────────────────────── */
static int           major_number;
static struct class *crypto_class  = NULL;
static struct device*crypto_device = NULL;

static int     dev_open(struct inode *inode, struct file *file)   { return 0; }
static int     dev_release(struct inode *inode, struct file *file){ return 0; }

static long dev_ioctl(struct file *file, unsigned int cmd,
                      unsigned long arg)
{
    struct crypto_request req;
    int ret = 0;

    if (copy_from_user(&req, (struct crypto_request __user *)arg,
                       sizeof(req)))
        return -EFAULT;

    switch (cmd) {

    case IOCTL_SHA1_HASH:
        req.input[MAX_BUF_SIZE - 1] = '\0';
        ret = kernel_sha1(req.input, strlen(req.input), req.output);
        if (ret) return ret;
        req.output_len = 40;
        break;

    case IOCTL_ENCRYPT_MSG:
        req.input[MAX_BUF_SIZE - 1] = '\0';
        req.input_len = strlen(req.input);
        subst_encrypt(req.input, req.output, req.input_len, req.key);
        req.output_len = req.input_len;
        break;

    case IOCTL_DECRYPT_MSG:
        req.input[MAX_BUF_SIZE - 1] = '\0';
        req.input_len = strlen(req.input);
        subst_decrypt(req.input, req.output, req.input_len, req.key);
        req.output_len = req.input_len;
        break;

    default:
        return -EINVAL;
    }

    if (copy_to_user((struct crypto_request __user *)arg, &req, sizeof(req)))
        return -EFAULT;

    return 0;
}

static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = dev_open,
    .release        = dev_release,
    .unlocked_ioctl = dev_ioctl,
};

/* ─── Module init / exit ────────────────────────────────────── */
static int __init crypto_driver_init(void)
{
    build_reverse_table();

    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        pr_err("crypto_chat: register_chrdev failed: %d\n", major_number);
        return major_number;
    }

    crypto_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(crypto_class)) {
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(crypto_class);
    }

    crypto_device = device_create(crypto_class, NULL,
                                  MKDEV(major_number, 0),
                                  NULL, DEVICE_NAME);
    if (IS_ERR(crypto_device)) {
        class_destroy(crypto_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(crypto_device);
    }

    pr_info("crypto_chat: driver loaded, major=%d\n", major_number);
    return 0;
}

static void __exit crypto_driver_exit(void)
{
    device_destroy(crypto_class, MKDEV(major_number, 0));
    class_destroy(crypto_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    pr_info("crypto_chat: driver unloaded\n");
}

module_init(crypto_driver_init);
module_exit(crypto_driver_exit);
