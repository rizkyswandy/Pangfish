#ifndef MULTIPOWERRSA_H
#define MULTIPOWERRSA_H

#include <stddef.h>
#include <gmp.h>

/* Multi-Power RSA context */
typedef struct {
    mpz_t p;          /* Prime p */
    mpz_t q;          /* Prime q */
    mpz_t n;          /* Modulus n = p^(b-1) * q */
    mpz_t e;          /* Public exponent */
    mpz_t d;          /* Private exponent */
    mpz_t r1;         /* CRT exponent 1 */
    mpz_t r2;         /* CRT exponent 2 */
    mpz_t phi_n;      /* Euler's totient function of n */
    mpz_t p_power;    /* p^(b-1) */
    unsigned int key_size;  /* Key size in bits */
    unsigned int b;   /* Power parameter */
} mp_rsa_ctx;

/* Initialize a Multi-Power RSA context */
void mp_rsa_init(mp_rsa_ctx *ctx, unsigned int key_size, unsigned int b);

/* Free all memory used by a Multi-Power RSA context */
void mp_rsa_clear(mp_rsa_ctx *ctx);

/* Generate key pair */
int mp_rsa_generate_keys(mp_rsa_ctx *ctx);

/* Encrypt a message using Multi-Power RSA */
int mp_rsa_encrypt(mp_rsa_ctx *ctx, const mpz_t message, mpz_t cipher);

/* Decrypt a message using Multi-Power RSA */
int mp_rsa_decrypt(mp_rsa_ctx *ctx, const mpz_t cipher, mpz_t message);

/* Export public key to memory */
int mp_rsa_export_public_key(mp_rsa_ctx *ctx, unsigned char **key, size_t *key_len);

/* Export private key to memory */
int mp_rsa_export_private_key(mp_rsa_ctx *ctx, unsigned char **key, size_t *key_len);

/* Import public key from memory */
int mp_rsa_import_public_key(mp_rsa_ctx *ctx, const unsigned char *key, size_t key_len);

/* Import private key from memory */
int mp_rsa_import_private_key(mp_rsa_ctx *ctx, const unsigned char *key, size_t key_len);

#endif /* MULTIPOWERRSA_H */