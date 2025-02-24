#ifndef TWOFISH_H
#define TWOFISH_H

#define u32 unsigned int
#define BYTE unsigned char
#ifndef BIG_ENDIAN
#define BIG_ENDIAN 0
#endif
#define RS_MOD 0x14D
#define RHO 0x01010101L

/* Twofish context structure */
typedef struct {
    u32 K[40];           /* Expanded key */
    u32 QF[4][256];      /* Fully keyed Q function */
} TWOFISH_CTX;

/* Initialize a Twofish context */
void twofish_init_ctx(TWOFISH_CTX *ctx);

/* Set the key for a Twofish context */
void twofish_set_key(TWOFISH_CTX *ctx, BYTE M[], int key_size);

/* Encrypt a block using Twofish */
void twofish_encrypt(TWOFISH_CTX *ctx, BYTE PT[16]);

/* Decrypt a block using Twofish */
void twofish_decrypt(TWOFISH_CTX *ctx, BYTE PT[16]);

/* Free resources in a Twofish context */
void twofish_free_ctx(TWOFISH_CTX *ctx);

#endif /* TWOFISH_H */