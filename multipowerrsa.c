#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <gmp.h>
#include "multipowerrsa.h"

/* Initialize a Multi-Power RSA context */
void mp_rsa_init(mp_rsa_ctx *ctx, unsigned int key_size, unsigned int b) {
    ctx->key_size = key_size;
    ctx->b = b;
    
    mpz_init(ctx->p);
    mpz_init(ctx->q);
    mpz_init(ctx->n);
    mpz_init_set_ui(ctx->e, 65537); /* Standard RSA public exponent */
    mpz_init(ctx->d);
    mpz_init(ctx->r1);
    mpz_init(ctx->r2);
    mpz_init(ctx->phi_n);
    mpz_init(ctx->p_power);
}

/* Free all memory used by a Multi-Power RSA context */
void mp_rsa_clear(mp_rsa_ctx *ctx) {
    mpz_clear(ctx->p);
    mpz_clear(ctx->q);
    mpz_clear(ctx->n);
    mpz_clear(ctx->e);
    mpz_clear(ctx->d);
    mpz_clear(ctx->r1);
    mpz_clear(ctx->r2);
    mpz_clear(ctx->phi_n);
    mpz_clear(ctx->p_power);
}

/* Generate a random prime number of specified bit length */
static void generate_prime(mpz_t prime, mp_bitcnt_t bits, gmp_randstate_t state) {
    mpz_t random_num;
    mpz_init(random_num);
    
    /* Generate a random number with the correct bit length */
    mpz_urandomb(random_num, state, bits);
    
    /* Set the most significant bit to ensure correct bit length */
    mpz_setbit(random_num, bits - 1);
    
    /* Set the least significant bit to ensure it's odd */
    mpz_setbit(random_num, 0);
    
    /* Find the next prime greater than or equal to the random number */
    mpz_nextprime(prime, random_num);
    
    mpz_clear(random_num);
}

/* Generate key pair */
int mp_rsa_generate_keys(mp_rsa_ctx *ctx) {
    gmp_randstate_t state;
    mpz_t p_minus_1, q_minus_1, gcd_value, temp;
    
    /* Initialize random state */
    gmp_randinit_default(state);
    gmp_randseed_ui(state, time(NULL));
    
    /* Calculate bit sizes for p and q */
    mp_bitcnt_t bit_size_p = (ctx->key_size * 2 / 3) / ctx->b;
    mp_bitcnt_t bit_size_q = ctx->key_size / 3;
    
    mpz_init(p_minus_1);
    mpz_init(q_minus_1);
    mpz_init(gcd_value);
    mpz_init(temp);
    
    do {
        /* Generate primes p and q */
        generate_prime(ctx->p, bit_size_p, state);
        generate_prime(ctx->q, bit_size_q, state);
        
        /* Calculate p^(b-1) */
        mpz_pow_ui(ctx->p_power, ctx->p, ctx->b - 1);
        
        /* Calculate n = p^(b-1) * q */
        mpz_mul(ctx->n, ctx->p_power, ctx->q);
        
        /* Calculate φ(n) = (p-1) * (q-1) * p^(b-2) */
        mpz_sub_ui(p_minus_1, ctx->p, 1);
        mpz_sub_ui(q_minus_1, ctx->q, 1);
        
        if (ctx->b > 2) {
            mpz_pow_ui(temp, ctx->p, ctx->b - 2);
            mpz_mul(ctx->phi_n, p_minus_1, temp);
            mpz_mul(ctx->phi_n, ctx->phi_n, q_minus_1);
        } else {
            mpz_mul(ctx->phi_n, p_minus_1, q_minus_1);
        }
        
        /* Check if e and phi(n) are coprime */
        mpz_gcd(gcd_value, ctx->e, ctx->phi_n);
    } while (mpz_cmp_ui(gcd_value, 1) != 0);
    
    /* Calculate private exponent d = e^(-1) mod φ(n) */
    mpz_invert(ctx->d, ctx->e, ctx->phi_n);
    
    /* Calculate CRT components */
    mpz_mod(ctx->r1, ctx->d, p_minus_1);
    mpz_mod(ctx->r2, ctx->d, q_minus_1);
    
    /* Clean up */
    mpz_clear(p_minus_1);
    mpz_clear(q_minus_1);
    mpz_clear(gcd_value);
    mpz_clear(temp);
    gmp_randclear(state);
    
    return 0;
}

/* Encrypt a message using Multi-Power RSA */
int mp_rsa_encrypt(mp_rsa_ctx *ctx, const mpz_t message, mpz_t cipher) {
    /* Check if message is smaller than modulus */
    if (mpz_cmp(message, ctx->n) >= 0) {
        return -1; /* Message too large */
    }
    
    /* c = m^e mod n */
    mpz_powm(cipher, message, ctx->e, ctx->n);
    
    return 0;
}

/* Decrypt a message using Multi-Power RSA with CRT optimization */
int mp_rsa_decrypt(mp_rsa_ctx *ctx, const mpz_t cipher, mpz_t message) {
    mpz_t m1, m2, m_prime1, error, correction, inverse, p_power_i, temp;
    int result = 0;
    
    mpz_init(m1);
    mpz_init(m2);
    mpz_init(m_prime1);
    mpz_init(error);
    mpz_init(correction);
    mpz_init(inverse);
    mpz_init(p_power_i);
    mpz_init(temp);
    
    /* Check if cipher is valid */
    if (mpz_cmp(cipher, ctx->n) >= 0) {
        result = -1;
        goto cleanup;
    }
    
    /* Compute m1 = c^r1 mod p */
    mpz_powm(m1, cipher, ctx->r1, ctx->p);
    
    /* Compute m2 = c^r2 mod q */
    mpz_powm(m2, cipher, ctx->r2, ctx->q);
    
    /* Perform Hensel lifting to find M'1 */
    if (ctx->b > 2) {
        /* Start with initial solution modulo p */
        mpz_set(m_prime1, m1);
        
        /* Iteratively lift solution to higher powers of p */
        for (unsigned int i = 1; i < ctx->b - 1; i++) {
            mpz_pow_ui(p_power_i, ctx->p, i + 1);
            
            /* Compute error in current approximation */
            mpz_powm(error, m_prime1, ctx->e, p_power_i);
            mpz_sub(error, error, cipher);
            mpz_mod(error, error, p_power_i);
            
            /* Compute correction factor */
            mpz_pow_ui(temp, ctx->p, i);
            mpz_fdiv_q(correction, error, temp);
            
            /* Compute inverse of e * m_prime1^(e-1) mod p */
            mpz_sub_ui(temp, ctx->e, 1);
            mpz_powm(temp, m_prime1, temp, ctx->p);
            mpz_mul(temp, temp, ctx->e);
            mpz_mod(temp, temp, ctx->p);
            mpz_invert(inverse, temp, ctx->p);
            
            /* Adjust m_prime1 */
            mpz_mul(temp, correction, inverse);
            mpz_mod(temp, temp, ctx->p);
            mpz_mul(temp, temp, p_power_i);
            mpz_sub(m_prime1, m_prime1, temp);
            mpz_mod(m_prime1, m_prime1, p_power_i);
        }
    } else {
        mpz_set(m_prime1, m1);
    }
    
    /* Apply Chinese Remainder Theorem */
    mpz_t q_inv, p_power_inv, term1, term2;
    mpz_init(q_inv);
    mpz_init(p_power_inv);
    mpz_init(term1);
    mpz_init(term2);
    
    /* Compute CRT coefficients */
    mpz_invert(q_inv, ctx->q, ctx->p_power);
    mpz_invert(p_power_inv, ctx->p_power, ctx->q);
    
    /* Apply CRT formula */
    mpz_mul(term1, m_prime1, ctx->q);
    mpz_mul(term1, term1, q_inv);
    mpz_mod(term1, term1, ctx->n);
    
    mpz_mul(term2, m2, ctx->p_power);
    mpz_mul(term2, term2, p_power_inv);
    mpz_mod(term2, term2, ctx->n);
    
    mpz_add(message, term1, term2);
    mpz_mod(message, message, ctx->n);
    
    mpz_clear(q_inv);
    mpz_clear(p_power_inv);
    mpz_clear(term1);
    mpz_clear(term2);
    
cleanup:
    mpz_clear(m1);
    mpz_clear(m2);
    mpz_clear(m_prime1);
    mpz_clear(error);
    mpz_clear(correction);
    mpz_clear(inverse);
    mpz_clear(p_power_i);
    mpz_clear(temp);
    
    return result;
}

/* Export public key to memory */
int mp_rsa_export_public_key(mp_rsa_ctx *ctx, unsigned char **key, size_t *key_len) {
    size_t n_size = mpz_sizeinbase(ctx->n, 16) + 2; // +2 for "0x" prefix
    size_t e_size = mpz_sizeinbase(ctx->e, 16) + 2;
    
    // Calculate total buffer size
    *key_len = n_size + e_size + 2; // Include 2 separator bytes
    
    // Allocate memory
    *key = (unsigned char*) malloc(*key_len);
    if (*key == NULL) {
        return -1;
    }
    
    // Format key as "n:e"
    char *n_str = mpz_get_str(NULL, 16, ctx->n);
    char *e_str = mpz_get_str(NULL, 16, ctx->e);
    
    snprintf((char*)*key, *key_len, "%s:%s", n_str, e_str);
    
    // Free temporary strings
    free(n_str);
    free(e_str);
    
    return 0;
}

/* Export private key to memory */
int mp_rsa_export_private_key(mp_rsa_ctx *ctx, unsigned char **key, size_t *key_len) {
    size_t p_size = mpz_sizeinbase(ctx->p, 16) + 2;
    size_t q_size = mpz_sizeinbase(ctx->q, 16) + 2;
    size_t r1_size = mpz_sizeinbase(ctx->r1, 16) + 2;
    size_t r2_size = mpz_sizeinbase(ctx->r2, 16) + 2;
    
    // Calculate total buffer size
    *key_len = p_size + q_size + r1_size + r2_size + 5; // 4 separators + 1 for b
    
    // Allocate memory
    *key = (unsigned char*) malloc(*key_len);
    if (*key == NULL) {
        return -1;
    }
    
    // Format key as "p:q:r1:r2:b"
    char *p_str = mpz_get_str(NULL, 16, ctx->p);
    char *q_str = mpz_get_str(NULL, 16, ctx->q);
    char *r1_str = mpz_get_str(NULL, 16, ctx->r1);
    char *r2_str = mpz_get_str(NULL, 16, ctx->r2);
    
    snprintf((char*)*key, *key_len, "%s:%s:%s:%s:%u", 
             p_str, q_str, r1_str, r2_str, ctx->b);
    
    // Free temporary strings
    free(p_str);
    free(q_str);
    free(r1_str);
    free(r2_str);
    
    return 0;
}

/* Import public key from memory */
int mp_rsa_import_public_key(mp_rsa_ctx *ctx, const unsigned char *key, size_t key_len) {
    char *key_copy = strndup((const char*)key, key_len);
    if (key_copy == NULL) {
        return -1;
    }
    
    // Parse "n:e" format
    char *e_str = strchr(key_copy, ':');
    if (e_str == NULL) {
        free(key_copy);
        return -2;
    }
    
    *e_str = '\0';
    e_str++;
    
    // Import the values
    if (mpz_set_str(ctx->n, key_copy, 16) != 0 ||
        mpz_set_str(ctx->e, e_str, 16) != 0) {
        free(key_copy);
        return -3;
    }
    
    free(key_copy);
    return 0;
}

/* Import private key from memory */
int mp_rsa_import_private_key(mp_rsa_ctx *ctx, const unsigned char *key, size_t key_len) {
    char *key_copy = strndup((const char*)key, key_len);
    if (key_copy == NULL) {
        return -1;
    }
    
    // Parse "p:q:r1:r2:b" format
    char *q_str = strchr(key_copy, ':');
    if (q_str == NULL) {
        free(key_copy);
        return -2;
    }
    
    *q_str = '\0';
    q_str++;
    
    char *r1_str = strchr(q_str, ':');
    if (r1_str == NULL) {
        free(key_copy);
        return -2;
    }
    
    *r1_str = '\0';
    r1_str++;
    
    char *r2_str = strchr(r1_str, ':');
    if (r2_str == NULL) {
        free(key_copy);
        return -2;
    }
    
    *r2_str = '\0';
    r2_str++;
    
    char *b_str = strchr(r2_str, ':');
    if (b_str == NULL) {
        free(key_copy);
        return -2;
    }
    
    *b_str = '\0';
    b_str++;
    
    // Import the values
    if (mpz_set_str(ctx->p, key_copy, 16) != 0 ||
        mpz_set_str(ctx->q, q_str, 16) != 0 ||
        mpz_set_str(ctx->r1, r1_str, 16) != 0 ||
        mpz_set_str(ctx->r2, r2_str, 16) != 0) {
        free(key_copy);
        return -3;
    }
    
    ctx->b = atoi(b_str);
    
    // Calculate p^(b-1)
    mpz_pow_ui(ctx->p_power, ctx->p, ctx->b - 1);
    
    // Calculate n = p^(b-1) * q
    mpz_mul(ctx->n, ctx->p_power, ctx->q);
    
    free(key_copy);
    return 0;
}