/*
 * clefia.h - Public API for the CLEFIA block cipher (RFC 6114 / ISO 29192-2).
 *
 * 128-bit block cipher with 128/192/256-bit keys, designed by Sony (2007).
 * A "lightweight" cipher (3 Kgates hardware / fast software) standardized
 * as ISO/IEC 29192-2, intended as an AES-compatible alternative for
 * constrained/IoT and embedded targets.
 *
 * This is a clean-room, dependency-free, portable C99 implementation
 * written from the IETF specification (RFC 6114), not from Sony's
 * reference code.
 *
 * Reference: RFC 6114 "The 128-Bit Blockcipher CLEFIA".
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef CLEFIA_H
#define CLEFIA_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CLEFIA_BLOCK_SIZE    16u
#define CLEFIA_MAX_KEY_BYTES 32u   /* 256-bit key */

typedef enum {
    CLEFIA_SUCCESS        = 0,
    CLEFIA_INVALID_KEYLEN = -1   /* key length not 16/24/32 bytes */
} clefia_status;

/*
 * Opaque context holding the expanded key schedule.
 * ek layout (byte buffer):
 *   [0..7]     = WK0 || WK1      (initial whitening)
 *   [8 .. 8+8r-1] = RK_0 .. RK_{2r-1}  (round keys, r = 18/22/26)
 *   [..]       = WK2 || WK3      (final whitening)
 */
typedef struct {
    uint8_t ek[224];   /* 8 + 4*52 + 8 = 224 bytes (max for 256-bit key) */
    int     rounds;    /* 18 (128-bit), 22 (192-bit), 26 (256-bit) */
    int     key_bits;
} clefia_ctx;

/*
 * Expand a key of 16, 24 or 32 bytes (128/192/256 bits) into a context.
 * Returns CLEFIA_INVALID_KEYLEN for other lengths.
 */
clefia_status clefia_set_key(clefia_ctx *ctx,
                             const uint8_t *key,
                             size_t key_len);

/* Encrypt/decrypt a single 16-byte block. */
void clefia_encrypt_block(const clefia_ctx *ctx,
                          const uint8_t in[CLEFIA_BLOCK_SIZE],
                          uint8_t out[CLEFIA_BLOCK_SIZE]);
void clefia_decrypt_block(const clefia_ctx *ctx,
                          const uint8_t in[CLEFIA_BLOCK_SIZE],
                          uint8_t out[CLEFIA_BLOCK_SIZE]);

/*
 * ECB helpers. in/out may alias for in-place operation.
 * len MUST be a multiple of CLEFIA_BLOCK_SIZE.
 * Returns CLEFIA_INVALID_KEYLEN if ctx is unset, else CLEFIA_SUCCESS.
 */
clefia_status clefia_ecb_encrypt(const clefia_ctx *ctx,
                                 const uint8_t *in, size_t len,
                                 uint8_t *out);
clefia_status clefia_ecb_decrypt(const clefia_ctx *ctx,
                                 const uint8_t *in, size_t len,
                                 uint8_t *out);

/* Self-test against RFC 6114 test vectors. Returns 0 on success,
 * non-zero (bitmask of failed vectors) on failure. */
int clefia_selftest(void);

#ifdef __cplusplus
}
#endif

#endif /* CLEFIA_H */
