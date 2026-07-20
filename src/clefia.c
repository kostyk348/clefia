/*
 * clefia.c - CLEFIA block cipher (RFC 6114 / ISO 29192-2), clean-room C99.
 *
 * Implementation written from RFC 6114 (S0/S1 tables, M0/M1 diffusion
 * matrices, GF(2^8)/GF(2^16) arithmetic, GFN structure, key schedule and
 * test vectors are all taken from that public IETF specification).
 *
 * SPDX-License-Identifier: MIT
 */
#include "clefia.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* S-boxes (RFC 6114 Table 1 and Table 2)                             */
/* ------------------------------------------------------------------ */
static const uint8_t S0[256] = {
    0x57,0x49,0xd1,0xc6,0x2f,0x33,0x74,0xfb,0x95,0x6d,0x82,0xea,0x0e,0xb0,0xa8,0x1c,
    0x28,0xd0,0x4b,0x92,0x5c,0xee,0x85,0xb1,0xc4,0x0a,0x76,0x3d,0x63,0xf9,0x17,0xaf,
    0xbf,0xa1,0x19,0x65,0xf7,0x7a,0x32,0x20,0x06,0xce,0xe4,0x83,0x9d,0x5b,0x4c,0xd8,
    0x42,0x5d,0x2e,0xe8,0xd4,0x9b,0x0f,0x13,0x3c,0x89,0x67,0xc0,0x71,0xaa,0xb6,0xf5,
    0xa4,0xbe,0xfd,0x8c,0x12,0x00,0x97,0xda,0x78,0xe1,0xcf,0x6b,0x39,0x43,0x55,0x26,
    0x30,0x98,0xcc,0xdd,0xeb,0x54,0xb3,0x8f,0x4e,0x16,0xfa,0x22,0xa5,0x77,0x09,0x61,
    0xd6,0x2a,0x53,0x37,0x45,0xc1,0x6c,0xae,0xef,0x70,0x08,0x99,0x8b,0x1d,0xf2,0xb4,
    0xe9,0xc7,0x9f,0x4a,0x31,0x25,0xfe,0x7c,0xd3,0xa2,0xbd,0x56,0x14,0x88,0x60,0x0b,
    0xcd,0xe2,0x34,0x50,0x9e,0xdc,0x11,0x05,0x2b,0xb7,0xa9,0x48,0xff,0x66,0x8a,0x73,
    0x03,0x75,0x86,0xf1,0x6a,0xa7,0x40,0xc2,0xb9,0x2c,0xdb,0x1f,0x58,0x94,0x3e,0xed,
    0xfc,0x1b,0xa0,0x04,0xb8,0x8d,0xe6,0x59,0x62,0x93,0x35,0x7e,0xca,0x21,0xdf,0x47,
    0x15,0xf3,0xba,0x7f,0xa6,0x69,0xc8,0x4d,0x87,0x3b,0x9c,0x01,0xe0,0xde,0x24,0x52,
    0x7b,0x0c,0x68,0x1e,0x80,0xb2,0x5a,0xe7,0xad,0xd5,0x23,0xf4,0x46,0x3f,0x91,0xc9,
    0x6e,0x84,0x72,0xbb,0x0d,0x18,0xd9,0x96,0xf0,0x5f,0x41,0xac,0x27,0xc5,0xe3,0x3a,
    0x81,0x6f,0x07,0xa3,0x79,0xf6,0x2d,0x38,0x1a,0x44,0x5e,0xb5,0xd2,0xec,0xcb,0x90,
    0x9a,0x36,0xe5,0x29,0xc3,0x4f,0xab,0x64,0x51,0xf8,0x10,0xd7,0xbc,0x02,0x7d,0x8e
};
static const uint8_t S1[256] = {
    0x6c,0xda,0xc3,0xe9,0x4e,0x9d,0x0a,0x3d,0xb8,0x36,0xb4,0x38,0x13,0x34,0x0c,0xd9,
    0xbf,0x74,0x94,0x8f,0xb7,0x9c,0xe5,0xdc,0x9e,0x07,0x49,0x4f,0x98,0x2c,0xb0,0x93,
    0x12,0xeb,0xcd,0xb3,0x92,0xe7,0x41,0x60,0xe3,0x21,0x27,0x3b,0xe6,0x19,0xd2,0x0e,
    0x91,0x11,0xc7,0x3f,0x2a,0x8e,0xa1,0xbc,0x2b,0xc8,0xc5,0x0f,0x5b,0xf3,0x87,0x8b,
    0xfb,0xf5,0xde,0x20,0xc6,0xa7,0x84,0xce,0xd8,0x65,0x51,0xc9,0xa4,0xef,0x43,0x53,
    0x25,0x5d,0x9b,0x31,0xe8,0x3e,0x0d,0xd7,0x80,0xff,0x69,0x8a,0xba,0x0b,0x73,0x5c,
    0x6e,0x54,0x15,0x62,0xf6,0x35,0x30,0x52,0xa3,0x16,0xd3,0x28,0x32,0xfa,0xaa,0x5e,
    0xcf,0xea,0xed,0x78,0x33,0x58,0x09,0x7b,0x63,0xc0,0xc1,0x46,0x1e,0xdf,0xa9,0x99,
    0x55,0x04,0xc4,0x86,0x39,0x77,0x82,0xec,0x40,0x18,0x90,0x97,0x59,0xdd,0x83,0x1f,
    0x9a,0x37,0x06,0x24,0x64,0x7c,0xa5,0x56,0x48,0x08,0x85,0xd0,0x61,0x26,0xca,0x6f,
    0x7e,0x6a,0xb6,0x71,0xa0,0x70,0x05,0xd1,0x45,0x8c,0x23,0x1c,0xf0,0xee,0x89,0xad,
    0x7a,0x4b,0xc2,0x2f,0xdb,0x5a,0x4d,0x76,0x67,0x17,0x2d,0xf4,0xcb,0xb1,0x4a,0xa8,
    0xb5,0x22,0x47,0x3a,0xd5,0x10,0x4c,0x72,0xcc,0x00,0xf9,0xe0,0xfd,0xe2,0xfe,0xae,
    0xf8,0x5f,0xab,0xf1,0x1b,0x42,0x81,0xd6,0xbe,0x44,0x29,0xa6,0x57,0xb9,0xaf,0xf2,
    0xd4,0x75,0x66,0xbb,0x68,0x9f,0x50,0x02,0x01,0x3c,0x7f,0x8d,0x1a,0x88,0xbd,0xac,
    0xf7,0xe4,0x79,0x96,0xa2,0xfc,0x6d,0xb2,0x6b,0x03,0xe1,0x2e,0x7d,0x14,0x95,0x1d
};

/* ------------------------------------------------------------------ */
/* GF(2^8) multiplication by 2 with polynomial                          */
/*   z^8 + z^4 + z^3 + z^2 + 1  (0x11d).                              */
/* This is the exact field multiply-by-z used by CLEFIA; the rotate +  */
/* 0x0e reduction is algebraically identical to (x<<1) ^ 0x1d.         */
/* ------------------------------------------------------------------ */
static uint8_t clefia_mul2(uint8_t x)
{
    if (x & 0x80U) x ^= 0x0eU;
    return (uint8_t)((x << 1) | (x >> 7));
}
static uint8_t clefia_mul4(uint8_t x) { return clefia_mul2(clefia_mul2(x)); }
static uint8_t clefia_mul6(uint8_t x) { return clefia_mul2(x) ^ clefia_mul4(x); }
static uint8_t clefia_mul8(uint8_t x) { return clefia_mul2(clefia_mul4(x)); }
static uint8_t clefia_mulA(uint8_t x) { return clefia_mul2(x) ^ clefia_mul8(x); }

/* ------------------------------------------------------------------ */
/* Diffusion M0 / M1 (RFC 6114 Section 4.4)                           */
/* ------------------------------------------------------------------ */
static void m0(uint8_t y[4], const uint8_t z[4])
{
    y[0] = (uint8_t)(z[0]            ^ clefia_mul2(z[1]) ^ clefia_mul4(z[2]) ^ clefia_mul6(z[3]));
    y[1] = (uint8_t)(clefia_mul2(z[0]) ^ z[1]            ^ clefia_mul6(z[2]) ^ clefia_mul4(z[3]));
    y[2] = (uint8_t)(clefia_mul4(z[0]) ^ clefia_mul6(z[1]) ^ z[2]            ^ clefia_mul2(z[3]));
    y[3] = (uint8_t)(clefia_mul6(z[0]) ^ clefia_mul4(z[1]) ^ clefia_mul2(z[2]) ^ z[3]);
}
static void m1(uint8_t y[4], const uint8_t z[4])
{
    y[0] = (uint8_t)(z[0]            ^ clefia_mul8(z[1]) ^ clefia_mul2(z[2]) ^ clefia_mulA(z[3]));
    y[1] = (uint8_t)(clefia_mul8(z[0]) ^ z[1]            ^ clefia_mulA(z[2]) ^ clefia_mul2(z[3]));
    y[2] = (uint8_t)(clefia_mul2(z[0]) ^ clefia_mulA(z[1]) ^ z[2]            ^ clefia_mul8(z[3]));
    y[3] = (uint8_t)(clefia_mulA(z[0]) ^ clefia_mul2(z[1]) ^ clefia_mul8(z[2]) ^ z[3]);
}

/* ------------------------------------------------------------------ */
/* F-functions. Process an 8-byte chunk (T0,T1) or (T2,T3): copy the   */
/* first 4 bytes untouched, XOR F0/F1 of (rk, first 4 bytes) into the  */
/* second 4 bytes.                                                     */
/* ------------------------------------------------------------------ */
static void f0_xor(uint8_t *dst, const uint8_t *src, const uint8_t *rk)
{
    uint8_t t[4], z[4], y[4];
    int j;
    for (j = 0; j < 4; j++) t[j] = (uint8_t)(src[j] ^ rk[j]);
    z[0] = S0[t[0]]; z[1] = S1[t[1]]; z[2] = S0[t[2]]; z[3] = S1[t[3]];
    m0(y, z);
    for (j = 0; j < 4; j++) dst[j] = src[j];
    for (j = 0; j < 4; j++) dst[4 + j] = (uint8_t)(src[4 + j] ^ y[j]);
}
static void f1_xor(uint8_t *dst, const uint8_t *src, const uint8_t *rk)
{
    uint8_t t[4], z[4], y[4];
    int j;
    for (j = 0; j < 4; j++) t[j] = (uint8_t)(src[j] ^ rk[j]);
    z[0] = S1[t[0]]; z[1] = S0[t[1]]; z[2] = S1[t[2]]; z[3] = S0[t[3]];
    m1(y, z);
    for (j = 0; j < 4; j++) dst[j] = src[j];
    for (j = 0; j < 4; j++) dst[4 + j] = (uint8_t)(src[4 + j] ^ y[j]);
}

static void byte_xor(uint8_t *dst, const uint8_t *a, const uint8_t *b, int n)
{
    int i;
    for (i = 0; i < n; i++) dst[i] = (uint8_t)(a[i] ^ b[i]);
}

/* ------------------------------------------------------------------ */
/* GFN_{4,r} and GFN_{4,r}^{-1} (RFC 6114 Section 4.1)                 */
/* ------------------------------------------------------------------ */
static void gfn4(uint8_t *y, const uint8_t *x, const uint8_t *rk, int r)
{
    uint8_t fin[16], fout[16];
    memcpy(fin, x, 16);
    while (r-- > 0) {
        f0_xor(fout + 0, fin + 0, rk + 0);
        f1_xor(fout + 8, fin + 8, rk + 4);
        rk += 8;
        if (r) {
            memcpy(fin + 0, fout + 4, 12);
            memcpy(fin + 12, fout + 0, 4);
        }
    }
    memcpy(y, fout, 16);
}
static void gfn4inv(uint8_t *y, const uint8_t *x, const uint8_t *rk, int r)
{
    uint8_t fin[16], fout[16];
    rk += (r - 1) * 8;
    memcpy(fin, x, 16);
    while (r-- > 0) {
        f0_xor(fout + 0, fin + 0, rk + 0);
        f1_xor(fout + 8, fin + 8, rk + 4);
        rk -= 8;
        if (r) {
            memcpy(fin + 0, fout + 12, 4);
            memcpy(fin + 4, fout + 0, 12);
        }
    }
    memcpy(y, fout, 16);
}

/* ------------------------------------------------------------------ */
/* GFN_{8,r} (RFC 6114 Section 4.1) - used by 192/256-bit key schedule */
/* ------------------------------------------------------------------ */
static void gfn8(uint8_t *y, const uint8_t *x, const uint8_t *rk, int r)
{
    uint8_t fin[32], fout[32];
    memcpy(fin, x, 32);
    while (r-- > 0) {
        f0_xor(fout + 0,  fin + 0,  rk + 0);
        f1_xor(fout + 8,  fin + 8,  rk + 4);
        f0_xor(fout + 16, fin + 16, rk + 8);
        f1_xor(fout + 24, fin + 24, rk + 12);
        rk += 16;
        if (r) {
            memcpy(fin + 0,  fout + 4, 28);
            memcpy(fin + 28, fout + 0, 4);
        }
    }
    memcpy(y, fout, 32);
}

/* ------------------------------------------------------------------ */
/* DoubleSwap (RFC 6114 Section 6.1) on a 128-bit value (16 bytes)     */
/* ------------------------------------------------------------------ */
static void double_swap(uint8_t *lk)
{
    uint8_t t[16];
    t[0]  = (uint8_t)((lk[0] << 7) | (lk[1]  >> 1));
    t[1]  = (uint8_t)((lk[1] << 7) | (lk[2]  >> 1));
    t[2]  = (uint8_t)((lk[2] << 7) | (lk[3]  >> 1));
    t[3]  = (uint8_t)((lk[3] << 7) | (lk[4]  >> 1));
    t[4]  = (uint8_t)((lk[4] << 7) | (lk[5]  >> 1));
    t[5]  = (uint8_t)((lk[5] << 7) | (lk[6]  >> 1));
    t[6]  = (uint8_t)((lk[6] << 7) | (lk[7]  >> 1));
    t[7]  = (uint8_t)((lk[7] << 7) | (lk[15] & 0x7fU));
    t[8]  = (uint8_t)((lk[8]  >> 7) | (lk[0]  & 0xfeU));
    t[9]  = (uint8_t)((lk[9]  >> 7) | (lk[8]  << 1));
    t[10] = (uint8_t)((lk[10] >> 7) | (lk[9]  << 1));
    t[11] = (uint8_t)((lk[11] >> 7) | (lk[10] << 1));
    t[12] = (uint8_t)((lk[12] >> 7) | (lk[11] << 1));
    t[13] = (uint8_t)((lk[13] >> 7) | (lk[12] << 1));
    t[14] = (uint8_t)((lk[14] >> 7) | (lk[13] << 1));
    t[15] = (uint8_t)((lk[15] >> 7) | (lk[14] << 1));
    memcpy(lk, t, 16);
}

/* ------------------------------------------------------------------ */
/* GF(2^16) multiply. Defining polynomial                              */
/*   P(x) = z^16 + z^15 + z^13 + z^11 + z^5 + z^4 + 1  (= 0x1a831)      */
/* The XOR-reduction constant is P(x) with the x^16 term dropped:       */
/*   0x0a831 (bits 15,13,11,5,4,0).                                    */
/* ------------------------------------------------------------------ */
static uint16_t gf16_mul(uint16_t a, uint16_t b)
{
    uint16_t p = 0;
    int i;
    for (i = 0; i < 16; i++) {
        if (b & 1) p ^= a;
        b >>= 1;
        if (a & 0x8000U) a = (uint16_t)(((a << 1) & 0xffffU) ^ 0x0a831U);
        else             a = (uint16_t)((a << 1) & 0xffffU);
    }
    return p;
}
#define CLEFIA_GF16_INV2 0xd418U   /* multiplicative inverse of z in GF(2^16) */

static uint16_t rotl16(uint16_t v, int n) { return (uint16_t)(((v << n) | (v >> (16 - n))) & 0xffffU); }
static void store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)((v >> 24) & 0xffU);
    p[1] = (uint8_t)((v >> 16) & 0xffU);
    p[2] = (uint8_t)((v >> 8)  & 0xffU);
    p[3] = (uint8_t)( v        & 0xffU);
}

/* Generate constant values CON_k[i] (RFC 6114 Section 6.6).
 * Writes 4 bytes per entry, 2*lk entries total, big-endian. */
static void con_set(uint8_t *con, uint16_t iv, int lk)
{
    uint16_t t = iv;
    int i;
    for (i = 0; i < lk; i++) {
        uint16_t x, y;
        uint32_t c0, c1;
        /* CON[2i]   = ((T ^ P) << 16) | rotl16(~T, 1)        ; P = 0xb7e1 */
        x = (uint16_t)(t ^ 0xb7e1U);
        y = rotl16((uint16_t)(~t), 1);
        c0 = ((uint32_t)x << 16) | y;
        /* CON[2i+1] = ((~T ^ Q) << 16) | rotl16(T, 8)        ; Q = 0x243f */
        x = (uint16_t)((~t) ^ 0x243fU);
        y = rotl16(t, 8);
        c1 = ((uint32_t)x << 16) | y;
        store_be32(con + (2 * i) * 4,     c0);
        store_be32(con + (2 * i + 1) * 4, c1);
        t = gf16_mul(t, CLEFIA_GF16_INV2);   /* T <- T * z^{-1} */
    }
}

/* ------------------------------------------------------------------ */
/* Key schedules (RFC 6114 Section 6)                                  */
/* ------------------------------------------------------------------ */
static void key_set128(clefia_ctx *c, const uint8_t *k)
{
    uint8_t con[4 * 60];
    uint8_t lk[16];
    uint8_t *rk = c->ek + 8;
    int i;
    con_set(con, 0x428aU, 30);                 /* CON_128 (60 entries) */
    gfn4(lk, k, con, 12);                      /* L = GFN_{4,12}(K)   */
    memcpy(c->ek + 0, k, 8);                   /* WK0 || WK1 = K      */
    for (i = 0; i < 9; i++) {
        uint8_t tmp[16];
        byte_xor(tmp, lk, con + (i * 4 + 24) * 4, 16);
        if (i % 2) byte_xor(tmp, tmp, k, 16);  /* odd i: T ^= K       */
        memcpy(rk, tmp, 16);
        rk += 16;
        double_swap(lk);
    }
    memcpy(c->ek + 8 + 36 * 4, k + 8, 8);      /* WK2 || WK3 = K[1]   */
}

static void key_set192(clefia_ctx *c, const uint8_t *k)
{
    uint8_t skey256[32];
    uint8_t con[4 * 84];
    uint8_t lk[32];
    uint8_t *rk = c->ek + 8;
    int i;
    memcpy(skey256, k, 24);
    for (i = 0; i < 8; i++) skey256[24 + i] = (uint8_t)(~k[i]); /* KR = K4|K5|~K0|~K1 */
    con_set(con, 0x7137U, 42);                 /* CON_192 (84 entries) */
    gfn8(lk, skey256, con, 10);                /* LL | LR             */
    byte_xor(c->ek + 0, skey256 + 0, skey256 + 16, 8);  /* WK0||WK1 = KL^KR */
    for (i = 0; i < 11; i++) {
        uint8_t tmp[16];
        if ((i / 2) % 2) {
            byte_xor(tmp, lk + 16, con + (i * 4 + 40) * 4, 16); /* LR */
            if (i % 2) byte_xor(tmp, tmp, skey256 + 0, 16);     /* ^ KL */
            double_swap(lk + 16);
        } else {
            byte_xor(tmp, lk + 0, con + (i * 4 + 40) * 4, 16);  /* LL */
            if (i % 2) byte_xor(tmp, tmp, skey256 + 16, 16);    /* ^ KR */
            double_swap(lk + 0);
        }
        memcpy(rk, tmp, 16);
        rk += 16;
    }
    byte_xor(c->ek + 8 + 44 * 4, skey256 + 8, skey256 + 24, 8); /* WK2||WK3 */
}

static void key_set256(clefia_ctx *c, const uint8_t *k)
{
    uint8_t con[4 * 92];
    uint8_t lk[32];
    uint8_t *rk = c->ek + 8;
    int i;
    con_set(con, 0xb5c0U, 46);                 /* CON_256 (92 entries) */
    gfn8(lk, k, con, 10);                      /* LL | LR             */
    byte_xor(c->ek + 0, k + 0, k + 16, 8);     /* WK0||WK1 = KL^KR */
    for (i = 0; i < 13; i++) {
        uint8_t tmp[16];
        if ((i / 2) % 2) {
            byte_xor(tmp, lk + 16, con + (i * 4 + 40) * 4, 16); /* LR */
            if (i % 2) byte_xor(tmp, tmp, k + 0, 16);           /* ^ KL */
            double_swap(lk + 16);
        } else {
            byte_xor(tmp, lk + 0, con + (i * 4 + 40) * 4, 16);  /* LL */
            if (i % 2) byte_xor(tmp, tmp, k + 16, 16);          /* ^ KR */
            double_swap(lk + 0);
        }
        memcpy(rk, tmp, 16);
        rk += 16;
    }
    byte_xor(c->ek + 8 + 52 * 4, k + 8, k + 24, 8); /* WK2||WK3 */
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */
clefia_status clefia_set_key(clefia_ctx *ctx, const uint8_t *key, size_t key_len)
{
    if (key_len == 16)      { ctx->rounds = 18; ctx->key_bits = 128; }
    else if (key_len == 24) { ctx->rounds = 22; ctx->key_bits = 192; }
    else if (key_len == 32) { ctx->rounds = 26; ctx->key_bits = 256; }
    else return CLEFIA_INVALID_KEYLEN;

    memset(ctx->ek, 0, sizeof(ctx->ek));
    if (key_len == 16)      key_set128(ctx, key);
    else if (key_len == 24) key_set192(ctx, key);
    else                    key_set256(ctx, key);
    return CLEFIA_SUCCESS;
}

void clefia_encrypt_block(const clefia_ctx *ctx,
                          const uint8_t in[CLEFIA_BLOCK_SIZE],
                          uint8_t out[CLEFIA_BLOCK_SIZE])
{
    uint8_t rin[16], rout[16];
    memcpy(rin, in, 16);
    byte_xor(rin + 4,  rin + 4,  ctx->ek + 0, 4);            /* WK0 */
    byte_xor(rin + 12, rin + 12, ctx->ek + 4, 4);            /* WK1 */
    gfn4(rout, rin, ctx->ek + 8, ctx->rounds);
    memcpy(out, rout, 16);
    byte_xor(out + 4,  out + 4,  ctx->ek + 8 + ctx->rounds * 8 + 0, 4); /* WK2 */
    byte_xor(out + 12, out + 12, ctx->ek + 8 + ctx->rounds * 8 + 4, 4); /* WK3 */
}

void clefia_decrypt_block(const clefia_ctx *ctx,
                          const uint8_t in[CLEFIA_BLOCK_SIZE],
                          uint8_t out[CLEFIA_BLOCK_SIZE])
{
    uint8_t rin[16], rout[16];
    memcpy(rin, in, 16);
    byte_xor(rin + 4,  rin + 4,  ctx->ek + 8 + ctx->rounds * 8 + 0, 4);  /* WK2 */
    byte_xor(rin + 12, rin + 12, ctx->ek + 8 + ctx->rounds * 8 + 4, 4);  /* WK3 */
    gfn4inv(rout, rin, ctx->ek + 8, ctx->rounds);
    memcpy(out, rout, 16);
    byte_xor(out + 4,  out + 4,  ctx->ek + 0, 4);            /* WK0 */
    byte_xor(out + 12, out + 12, ctx->ek + 4, 4);            /* WK1 */
}

clefia_status clefia_ecb_encrypt(const clefia_ctx *ctx,
                                 const uint8_t *in, size_t len, uint8_t *out)
{
    size_t i;
    if (ctx->rounds == 0) return CLEFIA_INVALID_KEYLEN;
    if (len % CLEFIA_BLOCK_SIZE) return CLEFIA_INVALID_KEYLEN;
    for (i = 0; i < len; i += CLEFIA_BLOCK_SIZE)
        clefia_encrypt_block(ctx, in + i, out + i);
    return CLEFIA_SUCCESS;
}
clefia_status clefia_ecb_decrypt(const clefia_ctx *ctx,
                                 const uint8_t *in, size_t len, uint8_t *out)
{
    size_t i;
    if (ctx->rounds == 0) return CLEFIA_INVALID_KEYLEN;
    if (len % CLEFIA_BLOCK_SIZE) return CLEFIA_INVALID_KEYLEN;
    for (i = 0; i < len; i += CLEFIA_BLOCK_SIZE)
        clefia_decrypt_block(ctx, in + i, out + i);
    return CLEFIA_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Self-test against RFC 6114 Appendix A vectors                       */
/* ------------------------------------------------------------------ */
int clefia_selftest(void)
{
    static const struct {
        int   key_len;
        uint8_t key[32];
        uint8_t pt[16];
        uint8_t ct[16];
    } vec[3] = {
        { 16,
          {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00},
          {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
          {0xde,0x2b,0xf2,0xfd,0x9b,0x74,0xaa,0xcd,0xf1,0x29,0x85,0x55,0x45,0x94,0x94,0xfd} },
        { 24,
          {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
           0xf0,0xe0,0xd0,0xc0,0xb0,0xa0,0x90,0x80},
          {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
          {0xe2,0x48,0x2f,0x64,0x9f,0x02,0x8d,0xc4,0x80,0xdd,0xa1,0x84,0xfd,0xe1,0x81,0xad} },
        { 32,
          {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00,
           0xf0,0xe0,0xd0,0xc0,0xb0,0xa0,0x90,0x80,0x70,0x60,0x50,0x40,0x30,0x20,0x10,0x00},
          {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f},
          {0xa1,0x39,0x78,0x14,0x28,0x9d,0xe8,0x0c,0x10,0xda,0x46,0xd1,0xfa,0x48,0xb3,0x8a} }
    };
    int fails = 0, v;
    for (v = 0; v < 3; v++) {
        clefia_ctx c;
        uint8_t out[16], back[16];
        int i, ok = 1;
        if (clefia_set_key(&c, vec[v].key, vec[v].key_len) != CLEFIA_SUCCESS) { fails |= (1 << v); continue; }
        clefia_encrypt_block(&c, vec[v].pt, out);
        for (i = 0; i < 16; i++) if (out[i] != vec[v].ct[i]) ok = 0;
        clefia_decrypt_block(&c, out, back);
        for (i = 0; i < 16; i++) if (back[i] != vec[v].pt[i]) ok = 0;
        if (!ok) fails |= (1 << v);
    }
    return fails;
}
