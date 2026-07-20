/*
 * clefia-cli.c - tiny command-line tool for CLEFIA.
 *
 *   clefia-cli selftest
 *       run RFC 6114 test-vector self-test
 *   clefia-cli ecb <enc|dec> <keyhex> <hex>
 *       ECB-encrypt/decrypt a single hex block (16 bytes) with a hex key
 *       (32/48/64 hex chars for 128/192/256-bit keys)
 *
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "clefia.h"

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int parse_hex(const char *s, uint8_t *out, size_t max, size_t *len)
{
    size_t n = strlen(s), i;
    if (n % 2) return -1;
    *len = n / 2;
    if (*len > max) return -1;
    for (i = 0; i < *len; i++) {
        int hi = hexval(s[2*i]), lo = hexval(s[2*i+1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}
static void print_hex(const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    if (argc >= 2 && strcmp(argv[1], "selftest") == 0) {
        return clefia_selftest() ? 1 : 0;
    }
    if (argc == 5 && strcmp(argv[1], "ecb") == 0) {
        uint8_t key[32], blk[16], out[16];
        size_t klen, blen;
        clefia_ctx c;
        if (parse_hex(argv[3], key, sizeof(key), &klen) != 0 ||
            parse_hex(argv[4], blk, sizeof(blk), &blen) != 0) {
            fprintf(stderr, "bad hex input\n");
            return 1;
        }
        if (klen != 16 && klen != 24 && klen != 32) {
            fprintf(stderr, "key must be 128/192/256 bits (32/48/64 hex)\n");
            return 1;
        }
        if (blen != 16) {
            fprintf(stderr, "block must be 128 bits (32 hex)\n");
            return 1;
        }
        if (clefia_set_key(&c, key, klen) != CLEFIA_SUCCESS) {
            fprintf(stderr, "key setup failed\n");
            return 1;
        }
        if (strcmp(argv[2], "enc") == 0)      clefia_encrypt_block(&c, blk, out);
        else if (strcmp(argv[2], "dec") == 0) clefia_decrypt_block(&c, blk, out);
        else { fprintf(stderr, "use enc or dec\n"); return 1; }
        print_hex(out, 16);
        return 0;
    }
    fprintf(stderr,
        "usage:\n"
        "  %s selftest\n"
        "  %s ecb <enc|dec> <keyhex> <blockhex>\n",
        argv[0], argv[0]);
    return 1;
}
