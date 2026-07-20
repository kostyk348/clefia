/*
 * test_clefia.c - CLEFIA self-test driver.
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include "clefia.h"

int main(void)
{
    int r = clefia_selftest();
    if (r == 0) {
        printf("CLEFIA self-test: PASS (RFC 6114 vectors, 128/192/256-bit)\n");
        return 0;
    }
    printf("CLEFIA self-test: FAIL (mask=0x%02x)\n", r);
    return 1;
}
