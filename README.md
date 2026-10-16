# CLEFIA — clean-room C implementation

[![Release](https://img.shields.io/github/v/release/kostyk348/clefia?sort=semver&color=blue)](https://github.com/kostyk348/clefia/releases)
[![License](https://img.shields.io/badge/license-Apache-2.0-green)](https://github.com/kostyk348/clefia/blob/master/LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/kostyk348/clefia?branch=master)](https://github.com/kostyk348/clefia/commits/master)

A dependency-free, portable **C99** implementation of **CLEFIA**, the
128-bit block cipher designed by Sony (2007) and standardized as
**ISO/IEC 29192-2** (lightweight cryptography). It supports **128 / 192 /
256-bit keys** and is API-compatible in spirit with AES.

This library is the companion to [`camellia`](https://github.com/kostyk348/camellia) —
part of a small series reviving solid Japanese cipher designs as clean,
auditable, drop-in C code.

> Written from the public IETF specification **RFC 6114** ("The 128-Bit
> Blockcipher CLEFIA"), not from Sony's reference code (whose license
> forbids redistribution/modification).

## Features

- 128/192/256-bit keys, full 18/22/26-round schedule.
- Single-file core (`src/clefia.c`), no external dependencies.
- Block encrypt/decrypt plus an ECB helper.
- Validated against the official RFC 6114 test vectors for all three key sizes.

## Build

```sh
make all        # builds static + shared lib, CLI, and runs the self-test
make test       # run RFC 6114 vector self-test
```

With CMake:
```sh
cmake -S . -B build && cmake --build build && ctest --test-dir build
```

## Usage

```c
#include "clefia.h"

uint8_t key[16] = {0xff,0xee,0xdd,0xcc,0xbb,0xaa,0x99,0x88,
                   0x77,0x66,0x55,0x44,0x33,0x22,0x11,0x00};
uint8_t pt[16]  = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                   0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
uint8_t ct[16];

clefia_ctx c;
clefia_set_key(&c, key, sizeof(key));
clefia_encrypt_block(&c, pt, ct);
/* ct == de 2b f2 fd 9b 74 aa cd f1 29 85 55 45 94 94 fd */
```

CLI:
```sh
./clefia-cli selftest
./clefia-cli ecb enc ffeeddccbbaa99887766554433221100 000102030405060708090a0b0c0d0e0f
```

## Algorithm notes

CLEFIA is a 4-branch generalized Feistel network with two 8-bit S-boxes
(S0, S1) and two 4×4 diffusion matrices (M0, M1). Its key schedule
reuses the same primitives (the "double-SPN" / Diffusion Switching
Mechanism design), which is what makes it compact in hardware. The spec
uses GF(2⁸) arithmetic (poly `0x11d`) for diffusion and GF(2¹⁶)
arithmetic (poly `0x1a831`) to derive the key-schedule constants.

## License

MIT — see [LICENSE](LICENSE).
