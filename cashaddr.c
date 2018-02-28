#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Fastest CashAddr encoding library ever. EVER!
/*
Copyright (c) 2018 DesWurstes

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

/* Copyright (c) 2017 Pieter Wuille
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/**
 * The cashaddr unsigned character set for encoding.
 */
const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const signed char CHARSET_REV[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 10, 17, 21, 20, 26, 30, 7,
    5,  -1, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22,
    31, 27, 19, -1, 1,  0,  3,  16, 11, 28, 12, 14, 6,  4,  2,  -1, -1, -1, -1,
    -1, -1, 29, -1, 24, 13, 25, 9,  8,  23, -1, 18, 22, 31, 27, 19, -1, 1,  0,
    3, 16, 11, 28, 12, 14, 6, 4, 2, -1, -1, -1, -1, -1};

static void convertBits8to5(char* out, const uint8_t firstByte, const uint8_t* in) {
    uint32_t val = firstByte;
    int bits = 0;
    int outlen = 0;
    int inlen = 20;
    bits = 3;
    out[outlen++] = (val >> bits) & 0x1f;
    while (inlen--) {
        val = (val << 8) | *(in++);
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[outlen++] = (val >> bits) & 0x1f;
        }
    }
    //if (bits) {
    out[outlen] = (val << (5 - bits)) & 0x1f;
    //}
}

uint64_t PolyMod(const char *input, uint64_t startValue = 1) {
    for (unsigned int i = 0; i < 42; i++) {
      uint64_t c0 = startValue >> 35;
      startValue = ((startValue & 0x07ffffffff) << 5) ^ (uint64_t) (input[i]);
      if (c0 & 0x01) {
          startValue ^= 0x98f2bc8e61;
      }
      if (c0 & 0x02) {
          startValue ^= 0x79b76d99e2;
      }
      if (c0 & 0x04) {
          startValue ^= 0xf33e5fb3c4;
      }
      if (c0 & 0x08) {
          startValue ^= 0xae2eabe2a8;
      }
      if (c0 & 0x10) {
          startValue ^= 0x1e4f43e470;
      }
    }
    return startValue ^ 1;
}


void CreateChecksum(const int isTestNet, const char *payload, char *result) {
    // https://play.golang.org/p/sM_CE4AQ7Vp
    uint64_t mod;
    if (isTestNet == 0) {
        mod = PolyMod(payload, 1058337025301);
    } else {
        mod = PolyMod(payload, 584719417569);
    }
    for (unsigned int i = 0; i < 8; ++i) {
        result[i] = (mod >> (5 * (7 - i))) & 0x1f;
    }
}

char* CashAddrEncode(const int isTestNet, const unsigned char* payload, const unsigned int type, const unsigned int withPrefix) {
    char convertedPayload[43];
    convertBits8to5(convertedPayload, type << 3, payload);
    CreateChecksum(isTestNet, convertedPayload, convertedPayload + 34);
    char *ret = (char *) malloc(sizeof(char) * 55);
    unsigned int i = 0;
    if (withPrefix) {
      if (isTestNet) {
        strcpy(ret, "bchtest:");
        i = 8;
        ret[50] = '\0';
      } else {
        strcpy(ret, "bitcoincash:");
        i = 12;
        ret[54] = '\0';
      }
    } else {
      ret[42] = '\0';
    }
    for (unsigned int k = 42 + i, z = i; i < k; i++) {
      ret[i] = CHARSET[(int) convertedPayload[i-z]];
    }
    return ret;
}
