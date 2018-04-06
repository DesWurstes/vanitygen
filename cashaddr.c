#include <stdint.h>

#include "cashaddr.h"

// Fastest CashAddr encoding library ever. EVER!
/*
 * Copyright (c) 2018 DesWurstes
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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

const char * CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static void convertBits8to5(char* out, const uint8_t firstByte, const uint8_t* in) {
    uint32_t val = (uint32_t) firstByte;
    int bits = 3;
    int outlen = 1;
    unsigned int inlen = 20;
    out[0] = (val >> bits) & 0x1f;
    while (inlen--) {
        val = (val << 8) | *(in++);
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[outlen++] = (val >> bits) & 0x1f;
        }
    }
    out[outlen] = (val << (5 - bits)) & 0x1f;
}

// startValue should be 1 if the prefix is a part of the input.
static uint64_t PolyMod(const char *input, uint64_t startValue) {
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


static inline void CreateChecksum(const int isTestNet, const char *payload,
  char * const result) {
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

void CashAddrEncode(const int isTestNet, const unsigned char* payload,
  const unsigned int type, const unsigned int withPrefix, char * const output) {
    unsigned int i = 0;
    if (withPrefix) {
      output[0] = 'b';
      if (isTestNet) {
        output[1] = 'c';
        output[2] = 'h';
        output[3] = 't';
        output[4] = 'e';
        output[5] = 's';
        output[6] = 't';
        output[7] = ':';
        i = 8;
        output[50] = '\0';
      } else {
        output[1] = 'i';
        output[2] = 't';
        output[3] = 'c';
        output[4] = 'o';
        output[5] = 'i';
        output[6] = 'n';
        output[7] = 'c';
        output[8] = 'a';
        output[9] = 's';
        output[10] = 'h';
        output[11] = ':';
        i = 12;
        output[54] = '\0';
      }
    } else {
      output[42] = '\0';
    }
    char *data = output + i;
    char *checksum = data + 34;
    // https://stackoverflow.com/a/17444554
    checksum[0] = 0;
    checksum[1] = 0;
    checksum[2] = 0;
    checksum[3] = 0;
    checksum[4] = 0;
    checksum[5] = 0;
    checksum[6] = 0;
    checksum[7] = 0;
    convertBits8to5(data, type << 3, payload);
    CreateChecksum(isTestNet, data, checksum);
    for (checksum += 8; data < checksum; data++) {
      *data = CHARSET[(int) (*data)];
    }
}
