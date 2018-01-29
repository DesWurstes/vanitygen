#include <vector>
#include <cstdint>
#include <string>
#include <iostream>
/*The MIT License (MIT)

Copyright (c) 2009-2015 Bitcoin Developers
Copyright (c) 2009-2017 The Bitcoin Core developers
Copyright (c) 2017 The Bitcoin ABC developers

Permission is hereby granted, free of unsigned charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.*/
// Copyright (c) 2017 Pieter Wuille
// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * The cashaddr unsigned character set for encoding.
 */
const char *CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/**
 * Concatenate two byte arrays.
 */
std::vector<unsigned char> Cat(std::vector<unsigned char> x, const std::vector<unsigned char> &y) {
    x.insert(x.end(), y.begin(), y.end());
    return x;
}

uint64_t PolyMod(const std::vector<unsigned char> &v) {
    uint64_t c = 1;
    for (unsigned char d : v) {
        unsigned char c0 = c >> 35;
        c = ((c & 0x07ffffffff) << 5) ^ d;
        if (c0 & 0x01) {
            c ^= 0x98f2bc8e61;
        }

        if (c0 & 0x02) {
            c ^= 0x79b76d99e2;
        }

        if (c0 & 0x04) {
            c ^= 0xf33e5fb3c4;
        }

        if (c0 & 0x08) {
            c ^= 0xae2eabe2a8;
        }

        if (c0 & 0x10) {
            c ^= 0x1e4f43e470;
        }
    }
    return c ^ 1;
}

template <int frombits, int tobits, bool pad, typename O, typename I>
bool ConvertBits(O &out, I it, I end) {
    size_t acc = 0;
    size_t bits = 0;
    constexpr size_t maxv = (1 << tobits) - 1;
    constexpr size_t max_acc = (1 << (frombits + tobits - 1)) - 1;
    while (it != end) {
        acc = ((acc << frombits) | *it) & max_acc;
        bits += frombits;
        while (bits >= tobits) {
            bits -= tobits;
            out.push_back((acc >> bits) & maxv);
        }
        ++it;
    }
    if (!pad && bits) {
        return false;
    }
    if (pad && bits) {
        out.push_back((acc << (tobits - bits)) & maxv);
    }
    return true;
}

std::vector<unsigned char> PackAddrData(const std::vector<unsigned char> &payload, unsigned char type) {
    unsigned char version_byte(type << 3);
    std::vector<unsigned char> data = {version_byte};
    data.insert(data.end(), payload.begin(), payload.end());
    std::vector<unsigned char> converted;
    converted.reserve(((20 + 1) * 8 + 4) / 5);
    ConvertBits<8, 5, true>(converted, std::begin(data), std::end(data));
    return converted;
}

std::vector<unsigned char> CreateChecksum(const int isMainNet, const std::vector<unsigned char> &payload) {
    std::vector<unsigned char> prefix;
    if (isMainNet != 0) {
        prefix = {2, 9, 20, 3, 15, 9, 14, 3, 1, 19, 8, 0};
    } else {
        prefix = {2, 3, 8, 20, 5, 19, 20, 0};
    }
    std::vector<unsigned char> enc = Cat(prefix, payload);
    enc.resize(enc.size() + 8);
    uint64_t mod = PolyMod(enc);
    std::vector<unsigned char> ret(8);
    for (size_t i = 0; i < 8; ++i) {
        ret[i] = (mod >> (5 * (7 - i))) & 0x1f;
    }
    return ret;
}

const char* CashAddrEncode(const int isMainNet, /*const std::vector<unsigned char> &payload*//*unsigned char payload[20]*/unsigned char* payload, unsigned int type) {
    std::vector<unsigned char> payloadPreConverted(payload, payload+20);
    std::vector<unsigned char> convertedPayload = PackAddrData(payloadPreConverted, type);
    std::vector<unsigned char> checksum = CreateChecksum(isMainNet, convertedPayload);
    std::vector<unsigned char> combined = Cat(convertedPayload, checksum);
    std::string ret = (isMainNet ? "bitcoincash:" : "bchtest:");
    ret.reserve(ret.size() + combined.size());
    for (unsigned char c : combined) {
        ret += CHARSET[c];
    }
    return ret.c_str();
    /*char characters[isMainNet != 0 ? (54 + 1) : (50 + 1)] = isMainNet != 0 ? "bitcoincash:" : "bchtest";
    characters[sizeof(characters) - 1] =
    for (unsigned int i = sizeof(characters) - 2; i >)
    for (unsigned char c : combined) {
        ret += CHARSET[c];
    }
    free(i)*/
}
