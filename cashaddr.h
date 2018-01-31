// Copyright (c) 2017 Pieter Wuille
// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CASHADDR_H
#define CASHADDR_H
#include <cstdint>
#include <string>
#include <vector>
#include <iostream>

extern const char *CHARSET;

extern const signed char CHARSET_REV[256];

/**
 * Encode a cashaddr string. Returns the empty string in case of failure.
 */
extern const char* CashAddrEncode(const int isMainNet, const unsigned char *payload, const unsigned int type, const unsigned int withPrefix);
#endif
