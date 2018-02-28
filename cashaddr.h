// Copyright (c) 2017 Pieter Wuille
// Copyright (c) 2017 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CASHADDR_H
#define CASHADDR_H

extern const char *CHARSET;

extern const signed char CHARSET_REV[128];

/**
 * Encode a cashaddr string.
 */
extern char* CashAddrEncode(const int isTestNet, const unsigned char* payload, const unsigned int type, const unsigned int withPrefix);
#endif
