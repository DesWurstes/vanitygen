/*
 * Vanitygen, vanity bitcoin address generator
 * Copyright (C) 2011 <samr7@cs.washington.edu>
 *
 * Vanitygen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * Vanitygen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Vanitygen.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __VG_UTIL_H__
#define __VG_UTIL_H__

#include <stdint.h>
#include <stdio.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <vector>
#include "cashaddr.h"

void fdumphex(FILE *fp, const unsigned char *src, size_t len);
void fdumpbn(FILE *fp, const BIGNUM *bn);
void dumphex(const unsigned char *src, size_t len);
void dumpbn(const BIGNUM *bn);

void vg_b58_encode_check(void *buf, size_t len, char *result);
int vg_b58_decode_check(const char *input, void *buf, size_t len);

void vg_encode_compressed_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
			      int testnet, char *result);
void vg_encode_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
			      int testnet, char *result);
void vg_encode_script_address(const EC_POINT *ppoint,
				     const EC_GROUP *pgroup,
				     int testnet, char *result);
void vg_encode_privkey_compressed(const EC_KEY *pkey, int addrtype, char *result);
void vg_encode_privkey(const EC_KEY *pkey, int addrtype, char *result);
int vg_set_privkey(const BIGNUM *bnpriv, EC_KEY *pkey);
int vg_decode_privkey(const char *b58encoded,
			     EC_KEY *pkey, int *addrtype);

int vg_protect_encode_privkey(char *out,
				     const EC_KEY *pkey, int keytype,
				     int parameter_group,
				     const char *pass);
int vg_protect_decode_privkey(EC_KEY *pkey, int *keytype,
				     const char *encoded, const char *pass);

int vg_pkcs8_encode_privkey(char *out, int outlen,
				   const EC_KEY *pkey,
				   const char *pass);
int vg_pkcs8_decode_privkey(EC_KEY *pkey, const char *pem_in,
				   const char *pass);

int vg_decode_privkey_any(EC_KEY *pkey, int *addrtype,
				 const char *input, const char *pass);

int vg_read_file(FILE *fp, char ***result, int *rescount);

#endif /* !defined (__VG_UTIL_H__) */
