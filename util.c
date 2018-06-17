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

#if defined(_WIN32)
#define _USE_MATH_DEFINES
#endif /* defined(_WIN32) */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

#include "cashaddr.h"
#include "pattern.h"
#include "util.h"

const char *vg_b58_alphabet =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// clang-format off
const signed char vg_b58_reverse_map[128] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
	-1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
	-1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
	47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1
};
// clang-format on

void fdumphex(FILE *fp, const unsigned char *src, size_t len) {
	size_t i;
	for (i = 0; i < len; i++) {
		fprintf(fp, "%02x", src[i]);
	}
	printf("\n");
}

void fdumpbn(FILE *fp, const BIGNUM *bn) {
	char *buf;
	buf = BN_bn2hex(bn);
	fprintf(fp, "%s\n", buf ? buf : "0");
	if (buf) OPENSSL_free(buf);
}

void dumphex(const unsigned char *src, size_t len) {
	fdumphex(stdout, src, len);
}

void dumpbn(const BIGNUM *bn) { fdumpbn(stdout, bn); }

/*
 * Key format encode/decode
 */

void vg_b58_encode_check(void *buf, size_t len, char *result) {
	unsigned char hash1[32];
	unsigned char hash2[32];

	int d, p;

	BN_CTX *bnctx;
	BIGNUM *bn, *bndiv, *bntmp;
	BIGNUM *bna = BN_new(), *bnb = BN_new(), *bnbase = BN_new(),
	       *bnrem = BN_new();
	unsigned char *binres;
	unsigned int brlen, zpfx;

	bnctx = BN_CTX_new();
	BN_set_word(bnbase, 58);

	bn = bna;
	bndiv = bnb;

	brlen = (2 * len) + 4;
	binres = (unsigned char *) malloc(brlen);
	memcpy(binres, buf, len);

	SHA256(binres, len, hash1);
	SHA256(hash1, sizeof(hash1), hash2);
	memcpy(&binres[len], hash2, 4);

	BN_bin2bn(binres, len + 4, bn);

	for (zpfx = 0; zpfx < (len + 4) && binres[zpfx] == 0; zpfx++)
		;

	p = brlen;
	while (!BN_is_zero(bn)) {
		BN_div(bndiv, bnrem, bn, bnbase, bnctx);
		bntmp = bn;
		bn = bndiv;
		bndiv = bntmp;
		d = BN_get_word(bnrem);
		binres[--p] = vg_b58_alphabet[d];
	}

	while (zpfx--) {
		binres[--p] = vg_b58_alphabet[0];
	}

	memcpy(result, &binres[p], brlen - p);
	result[brlen - p] = '\0';

	free(binres);
	BN_clear_free(bna);
	BN_clear_free(bnb);
	BN_clear_free(bnbase);
	BN_clear_free(bnrem);
	BN_CTX_free(bnctx);
}

#define skip_char(c) \
	(((c) == '\r') || ((c) == '\n') || ((c) == ' ') || ((c) == '\t'))

int vg_b58_decode_check(const char *input, void *buf, size_t len) {
	int i, l, c;
	unsigned char *xbuf = NULL;
	BIGNUM *bn = BN_new(), *bnw = BN_new(), *bnbase = BN_new();
	BN_CTX *bnctx;
	unsigned char hash1[32], hash2[32];
	int zpfx;
	int res = 0;

	BN_set_word(bnbase, 58);
	bnctx = BN_CTX_new();

	/* Build a bignum from the encoded value */
	l = strlen(input);
	for (i = 0; i < l; i++) {
		if (skip_char(input[i])) continue;
		c = vg_b58_reverse_map[(int) input[i]];
		if (c < 0) goto out;
		BN_clear(bnw);
		BN_set_word(bnw, c);
		BN_mul(bn, bn, bnbase, bnctx);
		BN_add(bn, bn, bnw);
	}

	/* Copy the bignum to a byte buffer */
	for (i = 0, zpfx = 0; input[i]; i++) {
		if (skip_char(input[i])) continue;
		if (input[i] != vg_b58_alphabet[0]) break;
		zpfx++;
	}
	c = BN_num_bytes(bn);
	l = zpfx + c;
	if (l < 5) goto out;
	xbuf = (unsigned char *) malloc(l);
	if (!xbuf) goto out;
	if (zpfx) memset(xbuf, 0, zpfx);
	if (c) BN_bn2bin(bn, xbuf + zpfx);

	/* Check the hash code */
	l -= 4;
	SHA256(xbuf, l, hash1);
	SHA256(hash1, sizeof(hash1), hash2);
	if (memcmp(hash2, xbuf + l, 4)) goto out;

	/* Buffer verified */
	if (len) {
		if (len > (unsigned) l) len = l;
		memcpy(buf, xbuf, len);
	}
	res = l;

out:
	if (xbuf) free(xbuf);
	BN_clear_free(bn);
	BN_clear_free(bnw);
	BN_clear_free(bnbase);
	BN_CTX_free(bnctx);
	return res;
}

void vg_encode_compressed_address(const EC_POINT *ppoint,
	const EC_GROUP *pgroup, int testnet, char *result) {
	unsigned char eckey_buf[128];
	unsigned char binres[20] = {};
	unsigned char hash1[32];

	EC_POINT_point2oct(pgroup, ppoint, POINT_CONVERSION_COMPRESSED,
		eckey_buf, sizeof(eckey_buf), NULL);
	SHA256(eckey_buf, 33, hash1);
	RIPEMD160(hash1, sizeof(hash1), binres);
	CashAddrEncode(testnet, binres, 0, 1, result);
}

void vg_encode_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
	int testnet, char *result) {
	unsigned char eckey_buf[128], *pend;
	unsigned char binres[20] = {};
	//	unsigned char binres[21] = {0,};
	unsigned char hash1[32];

	pend = eckey_buf;

	EC_POINT_point2oct(pgroup, ppoint, POINT_CONVERSION_UNCOMPRESSED,
		eckey_buf, sizeof(eckey_buf), NULL);
	pend = eckey_buf + 0x41;
	//	binres[0] = addrtype;
	SHA256(eckey_buf, pend - eckey_buf, hash1);
	//	RIPEMD160(hash1, sizeof(hash1), &binres[1]);
	RIPEMD160(hash1, sizeof(hash1), binres);
	CashAddrEncode(testnet, binres, 0, 1, result);
	//	vg_b58_encode_check(binres, sizeof(binres), result);
}

void vg_encode_script_address(const EC_POINT *ppoint, const EC_GROUP *pgroup,
	int testnet, char *result) {
	unsigned char script_buf[69];
	unsigned char *eckey_buf = script_buf + 2;
	//	unsigned char binres[21] = {0,};
	unsigned char binres[20] = {};
	unsigned char hash1[32];

	script_buf[0] = 0x51; // OP_1
	script_buf[1] = 0x41; // pubkey length
	// gap for pubkey
	script_buf[67] = 0x51; // OP_1
	script_buf[68] = 0xae; // OP_CHECKMULTISIG

	EC_POINT_point2oct(pgroup, ppoint, POINT_CONVERSION_UNCOMPRESSED,
		eckey_buf, 65, NULL);
	//	binres[0] = addrtype;
	SHA256(script_buf, 69, hash1);
	//	RIPEMD160(hash1, sizeof(hash1), &binres[1]);
	RIPEMD160(hash1, sizeof(hash1), binres);
	CashAddrEncode(testnet, binres, 1 << 3, 1, result);
	//	vg_b58_encode_check(binres, sizeof(binres), result);
}

void vg_encode_privkey_compressed(
	const EC_KEY *pkey, int addrtype, char *result) {
	unsigned char eckey_buf[128];
	const BIGNUM *bn;
	int nbytes;

	bn = EC_KEY_get0_private_key(pkey);

	eckey_buf[0] = addrtype;
	nbytes = BN_num_bytes(bn);
	assert(nbytes <= 32);
	if (nbytes < 32) memset(eckey_buf + 1, 0, 32 - nbytes);
	BN_bn2bin(bn, &eckey_buf[33 - nbytes]);
	eckey_buf[33] = 1;
	vg_b58_encode_check(eckey_buf, 34, result);
}

void vg_encode_privkey(const EC_KEY *pkey, int addrtype, char *result) {
	unsigned char eckey_buf[128];
	const BIGNUM *bn;
	int nbytes;

	bn = EC_KEY_get0_private_key(pkey);

	eckey_buf[0] = addrtype;
	nbytes = BN_num_bytes(bn);
	assert(nbytes <= 32);
	if (nbytes < 32) memset(eckey_buf + 1, 0, 32 - nbytes);
	BN_bn2bin(bn, &eckey_buf[33 - nbytes]);

	vg_b58_encode_check(eckey_buf, 33, result);
}

int vg_set_privkey(const BIGNUM *bnpriv, EC_KEY *pkey) {
	const EC_GROUP *pgroup;
	EC_POINT *ppnt;
	int res;

	pgroup = EC_KEY_get0_group(pkey);
	ppnt = EC_POINT_new(pgroup);

	res = (ppnt && EC_KEY_set_private_key(pkey, bnpriv) &&
		EC_POINT_mul(pgroup, ppnt, bnpriv, NULL, NULL, NULL) &&
		EC_KEY_set_public_key(pkey, ppnt));

	if (ppnt) EC_POINT_free(ppnt);

	if (!res) return 0;

	assert(EC_KEY_check_key(pkey));
	return 1;
}

int vg_decode_privkey(const char *b58encoded, EC_KEY *pkey, int *addrtype) {
	BIGNUM *bnpriv;
	unsigned char ecpriv[48];
	int res;

	res = vg_b58_decode_check(b58encoded, ecpriv, sizeof(ecpriv));
	if (res != 33) return 0;

	bnpriv = BN_new();
	BN_bin2bn(ecpriv + 1, res - 1, bnpriv);
	vg_set_privkey(bnpriv, pkey);
	BN_clear_free(bnpriv);
	*addrtype = ecpriv[0];
	return 1;
}

/*
 * Besides the bitcoin-adapted formats, we also support PKCS#8.
 */
int vg_pkcs8_encode_privkey(
	char *out, int outlen, const EC_KEY *pkey, const char *pass) {
	EC_KEY *pkey_copy = NULL;
	EVP_PKEY *evp_key = NULL;
	PKCS8_PRIV_KEY_INFO *pkcs8 = NULL;
	X509_SIG *pkcs8_enc = NULL;
	BUF_MEM *memptr;
	BIO *bio = NULL;
	int res = 0;

	pkey_copy = EC_KEY_dup(pkey);
	if (!pkey_copy) goto out;
	evp_key = EVP_PKEY_new();
	if (!evp_key || !EVP_PKEY_set1_EC_KEY(evp_key, pkey_copy)) goto out;
	pkcs8 = EVP_PKEY2PKCS8(evp_key);
	if (!pkcs8) goto out;

	bio = BIO_new(BIO_s_mem());
	if (!bio) goto out;

	if (!pass) {
		PEM_write_bio_PKCS8_PRIV_KEY_INFO(bio, pkcs8);
	} else {
		pkcs8_enc = PKCS8_encrypt(-1, EVP_aes_256_cbc(), pass,
			strlen(pass), NULL, 0, 4096, pkcs8);
		if (!pkcs8_enc) goto out;
		PEM_write_bio_PKCS8(bio, pkcs8_enc);
	}

	BIO_get_mem_ptr(bio, &memptr);
	res = memptr->length;
	if (res < outlen) {
		memcpy(out, memptr->data, res);
		out[res] = '\0';
	} else {
		memcpy(out, memptr->data, outlen - 1);
		out[outlen - 1] = '\0';
	}

out:
	if (bio) BIO_free(bio);
	if (pkey_copy) EC_KEY_free(pkey_copy);
	if (evp_key) EVP_PKEY_free(evp_key);
	if (pkcs8) PKCS8_PRIV_KEY_INFO_free(pkcs8);
	if (pkcs8_enc) X509_SIG_free(pkcs8_enc);
	return res;
}

inline static char decodeHex(char s) {
	switch (s) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'a': return 10;
	case 'b': return 11;
	case 'c': return 12;
	case 'd': return 13;
	case 'e': return 14;
	case 'f': return 15;
	default: return -1;
	}
}

int vg_read_range_file(
	FILE *fp, const char ***pat_list, int *pat_count, int *pat_alloc) {
	// newline + null character + extra
	char *buff = (char *) malloc((80 + 1 + 1 + 1) * sizeof(char));
	buff[82] = 0x01;
	while (1) {
		if (*pat_alloc == *pat_count) {
			*pat_list = (const char **) realloc(
				*pat_list, 2 * (*pat_alloc) * sizeof(char *));
			if (*pat_list == NULL) {
				fprintf(stderr, "Out of memory!\n");
				free(*pat_list);
				free(buff);
				return 0;
			}
			*pat_alloc *= 2;
		}
		if (fgets(buff, 80 + 1 + 1 + 1, (FILE *) fp) == NULL) {
			if (feof(fp)) break;
			fprintf(stderr,
				"Couldn't read range from input file! Error: %s\n",
				strerror(errno));
			fclose(fp);
			free(buff);
			return 0;
		}
		if (buff[82] != 0x01) {
			fprintf(stderr,
				"Line that starts with \"%.15s...\" is too long! (Corrupted range file)\n",
				buff);
			fclose(fp);
			free(buff);
			return 0;
		}
		char *buff2 = (char *) malloc(40 * sizeof(char));
		for (int i = 0; i < 80; i += 2) {
			buff2[i / 2] = decodeHex(buff[i]) * 16 +
				decodeHex(buff[i + 1]);
		}
		for (int i = 0; i < 40; i++) {
			if (buff2[i] == -1) {
				fprintf(stderr,
					"Non-lowercase-base16 character in line that starts with \"%.15s...\"\n",
					buff);
				free(buff);
				return 0;
			}
		}
		(*pat_list)[(*pat_count)++] = (const char *) buff2;
	}
	fclose(fp);
	free(buff);
	return 1;
}

/*
 * Pattern file reader
 * Absolutely disgusting, unable to free the pattern list when it's done
 */

int vg_read_file(FILE *fp, char ***result, int *rescount) {
	int ret = 1;

	char **patterns;
	char *buf = NULL, *obuf, *pat;
	const int blksize = 16 * 1024;
	int nalloc = 16;
	int npatterns = 0;
	int count, pos;

	patterns = (char **) malloc(sizeof(char *) * nalloc);
	count = 0;
	pos = 0;

	while (1) {
		obuf = buf;
		buf = (char *) malloc(blksize);
		if (!buf) {
			ret = 0;
			break;
		}
		if (pos < count) {
			memcpy(buf, &obuf[pos], count - pos);
		}
		pos = count - pos;
		count = fread(&buf[pos], 1, blksize - pos, fp);
		if (count < 0) {
			fprintf(stderr, "Error reading file: %s\n",
				strerror(errno));
			ret = 0;
		}
		if (count <= 0) break;
		count += pos;
		pat = buf;

		while (pos < count) {
			if ((buf[pos] == '\r') || (buf[pos] == '\n')) {
				buf[pos] = '\0';
				if (pat) {
					if (npatterns == nalloc) {
						nalloc *= 2;
						patterns = (char **) realloc(
							patterns,
							sizeof(char *) *
								nalloc);
					}
					patterns[npatterns] = pat;
					npatterns++;
					pat = NULL;
				}
			} else if (!pat) {
				pat = &buf[pos];
			}
			pos++;
		}

		pos = pat ? (pat - buf) : count;
	}

	*result = patterns;
	*rescount = npatterns;

	return ret;
}
