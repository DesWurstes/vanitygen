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

// These are needed, causes problems
// on Windows. Either way, they'll be
// included, however, this way compiles
// on Windows.
#include <stdint.h>
#include <cstdint>

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#if defined(_WIN32) && !defined(HAVE_STRUCT_TIMESPEC)
#define HAVE_STRUCT_TIMESPEC
#endif
#include <pthread.h>

#ifndef SHA256_ASM
#define SHA256_ASM
#endif
#ifndef RMD160_ASM
#define RMD160_ASM
#endif

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

#include <hs/hs.h>

#include "pattern.h"
#include "util.h"
#include "avl.h"
#include "cashaddr.h"

/*
	* Common code for execution helper
	*/

EC_KEY * vg_exec_context_new_key(void) {
	return EC_KEY_new_by_curve_name(NID_secp256k1);
}

/*
	* Thread synchronization helpers
	*/

static pthread_mutex_t vg_thread_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t vg_thread_rdcond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t vg_thread_wrcond = PTHREAD_COND_INITIALIZER;
static pthread_cond_t vg_thread_upcond = PTHREAD_COND_INITIALIZER;

static void __vg_exec_context_yield(vg_exec_context_t * vxcp) {
	vxcp->vxc_lockmode = 0;
	while (vxcp->vxc_vc->vc_thread_excl) {
		if (vxcp->vxc_stop) {
			assert(vxcp->vxc_vc->vc_thread_excl);
			vxcp->vxc_stop = 0;
			pthread_cond_signal(&vg_thread_upcond);
		}
		pthread_cond_wait(&vg_thread_rdcond, &vg_thread_lock);
	}
	assert(!vxcp->vxc_stop);
	assert(!vxcp->vxc_lockmode);
	vxcp->vxc_lockmode = 1;
}

int vg_exec_context_upgrade_lock(vg_exec_context_t * vxcp) {
	vg_exec_context_t * tp;
	vg_context_t * vcp;

	if (vxcp->vxc_lockmode == 2)
		return 0;

	pthread_mutex_lock(&vg_thread_lock);

	assert(vxcp->vxc_lockmode == 1);
	vxcp->vxc_lockmode = 0;
	vcp = vxcp->vxc_vc;

	if (vcp->vc_thread_excl++) {
		assert(vxcp->vxc_stop);
		vxcp->vxc_stop = 0;
		pthread_cond_signal(&vg_thread_upcond);
		pthread_cond_wait(&vg_thread_wrcond, &vg_thread_lock);

		for (tp = vcp->vc_threads; tp != NULL; tp = tp->vxc_next) {
			assert(!tp->vxc_lockmode);
			assert(!tp->vxc_stop);
		}

	} else {
		for (tp = vcp->vc_threads; tp != NULL; tp = tp->vxc_next) {
			if (tp->vxc_lockmode) {
				assert(tp->vxc_lockmode != 2);
				tp->vxc_stop = 1;
			}
		}

		do {
			for (tp = vcp->vc_threads; tp != NULL; tp = tp->vxc_next) {
				if (tp->vxc_lockmode) {
					assert(tp->vxc_lockmode != 2);
					pthread_cond_wait(&vg_thread_upcond, &vg_thread_lock);
					break;
				}
			}
		} while (tp);
	}

	vxcp->vxc_lockmode = 2;
	pthread_mutex_unlock(&vg_thread_lock);
	return 1;
}

void vg_exec_context_downgrade_lock(vg_exec_context_t * vxcp) {
	pthread_mutex_lock(&vg_thread_lock);
	assert(vxcp->vxc_lockmode == 2);
	assert(!vxcp->vxc_stop);
	if (!--vxcp->vxc_vc->vc_thread_excl) {
		vxcp->vxc_lockmode = 1;
		pthread_cond_broadcast(&vg_thread_rdcond);
		pthread_mutex_unlock(&vg_thread_lock);
		return;
	}
	pthread_cond_signal(&vg_thread_wrcond);
	__vg_exec_context_yield(vxcp);
	pthread_mutex_unlock(&vg_thread_lock);
}

int vg_exec_context_init(vg_context_t * vcp, vg_exec_context_t * vxcp) {
	pthread_mutex_lock(&vg_thread_lock);

	memset(vxcp, 0, sizeof(*vxcp));

	vxcp->vxc_vc = vcp;

	vxcp->vxc_bntarg = BN_new();
	vxcp->vxc_bnbase = BN_new();
	vxcp->vxc_bntmp = BN_new();
	vxcp->vxc_bntmp2 = BN_new();

	BN_set_word(vxcp->vxc_bnbase, 32);

	vxcp->vxc_bnctx = BN_CTX_new();
	assert(vxcp->vxc_bnctx);
	vxcp->vxc_key = vg_exec_context_new_key();
	assert(vxcp->vxc_key);
	EC_KEY_precompute_mult(vxcp->vxc_key, vxcp->vxc_bnctx);

	vxcp->vxc_lockmode = 0;
	vxcp->vxc_stop = 0;

	vcp->vc_prep(vcp, vxcp);

	vxcp->vxc_next = vcp->vc_threads;
	vcp->vc_threads = vxcp;
	__vg_exec_context_yield(vxcp);
	pthread_mutex_unlock(&vg_thread_lock);
	return 1;
}

void vg_exec_context_del(vg_exec_context_t * vxcp) {
	vg_exec_context_t *tp, **pprev;

	if (vxcp->vxc_lockmode == 2)
		vg_exec_context_downgrade_lock(vxcp);

	pthread_mutex_lock(&vg_thread_lock);
	assert(vxcp->vxc_lockmode == 1);
	vxcp->vxc_lockmode = 0;

	for (pprev = &vxcp->vxc_vc->vc_threads, tp = *pprev;
						(tp != vxcp) && (tp != NULL); pprev = &tp->vxc_next, tp = *pprev)
		;

	assert(tp == vxcp);
	*pprev = tp->vxc_next;

	if (tp->vxc_stop)
		pthread_cond_signal(&vg_thread_upcond);

	BN_clear_free(vxcp->vxc_bntarg);
	BN_clear_free(vxcp->vxc_bnbase);
	BN_clear_free(vxcp->vxc_bntmp);
	BN_clear_free(vxcp->vxc_bntmp2);
	BN_CTX_free(vxcp->vxc_bnctx);
	vxcp->vxc_bnctx = NULL;
	pthread_mutex_unlock(&vg_thread_lock);
}

void vg_exec_context_yield(vg_exec_context_t * vxcp) {
	if (vxcp->vxc_lockmode == 2)
		vg_exec_context_downgrade_lock(vxcp);

	else if (vxcp->vxc_stop) {
		assert(vxcp->vxc_lockmode == 1);
		pthread_mutex_lock(&vg_thread_lock);
		__vg_exec_context_yield(vxcp);
		pthread_mutex_unlock(&vg_thread_lock);
	}

	assert(vxcp->vxc_lockmode == 1);
}

void vg_exec_context_consolidate_key(vg_exec_context_t * vxcp) {
	if (vxcp->vxc_delta) {
		BN_clear(vxcp->vxc_bntmp);
		BN_set_word(vxcp->vxc_bntmp, vxcp->vxc_delta);
		BN_add(
			vxcp->vxc_bntmp2, EC_KEY_get0_private_key(vxcp->vxc_key), vxcp->vxc_bntmp);
		vg_set_privkey(vxcp->vxc_bntmp2, vxcp->vxc_key);
		vxcp->vxc_delta = 0;
	}
}

void vg_exec_context_calc_address(
	vg_exec_context_t * vxcp, const int isaddresscompressed) {
	EC_POINT * pubkey;
	const EC_GROUP * pgroup;
	unsigned char eckey_buf[96], hash1[32], hash2[20];
	int len;

	vg_exec_context_consolidate_key(vxcp);
	pgroup = EC_KEY_get0_group(vxcp->vxc_key);
	pubkey = EC_POINT_new(pgroup);
	EC_POINT_copy(pubkey, EC_KEY_get0_public_key(vxcp->vxc_key));
	if (vxcp->vxc_vc->vc_pubkey_base) {
		EC_POINT_add(
			pgroup, pubkey, pubkey, vxcp->vxc_vc->vc_pubkey_base, vxcp->vxc_bnctx);
	}
	len = EC_POINT_point2oct(pgroup, pubkey,
		isaddresscompressed ? POINT_CONVERSION_COMPRESSED :
																								POINT_CONVERSION_UNCOMPRESSED,
		eckey_buf, sizeof(eckey_buf), vxcp->vxc_bnctx);
	SHA256(eckey_buf, len, hash1);
	RIPEMD160(hash1, sizeof(hash1), hash2);
	memcpy(&vxcp->vxc_binres[1], hash2, 20);
	EC_POINT_free(pubkey);
}

enum { timing_hist_size = 5 };

typedef struct _timing_info_s {
	struct _timing_info_s * ti_next;
	pthread_t ti_thread;
	unsigned long ti_last_rate;

	unsigned long long ti_hist_time[timing_hist_size];
	unsigned long ti_hist_work[timing_hist_size];
	int ti_hist_last;
} timing_info_t;

static pthread_mutex_t timing_mutex = PTHREAD_MUTEX_INITIALIZER;

int vg_output_timing(vg_context_t * vcp, int cycle, struct timeval * last) {
	pthread_t me;
	struct timeval tvnow, tv;
	timing_info_t *tip, *mytip;
	unsigned long long rate, myrate = 0, mytime, total, sincelast;
	int p, i;

	/* Compute the rate */
	gettimeofday(&tvnow, NULL);
	timersub(&tvnow, last, &tv);
	memcpy(last, &tvnow, sizeof(*last));
	mytime = tv.tv_usec + (1000000ULL * tv.tv_sec);
	if (!mytime)
		mytime = 1;
	rate = 0;

	pthread_mutex_lock(&timing_mutex);
	me = pthread_self();
	for (tip = vcp->vc_timing_head, mytip = NULL; tip != NULL;
						tip = tip->ti_next) {
		if (pthread_equal(tip->ti_thread, me)) {
			mytip = tip;
			p = ((tip->ti_hist_last + 1) % timing_hist_size);
			tip->ti_hist_time[p] = mytime;
			tip->ti_hist_work[p] = cycle;
			tip->ti_hist_last = p;

			mytime = 0;
			myrate = 0;
			for (i = 0; i < timing_hist_size; i++) {
				mytime += tip->ti_hist_time[i];
				myrate += tip->ti_hist_work[i];
			}
			myrate = (myrate * 1000000) / mytime;
			tip->ti_last_rate = myrate;
			rate += myrate;

		} else
			rate += tip->ti_last_rate;
	}
	if (!mytip) {
		mytip = (timing_info_t *) malloc(sizeof(*tip));
		mytip->ti_next = vcp->vc_timing_head;
		mytip->ti_thread = me;
		vcp->vc_timing_head = mytip;
		mytip->ti_hist_last = 0;
		mytip->ti_hist_time[0] = mytime;
		mytip->ti_hist_work[0] = cycle;
		for (i = 1; i < timing_hist_size; i++) {
			mytip->ti_hist_time[i] = 1;
			mytip->ti_hist_work[i] = 0;
		}
		myrate = ((unsigned long long) cycle * 1000000) / mytime;
		mytip->ti_last_rate = myrate;
		rate += myrate;
	}

	vcp->vc_timing_total += cycle;
	if (vcp->vc_timing_prevfound != vcp->vc_found) {
		vcp->vc_timing_prevfound = vcp->vc_found;
		vcp->vc_timing_sincelast = 0;
	}
	vcp->vc_timing_sincelast += cycle;

	if (mytip != vcp->vc_timing_head) {
		pthread_mutex_unlock(&timing_mutex);
		return myrate;
	}
	total = vcp->vc_timing_total;
	sincelast = vcp->vc_timing_sincelast;
	pthread_mutex_unlock(&timing_mutex);

	vcp->vc_output_timing(vcp, sincelast, rate, total);
	return myrate;
}

void vg_context_thread_exit(vg_context_t * vcp) {
	timing_info_t *tip, **ptip;
	pthread_t me;

	pthread_mutex_lock(&timing_mutex);
	me = pthread_self();
	for (ptip = &vcp->vc_timing_head, tip = *ptip; tip != NULL;
						ptip = &tip->ti_next, tip = *ptip) {
		if (!pthread_equal(tip->ti_thread, me))
			continue;
		*ptip = tip->ti_next;
		free(tip);
		break;
	}
	pthread_mutex_unlock(&timing_mutex);
}

static void vg_timing_info_free(vg_context_t * vcp) {
	timing_info_t * tp;
	while (vcp->vc_timing_head != NULL) {
		tp = vcp->vc_timing_head;
		vcp->vc_timing_head = tp->ti_next;
		free(tp);
	}
}

void vg_output_timing_console(vg_context_t * vcp, double count,
	unsigned long long rate, unsigned long long total) {
	double prob, time, targ;
	char * unit;
	char linebuf[80];
	int rem, p;

	const double targs[] = {0.5, 0.75, 0.8, 0.9, 0.95, 1.0};

	targ = rate;
	unit = (char *) "key/s";
	if (targ > 1000) {
		unit = (char *) "Kkey/s";
		targ /= 1000.0;
		if (targ > 1000) {
			unit = (char *) "Mkey/s";
			targ /= 1000.0;
		}
	}

	rem = sizeof(linebuf);
	p = snprintf(linebuf, rem, "[%.2f %s][total %lld]", targ, unit, total);
	assert(p > 0);
	rem -= p;
	if (rem < 0)
		rem = 0;

	if (vcp->vc_chance >= 1.0) {
		prob = 1.0f - exp(-count / vcp->vc_chance);

		if (prob <= 0.999) {
			p = snprintf(&linebuf[p], rem, "[Prob %.1f%%]", prob * 100);
			assert(p > 0);
			rem -= p;
			if (rem < 0)
				rem = 0;
			p = sizeof(linebuf) - rem;
		}

		for (unsigned i = 0; i < sizeof(targs) / sizeof(targs[0]); i++) {
			targ = targs[i];
			if ((targ < 1.0) && (prob <= targ))
				break;
		}

		if (targ < 1.0) {
			time = ((-vcp->vc_chance * log(1.0 - targ)) - count) / rate;
			unit = (char *) "s";
			if (time > 60) {
				time /= 60;
				unit = (char *) "min";
				if (time > 60) {
					time /= 60;
					unit = (char *) "h";
					if (time > 24) {
						time /= 24;
						unit = (char *) "d";
						if (time > 365) {
							time /= 365;
							unit = (char *) "y";
						}
					}
				}
			}

			if (time > 1000000) {
				p = snprintf(
					&linebuf[p], rem, "[%d%% in %e%s]", (int) (100 * targ), time, unit);
			} else {
				p = snprintf(
					&linebuf[p], rem, "[%d%% in %.1f%s]", (int) (100 * targ), time, unit);
			}
			assert(p > 0);
			rem -= p;
			if (rem < 0)
				rem = 0;
			p = sizeof(linebuf) - rem;
		}
	}

	if (vcp->vc_found) {
		if (vcp->vc_remove_on_match)
			p = snprintf(&linebuf[p], rem, "[Found %lld/%ld]", vcp->vc_found,
				vcp->vc_npatterns_start);
		else
			p = snprintf(&linebuf[p], rem, "[Found %lld]", vcp->vc_found);
		assert(p > 0);
		rem -= p;
		if (rem < 0)
			rem = 0;
	}
	p = snprintf(&linebuf[p], rem, COLOR0 " ");
	if (rem) {
		memset(&linebuf[sizeof(linebuf) - rem], 0x20, rem);
		linebuf[sizeof(linebuf) - 1] = '\0';
	}
	printf("\r%s", linebuf);
	fflush(stdout);
}

void vg_output_match_console(vg_context_t * vcp, EC_KEY * pkey,
	const char * pattern, int isaddresscompressed) {
	unsigned char key_buf[512], *pend;
	char addr_buf[64], addr2_buf[64];
	char privkey_buf[128];
	const char * keytype = "Privkey";
	int len;
	int isscript = (vcp->vc_format == VCF_SCRIPT);

	EC_POINT * ppnt;
	int free_ppnt = 0;
	if (vcp->vc_pubkey_base) {
		ppnt = EC_POINT_new(EC_KEY_get0_group(pkey));
		EC_POINT_copy(ppnt, EC_KEY_get0_public_key(pkey));
		EC_POINT_add(EC_KEY_get0_group(pkey), ppnt, ppnt, vcp->vc_pubkey_base, NULL);
		free_ppnt = 1;
		keytype = "PrivkeyPart";
	} else {
		ppnt = (EC_POINT *) EC_KEY_get0_public_key(pkey);
	}

	assert(EC_KEY_check_key(pkey));
	if (isscript)
		vg_encode_script_address(
			ppnt, EC_KEY_get0_group(pkey), vcp->vc_istestnet, addr2_buf);
	else {
		if (isaddresscompressed) {
			vg_encode_compressed_address(
				ppnt, EC_KEY_get0_group(pkey), vcp->vc_istestnet, addr_buf);
		} else {
			vg_encode_address(
				ppnt, EC_KEY_get0_group(pkey), vcp->vc_istestnet, addr_buf);
		}
	}

	if (isaddresscompressed)
		vg_encode_privkey_compressed(pkey, vcp->vc_privtype, privkey_buf);
	else
		vg_encode_privkey(pkey, vcp->vc_privtype, privkey_buf);

	if (vcp->vc_verbose > 0 || !vcp->vc_result_file || !vcp->vc_result_file_csv) {
		printf("\r%79s\r" COLOR0 "Pattern: " COLOR33 "%s" COLOR0 "\n", "", pattern);
	}

	if (vcp->vc_verbose > 1) {
		pend = key_buf;
		len = i2o_ECPublicKey(pkey, &pend);
		printf("Pubkey (hex): ");
		dumphex(key_buf, len);
		printf("Privkey (hex): ");
		dumpbn(EC_KEY_get0_private_key(pkey));
		pend = key_buf;
		len = i2d_ECPrivateKey(pkey, &pend);
		printf("Privkey (ASN1): ");
		dumphex(key_buf, len);
	}

	if (vcp->vc_verbose > 0 || !vcp->vc_result_file || !vcp->vc_result_file_csv) {
		if (isscript) {
			printf("P2SHAddress: " COLOR32 "%s" COLOR0 "\n", addr2_buf);
		} else {
			printf("Address: " COLOR32 "%s" COLOR0 "\n", addr_buf);
		}
		printf("%s: " COLOR34 "%s" COLOR0 "\n", keytype, privkey_buf);
	}

	if (vcp->vc_result_file) {
		FILE * fp = fopen(vcp->vc_result_file, "a");
		if (!fp) {
			fprintf(
				stderr, "ERROR: could not open TSV result file: %s\n", strerror(errno));
		} else {
			fprintf(fp, "%s\t", pattern);
			if (isscript)
				fprintf(fp, "%s\t", addr2_buf);
			else
				fprintf(fp, "%s\t", addr_buf);
			fprintf(fp, "%s\n", privkey_buf);
			fclose(fp);
		}
	}
	if (vcp->vc_result_file_csv) {
		FILE * fp = fopen(vcp->vc_result_file_csv, "a");
		if (!fp) {
			fprintf(
				stderr, "ERROR: could not open CSV result file: %s\n", strerror(errno));
		} else {
			fprintf(fp, "%s,", pattern);
			if (isscript)
				fprintf(fp, "%s,", addr2_buf);
			else
				fprintf(fp, "%s,", addr_buf);
			fprintf(fp, "%s\n", privkey_buf);
			fclose(fp);
		}
	}
	if (free_ppnt)
		EC_POINT_free(ppnt);
}


void vg_context_free(vg_context_t * vcp) {
	vg_timing_info_free(vcp);
	vcp->vc_free(vcp);
}

int vg_context_add_patterns(
	vg_context_t * vcp, const char ** const patterns, int npatterns) {
	vcp->vc_pattern_generation++;
	return vcp->vc_add_patterns(vcp, patterns, npatterns);
}

void vg_context_clear_all_patterns(vg_context_t * vcp) {
	vcp->vc_clear_all_patterns(vcp);
	vcp->vc_pattern_generation++;
}

int vg_context_hash160_sort(vg_context_t * vcp, void * buf) {
	if (!vcp->vc_hash160_sort)
		return 0;
	return vcp->vc_hash160_sort(vcp, buf);
}

int vg_context_start_threads(vg_context_t * vcp) {
	vg_exec_context_t * vxcp;
	int res;

	for (vxcp = vcp->vc_threads; vxcp != NULL; vxcp = vxcp->vxc_next) {
		res = pthread_create((pthread_t *) &vxcp->vxc_pthread, NULL,
			(void * (*) (void *) ) vxcp->vxc_threadfunc, vxcp);
		if (res) {
			fprintf(stderr, "ERROR: could not create thread: %d\n", res);
			vg_context_stop_threads(vcp);
			return -1;
		}
		vxcp->vxc_thread_active = 1;
	}
	return 0;
}

void vg_context_stop_threads(vg_context_t * vcp) {
	vcp->vc_halt = 1;
	vg_context_wait_for_completion(vcp);
	vcp->vc_halt = 0;
}

void vg_context_wait_for_completion(vg_context_t * vcp) {
	vg_exec_context_t * vxcp;

	for (vxcp = vcp->vc_threads; vxcp != NULL; vxcp = vxcp->vxc_next) {
		if (!vxcp->vxc_thread_active)
			continue;
		pthread_join((pthread_t) vxcp->vxc_pthread, NULL);
		vxcp->vxc_thread_active = 0;
	}
}


/*
	* Find the bignum ranges that produce a given prefix.
	*/
static int get_prefix_ranges(int addrtype, const char * pfx, BIGNUM ** result) {
	BIGNUM *low = BN_new(), *high = BN_new();
	BIGNUM * bntmp = BN_new();
	int p = strlen(pfx);
	int ret = -1;
	if (p > 30) {
		fprintf(stderr, "Prefix too long! 30 characters at most.\n");
		ret = -2;
		goto out;
	}
	if (addrtype == 8) {
		if (pfx[0] != 'p') {
			fprintf(stderr,
				"The first character of the prefix must be 'p' for script addresses.\n");
			ret = -2;
			goto out;
		}
	} else {
		if (pfx[0] != 'q') {
			fprintf(stderr,
				"The first character of the prefix must be 'q' for standard addresses.\n");
			ret = -2;
			goto out;
		}
	}
	if (pfx[1] != 'q' && pfx[1] != 'p' && pfx[1] != 'z' && pfx[1] != 'r') {
		fprintf(stderr,
			"The second character of the prefix must be either 'q', 'p', 'r' or 'z'.\n");
		ret = -2;
		goto out;
	}
	for (int i = 0, c; i < p; i++) {
		c = CHARSET_REV[(int) pfx[i]];
		if (c == -1) {
			fprintf(stderr, "Invalid character '%c' in prefix '%s'\n", pfx[i], pfx);
			ret = -2;
			goto out;
		}
		BN_set_word(bntmp, c);
		BN_lshift(low, low, 5);
		BN_add(low, low, bntmp);
		BN_lshift(high, high, 5);
		BN_add(high, high, bntmp);
	}
	BN_set_word(bntmp, 31);
	for (; p < 42; p++) {
		BN_lshift(low, low, 5);
		BN_lshift(high, high, 5);
		BN_add(high, high, bntmp);
	}
	// TODO: Research why we need this:
	BN_rshift(low, low, 2);
	BN_rshift(high, high, 2);
	result[0] = low;
	result[1] = high;
	ret = 0;
out:
	BN_free(bntmp);
	return ret;
}

static void free_ranges(BIGNUM ** ranges) {
	BN_free(ranges[0]);
	BN_free(ranges[1]);
	ranges[0] = NULL;
	ranges[1] = NULL;
}


/*
	* Address prefix AVL tree node
	*/

//	const int vpk_nwords = (26 + sizeof(BN_ULONG) - 1) / sizeof(BN_ULONG);

typedef struct _vg_prefix_s {
	avl_item_t vp_item;
	struct _vg_prefix_s * vp_sibling;
	const char * vp_pattern;
	BIGNUM * vp_low;
	BIGNUM * vp_high;
} vg_prefix_t;

static void vg_prefix_free(vg_prefix_t * vp) {
	if (vp->vp_low)
		BN_free(vp->vp_low);
	if (vp->vp_high)
		BN_free(vp->vp_high);
	free(vp);
}

static vg_prefix_t * vg_prefix_avl_search(avl_root_t * rootp, BIGNUM * targ) {
	vg_prefix_t * vp;
	avl_item_t * itemp = rootp->ar_root;

	while (itemp) {
		vp = avl_item_entry(itemp, vg_prefix_t, vp_item);
		if (BN_cmp(vp->vp_low, targ) > 0) {
			itemp = itemp->ai_left;
		} else {
			if (BN_cmp(vp->vp_high, targ) < 0) {
				itemp = itemp->ai_right;
			} else
				return vp;
		}
	}
	return NULL;
}

static vg_prefix_t * vg_prefix_avl_insert(
	avl_root_t * rootp, vg_prefix_t * vpnew) {
	vg_prefix_t * vp;
	avl_item_t * itemp = NULL;
	avl_item_t ** ptrp = &rootp->ar_root;
	while (*ptrp) {
		itemp = *ptrp;
		vp = avl_item_entry(itemp, vg_prefix_t, vp_item);
		if (BN_cmp(vp->vp_low, vpnew->vp_high) > 0) {
			ptrp = &itemp->ai_left;
		} else {
			if (BN_cmp(vp->vp_high, vpnew->vp_low) < 0) {
				ptrp = &itemp->ai_right;
			} else
				return vp;
		}
	}
	vpnew->vp_item.ai_up = itemp;
	itemp = &vpnew->vp_item;
	*ptrp = itemp;
	avl_insert_fix(rootp, itemp);
	return NULL;
}

static vg_prefix_t * vg_prefix_first(avl_root_t * rootp) {
	avl_item_t * itemp;
	itemp = avl_first(rootp);
	if (itemp)
		return avl_item_entry(itemp, vg_prefix_t, vp_item);
	return NULL;
}

static vg_prefix_t * vg_prefix_next(vg_prefix_t * vp) {
	avl_item_t * itemp = &vp->vp_item;
	itemp = avl_next(itemp);
	if (itemp)
		return avl_item_entry(itemp, vg_prefix_t, vp_item);
	return NULL;
}

static vg_prefix_t * vg_prefix_add(
	avl_root_t * rootp, const char * pattern, BIGNUM * low, BIGNUM * high) {
	vg_prefix_t *vp, *vp2;
	assert(BN_cmp(low, high) < 0);
	vp = (vg_prefix_t *) malloc(sizeof(*vp));
	if (vp) {
		avl_item_init(&vp->vp_item);
		vp->vp_sibling = NULL;
		vp->vp_pattern = pattern;
		vp->vp_low = low;
		vp->vp_high = high;
		vp2 = vg_prefix_avl_insert(rootp, vp);
		if (vp2 != NULL) {
			fprintf(
				stderr, "Prefix '%s' ignored, overlaps '%s'\n", pattern, vp2->vp_pattern);
			vg_prefix_free(vp);
			vp = NULL;
		}
	}
	return vp;
}

static void vg_prefix_delete(avl_root_t * rootp, vg_prefix_t * vp) {
	vg_prefix_t *sibp, *delp;

	avl_remove(rootp, &vp->vp_item);
	sibp = vp->vp_sibling;
	while (sibp && sibp != vp) {
		avl_remove(rootp, &sibp->vp_item);
		delp = sibp;
		sibp = sibp->vp_sibling;
		vg_prefix_free(delp);
	}
	vg_prefix_free(vp);
}

static vg_prefix_t * vg_prefix_add_ranges(avl_root_t * rootp,
	const char * pattern, BIGNUM ** ranges, vg_prefix_t * master) {
	vg_prefix_t *vp, *vp2 = NULL;

	assert(ranges[0]);
	vp = vg_prefix_add(rootp, pattern, ranges[0], ranges[1]);
	if (!vp)
		return NULL;

	if (!master) {
		vp->vp_sibling = vp2;
		if (vp2)
			vp2->vp_sibling = vp;
	} else if (vp2) {
		vp->vp_sibling = vp2;
		vp2->vp_sibling = (master->vp_sibling ? master->vp_sibling : master);
		master->vp_sibling = vp;
	} else {
		vp->vp_sibling = (master->vp_sibling ? master->vp_sibling : master);
		master->vp_sibling = vp;
	}
	return vp;
}

static void vg_prefix_range_sum(
	vg_prefix_t * vp, BIGNUM * result, BIGNUM * tmp1) {
	vg_prefix_t * startp;

	startp = vp;
	BN_clear(result);
	do {
		BN_sub(tmp1, vp->vp_high, vp->vp_low);
		BN_add(result, result, tmp1);
		vp = vp->vp_sibling;
	} while (vp && (vp != startp));
}

typedef struct _vg_prefix_context_s {
	vg_context_t base;
	avl_root_t vcp_avlroot;
	BIGNUM * vcp_difficulty;
} vg_prefix_context_t;

static void vg_prefix_context_clear_all_patterns(vg_context_t * vcp) {
	vg_prefix_context_t * vcpp = (vg_prefix_context_t *) vcp;
	vg_prefix_t * vp;
	unsigned long npfx_left = 0;

	while (!avl_root_empty(&vcpp->vcp_avlroot)) {
		vp = avl_item_entry(vcpp->vcp_avlroot.ar_root, vg_prefix_t, vp_item);
		vg_prefix_delete(&vcpp->vcp_avlroot, vp);
		npfx_left++;
	}

	assert(npfx_left == vcpp->base.vc_npatterns);
	vcpp->base.vc_npatterns = 0;
	vcpp->base.vc_npatterns_start = 0;
	vcpp->base.vc_found = 0;
	BN_clear(vcpp->vcp_difficulty);
}

static void vg_prefix_context_free(vg_context_t * vcp) {
	vg_prefix_context_t * vcpp = (vg_prefix_context_t *) vcp;
	vg_prefix_context_clear_all_patterns(vcp);
	BN_clear_free(vcpp->vcp_difficulty);
	free(vcpp);
}

static void vg_prefix_context_next_difficulty(
	vg_prefix_context_t * vcpp, BIGNUM * bntmp, BIGNUM * bntmp2, BN_CTX * bnctx) {
	char * dbuf;
	BN_clear(bntmp);
	BN_set_bit(bntmp, 200);
	BN_div(bntmp2, NULL, bntmp, vcpp->vcp_difficulty, bnctx);

	dbuf = BN_bn2dec(bntmp2);
	if (vcpp->base.vc_verbose > 0) {
		if (vcpp->base.vc_npatterns > 1)
			fprintf(stderr,
				"Next match difficulty: " COLOR36 "%s" COLOR0 " (%ld prefixes)\n", dbuf,
				vcpp->base.vc_npatterns);
		else
			fprintf(stderr, "Difficulty: " COLOR36 "%s" COLOR0 "\n", dbuf);
	}
	vcpp->base.vc_chance = atof(dbuf);
	OPENSSL_free(dbuf);
}

static int vg_prefix_context_add_patterns(
	vg_context_t * vcp, const char ** const patterns, int npatterns) {
	vg_prefix_context_t * vcpp = (vg_prefix_context_t *) vcp;
	vg_prefix_t * vp;
	BN_CTX * bnctx;
	BIGNUM *bntmp = BN_new(), *bntmp2 = BN_new(), *bntmp3 = BN_new();
	BIGNUM * ranges[2];
	int ret = 0;
	int i, impossible = 0;
	unsigned long npfx;
	char * dbuf;

	bnctx = BN_CTX_new();

	npfx = 0;
	for (i = 0; i < npatterns; i++) {
		vp = NULL;
		ret = get_prefix_ranges(vcpp->base.vc_addrtype, patterns[i], ranges);
		if (!ret) {
			vp = vg_prefix_add_ranges(&vcpp->vcp_avlroot, patterns[i], ranges, NULL);
		}

		if (ret == -2) {
			fprintf(stderr, "Prefix '%s' not possible\n", patterns[i]);
			impossible++;
		}

		if (!vp)
			continue;

		npfx++;

		/* Determine the probability of finding a match */
		vg_prefix_range_sum(vp, bntmp, bntmp2);
		BN_add(bntmp2, vcpp->vcp_difficulty, bntmp);
		BN_copy(vcpp->vcp_difficulty, bntmp2);

		if (vcp->vc_verbose > 1) {
			BN_clear(bntmp2);
			BN_set_bit(bntmp2, 200);
			BN_div(bntmp3, NULL, bntmp2, bntmp, bnctx);

			dbuf = BN_bn2dec(bntmp3);
			fprintf(stderr, "Prefix difficulty: %20s %s\n", dbuf, patterns[i]);
			OPENSSL_free(dbuf);
		}
	}

	vcpp->base.vc_npatterns += npfx;
	vcpp->base.vc_npatterns_start += npfx;

	if (!npfx && impossible)
		fprintf(stderr, "Advice: run with the -c argument to see the conditions.\n");

	if (npfx)
		vg_prefix_context_next_difficulty(vcpp, bntmp, bntmp2, bnctx);

	ret = (npfx != 0);

	BN_clear_free(bntmp);
	BN_clear_free(bntmp2);
	BN_clear_free(bntmp3);
	BN_CTX_free(bnctx);
	return ret;
}

double vg_prefix_get_difficulty(int addrtype, const char * pattern) {
	BN_CTX * bnctx;
	BIGNUM *result = BN_new(), *bntmp = BN_new();
	BIGNUM * ranges[4];
	char * dbuf;
	int ret;
	double diffret = 0.0;

	bnctx = BN_CTX_new();

	ret = get_prefix_ranges(addrtype, pattern, ranges);

	if (ret == 0) {
		BN_sub(bntmp, ranges[1], ranges[0]);
		BN_add(result, result, bntmp);
		free_ranges(ranges);

		BN_clear(bntmp);
		BN_set_bit(bntmp, 200);
		BN_div(result, NULL, bntmp, result, bnctx);

		dbuf = BN_bn2dec(result);
		diffret = strtod(dbuf, NULL);
		OPENSSL_free(dbuf);
	}

	BN_clear_free(result);
	BN_clear_free(bntmp);
	BN_CTX_free(bnctx);
	return diffret;
}


static int vg_prefix_test(
	vg_exec_context_t * vxcp, const int isaddresscompressed) {
	vg_prefix_context_t * vcpp = (vg_prefix_context_t *) vxcp->vxc_vc;
	vg_prefix_t * vp;
	int res = 0;

	/*
		* We constrain the prefix so that we can check for
		* a match without generating the lower four byte
		* check code.
		*/

	BN_bin2bn(vxcp->vxc_binres, 26, vxcp->vxc_bntarg);

research:
	vp = vg_prefix_avl_search(&vcpp->vcp_avlroot, vxcp->vxc_bntarg);
	if (vp) {
		if (vg_exec_context_upgrade_lock(vxcp))
			goto research;

		vg_exec_context_consolidate_key(vxcp);
		vcpp->base.vc_output_match(
			&vcpp->base, vxcp->vxc_key, vp->vp_pattern, isaddresscompressed);

		vcpp->base.vc_found++;

		if (vcpp->base.vc_only_one) {
			return 2;
		}

		if (vcpp->base.vc_remove_on_match) {
			/* Subtract the range from the difficulty */
			vg_prefix_range_sum(vp, vxcp->vxc_bntarg, vxcp->vxc_bntmp);
			BN_sub(vxcp->vxc_bntmp, vcpp->vcp_difficulty, vxcp->vxc_bntarg);
			BN_copy(vcpp->vcp_difficulty, vxcp->vxc_bntmp);

			vg_prefix_delete(&vcpp->vcp_avlroot, vp);
			vcpp->base.vc_npatterns--;

			if (!avl_root_empty(&vcpp->vcp_avlroot))
				vg_prefix_context_next_difficulty(
					vcpp, vxcp->vxc_bntmp, vxcp->vxc_bntmp2, vxcp->vxc_bnctx);
			vcpp->base.vc_pattern_generation++;
		}
		res = 1;
	}
	if (avl_root_empty(&vcpp->vcp_avlroot)) {
		return 2;
	}
	return res;
}

static int vg_prefix_hash160_sort(vg_context_t * vcp, void * buf) {
	vg_prefix_context_t * vcpp = (vg_prefix_context_t *) vcp;
	vg_prefix_t * vp;
	unsigned char * cbuf = (unsigned char *) buf;
	unsigned char bnbuf[26];
	int nbytes, ncopy, nskip, npfx = 0;

	/*
		* Walk the prefix tree in order, copy the upper and lower bound
		* values into the hash160 buffer.  Skip the lower four bytes
		* and anything above the 24th byte.
		*/
	for (vp = vg_prefix_first(&vcpp->vcp_avlroot); vp != NULL;
						vp = vg_prefix_next(vp)) {
		npfx++;
		if (!buf)
			continue;

		/* Low */
		nbytes = BN_bn2bin(vp->vp_low, bnbuf);
		ncopy = ((nbytes >= 25) ? 20 : ((nbytes > 5) ? (nbytes - 5) : 0));
		nskip = (nbytes >= 25) ? (nbytes - 25) : 0;
		if (ncopy < 20)
			memset(cbuf, 0, 20 - ncopy);
		memcpy(cbuf + (20 - ncopy), bnbuf + nskip, ncopy);
		cbuf += 20;

		/* High */
		nbytes = BN_bn2bin(vp->vp_high, bnbuf);
		ncopy = ((nbytes >= 25) ? 20 : ((nbytes > 5) ? (nbytes - 5) : 0));
		nskip = (nbytes >= 25) ? (nbytes - 25) : 0;
		if (ncopy < 20)
			memset(cbuf, 0, 20 - ncopy);
		memcpy(cbuf + (20 - ncopy), bnbuf + nskip, ncopy);
		cbuf += 20;
	}
	return npfx;
}

inline static void vg_prefix_context_exec_prep(
	vg_context_t * vcp, vg_exec_context_t * vxcp) {
	(void) vcp;
	(void) vxcp;
}

vg_context_t * vg_prefix_context_new(int addrtype, int privtype, int testnet) {
	vg_prefix_context_t * vcpp;

	vcpp = (vg_prefix_context_t *) malloc(sizeof(*vcpp));
	if (vcpp) {
		memset(vcpp, 0, sizeof(*vcpp));
		vcpp->base.vc_addrtype = addrtype;
		vcpp->base.vc_istestnet = testnet;
		vcpp->base.vc_privtype = privtype;
		vcpp->base.vc_npatterns = 0;
		vcpp->base.vc_npatterns_start = 0;
		vcpp->base.vc_found = 0;
		vcpp->base.vc_chance = 0.0;
		vcpp->base.vc_prep = vg_prefix_context_exec_prep;
		vcpp->base.vc_free = vg_prefix_context_free;
		vcpp->base.vc_add_patterns = vg_prefix_context_add_patterns;
		vcpp->base.vc_clear_all_patterns = vg_prefix_context_clear_all_patterns;
		vcpp->base.vc_test = vg_prefix_test;
		vcpp->base.vc_hash160_sort = vg_prefix_hash160_sort;
		avl_root_init(&vcpp->vcp_avlroot);
		vcpp->vcp_difficulty = BN_new();
	}
	return &vcpp->base;
}



typedef struct _vg_regex_context_s {
	vg_context_t base;
	hs_database_t * vcr_db;
	const char ** vcr_regex_pat;
	hs_scratch_t * vcr_sample_scratch;
	int vcr_sync;
} vg_regex_context_t;

int vg_regex_context_prep_scratch(vg_context_t * vcp) {
	vg_regex_context_t * vcrp = (vg_regex_context_t *) vcp;
	// Just in case
	vcrp->vcr_sample_scratch = NULL;
	// Memory leak, assumed to be run once.
	int i = hs_alloc_scratch(vcrp->vcr_db, &vcrp->vcr_sample_scratch);
	if (i == HS_NOMEM) {
		fprintf(stderr, "Not enough RAM!\n");
	}
	return i == HS_SUCCESS;
}

static void vg_regex_context_clear_all_patterns(vg_context_t * vcp) {
	vg_regex_context_t * vcrp = (vg_regex_context_t *) vcp;
	hs_error_t stat;
	if (vcrp->vcr_db) {
		stat = hs_free_database(vcrp->vcr_db);
		if (stat)
			fprintf(stderr,
				"An error occured while cleaning database!\n"
				"Error code: %d\n",
				stat);
	}
	if (vcrp->vcr_sample_scratch) {
		stat = hs_free_scratch(vcrp->vcr_sample_scratch);
		if (stat)
			fprintf(stderr,
				"An error occured while cleaning scratch!\n"
				"Error code: %d\n",
				stat);
		;
	}
	vcrp->vcr_db = NULL;
	vcrp->vcr_sample_scratch = NULL;

	if (vcrp->vcr_regex_pat)
		free(vcrp->vcr_regex_pat);
	vcrp->base.vc_npatterns = 0;
	vcrp->base.vc_npatterns_start = 0;
	vcrp->base.vc_found = 0;
}

static int vg_regex_compile_patterns(const char ** const patterns,
	unsigned int npatterns, hs_database_t ** db,
	hs_compile_error_t ** compile_error) {
	unsigned int ids[npatterns];
	unsigned int flags[npatterns];
	for (unsigned int i = 0; i < (unsigned) npatterns; i++) {
		ids[i] = i;
		flags[i] =
			HS_FLAG_SINGLEMATCH | HS_FLAG_PREFILTER | HS_FLAG_CASELESS | HS_FLAG_DOTALL;
	}
	return hs_compile_multi(
		patterns, flags, ids, npatterns, HS_MODE_BLOCK, NULL, db, compile_error);
}

static int vg_regex_context_add_patterns(
	vg_context_t * vcp, const char ** const patterns, int npatterns) {
	if (!npatterns)
		return 1;
	vg_regex_context_t * vcrp = (vg_regex_context_t *) vcp;
	const char ** old_patterns = vcrp->vcr_regex_pat;
	vcrp->vcr_regex_pat = (const char **) malloc(
		(npatterns + vcrp->base.vc_npatterns) * sizeof(char *));
	memcpy(vcrp->vcr_regex_pat, patterns, npatterns * sizeof(char *));
	memcpy(&vcrp->vcr_regex_pat[npatterns], old_patterns,
		vcrp->base.vc_npatterns * sizeof(char *));
	free(old_patterns);

	hs_compile_error_t * compile_error;
	if (vg_regex_compile_patterns(vcrp->vcr_regex_pat,
						npatterns + vcrp->base.vc_npatterns, &vcrp->vcr_db,
						&compile_error) != HS_SUCCESS) {
		printf(
			"An error occured while compiling patterns: %s\n", compile_error->message);
		hs_free_compile_error(compile_error);
		return 0;
	}
	vcrp->base.vc_npatterns += npatterns;
	vcrp->base.vc_npatterns_start += npatterns;
	return 1;
}

static void vg_regex_context_free(vg_context_t * vcp) {
	vg_regex_context_clear_all_patterns(vcp);
	vg_regex_context_t * vcrp = (vg_regex_context_t *) vcp;
	free(vcrp);
}

typedef struct _vg_regex_scan_result_s {
	char state;
	int isaddresscompressed;
	vg_exec_context_t * vxcp;
} vg_regex_scan_result_t;

static int vg_regex_match_handler(unsigned int id, unsigned long long from,
	unsigned long long to, unsigned int flags, void * context) {
	(void) from;
	(void) to;
	(void) flags;
	vg_regex_scan_result_t * rct = (vg_regex_scan_result_t *) context;
	vg_exec_context_t * vxcp = (vg_exec_context_t *) rct->vxcp;
	vg_regex_context_t * vcrp = (vg_regex_context_t *) vxcp->vxc_vc;
	rct->state = 1;
	// Should this be && or ||
	if (vg_exec_context_upgrade_lock(vxcp) &&
		vxcp->vxc_regex_sync != vcrp->vcr_sync) {
		// Should this be done before a match occures?
		vxcp->vxc_regex_sync = vcrp->vcr_sync;
		hs_scratch_t * temp_scratch = NULL;
		if (hs_clone_scratch(vcrp->vcr_sample_scratch, &temp_scratch) == HS_NOMEM) {
			fprintf(stderr, "Not enough RAM!\n");
			hs_free_scratch(vcrp->vcr_sample_scratch);
			rct->state = 2;
			return 0;
		}
		hs_scratch_t * old_scratch = vxcp->vxc_scratch;
		vxcp->vxc_scratch = temp_scratch;
		hs_free_scratch(old_scratch);
		rct->state = 3;
		return 0;
	}
	vg_exec_context_consolidate_key(vxcp);
	vcrp->base.vc_output_match(&vcrp->base, vxcp->vxc_key, vcrp->vcr_regex_pat[id],
		rct->isaddresscompressed);
	vcrp->base.vc_found++;
	if (vcrp->base.vc_only_one || !vcrp->base.vc_npatterns) {
		rct->state = 2;
		return 0;
	}
	if (vcrp->base.vc_remove_on_match) {
		// TODO: Is there a race condition?
		vcrp->vcr_regex_pat[id] = vcrp->vcr_regex_pat[--vcrp->base.vc_npatterns];
		if (!vcrp->base.vc_npatterns) {
			rct->state = 2;
			return 0;
		}
		vcrp->vcr_sync++;
		vxcp->vxc_regex_sync++;
		hs_compile_error_t * compile_error;
		if (vg_regex_compile_patterns(vcrp->vcr_regex_pat, vcrp->base.vc_npatterns,
							&vcrp->vcr_db, &compile_error) != HS_SUCCESS) {
			printf("An error occured while re-compiling patterns: %s\n",
				compile_error->message);
			hs_free_compile_error(compile_error);
			rct->state = 2;
			return 0;
		}
		vcrp->base.vc_pattern_generation++;
	}
	return 0;
}

static int vg_regex_test(
	vg_exec_context_t * vxcp, const int isaddresscompressed) {
	vg_regex_context_t * vcrp = (vg_regex_context_t *) vxcp->vxc_vc;

	char addr[42];
	CashAddrEncode(vcrp->base.vc_istestnet, &vxcp->vxc_binres[1],
		vcrp->base.vc_addrtype, 0, addr);

	/*
		* Run the regular expressions on it
		* FAST, too fast!
		*/
restart_loop:
	if (!vcrp->base.vc_npatterns) {
		return 2;
	}
	vg_regex_scan_result_t result_input;
	result_input.isaddresscompressed = isaddresscompressed;
	result_input.vxcp = vxcp;
	result_input.state = 0;
	int scan = hs_scan(vcrp->vcr_db, addr, 42, 0, vxcp->vxc_scratch,
		vg_regex_match_handler, &result_input);
	if (scan != HS_SUCCESS) {
		fprintf(stderr, "ERROR: Unable to scan for regex. Error code: %d.\n", scan);
		hs_free_scratch(vxcp->vxc_scratch);
		hs_free_database(vcrp->vcr_db);
		return 2;
	}
	switch (result_input.state) {
	case 1:
		return 1;
	case 2:
		return 2;
	case 3:
		goto restart_loop;
	default:
		return 0;
	}
}

static void vg_regex_context_exec_prep(
	vg_context_t * vcp, vg_exec_context_t * vxcp) {
	vg_regex_context_t * vcrp = (vg_regex_context_t *) vcp;
	if (hs_clone_scratch(vcrp->vcr_sample_scratch, &vxcp->vxc_scratch) ==
		HS_NOMEM) {
		fprintf(stderr, "Not enough RAM!\n");
		hs_free_scratch(vcrp->vcr_sample_scratch);
		assert(0);
	}
}

vg_context_t * vg_regex_context_new(int addrtype, int privtype, int testnet) {
	vg_regex_context_t * vcrp;

	vcrp = (vg_regex_context_t *) malloc(sizeof(*vcrp));
	if (vcrp) {
		memset(vcrp, 0, sizeof(*vcrp));
		vcrp->base.vc_addrtype = addrtype;
		vcrp->base.vc_istestnet = testnet;
		vcrp->base.vc_privtype = privtype;
		vcrp->base.vc_npatterns = 0;
		vcrp->base.vc_npatterns_start = 0;
		vcrp->base.vc_found = 0;
		vcrp->base.vc_chance = 0.0;
		vcrp->base.vc_prep = vg_regex_context_exec_prep;
		vcrp->base.vc_free = vg_regex_context_free;
		vcrp->base.vc_add_patterns = vg_regex_context_add_patterns;
		vcrp->base.vc_clear_all_patterns = vg_regex_context_clear_all_patterns;
		vcrp->base.vc_test = vg_regex_test;
		vcrp->base.vc_hash160_sort = NULL;
		vcrp->vcr_db = NULL;
		vcrp->vcr_sample_scratch = NULL;
	}
	return &vcrp->base;
}
