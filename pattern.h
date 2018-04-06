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

#if !defined(__VG_PATTERN_H__)
#define __VG_PATTERN_H__

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <string>

#if defined(_WIN32) && !defined(HAVE_STRUCT_TIMESPEC)
#define HAVE_STRUCT_TIMESPEC
#endif
#include <pthread.h>
#include "cashaddr.h"

#ifdef _WIN32
#include "winglue.h"
#else
#define INLINE inline
#define PRSIZET "z"

#include <hs/hs.h>

#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#endif

#ifndef _WIN32
#define COLOR44 "\x1B[44m"
#define COLOR36 "\x1B[36m"
#define COLOR34 "\x1B[34m"
#define COLOR33 "\x1B[33m"
#define COLOR32 "\x1B[32m"
#define COLOR0 "\x1B[0m"
#else
#define COLOR44 ""
#define COLOR36 ""
#define COLOR34 ""
#define COLOR33 ""
#define COLOR32 ""
#define COLOR0 ""
#endif

#define VANITYGEN_VERSION "0.24"

typedef struct _vg_context_s vg_context_t;

struct _vg_exec_context_s;
typedef struct _vg_exec_context_s vg_exec_context_t;

typedef void * (*vg_exec_context_threadfunc_t)(vg_exec_context_t *);

/* Context of one pattern-matching unit within the process */
struct _vg_exec_context_s {
	vg_context_t * vxc_vc;
	BN_CTX * vxc_bnctx;
	EC_KEY * vxc_key;
	int vxc_delta;
	unsigned char vxc_binres[28];
	BIGNUM * vxc_bntarg;
	BIGNUM * vxc_bnbase;
	BIGNUM * vxc_bntmp;
	BIGNUM * vxc_bntmp2;

	vg_exec_context_threadfunc_t vxc_threadfunc;
	pthread_t vxc_pthread;
	int vxc_thread_active;
	hs_scratch_t * vxc_scratch;

	/* Thread synchronization */
	struct _vg_exec_context_s * vxc_next;
	int vxc_lockmode;
	int vxc_stop;
	int vxc_regex_sync;
};


typedef void (*vg_exec_prep_func_t)(vg_context_t *, vg_exec_context_t *);
typedef void (*vg_free_func_t)(vg_context_t *);
typedef int (*vg_add_pattern_func_t)(
	vg_context_t *, const char ** const patterns, int npatterns);
typedef void (*vg_clear_all_patterns_func_t)(vg_context_t *);
typedef int (*vg_test_func_t)(
	vg_exec_context_t *, const int isaddresscompressed);
typedef int (*vg_hash160_sort_func_t)(vg_context_t * vcp, void * buf);
typedef void (*vg_output_error_func_t)(vg_context_t * vcp, const char * info);
typedef void (*vg_output_match_func_t)(vg_context_t * vcp, EC_KEY * pkey,
	const char * pattern, int isaddresscompressed);
typedef void (*vg_output_timing_func_t)(vg_context_t * vcp, double count,
	unsigned long long rate, unsigned long long total);

enum vg_format {
	VCF_PUBKEY,
	VCF_SCRIPT,
};

/* Application-level context, incl. parameters and global pattern store */
struct _vg_context_s {
	int vc_addrtype;
	int vc_istestnet;
	int vc_privtype;
	unsigned long vc_npatterns;
	unsigned long vc_npatterns_start;
	unsigned long long vc_found;
	int vc_pattern_generation;
	double vc_chance;
	const char * vc_result_file;
	const char * vc_result_file_csv;
	int vc_remove_on_match;
	int vc_only_one;
	int vc_verbose;
	enum vg_format vc_format;
	int vc_pubkeytype;
	EC_POINT * vc_pubkey_base;
	int vc_halt;

	vg_exec_context_t * vc_threads;
	int vc_thread_excl;

	/* Internal methods */
	vg_exec_prep_func_t vc_prep;
	vg_free_func_t vc_free;
	vg_add_pattern_func_t vc_add_patterns;
	vg_clear_all_patterns_func_t vc_clear_all_patterns;
	vg_test_func_t vc_test;
	vg_hash160_sort_func_t vc_hash160_sort;

	/* Performance related members */
	unsigned long long vc_timing_total;
	unsigned long long vc_timing_prevfound;
	unsigned long long vc_timing_sincelast;
	struct _timing_info_s * vc_timing_head;

	/* External methods */
	vg_output_error_func_t vc_output_error;
	vg_output_match_func_t vc_output_match;
	vg_output_timing_func_t vc_output_timing;
};


/* Base context methods */
void vg_context_free(vg_context_t * vcp);
int vg_context_add_patterns(
	vg_context_t * vcp, const char ** const patterns, int npatterns);
void vg_context_clear_all_patterns(vg_context_t * vcp);
int vg_context_start_threads(vg_context_t * vcp);
void vg_context_stop_threads(vg_context_t * vcp);
void vg_context_wait_for_completion(vg_context_t * vcp);

/* Prefix context methods */
vg_context_t * vg_prefix_context_new(int addrtype, int privtype, int testnet);
double vg_prefix_get_difficulty(int addrtype, const char * pattern);

/* Regex context methods */
int vg_regex_context_prep_scratch(vg_context_t * vcp);
vg_context_t * vg_regex_context_new(int addrtype, int privtype, int testnet);

/* Utility functions */
int vg_output_timing(vg_context_t * vcp, int cycle, struct timeval * last);
void vg_output_match_console(vg_context_t * vcp, EC_KEY * pkey,
	const char * pattern, int isaddresscompressed);
void vg_output_timing_console(vg_context_t * vcp, double count,
	unsigned long long rate, unsigned long long total);



/* Internal vg_context methods */
int vg_context_hash160_sort(vg_context_t * vcp, void * buf);
void vg_context_thread_exit(vg_context_t * vcp);

/* Internal Init/cleanup for common execution context */
int vg_exec_context_init(vg_context_t * vcp, vg_exec_context_t * vxcp);
void vg_exec_context_del(vg_exec_context_t * vxcp);
void vg_exec_context_consolidate_key(vg_exec_context_t * vxcp);
void vg_exec_context_calc_address(
	vg_exec_context_t * vxcp, const int isaddresscompressed);
EC_KEY * vg_exec_context_new_key(void);

/* Internal execution context lock handling functions */
void vg_exec_context_downgrade_lock(vg_exec_context_t * vxcp);
int vg_exec_context_upgrade_lock(vg_exec_context_t * vxcp);
void vg_exec_context_yield(vg_exec_context_t * vxcp);


#endif /* !defined (__VG_PATTERN_H__) */
