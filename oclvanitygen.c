﻿/*
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

#include <assert.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>

#include "oclengine.h"
#include "pattern.h"
#include "util.h"

const char *version = VANITYGEN_VERSION;
const int debug = 0;

void usage(const char *name) {
	// clang-format off
	fprintf(stderr,
		COLOR44
"oclVanitygen Cash %s" COLOR0 " (" OPENSSL_VERSION_TEXT ")\n"
"Usage: %s [-vcqk1NTS] [-d <device>] [-f <filename>|-] [<pattern>...]\n"
"Generates a Bitcoin Cash receiving address matching <pattern>, and outputs\n"
"the address and associated private key. The private key may be stored in a\n"
"safe location or imported into a wallet client to spend any balance\n"
"received on the address.\n"
"By default, <pattern> is interpreted as an exact prefix.\n"
"By default, if no device is specified, and the system has exactly one OpenCL\n"
"device, it will be selected automatically, otherwise if the system has\n"
"multiple OpenCL devices and no device is specified, an error will be\n"
"reported. To use multiple devices simultaneously, specify the -D option for\n"
"each device.\n"
"\n"
"Options:\n"
"-v            Verbose output\n"
"-c            Print conditions for a valid address prefix\n"
"              (i.e. alphabet) and quit\n"
"-q            Quiet output\n"
"-k            Keep pattern and continue search after finding a match\n"
"-1            Stop after first match\n"
"-T            Generate Bitcoin Cash testnet address\n"
"-P <pubkey>   Specify base public key for piecewise key generation\n"
"-p <platform> Select OpenCL platform\n"
"-d <device>   Select OpenCL device\n"
"-D <devstr>   Use OpenCL device, identified by device string\n"
"              Form: <platform>:<devicenumber>[,<options>]\n"
"              Example: 0:0,grid=1024x1024\n"
"-S            Safe mode, disable OpenCL loop unrolling optimizations\n"
"-w <worksize> Set work items per thread in a work unit\n"
"-t <threads>  Set target thread count per multiprocessor\n"
"-g <x>x<y>    Set grid size\n"
"-b <invsize>  Set modular inverse ops per thread\n"
"-V            Enable kernel/OpenCL/hardware verification (SLOW)\n"
"-f <file>     File containing list of patterns, one per line\n"
"              (Use \"-\" as the file name for stdin)\n"
"-o <file>     Write pattern matches to <file> in TSV format (readable)\n"
"-O <file>     Write pattern matches to <file> in CSV format\n"
"              (importable e.g. Excel)\n"
"-s <file>     Seed random number generator from <file>\n",
		version, name);
	// clang-format on
}

#define MAX_DEVS 32
#define MAX_FILE 4

int main(int argc, char **argv) {
	int testnet = 0;
	int addrtype = 0;
	int privtype = 128;
	int opt;
	int platformidx = -1, deviceidx = -1;
	char *seedfile = NULL;
	char **patterns, *pend;
	int verbose = 1;
	int npatterns = 0;
	int nthreads = 0;
	int worksize = 0;
	int nrows = 0, ncols = 0;
	int invsize = 0;
	int remove_on_match = 1;
	int only_one = 0;
	int verify_mode = 0;
	int safe_mode = 0;
	vg_context_t *vcp = NULL;
	vg_ocl_context_t *vocp = NULL;
	EC_POINT *pubkey_base = NULL;
	const char *result_file = NULL;
	const char *result_file_csv = NULL;
	char *devstrs[MAX_DEVS];
	int ndevstrs = 0;
	int opened = 0;

	FILE *pattfp[MAX_FILE], *fp;
	int npattfp = 0;
	int pattstdin = 0;

	int i;

	while ((opt = getopt(argc, argv,
			"vcqk1Tp:P:d:w:t:g:b:VSh?f:o:O:s:D:")) != -1) {
		switch (opt) {
		case 'v': verbose = 2; break;
		case 'c':
			fprintf(stderr, "%s\n",
				"Conditions:\n"
				"• The alphabet is "
				"023456789acdefghjklmnpqrstuvwxyz\n"
				"• The first character must be 'q' for "
				"standard addresses or 'p' "
				"for P2SH\n"
				"• The second character must be either 'p', "
				"'q', 'r' or 'z'.\n"
				"• The prefix must be lowercase and typed "
				"without the CashAddr "
				"prefix "
				"(e.g. no \"bitcoincash:\")\n");
			return 0;
		case 'q': verbose = 0; break;
		case 'k': remove_on_match = 0; break;
		case '1': only_one = 1; break;
		case 'T':
			privtype = 239;
			testnet = 1;
			break;
		case 'p': platformidx = atoi(optarg); break;
		case 'd': deviceidx = atoi(optarg); break;
		case 'w':
			worksize = atoi(optarg);
			if (worksize == 0) {
				fprintf(stderr, "Invalid work size '%s'\n",
					optarg);
				return 1;
			}
			break;
		case 't':
			nthreads = atoi(optarg);
			if (nthreads == 0) {
				fprintf(stderr, "Invalid thread count '%s'\n",
					optarg);
				return 1;
			}
			break;
		case 'g':
			nrows = 0;
			ncols = strtol(optarg, &pend, 0);
			if (pend && *pend == 'x') {
				nrows = strtol(pend + 1, NULL, 0);
			}
			if (!nrows || !ncols) {
				fprintf(stderr, "Invalid grid size '%s'\n",
					optarg);
				return 1;
			}
			break;
		case 'b':
			invsize = atoi(optarg);
			if (!invsize) {
				fprintf(stderr,
					"Invalid modular inverse size '%s'\n",
					optarg);
				return 1;
			}
			if (invsize & (invsize - 1)) {
				fprintf(stderr,
					"Modular inverse size must be "
					"a power of 2\n");
				return 1;
			}
			break;
		case 'V': verify_mode = 1; break;
		case 'S': safe_mode = 1; break;
		case 'D':
			if (ndevstrs >= MAX_DEVS) {
				fprintf(stderr,
					"Too many OpenCL devices (limit %d)\n",
					MAX_DEVS);
				return 1;
			}
			devstrs[ndevstrs++] = optarg;
			break;
		case 'P': {
			if (pubkey_base != NULL) {
				fprintf(stderr,
					"Multiple base pubkeys specified\n");
				return 1;
			}
			EC_KEY *pkey = vg_exec_context_new_key();
			pubkey_base = EC_POINT_hex2point(
				EC_KEY_get0_group(pkey), optarg, NULL, NULL);
			EC_KEY_free(pkey);
			if (pubkey_base == NULL) {
				fprintf(stderr, "Invalid base pubkey\n");
				return 1;
			}
			break;
		}
		case 'f':
			if (npattfp >= MAX_FILE) {
				fprintf(stderr,
					"Too many input files specified\n");
				return 1;
			}
			if (!strcmp(optarg, "-")) {
				if (pattstdin) {
					fprintf(stderr,
						"ERROR: stdin "
						"specified multiple times\n");
					return 1;
				}
				fp = stdin;
			} else {
				fp = fopen(optarg, "r");
				if (!fp) {
					fprintf(stderr,
						"Could not open %s: %s\n",
						optarg, strerror(errno));
					return 1;
				}
			}
			pattfp[npattfp] = fp;
			// pattfpi[npattfp] = caseinsensitive;
			npattfp++;
			break;
		case 'o':
			if (result_file) {
				fprintf(stderr,
					"Multiple TSV output files "
					"specified\n");
				return 1;
			}
			result_file = optarg;
			break;
		case 'O':
			if (result_file_csv) {
				fprintf(stderr,
					"Multiple CSV output files "
					"specified\n");
				return 1;
			}
			result_file_csv = optarg;
			break;
		case 's':
			if (seedfile != NULL) {
				fprintf(stderr,
					"Multiple RNG seeds specified\n");
				return 1;
			}
			seedfile = optarg;
			break;
		default: usage(argv[0]); return 1;
		}
	}

#if !defined(_WIN32)
	if (!seedfile) {
		struct stat st1;
		if (stat("/dev/urandom", &st1) == 0) {
			seedfile = (char *) "/dev/urandom";
		}
	}
#endif

	if (seedfile) {
		opt = -1;
#if !defined(_WIN32)
		{
			struct stat st;
			if (!stat(seedfile, &st) &&
				(st.st_mode & (S_IFBLK | S_IFCHR))) {
				opt = 32;
			}
		}
#endif
		opt = RAND_load_file(seedfile, opt);
		if (!opt) {
			fprintf(stderr, "Could not load RNG seed %s\n", optarg);
			return 1;
		}
		if (verbose > 0 && strcmp(seedfile, (char *) "/dev/urandom")) {
			fprintf(stderr, "Read %d bytes from RNG seed file\n",
				opt);
		}
	}


	vcp = vg_prefix_context_new(addrtype, privtype, testnet);

	if (result_file) {
		FILE *fp = fopen(result_file, "a");
		if (!fp) {
			fprintf(stderr,
				"ERROR: could not open TSV result file: %s\n",
				strerror(errno));
			return 1;
		} else {
			fprintf(fp, "Pattern\tAddress\t");
			if (pubkey_base == NULL)
				fprintf(fp, "Private Key\n");
			else
				fprintf(fp, "Private Key Part\n");
			fclose(fp);
		}
	}

	if (result_file_csv) {
		FILE *fp = fopen(result_file_csv, "a");
		if (!fp) {
			fprintf(stderr,
				"ERROR: could not open CSV result file: %s\n",
				strerror(errno));
			return 1;
		} else {
			fprintf(fp, "Pattern\tAddress\t");
			if (pubkey_base == NULL)
				fprintf(fp, "Private Key\n");
			else
				fprintf(fp, "Private Key Part\n");
			fclose(fp);
		}
	}

	vcp->vc_verbose = verbose;
	vcp->vc_result_file = result_file;
	vcp->vc_result_file_csv = result_file_csv;
	vcp->vc_remove_on_match = remove_on_match;
	vcp->vc_only_one = only_one;
	vcp->vc_addrtype = addrtype;
	vcp->vc_pubkey_base = pubkey_base;

	vcp->vc_output_match = vg_output_match_console;
	vcp->vc_output_timing = vg_output_timing_console;

	if (!npattfp) {
		if (optind >= argc) {
			usage(argv[0]);
			return 1;
		}
		patterns = &argv[optind];
		npatterns = argc - optind;

		if (!vg_context_add_patterns(
			    vcp, (const char **) patterns, npatterns))
			return 1;
	}

	for (i = 0; i < npattfp; i++) {
		fp = pattfp[i];
		if (!vg_read_file(fp, &patterns, &npatterns)) {
			fprintf(stderr, "Failed to load pattern file\n");
			return 1;
		}
		if (fp != stdin) fclose(fp);

		if (!vg_context_add_patterns(
			    vcp, (const char **) patterns, npatterns))
			return 1;
	}

	if (!vcp->vc_npatterns) {
		fprintf(stderr, "No patterns to search\n");
		return 1;
	}

	if (ndevstrs) {
		for (opt = 0; opt < ndevstrs; opt++) {
			vocp = vg_ocl_context_new_from_devstr(
				vcp, devstrs[opt], safe_mode, verify_mode);
			if (!vocp) {
				fprintf(stderr,
					"Could not open device '%s', "
					"ignoring\n",
					devstrs[opt]);
			} else {
				opened++;
			}
		}
	} else {
		vocp = vg_ocl_context_new(vcp, platformidx, deviceidx,
			safe_mode, verify_mode, worksize, nthreads, nrows,
			ncols, invsize);
		if (vocp) opened++;
	}

	if (!opened) {
		vg_ocl_enumerate_devices();
		return 1;
	}

	opt = vg_context_start_threads(vcp);
	if (opt) return 1;

	vg_context_wait_for_completion(vcp);
	vg_ocl_context_free(vocp);
	return 0;
}
