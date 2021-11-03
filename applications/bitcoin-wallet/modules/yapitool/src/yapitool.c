#define _GNU_SOURCE
#include <getopt.h>

#define CSP_INIT
#include "csysperf.h"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>

// #include "btc/utils.h"

#include <yapi.h>

#include "cmd_ui.h"

static void print_hex(uint8_t *a, uint32_t len)
{
	printf("uint8_t/hex (len=%"PRIu32"):\n", len);
	for (uint32_t i = 0; i < len - 1; i++)
		printf("%02"PRIx8":", a[i]);
	printf("%02"PRIx8"\n", a[len - 1]);
}

//----------------------------------------------------------------------
//
// (1) Derive address to receive funds from testnet faucet
// $ ./yapitool --derive --path hw.db --dp "m/44'/1'/0'/0/75"
// m/44'/1'/0'/0/75  ⇝  muc3ytRa7e8AL5TyAH3wepkgRFa29gi3qF
// Ref txid: a9bfff0447a8ab6be24b0a2b2999bcc361768ae1273963130ea7e05f90640d8d
//
// (2) Sign tx with change (returns funds to testnet faucet, and keeps rest as change); broadcast to testnet
// $ ./yapitool --t1 --input-prev a9bfff0447a8ab6be24b0a2b2999bcc361768ae1273963130ea7e05f90640d8d --input-index 0 --input-dp "m/44'/1'/0'/0/75" --input-amount 000010000 --output-addr 2N8hwP1WmJrFF5QWABn38y63uYLhnJYJYTF --output-amount 000007000 --change-dp "m/44'/1'/0'/1'/350'" --change-amount 000003000 --path hw.db
// Ref txid: 8dd163fb1faec2d1ceaa8de3158cb4805e4311f5b6332d2213d362eddf045969
//
// (3) Sign tx with change (returns funds to testnet faucet, and keeps some change; plus leave some funds for mining fee); broadcast to testnet
// $ ./yapitool --t1 --input-prev a9bfff0447a8ab6be24b0a2b2999bcc361768ae1273963130ea7e05f90640d8d --input-index 0 --input-dp "m/44'/1'/0'/0/75" --input-amount 000010000 --output-addr 2N8hwP1WmJrFF5QWABn38y63uYLhnJYJYTF --output-amount 000007000 --change-dp "m/44'/1'/0'/1/75" --change-amount 000000015 --path hw.db
// Ref txid: b7671f98d53e8c9d28aca36ac6aad604e74c243baf10fe98199525e6330f4225
// Warn msg: "WARNING: This transaction had an attempted double-spent by 8dd163fb1faec2d1ceaa8de3158cb..., but was still confirmed."
//
// (4) Compute change address (received 000000015, i.e. 0.00000015 BTC)
// $ ./yapitool --derive --path hw.db --dp "m/44'/1'/0'/1/75"
// m/44'/1'/0'/1/75  ⇝  n3499kDcgNTLDWCw7e7oo2iaKqLG6PVHgH
// Ref: check address in a testnet block explorer, will have 0.00000015 BTC
//
//----------------------------------------------------------------------

static uint64_t str2u64(const char *s)
{
	errno = 0;
	char *endptr = NULL;

	unsigned long long int ull = strtoull(s, &endptr, 0);

	if (errno || ull > UINT64_MAX) {
		abort();
	}
	if (s == endptr) {
		fprintf(stderr, "`%s` is not a number\n", s);
		abort();
	}

	return (uint64_t) ull;
}

static void help()
{
	static const char *s =
			"\n"
			"SYNOPSIS\n"
			"    yapitool [command] [arguments]\n"
			"\n"
			"COMMANDS\n"
			"    --init          "
			"--path <path>       "
			"Initialize new wallet\n"
			"\n"
			"    --derive        "
			"--path <path>       "
			"Derive a new address for receiving funds\n"
			"                    --dp <derivation path>\n"
			"\n"
			"    --t1            "
			"--path <path>       "
			"Create and sign transaction\n"
			"                    --input-prev <hash>\n"
			"                    --input-index <index>\n"
			"                    --input-dp <derivation path>\n"
			"                    --input-amount <amount>\n"
			"                    --output-addr <address>\n"
			"                    --output-amount <amount>\n"
			"                   [--change-dp <derivation path>\n"
			"                    --change-amount <amount>]\n"
			"\n"
			"    The command --t1 creates and signs in one step.\n"
			"    The change is optional and goes to an internal address.\n"
			"\n"
			"GROUP MANAGEMENT\n"
			"    --platform-init   --platform-path <destination>\n"
			"\n"
			"    --platform-add    --path <path> --platform-path <source>\n"
			"\n"
			"    --platform-remove --path <path> --platform-id <pid>\n"
			"\n"
			"    --platform-list   --path <path>\n"
			"\n"
			"    These four commands are for managing the group of platforms.\n"
			"\n"
			"    The commands are for, respectively, initializing a\n"
			"    new platform, adding that platform to the group,\n"
			"    removing a platform, and listing all platforms in the group.\n"
			"\n"
			"    A platform saves a bundle to disk during initialization.\n"
			"    This data bundle is then loaded during `--platform-add`.\n"
			"\n"
			"";

	printf("%s", s);
}


// int main_two(int argc, char **argv);
// int main(int argc, char **argv)
// {
// 	for (size_t i = 0; i < 100; i++) {
// 		optind = 1;
// 		main_two(argc, argv);
// 	}
// 	CSP_POKE(MICRO, 0);
// 	for (size_t i = 0; i < 500; i++) {
// 		optind = 1;
// 		main_two(argc, argv);
// 	}
// 	CSP_POKE(MICRO, 1);
// 	CSP_REPORT(0);
// }
// int main_two(int argc, char **argv)
int main(int argc, char **argv)
{
	// CSP_POKE(MAIN, 0);

	// BEGIN APPLICATION -----------------------------------------------

	int is_init = 0;

	int is_derive = 0;
	int is_new_tx = 0;
	int is_sign_tx = 0;
	int is_t1 = 0;

	int group_command = 0;

	int is_help = 0;

	char *path = NULL;
	char *tx = NULL;
	char *dp = NULL;

	char *input_prev = NULL;
	int input_index = -1;
	char *input_dp = NULL;
	long input_amount = -1;
	char *output_addr = NULL;
	long output_amount = -1;
	char *change_dp = NULL;
	long change_amount = -1;

	char *platform_path = NULL;
	uint64_t platform_id = -1;

	const struct option longopts[] = {
		{"init", no_argument, &is_init,  1},

		{"derive", no_argument, &is_derive,  1},
		{"new",    no_argument, &is_new_tx,  1},  // not used
		{"sign",   no_argument, &is_sign_tx, 1},  // not used
		{"t1",     no_argument, &is_t1,      1},  // simple tx

		{"platform-init",   no_argument, &group_command, 1},
		{"platform-add",    no_argument, &group_command, 2},
		{"platform-remove", no_argument, &group_command, 3},
		{"platform-list",   no_argument, &group_command, 4},

		{"help",   no_argument, &is_help,    1},

		{"path",  required_argument, NULL, 'p'},  // data path
		{"tx",    required_argument, NULL, 't'},  // encoded transaction
		{"dp",    required_argument, NULL, 'd'},  // derivation path

		{"input-prev",    required_argument, NULL, 'H'},
		{"input-index",    required_argument, NULL, 'N'},
		{"input-dp",    required_argument, NULL, 'I'},
		{"input-amount",    required_argument, NULL, 'X'},
		{"output-addr",    required_argument, NULL, 'O'},
		{"output-amount",    required_argument, NULL, 'Y'},
		{"change-dp",    required_argument, NULL, 'C'},
		{"change-amount",    required_argument, NULL, 'Z'},

		{"platform-id",   required_argument, NULL, 'D'},  // PID
		{"platform-path", required_argument, NULL, 'T'},  // new platform path

		{0, 0, 0, 0}
	};
	const char optstring[] = "dns";
	int longindex = 0;
	int c;

	do {
		c = getopt_long(argc, argv, optstring, longopts, &longindex);

		switch (c) {
		case 'p':
			path = optarg;
			printf("data path: %s\n", path);
			break;
		case 't':
			tx = optarg;
			printf("tx: %s\n", tx);
			break;
		case 'd':
			dp = optarg;
			printf("dp: %s\n", dp);
			break;
		case 'H':
			input_prev = optarg;
			printf("input_prev: %s\n", input_prev);
			break;
		case 'N':
			input_index = atoi(optarg);
			printf("input_index: %d\n", input_index);
			break;
		case 'I':
			input_dp = optarg;
			printf("input_dp: %s\n", input_dp);
			break;
		case 'X':
			input_amount = atol(optarg);
			printf("input_amount: %ld\n", input_amount);
			break;
		case 'O':
			output_addr = optarg;
			printf("output_addr: %s\n", output_addr);
			break;
		case 'Y':
			output_amount = atol(optarg);
			printf("output_amount: %ld\n", output_amount);
			break;
		case 'C':
			change_dp = optarg;
			printf("change_dp: %s\n", change_dp);
			break;
		case 'Z':
			change_amount = atol(optarg);
			printf("change_amount: %ld\n", change_amount);
			break;
		case 'D':
			platform_id = str2u64(optarg);
			printf("platform_id: %#018"PRIx64"\n", platform_id);
			break;
		case 'T':
			platform_path = optarg;
			printf("platform_path: %s\n", platform_path);
			break;
		case '?':
		default:
			break;
		}
	} while (-1 != c);

	if (is_t1) {
		if (!path) {
			fprintf(stderr, "missing path: --t1 ...\n");
			return 1;
		}
		if (!input_prev) {
			fprintf(stderr, "missing input_prev: --t1 ...\n");
			return 1;
		}
		if (!input_dp) {
			fprintf(stderr, "missing input_dp: --t1 ...\n");
			return 1;
		}
		// // bench, warm up
		// for (size_t i = 0; i < 100; i++) {
		// 	tx_t1(path, input_prev, input_index, input_dp, input_amount,
		// 			output_addr, output_amount, change_dp, change_amount);
		// }
		// CSP_POKE(MICRO, 0);
		// for (size_t i = 0; i < 500; i++) {
		// 	tx_t1(path, input_prev, input_index, input_dp, input_amount,
		// 			output_addr, output_amount, change_dp, change_amount);
		// }
		// CSP_POKE(MICRO, 1);
		// // bench, result x500: 33.807405867 [microbench]
		tx_t1(path, input_prev, input_index, input_dp, input_amount,
				output_addr, output_amount, change_dp, change_amount);
	} else if (is_derive) {
		if (!path) {
			fprintf(stderr, "missing path: --derive --path <path> --dp <dp>\n");
			return 1;
		}
		if (!dp) {
			fprintf(stderr, "missing dp: --derive --path <path> --dp <dp>\n");
			return 1;
		}
		// // bench, warm up
		// for (size_t i = 0; i < 100; i++) {
		// 	yt_derive_address(path, dp);
		// }
		// CSP_POKE(MICRO, 0);
		// for (size_t i = 0; i < 500; i++) {
		// 	yt_derive_address(path, dp);
		// }
		// CSP_POKE(MICRO, 1);
		// // bench, result x500: 32.363308786 [microbench]
		yt_derive_address(path, dp);
	} else if (is_init) {
		if (!path) {
			fprintf(stderr, "missing path: --init --path <path>\n");
			return 1;
		}
		yt_init_wallet(path);
	} else if (group_command) {
		switch (group_command) {
		case 1:
			yt_platform_init(platform_path);
			break;
		case 2:
			yt_platform_add(path, platform_path);
			break;
		case 3:
			yt_platform_remove(path, platform_id);
			break;
		case 4:
			yt_platform_list(path);
			break;
		}
	} else {
		help();
	}

	// END APPLICATION -------------------------------------------------

	// CSP_POKE(MAIN, 1);
	// CSP_REPORT(0);

	return 0;
}
