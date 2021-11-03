// Copyright 2019 Daniel Andrade

// version: 0.3.1

/**
** csysperf.h:
**
** Using:
**         1. Update the IDs on the enum; but leave CSP_LAST intact
**         2. Update the human-readable versions of the IDs on the array
**         3. Define CSP_INIT in a single source file, and before the include
**         4. Invoke CSP_POKE(id, pos) in key locations on the code
**         5. Produce a report with CSP_REPORT(x) where x is 0 or 1
**
** On/off:
**         Compile with the flag `-DCSP_ENABLED` to enable csysperf.
**         Disable with `-UCSP_ENABLED`. Flag absence implies disabled.
**         (Compiling with `-DCSP_ENABLED=X` where X is 0/1 also works.)
**
** NOTE: Report prints the intervals in the order they appear in source code.
**
** NOTE: When an ID declared on the enum is not called by CSP_POKE
** then its time is set to the default value of zero. This affects
** the CSP_REPORT. The intervals where either side is zero are not shown.
**
** NOTE: The more nested calls, N, an interval has the less accurate the
** overhead removal operation is (because multiplies N by per-call overhead).
**
** ISSUES: Warnings shown during compilation when CSP_INIT not invoked:
**     `undefined reference to `csp_next'`
**     `undefined reference to `csp_nodes'`
** When CSP_INIT is invoked more than once, the warnings are:
**     `multiple definition of `csp_nodes'`
**     `multiple definition of `csp_next'`
**     `multiple definition of `csp_strs'`
**/
#pragma once

#if !(CSP_ENABLED)
// API becomes no-op
#define CSP_POKE(id, pos) do {} while(0)
#define CSP_REPORT(option) do {} while(0)
#else

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <time.h>

////////////////////////////////////////////////////////////////////////
//////////////////////////// change it here ////////////////////////////
enum {
	MICRO = 0,
	MAIN,
	ENCLAVE_C,
	ENCLAVE_D,
	// SERVER_C,
	// SERVER_D,
	INIT_DB_N_SAVE_FUNC,
	LOAD_N_ADD_ENTRY_N_SAVE_FUNC,
	LOAD_N_LIST_ALL_FUNC,
	LOAD_N_LIST_ID_FUNC,
	DB_GET_ONE,
	DB_INTEGRITY_CHECK,
	S3_EXEC,
	ADD_ENTRY_OP_INSERT_QUERY,
	LIST_ALL_OP_SELECT_QUERY,
	LIST_ONE_OP_SELECT_QUERY,
	COMPUTE_SECRET,
	LOAD_DATA,
	SAVE_DATA,
	DB_OPEN,
	DB_CLOSE,
	DB_LOAD,
	DB_SAVE,
	CSP_LAST // CSP_LAST is the length of the array; leave it in this position
};

#define CSP_CAPACITY (CSP_LAST + 150)  // increase to support more entries

#ifndef CSP_INIT
struct csp_node {
	int id;
	int pos;
	struct timespec tp;
};
extern struct csp_node csp_nodes[CSP_CAPACITY + 1];
extern size_t csp_next;
// extern struct timespec csp_tp[2][CSP_LAST]; // [0][] begin, [1][] end
extern char *csp_strs[CSP_LAST];
#else
struct csp_node {
	int id;
	int pos;
	struct timespec tp;
};
struct csp_node csp_nodes[CSP_CAPACITY + 1] = {[CSP_CAPACITY] = {.pos = -999}};
size_t csp_next = 0;
// struct timespec csp_tp[2][CSP_LAST] = {0};
char *csp_strs[CSP_LAST] = {
	[MICRO] = "microbench", // No nested, and use inner loop.
	[MAIN] = "main() · MAIN",
	"create_enclave() · ENCLAVE_C",
	"destroy_enclave() · ENCLAVE_D",
	// "server_connect()",
	// "server_disconnect()",
	"init_database() · INIT_DB_N_SAVE_FUNC",
	"add_new_entry() · LOAD_N_ADD_ENTRY_N_SAVE_FUNC",
	"list_all() · LOAD_N_LIST_ALL_FUNC",
	"list_by_id() · LOAD_N_LIST_ID_FUNC",
	[DB_GET_ONE] = "DB_GET_ONE · db_get_entry_by_id",
	"DB integrity check · DB_INTEGRITY_CHECK",
	[S3_EXEC] = "S3_EXEC · sqlite3_exec",
	"ADD insert query · ADD_ENTRY_OP_INSERT_QUERY",
	"LIST ALL select query · LIST_ALL_OP_SELECT_QUERY",
	"LIST ONE select query · LIST_ONE_OP_SELECT_QUERY",
	"compute_srx_secret() · COMPUTE_SECRET",
	[LOAD_DATA] = "LOAD_DATA · titan_load_data",
	[SAVE_DATA] = "SAVE_DATA · titan_save_data",
	[DB_OPEN] = "DB_OPEN · db_open",
	[DB_CLOSE] = "DB_CLOSE · db_close",
	[DB_LOAD] = "DB_LOAD · db_load",
	[DB_SAVE] = "DB_SAVE · db_save",
};
#endif
////////////////////////////////////////////////////////////////////////

/*
#define CSP_RESET() do {                                 \
	for (size_t i = 0; i < csp_next; i++) {              \
		csp_nodes[i].id = 0;                             \
		csp_nodes[i].pos = 0;                            \
		csp_nodes[i].tp.tv_sec = 0;                      \
		csp_nodes[i].tp.tv_nsec = 0;                     \
	}                                                    \
	csp_next = 0;                                        \
} while (0)
*/

// Returns true if x (of type struct csp_node *) is null.
#define CSP_NULL(x) __extension__({                             \
	struct csp_node *node = x;                                  \
	int b0 = node->id == 0 && node->pos == 0;                   \
	int b1 = (node->tp).tv_sec == 0 && (node->tp).tv_nsec == 0; \
	b0 && b1;                                                   \
})

// Computes the difference between two time points.
// struct timespec *y [in] time taken at end of interval
// struct timespec *x [in] time taken at beginning of interval
// Return type: struct timespec
#define CSP_DIFF(y, x) __extension__({     \
	struct timespec *end = y;              \
	struct timespec *begin = x;            \
	struct timespec result;                \
                                           \
	if (begin->tv_nsec > end->tv_nsec) {                               \
		result.tv_nsec = (1000000000 - begin->tv_nsec) + end->tv_nsec; \
		result.tv_sec = (end->tv_sec - begin->tv_sec) - 1;             \
	} else {                                                           \
		result.tv_nsec = end->tv_nsec - begin->tv_nsec;                \
		result.tv_sec = end->tv_sec - begin->tv_sec;                   \
	}           \
                \
	result;     \
})

// macro to mark time; can disable macro so it doesn't affect code
// Invoke with interval ID, and with position 0 for begin and 1 for end.
// int id_x [in] the ID of the interval
// int pos_x [in] position 0 for begin interval, and position 1 to end interval
#define CSP_POKE(id_x, pos_x) do {                                    \
	csp_nodes[csp_next].id = (id_x);                                  \
	csp_nodes[csp_next].pos = (pos_x);                                \
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &csp_nodes[csp_next].tp); \
	csp_next++;                                                       \
} while (0)
// clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &csp_tp[pos][id]);

// computes approximate overhead of a single invocation of `clock_gettime()`
// long *ld [out] destination for overhead in nanoseconds
#define CSP_CLOCK_OVERHEAD(ld) do {                      \
	long *p = ld;                                        \
	size_t reps = 100000;                                \
	struct timespec t0 = {0};                            \
	struct timespec t1 = {0};                            \
	struct timespec temp = {0};                          \
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t0);        \
	for (size_t i = 0; i < reps; i++) {                  \
		clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &temp);  \
	}                                                    \
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &t1);        \
	*p = (t1.tv_nsec - t0.tv_nsec) / (long) reps;        \
} while (0)

/*
// // int *result [out] destination of result, -1 if x<y, 0 if equal, 1 if x>y
// // struct timespec *x [in]
// // struct timespec *y [in]
// #define CSP_COMPARE(result, x, y) do {            \
// 	struct timespec *xp = x;                      \
// 	struct timespec *yp = y;                      \
// 	if (xp->tv_sec < yp->tv_sec) {                \
// 		*result = -1;                             \
// 	} else if (xp->tv_sec > yp->tv_sec) {         \
// 		*result = 1;                              \
// 	} else {                                      \
// 		if (xp->tv_nsec < yp->tv_nsec) {          \
// 			*result = -1;                         \
// 		} else if (xp->tv_nsec > yp->tv_nsec) {   \
// 			*result = 1;                          \
// 		} else {                                  \
// 			*result = 0;                          \
// 		}                                         \
// 	}                                             \
// } while (0)
//
// // counts number of nested calls between t0 and t1 where t0<t1
// // count is int pointer, t0/t1 are pointer to struct timespec
// // result placed in count
// #define CSP_COUNT_NESTED(count, t0, t1) do {      \
// 	*count = 0;                                   \
// 	struct timespec *x = t0;                      \
// 	struct timespec *y = t1;                      \
// 	int a, b;                                     \
// 	for (size_t i = 0; i < CSP_LAST; i++) {       \
// 		for (size_t pos = 0; pos < 2; pos++) {    \
// 			CSP_COMPARE(&a, &csp_tp[pos][i], x);  \
// 			CSP_COMPARE(&b, &csp_tp[pos][i], y);  \
// 			if (a > 0 && b < 0) {                 \
// 				(*count)++;                       \
// 			}                                     \
// 		}                                         \
// 	}                                             \
// } while (0)

// // DEPRECATED
// // sort array before reporting
// #define CSP_SORT() do {                                                \
// 	int swapped = 0;                                                   \
// 	do {                                                               \
// 		swapped = 0;                                                   \
// 		for (size_t i = 0; i < CSP_LAST - 1; i++) {                    \
// 			struct timespec tp = CSP_DIFF(&csp_tp[i+1], &csp_tp[i]);   \
// 			if (tp.tv_sec < 0 || tp.tv_nsec < 0) {                     \
// 				struct timespec tmp = {0};                             \
// 				tmp.tv_sec = csp_tp[i].tv_sec;                         \
// 				tmp.tv_nsec = csp_tp[i].tv_nsec;                       \
// 				csp_tp[i].tv_sec = csp_tp[i+1].tv_sec;                 \
// 				csp_tp[i].tv_nsec = csp_tp[i+1].tv_nsec;               \
// 				csp_tp[i+1].tv_sec = tmp.tv_sec;                       \
// 				csp_tp[i+1].tv_nsec = tmp.tv_nsec;                     \
// 				char *s = csp_strs[i];                                 \
// 				csp_strs[i] = csp_strs[i+1];                           \
// 				csp_strs[i+1] = s;                                     \
// 				swapped = 1;                                           \
// 			}                                                          \
// 		}                                                              \
// 	} while (swapped);                                                 \
// } while (0)
*/

// Prints a report.
// When option is 0, prints with raw values. When option is 1,
// there is an attempt at removing overhead before printing.
// int option [in] set to 1 to attempt to reduce overhead of nested calls
#define CSP_REPORT(option) do {                                       \
	if (csp_nodes[CSP_CAPACITY].pos != -999) {                         \
		printf("dead canary: more pokes than capacity\n");             \
		break;                                                         \
	}                                                                  \
	int opt = option;                                                 \
	long overhead = 0;                                                \
	CSP_CLOCK_OVERHEAD(&overhead);                                    \
	printf("------------ time in seconds ------------\n");            \
	int done[CSP_CAPACITY] = {0};                                     \
	for (size_t i = 0; i < CSP_CAPACITY - 1; i++) {                   \
		struct csp_node *node0 = &csp_nodes[i];                       \
		if (done[i] || node0->pos != 0) {                             \
			continue;                                                 \
		}                                                             \
		struct csp_node *node1 = NULL;                                \
		size_t end = i;                                               \
		int found = 0;                                                \
		while (++end < CSP_CAPACITY) {                                \
			if (done[end]) {                                          \
				continue;                                             \
			}                                                         \
			node1 = &csp_nodes[end];                                  \
			int b0 = node0->id == node1->id;                          \
			int b2 = node1->pos == 1;                                 \
			if (b0 && b2) {                                           \
				found = 1;                                            \
				break;                                                \
			}                                                         \
		}                                                             \
		if (found) {                                                        \
			struct timespec result = CSP_DIFF(&node1->tp, &node0->tp);      \
			long long secs = result.tv_sec;                                 \
			long nsecs = result.tv_nsec;                                    \
			if (opt == 1) {                                           \
				int count = end - i - 1;                              \
				long total_overhead = overhead * count;     \
				if (nsecs - total_overhead > 0) {           \
					nsecs -= total_overhead;                \
				} else {                                    \
					secs -= 1;                              \
					nsecs += (1000000000 - total_overhead); \
				}                                           \
				printf("%4lld.%.9ld [%s](%d)\n",                  \
						secs, nsecs, csp_strs[node0->id], count); \
			} else {                                                  \
				printf("%4lld.%.9ld [%s]\n",                      \
						secs, nsecs, csp_strs[node0->id]);        \
			}                                                         \
			done[i] = 1;                                                    \
			done[end] = 1;                                                  \
		}                                                                   \
	}                                                                 \
	printf("------ poke overhead: %.9ld ns ------\n", overhead);      \
} while (0)
// When report called with `1`, then we remove the poke overhead:
// the number of «nested calls» is computed, and
// «poke overhead» times «nested calls» is removed.
// Invoke report with 0 to print raw results; overhead per call still shown.

// Prints the main data structure to stdout (except null entries).
#define CSP_DUMP() do {                                                     \
	printf("-------- dump data structure --------\n");                      \
	for (size_t i = 0; i < CSP_CAPACITY && !CSP_NULL(&csp_nodes[i]); i++) { \
		struct csp_node *node = &csp_nodes[i];                              \
		printf("%30s (%d), %d\n", csp_strs[node->id], node->id, node->pos); \
	}                                                                       \
	printf("-------------------------------------\n");                      \
} while (0)

#endif /* CSP_ENABLED */
