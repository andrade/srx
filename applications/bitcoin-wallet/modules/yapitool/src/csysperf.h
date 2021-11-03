// Copyright 2019 Daniel Andrade

// version: 0.3.1

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
extern char *csp_strs[CSP_LAST];
#else
struct csp_node {
	int id;
	int pos;
	struct timespec tp;
};
struct csp_node csp_nodes[CSP_CAPACITY + 1] = {[CSP_CAPACITY] = {.pos = -999}};
size_t csp_next = 0;
char *csp_strs[CSP_LAST] = {
	[MICRO] = "microbench",
	[MAIN] = "MAIN",
};
#endif
////////////////////////////////////////////////////////////////////////

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

#define CSP_POKE(id_x, pos_x) do {                                    \
	csp_nodes[csp_next].id = (id_x);                                  \
	csp_nodes[csp_next].pos = (pos_x);                                \
	clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &csp_nodes[csp_next].tp); \
	csp_next++;                                                       \
} while (0)

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
