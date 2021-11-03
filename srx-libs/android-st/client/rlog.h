/**
** Header-only logging mechanism.
**
** @author      Daniel Andrade
** @date        28 Nov 18
**/

#pragma once

//#include <stdio.h> // fprintf   (outside SGX)
#include <usgx/t/util.h> // if inside SGX... TODO guard to dected normal/secure

#define RLOG_FATAL      0x0002
#define RLOG_ERROR      0x0004
#define RLOG_WARNING    0x0008
#define RLOG_INFO       0x0010
#define RLOG_DEBUG      0x0020
#define RLOG_VERBOSE    0x0040
#define RLOG_TRACE      0x0080

#define RLOG_LOW        0x0100
#define RLOG_HIGH       0x0200

// Enabled when either RLOG or DEBUG are defined.
// Force disable with RLOG=0 (even when DEBUG is defined).
// Set max log level with `RLOG=<level>`, e.g. `-DRLOG=RLOG_VERBOSE`.
#if defined RLOG && RLOG == 0
	#define ENABLE_RLOG 0
	#define RLOG_LEVEL  0
#elif defined DEBUG
	#define ENABLE_RLOG 1
	#if defined RLOG && RLOG >= RLOG_FATAL && RLOG <= RLOG_TRACE
		#define RLOG_LEVEL RLOG
	#else
		#define RLOG_LEVEL RLOG_DEBUG
	#endif
#elif defined RLOG
	#define ENABLE_RLOG 1
	#if RLOG == 1
		#define RLOG_LEVEL RLOG_INFO
	#else
		#define RLOG_LEVEL RLOG
	#endif
#else
	#define ENABLE_RLOG 0
	#define RLOG_LEVEL  0
#endif

#define R(options, format, ...) \
		do { if (ENABLE_RLOG && (((options) & 0xfe) <= RLOG_LEVEL)) { \
			if (((options) & RLOG_HIGH) == RLOG_HIGH) { \
				fprintf(stderr, "[  RLOG  ]  " format "  [%s(-) at %s:%d][%s on %s]\n", ##__VA_ARGS__, __func__, __FILE__, __LINE__, __TIME__, __DATE__); \
			} else if (((options) & RLOG_LOW) == RLOG_LOW) { \
				fprintf(stderr, "[  RLOG  ]  " format "\n", ##__VA_ARGS__); \
			} else { \
				fprintf(stderr, "[  RLOG  ]  " format "  [%s]\n", ##__VA_ARGS__, __func__); \
			} \
		} } while (0)
