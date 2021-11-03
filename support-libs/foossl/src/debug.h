#ifndef DEBUG_H
#define DEBUG_H

#ifdef DEBUG
#define LOG(...) fprintf(stderr, "[DEBUG] " __VA_ARGS__)
#else
#define LOG(...) \
		do { if (0) fprintf(stderr, "[DEBUG] " __VA_ARGS__); } while (0)
		/* do nothing but still validate macro */
#endif

#endif
