#ifndef _EPT_QRC_H
#define _EPT_QRC_H

#include <stddef.h>

/**
 * Create a QR code PNG image from the string.
 *
 * @param str    the NULL-terminated string
 * @param buf    the destination buffer for the PNG image
 * @param size   the size of the buffer
 * @return       zero on success
 */
int string_to_qrc_png(const char *str, char **buf, size_t *size);

// int bytes_to_qrc_png(char **buf, size_t *size, const unsigned char *data_in, int size_in);

/**
 * Create a QR code PNG image from a byte buffer.
 *
 * @param data   input data
 * @n            size of the input data
 * @param buf    the destination buffer for the PNG image
 * @param size   the size of the buffer
 * @return       zero on success
 */
// int buffer_to_qrc_png(const unsigned char *data, int n, char **buf, size_t *size);

#endif
