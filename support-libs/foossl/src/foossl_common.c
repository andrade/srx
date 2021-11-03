#include <openssl/ssl.h>
#include <errno.h>

#include "debug.h"
#include "foossl_common.h"

//TODO  returning values for proper erro checking by caller, in particular of shutdown condition or statuses necessary for polling. This should return the same value returned by the SSL_read function on error, or total number of bytes written on success. The reason is that the caller may want to check for EOF or call SSL_get_error and company itself and for that needs proper return codes. (Returning zero on success makes it for easy functions, but complicates caller's life, so need to update this: could have complex version and 'foossl_easy_' one) // Another issue, is if someone sends read 0 bytes, then by returning total read we are actually returning 0 which makes caller think it is EOF? (Actually, caller is aware it sent a read request for zero bytes.)
//NOTE  Consider possibility to return actual error code.
int foossl_read(SSL *ssl, void *buffer, int n)
{
	int br, total;

	for (total = 0; total < n; total += br) {
		br = SSL_read(ssl, buffer + total, n - total);
		if (br <= 0) {
			int ssl_err = SSL_get_error(ssl, br);
			int sys_err = ssl_err == 5 ? errno : 0;
			LOG("ssl_read (%d, %d, %d)\n", br, ssl_err, sys_err);
			return ssl_err;
		}
	}
	LOG("total_r=%d\n", total);

	return 0;
}

int foossl_write(SSL *ssl, const void *buffer, int n)
{
	int bw, total;

	for (total = 0; total < n; total += bw) {
		bw = SSL_write(ssl, buffer + total, n - total);
		if (bw <= 0) {
			int ssl_err = SSL_get_error(ssl, bw);
			int sys_err = ssl_err == 5 ? errno : 0;
			LOG("ssl_write (%d, %d, %d)\n", bw, ssl_err, sys_err);
			return ssl_err;
		}
	}
	LOG("total_w=%d\n", total);

	return 0;
}

/*
** NOTE  A return of SSL_ERROR_ZERO_RETURN is considered an error because
**       the number of bytes n to read or write is not respected.
*/
