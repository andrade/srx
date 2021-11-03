#include <stdio.h>

#include <foossl_client.h>
#include <foossl_common.h>
#include <openssl/ssl.h>

//#include "srx_u.h"
# include "network.h"

#define BUF_SIZE 8192

static struct foossl_client_st foossl;

int server_connect()
{
	return foossl_client_connect(&foossl, "localhost", 4433);
}

int server_exchange_data(const void *data_in, size_t size_in,
		void *data_out, size_t *size_out)
{
	if (size_in > 32767) {
		//err: foossl_write uses `int`
		return 1;
	}

	if (foossl_write(foossl.ssl, &size_in, 4)) {
		fprintf(stderr, "could not write size\n");
		return 2;
	}
	printf("ssl write size: %zu\n", size_in);

	if (foossl_write(foossl.ssl, data_in, size_in)) {
		fprintf(stderr, "could not write %zu bytes\n", size_in);
		return 3;
	}

	int n = 0;

	if (foossl_read(foossl.ssl, &n, 4)) {
		fprintf(stderr, "could not read size\n");
		return 4;
	}
	printf("ssl read size: %d\n", n);

	if ((size_t) n > *size_out) {
		fprintf(stderr, "output buffer has insufficient size (%d vs %zu)", n, *size_out);
		return 5;
	}
	*size_out = n;

	if (foossl_read(foossl.ssl, data_out, n)) {
		fprintf(stderr, "could not read %d bytes\n", n);
		return 6;
	}

	return 0;
}

int server_disconnect()
{
	SSL_shutdown(foossl.ssl);
	return foossl_client_destroy(&foossl);
}

int server_io(const void *data_in, size_t size_in,
		void *data_out, size_t size_out, size_t *bytes_read)
{
	int result = server_exchange_data(data_in, size_in, data_out, &size_out);
	*bytes_read = size_out;
	return result;
}
