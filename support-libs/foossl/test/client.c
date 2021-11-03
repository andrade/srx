#include <stdio.h>
#include <string.h>

#include "foossl_client.h"
#include "foossl_common.h"

#define BUF_SIZE 64

//TODO  Update Makefile and structure to have src/client and include/client and same for server since these should be separate. Still maintain client/server word in header because for some reason a dev may want to use both on same file and it would cause problems if they were both name the same.

//NOTE  this was the intiial version to test TLS, real one for SGX is below
static int test(SSL *ssl)
{
	char buffer[BUF_SIZE];
	//int br, bw;
	int n = 16; // amount of bytes to read (either reads n or returns error)

	/*br = SSL_read(ssl, buffer, BUF_SIZE - 1);
	if (br <= 0) {
		fprintf(stderr, "could not read\n");
		return -1;
	}*/
	if (foossl_read(ssl, buffer, n)) {
		fprintf(stderr, "could not read %d bytes\n", n);
		return -1;
	}
	buffer[n] = '\0';
	printf("ssl read: %s\n", buffer);

	strcpy(buffer, "client says hello");

	/*bw = SSL_write(ssl, buffer, 17);
	if (bw <= 0) {
		fprintf(stderr, "could not write\n");
		return -1;
	}*/
	if (foossl_write(ssl, buffer, n)) {
		fprintf(stderr, "could not write %d bytes\n", n);
		return -1;
	}
	printf("ssl write: %s\n", buffer);

	return 0;
}

int main()
{
	struct foossl_client_st foossl;

	if (foossl_client_connect(&foossl, "localhost", 4433)) {
		perror("unable to open secure connection to remote server");
		foossl_client_destroy(&foossl);
		return -1;
	}

	if (test(foossl.ssl))
		fprintf(stderr, "test error\n");

	SSL_shutdown(foossl.ssl);
	if (foossl_client_destroy(&foossl)) {
		perror("unable to close secure connection to remote server");
		return -1;
	}

	return 0;
}
