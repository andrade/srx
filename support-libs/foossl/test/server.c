#include <stdio.h>
#include <string.h>

#include "foossl_server.h"
#include "foossl_common.h"

#define BUF_SIZE 64

#define SRX_SERVER_PEM_PUB "/home/daniel/vc/srx/support-libs/foossl/tls/cert.pem"

static void handle_request(SSL *ssl)
{
	char buffer[BUF_SIZE] = "hello tiny world";
	//int br, bw;
	int n = 16; // forced read/write n, same as client; otherwise hangs/fails!

	/*bw = SSL_write(ssl, buffer, n);
	if (bw <= 0) {
		fprintf(stderr, "ssl_write: could not write\n");
		return;
	}*/
	if (foossl_write(ssl, buffer, n)) {
		fprintf(stderr, "could not write %d bytes\n", n);
		return;
	}
	printf("ssl write: %s\n", buffer);

	/*br = SSL_read(ssl, buffer, n);
	if (br <= 0) {
		fprintf(stderr, "ssl_read: could not read\n");
		return;
	}*/
	if (foossl_read(ssl, buffer, n)) {
		fprintf(stderr, "could not read %d bytes\n", n);
		return;
	}
	buffer[n] = '\0';
	printf("ssl read: %s\n", buffer);

	printf("end of handling client request.\n");
}

int main()
{
	struct foossl_server_st foossl;

	if (foossl_server_connect(&foossl, 4433)) {
		perror("connect: unable to create secure listening connection");
		foossl_server_destroy(&foossl);
		return -1;
	}

	while (1) {
		SSL *ssl = NULL;

		if (foossl_server_loop_acquire(&foossl, &ssl)) {
			perror("acquire: could not acquire client resources");
			continue;
		}

		handle_request(ssl);

		if (foossl_server_loop_release(ssl)) {
			perror("release: could not release client resources");
			continue;
		}
	}
	//TODO  maybe catch Ctrl+D to cleanly leave loop

	if (foossl_server_destroy(&foossl)) {
		perror("destroy: unable to destroy server resources");
		return -1;
	}

	return 0;
}
