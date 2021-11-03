#define _POSIX_C_SOURCE 201112L

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "foossl_server.h"

#define SRX_SERVER_PEM_PRIV "/home/daniel/vc/srx/support-libs/foossl/tls/key.pem"
#define SRX_SERVER_PEM_PUB "/home/daniel/vc/srx/support-libs/foossl/tls/cert.pem"

/**
** Creates a plain socket and marks it as a passive socket.
**
** Returns a file descriptor for the passive socket on success, and
** returns -1 on error.
**/
static int socket_connect(int port)
{
	int sfd = -1;
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	char service[sizeof(port) + 1];
	int ret;

	// convert port (see getaddrinfo(3))
	if (snprintf(service, sizeof(service), "%d", port) < 0) {
		return -1;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;
	hints.ai_protocol = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	ret = getaddrinfo(NULL, service, &hints, &result);
	if (ret) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
		return -1;
	}
	// try each address until successful, close on each failure
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1)
			continue;
		if (!bind(sfd, rp->ai_addr, rp->ai_addrlen) && !listen(sfd, 1))
			break;
		close(sfd);
	}
	freeaddrinfo(result);
	if (rp == NULL) {
		fprintf(stderr, "could not connect\n");
		return -1;
	}

	return sfd;
}

/**
** Creates a TLS endpoint and prepares the context with the certificates..
**
** Returns 0 on success, and -1 on error.
**/
static int ssl_prepare(struct foossl_server_st *foossl)
{
	int ret;

	// deprecated in OpenSSL 1.1.0 (also don't use specific method version):
	// SSL_load_error_strings();
	// SSL_library_init();
	// const SSL_METHOD *method = TLSv1_2_server_method();
	const SSL_METHOD *method = TLS_server_method();

	foossl->ctx = SSL_CTX_new(method);
	if (!foossl->ctx)
		return -1;

	//TODO  Receber path do caller em vez de var global
	// ret = SSL_CTX_use_certificate_file(foossl->ctx, "tls/cert.pem", SSL_FILETYPE_PEM);
	ret = SSL_CTX_use_certificate_file(foossl->ctx, SRX_SERVER_PEM_PUB, SSL_FILETYPE_PEM);
	if (ret != 1) {
		perror("SSL_CTX_use_certificate_file");
		return -1;
	}
	//TODO  Receber path do caller em vez de var global
	// ret = SSL_CTX_use_PrivateKey_file(foossl->ctx, "tls/key.pem", SSL_FILETYPE_PEM);
	ret = SSL_CTX_use_PrivateKey_file(foossl->ctx, SRX_SERVER_PEM_PRIV, SSL_FILETYPE_PEM);
	if (ret != 1) {
		perror("SSL_CTX_use_PrivateKey_file");
		return -1;
	}

	ret = SSL_CTX_check_private_key(foossl->ctx);
	if (ret != 1) {
		perror("SSL_CTX_check_private_key");
		return -1;
	}

	return 0;
}

int foossl_server_loop_acquire(struct foossl_server_st *foossl, SSL **ssl)
{
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	int client;

	client = accept(foossl->sfd, (struct sockaddr *) &addr, &addr_len);
	if (client < 0) {
		perror("accept");
		return -1;
	}

	*ssl = SSL_new(foossl->ctx);
	if (!ssl) {
		close(client);
		return -1;
	}

	if (SSL_set_fd(*ssl, client) != 1) {
		close(client);
		SSL_free(*ssl);
		return -1;
	}

	ERR_clear_error();
	int ret = SSL_accept(*ssl);
	printf("ret = %d\n", ret);
	if (1 != ret) {
		int rc = SSL_get_error(*ssl, ret);
		perror("SSL_accept");
		fprintf(stderr, "rc = %d\n", rc);
		close(client);
		SSL_free(*ssl);
		return -1;
	}

	return 0;
}

// ssl is always freed, but closing of client socket may fail
int foossl_server_loop_release(SSL *ssl)
{
	int client;

	client = SSL_get_fd(ssl);
	SSL_free(ssl);
	if (client < 0) {
		fprintf(stderr, "could not get the client file descriptor\n");
		return -1;
	}
	close(client);

	return 0;
}

int foossl_server_connect(struct foossl_server_st *foossl, int port)
{
	foossl->sfd = socket_connect(port);
	if (foossl->sfd == -1) {
		fprintf(stderr, "could not connect to socket\n");
		return -1;
	}
	fprintf(stdout, "listening at port %d\n", port);

	if (ssl_prepare(foossl)) {
		fprintf(stderr, "could not prepare a secure channel\n");
		return -1;
	}

	return 0;
}

int foossl_server_destroy(struct foossl_server_st *foossl)
{
	if (foossl->sfd)
		close(foossl->sfd);
	//if (foossl->ssl)
		//SSL_free(foossl->ssl);
	if (foossl->ctx)
		SSL_CTX_free(foossl->ctx);

	return 0;
}
