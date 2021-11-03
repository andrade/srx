#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <libconfig.h>

#include <foossl_server.h>
#include <foossl_common.h>

#include <Message.h>

#include <srx/crypto/ec.h>

#define SRX_SERVER_PEM_PRIV "/home/daniel/vc/srx/support-libs/foossl/tls/key.pem"
#define SRX_SERVER_PEM_PUB "/home/daniel/vc/srx/support-libs/foossl/tls/cert.pem"

#define BUF_SIZE 8192  // arbitrary buffer size, should be enough for all needs

static struct srx_kp *kp;

// mod is 'x' or 'd'
static void print_uint8a(const uint8_t *src, size_t n, char mod)
{
	if (0 == n) {
		printf("\n");
	} else if ('x' == mod) {
		for (size_t i = 0; i < n - 1; i++)
			printf("%02"PRIx8":", src[i]);
		printf("%02"PRIx8"\n", src[n - 1]);
	} else if ('d' == mod){
		for (size_t i = 0; i < n - 1; i++)
			printf("%03"PRIu8":", src[i]);
		printf("%03"PRIu8"\n", src[n - 1]);
	} else {
		printf("Unknown mod (`%c`) in `print_uint8a`\n", mod);
	}
}

/**
** Encodes a sign reply.
**
** @param[out]  buf       the destination buffer for the DER-encoded reply
** @param[in]   len       the length of the DER-encoded response stored in `buf`
** @param[in]   sig       the signature
** @param[in]   sig_len   the length of `sig`
**
** @return      Returns the length of the reply, stored in `buf`, on success.
**              Returns zero on error.
**/
static int encode_sig_rep(uint8_t *buf, size_t len,
		const uint8_t *sig, size_t sig_len)
{
	Message_t *reply = calloc(1, sizeof *reply);
	if (!reply) {
		fprintf(stderr, "calloc for Message_t");
		return 0;
	}
	reply->head.version = version_version_1_0;
	reply->head.operation = operation_sig_rep;

	Body_t *body = calloc(1, sizeof *body);
	if (!body) {
		fprintf(stderr, "calloc for Body_t");
		asn_DEF_Message.free_struct(&asn_DEF_Message, reply, 0);
		return 0;
	}
	body->present = Body_PR_sig_rep;

	OCTET_STRING_t *ras_sig = &body->choice.sig_rep.ras_sig;
	if (OCTET_STRING_fromBuf(ras_sig, (const char *) sig, sig_len)) {
		fprintf(stderr, "Error encoding signature");
		asn_DEF_Message.free_struct(&asn_DEF_Message, reply, 0);
		asn_DEF_Message.free_struct(&asn_DEF_Body, body, 0);
		return 0;
	}

	char errbuf[256];
	size_t errlen = 256;
	if (asn_check_constraints(&asn_DEF_Body, body, errbuf, &errlen)) {
		fprintf(stderr, "Error validating Body_t: %s", errbuf);
		asn_DEF_Message.free_struct(&asn_DEF_Message, reply, 0);
		asn_DEF_Message.free_struct(&asn_DEF_Body, body, 0);
		return 0;
	}
	reply->body = body;
	if (asn_check_constraints(&asn_DEF_Message, reply, errbuf, &errlen)) {
		fprintf(stderr, "Error validating Message_t: %s", errbuf);
		asn_DEF_Message.free_struct(&asn_DEF_Message, reply, 0);
		asn_DEF_Message.free_struct(&asn_DEF_Body, body, 0);
		return 0;
	}

	asn_enc_rval_t rval;
	rval = der_encode(&asn_DEF_Message, reply, NULL, NULL);
	if (1 > rval.encoded) {
		fprintf(stderr, "Error finding size of encoded Message_t");
		asn_DEF_Message.free_struct(&asn_DEF_Message, reply, 0);
		asn_DEF_Message.free_struct(&asn_DEF_Body, body, 0);
		return 0;
	}
	if (rval.encoded > BUF_SIZE) {
		char *error = "Buffer size not enough (got = %zu, need = %zd)\n";
		fprintf(stderr, error, len, rval.encoded);
		asn_DEF_Message.free_struct(&asn_DEF_Message, reply, 0);
		asn_DEF_Message.free_struct(&asn_DEF_Body, body, 0);
		return 0;
	}
	// uint8_t sbuf[rval.encoded];
	rval = der_encode_to_buffer(&asn_DEF_Message, reply, buf, len);
	if (-1 == rval.encoded) {
		fprintf(stderr, "Error DER-encoding Message_t");
		asn_DEF_Message.free_struct(&asn_DEF_Message, reply, 0);
		asn_DEF_Message.free_struct(&asn_DEF_Body, body, 0);
		return 0;
	}
	fprintf(stdout, "Encoded Message_t has size = %zd\n", rval.encoded);

	if (rval.encoded > 32767) {
		fprintf(stderr, "Reply too large (%zd > max int)\n", rval.encoded);
		asn_DEF_Message.free_struct(&asn_DEF_Message, reply, 0);
		asn_DEF_Message.free_struct(&asn_DEF_Body, body, 0);
		return 0;
	}

	asn_DEF_Message.free_struct(&asn_DEF_Message, reply, 0);
	// asn_DEF_Message.free_struct(&asn_DEF_Body, body, 0);  // DOUBLE FREE BAD

	return rval.encoded;
}

// Parses a signature request and prepares the response.
// Returns the length of the response (stored in `buffer`)
// on success, or zero on error.
static int handle_sig_req(uint8_t *buffer, Message_t *msg)
{
	Body_t *body = msg->body;
	if (!body) {
		fprintf(stderr, "Missing body\n");
		return 0;
	}
	if (Body_PR_sig_req != body->present) {
		fprintf(stderr, "%s\n", "Incorrect Body_t choice\n");
		return 0;
	}

	// Create bundle to sign:

	uint8_t tosign[BUF_SIZE] = {0};
	size_t tosign_len = 0;
	// asn_dec_rval_t dec_retval;
	OCTET_STRING_t *octet_string;

	//FIXME  Why below doesn't work, is it not the proper way?
	// SignatureRequest_t *sig_req = &body->choice.sig_req;
	// OCTET_STRING_t *octet_string = &body->choice.sig_req.comm_nonce;
	// dec_retval = ber_decode(NULL, &asn_DEF_OCTET_STRING,
	// 		(void **) &octet_string, tosign, sizeof tosign);
	// if (RC_OK != dec_retval.code) {
	// 	fprintf(stderr, "Error decoding communication nonce\n");
	// 	return 0;
	// }
	// printf("tosign buffer (%zu):\n", dec_retval.consumed);
	// print_uint8a(tosign, dec_retval.consumed, 'x');

	octet_string = &body->choice.sig_req.data;
	memcpy(tosign, octet_string->buf, octet_string->size);
	tosign_len += octet_string->size;
	//
	// octet_string = &body->choice.sig_req.comm_nonce;
	// memcpy(tosign, octet_string->buf, octet_string->size);
	// tosign_len += octet_string->size;
	//
	// octet_string = &body->choice.sig_req.comm_pub;
	// memcpy(tosign + tosign_len, octet_string->buf, octet_string->size);
	// tosign_len += octet_string->size;
	//
	// octet_string = &body->choice.sig_req.seal_nonce;
	// memcpy(tosign, octet_string->buf, octet_string->size);
	// tosign_len += octet_string->size;
	//
	// octet_string = &body->choice.sig_req.seal_pub;
	// memcpy(tosign + tosign_len, octet_string->buf, octet_string->size);
	// tosign_len += octet_string->size;

	// Sign data:

	uint8_t sig[1024];
	size_t sig_len = srx_sign(sig, sizeof sig, tosign, tosign_len, kp);
	if (!sig_len) {
		fprintf(stderr, "Could not sign\n");
		return 0;
	}

	// Encode response:

	int encoded_bytes = encode_sig_rep(buffer, BUF_SIZE, sig, sig_len);
	if (!encoded_bytes) {
		fprintf(stderr, "Could not encode reply\n");
		return 0;
	}

	return encoded_bytes;
}

// resets buffer (to return size of zero to client)
//@Deprecated  can simply reply with zero to signal no buf (unless set some err); ideally should still reply error in ASN.1
// static void set_buf_to_err(uint8_t *buffer, int *n)
// {
// 	memset(buffer, 0, BUF_SIZE);
// 	*n = 0;
// }

/**
** Validates a `Message_t` message.
** Returns zero on success, or non-zero otherwise.
**/
static int validate_message(const Message_t *msg)
{
	char errbuf[256];
	size_t errlen = 256;

	if (asn_check_constraints(&asn_DEF_Message, msg, errbuf, &errlen)) {
		fprintf(stderr, "Error validating Message_t: %s\n", errbuf);
		return 1;
	}
	if (msg->head.version != version_version_1_0) {
		fprintf(stderr, "Bad version\n");
		return 2;
	}
	// if (msg->body) {
	// 	if (asn_check_constraints(&asn_DEF_Body, body, errbuf, &errlen)) {
	// 		fprintf(stderr, "Error validating Body_t: %s\n", errbuf);
	// 		return 3;
	// 	}
	// }
	// already done above, if set

	return 0;
}

/**
** Handles a request and prepares the response.
**
** Always sets the buffer to a value that can be sent to the caller.
**
** @param[io]   buffer      the buffer with the request, and later the response
** @param[in]   n           the length of the request
**
** @return      Returns the length of the response stored
**              in `buffer` on success, or zero on error.
**/
static int process_buffer(uint8_t *buffer, int n)
{
	int result = 0;

	Message_t *msg = NULL;
	asn_dec_rval_t dec_retval = ber_decode(NULL, &asn_DEF_Message,
			(void **) &msg, (const void *) buffer, n);
	if (RC_OK != dec_retval.code) {
		fprintf(stderr, "Error decoding Message_t\n");
		result = 0;
		goto finally;
	}

	if (validate_message(msg)) {
		fprintf(stderr, "Error validating Message_t\n");
		result = 0;
		goto finally;
	}

	xer_fprint(stdout, &asn_DEF_Message, msg);

	switch (msg->head.operation) {
		case operation_sig_req:
			fprintf(stdout, "Handling signature-request operation...\n");
			result = handle_sig_req(buffer, msg);
			goto finally;
		default:
			fprintf(stderr, "Bad operation = %ld\n", msg->head.operation);
			result = 0;
			goto finally;
	}

finally:
	asn_DEF_Message.free_struct(&asn_DEF_Message, msg, 0);
	return result;
}

static void handle_request(SSL *ssl)
{
	uint8_t buffer[BUF_SIZE] = {0};
	int n = 0;

	if (foossl_read(ssl, &n, 4)) {
		fprintf(stderr, "could not read %d bytes\n", n);
		return;
	}
	printf("ssl read size: %d\n", n);

	if (foossl_read(ssl, buffer, n)) {
		fprintf(stderr, "could not read %d bytes\n", n);
		return;
	}

	n = process_buffer(buffer, n); // write if zero for proper termination

	if (foossl_write(ssl, &n, 4)) {
		fprintf(stderr, "could not write %d bytes\n", n);
		return;
	}
	printf("ssl write size: %d\n", n);

	if (foossl_write(ssl, buffer, n)) {
		fprintf(stderr, "could not write %d bytes\n", n);
		return;
	}

	printf("end of handling client request.\n");
}

int main(void)
{
	// configurations: read conf file and load private key from file

	config_t cfg;
	const char *path_kp;
	config_init(&cfg);

	if (!config_read_file(&cfg, "server.conf")) {
		fprintf(stderr, "%s:%d: %s\n", config_error_file(&cfg),
				config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return EXIT_FAILURE;
	}

	if (config_lookup_string(&cfg, "path_kp", &path_kp)) {
		printf("Path to private key for signing: %s\n", path_kp);
	} else {
		fprintf(stderr, "No 'path_kp' setting in configuration file\n");
		config_destroy(&cfg);
		return EXIT_FAILURE;
	}

	if (srx_load_kp(&kp, path_kp)) {
		config_destroy(&cfg);
		fprintf(stderr, "srx_load_kp: failure\n");
		return EXIT_FAILURE;
	}

	config_destroy(&cfg);

	// server init and loop:   --------------------------------

	struct foossl_server_st foossl;

	if (foossl_server_connect(&foossl, 4433)) {
		perror("connect: unable to create secure listening connection");
		foossl_server_destroy(&foossl);
		return EXIT_FAILURE;
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
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
