#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#include <srx/crypto/ec.h>

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

// examples extracting public key
static void run_pubs(const struct srx_kp *kp)
{
	size_t bytecount;

	uint8_t pub_octets[1024] = {0};
	bytecount = srx_i2o_pub(pub_octets, sizeof pub_octets, kp);
	if (!bytecount || sizeof(pub_octets) < bytecount) {
		const char fmt[] = "srx_i2o_pub(): failure (bytecount=%zu, len=%zu)\n";
		fprintf(stderr, fmt, bytecount, sizeof pub_octets);
		abort();
	}
	fprintf(stderr, "srx_i2o_pub(): success (%zu encoded bytes)\n", bytecount);
	print_uint8a(pub_octets, bytecount, 'x');

	uint8_t pub_der[512] = {0};
	bytecount = srx_i2d_pub(pub_der, sizeof pub_der, kp);
	if (!bytecount || sizeof(pub_der) < bytecount) {
		const char fmt[] = "srx_i2d_pub(): failure (bytecount=%zu, len=%zu)\n";
		fprintf(stderr, fmt, bytecount, sizeof pub_der);
		abort();
	}
	fprintf(stderr, "srx_i2d_pub(): success (%zu encoded bytes)\n", bytecount);
	print_uint8a(pub_der, bytecount, 'x');

	// reconstruct internal public key from DER
	struct srx_kp *kp_new_1 = NULL;
	if (srx_d2i_pub(&kp_new_1, pub_der, bytecount)) {
		fprintf(stderr, "srx_d2i_pub(): failure\n");
		abort();
	}
	fprintf(stdout, "srx_d2i_pub(): success\n");
	srx_free_kp(&kp_new_1);
}

// examples extracting private key
static void run_privs(const struct srx_kp *kp)
{
	size_t bytecount;

	uint8_t priv_octets[512] = {0};
	bytecount = srx_i2o_priv(priv_octets, sizeof priv_octets, kp);
	if (!bytecount || sizeof(priv_octets) < bytecount) {
		const char fmt[] = "srx_i2o_priv(): failure (bytecount=%zu, len=%zu)\n";
		fprintf(stderr, fmt, bytecount, sizeof priv_octets);
		abort();
	}
	fprintf(stderr, "srx_i2o_priv(): success (%zu encoded bytes)\n", bytecount);
	print_uint8a(priv_octets, bytecount, 'x');

	uint8_t priv_der[512] = {0};
	bytecount = srx_i2d_priv(priv_der, sizeof priv_der, kp);
	if (!bytecount || sizeof(priv_der) < bytecount) {
		const char fmt[] = "srx_i2d_priv(): failure (bytecount=%zu, len=%zu)\n";
		fprintf(stderr, fmt, bytecount, sizeof priv_der);
		abort();
	}
	fprintf(stderr, "srx_i2d_priv(): success (%zu encoded bytes)\n", bytecount);
	print_uint8a(priv_der, bytecount, 'x');

	// reconstruct internal private key from DER
	struct srx_kp *kp_new_1 = NULL;
	if (srx_d2i_priv(&kp_new_1, priv_der, bytecount)) {
		fprintf(stderr, "srx_d2i_priv(): failure\n");
		abort();
	}
	fprintf(stdout, "srx_d2i_priv(): success\n");
	srx_free_kp(&kp_new_1);
}

// examples signing data and verifying signatures
static void run_sigs(const struct srx_kp *kp)
{
	uint8_t data[] = {0x01, 0x02};
	uint8_t sig[1024] = {0};

	size_t sig_len = srx_sign(sig, sizeof sig, data, sizeof data, kp);

	if (!sig_len || sizeof(sig) < sig_len) {
		const char fmt[] = "srx_sign(): failure (sig_len=%zu, buf_len=%zu)\n";
		fprintf(stderr, fmt, sig_len, sizeof sig);
		abort();
	}
	fprintf(stdout, "srx_sign(): success (sig_len = %zu)\n", sig_len);
	print_uint8a(sig, sig_len, 'x');

	// sig[17] = 0xff;  // try bad tag
	// sig_len = 0x00;  // try failure
	srx_status xs = srx_verify(sig, sig_len, data, sizeof data, kp);
	if (SRX_SUCCESS == xs) {
		fprintf(stdout, "srx_verify(): success\n");
	} else if (SRX_BAD_TAG == xs) {
		fprintf(stdout, "srx_verify(): bad tag\n");
	} else {
		fprintf(stdout, "srx_verify(): failure (srx_status=%d)\n", xs);
	}
}

static void f1()
{
	struct srx_kp *kp = NULL;

	if (srx_init_kp(&kp, NULL)) {
		fprintf(stderr, "srx_init_kp(): failure\n");
		abort();
	}
	fprintf(stdout, "srx_init_kp(): success\n");

	srx_free_kp(&kp);
}

static void f2()
{
	const uint8_t bytes[32] = {
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
		0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
	};
	struct srx_kp *kp = NULL;

	if (srx_init_kp(&kp, bytes)) {
		fprintf(stderr, "srx_init_kp(): failure\n");
		abort();
	}
	fprintf(stdout, "srx_init_kp(): success\n");

	run_pubs(kp);
	run_privs(kp);
	run_sigs(kp);

	srx_free_kp(&kp);
}

int main(void)
{
	f1();
	f2();
	return 0;
}
