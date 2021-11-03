#include <b64/cencode.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <inttypes.h>

#include <sgx_eid.h>
#include <sgx_urts.h>

#include "srx_u.h"

#include "ctio/ctio.h"
#include "rlog.h"

#include "u/util.h"

extern sgx_enclave_id_t eid; // for using with `ecall_srx_receive`

const char *srxerror(srx_status xs)
{
	switch (xs) {
	case SRX_SUCCESS:
		return "SRX_SUCCESS";
	case SRX_FAILURE:
		return "SRX_FAILURE";
	case SRX_NO_MEM:
		return "SRX_NO_MEM";
	case SRX_NO_ENT:
		return "SRX_NO_ENT";
	case SRX_BAD_TAG:
		return "SRX_BAD_TAG";
	case SRX_NO_PERM:
		return "SRX_NO_PERM";
	case SRX_NO_AUTH:
		return "SRX_NO_AUTH";
	case SRX_NO_SELF:
		return "SRX_NO_SELF";
	default:
		return "Unknown SRX status code";
	}
}

static int encode_base64(const void *data, size_t size, char** output)
{

	char *input = (char *) data;
	//NOTE  Output length: There is padding, and some implementations add line breaks after a particular amount of characters. RFC mentions 64 as well as 76. This implementation appears to use 72. To be conservative, could set it to 64. // Actually, just using fixed buffer.
	// size_t buf_size = <size calculation here>;
	size_t buf_size = 2048;

	char *buf = malloc(buf_size);
	if (!buf)
		return 1;
	char *pos = buf; // current position
	int count = 0;

	base64_encodestate s;
	base64_init_encodestate(&s);
	count = base64_encode_block(input, size, pos, &s);
	pos += count;
	count = base64_encode_blockend(pos, &s);
	pos += count;
	*pos = '\0';

	*output = buf;

	return 0;
}

//// send data from client to token
//uint8_t ocall_srx_send(const void *data, size_t size)
//{
//	char *str_in = NULL;
//	if (encode_base64(data, size, &str_in)) {
//		//TODO  log: Error encoding string in base64
//		return 1;
//	}
//
//	fprintf(stdout, "input in base64: %s\n", str_in);
//
//	char *str_out = NULL;
//	if (exchange_strings(str_in, &str_out)) {
//		free(str_in);
//		return 2;
//	}
//
//	// args are bin, do direct conversion to string in enclave (to keep generic)
//	int status = 238;
//	sgx_status_t ss = SGX_SUCCESS;
//	uint8_t retval; //TODO check retval
//	ss = ecall_srx_receive(eid, &retval, str_out, strlen(str_out) + 1);
//	if (SGX_SUCCESS != ss) {
//		//TODO log sgx call error
//		status = 3;
//	} else if (retval) {
//		//TODO log function error
//		status = 4;
//	} else {
//		status = 0;
//	}
//	free(str_in);
//	free(str_out);
//
//	return status;
//}

// `n` should be large enough to store `data`
uint8_t ocall_srx_read(const char *path, uint8_t *data, uint32_t n)
{
	printf("source path = %s\n", path);

	FILE *fp = fopen(path, "rb");
	if (!fp) {
		perror(__func__);
		return 1;
	}

	// find file size
	if (fseek(fp, 0L, SEEK_END))
		goto evil_release;
	long sz = ftell(fp);
	if (sz == -1)
		goto evil_release;
	if (fseek(fp, 0L, SEEK_SET))
		goto evil_release;
	// restrict max size; sealed file never empty
	if (sz < 1 || sz > 1024 * 1024)
		goto evil_release;
	printf("read size is = %ld\n", sz);

	// make sure data fits in given buffer
	if (sz > n) {
		fprintf(stderr, "read size is greater than buffer size "
				"(%ld > %"PRIu32")\n", sz, n);
		goto evil_release;
	}

	size_t br = fread(data, sz, 1, fp); // expects to read exactly 1 nmemb
	if (br != 1) {
		goto evil_release;
	}

	fclose(fp);
	return 0;
evil_release:
	if (fclose(fp))
		perror(__func__);
	return 3;
}

uint8_t ocall_srx_write(const char *path, uint8_t *data, uint32_t n)
{
	printf("target path = %s\n", path);

	FILE *fp = fopen(path, "wb");
	if (!fp) {
		perror(__func__);
		return 1;
	}

	uint8_t result = 0;
	printf("write size is = %"PRIu32"\n", n);
	if (fwrite(data, n, 1, fp) != 1) {
		perror(__func__);
		result = 3;
	}

	if (fclose(fp)) {
		int errsv = errno;
		fprintf(stderr, "fclose failed (no flush, maybe), errno = %d", errsv);
		result = 4;
	}

	return result;
}

int token_io(const void *data_in, size_t size_in,
		void *data_out, size_t size_out, size_t *bytes_read)
{
	char *str_in = NULL;
	if (encode_base64(data_in, size_in, &str_in)) {
		R(RLOG_ERROR, "Error encoding data (for token) in base64");
		return 1;
	}

	//TEMP test skip BASE 64:
	// char *str_out = NULL;
	// if (exchange_strings(data_in, size_in, &str_out)) {
	// 	free(str_in);
	// 	R(RLOG_WARNING, "Error exchanging data with the security token");
	// 	return 2;
	// }
	char *str_out = NULL;
	if (exchange_strings(str_in, &str_out)) {
		free(str_in);
		R(RLOG_WARNING, "Error exchanging data with the security token");
		return 2;
	}

	//TODO do not add a NUL to keep consistent with input
	size_t br = strlen(str_out) + 1;
	if (br > size_out) {
		R(RLOG_WARNING, "Buffer too small (got=%zu, want=%zu)", size_out, br);
		free(str_in);
		free(str_out);
		return 3;
	}
	memcpy(data_out, str_out, br);
	*bytes_read = br;

	free(str_in);
	free(str_out);

	return 0;
}
