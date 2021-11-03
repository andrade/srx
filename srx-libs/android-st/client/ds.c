#include <assert.h>
#include <stdio.h>
#include <inttypes.h>
#include <string.h>

#include "ds.h"

static const char *level[] = {"", "  ", "    ", "      ", "        "};

/**
** Appends a string to `dest`.
**
** `n` is the available capacity in the destination buffer.
**/
static void append_str(char **dest, size_t *n, const char *s, size_t depth)
{
	assert(depth < 5);

	snprintf(*dest, *n, "%s%s\n", level[depth], s);
	*dest += strlen(level[depth]) + strlen(s) + 1;
	*n -= strlen(level[depth]) + strlen(s) + 1;

	assert(*n > 0);
}

/**
** Appends a byte array to `dest_buf`.
**
** `available` is the available capacity in the destination buffer.
**/
static void append_bytes_u8(char **dest_buf, size_t *available,
		const uint8_t *src, size_t len, size_t depth)
{
	assert(depth < 5);

	if (!src) {
		append_str(dest_buf, available, "<null>", depth);
		return;
	}
	if (len <= 0) {
		append_str(dest_buf, available, "<empty>", depth);
		return;
	}

	snprintf(*dest_buf, *available, "%s", level[depth]);
	*dest_buf += strlen(level[depth]);
	*available -= strlen(level[depth]);

	for (size_t i = 0; i < len - 1; i++) {
		snprintf(*dest_buf, *available, "%02"PRIx8":", src[i]);
		*dest_buf += 3;
		*available -= 3;

		if ((i + 1) % 16 == 0) {
			snprintf(*dest_buf, *available, "\n%s", level[depth]);
			*dest_buf += 1 + strlen(level[depth]);
			*available -= 1 + strlen(level[depth]);
		}
	}
	snprintf(*dest_buf, *available, "%02"PRIx8"\n", src[len - 1]);
	*dest_buf += 2 + 1;
	*available -= 2 + 1;

	assert (*available > 0);
}

static void append_x64_plus(char **dest, size_t *n,
		const char *label, uint64_t num, size_t depth)
{
	assert(depth < 5);

	snprintf(*dest, *n, "%s%s: 0x%016"PRIx64"\n", level[depth], label, num);
	*dest += strlen(level[depth]) + strlen(label) + 4 + 16 + 1;
	*n -= strlen(level[depth]) + strlen(label) + 4 + 16 + 1;

	assert(*n > 0);
}

static void append_u32_plus(char **dest, size_t *n,
		const char *label, uint32_t num, size_t depth)
{
	assert(depth < 5);

	snprintf(*dest, *n, "%s%s: %10"PRIu32"\n", level[depth], label, num);
	*dest += strlen(level[depth]) + strlen(label) + 2 + 10 + 1;
	*n -= strlen(level[depth]) + strlen(label) + 2 + 10 + 1;

	assert(*n > 0);
}

void dump_ds(char *dest, size_t capacity, const struct root *root)
{
	const char main_header[] = "--- STRUCT ROOT ----------------";
	const char plaintext[] = "PLAINTEXT:";
	const char cleartext[] = "CLEARTEXT:";
	const char ephemeral[] = "EPHEMERAL:";
	const char platform[] = "Platform:";

	char **p = &dest;
	size_t available = capacity;

	append_str(p, &available, main_header, 0);

	//------------------------------ Plaintext -------------------------

	const struct plaintext *priv = &root->priv;

	append_str(p, &available, plaintext, 1);

	append_str(p, &available, "Seed for secret keys:", 2);
	append_bytes_u8(p, &available, priv->seed, sizeof priv->seed, 3);

	append_str(p, &available, "Group Sealing Nonce (GSN):", 2);
	append_bytes_u8(p, &available, priv->gsn, sizeof priv->gsn, 3);

	append_str(p, &available, "sk_enc:", 2);
	append_bytes_u8(p, &available, priv->sk_enc, sizeof priv->sk_enc, 3);
	append_str(p, &available, "sk_mac:", 2);
	append_bytes_u8(p, &available, priv->sk_mac, sizeof priv->sk_mac, 3);

	//------------------------------ Cleartext -------------------------

	const struct cleartext *open = &root->open;

	append_str(p, &available, cleartext, 1);

	append_str(p, &available, "System Sealing Nonce:", 2);
	append_bytes_u8(p, &available,
			open->seal_nonce, sizeof open->seal_nonce, 3);

	append_str(p, &available, "Group Sealing Public Key (GSPK):", 2);
	append_bytes_u8(p, &available, open->gspk, open->gspk_len, 3);

	append_u32_plus(p, &available, "Platforms count", open->platforms_count, 2);
	append_str(p, &available, "System Encryption Nonce:", 2);
	append_bytes_u8(p, &available,
			open->encryption_nonce, sizeof open->encryption_nonce, 3);

	for (uint32_t i = 0; i < open->platforms_count; i++) {
		const struct platform plat = open->platforms[i];
		append_str(p, &available, platform, 1);
		append_x64_plus(p, &available, "pid", plat.pid, 2);

		append_str(p, &available, "Platform Sealing Nonce (PSN):", 2);
		append_bytes_u8(p, &available,
				plat.seal_nonce, sizeof plat.seal_nonce, 3);

		append_str(p, &available, "Encrypted base key \\ tag:", 2);
		append_bytes_u8(p, &available,
				plat.encrypted_base_key, plat.encrypted_base_key_len, 3);
		append_bytes_u8(p, &available, plat.ebk_tag, sizeof plat.ebk_tag, 3);
	}

	//------------------------------ Ephemeral -------------------------

	const struct ephemeral *t = &root->temp;

	append_str(p, &available, ephemeral, 1);

	append_str(p, &available, "Base Key:", 2);
	append_bytes_u8(p, &available, t->base_key, sizeof t->base_key, 3);

	append_str(p, &available, "Common Sealing Key (CSK):", 2);
	append_bytes_u8(p, &available, t->csk, sizeof t->csk, 3);

	append_str(p, &available, "Common IV (CIV):", 2);
	append_bytes_u8(p, &available, t->iv, sizeof t->iv, 3);
}
