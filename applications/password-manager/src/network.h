#pragma once

// connect to RAS, returns zero on success
int server_connect();

// exchanges data with the server, returns zero on success
// caller allocates output buffer (its size is at `*size_out`, which contains bytes read on exit)
int server_exchange_data(const void *data_in, size_t size_in,
		void *data_out, size_t *size_out);

// disconnect from RAS, returns zero on success
int server_disconnect();
