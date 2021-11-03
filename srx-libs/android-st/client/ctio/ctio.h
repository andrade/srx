#pragma once

/**
** Exchanges strings with the Security Token.
**
** Sends a string to the Security Token (phone), and
** receives another string in response.
**
** str_in      [in] the NULL-terminated string to send to the token
** str_out    [out] the NULL-terminated string received from the token;
**                  memory allocated internally (only on success)
**
** Returns zero on success, or non-zero otherwise.
**/
int exchange_strings(const char *str_in, char **str_out);
// int exchange_strings(const void *data_in, size_t size, char **str_out);
