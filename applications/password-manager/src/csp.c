#include "csysperf.h"

void ocall_csp_poke(int id, int pos)
{
	CSP_POKE(id, pos);
}
