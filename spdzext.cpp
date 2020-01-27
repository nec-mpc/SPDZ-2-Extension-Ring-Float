#include <iostream>
#include <vector>

#include "spdzext.h"
#include "spdz2_ext_processor_base.h"
#include "spdz2_ext_processor_Z2n.h"
#include "spdz2_ext_processor_Z2.h"

#include <syslog.h>
#include <assert.h>

typedef struct
{
	u_int64_t token;
	int party_id, num_of_parties, proc_id;
}context_t;

//-------------------------------------------------------------------------------------------//
int init(void ** handle, const int pid, const int num_of_parties, const int thread_id,
		const char * field, const int open_count, const int mult_count, const int bits_count)
{
	spdz2_ext_processor_base * proc = NULL;

	if(strncmp(field, "Z2n_Ring", 8) == 0)
	{
		proc = new spdz2_ext_processor_Z2n;
//		pctx->proc_id = 0;
	}
	else if(strncmp(field, "Z2_Bool", 7) == 0)
	{
		proc = new spdz2_ext_processor_Z2;
//		pctx->proc_id = 1;
	}
	else
	{
		syslog(LOG_ERR, "SPDZ-2 extension library init: invalid field type [%s]", field);
		return -1;
	}

	if(0 != proc->init(pid, num_of_parties, thread_id, field, open_count, mult_count, bits_count, 0))
	{
		delete proc;
		return -1;
	}

	*handle = proc;
	return 0;
}
//-------------------------------------------------------------------------------------------//

int term(void * handle) {
	spdz2_ext_processor_base * proc = ((spdz2_ext_processor_base *)handle);
	proc->term();
	delete proc;
	return 0;
}
//-------------------------------------------------------------------------------------------//
int offline(void * handle, const int offline_size)
{
	return 0;
}
//-------------------------------------------------------------------------------------------//
int opens(void * handle, const size_t share_count, const uint64_t * shares, uint64_t * opens, int verify)
{
	return ((spdz2_ext_processor_base *)handle)->open(share_count, shares, opens, verify);
}
//-------------------------------------------------------------------------------------------//
int triple(void * handle, uint64_t * a, uint64_t * b, uint64_t * c)
{
	return 0;
}
//-------------------------------------------------------------------------------------------//
int verify(void * handle, int * error)
{
//	return ((spdz2_ext_processor_base *)handle)->verify(error);?
	return -1;
}
//-------------------------------------------------------------------------------------------//
int input(void * handle, const int input_of_pid, const size_t num_of_inputs, uint64_t * inputs)
{
	return ((spdz2_ext_processor_base *)handle)->input(input_of_pid, num_of_inputs, inputs);
}
//-------------------------------------------------------------------------------------------//
int mult(void * handle, const size_t share_count, const uint64_t * xshares, const uint64_t * yshares, uint64_t * products, int verify)
{
	return ((spdz2_ext_processor_base *)handle)->mult(share_count, xshares, yshares, products, verify);
}
//-------------------------------------------------------------------------------------------//
int mix_add(void * handle, const uint64_t * share, const uint64_t * scalar, uint64_t * sum)
{
	return ((spdz2_ext_processor_base *)handle)->mix_add(share, scalar, sum);
}
//-------------------------------------------------------------------------------------------//
int mix_sub_scalar(void * handle, const uint64_t * share, const uint64_t * scalar, uint64_t * diff)
{
	return ((spdz2_ext_processor_base *)handle)->mix_sub_scalar(share, scalar, diff);
}
//-------------------------------------------------------------------------------------------//
int mix_sub_share(void * handle, const uint64_t * scalar, const uint64_t * share, uint64_t * diff)
{
	return ((spdz2_ext_processor_base *)handle)->mix_sub_share(scalar, share, diff);
}
//-------------------------------------------------------------------------------------------//
int mix_mul(void * handle, const uint64_t * share, const uint64_t * scalar, uint64_t * product)
{
	return ((spdz2_ext_processor_base *)handle)->mix_mul(share, scalar, product);
}
//-------------------------------------------------------------------------------------------//
int adds(void * handle, const uint64_t * share1, const uint64_t * share2, uint64_t * sum)
{
	return ((spdz2_ext_processor_base *)handle)->adds(share1, share2, sum);
}
//-------------------------------------------------------------------------------------------//
int subs(void * handle, const uint64_t * share1, const uint64_t * share2, uint64_t * diff)
{
	return ((spdz2_ext_processor_base *)handle)->subs(share1, share2, diff);
}
//-------------------------------------------------------------------------------------------//
int closes(void * handle, const int party_id, const size_t value_count, const uint64_t * values, uint64_t * shares)
{
	return ((spdz2_ext_processor_base *)handle)->closes(party_id, value_count, values, shares);
}
//-------------------------------------------------------------------------------------------//
int bit(void * handle, uint64_t * share)
{
	return 0; 	/* Not required for ring-based protocol */

}
//-------------------------------------------------------------------------------------------//
int inverse(void * handle, uint64_t * share_value, uint64_t * share_inverse)
{
	return 0; 	/* Not required for ring-based protocol */
}
//-------------------------------------------------------------------------------------------//
int skew_decomp(void * handle, const size_t bits_count, const uint64_t * ring_shares, uint64_t * bit_shares)
{
	return ((spdz2_ext_processor_base *)handle)->skew_decomp(bits_count, ring_shares, bit_shares);
}
//-------------------------------------------------------------------------------------------//
int skew_recomp(void * handle, const size_t bits_count, const uint64_t * bit_shares, uint64_t * ring_shares)
{
	return ((spdz2_ext_processor_base *)handle)->skew_recomp(bits_count, bit_shares, ring_shares);
}
//-------------------------------------------------------------------------------------------//
int skew_inject(void * handle, const uint64_t * bit_shares, uint64_t * ring_shares)
{
	return ((spdz2_ext_processor_base *)handle)->skew_inject(bit_shares, ring_shares);
}
//-------------------------------------------------------------------------------------------//
int mp_closes(void * handle, const int party_id, const size_t value_count, const uint64_t * values, uint64_t * shares)
{
	return ((spdz2_ext_processor_base *)handle)->mp_closes(party_id, value_count, values, shares);
}
//-------------------------------------------------------------------------------------------//
int mp_opens(void * handle, const size_t share_count, const uint64_t * shares, uint64_t * opens, int verify)
{
	return ((spdz2_ext_processor_base *)handle)->mp_open(share_count, shares, opens, verify);
}
//-------------------------------------------------------------------------------------------//
int mp_adds(void * handle, const uint64_t * share1, const uint64_t * share2, uint64_t * sum)
{
	return ((spdz2_ext_processor_base *)handle)->mp_adds(share1, share2, sum);
}
//-------------------------------------------------------------------------------------------//
int mp_mix_add(void * handle, const uint64_t * share, const uint64_t * scalar, uint64_t * sum)
{
	return ((spdz2_ext_processor_base *)handle)->mp_mix_add(share, scalar, sum);
}
//-------------------------------------------------------------------------------------------//
int mp_subs(void * handle, const uint64_t * share1, const uint64_t * share2, uint64_t * diff)
{
	return ((spdz2_ext_processor_base *)handle)->mp_subs(share1, share2, diff);
}
//-------------------------------------------------------------------------------------------//
int mp_mix_sub_share(void * handle, const uint64_t * scalar, const uint64_t * share, uint64_t * diff)
{
	return ((spdz2_ext_processor_base *)handle)->mp_mix_sub_share(scalar, share, diff);
}
//-------------------------------------------------------------------------------------------//
int mp_mix_sub_scalar(void * handle, const uint64_t * share, const uint64_t * scalar, uint64_t * diff)
{
	return ((spdz2_ext_processor_base *)handle)->mp_mix_sub_scalar(share, scalar, diff);
}
//-------------------------------------------------------------------------------------------//
int mp_mix_mul(void * handle, const uint64_t * share, const uint64_t * scalar, uint64_t * product)
{
	return ((spdz2_ext_processor_base *)handle)->mp_mix_mul(share, scalar, product);
}
//-------------------------------------------------------------------------------------------//
int mp_mult(void * handle, const size_t share_count, const uint64_t * xshares, const uint64_t * yshares, uint64_t * products, int verify)
{
	return ((spdz2_ext_processor_base *)handle)->mp_mult(share_count, xshares, yshares, products, verify);
}
//-------------------------------------------------------------------------------------------//
int mp_skew_decomp(void * handle, const size_t bits_count, const uint64_t * ring_shares, uint64_t * bit_shares)
{
	return ((spdz2_ext_processor_base *)handle)->mp_skew_decomp(bits_count, ring_shares, bit_shares);
}
//-------------------------------------------------------------------------------------------//
int mp_skew_recomp(void * handle, const size_t bits_count, const uint64_t * bit_shares, uint64_t * ring_shares)
{
	return ((spdz2_ext_processor_base *)handle)->mp_skew_recomp(bits_count, bit_shares, ring_shares);
}
//-------------------------------------------------------------------------------------------//
int mp_skew_inject(void * handle, const uint64_t * bit_shares, uint64_t * ring_shares)
{
	return ((spdz2_ext_processor_base *)handle)->mp_skew_inject(bit_shares, ring_shares);
}
//-------------------------------------------------------------------------------------------//

