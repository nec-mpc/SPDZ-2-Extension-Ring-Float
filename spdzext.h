#ifndef SPDZ_NEC_EXT_H_
#define SPDZ_NEC_EXT_H_

#include <stdlib.h>
//#include <gmp.h>

extern "C"
{
	int init(void ** handle, const int pid, const int num_of_parties, const int thread_id,
			const char * field, const int open_count, const int mult_count, const int bits_count);

	int term(void * handle);

	int opens(void * handle, const size_t share_count, const uint64_t * shares, uint64_t * opens, int verify);
	int closes(void * handle, const int party_id, const size_t value_count, const uint64_t * values, uint64_t * shares);
	int verify(void * handle, int * error);
	int input(void * handle, const int input_of_pid, const size_t num_of_inputs, uint64_t * inputs);
	int mult(void * handle, const size_t share_count, const uint64_t * xshares, const uint64_t * yshares, uint64_t * products, int verify);

	int mix_add(void * handle, const uint64_t * share, const uint64_t * scalar, uint64_t * sum);
	int mix_sub_scalar(void * handle, const uint64_t * share, const uint64_t * scalar, uint64_t * diff);
	int mix_sub_share(void * handle, const uint64_t * scalar, const uint64_t * share, uint64_t * diff);
	int mix_mul(void * handle, const uint64_t * share, const uint64_t * scalar, uint64_t * product);
	int adds(void * handle, const uint64_t * share1, const uint64_t * share2, uint64_t * sum);
	int subs(void * handle, const uint64_t * share1, const uint64_t * share2, uint64_t * diff);

	int skew_decomp(void * handle, const size_t bits_count, const uint64_t * ring_shares, uint64_t * bit_shares);
	int skew_recomp(void * handle, const size_t bits_count, const uint64_t * bit_shares, uint64_t * ring_shares);
	int skew_inject(void * handle, const uint64_t * bit_shares, uint64_t * ring_shares);

	int mp_closes(void * handle, const int party_id, const size_t value_count, const uint64_t * values, uint64_t * shares);
	int mp_opens(void * handle, const size_t share_count, const uint64_t * shares, uint64_t * opens, int verify);
	int mp_adds(void * handle, const uint64_t * share1, const uint64_t * share2, uint64_t * sum);
	int mp_mix_add(void * handle, const uint64_t * share, const uint64_t * scalar, uint64_t * sum);
	int mp_subs(void * handle, const uint64_t * share1, const uint64_t * share2, uint64_t * diff);
	int mp_mix_sub_share(void * handle, const uint64_t * scalar, const uint64_t * share, uint64_t * diff);
	int mp_mix_sub_scalar(void * handle, const uint64_t * share, const uint64_t * scalar, uint64_t * diff);
	int mp_mix_mul(void * handle, const uint64_t * share, const uint64_t * scalar, uint64_t * product);
	int mp_mult(void * handle, const size_t share_count, const uint64_t * xshares, const uint64_t * yshares, uint64_t * products, int verify);
	int mp_skew_decomp(void * handle, const size_t bits_count, const uint64_t * ring_shares, uint64_t * bit_shares);
	int mp_skew_recomp(void * handle, const size_t bits_count, const uint64_t * bit_shares, uint64_t * ring_shares);
	int mp_skew_inject(void * handle, const uint64_t * bit_shares, uint64_t * ring_shares);
	/***************************************************************************************/
	/* Not required for ring-based protocol */
	int offline(void * handle, const int offline_size);
	int triple(void * handle, uint64_t * a, uint64_t * b, uint64_t * c);
	int bit(void * handle, uint64_t * share);
	int inverse(void * handle, uint64_t * share_value, uint64_t * share_inverse);
}

#endif /* SPDZ_NEC_EXT_H_ */
