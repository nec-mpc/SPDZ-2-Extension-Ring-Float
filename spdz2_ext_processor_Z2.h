#pragma once

#include <NecProtocolPartyBoolFor3P.h>
#include "spdz2_ext_processor_base.h"
//#include <gmp.h>

//#include "Protocol.h"
//#include "ZpMersenneLongElement.h"

class spdz2_ext_processor_Z2 : public spdz2_ext_processor_base
{
	NecProtocolPartyBoolFor3P<uint64_t> * the_party;

public:
	spdz2_ext_processor_Z2();
	virtual ~spdz2_ext_processor_Z2();

	int init(const int pid, const int num_of_parties, const int thread_id, const char * field,
			 const int open_count, const int mult_count, const int bits_count, int log_level = 700);
	int term();

	int input(const int input_of_pid, const size_t num_of_inputs, uint64_t * input_value);

	int closes(const int share_of_pid, const size_t value_count, const uint64_t * values, uint64_t * shares);
	int open(const size_t share_count, const uint64_t * share_values, uint64_t * opens, int verify);
	int verify(int * error);
	int mult(const size_t share_count, const uint64_t * xshares, const uint64_t * yshares, uint64_t * products, int verify);

	int mix_add(const uint64_t * share, const uint64_t * scalar, uint64_t * sum);
	int mix_sub_scalar(const uint64_t * share, const uint64_t * scalar, uint64_t * diff);
	int mix_sub_share(const uint64_t * scalar, const uint64_t * share, uint64_t * diff);
	int mix_mul(const uint64_t * share, const uint64_t * scalar, uint64_t * product);
	int adds(const uint64_t * share1, const uint64_t * share2, uint64_t * sum);
	int subs(const uint64_t * share1, const uint64_t * share2, uint64_t * diff);

	int skew_decomp(const size_t bits_count, const uint64_t * ring_shares, uint64_t * bit_shares);
	int skew_recomp(const size_t bits_count, const uint64_t * bit_shares, uint64_t * ring_shares);
	int skew_inject(const uint64_t * bit_shares, uint64_t * ring_shares);

	int mp_closes(const int share_of_pid, const size_t value_count, const uint64_t * values, uint64_t * shares);
	int mp_open(const size_t share_count, const uint64_t * share_values, uint64_t * opens, int verify);
	int mp_adds(const uint64_t * share1, const uint64_t * share2, uint64_t * sum);
	int mp_mix_add(const uint64_t * share, const uint64_t * scalar, uint64_t * sum);
	int mp_subs(const uint64_t * share1, const uint64_t * share2, uint64_t * diff);
	int mp_mix_sub_share(const uint64_t * scalar, const uint64_t * share, uint64_t * diff);
	int mp_mix_sub_scalar(const uint64_t * share, const uint64_t * scalar, uint64_t * diff);
	int mp_mix_mul(const uint64_t * share, const uint64_t * scalar, uint64_t * product);
	int mp_mult(const size_t share_count, const uint64_t * xshares, const uint64_t * yshares, uint64_t * products, int verify);
	int mp_skew_decomp(const size_t bits_count, const uint64_t * ring_shares, uint64_t * bit_shares);
	int mp_skew_recomp(const size_t bits_count, const uint64_t * bit_shares, uint64_t * ring_shares);
	int mp_skew_inject(const uint64_t * bit_shares, uint64_t * ring_shares);

	std::string get_parties_file();
	std::string get_log_file();
	std::string get_log_category();

};
