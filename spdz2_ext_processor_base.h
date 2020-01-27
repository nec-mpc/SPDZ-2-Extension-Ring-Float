#pragma once

#include <pthread.h>
#include <semaphore.h>
#include <deque>
#include <vector>
#include <string>
#include <map>
#include <list>
//#include <gmp.h>
#include <cstdint>

class spdz2_ext_processor_base
{
protected:
	int m_pid, m_nparties;
	int m_thid;
	std::string m_field;
//	int m_nopen, m_nmult, m_nbits;
	std::string m_logcat;

	typedef struct
	{
		uint64_t * shared_values;
		size_t share_count,share_index;
	}shared_input_t;

	std::map< int , shared_input_t > m_shared_inputs;

	int load_inputs();
	int delete_inputs();
	int load_party_input_specs(std::list<std::string> & party_input_specs);
	int load_party_inputs(const std::string & party_input_spec);
	int load_party_inputs(const int pid, const size_t count);

	int load_self_party_inputs(const size_t count);
	int load_peer_party_inputs(const int pid, const size_t count, const uint64_t * clr_values = NULL);
	int load_clr_party_inputs(uint64_t * clr_values, const size_t count);

	int init_log(int log_level);

public:
	spdz2_ext_processor_base();
	virtual ~spdz2_ext_processor_base();

	virtual int init(const int pid, const int num_of_parties, const int thread_id, const char * field,
			 const int open_count, const int mult_count, const int bits_count, int log_level);

	virtual int term() = 0;

	virtual int input(const int input_of_pid, uint64_t * input_value);
	virtual int input(const int input_of_pid, const size_t num_of_inputs, uint64_t * inputs) = 0;
//	virtual int inverse(uint64_t * share_value, uint64_t * share_inverse);
//	virtual int inverse_value(const uint64_t * value, uint64_t * inverse);

//	virtual int get_P(mpz_t P) = 0;
//	virtual int offline(const int offline_size) = 0;
//	virtual int triple(uint64_t * a, uint64_t * b, uint64_t * c) = 0;
	virtual int closes(const int share_of_pid, const size_t value_count, const uint64_t * values, uint64_t * shares) = 0;
//	virtual int bit(uint64_t * share) = 0;
	virtual int open(const size_t share_count, const uint64_t * share_values, uint64_t * opens, int verify) = 0;
	virtual int verify(int * error) = 0;
	virtual int mult(const size_t share_count, const uint64_t * xshares, const uint64_t * yshares, uint64_t * products, int verify) = 0;

	virtual int mix_add(const uint64_t * share, const uint64_t * scalar, uint64_t * sum) = 0;
	virtual int mix_sub_scalar(const uint64_t * share, const uint64_t * scalar, uint64_t * diff) = 0;
	virtual int mix_sub_share(const uint64_t * scalar, const uint64_t * share, uint64_t * diff) = 0;
	virtual int mix_mul(const uint64_t * share, const uint64_t * scalar, uint64_t * product) = 0;
	virtual int adds(const uint64_t * share1, const uint64_t * share2, uint64_t * sum) = 0;
	virtual int subs(const uint64_t * share1, const uint64_t * share2, uint64_t * diff) = 0;

	virtual int skew_decomp(const size_t bits_count, const uint64_t * ring_shares, uint64_t * bit_shares) = 0;
	virtual int skew_recomp(const size_t bits_count, const uint64_t * bits_shares, uint64_t * ring_shares) = 0;
	virtual int skew_inject(const uint64_t * bit_shares, uint64_t * ring_shares) = 0;

	virtual int mp_closes(const int share_of_pid, const size_t value_count, const uint64_t * values, uint64_t * shares) = 0;
	virtual int mp_open(const size_t share_count, const uint64_t * share_values, uint64_t * opens, int verify) = 0;
	virtual int mp_adds(const uint64_t * share1, const uint64_t * share2, uint64_t * sum) = 0;
	virtual int mp_mix_add(const uint64_t * share, const uint64_t * scalar, uint64_t * sum) = 0;
	virtual int mp_subs(const uint64_t * share1, const uint64_t * share2, uint64_t * diff) = 0;
	virtual int mp_mix_sub_share(const uint64_t * scalar, const uint64_t * share, uint64_t * diff) = 0;
	virtual int mp_mix_sub_scalar(const uint64_t * share, const uint64_t * scalar, uint64_t * diff) = 0;
	virtual int mp_mix_mul(const uint64_t * share, const uint64_t * scalar, uint64_t * product) = 0;
	virtual int mp_mult(const size_t share_count, const uint64_t * xshares, const uint64_t * yshares, uint64_t * products, int verify) = 0;
	virtual int mp_skew_decomp(const size_t bits_count, const uint64_t * ring_shares, uint64_t * bit_shares) = 0;
	virtual int mp_skew_recomp(const size_t bits_count, const uint64_t * bits_shares, uint64_t * ring_shares) = 0;
	virtual int mp_skew_inject(const uint64_t * bit_shares, uint64_t * ring_shares) = 0;

	virtual std::string get_parties_file() = 0;
	virtual std::string get_log_file() = 0;
	virtual std::string get_log_category() = 0;
};

#define LC(x) log4cpp::Category::getInstance(x)

