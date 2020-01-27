#include "spdzext_width_defs.h"
#include "spdz2_ext_processor_Z2.h"
#include "Z2nIntReplicated.h"
#include "Z2nShareReplicated.h"

#include <log4cpp/Category.hh>

#include <syslog.h>
#include <math.h>

spdz2_ext_processor_Z2::spdz2_ext_processor_Z2()
 : spdz2_ext_processor_base()
 , the_party(NULL)
{
}

spdz2_ext_processor_Z2::~spdz2_ext_processor_Z2()
{
}

int spdz2_ext_processor_Z2::init(const int pid, const int num_of_parties, const int thread_id, const char * field,
		 	 	 	 	 	 	 	 	 const int open_count, const int mult_count, const int bits_count, int log_level)
{
	if(0 == spdz2_ext_processor_base::init(pid, num_of_parties, thread_id, field, open_count, mult_count, bits_count, log_level))
	{
		the_party = new NecProtocolPartyBoolFor3P<uint64_t>(pid, 0);
		the_party->init();
	}
	return 0;
}

int spdz2_ext_processor_Z2::term()
{
	delete the_party;
	the_party = NULL;
	LC(m_logcat).info("%s.", __FUNCTION__);
	return 0;
}

int spdz2_ext_processor_Z2::input(const int input_of_pid, const size_t num_of_inputs, uint64_t * input_value)
{
	if (0 != the_party->input(input_of_pid, num_of_inputs, input_value))
	{
		LC(m_logcat).error("%s: protocol input failure.", __FUNCTION__);
		return -1;
	}

	return 0;
}


int spdz2_ext_processor_Z2::closes(const int share_of_pid, const size_t value_count, const uint64_t * values, uint64_t * shares)
{
	std::vector<uint64_t> z2nshares1(GF2N_VECTOR*value_count);
	std::vector<uint64_t> z2nshares2(GF2N_VECTOR*value_count);
	std::vector<uint64_t> z2nvalues(GF2N_VECTOR*value_count);

	for(size_t i=0; i<GF2N_VECTOR*value_count; ++i) {
		z2nvalues[i] = values[i];
	}

	if(0 == the_party->makeShare(share_of_pid, z2nvalues, z2nshares1, z2nshares2))
	{
		for(size_t i=0; i<value_count; ++i)
		{
			uint64_t * share = shares + (i*GF2N_LIMBS);
			for(size_t j=0; j<GF2N_VECTOR; ++j)
			{
				share[j]   			 = z2nshares1[i*GF2N_VECTOR+j];
				share[j+GF2N_LIMBS]   = z2nshares2[i*GF2N_VECTOR+j];
			}
		}
		return 0;
	}
	else
	{
		LC(m_logcat).error("%s: protocol makeShare failure.", __FUNCTION__);
	}
	return -1;
}

int spdz2_ext_processor_Z2::open(const size_t share_count, const uint64_t * share_values, uint64_t * opens, int verify)
{
	int result = -1;
	std::vector<uint64_t> z2nshares1(GF2N_VECTOR*share_count);
	std::vector<uint64_t> z2nshares2(GF2N_VECTOR*share_count);
	std::vector<uint64_t> z2nopens(GF2N_VECTOR*share_count);

	for(size_t i=0; i<share_count; ++i)
	{
		const uint64_t * share = share_values + i*GF2N_SHR_LIMBS*GF2N_VECTOR;

		for(size_t j=0; j<GF2N_VECTOR; ++j)
		{
			z2nshares1[i*GF2N_VECTOR+j] = share[j];
			z2nshares2[i*GF2N_VECTOR+j] = share[j+GF2N_LIMBS*GF2N_VECTOR];
		}
	}

	if(0 == the_party->openShare((int)GF2N_VECTOR*share_count, z2nshares1, z2nshares2, z2nopens))
	{
		if(!verify || the_party->verify())
		{
			for(size_t i=0; i<GF2N_VECTOR*share_count; ++i)
			{
				opens[i] = z2nopens[i];
			}
			result = 0;
		}
		else
		{
			LC(m_logcat).error("%s: verify failure.", __FUNCTION__);
		}
	}
	else
	{
		LC(m_logcat).error("%s: openShare failure.", __FUNCTION__);
	}
	return result;
}

int spdz2_ext_processor_Z2::verify(int * error)
{
	return (0 == the_party->verify())? 0: -1;
}


int spdz2_ext_processor_Z2::mult(const size_t share_count, const uint64_t * xshares, const uint64_t * yshares, uint64_t * products, int verify)

{
	int result = -1;

	LC(m_logcat).info("%s called for %lu shares.", __FUNCTION__, share_count);
	std::vector<uint64_t> x_shares1(GF2N_VECTOR*share_count);
	std::vector<uint64_t> x_shares2(GF2N_VECTOR*share_count);
	std::vector<uint64_t> y_shares1(GF2N_VECTOR*share_count);
	std::vector<uint64_t> y_shares2(GF2N_VECTOR*share_count);
	std::vector<uint64_t> xy_shares1(GF2N_VECTOR*share_count);
	std::vector<uint64_t> xy_shares2(GF2N_VECTOR*share_count);

	for(size_t i=0; i<share_count; ++i)
	{
		const uint64_t * xshare = xshares + i*GF2N_SHR_LIMBS*GF2N_VECTOR;
		const uint64_t * yshare = yshares + i*GF2N_SHR_LIMBS*GF2N_VECTOR;
		for(size_t j=0; j<GF2N_VECTOR; ++j)
		{
			x_shares1[i*GF2N_VECTOR+j] = xshare[j];
			x_shares2[i*GF2N_VECTOR+j] = xshare[j+GF2N_LIMBS*GF2N_VECTOR];
			y_shares1[i*GF2N_VECTOR+j] = yshare[j];
			y_shares2[i*GF2N_VECTOR+j] = yshare[j+GF2N_LIMBS*GF2N_VECTOR];
		}
	}

	if(0 == the_party->multShares((int)GF2N_VECTOR*share_count, x_shares1, x_shares2, y_shares1, y_shares2, xy_shares1, xy_shares2))
	{
		for(size_t i=0; i<share_count; ++i)
		{
			uint64_t * product = products + i*GF2N_SHR_LIMBS*GF2N_VECTOR;
			for(size_t j=0; j<GF2N_VECTOR; ++j)
			{
				product[j]                         = xy_shares1[i*GF2N_VECTOR+j];
				product[j+GF2N_LIMBS*GF2N_VECTOR]  = xy_shares2[i*GF2N_VECTOR+j];
			}
		}
		result = 0;
	}
	else
	{
		LC(m_logcat).error("%s: protocol mult failure.", __FUNCTION__);
	}

	return result;
}


int spdz2_ext_processor_Z2::mix_add(const uint64_t * share, const uint64_t * scalar, uint64_t * sum)
{
	for(size_t i=0; i<GF2N_VECTOR; ++i)
	{
		uint64_t input[2], output[2], arg;
		input[0] = share[i];
		input[1] = share[i+GF2N_LIMBS*GF2N_VECTOR];
		arg = scalar[i];
		if (m_pid == 0) {
			output[0] = input[0];
			output[1] = input[1];
		}
		else if (m_pid == 1) {
			output[0] = input[0] ^ arg;
			output[1] = input[1] ^ arg;
		}
		else if (m_pid == 2) {
			output[0] = input[0] ^ arg;
			output[1] = input[1];
		}
		sum[i]                         = output[0];
		sum[i+GF2N_LIMBS*GF2N_VECTOR]  = output[1];
	}
	return 0;
}

int spdz2_ext_processor_Z2::mix_sub_scalar(const uint64_t * share, const uint64_t * scalar, uint64_t * diff)
{
	for(size_t i=0; i<GF2N_VECTOR; ++i)
	{
		uint64_t input[2], output[2], arg;
		input[0] = share[i];
		input[1] = share[i+GF2N_LIMBS*GF2N_VECTOR];
		arg = scalar[i];
		if (m_pid == 0) {
			output[0] = input[0];
			output[1] = input[1];
		}
		else if (m_pid == 1) {
			output[0] = input[0] ^ arg;
			output[1] = input[1] ^ arg;
		}
		else if (m_pid == 2) {
			output[0] = input[0] ^ arg;
			output[1] = input[1];
		}
		diff[i]                         = output[0];
		diff[i+GF2N_LIMBS*GF2N_VECTOR]  = output[1];
		LC(m_logcat + ".acct").debug("%s: sh=%lu; sc=%lu; df=%lu;", __FUNCTION__, share[i], scalar[i], diff[i]);
	}
	return 0;
}

int spdz2_ext_processor_Z2::mix_sub_share(const uint64_t * scalar, const uint64_t * share, uint64_t * diff)
{
	for(size_t i=0; i<GF2N_VECTOR; ++i)
	{
		uint64_t input[2], output[2], arg;
		input[0] = share[i];
		input[1] = share[i+GF2N_LIMBS*GF2N_VECTOR];
		arg = scalar[i];
		if (m_pid == 0) {
			output[0] =  input[0];
			output[1] =  input[1];
		}
		else if (m_pid == 1) {
			output[0] = arg ^ input[0];
			output[1] = arg ^ input[1];
		}
		else if (m_pid == 2) {
			output[0] = arg ^ input[0];
			output[1] = input[1];
		}
		diff[i]                          = output[0];
		diff[i+GF2N_LIMBS*GF2N_VECTOR]   = output[1];
		LC(m_logcat + ".acct").debug("%s: sh=%lu; sc=%lu; df=%lu;", __FUNCTION__, share[i], scalar[i], diff[i]);
	}
	return 0;
}

int spdz2_ext_processor_Z2::mix_mul(const uint64_t * share, const uint64_t * scalar, uint64_t * product)
{
	for(size_t i=0; i<GF2N_VECTOR; ++i)
	{
		uint64_t input[2], output[2], arg;
		input[0] = share[i];
		input[1] = share[i+GF2N_LIMBS*GF2N_VECTOR];
		arg = scalar[i];
		if (m_pid == 0) {
			output[0] = input[0] & arg;
			output[1] = input[1] & arg;
		}
		else if (m_pid == 1) {
			output[0] = input[0] & arg;
			output[1] = input[1] & arg;
		}
		else if (m_pid == 2) {
			output[0] = input[0] & arg;
			output[1] = input[1] & arg;
		}
		product[i]                          = output[0];
		product[i+GF2N_LIMBS*GF2N_VECTOR]   = output[1];
		LC(m_logcat + ".acct").debug("%s: sh=%lu; sc=%lu; pd=%lu;", __FUNCTION__, share[i], scalar[i], product[i]);
	}
	return 0;
}

int spdz2_ext_processor_Z2::adds(const uint64_t * share1, const uint64_t * share2, uint64_t * sum)
{
	for(size_t i=0; i<GF2N_VECTOR; ++i)
	{
		uint64_t __share1[2], __share2[2];
		__share1[0] = share1[i];
		__share1[1] = share1[i+GF2N_LIMBS*GF2N_VECTOR];
		__share2[0] = share2[i];
		__share2[1] = share2[i+GF2N_LIMBS*GF2N_VECTOR];
		sum[i]                         = __share1[0] ^ __share2[0];
		sum[i+GF2N_LIMBS*GF2N_VECTOR]  = __share1[1] ^ __share2[1];

		LC(m_logcat + ".acct").debug("%s: sh1=%lu; sh2=%lu; sum=%lu;", __FUNCTION__, share1[i], share2[i], sum[i]);
	}
	return 0;
}

int spdz2_ext_processor_Z2::subs(const uint64_t * share1, const uint64_t * share2, uint64_t * diff)
{
	for(size_t i=0; i<GF2N_VECTOR; ++i)
	{
		uint64_t __share1[2], __share2[2];
		__share1[0] = share1[i];
		__share1[1] = share1[i+GF2N_LIMBS*GF2N_VECTOR];
		__share2[0] = share2[i];
		__share2[1] = share2[i+GF2N_LIMBS*GF2N_VECTOR];
		diff[i]                         = __share1[0] ^ __share2[0];
		diff[i+GF2N_LIMBS*GF2N_VECTOR]  = __share1[1] ^ __share2[1];
		LC(m_logcat + ".acct").debug("%s: sh1=%lu; sh2=%lu; dif=%lu;", __FUNCTION__, share1[i], share2[i], diff[i]);
	}
	return 0;
}

int spdz2_ext_processor_Z2::skew_decomp(const size_t bits_count, const uint64_t * bits_input, uint64_t * rings_output)
{
	int result = -1;

	std::vector<uint64_t> b_x0(GF2N_VECTOR);
	std::vector<uint64_t> b_x1(GF2N_VECTOR);
	std::vector<uint64_t> r_x0_0(GF2N_VECTOR);
	std::vector<uint64_t> r_x0_1(GF2N_VECTOR);
	std::vector<uint64_t> r_x1_0(GF2N_VECTOR);
	std::vector<uint64_t> r_x1_1(GF2N_VECTOR);
	std::vector<uint64_t> r_x2_0(GF2N_VECTOR);
	std::vector<uint64_t> r_x2_1(GF2N_VECTOR);

	for(size_t i=0; i<GF2N_VECTOR; ++i) {
		b_x0[i] = bits_input[i];
		b_x1[i] = bits_input[i+GF2N_LIMBS*GF2N_VECTOR];
	}

	if(0 == the_party->skewDecomp((int)bits_count, b_x0, b_x1, r_x0_0, r_x0_1, r_x1_0, r_x1_1, r_x2_0, r_x2_1))
	{
		for(size_t i=0; i<bits_count; ++i)
		{
			uint64_t * rshare = rings_output;

			for(size_t j=0; j<GF2N_VECTOR; ++j)
			{
				rshare[j]                          = r_x0_0[j];
				rshare[j+GF2N_LIMBS*GF2N_VECTOR]   = r_x0_1[j];
				rshare += GF2N_SHR_LIMBS*GF2N_VECTOR;
				rshare[j]                          = r_x1_0[j];
				rshare[j+GF2N_LIMBS*GF2N_VECTOR]   = r_x1_1[j];
				rshare += GF2N_SHR_LIMBS*GF2N_VECTOR;
				rshare[j]                          = r_x2_0[j];
				rshare[j+GF2N_LIMBS*GF2N_VECTOR]   = r_x2_1[j];
			}
		}
		result = 0;
	}
	else
	{
		LC(m_logcat).error("%s: protocol skew_decomp failure.", __FUNCTION__);
	}

	return result;
}

int spdz2_ext_processor_Z2::skew_recomp(const size_t bits_count, const uint64_t * bit_shares, uint64_t * ring_shares)
{
	int result = -1;
	std::vector<uint64_t> bshares1(GF2N_VECTOR*bits_count);
	std::vector<uint64_t> bshares2(GF2N_VECTOR*bits_count);
	std::vector<uint64_t> rshares1(GF2N_VECTOR,0);
	std::vector<uint64_t> rshares2(GF2N_VECTOR,0);

	for(size_t i=0; i<bits_count; ++i)
	{
		for(size_t j=0; j<GF2N_VECTOR; ++j)
		{
			bshares1[i*GF2N_VECTOR+j] = bit_shares[i*GF2N_SHR_LIMBS*GF2N_VECTOR+j];
			bshares2[i*GF2N_VECTOR+j] = bit_shares[i*GF2N_SHR_LIMBS*GF2N_VECTOR+j+GF2N_LIMBS*GF2N_VECTOR];
		}
	}

	if(0 == the_party->skewRecomp((int)bits_count, bshares1, bshares2, rshares1, rshares2))
	{
		uint64_t * rshare = ring_shares;

		for(size_t j=0; j<GFP_VECTOR; ++j)
		{
			rshare[2*j]                         = rshares1[j];
			rshare[2*j+1]                       = 0;
			rshare[2*j+GFP_LIMBS*GFP_VECTOR]    = rshares2[j];
			rshare[2*j+GFP_LIMBS*GFP_VECTOR+1]  = 0;
		}
		result = 0;
	}
	else
	{
		LC(m_logcat).error("%s: protocol skew_recomp failure.", __FUNCTION__);
	}

	return result;
}

int spdz2_ext_processor_Z2::skew_inject(const uint64_t * bits_input, uint64_t * rings_output)
{
	int result = -1;

	std::vector<uint64_t> b_x0(GF2N_VECTOR);
	std::vector<uint64_t> b_x1(GF2N_VECTOR);
	std::vector<uint64_t> r_x0_0(GF2N_VECTOR);
	std::vector<uint64_t> r_x0_1(GF2N_VECTOR);
	std::vector<uint64_t> r_x1_0(GF2N_VECTOR);
	std::vector<uint64_t> r_x1_1(GF2N_VECTOR);
	std::vector<uint64_t> r_x2_0(GF2N_VECTOR);
	std::vector<uint64_t> r_x2_1(GF2N_VECTOR);

	for(size_t i=0; i<GF2N_VECTOR; ++i) {
		b_x0[i] = bits_input[i];
		b_x1[i] = bits_input[i+GF2N_LIMBS*GF2N_VECTOR];
//		cout << "input = " <<b_x0[i] << ", " << b_x1[i] << endl;
	}

	if(0 == the_party->skewInject(b_x0, b_x1, r_x0_0, r_x0_1, r_x1_0, r_x1_1, r_x2_0, r_x2_1))
	{
		uint64_t * rshare = rings_output;

		for(size_t j=0; j<GF2N_VECTOR; ++j)
		{
//			cout << "output 1 = " << r_x0_0[j] << ", "<<r_x0_1[j] << endl;
			rshare[2*j]                        = r_x0_0[j];
			rshare[2*j+1]                      = 0;
			rshare[2*j+GFP_LIMBS*GFP_VECTOR]   = r_x0_1[j];
			rshare[2*j+GFP_LIMBS*GFP_VECTOR+1] = 0;
			rshare += SHR_LIMBS*GF2N_VECTOR;
//			cout << "output 2 = " << r_x1_0[j] << ", "<<r_x1_1[j] << endl;
			rshare[2*j]                        = r_x1_0[j];
			rshare[2*j+1]                      = 0;
			rshare[2*j+GFP_LIMBS*GFP_VECTOR]   = r_x1_1[j];
			rshare[2*j+GFP_LIMBS*GFP_VECTOR+1] = 0;
			rshare += SHR_LIMBS*GF2N_VECTOR;
//			cout << "output 3 = " << r_x2_0[j] << ", "<<r_x2_1[j] << endl;
			rshare[2*j]                        = r_x2_0[j];
			rshare[2*j+1]                      = 0;
			rshare[2*j+GFP_LIMBS*GFP_VECTOR]   = r_x2_1[j];
			rshare[2*j+GFP_LIMBS*GFP_VECTOR+1] = 0;
		}
		result = 0;
	}
	else
	{
		LC(m_logcat).error("%s: protocol skew_inject failure.", __FUNCTION__);
	}

	return result;
}

int spdz2_ext_processor_Z2::mp_closes(const int share_of_pid, const size_t value_count, const uint64_t * values, uint64_t * shares)
{
	return 0;
}

int spdz2_ext_processor_Z2::mp_open(const size_t share_count, const uint64_t * share_values, uint64_t * opens, int verify)
{
	return 0;
}

int spdz2_ext_processor_Z2::mp_adds(const uint64_t * share1, const uint64_t * share2, uint64_t * sum)
{
	return 0;
}

int spdz2_ext_processor_Z2::mp_mix_add(const uint64_t * share, const uint64_t * scalar, uint64_t * sum)
{
	return 0;
}

int spdz2_ext_processor_Z2::mp_subs(const uint64_t * share1, const uint64_t * share2, uint64_t * diff)
{
	return 0;
}

int spdz2_ext_processor_Z2::mp_mix_sub_share(const uint64_t * scalar, const uint64_t * share, uint64_t * diff)
{
	return 0;
}
int spdz2_ext_processor_Z2::mp_mix_sub_scalar(const uint64_t * share, const uint64_t * scalar, uint64_t * diff)
{
	return 0;
}
int spdz2_ext_processor_Z2::mp_mix_mul(const uint64_t * share, const uint64_t * scalar, uint64_t * product)
{
	return 0;
}
int spdz2_ext_processor_Z2::mp_mult(const size_t share_count, const uint64_t * xshares, const uint64_t * yshares, uint64_t * products, int verify)
{
	return 0;
}
int spdz2_ext_processor_Z2::mp_skew_decomp(const size_t bits_count, const uint64_t * bits_input, uint64_t * rings_output)
{
	return 0;
}

int spdz2_ext_processor_Z2::mp_skew_recomp(const size_t bits_count, const uint64_t * bit_shares, uint64_t * ring_shares)
{
	int result = -1;
	// GFP_VECTOR=GF2N_VECTOR=1
	std::vector<uint64_t> bshares1(GF2N_VECTOR*bits_count);
	std::vector<uint64_t> bshares2(GF2N_VECTOR*bits_count);
	std::vector<uint64_t> rshares1(GFP_VECTOR*GFP_LIMBS,0);
	std::vector<uint64_t> rshares2(GFP_VECTOR*GFP_LIMBS,0);
//	uint64_t bshares1[GF2N_VECTOR*bits_count];
//	uint64_t bshares2[GF2N_VECTOR*bits_count];
//	uint64_t rshares1[GFP_VECTOR*GFP_LIMBS];
//	uint64_t rshares2[GFP_VECTOR*GFP_LIMBS];


	for(size_t i=0; i<bits_count; ++i)
	{
		for(size_t j=0; j<GF2N_VECTOR; ++j)
		{
			bshares1[i*GF2N_VECTOR+j] = bit_shares[i*GF2N_SHR_LIMBS*GF2N_VECTOR+j];
			bshares2[i*GF2N_VECTOR+j] = bit_shares[i*GF2N_SHR_LIMBS*GF2N_VECTOR+j+GF2N_LIMBS*GF2N_VECTOR];
		}
	}

	if(0 == the_party->MP_skewRecomp((int)bits_count, bshares1, bshares2, rshares1, rshares2))
	{
		uint64_t * rshare = ring_shares;

		for(size_t j=0; j<GFP_VECTOR; ++j)
		{
			rshare[4*j]                         = rshares1[4*j];
			rshare[4*j+1]                       = rshares1[4*j+1];
			rshare[4*j+2]                       = rshares1[4*j+2];
			rshare[4*j+3]                       = rshares1[4*j+3];
			rshare[4*j+GFP_LIMBS*GFP_VECTOR]    = rshares2[4*j];
			rshare[4*j+1+GFP_LIMBS*GFP_VECTOR]  = rshares2[4*j+1];
			rshare[4*j+2+GFP_LIMBS*GFP_VECTOR]  = rshares2[4*j+2];
			rshare[4*j+3+GFP_LIMBS*GFP_VECTOR]  = rshares2[4*j+3];
		}
		result = 0;
	}
	else
	{
		LC(m_logcat).error("%s: protocol skew_recomp failure.", __FUNCTION__);
	}

	return result;
}

int spdz2_ext_processor_Z2::mp_skew_inject(const uint64_t * bits_input, uint64_t * rings_output)
{
	int result = -1;

	// no packing
	// GF2N_VECTOR = GFP_VECTOR
	std::vector<uint64_t> b_x0(GF2N_VECTOR);
	std::vector<uint64_t> b_x1(GF2N_VECTOR);
	std::vector<uint64_t> r_x0_0(GF2N_VECTOR);
	std::vector<uint64_t> r_x0_1(GF2N_VECTOR);
	std::vector<uint64_t> r_x1_0(GF2N_VECTOR);
	std::vector<uint64_t> r_x1_1(GF2N_VECTOR);
	std::vector<uint64_t> r_x2_0(GF2N_VECTOR);
	std::vector<uint64_t> r_x2_1(GF2N_VECTOR);

//	uint64_t b_x0[GF2N_VECTOR];
//	uint64_t b_x1[GF2N_VECTOR];
//	uint64_t r_x0_0[GF2N_VECTOR];
//	uint64_t r_x0_1[GF2N_VECTOR];
//	uint64_t r_x1_0[GF2N_VECTOR];
//	uint64_t r_x1_1[GF2N_VECTOR];
//	uint64_t r_x2_0[GF2N_VECTOR];
//	uint64_t r_x2_1[GF2N_VECTOR];

	for(size_t i=0; i<GF2N_VECTOR; ++i) {
		b_x0[i] = bits_input[i];
		b_x1[i] = bits_input[i+GF2N_LIMBS*GF2N_VECTOR];
	}

	if(0 == the_party->MP_skewInject(b_x0, b_x1, r_x0_0, r_x0_1, r_x1_0, r_x1_1, r_x2_0, r_x2_1))
	{
		uint64_t * rshare = rings_output;

		for(size_t j=0; j<GF2N_VECTOR; ++j)
		{
			rshare[2*j]                        = r_x0_0[j];
			rshare[2*j+1]                      = 0;
			rshare[2*j+2]                      = 0;
			rshare[2*j+3]                      = 0;
			rshare[2*j+GFP_LIMBS*GFP_VECTOR]   = r_x0_1[j];
			rshare[2*j+GFP_LIMBS*GFP_VECTOR+1] = 0;
			rshare[2*j+GFP_LIMBS*GFP_VECTOR+2] = 0;
			rshare[2*j+GFP_LIMBS*GFP_VECTOR+3] = 0;
			rshare += SHR_LIMBS*GF2N_VECTOR;

			rshare[2*j]                        = r_x1_0[j];
			rshare[2*j+1]                      = 0;
			rshare[2*j+2]                      = 0;
			rshare[2*j+3]                      = 0;
			rshare[2*j+GFP_LIMBS*GFP_VECTOR]   = r_x1_1[j];
			rshare[2*j+GFP_LIMBS*GFP_VECTOR+1] = 0;
			rshare[2*j+GFP_LIMBS*GFP_VECTOR+2] = 0;
			rshare[2*j+GFP_LIMBS*GFP_VECTOR+3] = 0;
			rshare += SHR_LIMBS*GF2N_VECTOR;

			rshare[2*j]                        = r_x2_0[j];
			rshare[2*j+1]                      = 0;
			rshare[2*j+2]                      = 0;
			rshare[2*j+3]                      = 0;
			rshare[2*j+GFP_LIMBS*GFP_VECTOR]   = r_x2_1[j];
			rshare[2*j+GFP_LIMBS*GFP_VECTOR+1] = 0;
			rshare[2*j+GFP_LIMBS*GFP_VECTOR+2] = 0;
			rshare[2*j+GFP_LIMBS*GFP_VECTOR+3] = 0;
		}
		result = 0;
	}
	else
	{
		LC(m_logcat).error("%s: protocol skew_inject failure.", __FUNCTION__);
	}
	return result;
}

std::string spdz2_ext_processor_Z2::get_parties_file()
{
	return "parties_z2.txt";
}

std::string spdz2_ext_processor_Z2::get_log_file()
{
	char buffer[128];
	snprintf(buffer, 128, "spdz2_x_z2_%d_%d.log", m_pid, m_thid);
	return std::string(buffer);
}

std::string spdz2_ext_processor_Z2::get_log_category()
{
	return "z2";
}

