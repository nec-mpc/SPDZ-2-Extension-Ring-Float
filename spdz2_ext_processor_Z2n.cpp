#include "spdzext_width_defs.h"
#include "spdz2_ext_processor_Z2n.h"
#include "Z2nIntReplicated.h"
#include "Z2nShareReplicated.h"

#include <log4cpp/Category.hh>

#include <syslog.h>
#include <bitset>

//std::vector<uint64_t> x_shares1;
//std::vector<uint64_t> x_shares2;
//std::vector<uint64_t> y_shares1;
//std::vector<uint64_t> y_shares2;
//std::vector<uint64_t> xy_shares1;
//std::vector<uint64_t> xy_shares2;

spdz2_ext_processor_Z2n::spdz2_ext_processor_Z2n()
 : spdz2_ext_processor_base()
 , the_party(NULL)
{
}

spdz2_ext_processor_Z2n::~spdz2_ext_processor_Z2n()
{
}

int spdz2_ext_processor_Z2n::init(const int pid, const int num_of_parties, const int thread_id, const char * field,
		 	 	 	 	 	 	 	 	 const int open_count, const int mult_count, const int bits_count, int log_level)
{
	if(0 == spdz2_ext_processor_base::init(pid, num_of_parties, thread_id, field, open_count, mult_count, bits_count, log_level))
	{
		the_party = new NecProtocolPartyRingFor3P<uint64_t>(pid, 0);
		the_party->init();
	}
	return 0;
}

int spdz2_ext_processor_Z2n::term()
{
	delete the_party;
	the_party = NULL;
	LC(m_logcat).info("%s.", __FUNCTION__);
	return 0;
}

int spdz2_ext_processor_Z2n::input(const int input_of_pid, const size_t num_of_inputs, uint64_t * input_value)
{
	if (0 != the_party->input(input_of_pid, num_of_inputs, input_value))
	{
		LC(m_logcat).error("%s: protocol input failure.", __FUNCTION__);
		return -1;
	}

	return 0;
}


int spdz2_ext_processor_Z2n::closes(const int share_of_pid, const size_t value_count, const uint64_t * values, uint64_t * shares)
{
	std::vector<uint64_t> z2nshares1(GFP_VECTOR*value_count);
	std::vector<uint64_t> z2nshares2(GFP_VECTOR*value_count);
	std::vector<uint64_t> z2nvalues(GFP_VECTOR*value_count);

	for(size_t i=0; i<GFP_VECTOR*value_count; ++i) {
		z2nvalues[i] = values[GFP_LIMBS*i];
	}

	if(0 == the_party->makeShare(share_of_pid, z2nvalues, z2nshares1, z2nshares2))
	{
		for(size_t i=0; i<value_count; ++i)
		{
			uint64_t * share = shares + (i*SHR_LIMBS*GFP_VECTOR);
			for(size_t j=0; j<GFP_VECTOR; ++j)
			{
				memset(share, 0, SHR_LIMBS*GFP_VECTOR*sizeof(uint64_t));
				share[j*GFP_LIMBS]                      = z2nshares1[i*GFP_VECTOR+j];
				share[j*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR] = z2nshares2[i*GFP_VECTOR+j];
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

int spdz2_ext_processor_Z2n::open(const size_t share_count, const uint64_t * share_values, uint64_t * opens, int verify)
{
	int result = -1;
	std::vector<uint64_t> z2nshares1(GFP_VECTOR*share_count);
	std::vector<uint64_t> z2nshares2(GFP_VECTOR*share_count);
	std::vector<uint64_t> z2nopens(GFP_VECTOR*share_count);

	for(size_t i=0; i<share_count; ++i)
	{
		const uint64_t * share = share_values + i*SHR_LIMBS*GFP_VECTOR;

		for(size_t j=0; j<GFP_VECTOR; ++j)
		{
			z2nshares1[i*GFP_VECTOR+j] = share[GFP_LIMBS*j];
			z2nshares2[i*GFP_VECTOR+j] = share[GFP_LIMBS*j+GFP_LIMBS*GFP_VECTOR];
		}
	}


	if(0 == the_party->openShare((int)GFP_VECTOR*share_count, z2nshares1, z2nshares2, z2nopens))
	{

		if(!verify || the_party->verify())
		{
			for(size_t i=0; i<GFP_VECTOR*share_count; ++i)
			{
				memset(&opens[GFP_LIMBS*i], 0, GFP_LIMBS*sizeof(uint64_t));
				opens[GFP_LIMBS*i]   = z2nopens[i];
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

int spdz2_ext_processor_Z2n::verify(int * error)
{
	return (0 == the_party->verify())? 0: -1;
}

int spdz2_ext_processor_Z2n::mult(const size_t share_count, const uint64_t * xshares, const uint64_t * yshares, uint64_t * products, int verify)

{
	LC(m_logcat).info("%s called for %lu shares.", __FUNCTION__, share_count);
	int result = -1;
	std::vector<uint64_t> x_shares1(GFP_VECTOR*share_count);
	std::vector<uint64_t> x_shares2(GFP_VECTOR*share_count);
	std::vector<uint64_t> y_shares1(GFP_VECTOR*share_count);
	std::vector<uint64_t> y_shares2(GFP_VECTOR*share_count);
	std::vector<uint64_t> xy_shares1(GFP_VECTOR*share_count);
	std::vector<uint64_t> xy_shares2(GFP_VECTOR*share_count);

	for(size_t i=0; i<share_count; ++i)
	{
		const uint64_t * xshare = xshares + i*SHR_LIMBS*GFP_VECTOR;
		const uint64_t * yshare = yshares + i*SHR_LIMBS*GFP_VECTOR;
		for(size_t j=0; j<GFP_VECTOR; ++j)
		{
			x_shares1[i*GFP_VECTOR+j] = xshare[2*j];
			x_shares2[i*GFP_VECTOR+j] = xshare[2*j+GFP_LIMBS*GFP_VECTOR];
			y_shares1[i*GFP_VECTOR+j] = yshare[2*j];
			y_shares2[i*GFP_VECTOR+j] = yshare[2*j+GFP_LIMBS*GFP_VECTOR];
		}
	}

	if(0 == the_party->multShares((int)GFP_VECTOR*share_count, x_shares1, x_shares2, y_shares1, y_shares2, xy_shares1, xy_shares2))
	{
		for(size_t i=0; i<share_count; ++i)
		{
			uint64_t * product = products + i*SHR_LIMBS*GFP_VECTOR;
			for(size_t j=0; j<GFP_VECTOR; ++j)
			{
//				memset(&product[GFP_LIMBS*j], 0, GFP_LIMBS*sizeof(uint64_t));
//				memset(&product[GFP_LIMBS*j+GFP_LIMBS*GFP_VECTOR], 0, GFP_LIMBS*sizeof(uint64_t));
				product[GFP_LIMBS*j]                      = xy_shares1[i*GFP_VECTOR+j];
				product[GFP_LIMBS*j+GFP_LIMBS*GFP_VECTOR]   = xy_shares2[i*GFP_VECTOR+j];
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

int spdz2_ext_processor_Z2n::mix_add(const uint64_t * share, const uint64_t * scalar, uint64_t * sum)
{
	for(size_t i=0; i<GFP_VECTOR; ++i)
	{
		uint64_t input[2], output[2], arg;
		input[0] = share[i*GFP_LIMBS];
		input[1] = share[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR];
		arg = scalar[i*GFP_LIMBS];
		if (m_pid == 0) {
			output[0] = input[0];
			output[1] = input[1];
		}
		else if (m_pid == 1) {
			output[0] = input[0] + arg;
			output[1] = input[1] + arg;
		}
		else if (m_pid == 2) {
			output[0] = input[0] + arg;
			output[1] = input[1];
		}
//		memset(&sum[i*GFP_LIMBS], 0, GFP_LIMBS*sizeof(uint64_t));
//		memset(&sum[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR] , 0, GFP_LIMBS*sizeof(uint64_t));
		sum[i*GFP_LIMBS]                        = output[0];
		sum[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR]   = output[1];
		LC(m_logcat + ".acct").debug("%s: sh=%lu; sc=%lu; su=%lu, %lu;", __FUNCTION__, share[i*2], scalar[i*2], sum[i*2], sum[i*2+GFP_LIMBS*GFP_VECTOR]);
	}
	return 0;
}

int spdz2_ext_processor_Z2n::mix_sub_scalar(const uint64_t * share, const uint64_t * scalar, uint64_t * diff)
{
	for(size_t i=0; i<GFP_VECTOR; ++i)
	{
		uint64_t input[2], output[2], arg;
		input[0] = share[i*GFP_LIMBS];
		input[1] = share[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR];
		arg = scalar[i*GFP_LIMBS];
		if (m_pid == 0) {
			output[0] = input[0];
			output[1] = input[1];
		}
		else if (m_pid == 1) {
			output[0] = input[0] - arg;
			output[1] = input[1] - arg;
		}
		else if (m_pid == 2) {
			output[0] = input[0] - arg;
			output[1] = input[1];
		}
//		memset(&diff[i*GFP_LIMBS], 0, GFP_LIMBS*sizeof(uint64_t));
//		memset(&diff[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR] , 0, GFP_LIMBS*sizeof(uint64_t));
		diff[i*GFP_LIMBS]                        = output[0];
		diff[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR]   = output[1];
		LC(m_logcat + ".acct").debug("%s: sh=%lu; sc=%lu; df=%lu, %lu;", __FUNCTION__, share[i*2], scalar[i*2], diff[i*2], diff[i*2+GFP_LIMBS*GFP_VECTOR]);
	}
	return 0;
}

int spdz2_ext_processor_Z2n::mix_sub_share(const uint64_t * scalar, const uint64_t * share, uint64_t * diff)
{
	for(size_t i=0; i<GFP_VECTOR; ++i)
	{
		uint64_t input[2], output[2], arg;
		input[0] = share[i*GFP_LIMBS];
		input[1] = share[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR];
		arg = scalar[i*GFP_LIMBS];
		if (m_pid == 0) {
			output[0] = - input[0];
			output[1] = - input[1];
		}
		else if (m_pid == 1) {
			output[0] = arg - input[0];
			output[1] = arg - input[1];
		}
		else if (m_pid == 2) {
			output[0] = arg - input[0];
			output[1] = - input[1];
		}
//		memset(&diff[i*GFP_LIMBS], 0, GFP_LIMBS*sizeof(uint64_t));
//		memset(&diff[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR] , 0, GFP_LIMBS*sizeof(uint64_t));
		diff[i*GFP_LIMBS]                        = output[0];
		diff[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR]   = output[1];
		LC(m_logcat + ".acct").debug("%s: sh=%lu; sc=%lu; df=%lu, %lu;", __FUNCTION__, share[i*2], scalar[i*2], diff[i*2], diff[i*2+GFP_LIMBS*GFP_VECTOR]);
	}
	return 0;
}

int spdz2_ext_processor_Z2n::mix_mul(const uint64_t * share, const uint64_t * scalar, uint64_t * product)
{
	for(size_t i=0; i<GFP_VECTOR; ++i)
	{
		uint64_t input[2], output[2], arg;
		input[0] = share[i*GFP_LIMBS];
		input[1] = share[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR];
		arg = scalar[i*GFP_LIMBS];
		if (m_pid == 0) {
			output[0] = input[0] * arg;
			output[1] = input[1] * arg;
		}
		else if (m_pid == 1) {
			output[0] = input[0] * arg;
			output[1] = input[1] * arg;
		}
		else if (m_pid == 2) {
			output[0] = input[0] * arg;
			output[1] = input[1] * arg;
		}
//		memset(&product[i*GFP_LIMBS], 0, GFP_LIMBS*sizeof(uint64_t));
//		memset(&product[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR] , 0, GFP_LIMBS*sizeof(uint64_t));
		product[i*GFP_LIMBS]                        = output[0];
		product[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR]   = output[1];
		LC(m_logcat + ".acct").debug("%s: sh=%lu; sc=%lu; pd=%lu, %lu;", __FUNCTION__, share[i*2], scalar[i*2], product[i*2], product[i*2+GFP_LIMBS*GFP_VECTOR]);
	}
	return 0;
}

int spdz2_ext_processor_Z2n::adds(const uint64_t * share1, const uint64_t * share2, uint64_t * sum)
{
	for(size_t i=0; i<GFP_VECTOR; ++i)
	{
		uint64_t __share1[2], __share2[2];
		__share1[0] = share1[i*GFP_LIMBS];
		__share1[1] = share1[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR];
		__share2[0] = share2[i*GFP_LIMBS];
		__share2[1] = share2[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR];
//		memset(&sum[i*GFP_LIMBS], 0, GFP_LIMBS*sizeof(uint64_t));
//		memset(&sum[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR] , 0, GFP_LIMBS*sizeof(uint64_t));
		sum[i*GFP_LIMBS]                        = __share1[0] + __share2[0];
		sum[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR]   = __share1[1] + __share2[1];
		LC(m_logcat + ".acct").debug("%s: sh1=%lu; sh2=%lu; sum=%lu, %lu;", __FUNCTION__, __share1[0], __share2[0], sum[i*2], sum[i*2+GFP_LIMBS*GFP_VECTOR]);
	}
	return 0;
}

int spdz2_ext_processor_Z2n::subs(const uint64_t * share1, const uint64_t * share2, uint64_t * diff)
{
	for(size_t i=0; i<GFP_VECTOR; ++i)
	{
		uint64_t __share1[2], __share2[2];
		__share1[0] = share1[i*GFP_LIMBS];
		__share1[1] = share1[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR];
		__share2[0] = share2[i*GFP_LIMBS];
		__share2[1] = share2[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR];
//		memset(&diff[i*GFP_LIMBS], 0, GFP_LIMBS*sizeof(uint64_t));
//		memset(&diff[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR] , 0, GFP_LIMBS*sizeof(uint64_t));
		diff[i*GFP_LIMBS]                        = __share1[0] - __share2[0];
		diff[i*GFP_LIMBS+GFP_LIMBS*GFP_VECTOR]   = __share1[1] - __share2[1];
		LC(m_logcat + ".acct").debug("%s: sh1=%lu; sh2=%lu; dif=%lu, %lu;", __FUNCTION__, __share1[0], __share2[0], diff[i*2], diff[i*2+GFP_LIMBS*GFP_VECTOR]);
	}
	return 0;
}

int spdz2_ext_processor_Z2n::skew_decomp(const size_t bits_count, const uint64_t * ring_shares, uint64_t * bit_shares)
{

	int result = -1;

	std::vector<uint64_t> r_x0(GFP_VECTOR);
	std::vector<uint64_t> r_x1(GFP_VECTOR);
	std::vector<uint64_t> b_x0_0(GFP_VECTOR*bits_count);
	std::vector<uint64_t> b_x0_1(GFP_VECTOR*bits_count);
	std::vector<uint64_t> b_x1_0(GFP_VECTOR*bits_count);
	std::vector<uint64_t> b_x1_1(GFP_VECTOR*bits_count);
	std::vector<uint64_t> b_x2_0(GFP_VECTOR*bits_count);
	std::vector<uint64_t> b_x2_1(GFP_VECTOR*bits_count);

	for(size_t i=0; i<GFP_VECTOR; ++i) {
		r_x0[i] = ring_shares[2*i];
		r_x1[i] = ring_shares[2*i+GFP_LIMBS*GFP_VECTOR];
	}

	if(0 == the_party->skewDecomp((int)bits_count, r_x0, r_x1, b_x0_0, b_x0_1, b_x1_0, b_x1_1, b_x2_0, b_x2_1))
	{
		for(size_t i=0; i<bits_count; ++i)
		{
			uint64_t * bshare = bit_shares + 3*i*GF2N_SHR_LIMBS*GF2N_VECTOR;
			for(size_t j=0; j<GFP_VECTOR; ++j)
			{
				bshare[j]                          = b_x0_0[i*GFP_VECTOR+j];
				bshare[j+GF2N_LIMBS*GF2N_VECTOR]   = b_x0_1[i*GFP_VECTOR+j];
				bshare += GF2N_SHR_LIMBS*GF2N_VECTOR;
				bshare[j]                          = b_x1_0[i*GFP_VECTOR+j];
				bshare[j+GF2N_LIMBS*GF2N_VECTOR]   = b_x1_1[i*GFP_VECTOR+j];
				bshare += GF2N_SHR_LIMBS*GF2N_VECTOR;
				bshare[j]                          = b_x2_0[i*GFP_VECTOR+j];
				bshare[j+GF2N_LIMBS*GF2N_VECTOR]   = b_x2_1[i*GFP_VECTOR+j];
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


int spdz2_ext_processor_Z2n::mp_skew_decomp(const size_t bits_count, const uint64_t * ring_shares, uint64_t * bit_shares)
{
	int result = -1;

	// no packing
	// GFP_VECTOR = GF2N_VECTOR
	std::vector<uint64_t> r_x0(GFP_LIMBS*GFP_VECTOR);
	std::vector<uint64_t> r_x1(GFP_LIMBS*GFP_VECTOR);
	std::vector<uint64_t> b_x0_0(GFP_VECTOR*bits_count);
	std::vector<uint64_t> b_x0_1(GFP_VECTOR*bits_count);
	std::vector<uint64_t> b_x1_0(GFP_VECTOR*bits_count);
	std::vector<uint64_t> b_x1_1(GFP_VECTOR*bits_count);
	std::vector<uint64_t> b_x2_0(GFP_VECTOR*bits_count);
	std::vector<uint64_t> b_x2_1(GFP_VECTOR*bits_count);

	for(size_t i=0; i<GFP_VECTOR; ++i) {
		for(size_t j=0; j<GFP_LIMBS; ++j) {
			r_x0[GFP_LIMBS*i+j] = ring_shares[GFP_LIMBS*i+j];
			r_x1[GFP_LIMBS*i+j] = ring_shares[GFP_LIMBS*GFP_VECTOR+GFP_LIMBS*i+j];
		}
	}

	if(0 == the_party->MP_skewDecomp((int)bits_count, r_x0, r_x1, b_x0_0, b_x0_1, b_x1_0, b_x1_1, b_x2_0, b_x2_1))
	{
		// GFP_VECTOR = GF2N_VECTOR
		for(size_t i=0; i<bits_count; ++i)
		{
			uint64_t * bshare = bit_shares + 3*i*GF2N_SHR_LIMBS*GF2N_VECTOR;
			for(size_t j=0; j<GFP_VECTOR; ++j)
			{
				bshare[j]                          = b_x0_0[i*GFP_VECTOR+j];
				bshare[j+GF2N_LIMBS*GF2N_VECTOR]   = b_x0_1[i*GFP_VECTOR+j];
				bshare += GF2N_SHR_LIMBS*GF2N_VECTOR;
				bshare[j]                          = b_x1_0[i*GFP_VECTOR+j];
				bshare[j+GF2N_LIMBS*GF2N_VECTOR]   = b_x1_1[i*GFP_VECTOR+j];
				bshare += GF2N_SHR_LIMBS*GF2N_VECTOR;
				bshare[j]                          = b_x2_0[i*GFP_VECTOR+j];
				bshare[j+GF2N_LIMBS*GF2N_VECTOR]   = b_x2_1[i*GFP_VECTOR+j];
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

int spdz2_ext_processor_Z2n::skew_recomp(const size_t bits_count, const uint64_t * bit_shares, uint64_t * ring_shares)
{
	return 0;
}

int spdz2_ext_processor_Z2n::skew_inject(const uint64_t * bit_shares, uint64_t * ring_shares)
{
	return 0;
}

int spdz2_ext_processor_Z2n::mp_closes(const int share_of_pid, const size_t value_count, const uint64_t * values, uint64_t * shares)
{
	// value_count = 1
	std::vector<uint64_t> z2nshares1(GFP_LIMBS*GFP_VECTOR*value_count);
	std::vector<uint64_t> z2nshares2(GFP_LIMBS*GFP_VECTOR*value_count);
	std::vector<uint64_t> z2nvalues(GFP_LIMBS*GFP_VECTOR*value_count);

	for(size_t i=0; i<GFP_VECTOR*value_count; ++i) {
		for(size_t j=0; j<GFP_LIMBS; ++j) {
			z2nvalues[GFP_LIMBS*i+j] = values[GFP_LIMBS*i+j];
		}
	}

	if(0 == the_party->makeShare(share_of_pid, z2nvalues, z2nshares1, z2nshares2))
	{
		for(size_t i=0; i<value_count; ++i)
		{
			uint64_t * share = shares + (i*SHR_LIMBS*GFP_VECTOR);
			memset(share, 0, SHR_LIMBS*GFP_VECTOR*sizeof(uint64_t));
			for(size_t j=0; j<GFP_VECTOR; ++j)
			{
				for(size_t k=0; k<GFP_LIMBS; ++k)
				{
					share[j*GFP_LIMBS+k]                      = z2nshares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+k];
					share[GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+k] = z2nshares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+k];
				}
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

int spdz2_ext_processor_Z2n::mp_open(const size_t share_count, const uint64_t * share_values, uint64_t * opens, int verify)
{
	int result = -1;
	std::vector<uint64_t> z2nshares1(GFP_LIMBS*GFP_VECTOR*share_count);
	std::vector<uint64_t> z2nshares2(GFP_LIMBS*GFP_VECTOR*share_count);
	std::vector<uint64_t> z2nopens(GFP_LIMBS*GFP_VECTOR*share_count);

//	uint64_t z2nshares1[GFP_LIMBS*GFP_VECTOR*share_count];
//	uint64_t z2nshares2[GFP_LIMBS*GFP_VECTOR*share_count];
//	uint64_t z2nopens[GFP_LIMBS*GFP_VECTOR*share_count];

	for(size_t i=0; i<share_count; ++i)
	{
		const uint64_t * share = share_values + i*SHR_LIMBS*GFP_VECTOR;
		for(size_t j=0; j<GFP_VECTOR; ++j)
		{
			for(size_t k=0; k<GFP_LIMBS; ++k)
			{
				z2nshares1[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+k] = share[GFP_LIMBS*j+k];
				z2nshares2[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+k] = share[GFP_LIMBS*GFP_VECTOR+GFP_LIMBS*j+k];
			}
		}
	}


	if(0 == the_party->openMPShare((int)GFP_LIMBS*GFP_VECTOR*share_count, z2nshares1, z2nshares2, z2nopens))
	{

		if(!verify || the_party->verify())
		{
			for(size_t i=0; i<share_count; ++i)
			{
				for(size_t j=0; j<GFP_VECTOR; ++j)
				{
					for(size_t k=0; k<GFP_LIMBS; ++k)
					{
						opens[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+k] = z2nopens[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+k];
					}
				}
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
		LC(m_logcat).error("%s: openMPShare failure.", __FUNCTION__);
	}
	return result;

}

int spdz2_ext_processor_Z2n::mp_adds(const uint64_t * share1, const uint64_t * share2, uint64_t * sum)
{
	mp::uint256_t sh11, sh12, sh21, sh22, res1, res2;
	mp::uint256_t sh_tmp;

#if(MP_RING_SIZE!=256)
	mp::uint256_t mp_mod = (std::numeric_limits<mp::uint256_t>::max()) >> (256 - MP_RING_SIZE);
#endif

	for(size_t i=0; i<GFP_VECTOR; ++i)
	{
		sh11 = sh12 = sh21 = sh22 = 0;
		for(size_t j=0; j<GFP_LIMBS; ++j)
		{
			sh_tmp = (mp::uint256_t) share1[GFP_LIMBS * i + j];
//			cout << "[spdz2_ext_processor_Z2n.cpp] share1[" << GFP_LIMBS * i + j << "] = " << sh_tmp << endl;
			sh11 += (sh_tmp << (64 * j));
			sh_tmp = (mp::uint256_t) share1[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + j];
//			cout << "[spdz2_ext_processor_Z2n.cpp] share1[" << GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + j << "] = " << sh_tmp << endl;
			sh12 += (sh_tmp << (64 * j));
			sh_tmp = (mp::uint256_t) share2[GFP_LIMBS * i + j];
//			cout << "[spdz2_ext_processor_Z2n.cpp] share2[" << GFP_LIMBS * i + j << "] = " << sh_tmp << endl;
			sh21 += (sh_tmp << (64 * j));
			sh_tmp = (mp::uint256_t) share2[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + j];
//			cout << "[spdz2_ext_processor_Z2n.cpp] share2[" << GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + j << "] = " << sh_tmp << endl;
			sh22 += (sh_tmp << (64 * j));
		}
#if(MP_RING_SIZE==256)
			res1 = sh11 + sh21;
			res2 = sh12 + sh22;
#else
			res1 = (sh11 + sh21) & mp_mod;
			res2 = (sh12 + sh22) & mp_mod;
#endif
		// share1 of sum
		sum[GFP_LIMBS * i + 0] = (uint64_t) (res1 & 0xffffffffffffffff);
		sum[GFP_LIMBS * i + 1] = (uint64_t) ((res1 >> 64) & 0xffffffffffffffff);
		sum[GFP_LIMBS * i + 2] = (uint64_t) ((res1 >> 128) & 0xffffffffffffffff);
		sum[GFP_LIMBS * i + 3] = (uint64_t) ((res1 >> 192) & 0xffffffffffffffff);
		// share2 of sum
		sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0] = (uint64_t) (res2 & 0xffffffffffffffff);
		sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1] = (uint64_t) ((res2 >> 64) & 0xffffffffffffffff);
		sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2] = (uint64_t) ((res2 >> 128) & 0xffffffffffffffff);
		sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3] = (uint64_t) ((res2 >> 192) & 0xffffffffffffffff);
	//		LC(m_logcat + ".acct").debug("%s: sh=%lu; sc=%lu; su=%lu, %lu;", __FUNCTION__, share[i*2], scalar[i*2], sum[i*2], sum[i*2+GFP_LIMBS*GFP_VECTOR]);
	}
	return 0;
}


int spdz2_ext_processor_Z2n::mp_mix_add(const uint64_t * share, const uint64_t * scalar, uint64_t * sum)
{
	mp::uint256_t sh1, sh2, clr;
	mp::uint256_t sh_tmp1, sh_tmp2, clr_tmp;

#if(MP_RING_SIZE!=256)
	mp::uint256_t mp_mod = (std::numeric_limits<mp::uint256_t>::max()) >> (256 - MP_RING_SIZE);
#endif

	for(size_t i=0; i<GFP_VECTOR; ++i)
	{
		sh1 = sh2 = clr =0;
		for(size_t j=0; j<GFP_LIMBS; ++j)
		{
			sh_tmp1 = (mp::uint256_t) share[GFP_LIMBS * i + j];
			sh1 += (sh_tmp1 << (64 * j));
			sh_tmp2 = (mp::uint256_t) share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + j];
			sh2 += (sh_tmp2 << (64 * j));
			clr_tmp = (mp::uint256_t) scalar[GFP_LIMBS * i + j];
			clr += (clr_tmp << (64 * j));
		}

		if (m_pid == 0) {
			// share1 of sum
			sum[GFP_LIMBS * i + 0] = share[GFP_LIMBS * i + 0];
			sum[GFP_LIMBS * i + 1] = share[GFP_LIMBS * i + 1];
			sum[GFP_LIMBS * i + 2] = share[GFP_LIMBS * i + 2];
			sum[GFP_LIMBS * i + 3] = share[GFP_LIMBS * i + 3];
			// share2 of sum
			sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0];
			sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1];
			sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2];
			sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3];
		}
		else if (m_pid == 1) {
#if(MP_RING_SIZE==256)
			sh1 += clr;
			sh2 += clr;
#else
			sh1 = (sh1 + clr) & mp_mod;
			sh2 = (sh2 + clr) & mp_mod;
#endif
			// share1 of sum
			sum[GFP_LIMBS * i + 0] = (uint64_t) (sh1 & 0xffffffffffffffff);
			sum[GFP_LIMBS * i + 1] = (uint64_t) ((sh1 >> 64) & 0xffffffffffffffff);
			sum[GFP_LIMBS * i + 2] = (uint64_t) ((sh1 >> 128) & 0xffffffffffffffff);
			sum[GFP_LIMBS * i + 3] = (uint64_t) ((sh1 >> 192) & 0xffffffffffffffff);
			// share2 of sum
			sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0] = (uint64_t) (sh2 & 0xffffffffffffffff);
			sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1] = (uint64_t) ((sh2 >> 64) & 0xffffffffffffffff);
			sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2] = (uint64_t) ((sh2 >> 128) & 0xffffffffffffffff);
			sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3] = (uint64_t) ((sh2 >> 192) & 0xffffffffffffffff);
		}
		else if (m_pid == 2) {
#if(MP_RING_SIZE==256)
			sh1 += clr;
#else
			sh1 = (sh1 + clr) & mp_mod;
#endif
			// share1 of sum
			sum[GFP_LIMBS * i + 0] = (uint64_t) (sh1 & 0xffffffffffffffff);
			sum[GFP_LIMBS * i + 1] = (uint64_t) ((sh1 >> 64) & 0xffffffffffffffff);
			sum[GFP_LIMBS * i + 2] = (uint64_t) ((sh1 >> 128) & 0xffffffffffffffff);
			sum[GFP_LIMBS * i + 3] = (uint64_t) ((sh1 >> 192) & 0xffffffffffffffff);
			// share2 of sum
			sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0];
			sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1];
			sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2];
			sum[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3];
		}
//		LC(m_logcat + ".acct").debug("%s: sh=%lu; sc=%lu; su=%lu, %lu;", __FUNCTION__, share[i*2], scalar[i*2], sum[i*2], sum[i*2+GFP_LIMBS*GFP_VECTOR]);
	}
	return 0;
}

int spdz2_ext_processor_Z2n::mp_subs(const uint64_t * share1, const uint64_t * share2, uint64_t * diff)
{
	mp::uint256_t sh11, sh12, sh21, sh22, res1, res2;
	mp::uint256_t sh_tmp;
#if(MP_RING_SIZE!=256)
	mp::uint256_t mp_mod = (std::numeric_limits<mp::uint256_t>::max()) >> (256 - MP_RING_SIZE);
#endif
	for(size_t i=0; i<GFP_VECTOR; ++i)
	{
		sh11 = sh12 = sh21 = sh22 = 0;
		for(size_t j=0; j<GFP_LIMBS; ++j)
		{
			sh_tmp = (mp::uint256_t) share1[GFP_LIMBS * i + j];
			sh11 += (sh_tmp << (64 * j));
			sh_tmp = (mp::uint256_t) share1[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + j];
			sh12 += (sh_tmp << (64 * j));
			sh_tmp = (mp::uint256_t) share2[GFP_LIMBS * i + j];
			sh21 += (sh_tmp << (64 * j));
			sh_tmp = (mp::uint256_t) share2[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + j];
			sh22 += (sh_tmp << (64 * j));
		}
#if(MP_RING_SIZE==256)
			res1 = sh11 - sh21;
			res2 = sh12 - sh22;
#else
			res1 = (sh11 - sh21) & mp_mod;
			res2 = (sh12 - sh22) & mp_mod;
#endif
			// share1 of sum
			diff[GFP_LIMBS * i + 0] = (uint64_t) (res1 & 0xffffffffffffffff);
			diff[GFP_LIMBS * i + 1] = (uint64_t) ((res1 >> 64) & 0xffffffffffffffff);
			diff[GFP_LIMBS * i + 2] = (uint64_t) ((res1 >> 128) & 0xffffffffffffffff);
			diff[GFP_LIMBS * i + 3] = (uint64_t) ((res1 >> 192) & 0xffffffffffffffff);
			// share2 of sum
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0] = (uint64_t) (res2 & 0xffffffffffffffff);
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1] = (uint64_t) ((res2 >> 64) & 0xffffffffffffffff);
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2] = (uint64_t) ((res2 >> 128) & 0xffffffffffffffff);
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3] = (uint64_t) ((res2 >> 192) & 0xffffffffffffffff);
	//		LC(m_logcat + ".acct").debug("%s: sh=%lu; sc=%lu; su=%lu, %lu;", __FUNCTION__, share[i*2], scalar[i*2], sum[i*2], sum[i*2+GFP_LIMBS*GFP_VECTOR]);
	}

	return 0;
}

int spdz2_ext_processor_Z2n::mp_mix_sub_share(const uint64_t * scalar, const uint64_t * share, uint64_t * diff)
{
	mp::uint256_t sh1, sh2, clr;
	mp::uint256_t sh_tmp1, sh_tmp2, clr_tmp;

#if(MP_RING_SIZE!=256)
	mp::uint256_t mp_mod = (std::numeric_limits<mp::uint256_t>::max()) >> (256 - MP_RING_SIZE);
#endif

	for(size_t i=0; i<GFP_VECTOR; ++i) {
		sh1 = sh2 = clr =0;
		for(size_t j=0; j<GFP_LIMBS; ++j) {
			sh_tmp1 = (mp::uint256_t) share[GFP_LIMBS * i + j];
			sh1 += (sh_tmp1 << (64 * j));
			sh_tmp2 = (mp::uint256_t) share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + j];
			sh2 += (sh_tmp2 << (64 * j));
			clr_tmp = (mp::uint256_t) scalar[GFP_LIMBS * i + j];
			clr += (clr_tmp << (64 * j));
		}
		if (m_pid == 0) {
#if(MP_RING_SIZE==256)
			sh1 = 0 - sh1;
			sh2 = 0 - sh2;
#else
			sh1 = (0 - sh1) & mp_mod;
			sh2 = (0 - sh2) & mp_mod;
#endif
		}
		else if (m_pid == 1) {
#if(MP_RING_SIZE==256)
			sh1 = clr - sh1;
			sh2 = clr - sh2;
#else
			sh1 = (clr - sh1) & mp_mod;
			sh2 = (clr - sh2) & mp_mod;
#endif
		}
		else if (m_pid == 2) {
#if(MP_RING_SIZE==256)
			sh1 = clr - sh1;
			sh2 = 0 - sh2;
#else
			sh1 = (clr - sh1) & mp_mod;
			sh2 = (0 - sh1) & mp_mod;
#endif
		}
		// share1 of diff
		diff[GFP_LIMBS * i + 0] = (uint64_t) (sh1 & 0xffffffffffffffff);
		diff[GFP_LIMBS * i + 1] = (uint64_t) ((sh1 >> 64) & 0xffffffffffffffff);
		diff[GFP_LIMBS * i + 2] = (uint64_t) ((sh1 >> 128) & 0xffffffffffffffff);
		diff[GFP_LIMBS * i + 3] = (uint64_t) ((sh1 >> 192) & 0xffffffffffffffff);
		// share2 of diff
		diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0] = (uint64_t) (sh2 & 0xffffffffffffffff);
		diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1] = (uint64_t) ((sh2 >> 64) & 0xffffffffffffffff);
		diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2] = (uint64_t) ((sh2 >> 128) & 0xffffffffffffffff);
		diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3] = (uint64_t) ((sh2 >> 192) & 0xffffffffffffffff);
//		LC(m_logcat + ".acct").debug("%s: sh=%lu; sc=%lu; df=%lu, %lu;", __FUNCTION__, share[i*2], scalar[i*2], diff[i*2], diff[i*2+GFP_LIMBS*GFP_VECTOR]);
	}
	return 0;
}

int spdz2_ext_processor_Z2n::mp_mix_sub_scalar(const uint64_t * share, const uint64_t * scalar, uint64_t * diff)
{
	mp::uint256_t sh1, sh2, clr;
	mp::uint256_t sh_tmp1, sh_tmp2, clr_tmp;

#if(MP_RING_SIZE!=256)
	mp::uint256_t mp_mod = (std::numeric_limits<mp::uint256_t>::max()) >> (256 - MP_RING_SIZE);
#endif

	for(size_t i=0; i<GFP_VECTOR; ++i)
	{
		sh1 = sh2 = clr =0;
		for(size_t j=0; j<GFP_LIMBS; ++j)
		{
			sh_tmp1 = (mp::uint256_t) share[GFP_LIMBS * i + j];
			sh1 += (sh_tmp1 << (64 * j));
			sh_tmp2 = (mp::uint256_t) share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + j];
			sh2 += (sh_tmp2 << (64 * j));
			clr_tmp = (mp::uint256_t) scalar[GFP_LIMBS * i + j];
			clr += (clr_tmp << (64 * j));
		}

		if (m_pid == 0) {
			// share1 of diff
			diff[GFP_LIMBS * i + 0] = share[GFP_LIMBS * i + 0];
			diff[GFP_LIMBS * i + 1] = share[GFP_LIMBS * i + 1];
			diff[GFP_LIMBS * i + 2] = share[GFP_LIMBS * i + 2];
			diff[GFP_LIMBS * i + 3] = share[GFP_LIMBS * i + 3];
			// share2 of sum
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0];
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1];
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2];
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3];
		}
		else if (m_pid == 1) {
#if(MP_RING_SIZE==256)
			sh1 = sh1 - clr;
			sh2 = sh2 - clr;
#else
			sh1 = (sh1 - clr) & mp_mod;
			sh2 = (sh2 - clr) & mp_mod;
#endif
			// share1 of diff
			diff[GFP_LIMBS * i + 0] = (uint64_t) (sh1 & 0xffffffffffffffff);
			diff[GFP_LIMBS * i + 1] = (uint64_t) ((sh1 >> 64) & 0xffffffffffffffff);
			diff[GFP_LIMBS * i + 2] = (uint64_t) ((sh1 >> 128) & 0xffffffffffffffff);
			diff[GFP_LIMBS * i + 3] = (uint64_t) ((sh1 >> 192) & 0xffffffffffffffff);
			// share2 of diff
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0] = (uint64_t) (sh2 & 0xffffffffffffffff);
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1] = (uint64_t) ((sh2 >> 64) & 0xffffffffffffffff);
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2] = (uint64_t) ((sh2 >> 128) & 0xffffffffffffffff);
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3] = (uint64_t) ((sh2 >> 192) & 0xffffffffffffffff);
		}
		else if (m_pid == 2) {
#if(MP_RING_SIZE==256)
			sh1 = sh1 - clr;
#else
			sh1 = (sh1 - clr) & mp_mod;
#endif
			// share1 of diff
			diff[GFP_LIMBS * i + 0] = (uint64_t) (sh1 & 0xffffffffffffffff);
			diff[GFP_LIMBS * i + 1] = (uint64_t) ((sh1 >> 64) & 0xffffffffffffffff);
			diff[GFP_LIMBS * i + 2] = (uint64_t) ((sh1 >> 128) & 0xffffffffffffffff);
			diff[GFP_LIMBS * i + 3] = (uint64_t) ((sh1 >> 192) & 0xffffffffffffffff);
			// share2 of diff
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0];
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1];
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2];
			diff[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3] = share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3];
		}
//		LC(m_logcat + ".acct").debug("%s: sh=%lu; sc=%lu; df=%lu, %lu;", __FUNCTION__, share[i*2], scalar[i*2], diff[i*2], diff[i*2+GFP_LIMBS*GFP_VECTOR]);
	}
	return 0;
}

int spdz2_ext_processor_Z2n::mp_mix_mul(const uint64_t * share, const uint64_t * scalar, uint64_t * product)
{
	mp::uint256_t sh1, sh2, clr;
	mp::uint256_t sh_tmp1, sh_tmp2, clr_tmp;

#if(MP_RING_SIZE!=256)
	mp::uint256_t mp_mod = (std::numeric_limits<mp::uint256_t>::max()) >> (256 - MP_RING_SIZE);
#endif

	for(size_t i=0; i<GFP_VECTOR; ++i)
	{
		sh1 = sh2 = clr =0;
		for(size_t j=0; j<GFP_LIMBS; ++j)
		{
			sh_tmp1 = (mp::uint256_t) share[GFP_LIMBS * i + j];
			sh1 += (sh_tmp1 << (64 * j));
			sh_tmp2 = (mp::uint256_t) share[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + j];
			sh2 += (sh_tmp2 << (64 * j));
			clr_tmp = (mp::uint256_t) scalar[GFP_LIMBS * i + j];
			clr += (clr_tmp << (64 * j));
		}
#if(MP_RING_SIZE==256)
		sh1 = sh1 * clr;
		sh2 = sh2 * clr;
#else
		sh1 = (sh1 * clr) & mp_mod;
		sh2 = (sh2 * clr) & mp_mod;
#endif
		// share1 of product
		product[GFP_LIMBS * i + 0] = (uint64_t) (sh1 & 0xffffffffffffffff);
		product[GFP_LIMBS * i + 1] = (uint64_t) ((sh1 >> 64) & 0xffffffffffffffff);
		product[GFP_LIMBS * i + 2] = (uint64_t) ((sh1 >> 128) & 0xffffffffffffffff);
		product[GFP_LIMBS * i + 3] = (uint64_t) ((sh1 >> 192) & 0xffffffffffffffff);
		// share2 of product
		product[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 0] = (uint64_t) (sh2 & 0xffffffffffffffff);
		product[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 1] = (uint64_t) ((sh2 >> 64) & 0xffffffffffffffff);
		product[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 2] = (uint64_t) ((sh2 >> 128) & 0xffffffffffffffff);
		product[GFP_LIMBS * GFP_VECTOR + GFP_LIMBS * i + 3] = (uint64_t) ((sh2 >> 192) & 0xffffffffffffffff);
//		LC(m_logcat + ".acct").debug("%s: sh=%lu; sc=%lu; pd=%lu, %lu;", __FUNCTION__, share[i*2], scalar[i*2], product[i*2], product[i*2+GFP_LIMBS*GFP_VECTOR]);
	}
	return 0;
}

int spdz2_ext_processor_Z2n::mp_mult(const size_t share_count, const uint64_t * xshares, const uint64_t * yshares, uint64_t * products, int verify)
{
	LC(m_logcat).info("%s called for %lu shares.", __FUNCTION__, share_count);
	int result = -1;
	std::vector<uint64_t> x_shares1(GFP_LIMBS*GFP_VECTOR*share_count);
	std::vector<uint64_t> x_shares2(GFP_LIMBS*GFP_VECTOR*share_count);
	std::vector<uint64_t> y_shares1(GFP_LIMBS*GFP_VECTOR*share_count);
	std::vector<uint64_t> y_shares2(GFP_LIMBS*GFP_VECTOR*share_count);
	std::vector<uint64_t> xy_shares1(GFP_LIMBS*GFP_VECTOR*share_count);
	std::vector<uint64_t> xy_shares2(GFP_LIMBS*GFP_VECTOR*share_count);

//	uint64_t x_shares1[GFP_LIMBS*GFP_VECTOR*share_count];
//	uint64_t x_shares2[GFP_LIMBS*GFP_VECTOR*share_count];
//	uint64_t y_shares1[GFP_LIMBS*GFP_VECTOR*share_count];
//	uint64_t y_shares2[GFP_LIMBS*GFP_VECTOR*share_count];
//	uint64_t xy_shares1[GFP_LIMBS*GFP_VECTOR*share_count];
//	uint64_t xy_shares2[GFP_LIMBS*GFP_VECTOR*share_count];

	for(size_t i=0; i<share_count; ++i)
	{
		const uint64_t * xshare = xshares + i*SHR_LIMBS*GFP_VECTOR;
		const uint64_t * yshare = yshares + i*SHR_LIMBS*GFP_VECTOR;
		for(size_t j=0; j<GFP_VECTOR; ++j)
		{
			x_shares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+0] = xshare[GFP_LIMBS*j+0];
			x_shares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+1] = xshare[GFP_LIMBS*j+1];
			x_shares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+2] = xshare[GFP_LIMBS*j+2];
			x_shares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+3] = xshare[GFP_LIMBS*j+3];

			x_shares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+0] = xshare[GFP_LIMBS*GFP_VECTOR+GFP_LIMBS*j+0];
			x_shares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+1] = xshare[GFP_LIMBS*GFP_VECTOR+GFP_LIMBS*j+1];
			x_shares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+2] = xshare[GFP_LIMBS*GFP_VECTOR+GFP_LIMBS*j+2];
			x_shares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+3] = xshare[GFP_LIMBS*GFP_VECTOR+GFP_LIMBS*j+3];

			y_shares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+0] = yshare[GFP_LIMBS*j+0];
			y_shares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+1] = yshare[GFP_LIMBS*j+1];
			y_shares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+2] = yshare[GFP_LIMBS*j+2];
			y_shares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+3] = yshare[GFP_LIMBS*j+3];

			y_shares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+0] = yshare[GFP_LIMBS*GFP_VECTOR+GFP_LIMBS*j+0];
			y_shares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+1] = yshare[GFP_LIMBS*GFP_VECTOR+GFP_LIMBS*j+1];
			y_shares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+2] = yshare[GFP_LIMBS*GFP_VECTOR+GFP_LIMBS*j+2];
			y_shares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+3] = yshare[GFP_LIMBS*GFP_VECTOR+GFP_LIMBS*j+3];
		}
	}

	if(0 == the_party->multMPShares((int)GFP_LIMBS*GFP_VECTOR*share_count, x_shares1, x_shares2, y_shares1, y_shares2, xy_shares1, xy_shares2))
	{
		for(size_t i=0; i<share_count; ++i)
		{
			uint64_t * product = products + i*SHR_LIMBS*GFP_VECTOR;
			for(size_t j=0; j<GFP_VECTOR; ++j)
			{
				product[j*GFP_LIMBS+0] = xy_shares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+0];
				product[j*GFP_LIMBS+1] = xy_shares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+1];
				product[j*GFP_LIMBS+2] = xy_shares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+2];
				product[j*GFP_LIMBS+3] = xy_shares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+3];
				product[GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+0] = xy_shares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+0];
				product[GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+1] = xy_shares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+1];
				product[GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+2] = xy_shares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+2];
				product[GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+3] = xy_shares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+3];
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

int spdz2_ext_processor_Z2n::mp_skew_recomp(const size_t bits_count, const uint64_t * bit_shares, uint64_t * ring_shares)
{
	return 0;
}

int spdz2_ext_processor_Z2n::mp_skew_inject(const uint64_t * bit_shares, uint64_t * ring_shares)
{
	return 0;
}

std::string spdz2_ext_processor_Z2n::get_parties_file()
{
	return "parties_z2n.txt";
}

std::string spdz2_ext_processor_Z2n::get_log_file()
{
	char buffer[128];
	snprintf(buffer, 128, "spdz2_x_z2n_%d_%d.log", m_pid, m_thid);
	return std::string(buffer);
}

std::string spdz2_ext_processor_Z2n::get_log_category()
{
	return "z2n";
}

