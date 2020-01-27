#ifndef NEC_PROTOCOLPARTY_RING_FOR_3P_H_
#define NEC_PROTOCOLPARTY_RING_FOR_3P_H_

#include <cstdint>
#include <stdlib.h>
#include "MPCParty.hpp"
#include "PRG.hpp"
#include "Z2nIntReplicated.h"
#include "Z2nShareReplicated.h"
#include "../../spdzext_width_defs.h"
#include "../../util.h"

#include <thread>
#include <iostream>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/format.hpp>
namespace mp = boost::multiprecision;
//#include <gmp.h>

#define flag_print false
#define flag_print_timings true

#define N 3

using namespace std;

template <typename T>
class NecProtocolPartyRingFor3P {
 private:
  /*
   * N - number of parties
   * T - number of malicious
   * M - number of gates
   */

  byte key1_prg [16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
			0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
  byte key2_prg [16] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
			0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};
  
  byte key1_cr [16] = {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
		       0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf};
  byte key2_cr [16] = {0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
		       0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf};
  byte key3_cr [16] = {0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
		       0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef};
  byte *keys [3] = {key1_cr, key2_cr, key3_cr};

  byte key_input [16] = {0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
			 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xff};
  
  int m_partyId;
  MPCParty *mpcParty;
  int numOfMults = 1000; // should be given from spdz
  int m_nextParty, m_prevParty;

  PRG *prg_input;

  PRG *prg_i;
  PRG *prg_iMinus1;

  PRG *prg_genshare1;
  PRG *prg_genshare2;

  FILE * input_file_int;

  mp::uint256_t mp_mod;

 public:
  
  NecProtocolPartyRingFor3P(int partyID, int numOfOpens);
  ~NecProtocolPartyRingFor3P();

  void init(); // establish communications
  
  int input(const int input_of_pid, const size_t num_of_inputs, T * input_value);

  int makeShare(const int pid, vector<T> &z2nvalues, vector<T> &z2nshares1, vector<T> &z2nshares2);

  int openShare(const int share_count, vector<T> &z2nshares1, vector<T> &z2nshares2, vector<T> &z2nopens);

  int verify();

  int multShares(const int share_count, vector<T> &xshares1, vector<T> &xshares2,
		  	  	  	  	  	  	  	  	  	  vector<T> &yshares1, vector<T> &yshares2,
											  vector<T> &xyshares1, vector<T> &xyshares2);

  int skewDecomp(const int bits_count, vector<T> &rshares1, vector<T> &rshares2,
  											vector<T> &b_x0_0, vector<T> &b_x0_1,
  											vector<T> &b_x1_0, vector<T> &b_x1_1,
											vector<T> &b_x2_0, vector<T> &b_x2_1);

  int openMPShare(const int size, vector<T> &z2nshares1, vector<T> &z2nshares2, vector<T> &z2nopens);

  int multMPShares(const int share_count, vector<T> &xshares1, vector<T> &xshares2,
  		  	  	  	  	  	  	  	  	  	  vector<T> &yshares1, vector<T> &yshares2,
  											  vector<T> &xyshares1, vector<T> &xyshares2);

  int MP_skewDecomp(const int bits_count, vector<T> &rshares1, vector<T> &rshares2,
    											vector<T> &b_x0_0, vector<T> &b_x0_1,
    											vector<T> &b_x1_0, vector<T> &b_x1_1,
  											    vector<T> &b_x2_0, vector<T> &b_x2_1);
};
//
//

template <typename T>
NecProtocolPartyRingFor3P<T>::NecProtocolPartyRingFor3P(int partyID, int numOfOpens)
{
  numOfMults = numOfOpens;
  m_partyId = partyID;

  byte *key_i = keys[(partyID+1) % 3];
  byte *key_iMinus1 = keys[partyID % 3];

  prg_i = new PRG(key_i);
  prg_iMinus1 = new PRG(key_iMinus1);

  prg_input = new PRG(key_input);

  prg_genshare1 = new PRG(key1_prg);
  prg_genshare2 = new PRG(key2_prg);

  m_nextParty = (m_partyId +1) % 3;
  m_prevParty = (m_nextParty + 1) % 3;
  mpcParty = NULL;

  input_file_int = NULL;

  mp_mod = (std::numeric_limits<mp::uint256_t>::max()) >> (256 - MP_RING_SIZE);
}

template <typename T>
NecProtocolPartyRingFor3P<T>::~NecProtocolPartyRingFor3P() {
  delete prg_i;
  delete prg_iMinus1;
  delete prg_input;
  delete prg_genshare1;
  delete prg_genshare2;
  delete mpcParty;
  fclose(input_file_int);
  input_file_int = NULL;
}

template <typename T>
void NecProtocolPartyRingFor3P<T>::init() {
	  mpcParty = new MPCParty(m_partyId, 0, "partiesMPCLocal.conf");
//	  mpcParty = new MPCParty(m_partyId, 0, "partiesMPC.conf");
	  char buffer[256];//static int read_input_line(FILE * input_file, std::string & line)
	  //{
	  //	char buffer[256];
	  //	if(NULL != fgets(buffer, 256, input_file))
	  //	{
	  //		line = buffer;
	  //		return 0;
	  //	}
	  //	else
	  //		return -1;
	  //}

	  snprintf(buffer, 256, "integers_input_%d.txt", m_partyId);
	  input_file_int = fopen(buffer, "r");
	  if (NULL == input_file_int)
	  {
		  cout << "file "<< buffer << " doesn't exist. "<< endl;
		  abort();
	  }
}

template <typename T>
int NecProtocolPartyRingFor3P<T>::input(const int input_of_pid, const size_t num_of_inputs, T * input_value)
{
	int sz = num_of_inputs;

	if (m_partyId == input_of_pid)
	{
		std::string str_input;
		T int_input;
		T share0[2*sz], share1[2*sz], share2[2*sz];
		if (0 != read_input_line(input_file_int, str_input))
		{
			abort();
		}
		int_input = strtol(str_input.c_str(), NULL, 10);

		share0[1] = prg_genshare1->getRandomLong();
		share1[1] = prg_genshare2->getRandomLong();
		share2[1] = int_input - share0[1] - share1[1];
		share0[0] = share2[1] + share0[0];
		share1[0] = share0[1] + share1[1];
		share2[0] = share1[1] + share2[2];
		mpcParty->Write(&share1[0], 2, m_nextParty);
		mpcParty->Write(&share2[0], 2, m_prevParty);
		input_value[0] = share0[0];
		input_value[1] = 0;
		input_value[2] = share0[1];
		input_value[3] = 0;
	}
	else
	{
		T shares[2];
		mpcParty->Read(&shares[0], 2, input_of_pid);
		input_value[0] = shares[0];
		input_value[1] = 0;
		input_value[2] = shares[1];
		input_value[3] = 0;
	}
}

template <typename T>
int NecProtocolPartyRingFor3P<T>::makeShare(const int pid, vector<T> &z2nvalues, vector<T> &z2nshares1, vector<T> &z2nshares2)
{
	size_t sz = z2nvalues.size();

	if (m_partyId == 0)
	{
		for(size_t i=0; i<sz; ++i)
		{
			z2nshares1[i] = 0;
			z2nshares2[i] = 0;
		}
	}
	else if (m_partyId == 1)
	{
		for (size_t i=0; i<sz; ++i)
		{
			z2nshares1[i] = z2nvalues[i];
			z2nshares2[i] = z2nvalues[i];

		}
	}
	else if (m_partyId == 2)
	{
		for (size_t i=0; i<sz; ++i)
		{
			z2nshares1[i] = z2nvalues[i];
			z2nshares2[i] = 0;
		}
	}
	else {
		cout << "ProtocolPartyRing - makeShare failed: the party_id = " << m_partyId << "doesn't exists" << endl;
		return -1;
	}


	return 0;
}

template <typename T>
int NecProtocolPartyRingFor3P<T>::openShare(const int share_count, vector<T> &z2nshares1, vector<T> &z2nshares2, vector<T> &z2nopens)
{
	size_t sz = share_count;

	uint64_t recBuf[sz];

	mpcParty->Write(&z2nshares1[0], sz, m_nextParty);
	mpcParty->Read(&recBuf[0], sz, m_prevParty);

	for (size_t i=0; i<sz; ++i)
	{
		z2nopens[i] = z2nshares2[i] + recBuf[i];
	}

	return 0;
}

template <typename T>
int NecProtocolPartyRingFor3P<T>::verify()
{
	return 1; // not implemented
}

template <typename T>
int NecProtocolPartyRingFor3P<T>::multShares(const int share_count,
													vector<T> &xshares1,
													vector<T> &xshares2,
													vector<T> &yshares1,
													vector<T> &yshares2,
													vector<T> &xyshares1,
													vector<T> &xyshares2)
{
	size_t sz = share_count;

	uint64_t recBuf[sz];

	for (size_t i=0; i<sz; ++i)
	{
		xyshares2[i] = (xshares1[i] * yshares1[i]) - (xshares2[i] * yshares2[i]) + (prg_i->getRandomLong() - prg_iMinus1->getRandomLong());
	}
	mpcParty->Write(&xyshares2[0], sz, m_nextParty);
	mpcParty->Read(&recBuf[0], sz, m_prevParty);

	for(size_t i=0; i<sz; ++i)
	{
		xyshares1[i] = xyshares2[i] + recBuf[i];
	}

	return 0;
}

template <typename T>
int NecProtocolPartyRingFor3P<T>::skewDecomp(const int bits_count, vector<T> &rshares1, vector<T> &rshares2,
													vector<T> &b_x0_0, vector<T> &b_x0_1,
													vector<T> &b_x1_0, vector<T> &b_x1_1,
													vector<T> &b_x2_0, vector<T> &b_x2_1)
{
	size_t sz = bits_count;

	for (size_t i=0; i<sz; ++i) {

		for (size_t j=0; j<GFP_VECTOR; ++j)
		{
			if (m_partyId == 0)
			{
				// [x_0,i]^B
				b_x0_0[i*GFP_VECTOR+j] = 0;
				b_x0_1[i*GFP_VECTOR+j] = 0;
				// [x_1,i]^B
				b_x1_0[i*GFP_VECTOR+j] = ((rshares1[j] - rshares2[j]) >> i) & 1;
				b_x1_1[i*GFP_VECTOR+j] = 0;
				// [x_2,i]^B
				b_x2_0[i*GFP_VECTOR+j] = 0;
				b_x2_1[i*GFP_VECTOR+j] = (rshares2[j] >> i) & 1;
			}
			else if (m_partyId == 1)
			{
				// [x_0,i]^B
				b_x0_0[i*GFP_VECTOR+j] = 0;
				b_x0_1[i*GFP_VECTOR+j] = (rshares2[j] >> i) & 1;
				// [x_1,i]^B
				b_x1_0[i*GFP_VECTOR+j] = 0;
				b_x1_1[i*GFP_VECTOR+j] = 0;
				// [x_2,i]^B
				b_x2_0[i*GFP_VECTOR+j] = ((rshares1[j] - rshares2[j]) >> i) & 1;
				b_x2_1[i*GFP_VECTOR+j] = 0;
			}
			else if (m_partyId == 2)
			{
				// [x_0,i]^B
				b_x0_0[i*GFP_VECTOR+j] = ((rshares1[j] - rshares2[j]) >> i) & 1;
				b_x0_1[i*GFP_VECTOR+j] = 0;
				// [x_1,i]^B
				b_x1_0[i*GFP_VECTOR+j] = 0;
				b_x1_1[i*GFP_VECTOR+j] = (rshares2[j] >> i) & 1;
				// [x_2,i]^B
				b_x2_0[i*GFP_VECTOR+j] = 0;
				b_x2_1[i*GFP_VECTOR+j] = 0;
			}
			b_x0_0[i] ^= b_x0_1[i];
			b_x1_0[i] ^= b_x1_1[i];
			b_x2_0[i] ^= b_x2_1[i];
		}
	}

	return 0;
}

template <typename T>
int NecProtocolPartyRingFor3P<T>::openMPShare(const int size, vector<T> &z2nshares1, vector<T> &z2nshares2, vector<T> &z2nopens)
{
	size_t sz = size;
	uint64_t recBuf[sz];

	uint32_t size_comp = size;
	uint32_t clr_reg_count;
	clr_reg_count = size_comp / (GFP_LIMBS * GFP_VECTOR);

	mpcParty->Write(&z2nshares1[0], sz, m_nextParty);
	mpcParty->Read(&recBuf[0], sz, m_prevParty);

	mp::uint256_t share_1, share_2, tmp, clr_val;
	for(size_t i=0; i<clr_reg_count; ++i)
	{
		for(size_t j=0; j<GFP_VECTOR; ++j)
		{
			share_1=share_2=tmp=clr_val=0;
			share_1  = (mp::uint256_t) recBuf[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+0];
			tmp      = (mp::uint256_t) recBuf[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+1];
			share_1 += (tmp << 64);
			tmp      = (mp::uint256_t) recBuf[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+2];
			share_1 += (tmp << 128);
			tmp      = (mp::uint256_t) recBuf[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+3];
			share_1 += (tmp << 192);

			share_2  = (mp::uint256_t) z2nshares2[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+0];
			tmp      = (mp::uint256_t) z2nshares2[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+1];
			share_2 += (tmp << 64);
			tmp      = (mp::uint256_t) z2nshares2[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+2];
			share_2 += (tmp << 128);
			tmp      = (mp::uint256_t) z2nshares2[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+3];
			share_2 += (tmp << 192);

#if(MP_RING_SIZE==256)
			clr_val = share_2 + share_1;
#else
			clr_val = (share_2 + share_1) & mp_mod;
#endif
			z2nopens[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+0] = (uint64_t) (clr_val & 0xffffffffffffffff); // extract 64bits from LSB
			z2nopens[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+1] = (uint64_t) ((clr_val >> 64) & 0xffffffffffffffff);
			z2nopens[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+2] = (uint64_t) ((clr_val >> 128) & 0xffffffffffffffff);
			z2nopens[GFP_LIMBS*GFP_VECTOR*i+GFP_LIMBS*j+3] = (uint64_t) ((clr_val >> 192) & 0xffffffffffffffff);
		}
	}

	return 0;
}

template <typename T>
int NecProtocolPartyRingFor3P<T>::multMPShares(const int share_count,
													vector<T> &xshares1,
													vector<T> &xshares2,
													vector<T> &yshares1,
													vector<T> &yshares2,
													vector<T> &xyshares1,
													vector<T> &xyshares2)
{
	size_t sz = share_count;
	uint64_t recBuf[sz];

	uint32_t size_comp = share_count;
	uint32_t sh_reg_count;
	sh_reg_count = size_comp/(GFP_LIMBS*GFP_VECTOR);

	mp::uint256_t x1_tmp, y1_tmp, xy1_tmp, x2_tmp, y2_tmp, xy2_tmp, prg_i_tmp, prg_i_minus1_tmp, tmp_for_shift, res1_tmp, res2_tmp;

	for (size_t i=0; i<sh_reg_count; ++i)
	{
		for(size_t j=0; j<GFP_VECTOR; ++j)
		{
			x1_tmp = y1_tmp = xy1_tmp = x2_tmp = y2_tmp = xy2_tmp = prg_i_tmp = prg_i_minus1_tmp = tmp_for_shift = res1_tmp = res2_tmp = 0;
			for(size_t k=0; k<GFP_LIMBS; ++k)
			{
				tmp_for_shift = (mp::uint256_t) xshares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+k];
				x1_tmp += (tmp_for_shift << (64 * k));
				tmp_for_shift = (mp::uint256_t) yshares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+k];
				y1_tmp += (tmp_for_shift << (64 * k));
				tmp_for_shift = (mp::uint256_t) xshares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+k];
				x2_tmp += (tmp_for_shift << (64 * k));
				tmp_for_shift = (mp::uint256_t) yshares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+k];
				y2_tmp += (tmp_for_shift << (64 * k));
				tmp_for_shift = (mp::uint256_t) prg_i->getRandomLong();
				prg_i_tmp += (tmp_for_shift << (64 * k));
				tmp_for_shift = (mp::uint256_t) prg_iMinus1->getRandomLong();
				prg_i_minus1_tmp += (tmp_for_shift << (64 * k));
			}
#if(MP_RING_SIZE==256)
			xy1_tmp = x1_tmp * y1_tmp;
			xy2_tmp = x2_tmp * y2_tmp;
			res2_tmp = xy1_tmp - xy2_tmp + (prg_i_tmp - prg_i_minus1_tmp);
			for(size_t k=0; k<GFP_LIMBS; ++k)
			{
				xyshares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+k] = (uint64_t) ((res2_tmp >> (64 * k)) & 0xffffffffffffffff);
			}
#else
			xy1_tmp = x1_tmp * y1_tmp;
			xy2_tmp = x2_tmp * y2_tmp;
			res2_tmp = (xy1_tmp - xy2_tmp + (prg_i_tmp - prg_i_minus1_tmp)) & mp_mod;
			for(size_t k=0; k<GFP_LIMBS; ++k)
			{
				xyshares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+k] = (uint64_t) ((res2_tmp >> (64 * k)) & 0xffffffffffffffff);
			}
#endif
		}
	}
	mpcParty->Write(&xyshares2[0], sz, m_nextParty);
	mpcParty->Read(&recBuf[0], sz, m_prevParty);

	for (size_t i=0; i<sh_reg_count; ++i)
	{
		for(size_t j=0; j<GFP_VECTOR; ++j)
		{
			tmp_for_shift = res1_tmp = res2_tmp = 0;
			for(size_t k=0; k<GFP_LIMBS; ++k)
			{
				tmp_for_shift = (mp::uint256_t) xyshares2[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+k];
				res2_tmp += (tmp_for_shift << (64 * k));
				tmp_for_shift = (mp::uint256_t) recBuf[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+k];
				res1_tmp += (tmp_for_shift << (64 * k));
			}
#if(MP_RING_SIZE==256)
			res1_tmp += res2_tmp;
#else
			res1_tmp = (res1_tmp + res2_tmp) & mp_mod;
#endif
			for(size_t k=0; k<GFP_LIMBS; ++k)
			{
				xyshares1[i*GFP_LIMBS*GFP_VECTOR+j*GFP_LIMBS+k] = (uint64_t) ((res1_tmp >> (64 * k)) & 0xffffffffffffffff);
			}
		}
	}
	return 0;
}

template <typename T>
int NecProtocolPartyRingFor3P<T>::MP_skewDecomp(const int bits_count, vector<T> &rshares1, vector<T> &rshares2,
													vector<T> &b_x0_0, vector<T> &b_x0_1,
													vector<T> &b_x1_0, vector<T> &b_x1_1,
													vector<T> &b_x2_0, vector<T> &b_x2_1)
{
	size_t sz = bits_count;

	mp::uint256_t diff[GFP_VECTOR], share2[GFP_VECTOR];
	for(size_t i=0; i<GFP_VECTOR; ++i) {
		mp::uint256_t val1,tmp;
		val1=tmp=0;
		val1 = (mp::uint256_t) rshares1[i*GFP_LIMBS+0];
		tmp = (mp::uint256_t) rshares1[i*GFP_LIMBS+1];
		val1 += (tmp << 64);
		tmp = (mp::uint256_t) rshares1[i*GFP_LIMBS+2];
		val1 += (tmp << 128);
		tmp = (mp::uint256_t) rshares1[i*GFP_LIMBS+3];
		val1 += (tmp << 192);
		share2[i] = (mp::uint256_t) rshares2[i*GFP_LIMBS+0];
		tmp = (mp::uint256_t) rshares2[i*GFP_LIMBS+1];
		share2[i] += (tmp << 64);
		tmp = (mp::uint256_t) rshares2[i*GFP_LIMBS+2];
		share2[i] += (tmp << 128);
		tmp = (mp::uint256_t) rshares2[i*GFP_LIMBS+3];
		share2[i] += (tmp << 192);

#if(MP_RING_SIZE==256)
		diff[i] = val1 - share2[i];
#else
		diff[i] = (val1 - share2[i]) & mp_mod;
#endif
	}

	for (size_t i=0; i<sz; ++i) {

		for (size_t j=0; j<GFP_VECTOR; ++j)
		{
			if (m_partyId == 0)
			{
				// [x_0,i]^B
				b_x0_0[i*GFP_VECTOR+j] = 0;
				b_x0_1[i*GFP_VECTOR+j] = 0;
				// [x_1,i]^B
				b_x1_0[i*GFP_VECTOR+j] = (uint64_t) ((diff[j] >> i) & 1);
				b_x1_1[i*GFP_VECTOR+j] = 0;
				// [x_2,i]^B
				b_x2_0[i*GFP_VECTOR+j] = 0;
				b_x2_1[i*GFP_VECTOR+j] = (uint64_t) ((share2[j]>> i) & 1);
			}
			else if (m_partyId == 1)
			{
				// [x_0,i]^B
				b_x0_0[i*GFP_VECTOR+j] = 0;
				b_x0_1[i*GFP_VECTOR+j] = (uint64_t) ((share2[j]>> i) & 1);
				// [x_1,i]^B
				b_x1_0[i*GFP_VECTOR+j] = 0;
				b_x1_1[i*GFP_VECTOR+j] = 0;
				// [x_2,i]^B
				b_x2_0[i*GFP_VECTOR+j] = (uint64_t) ((diff[j] >> i) & 1);
				b_x2_1[i*GFP_VECTOR+j] = 0;
			}
			else if (m_partyId == 2)
			{
				// [x_0,i]^B
				b_x0_0[i*GFP_VECTOR+j] = (uint64_t) ((diff[j] >> i) & 1);
				b_x0_1[i*GFP_VECTOR+j] = 0;
				// [x_1,i]^B
				b_x1_0[i*GFP_VECTOR+j] = 0;
				b_x1_1[i*GFP_VECTOR+j] = (uint64_t) ((share2[j]>> i) & 1);
				// [x_2,i]^B
				b_x2_0[i*GFP_VECTOR+j] = 0;
				b_x2_1[i*GFP_VECTOR+j] = 0;
			}
			b_x0_0[i] ^= b_x0_1[i];
			b_x1_0[i] ^= b_x1_1[i];
			b_x2_0[i] ^= b_x2_1[i];

		}
	}

	return 0;
}

#endif // NEC_PROTOCOLPARTY_H_
