#ifndef NEC_PROTOCOLPARTY_Bool_FOR_3P_H_
#define NEC_PROTOCOLPARTY_Bool_FOR_3P_H_

#include <cstdint>
#include <stdlib.h>
#include <iostream>
#include "MPCParty.hpp"
#include "PRG.hpp"
#include "Z2nIntReplicated.h"
#include "Z2nShareReplicated.h"
#include "../../spdzext_width_defs.h"
#include "../../util.h"

#include <vector>
#include <thread>
#include <iostream>
#include <vector>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/format.hpp>
namespace mp = boost::multiprecision;
//#include <gmp.h>
#include <math.h>

#define MAX_SHARES 10000

#define flag_print false
#define flag_print_timings true

#define N 3

using namespace std;

template <typename T>
class NecProtocolPartyBoolFor3P {
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

  FILE * input_file_bit;

  mp::uint256_t mp_mod;

 public:

  NecProtocolPartyBoolFor3P(int partyID, int numOfOpens);
  ~NecProtocolPartyBoolFor3P();

  void init(); // establish communications

  int input(const int input_of_pid, const size_t num_of_inputs, T * input_value);

  int makeShare(const int pid, vector<T> &z2nvalues, vector<T> &z2nshares1, vector<T> &z2nshares2);

  int openShare(const int share_count, vector<T> &z2nshares1, vector<T> &z2nshares2, vector<T> &z2nopens);

  int verify();

  int multShares(const int share_count, vector<T> &xshares1, vector<T> &xshares2,
		  	  	  	  	  	  	  	  	  	  vector<T> &yshares1, vector<T> &yshares2,
											  vector<T> &xyshares1, vector<T> &xyshares2);


  int skewDecomp(const int bits_count, vector<T> &bshares1, vector<T> &bshares2,
  											vector<T> &b_x0_0, vector<T> &b_x0_1,
											vector<T> &b_x1_0, vector<T> &b_x1_1,
											vector<T> &b_x2_0, vector<T> &b_x2_1);

  int skewInject(vector<T> &bshares1, vector<T> &bshares2,
  					vector<T> &b_x0_0, vector<T> &b_x0_1,
  					vector<T> &b_x1_0, vector<T> &b_x1_1,
					vector<T> &b_x2_0, vector<T> &b_x2_1);

  int skewRecomp(const int bits_count, vector<T> &bshares1, vector<T> &bshares2,
		  	  	  	  	  	  	  	  	  	vector<T> &rshares1, vector<T> &rshares2);

  int MP_skewRecomp(const int bits_count, vector<T> &bshares1, vector<T> &bshares2,
  		  	  	  	  	  	  	  	  	  	vector<T> &rshares1, vector<T> &rshares2);

  int MP_skewInject(vector<T> &bshares1, vector<T> &bshares2,
  						vector<T> &b_x0_0, vector<T> &b_x0_1,
						vector<T> &b_x1_0, vector<T> &b_x1_1,
						vector<T> &b_x2_0, vector<T> &b_x2_1);

};


template <typename T>
NecProtocolPartyBoolFor3P<T>::NecProtocolPartyBoolFor3P(int partyID, int numOfOpens)
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

  input_file_bit = NULL;

  mp_mod = (std::numeric_limits<mp::uint256_t>::max()) >> (256 - MP_RING_SIZE);
}

template <typename T>
NecProtocolPartyBoolFor3P<T>::~NecProtocolPartyBoolFor3P() {
  delete prg_i;
  delete prg_iMinus1;
  delete prg_input;
  delete prg_genshare1;
  delete prg_genshare2;
  delete mpcParty;
}

template <typename T>
void NecProtocolPartyBoolFor3P<T>::init() {
	  mpcParty = new MPCParty(m_partyId, 1, "partiesMPCLocal.conf");
//	  mpcParty = new MPCParty(m_partyId, 1, "partiesMPC.conf");
	  char buffer[256];
	  snprintf(buffer, 256, "bits_input_%d.txt", m_partyId);
	  input_file_bit = fopen(buffer, "r");
	  if (NULL == input_file_bit)
	  {
		  cout << "file "<< buffer << " doesn't exist. "<< endl;
		  abort();
	  }
}

template <typename T>
int NecProtocolPartyBoolFor3P<T>::input(const int input_of_pid, const size_t num_of_inputs, T * input_value)
{
	int sz = num_of_inputs;
	if (m_partyId == input_of_pid)
	{
		std::string str_input;
		T int_input;
		T share0[2*sz], share1[2*sz], share2[2*sz];
		if (0 != read_input_line(input_file_bit, str_input))
		{
			abort();
		}
		int_input = strtol(str_input.c_str(), NULL, 10);

		share0[1] = prg_genshare1->getRandomLong();
		share1[1] = prg_genshare2->getRandomLong();
		share2[1] = int_input ^ share0[1] ^ share1[1];
		share0[0] = share2[1] ^ share0[0];
		share1[0] = share0[1] ^ share1[1];
		share2[0] = share1[1] ^ share2[2];
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
int NecProtocolPartyBoolFor3P<T>::makeShare(const int pid, vector<T> &z2nvalues, vector<T> &z2nshares1, vector<T> &z2nshares2)
{
	size_t sz = z2nvalues.size();

	if (m_partyId == 0) {
		for(size_t i=0; i<sz; ++i) {
			z2nshares1[i] = 0;
			z2nshares2[i] = 0;
		}
	}
	else if (m_partyId == 1) {
		for (size_t i=0; i<sz; ++i) {
			z2nshares1[i] = z2nvalues[i];
			z2nshares2[i] = z2nvalues[i];
		}
	}
	else if (m_partyId == 2) {
		for (size_t i=0; i<sz; ++i) {
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
int NecProtocolPartyBoolFor3P<T>::openShare(const int share_count, vector<T> &z2nshares1, vector<T> &z2nshares2, vector<T> &z2nopens)
{
	size_t sz = share_count;
	uint64_t recBuf[sz];

	mpcParty->Write(&z2nshares1[0], sz, m_nextParty);
	mpcParty->Read(&recBuf[0], sz, m_prevParty);

	for (size_t i=0; i<sz; ++i)
	{
		z2nopens[i] = z2nshares2[i] ^ recBuf[i];
	}

	return 0;
}

template <typename T>
int NecProtocolPartyBoolFor3P<T>::verify()
{
	return 1; // not implemented
}

template <typename T>
int NecProtocolPartyBoolFor3P<T>::multShares(const int share_count,
													vector<T> &xshares1,
													vector<T> &xshares2,
													vector<T> &yshares1,
													vector<T> &yshares2,
													vector<T> &xyshares1,
													vector<T> &xyshares2)
{
	size_t sz = share_count;
	int bufsize = ceil((float)share_count/8);
//	uint8_t x1_packed[MAX_SHARES], x2_packed[MAX_SHARES], y1_packed[MAX_SHARES], y2_packed[MAX_SHARES], xy1_packed[MAX_SHARES], xy2_packed[MAX_SHARES];
	std::vector<uint8_t> x1_packed(bufsize), x2_packed(bufsize), y1_packed(bufsize), y2_packed(bufsize), xy1_packed(bufsize), xy2_packed(bufsize);

	memset(&x1_packed[0], 0, bufsize);
	memset(&x2_packed[0], 0, bufsize);
	memset(&y1_packed[0], 0, bufsize);
	memset(&y2_packed[0], 0, bufsize);

	for(size_t i=0; i<sz; ++i)
	{
		x1_packed[i/8] ^= (xshares1[i] & 0x1) << (i%8);
		x2_packed[i/8] ^= (xshares2[i] & 0x1) << (i%8);
		y1_packed[i/8] ^= (yshares1[i] & 0x1) << (i%8);
		y2_packed[i/8] ^= (yshares2[i] & 0x1) << (i%8);
	}

	uint8_t recBuf[bufsize];

	for (size_t i=0; i<bufsize; ++i)
	{
		xy2_packed[i] = (x1_packed[i] & y1_packed[i]) ^ (x2_packed[i] & y2_packed[i]) ^ (prg_i->getRandomByte() ^ prg_iMinus1->getRandomByte());
	}
	mpcParty->Write(&xy2_packed[0], bufsize, m_nextParty);
	mpcParty->Read(&recBuf[0], bufsize, m_prevParty);

	for(size_t i=0; i<bufsize; ++i)
	{
		xy1_packed[i] = xy2_packed[i] ^ recBuf[i];
	}

	for(size_t i=0; i<sz; ++i)
	{
		xyshares1[i] = (uint64_t)((xy1_packed[i/8] >> (i%8)) & 0x1);
		xyshares2[i] = (uint64_t)((xy2_packed[i/8] >> (i%8)) & 0x1);
	}

//
//	// without packing
//	size_t sz = share_count;
//
//	uint64_t recBuf[sz];
//
//	for (size_t i=0; i<sz; ++i)
//	{
//		xyshares2[i] = (xshares1[i] & yshares1[i]) ^ (xshares2[i] & yshares2[i]) ^ ((prg_i->getRandomLong() ^ prg_iMinus1->getRandomLong()) & 0x1);
//	}
//	mpcParty->Write(&xyshares2[0], sz, m_nextParty);
//	mpcParty->Read(&recBuf[0], sz, m_prevParty);
//
//	for(size_t i=0; i<sz; ++i)
//	{
//		xyshares1[i] = xyshares2[i] ^ recBuf[i];
//	}

	return 0;
}

template <typename T>
int NecProtocolPartyBoolFor3P<T>::skewDecomp(const int bits_count, vector<T> &rshares1, vector<T> &rshares2,
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
				b_x0_0[i*GF2N_VECTOR+j] = 0;
				b_x0_1[i*GF2N_VECTOR+j] = 0;
				// [x_1,i]^B
				b_x1_0[i*GF2N_VECTOR+j] = ((rshares1[j] ^ rshares2[j]) >> i) & 1;
				b_x1_1[i*GF2N_VECTOR+j] = 0;
				// [x_2,i]^B
				b_x2_0[i*GF2N_VECTOR+j] = 0;
				b_x2_1[i*GF2N_VECTOR+j] = (rshares2[j] >> i) & 1;
			}
			else if (m_partyId == 1)
			{
				// [x_0,i]^B
				b_x0_0[i*GF2N_VECTOR+j] = 0;
				b_x0_1[i*GF2N_VECTOR+j] = (rshares2[j] >> i) & 1;
				// [x_1,i]^B
				b_x1_0[i*GF2N_VECTOR+j] = 0;
				b_x1_1[i*GF2N_VECTOR+j] = 0;
				// [x_2,i]^B
				b_x2_0[i*GF2N_VECTOR+j] = ((rshares1[j] ^ rshares2[j]) >> i) & 1;
				b_x2_1[i*GF2N_VECTOR+j] = 0;
			}
			else if (m_partyId == 2)
			{
				// [x_0,i]^B
				b_x0_0[i*GF2N_VECTOR+j] = ((rshares1[j] ^ rshares2[j]) >> i) & 1;
				b_x0_1[i*GF2N_VECTOR+j] = 0;
				// [x_1,i]^B
				b_x1_0[i*GF2N_VECTOR+j] = 0;
				b_x1_1[i*GF2N_VECTOR+j] = (rshares2[j] >> i) & 1;
				// [x_2,i]^B
				b_x2_0[i*GF2N_VECTOR+j] = 0;
				b_x2_1[i*GF2N_VECTOR+j] = 0;
			}
			b_x0_0[i*GF2N_VECTOR+j] ^= b_x0_1[i*GF2N_VECTOR+j];
			b_x1_0[i*GF2N_VECTOR+j] ^= b_x1_1[i*GF2N_VECTOR+j];
			b_x2_0[i*GF2N_VECTOR+j] ^= b_x2_1[i*GF2N_VECTOR+j];
		}
	}

	return 0;
}

template <typename T>
int NecProtocolPartyBoolFor3P<T>::skewInject(vector<T> &bshares1, vector<T> &bshares2,
											vector<T> &r_x0_0, vector<T> &r_x0_1,
											vector<T> &r_x1_0, vector<T> &r_x1_1,
											vector<T> &r_x2_0, vector<T> &r_x2_1)
{
	for (size_t j=0; j<GF2N_VECTOR; ++j)
	{
		if (m_partyId == 0)
		{
			// [x_0,i]^B
			r_x0_0[j] = 0;
			r_x0_1[j] = 0;
			// [x_1,i]^B
			r_x1_0[j] = ((bshares1[j] ^ bshares2[j])) & 1;
			r_x1_1[j] = 0;
			// [x_2,i]^B
			r_x2_0[j] = 0;
			r_x2_1[j] = (bshares2[j]) & 1;
		}
		else if (m_partyId == 1)
		{
			// [x_0,i]^B
			r_x0_0[j] = 0;
			r_x0_1[j] = (bshares2[j]);
			// [x_1,i]^B
			r_x1_0[j] = 0;
			r_x1_1[j] = 0;
			// [x_2,i]^B
			r_x2_0[j] = ((bshares1[j] ^ bshares2[j])) & 1;
			r_x2_1[j] = 0;
		}
		else if (m_partyId == 2)
		{
			// [x_0,i]^B
			r_x0_0[j] = ((bshares1[j] ^ bshares2[j])) & 1;
			r_x0_1[j] = 0;
			// [x_1,i]^B
			r_x1_0[j] = 0;
			r_x1_1[j] = (bshares2[j]) & 1;
			// [x_2,i]^B
			r_x2_0[j] = 0;
			r_x2_1[j] = 0;
		}
		r_x0_0[j] += r_x0_1[j];
		r_x1_0[j] += r_x1_1[j];
		r_x2_0[j] += r_x2_1[j];
	}

	return 0;
}

template <typename T>
int NecProtocolPartyBoolFor3P<T>::skewRecomp(const int bits_count, vector<T> &bshares1, vector<T> &bshares2, vector<T> &rshares1, vector<T> &rshares2)
{
	size_t sz = bits_count;

	for(size_t i=0; i<sz; ++i)
	{
		for(int j=0; j<GF2N_VECTOR; ++j)
		{
			rshares1[j] += ((bshares1[i*GF2N_VECTOR+j] ^ bshares2[i*GF2N_VECTOR+j]) << i);
			rshares2[j] += (bshares2[i*GF2N_VECTOR+j] << i);
		}
	}

	for (int j=0; j<GF2N_VECTOR; ++j) {
		rshares1[j] += rshares2[j];
	}

	return 0;
}

template <typename T>
int NecProtocolPartyBoolFor3P<T>::MP_skewRecomp(const int bits_count, vector<T> &bshares1, vector<T> &bshares2, vector<T> &rshares1, vector<T> &rshares2)
{
	size_t sz = bits_count;

	// (ideal) GF2N_VECTOR = GFP_VECTOR / 64
	// (now)   GF2N_VECTOR = GFP_VECTOR = 1

	mp::uint256_t share1[GFP_VECTOR], share2[GFP_VECTOR];
	mp::uint256_t tmp_for_shift=0;
	for(size_t i=0; i<sz; ++i)
	{
		for(int j=0; j<GF2N_VECTOR; ++j)
		{
			tmp_for_shift = (mp::uint256_t) (bshares1[i*GF2N_VECTOR+j] ^ bshares2[i*GF2N_VECTOR+j]);
			share1[0] += (tmp_for_shift << i);
			tmp_for_shift = (mp::uint256_t) (bshares2[i*GF2N_VECTOR+j]);
			share2[0] += (tmp_for_shift << i);
		}
	}

	for (int j=0; j<GFP_VECTOR; ++j) {
#if(MP_RING_SIZE==256)
		share1[j] += share2[j];
#else
		share1[j] = (share1[j] + share2[j]) & mp_mod;
#endif
		uint64_t bit_mask = 0xffffffffffffffff;
		rshares1[j*GFP_LIMBS+0] = (uint64_t) (share1[j] & bit_mask);
		rshares1[j*GFP_LIMBS+1] = (uint64_t) ((share1[j] >> 64) & bit_mask);
		rshares1[j*GFP_LIMBS+2] = (uint64_t) ((share1[j] >> 128) & bit_mask);
		rshares1[j*GFP_LIMBS+3] = (uint64_t) ((share1[j] >> 192) & bit_mask);
		rshares2[j*GFP_LIMBS+0] = (uint64_t) (share2[j] & bit_mask);
		rshares2[j*GFP_LIMBS+1] = (uint64_t) ((share2[j] >> 64) & bit_mask);
		rshares2[j*GFP_LIMBS+2] = (uint64_t) ((share2[j] >> 128) & bit_mask);
		rshares2[j*GFP_LIMBS+3] = (uint64_t) ((share2[j] >> 192) & bit_mask);
	}

	return 0;
}

template <typename T>
int NecProtocolPartyBoolFor3P<T>::MP_skewInject(vector<T> &bshares1, vector<T> &bshares2,
											vector<T> &r_x0_0, vector<T> &r_x0_1,
											vector<T> &r_x1_0, vector<T> &r_x1_1,
											vector<T> &r_x2_0, vector<T> &r_x2_1)
{
	for (size_t j=0; j<GF2N_VECTOR; ++j)
	{
		if (m_partyId == 0)
		{
			// [x_0,i]^B
			r_x0_0[j] = 0;
			r_x0_1[j] = 0;
			// [x_1,i]^B
			r_x1_0[j] = ((bshares1[j] ^ bshares2[j])) & 1;
			r_x1_1[j] = 0;
			// [x_2,i]^B
			r_x2_0[j] = 0;
			r_x2_1[j] = (bshares2[j]) & 1;
		}
		else if (m_partyId == 1)
		{
			// [x_0,i]^B
			r_x0_0[j] = 0;
			r_x0_1[j] = (bshares2[j]);
			// [x_1,i]^B
			r_x1_0[j] = 0;
			r_x1_1[j] = 0;
			// [x_2,i]^B
			r_x2_0[j] = ((bshares1[j] ^ bshares2[j])) & 1;
			r_x2_1[j] = 0;
		}
		else if (m_partyId == 2)
		{
			// [x_0,i]^B
			r_x0_0[j] = ((bshares1[j] ^ bshares2[j])) & 1;
			r_x0_1[j] = 0;
			// [x_1,i]^B
			r_x1_0[j] = 0;
			r_x1_1[j] = (bshares2[j]) & 1;
			// [x_2,i]^B
			r_x2_0[j] = 0;
			r_x2_1[j] = 0;
		}
		r_x0_0[j] += r_x0_1[j];
		r_x1_0[j] += r_x1_1[j];
		r_x2_0[j] += r_x2_1[j];
	}


	return 0;
}
#endif // NEC_PROTOCOLPARTY_H_
