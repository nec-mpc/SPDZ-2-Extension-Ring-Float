#pragma once


#define			GFP_VECTOR			1
#define			GFP_LIMBS			4
#define			SHR_LIMBS			GFP_LIMBS*2
#define			GFP_BYTES			GFP_LIMBS*sizeof(uint64_t)
#define			SHR_BYTES			SHR_LIMBS*sizeof(uint64_t)

#define			GF2N_VECTOR		1
#define			GF2N_LIMBS			1
#define			GF2N_SHR_LIMBS	GF2N_LIMBS*2
#define			GF2N_BYTES			GF2N_LIMBS*sizeof(uint64_t)
#define			GF2N_SHR_BYTES	GF2N_SHR_LIMBS*sizeof(uint64_t)

#define			MP_RING_SIZE		256
