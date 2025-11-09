#ifndef BFTVMHORS_PRNG_H
#define BFTVMHORS_PRNG_H

#include <bftvmhors/types.h>

/// Implements the ChaCha20 Pseudo-random number generator
/// \param random_output Pointer to the variable that holds the pointer to the
/// output \param seed Pointer to the seed \param seed_len Length of the seed
/// \param prn_output_len Length of the prn number
/// \return 0 if successful, 1 otherwise
u64 prng_chacha20(u8** random_output, u8* seed, u64 seed_len,
                  u64 prn_output_len);

#endif
