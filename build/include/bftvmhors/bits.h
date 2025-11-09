#ifndef BFTVMHORS_BITS_H
#define BFTVMHORS_BITS_H

#include <bftvmhors/types.h>

#define BITS_2_BYTES(bits) (bits / 8)
#define BITS_MOD_BYTES(bits) (bits % 8)


/// Read slice of bits as a 4-byte unsigned integer
/// \param input Pointer to the byte array
/// \param nth N'th slice of bits
/// \param bit_slice_len Size of the bit slice
/// \return 4-byte unsigned integer
u32 read_bits_as_4bytes(const u8* input, u32 nth, u32 bit_slice_len);

#endif
