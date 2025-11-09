#ifndef BFTVMHORS_FORMAT_H
#define BFTVMHORS_FORMAT_H

#include <bftvmhors/types.h>

/// Concatenate two buffers into one
/// \param output Output buffer
/// \param buffer1 First buffer
/// \param len1 Length of the first buffer
/// \param buffer2 Second buffer
/// \param len2 Length of the second buffer
/// \return Length of the result
u64 concat_buffers(u8* output, u8* buffer1, u32 len1, u8* buffer2, u32 len2);

/// Removes the whitespaces at the left of the input
/// \param input Pointer to the input
/// \return Pointer to the beginning of the new string
u8* str_ltrim(u8* input);

/// Removes the whitespaces at the right of the input
/// \param input Pointer to the input
void str_rtrim(u8* input);

/// Removes the whitespaces at both the right and left of the input
/// \param input Pointer to the input
/// \return Pointer to the beginning of the new string
u8* str_trim(u8* input);

/// Removes the whitespaces at the left of the input
/// \param input Pointer to the input
/// \param char Consider ch along with the whitespaces
/// \return Pointer to the beginning of the new string
u8* str_ltrim_char(u8* input, u8 ch);

/// Removes the whitespaces at the right of the input
/// \param char Consider ch along with the whitespaces
/// \param input Pointer to the input
void str_rtrim_char(u8* input, u8 ch);

/// Removes the whitespaces at both the right and left of the input
/// \param char Consider ch along with the whitespaces
/// \param input Pointer to the input
/// \return Pointer to the beginning of the new string
u8* str_trim_char(u8* input, u8 ch);

#endif