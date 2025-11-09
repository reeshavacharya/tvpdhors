#ifndef BFTVMHORS_FILE_H
#define BFTVMHORS_FILE_H

#include <bftvmhors/types.h>

#define FILE_OP_SUCCESS 0
#define FILE_OPEN_ERROR 1
#define FILE_READ_ERROR 2


/// Reads the file line by line
/// \param line Pointer to the buffer where the line will be stored
/// \param line_size Size of the buffer for storing the line
/// \param file_name Name of the file where we will read line from. (Passing NULL will reset the offset to the beginning)
/// \return 0 if successful, 1 otherwise
u32 read_file_line(u8 * line, u32 line_size, u8 * file_name);


/// Read the content of the file into the buffer and puts the address into the output_buffer
/// \param output_buffer Pointer to the output buffer for writing the file into it
/// \param file_name Pointer to the name of the file
/// \return Number of read bytes
u32 read_file(u8 ** output_buffer, u8 * file_name);

#endif//BFTVMHORS_FILE_H
