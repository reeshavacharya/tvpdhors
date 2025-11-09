#ifndef BFTVMHORS_DEBUG_H
#define BFTVMHORS_DEBUG_H

#include <bftvmhors/types.h>

#define DEBUG_INF 0
#define DEBUG_ERR 1
#define DEBUG_WARNING 2

/// Debug function
/// \param message Message to be printed as the debug
/// \param debug_level Level of the debug
void debug(u8 * message, u32 debug_level);


#endif
