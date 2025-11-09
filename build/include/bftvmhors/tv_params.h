#ifndef BFTVMHORS_TV_PARAMS_H
#define BFTVMHORS_TV_PARAMS_H


/* Thread capacity denotes the number of keys a thread handles */
#define BFTVMHORS_KEYGEN_THREAD_CAPACITY 16
#define HORS_KEYGEN_THREAD_CAPACITY 64

/* TV selected hash function */
#define TVOPTIMIZED_HORS_HASH_FUNCTION blake2s_128
#define TVOPTIMIZED_BFTVMHORS_HASH_FUNCTION xxhash3_128 // For the underlying BF


/* TV selected HORS parameters */
#define TVOPTIMIZED_T 128
#define TVOPTIMIZED_K 12
#define TVOPTIMIZED_L 64
#define TVOPTIMIZED_LPK 128

#endif