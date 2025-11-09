#include <bftvmhors/bf.h>
#include <bftvmhors/bits.h>
#include <bftvmhors/format.h>
#include <bftvmhors/hash.h>
#include <bftvmhors/tv_params.h>
#include <openssl/bn.h>
#include <stdlib.h>
#include <string.h>

sbf_hp_t sbf_new_hp(u32 size, u32 num_hash_functions, const u8 *hash_family) {
  sbf_hp_t sbf_hp;
  sbf_hp.size = size;
  sbf_hp.num_hash_functions = num_hash_functions;
  sbf_hp.hash_family = hash_family;
  return sbf_hp;
}

u32 sbf_create(sbf_t *sbf, const sbf_hp_t *sbf_hp) {
  sbf->size = sbf_hp->size;
  sbf->num_hash_functions = sbf_hp->num_hash_functions;
  sbf->bv = malloc(sbf->size / 8);

  /* Zero out the bit vector */
  for (u32 i = 0; i < sbf->size / 8; i++) sbf->bv[i] = 0;

  sbf->hash_functions = malloc(sizeof(u32(*)(u8 *, const u8 *, u64)) * sbf->size);

  u32 (*selected_hash_function)(u8 *, const u8 *, u64);

  if (strcmp(sbf_hp->hash_family, "ltc_sha256") == 0)
    selected_hash_function = ltc_hash_sha2_256;
  else if (strcmp(sbf_hp->hash_family, "openssl_sha256") == 0)
    selected_hash_function = openssl_hash_sha2_256;
  else if (strcmp(sbf_hp->hash_family, "openssl_md5") == 0)
    selected_hash_function = openssl_hash_md5;
  else if (strcmp(sbf_hp->hash_family, "openssl_sha1") == 0)
    selected_hash_function = openssl_hash_sha1;
  else if (strcmp(sbf_hp->hash_family, "jenkins_oaat") == 0)
    selected_hash_function = jenkins_oaat;
  else if (strcmp(sbf_hp->hash_family, "fnv64_0") == 0)
    selected_hash_function = fnv64_0;
  else if (strcmp(sbf_hp->hash_family, "fnv64_1") == 0)
    selected_hash_function = fnv64_1;
  else if (strcmp(sbf_hp->hash_family, "fnv64_1a") == 0)
    selected_hash_function = fnv64_1a;
  else if (strcmp(sbf_hp->hash_family, "jp_aumasson_siphash") == 0)
    selected_hash_function = jp_aumasson_siphash;
  else if (strcmp(sbf_hp->hash_family, "blake2b_256") == 0)
    selected_hash_function = blake2b_256;
  else if (strcmp(sbf_hp->hash_family, "blake2b_384") == 0)
    selected_hash_function = blake2b_384;
  else if (strcmp(sbf_hp->hash_family, "blake2b_512") == 0)
    selected_hash_function = blake2b_512;
  else if (strcmp(sbf_hp->hash_family, "blake2s_128") == 0)
    selected_hash_function = blake2s_128;
  else if (strcmp(sbf_hp->hash_family, "blake2s_160") == 0)
    selected_hash_function = blake2s_160;
  else if (strcmp(sbf_hp->hash_family, "blake2s_224") == 0)
    selected_hash_function = blake2s_224;
  else if (strcmp(sbf_hp->hash_family, "blake2s_256") == 0)
    selected_hash_function = blake2s_256;
  else if (strcmp(sbf_hp->hash_family, "xxhash_32") == 0)
    selected_hash_function = xxhash_32;
  else if (strcmp(sbf_hp->hash_family, "xxhash_64") == 0)
    selected_hash_function = xxhash_64;
  else if (strcmp(sbf_hp->hash_family, "xxhash3_64") == 0)
    selected_hash_function = xxhash3_64;
  else if (strcmp(sbf_hp->hash_family, "xxhash3_128") == 0)
    selected_hash_function = xxhash3_128;
  else if (strcmp(sbf_hp->hash_family, "murmur2_32") == 0)
    selected_hash_function = murmur2_32;
  else if (strcmp(sbf_hp->hash_family, "murmur2_64") == 0)
    selected_hash_function = murmur2_64;
  else  // Default
    selected_hash_function = ltc_hash_sha2_256;

  for (u32 i = 0; i < sbf->num_hash_functions; i++) sbf->hash_functions[i] = selected_hash_function;

  return 0;
}

void sbf_destroy(const sbf_t *sbf) {
  free(sbf->hash_functions);
  free(sbf->bv);
}

// TODO inout changed from const to non-const
void sbf_insert(const sbf_t *sbf, u8 *input, u64 length) {
  u8 hash_buffer[HASH_MAX_LENGTH_THRESHOLD];


#ifndef TVHASHOPTIMIZED
  BIGNUM *hash_bn = BN_new();
  BIGNUM *sbf_size_bn = BN_new();
  BIGNUM *target_idx_bn = BN_new();

  /* Convert the SBF size to BigNum */
  BN_set_word(sbf_size_bn, sbf->size);
#endif

#ifndef TVHASHOPTIMIZED
  /* We concat the given input with the 4-byte index of the SBF hash function */
  u8 *concat_buffer = malloc(length + sizeof(u32));
#endif


  for (u32 i = 0; i < sbf->num_hash_functions; i++) {
#ifndef TVHASHOPTIMIZED
  u8 idx_bytes[4]; memcpy(idx_bytes, &i, 4);
  u32 concat_buffer_length = concat_buffers(concat_buffer, input, length, idx_bytes, 4);
    u32 hash_size = sbf->hash_functions[i](hash_buffer, concat_buffer, concat_buffer_length);
#else
    /* We do not concat the index with the input but we add it to it */
    input[0] += i; //TODO const changed to non-const
    u32 hash_size = TVOPTIMIZED_BFTVMHORS_HASH_FUNCTION(hash_buffer, input, length);
#endif

    /* Convert the hash value to BigNum for further evaluations.
     *
     * We aim to compute the following to get an index for the SBF:
     *              target_idx = hash % SBF_SIZE
     * */

      unsigned __int128 target_idx;
#ifndef TVHASHOPTIMIZED
    /* Convert the computed hash to a BIGNUM */
    BN_bin2bn(hash_buffer, hash_size, hash_bn);

    /* Compute hash % SBF_SIZE */
    BN_mod(target_idx_bn, hash_bn, sbf_size_bn, BN_CTX_new());

    /* Converting the result to integer in base 10 */
    target_idx = strtol(BN_bn2dec(target_idx_bn), NULL, 10);
#else
    target_idx = *(unsigned __int128 *)hash_buffer % sbf->size;
#endif

    /* Read the target byte and set the appropriate bit and write back */
    u8 sbf_target_byte = sbf->bv[BITS_2_BYTES(target_idx)];
    sbf_target_byte |= 1 << (8 - BITS_MOD_BYTES(target_idx) - 1);
    sbf->bv[BITS_2_BYTES(target_idx)] = sbf_target_byte;
  }
#ifndef TVHASHOPTIMIZED
  free(concat_buffer);
#endif
}

//TOCO input to non-const
u32 sbf_check(const sbf_t *sbf, u8 *input, u64 length) {
    u8 hash_buffer[HASH_MAX_LENGTH_THRESHOLD];

#ifndef TVHASHOPTIMIZED
    BIGNUM *hash_bn = BN_new();
    BIGNUM *sbf_size_bn = BN_new();
    BIGNUM *target_idx_bn = BN_new();

    /* Convert the SBF size to BigNum */
    BN_set_word(sbf_size_bn, sbf->size);
#endif

#ifndef TVHASHOPTIMIZED
    /* We concat the given input with the 4-byte index of the SBF hash function */
    u8 *concat_buffer = malloc(length + sizeof(u32));
#endif
    for (u32 i = 0; i < sbf->num_hash_functions; i++) {
#ifndef TVHASHOPTIMIZED
  u8 idx_bytes[4]; memcpy(idx_bytes, &i, 4);
  u32 concat_buffer_length = concat_buffers(concat_buffer, input, length, idx_bytes, 4);
        u32 hash_size = sbf->hash_functions[i](hash_buffer, concat_buffer, concat_buffer_length);
#else
        /* We do not concat the index with the input but we add it to it */
    input[0] += i; //TODO const changed to non-const endianness
    u32 hash_size = TVOPTIMIZED_BFTVMHORS_HASH_FUNCTION(hash_buffer, input, length);
#endif

        /* Convert the hash value to BigNum for further evaluations.
         *
         * We aim to compute the following to get an index for the SBF:
         *              target_idx = hash % SBF_SIZE
         * */

        unsigned __int128 target_idx;
#ifndef TVHASHOPTIMIZED
        /* Convert the computed hash to a BIGNUM */
        BN_bin2bn(hash_buffer, hash_size, hash_bn);

        /* Compute hash % SBF_SIZE */
        BN_mod(target_idx_bn, hash_bn, sbf_size_bn, BN_CTX_new());

        /* Converting the result to integer in base 10 */
        target_idx = strtol(BN_bn2dec(target_idx_bn), NULL, 10);
#else
        target_idx = *(unsigned __int128 *)hash_buffer % sbf->size;
#endif
    /* Read the target byte and check for the set/unset state of the desired bit */
    u8 sbf_target_byte = sbf->bv[BITS_2_BYTES(target_idx)];
    if (!(sbf_target_byte & (1 << (8 - BITS_MOD_BYTES(target_idx) - 1)))) {
#ifndef TVHASHOPTIMIZED
        free(concat_buffer);
#endif
        return SBF_ELEMENT_ABSENTS;
    }
  }
#ifndef TVHASHOPTIMIZED
  free(concat_buffer);
#endif

  return SBF_ELEMENT_EXISTS;
}