#include <bftvmhors/ohbf.h>
#include <bftvmhors/hash.h>
#include <bftvmhors/bits.h>
#include <bftvmhors/tv_params.h>
#include <openssl/bn.h>
#include <stdlib.h>
#include <string.h>


//TODO check with paper
/// Determining the length of the partitions based on the Algorithm 1 of "One-Hashing Bloom Filter" paper
/// \param partitions Pointer to the array of partition sizes
/// \param required_size Required length for summing all the partition sizes
/// \param num_of_partitions Number of partitions
/// \return Actual sum of the partition sizes
static u32 ohbf_create_partitions(u32 ** partitions, u32 required_size, u32 num_of_partitions){
    /* Allocate partition size table */
    *partitions = (u32 *) malloc(sizeof(u32)*(num_of_partitions+2));

    /* Find the closest prime to the required_size/num_of_partitions */
    int closest_prime_dist = INT_MAX;
    int closest_prime_idx = 0;

    for (int i=0; i<OHBF_PRIME_COUNT; i++){
        if (abs(ohbf_primes[i] - required_size/num_of_partitions) < closest_prime_dist){
            closest_prime_dist = abs(ohbf_primes[i] - required_size/num_of_partitions);
            closest_prime_idx = i;
        }
    }

    int sum = 0, diff = 0, actual_size=0;

    for (int i=closest_prime_idx-num_of_partitions; i<closest_prime_idx; i++) {

        int j = i;
        if (j<0)
            j+=100000;
        sum += ohbf_primes[j];
    }

    int min = abs(sum - required_size);
    int j = closest_prime_idx ;

    while(1){
        int idx = j-num_of_partitions;
        if(idx<0)
            idx+=100000;

        sum += ohbf_primes[j] - ohbf_primes[idx];

        diff = abs(sum-required_size);
        if (diff >= min)
            break;
        min = diff;
        j++;
    }

    for (int i=0; i<num_of_partitions; i++){
        int idx = j-num_of_partitions;
        if (idx<0)
            idx+=100000;

        (*partitions)[i] = ohbf_primes[idx+i];
        actual_size += (*partitions)[i];
    }

    return actual_size;
}

u32 ohbf_new_hp(ohbf_hp_t * ohbf_hp, u32 required_size, u32 num_of_mod_operations, const u8 *hash_family) {
    ohbf_hp->required_size = required_size;

    ohbf_hp->actual_size = ohbf_create_partitions(&ohbf_hp->partitions, required_size, num_of_mod_operations);
    ohbf_hp->num_of_mod_operations = num_of_mod_operations;
    ohbf_hp->hash_family = hash_family;
    return OHBF_NEW_HP_SUCCESS;
}

u32 ohbf_create(ohbf_t *ohbf, const ohbf_hp_t *ohbf_hp){
    /* Size is in bits */
    ohbf->size = ohbf_hp->actual_size;
    ohbf->num_of_mod_operations = ohbf_hp->num_of_mod_operations;

    ohbf->partitions = ohbf_hp->partitions;

    /* Allocate ceil(size/8) bytes for the bit-vector */
    u32 bv_bytes = (ohbf->size + 7) / 8;
    ohbf->bv = calloc(bv_bytes, 1);

    if (strcmp(ohbf_hp->hash_family, "ltc_sha256") == 0)
        ohbf->hash_function = ltc_hash_sha2_256;
    else if (strcmp(ohbf_hp->hash_family, "openssl_sha256") == 0)
        ohbf->hash_function = openssl_hash_sha2_256;
    else if (strcmp(ohbf_hp->hash_family, "openssl_md5") == 0)
        ohbf->hash_function = openssl_hash_md5;
    else if (strcmp(ohbf_hp->hash_family, "openssl_sha1") == 0)
        ohbf->hash_function = openssl_hash_sha1;
    else if (strcmp(ohbf_hp->hash_family, "jenkins_oaat") == 0)
        ohbf->hash_function = jenkins_oaat;
    else if (strcmp(ohbf_hp->hash_family, "fnv64_0") == 0)
        ohbf->hash_function = fnv64_0;
    else if (strcmp(ohbf_hp->hash_family, "fnv64_1") == 0)
        ohbf->hash_function = fnv64_1;
    else if (strcmp(ohbf_hp->hash_family, "fnv64_1a") == 0)
        ohbf->hash_function = fnv64_1a;
    else if (strcmp(ohbf_hp->hash_family, "jp_aumasson_siphash") == 0)
        ohbf->hash_function = jp_aumasson_siphash;
    else if (strcmp(ohbf_hp->hash_family, "blake2b_256") == 0)
        ohbf->hash_function = blake2b_256;
    else if (strcmp(ohbf_hp->hash_family, "blake2b_384") == 0)
        ohbf->hash_function = blake2b_384;
    else if (strcmp(ohbf_hp->hash_family, "blake2b_512") == 0)
        ohbf->hash_function = blake2b_512;
    else if (strcmp(ohbf_hp->hash_family, "blake2s_128") == 0)
        ohbf->hash_function = blake2s_128;
    else if (strcmp(ohbf_hp->hash_family, "blake2s_160") == 0)
        ohbf->hash_function = blake2s_160;
    else if (strcmp(ohbf_hp->hash_family, "blake2s_224") == 0)
        ohbf->hash_function = blake2s_224;
    else if (strcmp(ohbf_hp->hash_family, "blake2s_256") == 0)
        ohbf->hash_function = blake2s_256;
    else if (strcmp(ohbf_hp->hash_family, "xxhash_32") == 0)
        ohbf->hash_function = xxhash_32;
    else if (strcmp(ohbf_hp->hash_family, "xxhash_64") == 0)
        ohbf->hash_function = xxhash_64;
    else if (strcmp(ohbf_hp->hash_family, "xxhash3_64") == 0)
        ohbf->hash_function = xxhash3_64;
    else if (strcmp(ohbf_hp->hash_family, "xxhash3_128") == 0)
        ohbf->hash_function = xxhash3_128;
    else if (strcmp(ohbf_hp->hash_family, "murmur2_32") == 0)
        ohbf->hash_function = murmur2_32;
    else if (strcmp(ohbf_hp->hash_family, "murmur2_64") == 0)
        ohbf->hash_function = murmur2_64;
    else  // Default
        ohbf->hash_function = ltc_hash_sha2_256;

    return OHBF_CREATE_SUCCESS;

}

void ohbf_destroy(const ohbf_t *ohbf) {
    free(ohbf->bv);
    /* partitions memory is owned by ohbf_hp; do not free here */
}


void ohbf_insert(const ohbf_t *ohbf, const u8 *input, u64 length) {
    u8 hash_buffer[HASH_MAX_LENGTH_THRESHOLD];

#ifndef TVHASHOPTIMIZED
    /* Hash the input */
    u32 hash_size = ohbf->hash_function(hash_buffer, input, length);
    BIGNUM *hash_bn = BN_new();
    BIGNUM *ohbf_partition_size_bn = BN_new();
    BIGNUM *target_idx_bn = BN_new();

    /* Convert the computed hash to a BIGNUM */
    BN_bin2bn(hash_buffer, hash_size, hash_bn);
#else
    u32 hash_size = TVOPTIMIZED_BFTVMHORS_HASH_FUNCTION(hash_buffer, input, length);
#endif
    /* Precompute cumulative bit offsets for partitions to avoid out-of-range access */
    u32 *part_offsets = malloc(sizeof(u32) * ohbf->num_of_mod_operations);
    u32 acc = 0;
    for (u32 i=0;i<ohbf->num_of_mod_operations;i++) { part_offsets[i] = acc; acc += ohbf->partitions[i]; }

    for (u32 i = 0; i < ohbf->num_of_mod_operations; i++) {

        /* Convert the hash value to BigNum for further evaluations.
         *
         * We aim to compute the following to get an index for the OHBF:
         *              target_idx = hash % m_i,  where m_i is the length of each partition
         * */
        unsigned __int128 target_idx;
#ifndef TVHASHOPTIMIZED
        /* Convert the partition size to the BigNum */
        BN_set_word(ohbf_partition_size_bn, ohbf->partitions[i]);

        /* Compute hash % OHBF_SIZE */
        BN_mod(target_idx_bn, hash_bn, ohbf_partition_size_bn, BN_CTX_new());

        /* Converting the result to integer in base 10 */
        target_idx = strtol(BN_bn2dec(target_idx_bn), NULL, 10);
#else

        target_idx = *(unsigned __int128 *)hash_buffer % ohbf->partitions[i];
#endif
        /* Read the target byte from the target partition and set the appropriate bit and write back */
        /* Compute bit index within the whole BV: offset of partition (in bits) + local index */
        u32 bit_index = part_offsets[i] + (u32)target_idx;
        u8 * target_partition = ohbf->bv;
        u8 ohbf_target_byte = target_partition[BITS_2_BYTES(bit_index)];
        ohbf_target_byte |= 1 << (8 - BITS_MOD_BYTES(bit_index) - 1);
        target_partition[BITS_2_BYTES(bit_index)] = ohbf_target_byte;
    }
    free(part_offsets);
}


u32 ohbf_check(const ohbf_t *ohbf, const u8 *input, u64 length) {
    u8 hash_buffer[HASH_MAX_LENGTH_THRESHOLD];

#ifndef TVHASHOPTIMIZED
    /* Hash the input */
    u32 hash_size = ohbf->hash_function(hash_buffer, input, length);
    BIGNUM *hash_bn = BN_new();
    BIGNUM *ohbf_partition_size_bn = BN_new();
    BIGNUM *target_idx_bn = BN_new();

    /* Convert the computed hash to a BIGNUM */
    BN_bin2bn(hash_buffer, hash_size, hash_bn);
#else
    u32 hash_size = TVOPTIMIZED_BFTVMHORS_HASH_FUNCTION(hash_buffer, input, length);
#endif

    /* Precompute cumulative bit offsets for partitions */
    u32 *part_offsets = malloc(sizeof(u32) * ohbf->num_of_mod_operations);
    u32 acc = 0;
    for (u32 i=0;i<ohbf->num_of_mod_operations;i++) { part_offsets[i] = acc; acc += ohbf->partitions[i]; }

    for (u32 i = 0; i < ohbf->num_of_mod_operations; i++) {

        /* Convert the hash value to BigNum for further evaluations.
         *
         * We aim to compute the following to get an index for the OHBF:
         *              target_idx = hash % m_i,  where m_i is the length of each partition
         * */
        unsigned __int128 target_idx;
#ifndef TVHASHOPTIMIZED
        /* Convert the partition size to the BigNum */
        BN_set_word(ohbf_partition_size_bn, ohbf->partitions[i]);

        /* Compute hash % OHBF_SIZE */
        BN_mod(target_idx_bn, hash_bn, ohbf_partition_size_bn, BN_CTX_new());

        /* Converting the result to integer in base 10 */
        target_idx = strtol(BN_bn2dec(target_idx_bn), NULL, 10);
#else
        target_idx = *(unsigned __int128 *)hash_buffer % ohbf->partitions[i];
#endif

        /* Read the target byte from the target partition and check for the set/unset state of the desired bit */
        u32 bit_index = part_offsets[i] + (u32)target_idx;
        u8 * target_partition = ohbf->bv;
        u8 ohbf_target_byte = target_partition[BITS_2_BYTES(bit_index)];
        if (!(ohbf_target_byte & (1 << (8 - BITS_MOD_BYTES(bit_index) - 1)))) {
            return OHBF_ELEMENT_ABSENTS;
        }
    }
    free(part_offsets);
    return OHBF_ELEMENT_EXISTS;
}

