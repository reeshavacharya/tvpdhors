#ifndef BFTVMHORS_HASH_H
#define BFTVMHORS_HASH_H

#include <bftvmhors/types.h>

/// This defines the maximum hash length (in Bytes) of all the hash functions
/// supported
#define HASH_MAX_LENGTH_THRESHOLD 80

/// Computes the hash value based on the Tomcrypt SHA2-256
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 ltc_hash_sha2_256(u8* hash_output, const u8* input, u64 length);

/// Computes the hash value based on the Openssl SHA2-256
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 openssl_hash_sha2_256(u8* hash_output, const u8* input, u64 length);

/// Computes the hash value based on the Jenkins one_at_a_time
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 jenkins_oaat(u8* hash_output, const u8* key, u64 length);

/// Computes the hash value based on the Fowler–Noll–Vo (FNV) type 0
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 fnv64_0(u8* hash_output, const u8* input, u64 length);

/// Computes the hash value based on the Fowler–Noll–Vo (FNV) type 1
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 fnv64_1(u8* hash_output, const u8* input, u64 length);

/// Computes the hash value based on the Fowler–Noll–Vo (FNV) type 1a
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 fnv64_1a(u8* hash_output, const u8* input, u64 length);


/// Computes the hash value based on the MD5
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 openssl_hash_md5(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the sha1
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 openssl_hash_sha1(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the SipHash by Jean-Philippe Aumasson (https://github.com/veorq/SipHash)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 jp_aumasson_siphash(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the Blake2b-256 by (https://github.com/rurban/smhasher?tab=readme-ov-file)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 blake2b_256(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the Blake2b-384 by (https://github.com/rurban/smhasher?tab=readme-ov-file)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 blake2b_384(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the Blake2b-512 by (https://github.com/rurban/smhasher?tab=readme-ov-file)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 blake2b_512(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the Blake2s-128 by (https://github.com/rurban/smhasher?tab=readme-ov-file)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 blake2s_128(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the Blake2s-160 by (https://github.com/rurban/smhasher?tab=readme-ov-file)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 blake2s_160(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the Blake2s-224 by (https://github.com/rurban/smhasher?tab=readme-ov-file)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 blake2s_224(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the Blake2s-256 by (https://github.com/rurban/smhasher?tab=readme-ov-file)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 blake2s_256(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the XXHash-32 by (https://github.com/Cyan4973/xxHash)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 xxhash_32(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the XXHash-64 by (https://github.com/Cyan4973/xxHash)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 xxhash_64(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the XXHash3-64 by (https://github.com/Cyan4973/xxHash)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 xxhash3_64(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the XXHash3-128 by (https://github.com/Cyan4973/xxHash)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 xxhash3_128(u8 * hash_output, const u8 * input , u64 length);


/// Computes the hash value based on the murmur2-32 by (https://github.com/rurban/smhasher/tree/master)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 murmur2_32(u8 * hash_output, const u8 * input , u64 length);

/// Computes the hash value based on the murmur2-64 by (https://github.com/rurban/smhasher/tree/master)
/// \param hash_output Pointer to buffer that the hash will be stored
/// \param input Pointer to the input that we want the hash value
/// \param length The length of the input
/// \return The size of the hash
u32 murmur2_64(u8 * hash_output, const u8 * input , u64 length);

#endif