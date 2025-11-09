#ifndef BFTVMHORS_BFTVMHORS_H
#define BFTVMHORS_BFTVMHORS_H

#include <bftvmhors/bf.h>
#include <bftvmhors/ohbf.h>
#include <bftvmhors/types.h>


double bftvmhors_get_keygen_time();
double bftvmhors_get_sign_time();
double bftvmhors_get_verify_time();


#define BFTVMHORS_KEYGEN_TIME bftvmhors_get_keygen_time()
#define BFTVMHORS_SIGN_TIME bftvmhors_get_sign_time()
#define BFTVMHORS_VERIFY_TIME bftvmhors_get_verify_time()


#define BFTVMHORS_NEW_HP_SUCCESS 0
#define BFTVMHORS_NEW_HP_FAILED 1

#define BFTVMHORS_NEW_SIGNER_SUCCESS 0
#define BFTVMHORS_NEW_SIGNER_FAILED 1

#define BFTVMHORS_NEW_VERIFIER_SUCCESS 0
#define BFTVMHORS_NEW_VERIFIER_FAILED 1

#define BFTVMHORS_KEYGEN_SUCCESS 0
#define BFTVMHORS_KEYGEN_FAILED 1

#define BFTVMHORS_SIGNATURE_ACCEPTED 0
#define BFTVMHORS_SIGNATURE_REJECTED 1

#define BFTVMHORS_SIGNING_SUCCESS 0
#define BFTVMHORS_SIGNING_FAILED 1

#define BFTVMHORS_REJECTION_SAMPLING_SUCCESS 0
#define BFTVMHORS_REJECTION_SAMPLING_FAILED 1

#define BFTVMHORS_REJECTION_SAMPLING_DONE 0
#define BFTVMHORS_REJECTION_SAMPLING_NOT_DONE 1

/// Implements the hyper parameters of BFTVMHORS
typedef struct bftvmhors_hp {
  u32 N;                     // Number of messages to be signed
  u32 k;                     // k parameter of the HORS signature
  u32 t;                     // t parameter of the HORS signature
  u32 l;                     // l parameter of the HORS signature
  u32 lpk;                    // Size of the public key portion
  u8 *seed_file;             // Seed file
  u32 sk_seed_len;           // Length of private key seeds in bits
#ifdef OHBF
    ohbf_hp_t ohbf_hp;           // Hyper parameters of the underlying Standard Bloom Filter (OHBF)
#else
    sbf_hp_t sbf_hp;           // Hyper parameters of the underlying Standard Bloom Filter (SBF)
#endif
  u8 do_rejection_sampling;  // Do/Don't perform rejection sampling
} bftvmhors_hp_t;

/// Implements the BFTVMHORS keys
typedef struct bftvmhors_keys {
  u8 *seed;
  u8 *sk_seeds;
#ifdef OHBF
  ohbf_t pk;
#else
  sbf_t pk;
#endif
  u32 num_of_keys;
} bftvmhors_keys_t;

/// Implements the BFTVMHORS signature
typedef struct bftvmhors_signature {
  const u8 *signature;
  u32 rejection_sampling_counter;
} bftvmhors_signature_t;

/// Implements the BFTVMHORS signer
typedef struct bftvmhors_signer {
  u32 state;
  bftvmhors_keys_t *keys;
  bftvmhors_hp_t *hp;
} bftvmhors_signer_t;

/// Implements the BFTVMHORS verifier
typedef struct bftvmhors_verifier {
  u32 state;
#ifdef OHBF
  ohbf_t *pk;
#else
  sbf_t *pk;
#endif
} bftvmhors_verifier_t;

/// Creates hyper parameters for the BFTVMHORS
/// \param new_hp Pointer to the hyper parameter variable
/// \param config_file Name/Path of the config_sample file
/// \return 0 if parsing the config_sample file is successful, 1 otherwise
u32 bftvmhors_new_hp(bftvmhors_hp_t *new_hp, const u8 *config_file);

/// Destroys the hyper parameter struct
/// \param hp Pointer to the hyper parameter struct
void bftvmhors_destroy_hp(bftvmhors_hp_t* hp);

/// Destroys the keys struct
/// \param keys Pointer to the keys struct
void bftvmhors_destroy_keys(bftvmhors_keys_t* keys);

/// Generates the BFTVMHORS keys
/// \param keys Pointer to the BFTVMHORS key struct
/// \param hp Pointer to the BFTVMHORS hyper parameter struct
/// \return 0 if successful, 1 otherwise
u32 bftvmhors_keygen(bftvmhors_keys_t *keys, bftvmhors_hp_t *hp);


/// Passing the BFTVMHORS hyper parameters and the keys it creates a BFTVMHORS signer
/// \param signer Pointer to the signer struct
/// \param hp BFTVMHORS hyper parameter
/// \param keys BFTVMHORS keys
/// \return BFTVMHORS_NEW_SIGNER_SUCCESS and BFTVMHORS_NEW_SIGNER_FAILED
u32 bftvmhors_new_signer(bftvmhors_signer_t * signer, bftvmhors_hp_t* hp, bftvmhors_keys_t* keys);

/// BFTVMHORS signer
/// \param signature Pointer to the output signature struct
/// \param signer Pointer to the BFTVMHORS signer struct
/// \param message  Pointer to the message to check signature on
/// \param message_len  Length of the input message
/// \return BFTVMHORS_SIGNING_SUCCESS, BFTVMHORS_SIGNING_FAILED
u32 bftvmhors_sign(bftvmhors_signature_t* signature, bftvmhors_signer_t* signer, u8* message,
                   u64 message_len);


/// Passing the BFTVMHORS public key (sbf_t type), returns a BFTVMHORS verifier
/// \param pk BFTVMHORS public key which is a SBF
/// \return BFTVMHORS_NEW_VERIFIER_SUCCESS, BFTVMHORS_NEW_VERIFIER_FAILED
#ifdef OHBF
u32 bftvmhors_new_verifier(bftvmhors_verifier_t * verifier, ohbf_t* pk);
#else
u32 bftvmhors_new_verifier(bftvmhors_verifier_t * verifier, sbf_t* pk);
#endif

/// BFTVMHORS verifier
/// \param verifier Pointer to the BFTVMHORS verifier struct
/// \param hp Pointer to the BFTVMHORS hyper parameter struct
/// \param signature Pointer to the BFTVMHORS signature struct
/// \param message  Pointer to the message to check signature on
/// \param message_len Length of the input message
/// \return BFTVMHORS_SIGNATURE_VERIFIED and BFTVMHORS_SIGNATURE_REJECTED
u32 bftvmhors_verify(bftvmhors_verifier_t* verifier, bftvmhors_hp_t* hp,
                     bftvmhors_signature_t * signature, u8* message, u64 message_len);

#endif