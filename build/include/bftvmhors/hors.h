#ifndef BFTVMHORS_HORS_H
#define BFTVMHORS_HORS_H

#include <bftvmhors/types.h>

double hors_get_keygen_time();
double hors_get_sign_time();
double hors_get_verify_time();

#define HORS_KEYGEN_TIME hors_get_keygen_time()
#define HORS_SIGN_TIME hors_get_sign_time()
#define HORS_VERIFY_TIME hors_get_verify_time()

#define HORS_NEW_HP_SUCCESS 0
#define HORS_NEW_HP_FAILED 1

#define HORS_KEYGEN_SUCCESS 0
#define HORS_KEYGEN_FAILED 1

#define HORS_NEW_SIGNER_SUCCESS 0
#define HORS_NEW_SIGNER_FAILED 1

#define HORS_NEW_VERIFIER_SUCCESS 0
#define HORS_NEW_VERIFIER_FAILED 1

#define HORS_SIGNATURE_ACCEPTED 0
#define HORS_SIGNATURE_REJECTED 1

#define HORS_SIGNING_SUCCESS 0
#define HORS_SIGNING_FAILED 1

#define HORS_REJECTION_SAMPLING_SUCCESS 0
#define HORS_REJECTION_SAMPLING_FAILED 1

#define HORS_REJECTION_SAMPLING_DONE 0
#define HORS_REJECTION_SAMPLING_NOT_DONE 1

/// Implements the hyper parameters of HORS
typedef struct hors_hp {
    u32 N;                     // Number of messages to be signed
    u32 k;                     // k parameter of the HORS signature
    u32 t;                     // t parameter of the HORS signature
    u32 l;                     // l parameter of the HORS signature
    u32 lpk;                   // Size of the public key portion
    u8* seed_file;             // Seed file
    u8 do_rejection_sampling;  // Do/Don't perform rejection sampling
} hors_hp_t;

/// Implements the HORS keys
typedef struct hors_keys {
    u8* sk;
    u8* pk;
} hors_keys_t;

/// Implements the HORS signature
typedef struct hors_signature {
    u8* signature;
    u32 rejection_sampling_counter;
} hors_signature_t;

/// Implements the HORS signer
typedef struct hors_signer {
    u32 state;  // Not necessarily used. It is here for compatibility
    hors_keys_t* keys;
    hors_hp_t* hp;
} hors_signer_t;

/// Implements the HORS verifier
typedef struct hors_verifier {
    u32 state;  // Not necessarily used. It is here for compatibility
    u8* pk;
} hors_verifier_t;

/// Passing the config_sample file, it creates a new hyper parameter struct
/// \param new_hp Pointer to the hyper parameter struct
/// \param config_file Path of the config_sample file
/// \return HORS_NEW_HP_SUCCESS and HORS_NEW_HP_FAILED
u32 hors_new_hp(hors_hp_t* new_hp, const u8* config_file);

/// HORS destroys the internal hyper parameter elements
/// \param hp Pointer to the hyper parameter
void hors_destroy_hp(hors_hp_t* hp);


/// HORS key generation
/// \param keys Pointer to the HORS keys
/// \param hp Pointer to the HORS HP
/// \return HORS_KEYGEN_SUCCESS, HORS_KEYGEN_FAILED
u32 hors_keygen(hors_keys_t* keys, hors_hp_t* hp);

/// HORS destroys the internal key elements
/// \param keys Pointer to the keys
void hors_destroy_keys(hors_keys_t* keys);

/// Passing the HORS hyper parameters and the keys it creates a HORS signer
/// \param signer Pointer to the HORS signer struct
/// \param hp HORS hyper parameter
/// \param keys HORS keys
/// \return HORS signer
u32 hors_new_signer(hors_signer_t* signer, hors_hp_t* hp, hors_keys_t* keys);

/// HORS signer
/// \param signature Pointer to the output signature struct
/// \param signer Pointer to the signer signer struct
/// \param message  Pointer to the message to check signature on
/// \param message_len  Length of the input message
/// \return HORS_SIGNING_SUCCESS, HORS_SIGNING_FAILED
u32 hors_sign(hors_signature_t* signature, hors_signer_t* signer, u8* message,
              u64 message_len);

/// Passing the HORS public key, returns a HORS verifier
/// \param pk HORS public key
/// \return HORS verifier
u32 hors_new_verifier(hors_verifier_t* verifier, u8* pk);

/// HORS verifier
/// \param verifier Pointer to the HORS verifier struct
/// \param hp Pointer to the HORS hyper parameter struct
/// \param signature Pointer to the HORS signature struct
/// \param message  Pointer to the message to check signature on
/// \param message_len Length of the input message
/// \return HORS_SIGNATURE_VERIFIED and HORS_SIGNATURE_REJECTED
u32 hors_verify(hors_verifier_t* verifier, hors_hp_t* hp,
                hors_signature_t* signature, u8* message, u64 message_len);

#endif