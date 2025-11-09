#include <bftvmhors/hors.h>
#include <bftvmhors/bits.h>
#include <bftvmhors/debug.h>
#include <bftvmhors/file.h>
#include <bftvmhors/mht.h>
#include <bftvmhors/hash.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {

    if (argc<3){
        debug("Usage:  ./hors CONFIG_FILE_PATH MESSAGE_FILE_PATH", DEBUG_ERR);
        return 1;
    }
    debug("Parameters of the config_sample file should be chosen carefully (t, k, multi-thread...), otherwise, the output can be unexpected", DEBUG_WARNING);

    /* Hyper parameters and keys */
    hors_hp_t hp;
    hors_keys_t keys;

    debug("Reading the config file...", DEBUG_INF);
    if (hors_new_hp(&hp, argv[1]) == HORS_NEW_HP_FAILED)
        return 1;
    printf("k: %d\n", hp.k);
    printf("t: %d\n",hp.t);

    debug("Generating private and public keys...", DEBUG_INF);
//    if (hors_keygen(&keys, &hp) == HORS_KEYGEN_FAILED)
//        return 1;

#define ITER 10000

#ifdef MULTIPLE
#define LEAVES 64
#else
#define LEAVES 1
#endif
//printf("%d\n", LEAVES);

    double keygen_time = 0;
    u8 all_pks[4194304];
    struct timeval start_time, end_time;

    for(int i=0; i<ITER; i++) {

        for(int i=0; i<LEAVES;i++) {
            if (hors_keygen(&keys, &hp) == HORS_KEYGEN_FAILED)
                return 1;

            keygen_time += HORS_KEYGEN_TIME;
            memcpy(&all_pks[i * BITS_2_BYTES(hp.lpk) * hp.t], keys.pk, BITS_2_BYTES(hp.lpk) * hp.t);
            hors_destroy_keys(&keys);
        }

#ifdef MULTIPLE
        gettimeofday(&start_time, NULL);

        /* Build MHT on top of all the PKs */
        mht_node_t * root = mht_build(all_pks, 64, BITS_2_BYTES(hp.lpk) * hp.t, MHT_NOT_GENERATE_AUTH_PATH, 1, NULL);

        gettimeofday(&end_time, NULL);

        keygen_time += (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;

        mht_destroy_node(root);

#endif
    }

    printf("KEYGEN: %0.12f\n", keygen_time/(ITER) * 1000000);










    hors_keygen(&keys, &hp);
    /* Signer */
    debug("New signer is created", DEBUG_INF);
    hors_signer_t signer;
    hors_new_signer(&signer, &hp, &keys);
    hors_signature_t signature;
    signature.signature = malloc(signer.hp->k * BITS_2_BYTES(signer.hp->lpk));

    /* Reading the message */
    u8 * message;
    u32 message_len;
    if ((message_len = read_file(&message, argv[2])) == FILE_OPEN_ERROR)
        return 1;

    hors_sign(&signature, &signer, message, message_len);
    double sign_time = 0;
    u8 aut_path[140000];

    for(int i=0;i<ITER;i++) {
        hors_sign(&signature, &signer, message, message_len);
        sign_time += HORS_SIGN_TIME;

#ifdef MULTIPLE
        /* Generating auth path */
        gettimeofday(&start_time, NULL);

        // For MHT fractal estimation
        mht_build(all_pks, 8, BITS_2_BYTES(hp.lpk) * hp.t, MHT_GENERATE_AUTH_PATH, 1, aut_path);
        gettimeofday(&end_time, NULL);
        sign_time += (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
#endif
    }

    printf("SIGN: %0.12f\n", sign_time/(ITER) * 1000000);

    debug("Signature is ready", DEBUG_INF);





    /* Verifier */
    debug("New verifier is created", DEBUG_INF);
    hors_verifier_t verifier;
    hors_new_verifier(&verifier, keys.pk);

    double verify_time = 0;

    u8 commitment[256];
    u8 node1[256];
    u8 node2[256];
    u8 node12[512];

    for(int i=0; i< ITER; i++) {

#ifdef MULTIPLE
        // Simulating commitment computation
        gettimeofday(&start_time, NULL);

        for (int i = 0; i < log2(hp.t) - 1; i++) {
            // combining nodes
            memcpy(node12, node1, 256);
            memcpy(node12 + 256, commitment, 256);
            ltc_hash_sha2_256(commitment, node12, 256);
        }
        // compare
        memcmp(commitment, commitment, 256);

        gettimeofday(&end_time, NULL);
        verify_time += (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;

#endif

        hors_verify(&verifier, &hp, &signature, message, message_len);
        verify_time += HORS_VERIFY_TIME;

    }
    printf("VERIFY: %0.12f\n", verify_time/(ITER) * 1000000);



    if (hors_verify(&verifier, &hp, &signature, message, message_len) == HORS_SIGNATURE_ACCEPTED)
        debug("Verification: Signature is valid", DEBUG_INF);
    else
        debug("Verification: Signature is (not) valid", DEBUG_INF);


    debug("Deleting hyper parameter and the keys", DEBUG_INF);
//    hors_destroy_hp(&hp);
//    hors_destroy_keys(&keys);
}


