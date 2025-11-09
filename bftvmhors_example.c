#include <bftvmhors/bftvmhors.h>
#include <bftvmhors/bits.h>
#include <bftvmhors/debug.h>
#include <bftvmhors/file.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <bftvmhors/mht.h>


int main(int argc, char** argv) {

    if (argc<3){
        debug("Usage:  ./bftvmhors CONFIG_FILE_PATH MESSAGE_FILE_PATH", DEBUG_ERR);
        return 1;
    }
    debug("Parameters of the config_sample file should be chosen carefully (bf, t, k, multi-thread...), otherwise, the output can be unexpected", DEBUG_WARNING);

    /* Hyper parameters and keys */
    bftvmhors_hp_t hp;
    bftvmhors_keys_t keys;

    debug("Reading the config file...", DEBUG_INF);
    if (bftvmhors_new_hp(&hp, argv[1]) == BFTVMHORS_NEW_HP_FAILED)
        return 1;

    printf("k: %d\n", hp.k);
    printf("t: %d\n",hp.t);
    printf("size: %d\n", hp.ohbf_hp.required_size);
    printf("k': %d\n", hp.ohbf_hp.num_of_mod_operations);


    debug("Generating private and public keys...", DEBUG_INF);
//    if (bftvmhors_keygen(&keys, &hp) == BFTVMHORS_KEYGEN_FAILED)
//        return 1;

#define ITER 10000

#ifdef MULTIPLE
#define LEAVES 64
#else
#define LEAVES 1
#endif

    double keygen_time = 0;
    u8 all_pks[8194304];
    struct timeval start_time, end_time;

    for(int i=0; i< ITER; i++) {

        for(int j=0; j< LEAVES; j++) {
            if (bftvmhors_keygen(&keys, &hp) == BFTVMHORS_KEYGEN_FAILED)
                return 1;
            keygen_time += BFTVMHORS_KEYGEN_TIME;

            memcpy(&all_pks[j * keys.pk.size], keys.pk.bv, keys.pk.size);
//            bftvmhors_destroy_keys(&keys); // Bug on deleting the pk.partitions

        }

#ifdef MULTIPLE
        gettimeofday(&start_time, NULL);


        /* Build MHT on top of all the PKs */
        mht_node_t * root = mht_build(all_pks, 64, keys.pk.size, MHT_NOT_GENERATE_AUTH_PATH, 1, NULL);

        gettimeofday(&end_time, NULL);

        keygen_time += (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;

        mht_destroy_node(root);

#endif
    }

    printf("KEYGEN: %0.12f\n", keygen_time/(ITER) * 1000000);



    /* Signer */
    debug("New signer is created", DEBUG_INF);
    bftvmhors_signer_t signer;
    bftvmhors_new_signer(&signer, &hp, &keys);
    bftvmhors_signature_t signature;
    signature.signature = malloc(signer.hp->k * BITS_2_BYTES(signer.hp->l));

    /* Reading the message */
    u8 * message;
    u32 message_len;
    if ((message_len = read_file(&message, argv[2])) == FILE_OPEN_ERROR)
        return 1;




    double sign_time = 0;
    u8 aut_path[140000];
    for(int i=0;i<ITER;i++) {
        bftvmhors_sign(&signature, &signer, message, message_len);;
        sign_time += BFTVMHORS_SIGN_TIME;

#ifdef MULTIPLE
        /* Generating auth path */
        gettimeofday(&start_time, NULL);
        mht_build(all_pks, 8, BITS_2_BYTES(hp.lpk) * hp.t, MHT_GENERATE_AUTH_PATH, 1, aut_path);

        gettimeofday(&end_time, NULL);
        sign_time += (end_time.tv_sec - start_time.tv_sec) + (end_time.tv_usec - start_time.tv_usec) / 1.0e6;
#endif

    }

    printf("SIGN: %0.12f\n", sign_time/(ITER) * 1000000);






//    bftvmhors_sign(&signature, &signer, message, message_len);
    debug("Signature is ready", DEBUG_INF);

    /* Verifier */
    debug("New verifier is created", DEBUG_INF);
    bftvmhors_verifier_t verifier;
    bftvmhors_new_verifier(&verifier, &keys.pk);


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

        bftvmhors_verify(&verifier, &hp, &signature, message, message_len);
        verify_time += BFTVMHORS_VERIFY_TIME;

    }
    printf("VERIFY: %0.12f\n", verify_time/(ITER) * 1000000);






    if (bftvmhors_verify(&verifier, &hp, &signature, message, message_len) == BFTVMHORS_SIGNATURE_ACCEPTED)
        debug("Verification: Signature is valid", DEBUG_INF);
    else
        debug("Verification: Signature is (not) valid", DEBUG_INF);

    debug("Deleting hyper parameter and the keys", DEBUG_INF);
    bftvmhors_destroy_keys(&keys);
    bftvmhors_destroy_hp(&hp);

}

