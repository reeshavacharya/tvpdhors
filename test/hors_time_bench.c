#define _GNU_SOURCE
#include <bftvmhors/hors.h>
#include <bftvmhors/bits.h>
#include <bftvmhors/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static inline long long nsec_diff(const struct timespec *a, const struct timespec *b) {
    return (a->tv_sec - b->tv_sec) * 1000000000LL + (a->tv_nsec - b->tv_nsec);
}

static int cmp_ll(const void *a, const void *b) {
    long long x = *(const long long *)a;
    long long y = *(const long long *)b;
    return (x>y) - (x<y);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s CONFIG_FILE MESSAGE_FILE ITERATIONS\n", argv[0]);
        return 1;
    }
    const char *config_path = argv[1];
    const char *message_path = argv[2];
    int iters = atoi(argv[3]);
    if (iters <= 0) iters = 10;

    hors_hp_t hp;
    if (hors_new_hp(&hp, (const u8*)config_path) != HORS_NEW_HP_SUCCESS) {
        fprintf(stderr, "Failed to parse config: %s\n", config_path);
        return 1;
    }

    // Read message
    u8 *message = NULL; u32 message_len = 0;
    message_len = read_file(&message, (const u8*)message_path);
    if ((int)message_len <= 0) {
        fprintf(stderr, "Failed to read message: %s\n", message_path);
        return 1;
    }

    // Keygen timing (repeat to get stats)
    long long *t_keygen = malloc(sizeof(long long)*iters);
    for (int i=0;i<iters;i++) {
        hors_keys_t keys;
        struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
        if (hors_keygen(&keys, &hp) != HORS_KEYGEN_SUCCESS) {
            fprintf(stderr, "keygen failed\n");
            return 1;
        }
        clock_gettime(CLOCK_MONOTONIC, &t1);
        t_keygen[i] = nsec_diff(&t1, &t0);
        hors_destroy_keys(&keys);
    }
    // Prepare a single key for sign/verify loops
    hors_keys_t keys;
    if (hors_keygen(&keys, &hp) != HORS_KEYGEN_SUCCESS) {
        fprintf(stderr, "keygen failed\n");
        return 1;
    }

    hors_signer_t signer; hors_new_signer(&signer, &hp, &keys);
    hors_signature_t sig; sig.signature = malloc(signer.hp->k * BITS_2_BYTES(signer.hp->l));

    long long *t_sign = malloc(sizeof(long long)*iters);
    for (int i=0;i<iters;i++) {
        struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
        hors_sign(&sig, &signer, message, message_len);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        t_sign[i] = nsec_diff(&t1, &t0);
    }

    hors_verifier_t verifier; hors_new_verifier(&verifier, keys.pk);
    long long *t_verify = malloc(sizeof(long long)*iters);
    for (int i=0;i<iters;i++) {
        struct timespec t0, t1; clock_gettime(CLOCK_MONOTONIC, &t0);
        hors_verify(&verifier, &hp, &sig, message, message_len);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        t_verify[i] = nsec_diff(&t1, &t0);
    }

    // Stats
    long long sum_k=0,sum_s=0,sum_v=0; for(int i=0;i<iters;i++){sum_k+=t_keygen[i];sum_s+=t_sign[i];sum_v+=t_verify[i];}
    qsort(t_keygen,iters,sizeof(long long),cmp_ll);
    qsort(t_sign,iters,sizeof(long long),cmp_ll);
    qsort(t_verify,iters,sizeof(long long),cmp_ll);
    long long med_k = t_keygen[iters/2];
    long long med_s = t_sign[iters/2];
    long long med_v = t_verify[iters/2];

    printf("HORS Benchmark (ITER=%d)\n", iters);
    printf("Keygen: %lld ns (%0.3f ms)\n", sum_k/(long long)iters, (double)(sum_k/(double)iters)/1e6);
    printf("Sign:   avg %lld ns (%0.3f ms), med %lld ns (%0.3f ms)\n", sum_s/(long long)iters, (double)(sum_s/(double)iters)/1e6, med_s, (double)med_s/1e6);
    printf("Verify: avg %lld ns (%0.3f ms), med %lld ns (%0.3f ms)\n", sum_v/(long long)iters, (double)(sum_v/(double)iters)/1e6, med_v, (double)med_v/1e6);

    free(t_keygen); free(t_sign); free(t_verify);
    free(sig.signature); hors_destroy_keys(&keys); hors_destroy_hp(&hp); free(message);
    return 0;
}
