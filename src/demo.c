#include <lib-mesg.h>
#include <lib-misc.h>
#include <lib-2k-prs.h>
#include <lib-timing.h>
#include <gmp.h>
#include <stdio.h>
#include <string.h>

#define prng_sec_level 128
#define DEFAULT_MOD_BITS 4096
#define BENCHMARK_ITERATIONS 10

#define sampling_time 4 /* secondi */
#define max_samples (sampling_time * 50)

gmp_randstate_t prng;

int main(int argc, char *argv[])
{
    printf("Initializing PRNG...\n\n");
    gmp_randinit_default(prng);                // prng means its state & init
    gmp_randseed_os_rng(prng, prng_sec_level); // seed setting

    set_messaging_level(msg_very_verbose); // level of detail of input

    prs_keys_t keys;
    prs_plaintext_t plaintext, dec_plaintext;
    prs_plaintext_init(plaintext);
    prs_plaintext_init(dec_plaintext);
    prs_ciphertext_t ciphertext;
    prs_ciphertext_init(ciphertext);

    printf("Launching demo with k=%d, n_bits=%d\n\n", DEFAULT_MOD_BITS / 4, DEFAULT_MOD_BITS);

    prs_generate_keys(keys, DEFAULT_MOD_BITS / 4, DEFAULT_MOD_BITS, prng);
    gmp_printf("p: %Zd\n", keys->p);
    gmp_printf("q: %Zd\n", keys->q);
    gmp_printf("n: %Zd\n", keys->n);
    gmp_printf("y: %Zd\n", keys->y);
    printf("k: %d\n", keys->k);
    gmp_printf("2^k: %Zd\n", keys->k_2);

    mpz_urandomb(plaintext->m, prng, keys->k);

    printf("Starting prs_encrypt\n");
    prs_encrypt(ciphertext, keys, plaintext, prng, 512);
    gmp_printf("c: %Zd\n\n", ciphertext->c);

    printf("Starting prs_decrypt\n");
    prs_decrypt(dec_plaintext, keys, ciphertext);
    gmp_printf("Original Plaintext: %Zd\n\n", plaintext->m);
    gmp_printf("Plaintext from Dec: %Zd\n\n", dec_plaintext->m);
    assert(mpz_cmp(plaintext->m, dec_plaintext->m) == 0);

    printf("All done!!\n");
    prs_plaintext_clear(plaintext);
    prs_plaintext_clear(dec_plaintext);
    prs_ciphertext_clear(ciphertext);
    gmp_randclear(prng);

    return 0;
}
