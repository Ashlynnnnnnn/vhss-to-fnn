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

void random_split(prs_plaintext_t input, prs_plaintext_t part1, prs_plaintext_t part2){
    mpz_urandomm(part1->m, prng, input->m);
    if (mpz_cmp_ui(part1->m, 0) == 0)
    {
        mpz_set_ui(part1->m, 1);
    }

    mpz_sub(part2->m, input->m, part1->m);
    if (mpz_cmp_ui(part2->m, 0) <= 0)
    {
        mpz_set_ui(part2->m, 1);
        mpz_sub_ui(part1->m, input->m, 1);
    }
}

void sub_eval(prs_plaintext_t a, prs_plaintext_t b, prs_ciphertext_t e, prs_ciphertext_t res, prs_keys_t kk){
    mpz_t t;
    mpz_init(t);

    mpz_mul(t ,a->m, b->m);
    mpz_mod(t, t, kk->k_2);

    mpz_powm(t, e->c, t, kk->n);

    mpz_mul(res->c, res->c, t);
    mpz_mod(res->c, res->c, kk->n);

    mpz_clear(t);
}

void plain_eval(prs_plaintext_t a, prs_plaintext_t b, prs_plaintext_t e, prs_ciphertext_t res, prs_keys_t kk){
    prs_plaintext_t t;
    prs_plaintext_init(t);

    mpz_mul(t->m, a->m, b->m);
    mpz_mod(t->m, t->m, kk->k_2);
    mpz_mul(t->m, t->m, e->m);
    mpz_mod(t->m, t->m, kk->k_2);

    prs_ciphertext_t ct;
    prs_ciphertext_init(ct);
    prs_encrypt(ct, kk, t, prng, 512);

    mpz_mul(res->c, res->c, ct->c);
    mpz_mod(res->c, res->c, kk->n);

    prs_plaintext_clear(t);
    prs_ciphertext_clear(ct);
}

int main(int argc, char *argv[])
{
    printf("Initializing PRNG...\n\n");
    gmp_randinit_default(prng);                // prng means its state & init
    gmp_randseed_os_rng(prng, prng_sec_level); // seed setting

    set_messaging_level(msg_very_verbose); // level of detail of input

    prs_keys_t keys;
    prs_plaintext_t x, y, z, x1, x2, y1, y2, z1, z2;
    prs_plaintext_init(x), prs_plaintext_init(y), prs_plaintext_init(z);
    prs_plaintext_init(x1), prs_plaintext_init(y1), prs_plaintext_init(z1);
    prs_plaintext_init(x2), prs_plaintext_init(y2), prs_plaintext_init(z2);
    prs_ciphertext_t cx1, cx2, cy1, cy2, cz1, cz2;
    prs_ciphertext_init(cx1), prs_ciphertext_init(cx2);
    prs_ciphertext_init(cy1), prs_ciphertext_init(cy2);
    prs_ciphertext_init(cz1), prs_ciphertext_init(cz2);

    printf("Launching demo with k=%d, n_bits=%d\n\n", DEFAULT_MOD_BITS / 4, DEFAULT_MOD_BITS);

    prs_generate_keys(keys, DEFAULT_MOD_BITS / 4, DEFAULT_MOD_BITS, prng);
    gmp_printf("p: %Zd\n", keys->p);
    gmp_printf("q: %Zd\n", keys->q);
    gmp_printf("n: %Zd\n", keys->n);
    gmp_printf("y: %Zd\n", keys->y);
    printf("k: %d\n", keys->k);
    gmp_printf("2^k: %Zd\n\n", keys->k_2);

    mpz_urandomb(x->m, prng, keys->k);
    mpz_urandomb(y->m, prng, keys->k);
    mpz_urandomb(z->m, prng, keys->k);
    random_split(x, x1, x2);
    random_split(y, y1, y2);
    random_split(z, z1, z2);

    mpz_t plain_res;
    mpz_init(plain_res);
    mpz_mul(plain_res, x->m, y->m);
    mpz_mod(plain_res, plain_res, keys->k_2);
    mpz_mul(plain_res, plain_res, z->m);
    mpz_mod(plain_res, plain_res, keys->k_2);

    printf("Starting prs_encrypt\n");
    prs_encrypt(cx1, keys, x1, prng, 512), prs_encrypt(cx2, keys, x2, prng, 512);
    prs_encrypt(cy1, keys, y1, prng, 512), prs_encrypt(cy2, keys, y2, prng, 512);
    prs_encrypt(cz1, keys, z1, prng, 512), prs_encrypt(cz2, keys, z2, prng, 512);

    gmp_printf("S1 gets: %Zd, %Zd, %Zd, %Zd, %Zd, %Zd\n", cx1->c, cy1->c, cz1->c, x2->m, y2->m, z2->m);
    gmp_printf("S2 gets: %Zd, %Zd, %Zd, %Zd, %Zd, %Zd\n\n", x1->m, y1->m, z1->m, cx2->c, cy2->c, cz2->c);

    // S1's evaluation
    printf("S1 starts evaluation!\n");
    prs_ciphertext_t s1;
    prs_ciphertext_init(s1);
    mpz_set_ui(s1->c, 1);
    sub_eval(y2, z2, cx1, s1, keys);
    sub_eval(x2, z2, cy1, s1, keys);
    sub_eval(x2, y2, cz1, s1, keys);
    plain_eval(x2, y2, z2, s1, keys);
    gmp_printf("S1 outputs: %Zd\n\n", s1->c);

    // S2's evaluation
    printf("S2 starts evaluation!\n");
    prs_ciphertext_t s2;
    prs_ciphertext_init(s2);
    mpz_set_ui(s2->c, 1);
    sub_eval(y1, z1, cx2, s2, keys);
    sub_eval(x1, z1, cy2, s2, keys);
    sub_eval(x1, y1, cz2, s2, keys);
    plain_eval(x1, y1, z1, s2, keys);
    gmp_printf("S2 outputs: %Zd\n\n", s2->c);

    //dec
    printf("Starting decoding\n");
    prs_plaintext_t dec_res;
    prs_plaintext_init(dec_res);
    prs_ciphertext_t res;
    prs_ciphertext_init(res);
    mpz_mul(res->c, s1->c, s2->c);
    mpz_mod(res->c, res->c, keys->n);
    prs_decrypt(dec_res, keys, res);
    gmp_printf("Original Plaintext: %Zd\n\n", plain_res);
    gmp_printf("Result from Dec: %Zd\n\n", dec_res->m);
    assert(mpz_cmp(plain_res, dec_res->m) == 0);

    printf("All done!!\n");
    //prs_plaintext_clear(plaintext);
    //prs_plaintext_clear(dec_plaintext);
    //prs_ciphertext_clear(ciphertext);
    gmp_randclear(prng);

    return 0;
}
