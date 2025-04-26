#ifndef DEMO_H
#define DEMO_H

#include <lib-mesg.h>
#include <lib-misc.h>
#include <lib-2k-prs.h>
#include <gmp.h>

#define prng_sec_level 128
#define DEFAULT_MOD_BITS 384
#define MESSAGE_BITS 96
#define item_number 2
#define server_number 2

void share(prs_plaintext_t input, mpz_t y, prs_ciphertext_t enc_s[], prs_plaintext_t ss[]);
void evaluate(prs_ciphertext_t s, mpz_t input, prs_ciphertext_t ct);
void decode(prs_ciphertext_t s[], mpz_t p, mpz_t *d, prs_plaintext_t dec_res);

extern gmp_randstate_t prng;
extern mpz_t eval_parts[server_number], N, k_2, co_1, co_2;

int demo_main(int argc, char *argv[]);

#endif