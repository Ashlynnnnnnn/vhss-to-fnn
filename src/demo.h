#ifndef DEMO_H
#define DEMO_H

#include <lib-mesg.h>
#include <lib-misc.h>
#include <lib-2k-prs.h>
#include <gmp.h>

#define prng_sec_level 128
#define DEFAULT_MOD_BITS 384
#define item_number 2
#define server_number 2

void share(prs_plaintext_t input, prs_keys_t *keys, prs_ciphertext_t enc_s[], prs_plaintext_t ss[]);
void evaluate(prs_ciphertext_t s, prs_keys_t *keys, int index);
void decode(prs_ciphertext_t s[], prs_keys_t *keys, prs_plaintext_t dec_res);

extern gmp_randstate_t prng;
extern int current[server_number], remaining_degree, degree[item_number], coefficient[item_number];
extern mpz_t eval_parts[server_number], comp[server_number], added_value, times;

int demo_main(int argc, char *argv[]);

#endif