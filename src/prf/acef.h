#ifndef ACEF_H
#define ACEF_H

#include <stdint.h>
#include <gmp.h>
#include <relic/relic.h>

#define BLOCK_SIZE 64
#define HASH_LEN 32
#define SEC_PARAM 32

uint8_t *generate_seed(gmp_randstate_t prng, mpz_t seed);
void hmac(uint8_t *output, uint8_t *input, int input_size, uint8_t *key);
void expand(uint8_t *output, uint8_t *input, int byte_number);
void f(uint8_t* delta, int index, uint8_t* k1_byte, uint8_t* k2_byte, mpz_t output, mpz_t g, mpz_t n_prime);

#endif