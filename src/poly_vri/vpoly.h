#ifndef VPOLY_H
#define VPOLY_H

#include <stdint.h>
#include <../prf/acef.h>
#include <lib-2k-prs.h>

uint8_t* get_delta(uint8_t *key, mpz_t input);
void prob_gen(uint8_t *delta, uint8_t *k1_byte, uint8_t *k2_byte, mpz_t sigma, mpz_t alpha, mpz_t g, mpz_t n_prime, mpz_t r, mpz_t c);
void verify(mpz_t c, mpz_t sigma, mpz_t r, mpz_t alpha, mpz_t a, mpz_t y, prs_ciphertext_t ct);

#endif