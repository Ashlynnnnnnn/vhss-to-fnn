/*
 *  Copyright 2020 Di Franco Francesco <francescodifranco90@gmail.com>
 *
 *  This source code is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This source code is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef PRS_H
#define PRS_H

#include <lib-mesg.h>
#include <assert.h>
#include <gmp.h>
#include <stdio.h>
#include <strings.h>

#define PRS_MR_ITERATIONS 12

typedef enum { prs_public_key_type, prs_secret_key_type } prs_key_type_t;
struct prs_keys_struct {
    //prs_key_type_t type; // where to use
    unsigned int n_bits;
    unsigned int k;
    mpz_t n;
    mpz_t y;

    mpz_t k_2; // 2^k
    mpz_t p;
    mpz_t q;
    mpz_t *d; // fast decrption
};
typedef struct prs_keys_struct prs_keys_t[1]; // in pointer ...

struct prs_plaintext_struct {
    mpz_t m;
};
typedef struct prs_plaintext_struct prs_plaintext_t[1];

struct prs_ciphertext_struct {
    mpz_t c;
};
typedef struct prs_ciphertext_struct prs_ciphertext_t[1];

void prs_generate_keys(prs_keys_t *keys, unsigned int k, unsigned int n_bits, gmp_randstate_t prng);

void prs_keys_init(prs_keys_t *keys);
void prs_keys_clear(prs_keys_t *keys);
void prs_plaintext_init(prs_plaintext_t plaintext);
void prs_plaintext_clear(prs_plaintext_t plaintext);
void prs_ciphertext_init(prs_ciphertext_t ciphertext);
void prs_ciphertext_clear(prs_ciphertext_t ciphertext);

void prs_encrypt(prs_ciphertext_t ciphertext, prs_keys_t *keys, prs_plaintext_t plaintext, gmp_randstate_t prng, unsigned int base_size);

void prs_decrypt(prs_plaintext_t plaintext, prs_keys_t *keys, prs_ciphertext_t ciphertext);
#endif //PRS_H
