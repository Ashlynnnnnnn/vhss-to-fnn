#include <stdint.h>
#include <../prf/acef.h>
#include <lib-2k-prs.h>
#include <../demo.h>

uint8_t* get_delta(uint8_t* key, mpz_t input)
{
    uint8_t* delta = (uint8_t*)malloc(sizeof(uint8_t) * SEC_PARAM);
    uint8_t* hash_msg = (uint8_t*)malloc(sizeof(uint8_t) * HASH_LEN);
    size_t input_size;
    size_t byte_count = (mpz_sizeinbase(input, 2) + 7) / 8;
    uint8_t* input_bytes = (uint8_t*)malloc(sizeof(uint8_t) * byte_count);
    mpz_export(input_bytes, &input_size, 1, sizeof(uint8_t), 0, 0, input);

    hmac(hash_msg, input_bytes, input_size, key);
    expand(delta, hash_msg, SEC_PARAM);

    free(hash_msg);
    free(input_bytes);
    return delta;
}

void prob_gen(uint8_t* delta, uint8_t* k1_byte, uint8_t* k2_byte, mpz_t sigma, mpz_t alpha, mpz_t g, mpz_t n_prime, mpz_t r, mpz_t c)
{
    f(delta, 1, k1_byte, k2_byte, r, g, n_prime);
    mpz_powm(sigma, c, alpha, N);
    mpz_mul(sigma, sigma, r);
    mpz_mod(sigma, sigma, N);

    return;
}

void verify(mpz_t c, mpz_t sigma, mpz_t r, mpz_t alpha, mpz_t a, mpz_t y, prs_ciphertext_t ct)
{
    mpz_t temp1, temp2, alpha_prime;
    mpz_inits(temp1, temp2, alpha_prime, NULL);

    mpz_powm(temp1, c, alpha, N);
    mpz_powm(temp2, r, a, N);
    mpz_mul(temp1, temp1, temp2);
    mpz_mod(temp1, temp1, N);

    mpz_sub_ui(alpha_prime, alpha, 1);
    mpz_powm(temp2, ct->c, alpha_prime, N);
    mpz_invert(temp2, temp2, N);
    //gmp_printf("temp2: %Zd\n", temp2);
    mpz_mul(temp1, temp1, temp2);
    mpz_mod(temp1, temp1, N);

    if(mpz_cmp(temp1, sigma) == 0)
    {
        //gmp_printf("Verification value: %Zd\n\n", sigma);
        //printf("passes verification!\n\n");
    }
    else
    {
        printf("doesn't pass verification!\n\n");
    }

    mpz_clears(temp1, temp2, alpha_prime, NULL);
    return;
}