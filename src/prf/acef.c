#include <stdint.h>
#include <gmp.h>
#include <relic/relic.h>
#include <relic/relic_md.h>
#include <../demo.h>

#define BLOCK_SIZE 64
#define HASH_LEN 32
#define SEC_PARAM 32

uint8_t* generate_seed(gmp_randstate_t prng, mpz_t seed)
{
    //gettimeofday(&start, NULL);
    mpz_urandomb(seed, prng, BLOCK_SIZE * 8);
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);
    uint8_t *bytes = (uint8_t *)malloc(sizeof(uint8_t) * BLOCK_SIZE);
    size_t count;
    mpz_export(bytes, &count, 1, sizeof(uint8_t), 0, 0, seed);
    if (count < BLOCK_SIZE)
    {
        memmove(bytes + (BLOCK_SIZE - count), bytes, count);
        memset(bytes, 0, BLOCK_SIZE - count);
    }
    return bytes;
}

void concatenate(uint8_t *out, int size_out, uint8_t *in1, int size1, uint8_t *in2, int size2)
{
    for (int i = 0; i < size_out; ++i)
    {
        if (i < size1)
        {
            out[i] = in1[i];
        }
        else
        {
            out[i] = in2[i - size1];
        }
    }
    return;
}

void hmac(uint8_t *output, uint8_t *input, int input_size, uint8_t *key)
{
    //if (core_init() != RLC_OK)
    //
    //    return;
    //}
    uint8_t *k_o = malloc(sizeof(uint8_t) * BLOCK_SIZE);
    uint8_t *k_i = malloc(sizeof(uint8_t) * BLOCK_SIZE);
    uint8_t opad = (uint8_t)0x5c;
    uint8_t ipad = (uint8_t)0x36;

    //gettimeofday(&start, NULL);
    for (int i = 0; i < BLOCK_SIZE; ++i)
    {
        k_o[i] = key[i] ^ opad;
        k_i[i] = key[i] ^ ipad;
    }
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);

    uint8_t *inner_input = malloc(sizeof(uint8_t) * (input_size + BLOCK_SIZE));
    uint8_t *outer_input = malloc(sizeof(uint8_t) * (HASH_LEN + BLOCK_SIZE));
    //gettimeofday(&start, NULL);
    concatenate(inner_input, input_size + BLOCK_SIZE, k_i, BLOCK_SIZE, input, input_size);
    //core_init();
    md_map_sh256(output, inner_input, input_size + BLOCK_SIZE);
    //core_clean();
    concatenate(outer_input, HASH_LEN + BLOCK_SIZE, k_o, BLOCK_SIZE, output, HASH_LEN);
    //core_init();
    md_map_sh256(output, outer_input, HASH_LEN + BLOCK_SIZE);
    //core_clean();
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);

    free(k_o);
    free(k_i);
    return;
}

void expand(uint8_t *output, uint8_t *input, int byte_number)
{
    //gettimeofday(&start, NULL);
    int hash_num = byte_number / HASH_LEN;
    int over_byte = byte_number % HASH_LEN;
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);
    uint8_t *hashed_in = malloc(sizeof(uint8_t) * HASH_LEN);
    uint8_t *conc_in = malloc(sizeof(uint8_t) * (HASH_LEN + 1));

    for (int i = 0; i < HASH_LEN; ++i)
    {
        conc_in[i] = input[i];
    }
    for (int i = 0; i < hash_num; ++i)
    {
        conc_in[HASH_LEN] = (uint8_t)i;
        //gettimeofday(&start, NULL);
        md_map_sh256(hashed_in, conc_in, HASH_LEN + 1);
        //gettimeofday(&end, NULL);
        //total_time += get_time_elapsed(start, end);
        for (int j = 0; j < HASH_LEN; ++j)
        {
            output[i * HASH_LEN + j] = hashed_in[j];
        }
    }

    if (over_byte != 0)
    {
        conc_in[HASH_LEN] = (uint8_t)hash_num;

        //gettimeofday(&start, NULL);
        md_map_sh256(hashed_in, conc_in, HASH_LEN + 1);
        //gettimeofday(&end, NULL);
        //total_time += get_time_elapsed(start, end);

        for (int j = 0; j < over_byte; ++j)
        {
            output[hash_num * HASH_LEN + j] = hashed_in[j];
        }
    }

    free(hashed_in);
    free(conc_in);
    return;
}

void f_prime(uint8_t *key, uint8_t *input, int input_size, mpz_t output, mpz_t n_prime)
{
    uint8_t *hash_msg = (uint8_t*)malloc(sizeof(uint8_t) * HASH_LEN);
    hmac(hash_msg, input, input_size, key);

    size_t bit_size = mpz_sizeinbase(n_prime, 2); //p'q'
    int exp_len = bit_size + (int)(bit_size / 2);
    int byte_size = exp_len / 8 + 1 * (exp_len % 8 != 0);
    uint8_t *exp_msg = (uint8_t*)malloc(sizeof(uint8_t) * byte_size);
    expand(exp_msg, hash_msg, byte_size);
    mpz_import(output, byte_size, 1, sizeof(uint8_t), 0, 0, exp_msg);
    //gettimeofday(&start, NULL);
    mpz_mod(output, output, n_prime);
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);

    free(hash_msg);
    free(exp_msg);
    return;
}

void f(uint8_t* delta, int index, uint8_t* k1_byte, uint8_t* k2_byte, mpz_t output, mpz_t g, mpz_t n_prime)
{
    uint8_t* index_bytes = (uint8_t*)malloc(sizeof(uint8_t) * 1);
    index_bytes[0] = (uint8_t)index;
    mpz_t b, v, mul;
    mpz_inits(b, v, mul, NULL);

    f_prime(k1_byte, index_bytes, 1, v, n_prime);
    f_prime(k2_byte, delta, SEC_PARAM, b, n_prime);

    //gettimeofday(&start, NULL);
    mpz_mul(mul, b, v);
    mpz_mod(mul, mul, g);
    mpz_powm(output, g, mul, N);
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);

    free(index_bytes);
    mpz_clears(b, v, mul, NULL);
    return;
}