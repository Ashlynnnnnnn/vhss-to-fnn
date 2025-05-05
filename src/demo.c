#include "demo.h"
#include <lib-mesg.h>
#include <lib-misc.h>
#include <lib-2k-prs.h>
#include <lib-timing.h>
#include <gmp.h>
#include <stdio.h>
#include <string.h>

#define prng_sec_level 128
#define DEFAULT_MOD_BITS 256
#define BENCHMARK_ITERATIONS 10
#define MESSAGE_BITS 64

#define item_number 2
#define server_number 2

#define sampling_time 4 /* secondi */
#define max_samples (sampling_time * 50)

int degree[item_number], coefficient[item_number];

gmp_randstate_t prng;

mpz_t eval_parts[server_number], N, k_2, co_1, co_2;

void combination(mpz_t result, int x, int y)
{
    mpz_t temp, temp_y, temp_i, comb;
    mpz_init_set_ui(comb, 1);
    mpz_init(temp);
    mpz_init_set_ui(temp_y, y);
    mpz_init(temp_i);

    for (int i = 1; i <= x; i++)
    {
        mpz_set_ui(temp_i, i);
        mpz_sub_ui(temp, temp_y, x - i);
        mpz_mul(comb, comb, temp);
        mpz_divexact(comb, comb, temp_i);
    }

    mpz_mul(result, result, comb);

    mpz_clear(temp);
    mpz_clear(temp_y);
    mpz_clear(temp_i);
    mpz_clear(comb);
}

void get_outcome(prs_plaintext_t input, prs_keys_t *keys, mpz_t res){
    mpz_t expp, temp;
    mpz_init(expp), mpz_init(temp);
    for(int i=0;i<item_number;i++){
        mpz_set_ui(expp, degree[i]);
        mpz_powm(temp, input->m, expp, keys[0]->k_2);
        mpz_mul_ui(temp, temp, coefficient[i]);
        mpz_add(res, res, temp);
        mpz_mod(res, res, keys[0]->k_2);
    }
    if (mpz_cmp_si(res, 20000) > 0){
        mpz_sub(res, res, keys[0]->k_2);
    }
        mpz_clear(expp);
}

elapsed_time_t time_get_outcome(prs_plaintext_t input, prs_keys_t *keys, mpz_t res)
{
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        get_outcome(input, keys, res);
    });
    return time;
}

void random_split(prs_plaintext_t input, prs_plaintext_t parts[], mpz_t k_2)
{
    mpz_t sum_of_parts;
    mpz_init(sum_of_parts);
    mpz_set_ui(sum_of_parts, 0);
    //gettimeofday(&start, NULL);
    for(int i=0;i<server_number-1;i++){
        mpz_urandomm(parts[i]->m, prng, input->m);
        mpz_add(sum_of_parts, sum_of_parts, parts[i]->m);
    }
    mpz_sub(parts[server_number-1]->m, input->m, sum_of_parts);
    for(int i=0;i<server_number;i++){
        mpz_mod(parts[i]->m, parts[i]->m, k_2);
        //gmp_printf("Part %d of %Zd is %Zd\n", i, input, parts[i]);
    }
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);
    mpz_clear(sum_of_parts);
}

void share(prs_plaintext_t input, mpz_t y, prs_ciphertext_t enc_s[], prs_plaintext_t ss[])
{
    random_split(input, ss, k_2);
    //gettimeofday(&start, NULL);
    for (int j = 0; j < server_number; j++)
    {
        prs_encrypt(enc_s[j], MESSAGE_BITS, y, N, k_2, ss[j], prng, 48);
    }
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);
}

elapsed_time_t time_share(prs_plaintext_t input, mpz_t y, prs_ciphertext_t enc_s[], prs_plaintext_t ss[])
{
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        share(input, y, enc_s, ss);
    });
    return time;
}

void evaluate(prs_ciphertext_t s, mpz_t input, prs_ciphertext_t ct)
{
    mpz_t temp;
    mpz_init(temp);

    mpz_powm(temp, input, co_1, N);
    mpz_mul(s->c, s->c, temp);
    mpz_mod(s->c, s->c, N);

    //gmp_printf("ct: %Zd\n", ct->c);
    mpz_mul(s->c, s->c, ct->c);
    mpz_mod(s->c, s->c, N);

    mpz_clear(temp);
    return;
}

elapsed_time_t time_evaluate(prs_ciphertext_t s, mpz_t input, prs_ciphertext_t ct)
{
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        evaluate(s, input, ct);
    });
    return time;
}

void decode(prs_ciphertext_t s[], mpz_t p, mpz_t *d, prs_plaintext_t dec_res)
{
    prs_ciphertext_t res;
    prs_ciphertext_init(res);
    mpz_set_ui(res->c, 1);

    //gettimeofday(&start, NULL);
    for(int i=0;i<server_number;i++){
        mpz_mul(res->c, res->c, s[i]->c);
        mpz_mod(res->c, res->c, N);
    }
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);
    prs_decrypt(dec_res, p, MESSAGE_BITS, d, res);
    prs_ciphertext_clear(res);
}

elapsed_time_t time_decode(prs_ciphertext_t s[], mpz_t p, mpz_t *d, prs_plaintext_t dec_res)
{
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        decode(s, p, d, dec_res);
    });
    return time;
}

#ifdef BUILD_AS_LIBRARY
int demo_main(int argc, char *argv[])
#else
int main(int argc, char *argv[])
#endif
{
    printf("Initializing PRNG...\n\n");
    gmp_randinit_default(prng);                // prng means its state & init
    gmp_randseed_os_rng(prng, prng_sec_level); // seed setting

    set_messaging_level(msg_very_verbose); // level of detail of input

    prs_keys_t *keys = (prs_keys_t *)malloc(sizeof(prs_keys_t));
    prs_plaintext_t input, ss[server_number];
    prs_ciphertext_t enc_share[server_number], s[server_number];
    prs_keys_init(keys);
    prs_plaintext_init(input);
    for (int j = 0; j < server_number; j++)
    {
        prs_plaintext_init(ss[j]);
        mpz_init(eval_parts[j]);
        prs_ciphertext_init(enc_share[j]);
    }
    degree[0] = 2, degree[1] = 1;
    coefficient[0] = 1, coefficient[1] = 100;
    for(int j=0;j<server_number;j++){
        prs_ciphertext_init(s[j]);
        mpz_set_ui(s[j]->c, 1);
    }
    prs_ciphertext_t ct;
    prs_ciphertext_init(ct);
    prs_plaintext_t pt;
    prs_plaintext_init(pt);
    printf("Launching demo with k=%d, n_bits=%d\n\n", DEFAULT_MOD_BITS / 4, DEFAULT_MOD_BITS);

    printf("Calibrating timing tools...\n\n");
    calibrate_clock_cycles_ratio();
    detect_clock_cycles_overhead();
    detect_timestamp_overhead();

    printf("Starting key generation\n");
    elapsed_time_t keygen_time; // no need to consider time of generating the PRNG (little value)
    perform_oneshot_clock_cycles_sampling(keygen_time, tu_millis, {
        prs_generate_keys(keys, MESSAGE_BITS, DEFAULT_MOD_BITS, prng);
    });
    printf_et("Key generation time elapsed: ", keygen_time, tu_millis, "\n");
    gmp_printf("p: %Zd\n", keys[0]->p);
    gmp_printf("q: %Zd\n", keys[0]->q);
    gmp_printf("n: %Zd\n", keys[0]->n);
    gmp_printf("y: %Zd\n", keys[0]->y);
    printf("k: %d\n", keys[0]->k);
    gmp_printf("2^k: %Zd\n\n", keys[0]->k_2);

    mpz_inits(N, k_2, NULL);
    mpz_set(N, keys[0]->n);
    mpz_set(k_2, keys[0]->k_2);

    // Direct computation
    //mpz_urandomb(input->m, prng, keys->k);
    mpz_set_si(input->m, 27);
    mpz_t plain_res;
    mpz_init(plain_res);
    elapsed_time_t direct_computation_time;
    direct_computation_time = time_get_outcome(input, keys, plain_res);

    // Sharing
    printf("Starting sharing\n");
    elapsed_time_t share_time;
    share_time = time_share(input, keys[0]->y, enc_share, ss);
    printf_et("Sharing time elapsed: ", share_time, tu_millis, "\n\n");

    //evaluation
    mpz_inits(co_1, co_2, NULL);
    elapsed_time_t eval_time[server_number];
    for(int i=0;i<server_number;i++){
        printf("S%d starts evaluation!\n", i+1);
        for (int j = 0; j < server_number; j++)
        {
            if (j != i)
            {
                mpz_set(eval_parts[j], ss[j]->m);
            }
        }
        mpz_set(eval_parts[i], enc_share[i]->c);
        mpz_powm_ui(co_2, eval_parts[1-i], 2, k_2);  // co_2 = eval_parts[1-i]^2 mod k_2
        mpz_mul_ui(co_1, eval_parts[1-i], 50);       // co_1 = 50 * eval_parts[1-i]
        mpz_add(co_2, co_2, co_1);                   // co_2 = co_2 + co_1
        mpz_mod(co_2, co_2, k_2);                    // co_2 = co_2 mod k_2
        mpz_set(co_1, eval_parts[1 - i]);
        mpz_add_ui(co_1, co_1, 50);
        mpz_mod(co_1, co_1, k_2);
        mpz_set(pt->m, co_2);
        prs_encrypt(ct, MESSAGE_BITS, keys[0]->y, N, k_2, pt, prng, 48);
        eval_time[i] = time_evaluate(s[i], eval_parts[i], ct);
        printf("S%d's ", i+1);
        printf_et("evaluation time elapsed: ", eval_time[i], tu_millis, "\n");
        gmp_printf("S%d outputs: %Zd\n\n", i+1, s[i]->c);
    }
    long total = 0;
    for(int i=0;i<server_number;i++){
        total += eval_time[i];
    }
    elapsed_time_t ave_eval_time = total / server_number;
    printf_et("Each server's evaluation time is approximately: ", ave_eval_time, tu_millis, "\n");

    //dec
    printf("Starting decoding\n");
    prs_plaintext_t dec_res;
    prs_plaintext_init(dec_res);
    elapsed_time_t decoding_time;
    decoding_time = time_decode(s, keys[0]->p, keys[0]->d, dec_res);
    if (mpz_cmp_si(dec_res->m, 20000) > 0)
    {
        mpz_sub(dec_res->m, dec_res->m, keys[0]->k_2);
    }
    printf_et("Decoding time elapsed: ", decoding_time, tu_millis, "\n");
    gmp_printf("Original Result: %Zd\n\n", plain_res);
    gmp_printf("Result from Dec: %Zd\n\n", dec_res->m);
    assert(mpz_cmp(plain_res, dec_res->m) == 0);
    printf_et("HSS time elapsed: ", keygen_time + share_time + ave_eval_time + decoding_time, tu_millis, "\n");
    printf_et("Direct computation time elapsed: ", direct_computation_time, tu_millis, "\n\n");

    printf("All done!!\n");
    prs_plaintext_clear(input);
    for (int j = 0; j < server_number; j++)
    {
        prs_plaintext_clear(ss[j]);
        mpz_clear(eval_parts[j]);
        prs_ciphertext_clear(enc_share[j]);
        prs_ciphertext_clear(s[j]);
    }
    prs_plaintext_clear(dec_res);
    prs_ciphertext_clear(ct);
    prs_plaintext_clear(pt);
    prs_keys_clear(keys);
    free(keys);
    gmp_randclear(prng);
    mpz_clears(plain_res, co_1, co_2, NULL);
    return 0;
}
