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

#define item_number 2
#define server_number 2

#define sampling_time 4 /* secondi */
#define max_samples (sampling_time * 50)

int current[server_number], remaining_degree, degree[item_number], coefficient[item_number];

gmp_randstate_t prng;

mpz_t eval_parts[server_number], comp[server_number], added_value, times, tmp;

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

void get_outcome(prs_plaintext_t input, prs_keys_t keys, mpz_t res){
    mpz_t expp, temp;
    mpz_init(expp), mpz_init(temp);
    for(int i=0;i<item_number;i++){
        mpz_set_ui(expp, degree[i]);
        mpz_powm(temp, input->m, expp, keys->k_2);
        mpz_mul_ui(temp, temp, coefficient[i]);
        mpz_add(res, res, temp);
        mpz_mod(res, res, keys->k_2);
    }
    mpz_clear(expp);
}

elapsed_time_t time_get_outcome(prs_plaintext_t input, prs_keys_t keys, mpz_t res)
{
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        get_outcome(input, keys, res);
    });
    return time;
}

void random_split(prs_plaintext_t input, prs_plaintext_t parts[], prs_keys_t keys)
{
    mpz_t sum_of_parts;
    mpz_init(sum_of_parts);
    mpz_set_ui(sum_of_parts, 0);
    for(int i=0;i<server_number-1;i++){
        mpz_urandomm(parts[i]->m, prng, input->m);
        mpz_add(sum_of_parts, sum_of_parts, parts[i]->m);
    }
    mpz_sub(parts[server_number-1]->m, input->m, sum_of_parts);
    for(int i=0;i<server_number;i++){
        mpz_mod(parts[i]->m, parts[i]->m, keys->k_2);
        //gmp_printf("Part %d of %Zd is %Zd\n", i, input, parts[i]);
    }
    mpz_clear(sum_of_parts);
}

void share(prs_plaintext_t input, prs_keys_t keys, prs_ciphertext_t enc_s[], prs_plaintext_t ss[]){
    random_split(input, ss, keys);
    for (int j = 0; j < server_number; j++)
    {
        prs_encrypt(enc_s[j], keys, ss[j], prng, 512);
    }
}

elapsed_time_t time_share(prs_plaintext_t input, prs_keys_t keys, prs_ciphertext_t enc_s[], prs_plaintext_t ss[])
{
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        share(input, keys, enc_s, ss);
    });
    return time;
}

void sub_eval(mpz_t component[], int len, mpz_t e, prs_ciphertext_t res, prs_keys_t kk, int item_index){
    mpz_t t;
    mpz_init(t);
    mpz_set_ui(t, 1);

    for (int i = 0; i < len; i++)
    {
        mpz_mul(t, t, component[i]);
        mpz_mod(t, t, kk->k_2);
    }

    mpz_mul_ui(t, t, coefficient[item_index]);
    mpz_mod(t, t, kk->k_2);

    mpz_powm(t, e, t, kk->n);
    mpz_powm(t, t, times, kk->n);

    mpz_mul(res->c, res->c, t);
    mpz_mod(res->c, res->c, kk->n);

    mpz_clear(t);
}

void plain_eval(mpz_t component[], int len, prs_ciphertext_t res, prs_keys_t kk, int item_index){
    prs_plaintext_t t;
    prs_plaintext_init(t);
    mpz_set_ui(t->m, 1);

    for(int i=0;i<len;i++){
        mpz_mul(t->m, t->m, component[i]);
        mpz_mod(t->m, t->m, kk->k_2);
    }

    mpz_mul_ui(t->m, t->m, coefficient[item_index]);
    mpz_mod(t->m, t->m, kk->k_2);

    prs_ciphertext_t ct;
    prs_ciphertext_init(ct);
    prs_encrypt(ct, kk, t, prng, 512);

    mpz_powm(ct->c, ct->c, times, kk->n);
    mpz_mul(res->c, res->c, ct->c);
    mpz_mod(res->c, res->c, kk->n);

    prs_plaintext_clear(t);
    prs_ciphertext_clear(ct);
}

void generateResult(int total_index, prs_keys_t keys, prs_ciphertext_t s, int item_index)
{
    mpz_set_ui(times, 1);
    for (int i = 0; i < server_number; i++)
    {
        mpz_set_ui(comp[i], 1);
    }
    remaining_degree = degree[item_index];
    for (int i = 0; i < total_index; i++)
    {
        mpz_powm_ui(comp[i], eval_parts[i], current[i], keys->k_2);
        combination(times, current[i], remaining_degree);
        remaining_degree -= current[i];
    }
    if (total_index == server_number - 1 && remaining_degree == 0)
    {
        // printf("Start plain_eval\n");
        plain_eval(comp, total_index, s, keys, item_index);
    }
    if (total_index != server_number - 1)
    {
        // printf("Start plain_eval\n");
        mpz_powm_ui(comp[total_index], added_value, remaining_degree, keys->k_2);
        plain_eval(comp, total_index + 1, s, keys, item_index);
    }
    if (remaining_degree > 0)
    {
        mpz_mul_ui(times, times, remaining_degree);
        if (total_index == server_number - 1 && remaining_degree == 1)
        {
            // printf("Start sub_eval\n");
            sub_eval(comp, total_index, eval_parts[total_index], s, keys, item_index);
        }
        if (total_index != server_number - 1)
        {
            // printf("Start sub_eval\n");
            mpz_powm_ui(comp[total_index], added_value, remaining_degree - 1, keys->k_2);
            sub_eval(comp, total_index + 1, eval_parts[total_index], s, keys, item_index);
        }
    }
    return;
}

void generateCombinations(int index, int pos, int currentSum, prs_keys_t keys, prs_ciphertext_t s, int item_index) // generate the combinations of first index servers
{
    if (pos == index)
    {
        if (currentSum <= degree[item_index])
        {
            //printf("currentSum = %d\n", currentSum);
            if (index == server_number - 1 && currentSum < degree[item_index] - 1)
            {
                return;
            }
            else
            {
                generateResult(index, keys, s, item_index);
            }
        }
        return;
    }
    for (int i = 2; i <= degree[item_index]; i++)
    {
        if (currentSum + i > degree[item_index])
        {
            continue;
        }
        current[pos] = i;
        generateCombinations(index, pos + 1, currentSum + i, keys, s, item_index);
    }
}

void evaluate(prs_ciphertext_t s, prs_keys_t keys, int index){
    for(int i=0;i<item_number;i++){
        generateCombinations(index, 0, 0, keys, s, i);
    }
}

elapsed_time_t time_evaluate(prs_ciphertext_t s, prs_keys_t keys, int index)
{
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        evaluate(s, keys, index);
    });
    return time;
}

void decode(prs_ciphertext_t s[], prs_keys_t keys, prs_plaintext_t dec_res){
    prs_ciphertext_t res;
    prs_ciphertext_init(res);
    mpz_set_ui(res->c, 1);

    for(int i=0;i<server_number;i++){
        mpz_mul(res->c, res->c, s[i]->c);
        mpz_mod(res->c, res->c, keys->n);
    }
    prs_decrypt(dec_res, keys, res);

    prs_ciphertext_clear(res);
}

elapsed_time_t time_decode(prs_ciphertext_t s[], prs_keys_t keys, prs_plaintext_t dec_res)
{
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        decode(s, keys, dec_res);
    });
    return time;
}

int main(int argc, char *argv[])
{
    printf("Initializing PRNG...\n\n");
    gmp_randinit_default(prng);                // prng means its state & init
    gmp_randseed_os_rng(prng, prng_sec_level); // seed setting

    set_messaging_level(msg_very_verbose); // level of detail of input

    prs_keys_t keys;
    prs_plaintext_t input, ss[server_number];
    prs_ciphertext_t enc_share[server_number], s[server_number];
    prs_plaintext_init(input);
    mpz_init(added_value);
    for (int j = 0; j < server_number; j++)
    {
        prs_plaintext_init(ss[j]);
        mpz_init(eval_parts[j]);
        prs_ciphertext_init(enc_share[j]);
    }
    degree[0] = 2, degree[1] = 1;
    coefficient[0] = 1, coefficient[1] = 1;
    for(int j=0;j<server_number;j++){
        prs_ciphertext_init(s[j]);
        mpz_set_ui(s[j]->c, 1);
    }
    for(int i=0;i<server_number;i++){
        mpz_init(comp[i]);
        mpz_set_ui(comp[i], 1);
    }
    mpz_init_set_ui(times, 1), mpz_init(tmp);
    printf("Launching demo with k=%d, n_bits=%d\n\n", DEFAULT_MOD_BITS / 4, DEFAULT_MOD_BITS);

    printf("Calibrating timing tools...\n\n");
    calibrate_clock_cycles_ratio();
    detect_clock_cycles_overhead();
    detect_timestamp_overhead();

    printf("Starting key generation\n");
    elapsed_time_t keygen_time; // no need to consider time of generating the PRNG (little value)
    perform_oneshot_clock_cycles_sampling(keygen_time, tu_millis, {
        prs_generate_keys(keys, DEFAULT_MOD_BITS / 4, DEFAULT_MOD_BITS, prng);
    });
    printf_et("Key generation time elapsed: ", keygen_time, tu_millis, "\n");
    gmp_printf("p: %Zd\n", keys->p);
    gmp_printf("q: %Zd\n", keys->q);
    gmp_printf("n: %Zd\n", keys->n);
    gmp_printf("y: %Zd\n", keys->y);
    printf("k: %d\n", keys->k);
    gmp_printf("2^k: %Zd\n\n", keys->k_2);

    // Direct computation
    //mpz_urandomb(input->m, prng, keys->k);
    mpz_set_si(input->m, -20);
    mpz_t plain_res;
    mpz_init(plain_res);
    elapsed_time_t direct_computation_time;
    direct_computation_time = time_get_outcome(input, keys, plain_res);

    // Sharing
    printf("Starting sharing\n");
    elapsed_time_t share_time;
    share_time = time_share(input, keys, enc_share, ss);
    printf_et("Sharing time elapsed: ", share_time, tu_millis, "\n\n");

    for (int j = 1; j < server_number; j++)
    {
        mpz_add(added_value, added_value, ss[j]->m);
    }
    mpz_mod(added_value, added_value, keys->k_2);

    //evaluation
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
        eval_time[i] = time_evaluate(s[i], keys, i);
        if (i != server_number - 1)
        {
            mpz_sub(added_value, added_value, eval_parts[i + 1]);
            mpz_mod(added_value, added_value, keys->k_2);
        }
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
    decoding_time = time_decode(s, keys, dec_res);
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
    gmp_randclear(prng);
    mpz_clear(plain_res);
    return 0;
}
