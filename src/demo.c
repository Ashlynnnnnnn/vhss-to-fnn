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

#define input_number 1
#define server_number 10

#define sampling_time 4 /* secondi */
#define max_samples (sampling_time * 50)

int current[server_number], remaining_degree;

gmp_randstate_t prng;

mpz_t eval_parts[input_number][server_number], comp[19], added_value, times;

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

void get_outcome(prs_plaintext_t input[], prs_keys_t keys, mpz_t res){
    mpz_t expp;
    mpz_init(expp);
    mpz_set_ui(expp, 19);
    mpz_powm(res, input[0]->m, expp, keys->k_2);
    mpz_clear(expp);
}

elapsed_time_t time_get_outcome(prs_plaintext_t input[], prs_keys_t keys, mpz_t res)
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

void share(prs_plaintext_t input[], prs_keys_t keys, prs_ciphertext_t enc_s[][server_number], prs_plaintext_t ss[][server_number]){
    for(int i=0;i<input_number;i++){
        random_split(input[i], ss[i], keys);
        for(int j=0;j<server_number;j++){
            prs_encrypt(enc_s[i][j], keys, ss[i][j], prng, 512);
        }
    }
}

elapsed_time_t time_share(prs_plaintext_t input[], prs_keys_t keys, prs_ciphertext_t enc_s[][server_number], prs_plaintext_t ss[][server_number])
{
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        share(input, keys, enc_s, ss);
    });
    return time;
}

void sub_eval(mpz_t component[], int len, mpz_t e, prs_ciphertext_t res, prs_keys_t kk){
    mpz_t t;
    mpz_init(t);
    mpz_set_ui(t, 1);

    for (int i = 0; i < len; i++)
    {
        mpz_mul(t, t, component[i]);
        mpz_mod(t, t, kk->k_2);
    }

    mpz_powm(t, e, t, kk->n);
    mpz_powm(t, t, times, kk->n);

    mpz_mul(res->c, res->c, t);
    mpz_mod(res->c, res->c, kk->n);

    mpz_clear(t);
}

void plain_eval(mpz_t component[], int len, prs_ciphertext_t res, prs_keys_t kk){
    prs_plaintext_t t;
    prs_plaintext_init(t);
    mpz_set_ui(t->m, 1);

    for(int i=0;i<len;i++){
        mpz_mul(t->m, t->m, component[i]);
        mpz_mod(t->m, t->m, kk->k_2);
    }

    prs_ciphertext_t ct;
    prs_ciphertext_init(ct);
    prs_encrypt(ct, kk, t, prng, 512);

    mpz_powm(ct->c, ct->c, times, kk->n);
    mpz_mul(res->c, res->c, ct->c);
    mpz_mod(res->c, res->c, kk->n);

    prs_plaintext_clear(t);
    prs_ciphertext_clear(ct);
}

void generateCombinations(int index, int pos, int currentSum, prs_keys_t keys, prs_ciphertext_t s)
{
    if (pos == index)
    {
        if (currentSum <= 19)
        {
            mpz_set_ui(times, 1), remaining_degree = 19;
            //printf("currentSum = %d\n", currentSum);
            for(int i=0;i<index;i++){
                mpz_powm_ui(comp[i], eval_parts[0][i], current[i], keys->k_2);
                combination(times, current[i], remaining_degree);
                remaining_degree -= current[i];
                //gmp_printf("current[%d] = %d, times=%Zd\n", i, current[i], times);
            }
            //gmp_printf("Final times=%Zd\n", times);
            if(index == server_number - 1 && currentSum == 19){
                //printf("Start plain_eval\n");
                plain_eval(comp, index, s, keys);
            }
            if(index != server_number-1){
                //printf("Start plain_eval\n");
                mpz_powm_ui(comp[index], added_value, 19 - currentSum, keys->k_2);
                plain_eval(comp, index + 1, s, keys);
            }
            if(currentSum < 19){
                //printf("Fullfil the first step of sub_eval\n");
                mpz_mul_ui(times, times, remaining_degree);
                //gmp_printf("Upgraded times=%Zd\n", times);
                if(index == server_number - 1 && currentSum == 18){
                    //printf("Start sub_eval\n");
                    sub_eval(comp, index, eval_parts[0][index], s, keys);
                }
                if(index != server_number-1){
                    //printf("Start sub_eval\n");
                    mpz_powm_ui(comp[index], added_value, 18 - currentSum, keys->k_2);
                    sub_eval(comp, index + 1, eval_parts[0][index], s, keys);
                }
            }
            //printf("------End of this case------\n\n");
        }
        return;
    }
    for (int i = 2; i <= 19; i++)
    {
        if (currentSum + i > 19)
        {
            continue;
        }
        current[pos] = i;
        generateCombinations(index, pos + 1, currentSum + i, keys, s);
    }
}

void evaluate(mpz_t eval_parts[][server_number], prs_ciphertext_t s, prs_keys_t keys, int index, prs_plaintext_t ss[][server_number], prs_ciphertext_t enc_share[][server_number]){
    for (int i = 0; i < input_number; i++)
    {
        for (int j = 0; j < server_number; j++)
        {
            if (j != index)
            {
                mpz_set(eval_parts[i][j], ss[i][j]->m);
            }
        }
    }
    for (int i = 0; i < input_number; i++)
    {
        mpz_set(eval_parts[i][index], enc_share[i][index]->c);
    }
    generateCombinations(index, 0, 0, keys, s);
    if(index != server_number-1){
        mpz_sub(added_value, added_value, eval_parts[0][index + 1]);
        mpz_mod(added_value, added_value, keys->k_2);
    }
}

elapsed_time_t time_evaluate(mpz_t eval_parts[][server_number], prs_ciphertext_t s, prs_keys_t keys, int index, prs_plaintext_t ss[][server_number], prs_ciphertext_t enc_share[][server_number])
{
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        evaluate(eval_parts, s, keys, index, ss, enc_share);
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
    prs_plaintext_t input[input_number], ss[input_number][server_number];
    prs_ciphertext_t enc_share[input_number][server_number], s[server_number];
    for(int i=0;i<input_number;i++){
        prs_plaintext_init(input[i]);
        for(int j=0;j<server_number;j++){
            prs_plaintext_init(ss[i][j]);
            mpz_init(eval_parts[i][j]);
            prs_ciphertext_init(enc_share[i][j]);
        }
    }
    for(int j=0;j<server_number;j++){
        prs_ciphertext_init(s[j]);
        mpz_set_ui(s[j]->c, 1);
    }
    for(int i=0;i<19;i++){
        mpz_init(comp[i]);
        mpz_set_ui(comp[i], 1);
    }
    mpz_init(added_value), mpz_init_set_ui(times, 1);
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
    for(int i=0;i<input_number;i++){
        mpz_urandomb(input[i]->m, prng, keys->k);
    }
    mpz_t plain_res;
    mpz_init(plain_res);
    elapsed_time_t direct_computation_time;
    direct_computation_time = time_get_outcome(input, keys, plain_res);

    // Sharing
    printf("Starting sharing\n");
    elapsed_time_t share_time;
    share_time = time_share(input, keys, enc_share, ss);
    printf_et("Sharing time elapsed: ", share_time, tu_millis, "\n\n");

    for (int i = 1; i < server_number; i++)
    {
        mpz_add(added_value, added_value, ss[0][i]->m);
    }
    mpz_mod(added_value, added_value, keys->k_2);

    //evaluation
    elapsed_time_t eval_time[server_number];
    for(int i=0;i<server_number;i++){
        printf("S%d starts evaluation!\n", i+1);
        eval_time[i] = time_evaluate(eval_parts, s[i], keys, i, ss, enc_share);
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
    for(int i=0;i<input_number;i++){
        prs_plaintext_clear(input[i]);
        for(int j=0;j<server_number;j++){
            prs_plaintext_clear(ss[i][j]);
            mpz_clear(eval_parts[i][j]);
            prs_ciphertext_clear(enc_share[i][j]);
        }
    }
    for(int j=0;j<server_number;j++){
        prs_ciphertext_clear(s[j]);
    }
    prs_plaintext_clear(dec_res);
    gmp_randclear(prng);
    mpz_clear(plain_res);
    return 0;
}
