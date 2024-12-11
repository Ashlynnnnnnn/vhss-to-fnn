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

#define input_number 3
#define server_number 2

#define sampling_time 4 /* secondi */
#define max_samples (sampling_time * 50)

gmp_randstate_t prng;

void get_outcome(prs_plaintext_t input[], prs_keys_t keys, mpz_t res){
    mpz_mul(res, input[0]->m, input[1]->m);
    mpz_mod(res, res, keys->k_2);
    mpz_mul(res, res, input[2]->m);
    mpz_mod(res, res, keys->k_2);
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

void share(prs_plaintext_t input[],
           prs_keys_t keys, prs_ciphertext_t enc_x1, prs_ciphertext_t enc_y1, prs_ciphertext_t enc_z1,
           prs_ciphertext_t enc_x2, prs_ciphertext_t enc_y2, prs_ciphertext_t enc_z2,
           prs_plaintext_t ss[][server_number]){
    for(int i=0;i<input_number;i++){
        random_split(input[i], ss[i], keys);
    }
    prs_encrypt(enc_x1, keys, ss[0][0], prng, 512), prs_encrypt(enc_x2, keys, ss[0][1], prng, 512);
    prs_encrypt(enc_y1, keys, ss[1][0], prng, 512), prs_encrypt(enc_y2, keys, ss[1][1], prng, 512);
    prs_encrypt(enc_z1, keys, ss[2][0], prng, 512), prs_encrypt(enc_z2, keys, ss[2][1], prng, 512);
    gmp_printf("S1 gets: %Zd, %Zd, %Zd, %Zd, %Zd, %Zd\n", enc_x1->c, enc_y1->c, enc_z1->c, ss[0][1]->m, ss[1][1]->m, ss[2][1]->m);
    gmp_printf("S2 gets: %Zd, %Zd, %Zd, %Zd, %Zd, %Zd\n", ss[0][0]->m, ss[1][0]->m, ss[2][0]->m, enc_x2->c, enc_y2->c, enc_z2->c);
}

elapsed_time_t time_share(prs_plaintext_t input[],
                          prs_keys_t keys, prs_ciphertext_t enc_x1, prs_ciphertext_t enc_y1, prs_ciphertext_t enc_z1,
                          prs_ciphertext_t enc_x2, prs_ciphertext_t enc_y2, prs_ciphertext_t enc_z2,
                          prs_plaintext_t ss[][server_number])
{
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        share(input, keys, enc_x1, enc_y1, enc_z1, enc_x2, enc_y2, enc_z2, ss);
    });
    return time;
}

void sub_eval(mpz_t a, mpz_t b, mpz_t e, prs_ciphertext_t res, prs_keys_t kk){
    mpz_t t;
    mpz_init(t);

    mpz_mul(t ,a, b);
    mpz_mod(t, t, kk->k_2);

    mpz_powm(t, e, t, kk->n);

    mpz_mul(res->c, res->c, t);
    mpz_mod(res->c, res->c, kk->n);

    mpz_clear(t);
}

void plain_eval(mpz_t a, mpz_t b, mpz_t e, prs_ciphertext_t res, prs_keys_t kk){
    prs_plaintext_t t;
    prs_plaintext_init(t);

    mpz_mul(t->m, a, b);
    mpz_mod(t->m, t->m, kk->k_2);
    mpz_mul(t->m, t->m, e);
    mpz_mod(t->m, t->m, kk->k_2);

    prs_ciphertext_t ct;
    prs_ciphertext_init(ct);
    prs_encrypt(ct, kk, t, prng, 512);

    mpz_mul(res->c, res->c, ct->c);
    mpz_mod(res->c, res->c, kk->n);

    prs_plaintext_clear(t);
    prs_ciphertext_clear(ct);
}

void evaluate(mpz_t eval_parts[][server_number], prs_ciphertext_t s, prs_keys_t keys, int index){
    sub_eval(eval_parts[1][1-index], eval_parts[2][1-index], eval_parts[0][index], s, keys);
    sub_eval(eval_parts[0][1-index], eval_parts[2][1-index], eval_parts[1][index], s, keys);
    sub_eval(eval_parts[0][1-index], eval_parts[1][1-index], eval_parts[2][index], s, keys);
    plain_eval(eval_parts[0][1 - index], eval_parts[1][1 - index], eval_parts[2][1-index], s, keys);
}

elapsed_time_t time_evaluate(mpz_t eval_parts[][server_number], prs_ciphertext_t s, prs_keys_t keys, int index)
{
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        evaluate(eval_parts, s, keys, index);
    });
    return time;
}

void decode(prs_ciphertext_t s1, prs_ciphertext_t s2, prs_keys_t keys, prs_plaintext_t dec_res){
    prs_ciphertext_t res;
    prs_ciphertext_init(res);

    mpz_mul(res->c, s1->c, s2->c);
    mpz_mod(res->c, res->c, keys->n);
    prs_decrypt(dec_res, keys, res);

    prs_ciphertext_clear(res);
}

elapsed_time_t time_decode(prs_ciphertext_t s1, prs_ciphertext_t s2, prs_keys_t keys, prs_plaintext_t dec_res){
    elapsed_time_t time;
    perform_oneshot_clock_cycles_sampling(time, tu_millis, {
        decode(s1, s2, keys, dec_res);
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
    mpz_t eval_parts[input_number][server_number];
    for(int i=0;i<input_number;i++){
        prs_plaintext_init(input[i]);
        for(int j=0;j<server_number;j++){
            prs_plaintext_init(ss[i][j]);
            mpz_init(eval_parts[i][j]);
        }
    }
    prs_ciphertext_t cx1, cx2, cy1, cy2, cz1, cz2;
    prs_ciphertext_init(cx1), prs_ciphertext_init(cx2);
    prs_ciphertext_init(cy1), prs_ciphertext_init(cy2);
    prs_ciphertext_init(cz1), prs_ciphertext_init(cz2);

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
    share_time = time_share(input, keys, cx1, cy1, cz1, cx2, cy2, cz2, ss);
    printf_et("Sharing time elapsed: ", share_time, tu_millis, "\n\n");

    // S1's evaluation
    printf("S1 starts evaluation!\n");
    prs_ciphertext_t s1;
    prs_ciphertext_init(s1);
    mpz_set_ui(s1->c, 1);
    for(int i=0;i<input_number;i++){
        for(int j=0;j<server_number;j++){
            if(j != 0){
                mpz_set(eval_parts[i][j], ss[i][j]->m);
            }
        }
    }
    mpz_set(eval_parts[0][0], cx1->c);
    mpz_set(eval_parts[1][0], cy1->c);
    mpz_set(eval_parts[2][0], cz1->c);
    elapsed_time_t eval_time_1;
    eval_time_1 = time_evaluate(eval_parts, s1, keys, 0);
    printf_et("S1's evaluation time elapsed: ", eval_time_1, tu_millis, "\n");
    gmp_printf("S1 outputs: %Zd\n\n", s1->c);

    // S2's evaluation
    printf("S2 starts evaluation!\n");
    prs_ciphertext_t s2;
    prs_ciphertext_init(s2);
    mpz_set_ui(s2->c, 1);
    for (int i = 0; i < input_number; i++)
    {
        for (int j = 0; j < server_number; j++)
        {
            if (j != 1)
            {
                mpz_set(eval_parts[i][j], ss[i][j]->m);
            }
        }
    }
    mpz_set(eval_parts[0][1], cx2->c);
    mpz_set(eval_parts[1][1], cy2->c);
    mpz_set(eval_parts[2][1], cz2->c);
    elapsed_time_t eval_time_2;
    eval_time_2 = time_evaluate(eval_parts, s2, keys, 1);
    printf_et("S2's evaluation time elapsed: ", eval_time_2, tu_millis, "\n");
    gmp_printf("S2 outputs: %Zd\n\n", s2->c);

    //dec
    printf("Starting decoding\n");
    prs_plaintext_t dec_res;
    prs_plaintext_init(dec_res);
    elapsed_time_t decoding_time;
    decoding_time = time_decode(s1, s2, keys, dec_res);
    printf_et("Decoding time elapsed: ", decoding_time, tu_millis, "\n");
    gmp_printf("Original Result: %Zd\n\n", plain_res);
    gmp_printf("Result from Dec: %Zd\n\n", dec_res->m);
    assert(mpz_cmp(plain_res, dec_res->m) == 0);
    printf_et("HSS time elapsed: ", keygen_time + share_time + eval_time_1 + eval_time_2 + decoding_time, tu_millis, "\n");
    printf_et("Direct computation time elapsed: ", direct_computation_time, tu_millis, "\n\n");

    printf("All done!!\n");
    for(int i=0;i<input_number;i++){
        prs_plaintext_clear(input[i]);
        for(int j=0;j<server_number;j++){
            prs_plaintext_clear(ss[i][j]);
            mpz_clear(eval_parts[i][j]);
        }
    }
    prs_ciphertext_clear(cx1), prs_ciphertext_clear(cx2);
    prs_ciphertext_clear(cy1), prs_ciphertext_clear(cy2);
    prs_ciphertext_clear(cz1), prs_ciphertext_clear(cz2);
    prs_ciphertext_clear(s1), prs_ciphertext_clear(s2);
    prs_plaintext_clear(dec_res);
    gmp_randclear(prng);
    mpz_clear(plain_res);
    return 0;
}
