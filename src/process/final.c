#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdbool.h>
#include <gmp.h>
#include "../demo.h"
#include "../poly_vri/fri.h"
#include "../prf/acef.h"
#include "../poly_vri/vpoly.h"
#include <sys/time.h>

#define INITIAL_IMAGE_SIZE 784 // 28*28 pixels
#define MAX_LINE_LENGTH 4096
#define MAX_IMAGES 10000
#define WEIGHT1_ROWS 512
#define WEIGHT1_COLS 784
#define WEIGHT2_ROWS 512
#define WEIGHT2_COLS 512
#define WEIGHT3_COLS 512
#define WEIGHT3_ROWS 10

struct timeval start, end;
double total_time = 0.0;

// all mnist data is stored in this struct
typedef struct
{
    float (*data)[MAX_IMAGES]; // pointer to a two-dimensional array
    int (*temp)[MAX_IMAGES];
    int (*result_data)[MAX_IMAGES];
    int num_images;
    int image_size; // pixels per image
} MNISTData;

double get_time_elapsed(struct timeval start, struct timeval end)
{
    return ((end.tv_sec - start.tv_sec) * 1000000u + end.tv_usec - start.tv_usec) / 1.e6;
}

void skip_header(FILE *file)
{
    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), file))
    {
        if (line[0] != '#')
        {
            fseek(file, -strlen(line), SEEK_CUR); // Go back to the beginning of the line
            break;
        }
    }
}

MNISTData *read_mnist_images(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        printf("Error: Can't open the file %s\n", filename);
        return NULL;
    }

    MNISTData *mnist = (MNISTData *)malloc(sizeof(MNISTData));
    if (!mnist)
    {
        printf("Error: Memory allocation failure\n");
        fclose(file);
        return NULL;
    }

    mnist->image_size = INITIAL_IMAGE_SIZE; // 784 pixels
    mnist->num_images = 0;
    mnist->data = (float(*)[MAX_IMAGES])malloc(INITIAL_IMAGE_SIZE * MAX_IMAGES * sizeof(float));
    mnist->temp = (int(*)[MAX_IMAGES])malloc(INITIAL_IMAGE_SIZE * MAX_IMAGES * sizeof(int));
    mnist->result_data = (int(*)[MAX_IMAGES])malloc(INITIAL_IMAGE_SIZE * MAX_IMAGES * sizeof(int));
    if (!mnist->data)
    {
        printf("Error: Image data memory allocation failure\n");
        free(mnist);
        fclose(file);
        return NULL;
    }

    skip_header(file); // change the position of file pointer to the beginning of the image data

    char line[MAX_LINE_LENGTH]; // 4096
    int image_index = 0;
    char *token;

    while (fgets(line, sizeof(line), file) && image_index < MAX_IMAGES)
    {
        token = strtok(line, " \n");
        int pixel_index = 0;

        while (token != NULL && pixel_index < INITIAL_IMAGE_SIZE)
        {
            mnist->data[pixel_index][image_index] = atof(token);
            token = strtok(NULL, " \n");
            pixel_index++;
        }

        if (pixel_index == INITIAL_IMAGE_SIZE)
        {
            image_index++;
        }
    }

    mnist->num_images = image_index;
    fclose(file);

    // If the actual number of images is less than MAX_IMAGES, readjust the memory size
    if (mnist->num_images < MAX_IMAGES)
    {
        float(*temp)[MAX_IMAGES] = (float(*)[MAX_IMAGES])realloc(mnist->data,
                                                                 mnist->num_images * INITIAL_IMAGE_SIZE * sizeof(float));
        if (temp)
        {
            mnist->data = temp;
        }
    }

    return mnist;
}

void free_mnist_data(MNISTData *mnist)
{
    if (mnist)
    {
        free(mnist->data);
        free(mnist->result_data);
        free(mnist);
    }
}

void read_weight(const char *filename, int weight_rows, int weight_cols, float (*weight)[weight_cols], int weight_index)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        printf("Error: Can't open the file %s\n", filename);
        return;
    }

    char line[MAX_LINE_LENGTH];
    int row = 0, col = 0;
    int weight_found = 0;
    char weight_header[32];

    snprintf(weight_header, sizeof(weight_header), "Shape of weight %d:", weight_index);

    while (fgets(line, sizeof(line), file))
    {
        if (strstr(line, weight_header) != NULL)
        {
            weight_found = 1;
            fgets(line, sizeof(line), file); // Skip the next line
            continue;
        }

        if (weight_found)
        {
            char *token = strtok(line, " \n");
            while (token != NULL)
            {
                if (row < weight_rows && col < weight_cols)
                {
                    weight[row][col] = atof(token);
                    col++;
                    if (col == weight_cols)
                    {
                        col = 0;
                        row++;
                        break;
                    }
                }
                token = strtok(NULL, " \n");
            }
            if (row == weight_rows)
            {
                break;
            }
        }
    }

    fclose(file);
}

void read_bias(const char *filename, float *bias, int bias_size, int bias_index)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        printf("Error: Can't open the file %s\n", filename);
        return;
    }

    char line[MAX_LINE_LENGTH];
    int index = 0;
    int bias_found = 0;
    char bias_header[32];

    // Construct the weight identifier
    snprintf(bias_header, sizeof(bias_header), "Shape of bia %d:", bias_index);

    while (fgets(line, sizeof(line), file))
    {
        if (strstr(line, bias_header) != NULL)
        {
            bias_found = 1;
            fgets(line, sizeof(line), file); // Skip the next line
            continue;
        }

        if (bias_found)
        {
            char *token = strtok(line, " \n");
            while (token != NULL && index < bias_size)
            {
                bias[index] = atof(token);
                index++;
                token = strtok(NULL, " \n");
            }
            if (index == bias_size)
            {
                break;
            }
        }
    }

    fclose(file);
}

int *read_labels(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        printf("Error: Can't open the labels file %s\n", filename);
        return NULL;
    }

    char line[MAX_LINE_LENGTH];
    // skip
    fgets(line, sizeof(line), file);
    fgets(line, sizeof(line), file);
    fgets(line, sizeof(line), file);

    int *labels = (int *)malloc(MAX_IMAGES * sizeof(int));
    if (!labels)
    {
        fclose(file);
        return NULL;
    }

    int num_labels = 0;
    while (fgets(line, sizeof(line), file) && num_labels < MAX_IMAGES)
    {
        if (strlen(line) > 0)
        {
            labels[num_labels] = atoi(line);
            num_labels++;
        }
    }

    fclose(file);
    return labels;
}

void linear_split(MNISTData *original_data, MNISTData *share1, MNISTData *share2)
{
    srand(time(NULL));
    for (int i = 0; i < original_data->image_size; i++)
    {
        for (int j = 0; j < original_data->num_images; j++)
        {
            int enlarged_value = (int)roundf(original_data->data[i][j] * 100);
            gettimeofday(&start, NULL);
            share1->temp[i][j] = rand() % (2 * abs(enlarged_value) + 1) - abs(enlarged_value);
            share2->temp[i][j] = enlarged_value - share1->temp[i][j];
            gettimeofday(&end, NULL);
            total_time += get_time_elapsed(start, end);
        }
    }

    share1->image_size = original_data->image_size, share1->num_images = original_data->num_images;
    share2->image_size = original_data->image_size, share2->num_images = original_data->num_images;

    return;
}

void bia_split(float *bias, int bias_size, float *share1, float *share2)
{
    srand(time(NULL));
    for (int i = 0; i < bias_size; i++)
    {
        gettimeofday(&start, NULL);
        float random_factor = ((float)rand() / (float)RAND_MAX * 2 - 1);
        share1[i] = roundf((random_factor * bias[i]) * 10000) / 10000;
        share2[i] = roundf((bias[i] - share1[i]) * 10000) / 10000;
        gettimeofday(&end, NULL);
        total_time += get_time_elapsed(start, end);
    }

    return;
}

void linear_evaluate(MNISTData *input_data, int weight_rows, int weight_cols, float (*weight)[weight_cols], float *bias)
{
    for (int img = 0; img < input_data->num_images; img++)
    {
        for (int i = 0; i < weight_rows; i++)
        {
            input_data->result_data[i][img] = (int)roundf(bias[i] * 10000);
            for (int j = 0; j < weight_cols; j++)
            {
                input_data->result_data[i][img] += (int)roundf(weight[i][j] * 100) * input_data->temp[j][img];
            }
        }
    }
    input_data->image_size = weight_rows;
    return;
}

bool linear_veri(MNISTData *input_data, int weight_rows, int weight_cols, float (*weight)[weight_cols], float *bias)
{
    int r = 1;
    int *x = (int *)malloc(input_data->num_images * sizeof(int));
    int *true_output = (int *)malloc(weight_rows * sizeof(int));
    int *real_output = (int *)malloc(weight_rows * sizeof(int));

    if (!x || !true_output || !real_output)
    {
        printf("Memory allocation failed\n");
        free(x);
        free(true_output);
        free(real_output);
        return false;
    }

    x[0] = 1;
    for (int i = 1; i < input_data->num_images; i++)
    {
        x[i] = x[i - 1] * r;
    }

    for (int i = 0; i < weight_rows; i++)
    {
        true_output[i] = 0, real_output[i] = 0;
        //gettimeofday(&start, NULL);
        for (int k = 0; k < input_data->num_images; k++)
        {
            true_output[i] += (int)roundf(bias[i] * 10000) * x[k];
        }
        for (int k = 0; k < input_data->num_images; k++)
        {
            real_output[i] += input_data->result_data[i][k] * x[k];
        }
        //gettimeofday(&end, NULL);
        //total_time += get_time_elapsed(start, end);

        for (int k = 0; k < weight_cols; k++)
        {
            int temp = 0;
            //gettimeofday(&start, NULL);
            for (int j = 0; j < input_data->num_images; j++)
            {
                temp += (int)roundf(input_data->data[k][j] * 100) * x[j];
            }
            true_output[i] += (int)roundf(weight[i][k] * 100) * temp;
            //gettimeofday(&end, NULL);
            //total_time += get_time_elapsed(start, end);
        }
    }

    //gettimeofday(&start, NULL);
    for (int i = 0; i < weight_rows; i++)
    {
        if (true_output[i] != real_output[i])
        {
            printf("False at %d\n", i);
            printf("True: %d, Real: %d\n", true_output[i], real_output[i]);
            free(x);
            free(true_output);
            free(real_output);
            return false;
        }
    }
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);

    free(x);
    free(true_output);
    free(real_output);
    return true;
}

bool poly_veri(mpz_t input, mpz_t output, int *coefficient, int *degree)
{
    int initial_domain_length = 8;
    mpz_t field_modulus, omega;
    mpz_t *precode = (mpz_t *)malloc(initial_domain_length * sizeof(mpz_t));
    mpz_set_ui(field_modulus, 65537), mpz_set_ui(omega, 4096);


    mpz_clear(field_modulus), mpz_clear(omega);
    for (int i = 0; i < initial_domain_length; i++)
    {
        mpz_clear(precode[i]);
    }
    free(precode);
}

int process_rounded_val(float rounded_val, prs_keys_t *keys, uint8_t *k1, uint8_t *k2, mpz_t alpha)
{
    if (rounded_val == 0.0f || rounded_val == -0.0f)
    {
        return 0;
    }

    prs_plaintext_t input, ss[server_number];
    prs_ciphertext_t enc_share[server_number], s[server_number], sigma;
    prs_plaintext_init(input);
    for (int j = 0; j < server_number; j++)
    {
        prs_plaintext_init(ss[j]);
        mpz_init(eval_parts[j]);
        prs_ciphertext_init(enc_share[j]);
    }
    for (int j = 0; j < server_number; j++)
    {
        prs_ciphertext_init(s[j]);
        mpz_set_ui(s[j]->c, 1);
    }
    prs_ciphertext_init(sigma);
    prs_ciphertext_t ct;
    prs_ciphertext_init(ct);
    prs_plaintext_t pt;
    prs_plaintext_init(pt);
    mpz_t r, sigma_1, temp;
    mpz_inits(r, sigma_1, temp, NULL);

    mpz_set_si(input->m, (int)roundf(rounded_val * 100));

    // Sharing
    gettimeofday(&start, NULL);
    share(input, keys[0]->y, enc_share, ss);
    gettimeofday(&end, NULL);
    total_time += get_time_elapsed(start, end);

    // evaluation
    mpz_inits(co_1, co_2, NULL);
    for (int i = 0; i < server_number; i++)
    {
        for (int j = 0; j < server_number; j++)
        {
            if (j != i)
            {
                mpz_set(eval_parts[j], ss[j]->m);
            }
        }
        mpz_set(eval_parts[i], enc_share[i]->c);
        //gettimeofday(&start, NULL);
        uint8_t* delta = get_delta(k1, ss[i]->m);
        prob_gen(delta, k1, k2, sigma_1, alpha, keys[0]->g, keys[0]->n_prime, r, eval_parts[i]);
        //gettimeofday(&end, NULL);
        //total_time += get_time_elapsed(start, end);
        mpz_powm_ui(co_2, eval_parts[1 - i], 2, k_2); // co_2 = eval_parts[1-i]^2 mod k_2
        mpz_mul_ui(co_1, eval_parts[1 - i], 50);      // co_1 = 50 * eval_parts[1-i]
        mpz_add(co_2, co_2, co_1);                    // co_2 = co_2 + co_1
        mpz_mod(co_2, co_2, k_2);                     // co_2 = co_2 mod k_2
        mpz_set(co_1, eval_parts[1 - i]);
        mpz_add_ui(co_1, co_1, 50);
        mpz_mod(co_1, co_1, k_2);
        mpz_set(pt->m, co_2);
        prs_encrypt(ct, MESSAGE_BITS, keys[0]->y, N, k_2, pt, prng, 48);
        mpz_set_ui(sigma->c, 1);
        evaluate(s[i], eval_parts[i], ct);
        evaluate(sigma, sigma_1, ct);
        //gettimeofday(&start, NULL);
        verify(s[i]->c, sigma->c, r, alpha, co_1, keys[0]->y, ct);
        //gettimeofday(&end, NULL);
        //total_time += get_time_elapsed(start, end);
        free(delta);
    }

    // decode
    prs_plaintext_t dec_res;
    prs_plaintext_init(dec_res);
    gettimeofday(&start, NULL);
    decode(s, keys[0]->p, keys[0]->d, dec_res);
    gettimeofday(&end, NULL);
    total_time += get_time_elapsed(start, end);
    if (mpz_cmp_si(dec_res->m, 20000) > 0)
    {
        mpz_sub(dec_res->m, dec_res->m, keys[0]->k_2);
    }
    int result = (int)mpz_get_si(dec_res->m);

    prs_plaintext_clear(input);
    for (int j = 0; j < server_number; j++)
    {
        prs_plaintext_clear(ss[j]);
        mpz_clear(eval_parts[j]);
        prs_ciphertext_clear(enc_share[j]);
        prs_ciphertext_clear(s[j]);
    }
    prs_plaintext_clear(dec_res);
    mpz_clears(r, sigma_1, temp, NULL);
    prs_ciphertext_clear(sigma);
    prs_ciphertext_clear(ct);
    prs_plaintext_clear(pt);
    return result;
}

void get_phi(mpz_t p, mpz_t q, mpz_t phi){
    mpz_t p_1, q_1;
    mpz_inits(p_1, q_1, NULL);
    //gettimeofday(&start, NULL);
    mpz_sub_ui(p_1, p, 1);
    mpz_sub_ui(q_1, q, 1);
    mpz_mul(phi, p_1, q_1);
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);
    mpz_clears(p_1, q_1, NULL);
    return;
}

void get_random_star(mpz_t N, mpz_t alpha)
{
    mpz_t gcd;
    mpz_init(gcd);

    //gettimeofday(&start, NULL);
    do
    {
        mpz_urandomm(alpha, prng, N); // [0,N-1]
        mpz_add_ui(alpha, alpha, 1); // [1,N]
        mpz_gcd(gcd, alpha, N);
    } while (mpz_cmp_ui(gcd, 1) != 0);
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);

    mpz_clear(gcd);
    return;
}

int main()
{
    gmp_randinit_default(prng);                // prng means its state & init
    gmp_randseed_os_rng(prng, prng_sec_level); // seed setting

    set_messaging_level(msg_very_verbose); // level of detail of input
    prs_keys_t *keys = (prs_keys_t *)malloc(sizeof(prs_keys_t));
    prs_keys_init(keys);

    gettimeofday(&start, NULL);
    prs_generate_keys(keys, MESSAGE_BITS, DEFAULT_MOD_BITS, prng);
    gettimeofday(&end, NULL);
    total_time += get_time_elapsed(start, end);
    mpz_inits(N, k_2, NULL);
    mpz_set(N, keys[0]->n);
    mpz_set(k_2, keys[0]->k_2);

    mpz_t k1, k2;
    mpz_inits(k1, k2, NULL);
    //gettimeofday(&start, NULL);
    uint8_t* k1_bytes = generate_seed(prng, k1);
    uint8_t* k2_bytes = generate_seed(prng, k2);
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);

    mpz_t alpha, phi_N;
    mpz_inits(alpha, phi_N, NULL);
    //gettimeofday(&start, NULL);
    get_phi(keys[0]->p, keys[0]->q, phi_N);
    get_random_star(phi_N, alpha);
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);

    MNISTData *mnist = read_mnist_images("/home/ashlynsun/vhss-to-fnn/data/mnist_images.txt");
    if (!mnist)
    {
        printf("Failed to read MNIST data\n");
        return 1;
    }
    mnist->num_images = 1;

    float weight1[WEIGHT1_ROWS][WEIGHT1_COLS];
    float bia1[WEIGHT1_ROWS], bia1_1[WEIGHT1_ROWS], bia1_2[WEIGHT1_ROWS];
    read_weight("/home/ashlynsun/vhss-to-fnn/data/model_parameters.txt", WEIGHT1_ROWS, WEIGHT1_COLS, weight1, 1);
    read_bias("/home/ashlynsun/vhss-to-fnn/data/model_parameters.txt", bia1, WEIGHT1_ROWS, 1);

    float weight2[WEIGHT2_ROWS][WEIGHT2_COLS];
    float bia2[WEIGHT2_ROWS], bia2_1[WEIGHT2_ROWS], bia2_2[WEIGHT2_ROWS];
    read_weight("/home/ashlynsun/vhss-to-fnn/data/model_parameters.txt", WEIGHT2_ROWS, WEIGHT2_COLS, weight2, 2);
    read_bias("/home/ashlynsun/vhss-to-fnn/data/model_parameters.txt", bia2, WEIGHT2_ROWS, 2);

    float weight3[WEIGHT3_ROWS][WEIGHT3_COLS];
    float bia3[WEIGHT3_ROWS], bia3_1[WEIGHT3_ROWS], bia3_2[WEIGHT3_ROWS];
    read_weight("/home/ashlynsun/vhss-to-fnn/data/model_parameters.txt", WEIGHT3_ROWS, WEIGHT3_COLS, weight3, 3);
    read_bias("/home/ashlynsun/vhss-to-fnn/data/model_parameters.txt", bia3, WEIGHT3_ROWS, 3);

    MNISTData *linear_data_1 = (MNISTData *)malloc(sizeof(MNISTData));
    linear_data_1->image_size = INITIAL_IMAGE_SIZE; // 784 pixels
    linear_data_1->num_images = mnist->num_images;
    linear_data_1->data = (float(*)[MAX_IMAGES])malloc(MAX_IMAGES * INITIAL_IMAGE_SIZE * sizeof(float));
    linear_data_1->temp = (int(*)[MAX_IMAGES])malloc(MAX_IMAGES * INITIAL_IMAGE_SIZE * sizeof(int));
    linear_data_1->result_data = (int(*)[MAX_IMAGES])malloc(MAX_IMAGES * INITIAL_IMAGE_SIZE * sizeof(int));

    MNISTData *linear_data_2 = (MNISTData *)malloc(sizeof(MNISTData));
    linear_data_2->image_size = INITIAL_IMAGE_SIZE; // 784 pixels
    linear_data_2->num_images = mnist->num_images;
    linear_data_2->data = (float(*)[MAX_IMAGES])malloc(MAX_IMAGES * INITIAL_IMAGE_SIZE * sizeof(float));
    linear_data_2->temp = (int(*)[MAX_IMAGES])malloc(MAX_IMAGES * INITIAL_IMAGE_SIZE * sizeof(int));
    linear_data_2->result_data = (int(*)[MAX_IMAGES])malloc(MAX_IMAGES * INITIAL_IMAGE_SIZE * sizeof(int));

    //gettimeofday(&start, NULL);
    linear_split(mnist, linear_data_1, linear_data_2);
    bia_split(bia1, WEIGHT1_ROWS, bia1_1, bia1_2);
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);

    linear_evaluate(linear_data_1, WEIGHT1_ROWS, WEIGHT1_COLS, weight1, bia1_1);
    linear_evaluate(linear_data_2, WEIGHT1_ROWS, WEIGHT1_COLS, weight1, bia1_2);
    gettimeofday(&start, NULL);
    for (int img = 0; img < mnist->num_images; img++)
    {
        for (int i = 0; i < WEIGHT1_ROWS; i++)
        {
            mnist->result_data[i][img] = linear_data_1->result_data[i][img] + linear_data_2->result_data[i][img];
        }
    }
    gettimeofday(&end, NULL);
    total_time += get_time_elapsed(start, end);
    if (!linear_veri(mnist, WEIGHT1_ROWS, WEIGHT1_COLS, weight1, bia1))
    {
        printf("Verification of first linear calculation failed\n");
        return 1;
    }
    printf("Verification of first linear calculation passed\n\n");
    mnist->image_size = WEIGHT1_ROWS;
    for (int i = 0; i < mnist->image_size; i++)
    {
        for (int j = 0; j < mnist->num_images; j++)
        {
            printf("First: i = %d, j = %d\n\n", i, j);
            gettimeofday(&start, NULL);
            mnist->data[i][j] = (float)(mnist->result_data[i][j]) / 10000.0f;
            float rounded_val = roundf(mnist->data[i][j] * 100) / 100; // Retain 2 decimals
            gettimeofday(&end, NULL);
            total_time += get_time_elapsed(start, end);
            int processed_val = process_rounded_val(rounded_val, keys, k1_bytes, k2_bytes, alpha);
            gettimeofday(&start, NULL);
            if (processed_val == 0) {
                mnist->data[i][j] = 0.0f;
            } else {
                mnist->data[i][j] = (float)processed_val / 10000.0f;
            }
            mnist->data[i][j] = roundf(mnist->data[i][j] * 100) / 100;
            gettimeofday(&end, NULL);
            total_time += get_time_elapsed(start, end);
        }
    }

    //gettimeofday(&start, NULL);
    linear_split(mnist, linear_data_1, linear_data_2);
    bia_split(bia2, WEIGHT2_ROWS, bia2_1, bia2_2);
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);

    linear_evaluate(linear_data_1, WEIGHT2_ROWS, WEIGHT2_COLS, weight2, bia2_1);
    linear_evaluate(linear_data_2, WEIGHT2_ROWS, WEIGHT2_COLS, weight2, bia2_2);
    gettimeofday(&start, NULL);
    for (int img = 0; img < mnist->num_images; img++)
    {
        for (int i = 0; i < WEIGHT2_ROWS; i++)
        {
            mnist->result_data[i][img] = linear_data_1->result_data[i][img] + linear_data_2->result_data[i][img];
        }
    }
    gettimeofday(&end, NULL);
    total_time += get_time_elapsed(start, end);

    if (!linear_veri(mnist, WEIGHT2_ROWS, WEIGHT2_COLS, weight2, bia2))
    {
        printf("Verification of second linear calculation failed\n");
        return 1;
    }
    printf("Verification of second linear calculation passed\n\n");
    mnist->image_size = WEIGHT2_ROWS;
    for (int i = 0; i < mnist->image_size; i++)
    {
        for (int j = 0; j < mnist->num_images; j++)
        {
            printf("Second: i = %d, j = %d\n\n", i, j);
            gettimeofday(&start, NULL);
            mnist->data[i][j] = (float)(mnist->result_data[i][j]) / 10000.0f;
            float rounded_val = roundf(mnist->data[i][j] * 100) / 100; // Retain 2 decimals
            gettimeofday(&end, NULL);
            total_time += get_time_elapsed(start, end);
            int processed_val = process_rounded_val(rounded_val, keys, k1_bytes, k2_bytes, alpha);
            gettimeofday(&start, NULL);
            if (processed_val == 0)
            {
                mnist->data[i][j] = 0.0f;
            }
            else
            {
                mnist->data[i][j] = (float)processed_val / 10000.0f;
            }
            mnist->data[i][j] = roundf(mnist->data[i][j] * 100) / 100;
            gettimeofday(&end, NULL);
            total_time += get_time_elapsed(start, end);
        }
    }

    //gettimeofday(&start, NULL);
    linear_split(mnist, linear_data_1, linear_data_2);
    bia_split(bia3, WEIGHT3_ROWS, bia3_1, bia3_2);
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);

    linear_evaluate(linear_data_1, WEIGHT3_ROWS, WEIGHT3_COLS, weight3, bia3_1);
    linear_evaluate(linear_data_2, WEIGHT3_ROWS, WEIGHT3_COLS, weight3, bia3_2);
    gettimeofday(&start, NULL);
    for (int img = 0; img < mnist->num_images; img++)
    {
        for (int i = 0; i < WEIGHT3_ROWS; i++)
        {
            mnist->result_data[i][img] = linear_data_1->result_data[i][img] + linear_data_2->result_data[i][img];
        }
    }
    gettimeofday(&end, NULL);
    total_time += get_time_elapsed(start, end);
    if (!linear_veri(mnist, WEIGHT3_ROWS, WEIGHT3_COLS, weight3, bia3))
    {
        printf("Verification of third linear calculation failed\n");
        return 1;
    }
    printf("Verification of third linear calculation passed\n\n");
    mnist->image_size = WEIGHT3_ROWS;
    for (int i = 0; i < mnist->image_size; i++)
    {
        for (int j = 0; j < mnist->num_images; j++)
        {
            mnist->data[i][j] = (float)(mnist->result_data[i][j]) / 10000.0f;
        }
    }

    int *true_labels = read_labels("/home/ashlynsun/vhss-to-fnn/data/mnist_labels.txt");
    if (!true_labels)
    {
        printf("Failed to read true labels\n");
        free_mnist_data(mnist);
        return 1;
    }
    int *predicted_labels = read_labels("/home/ashlynsun/vhss-to-fnn/data/predicted_labels.txt");
    if (!predicted_labels)
    {
        printf("Failed to read predicted labels\n");
        free_mnist_data(mnist);
        free(true_labels);
        return 1;
    }

    int correct_predictions = 0;
    int aligned_predictions = 0;

    for (int img = 0; img < mnist->num_images; img++)
    {
        float max_val = mnist->data[0][img];
        int max_idx = 0;

        for (int i = 1; i < 10; i++)
        {
            if (mnist->data[i][img] > max_val)
            {
                max_val = mnist->data[i][img];
                max_idx = i;
            }
        }

        if (max_idx == true_labels[img])
        {
            correct_predictions++;
        }
        if (max_idx == predicted_labels[img])
        {
            aligned_predictions++;
        }
    }

    printf("Total sample size: %d\n", mnist->num_images);
    printf("\nCompare with true labels:\n");
    printf("----------------------------------------\n");
    printf("Correct prediction: %d\n", correct_predictions);
    printf("Accuracy: %.2f%%\n", (float)correct_predictions / mnist->num_images * 100);
    printf("\nCompare with original predicted labels:\n");
    printf("----------------------------------------\n");
    printf("Aligned prediction: %d\n", aligned_predictions);
    printf("Rate: %.2f%%\n", (float)aligned_predictions / mnist->num_images * 100);
    printf("\nTotal time: %.3f ms\n", total_time * 1000);
    printf("Amortized time per image: %.3f ms\n", total_time * 1000 / mnist->num_images);

    // free memory
    free(true_labels);
    free(predicted_labels);
    free_mnist_data(mnist);
    free(k1_bytes);
    free(k2_bytes);
    gmp_randclear(prng);
    prs_keys_clear(keys);
    free(keys);
    mpz_clears(alpha, phi_N, k_2, N, k1, k2, NULL);
    return 0;
}