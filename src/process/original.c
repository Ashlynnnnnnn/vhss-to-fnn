#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
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

// all mnist data is stored in this struct
typedef struct
{
    float *data;
    float *result_data;
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
    mnist->data = (float *)malloc(MAX_IMAGES * INITIAL_IMAGE_SIZE * sizeof(float));
    mnist->result_data = (float *)malloc(MAX_IMAGES * INITIAL_IMAGE_SIZE * sizeof(float));
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
            mnist->data[image_index * INITIAL_IMAGE_SIZE + pixel_index] = atof(token);
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
        float *temp = (float *)realloc(mnist->data,
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

float relu(float x)
{
    return (x > 0) ? x : 0;
}

int main()
{
    struct timeval start, end;
    double total_time = 0.0;

    MNISTData *mnist = read_mnist_images("/home/ashlynsun/vhss-to-fnn/data/mnist_images.txt");
    if (!mnist)
    {
        printf("Failed to read MNIST data\n");
        return 1;
    }
    mnist->num_images = 5000;

    float weight1[WEIGHT1_ROWS][WEIGHT1_COLS];
    float bia1[WEIGHT1_ROWS];
    read_weight("/home/ashlynsun/vhss-to-fnn/data/model_parameters.txt", WEIGHT1_ROWS, WEIGHT1_COLS, weight1, 1);
    read_bias("/home/ashlynsun/vhss-to-fnn/data/model_parameters.txt", bia1, WEIGHT1_ROWS, 1);

    float weight2[WEIGHT2_ROWS][WEIGHT2_COLS];
    float bia2[WEIGHT2_ROWS];
    read_weight("/home/ashlynsun/vhss-to-fnn/data/model_parameters.txt", WEIGHT2_ROWS, WEIGHT2_COLS, weight2, 2);
    read_bias("/home/ashlynsun/vhss-to-fnn/data/model_parameters.txt", bia2, WEIGHT2_ROWS, 2);

    float weight3[WEIGHT3_ROWS][WEIGHT3_COLS];
    float bia3[WEIGHT3_ROWS];
    read_weight("/home/ashlynsun/vhss-to-fnn/data/model_parameters.txt", WEIGHT3_ROWS, WEIGHT3_COLS, weight3, 3);
    read_bias("/home/ashlynsun/vhss-to-fnn/data/model_parameters.txt", bia3, WEIGHT3_ROWS, 3);

    gettimeofday(&start, NULL);
    for (int img = 0; img < mnist->num_images; img++)
    {
        for (int i = 0; i < WEIGHT1_ROWS; i++)
        {
            mnist->result_data[img * WEIGHT1_ROWS + i] = bia1[i];
            for (int j = 0; j < WEIGHT1_COLS; j++)
            {
                mnist->result_data[img * WEIGHT1_ROWS + i] += weight1[i][j] * mnist->data[img * INITIAL_IMAGE_SIZE + j];
            }
        }
    }
    mnist->image_size = 512;
    for (int dp = 0; dp < mnist->image_size * mnist->num_images; dp++)
    {
        mnist->data[dp] = mnist->result_data[dp];
        //float rounded_val = roundf(mnist->data[dp] * 100) / 100; // Retain 2 decimals
        mnist->data[dp] = relu(mnist->data[dp]);
        //mnist->data[dp] = roundf(mnist->data[dp] * 100) / 100;
    }

    for (int img = 0; img < mnist->num_images; img++)
    {
        for (int i = 0; i < WEIGHT2_ROWS; i++)
        {
            mnist->result_data[img * WEIGHT2_ROWS + i] = bia2[i];
            for (int j = 0; j < WEIGHT2_COLS; j++)
            {
                mnist->result_data[img * WEIGHT2_ROWS + i] += weight2[i][j] * mnist->data[img * WEIGHT1_ROWS + j];
            }
        }
    }
    for (int dp = 0; dp < mnist->image_size * mnist->num_images; dp++)
    {
        mnist->data[dp] = mnist->result_data[dp];
        //float rounded_val = roundf(mnist->data[dp] * 100) / 100;
        mnist->data[dp] = relu(mnist->data[dp]);
        //mnist->data[dp] = roundf(mnist->data[dp] * 100) / 100;
    }

    for (int img = 0; img < mnist->num_images; img++)
    {
        for (int i = 0; i < WEIGHT3_ROWS; i++)
        {
            mnist->result_data[img * WEIGHT3_ROWS + i] = bia3[i];
            for (int j = 0; j < WEIGHT3_COLS; j++)
            {
                mnist->result_data[img * WEIGHT3_ROWS + i] += weight3[i][j] * mnist->data[img * WEIGHT2_ROWS + j];
            }
        }
    }
    mnist->image_size = 10;
    for (int dp = 0; dp < mnist->image_size * mnist->num_images; dp++)
    {
        mnist->data[dp] = mnist->result_data[dp];
    }
    gettimeofday(&end, NULL);
    total_time += get_time_elapsed(start, end);

    printf("\nTotal time: %.3f ms\n", total_time * 1000);
    printf("Amortized time per image: %.3f ms\n", total_time * 1000 / mnist->num_images);

    // 释放内存
    free_mnist_data(mnist);
    return 0;
}