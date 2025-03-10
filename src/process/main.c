#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IMAGE_SIZE 784       // 28*28 pixels
#define MAX_LINE_LENGTH 4096
#define MAX_IMAGES 10000

// all mnist data is stored in this struct
typedef struct
{
    float *data;
    int num_images;
    int image_size; // pixels per image
} MNISTData;

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

// 函数：读取MNIST数据
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

    mnist->image_size = IMAGE_SIZE; // 784 pixels
    mnist->num_images = 0;
    mnist->data = (float *)malloc(MAX_IMAGES * IMAGE_SIZE * sizeof(float));
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

        while (token != NULL && pixel_index < IMAGE_SIZE)
        {
            mnist->data[image_index * IMAGE_SIZE + pixel_index] = atof(token);
            token = strtok(NULL, " \n");
            pixel_index++;
        }

        if (pixel_index == IMAGE_SIZE)
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
                                       mnist->num_images * IMAGE_SIZE * sizeof(float));
        if (temp)
        {
            mnist->data = temp;
        }
    }

    return mnist;
}

// 函数：释放MNIST数据内存
void free_mnist_data(MNISTData *mnist)
{
    if (mnist)
    {
        free(mnist->data);
        free(mnist);
    }
}

int main()
{
    MNISTData *mnist = read_mnist_images("/home/ashlynsun/vhss-to-fnn/data/mnist_images.txt");
    if (!mnist)
    {
        printf("Failed to read MNIST data\n");
        return 1;
    }

    // free memory
    free_mnist_data(mnist);
    return 0;
}