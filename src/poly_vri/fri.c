#include "fri.h"

void get_initial_poly_codeword(mpz_t *codeword, int *coefficient, int *degree, int size, mpz_t omega, int order)
{
    // 创建临时数组存储展开后的系数
    mpz_t *temp = (mpz_t*)malloc(order * sizeof(mpz_t));
    for(int i = 0; i < order; i++) {
        mpz_init(temp[i]);
        mpz_set_ui(temp[i], 0);
    }

    // 将系数放入对应的位置
    for(int i = 0; i < size; i++) {
        mpz_set_ui(temp[degree[i]], coefficient[i]);
    }

    // 计算FFT
    fft(codeword, temp, order, omega, 1);

    for(int i = 0; i < order; i++) {
        mpz_clear(temp[i]);
    }
    free(temp);
    return;
}

// FFT实现
void fft(mpz_t *output, mpz_t *input, int n, mpz_t omega, int direction)
{
    if(n == 1) {
        mpz_set(output[0], input[0]);
        return;
    }

    mpz_t *even = (mpz_t*)malloc(n/2 * sizeof(mpz_t));
    mpz_t *odd = (mpz_t*)malloc(n/2 * sizeof(mpz_t));
    for(int i = 0; i < n/2; i++) {
        mpz_init(even[i]);
        mpz_init(odd[i]);
    }

    for(int i = 0; i < n/2; i++) {
        mpz_set(even[i], input[2*i]);
        mpz_set(odd[i], input[2*i+1]);
    }

    mpz_t omega_squared;
    mpz_init(omega_squared);
    mpz_mul(omega_squared, omega, omega);

    fft(output, even, n/2, omega_squared, direction);
    fft(output + n/2, odd, n/2, omega_squared, direction);

    mpz_t current_omega, temp;
    mpz_init_set_ui(current_omega, 1);
    mpz_init(temp);

    for(int k = 0; k < n/2; k++) {
        mpz_mul(temp, current_omega, output[k + n/2]);
        mpz_t t;
        mpz_init_set(t, output[k]);
        mpz_add(output[k], t, temp);
        mpz_sub(output[k + n/2], t, temp);
        mpz_mul(current_omega, current_omega, omega);
        mpz_clear(t);
    }

    for(int i = 0; i < n/2; i++) {
        mpz_clear(even[i]);
        mpz_clear(odd[i]);
    }
    free(even);
    free(odd);
    mpz_clear(omega_squared);
    mpz_clear(current_omega);
    mpz_clear(temp);

    return;
}