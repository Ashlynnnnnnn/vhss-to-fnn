/*
 *  Copyright 2020 Di Franco Francesco <francescodifranco90@gmail.com>
 *
 *  This source code is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This source code is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <lib-2k-prs.h>

void prs_keys_init(prs_keys_t *keys)
{
    (*keys)->n_bits = 0;
    (*keys)->k = 0;

    mpz_init((*keys)->n);
    mpz_init((*keys)->y);
    mpz_init((*keys)->k_2);
    mpz_init((*keys)->p);
    mpz_init((*keys)->q);
    mpz_init((*keys)->g);
    mpz_init((*keys)->n_prime);
    (*keys)->d = NULL;
}

void prs_keys_clear(prs_keys_t *keys)
{
    mpz_clear((*keys)->n);
    mpz_clear((*keys)->y);
    mpz_clear((*keys)->k_2);
    mpz_clear((*keys)->p);
    mpz_clear((*keys)->q);
    mpz_init((*keys)->g);
    mpz_clear((*keys)->n_prime);
    if ((*keys)->d != NULL)
    {
        free((*keys)->d);
    }
}

/**
 * Init plaintext struct
 * @param plaintext
 */
void prs_plaintext_init(prs_plaintext_t plaintext){
    assert(plaintext); // null?
    mpz_init(plaintext->m); // init to 0
}

/**
 * Clear plaintext struct
 * @param plaintext
 */
void prs_plaintext_clear(prs_plaintext_t plaintext){
    assert(plaintext);
    mpz_clear(plaintext->m);
}

/**
 * Init ciphertext struct
 * @param ciphertext
 */
void prs_ciphertext_init(prs_ciphertext_t ciphertext){
    assert(ciphertext);
    mpz_init(ciphertext->c);
}

/**
 * Clear ciphertext struct
 * @param ciphertext
 */
void prs_ciphertext_clear(prs_ciphertext_t ciphertext){
    assert(ciphertext);
    mpz_clear(ciphertext->c);
}

void find_generator(mpz_t result, mpz_t N, mpz_t n_prime, gmp_randstate_t prng, mpz_t k_2)
{
    mpz_t x, temp;
    mpz_inits(x, temp, NULL);

    do
    {
        // 随机选择 x
        mpz_urandomm(x, prng, N);

        // 计算 y = x^(2^k) mod N
        mpz_powm(result, x, k_2, N);
        //gmp_printf("生成元：%Zd\n", result);

        // 验证条件
        if (mpz_cmp_ui(result, 1) == 0)
            continue;

        mpz_powm(temp, result, n_prime, N);

        if (mpz_cmp_ui(temp, 1) != 0)
        {
            gmp_printf("警告：生成元验证失败\n");
            continue;
        }

        break;
    } while (1);

    mpz_clears(x, temp, NULL);
    return;
}

// 添加验证函数
void verify_generator(mpz_t g, mpz_t N, mpz_t p_prime, mpz_t q_prime) {
    mpz_t temp;
    mpz_init(temp);

    // 验证g^(p'q'/r)!=1，其中r是p'q'的任意素因子
    mpz_powm(temp, g, p_prime, N);
    if (mpz_cmp_ui(temp, 1) == 0) {
        gmp_printf("警告：生成元的阶不是p'q'\n");
    }
    mpz_powm(temp, g, q_prime, N);
    if (mpz_cmp_ui(temp, 1) == 0) {
        gmp_printf("警告：生成元的阶不是p'q'\n");
    }

    mpz_clear(temp);
    return;
}

/**
 * Generate keys: Given a security parameter κ, KeyGen defines an integer k ≥ 1, randomly generates
 * primes p and q such that p ≡ 1 ( mod 2 k ) , and sets N = pq. It also picks a random y ∈ J N \ QR N .
 * The public and private keys are pk = {N, y, k} and sk = {p}, respectively.
 * @param keys target keys struct where save keys
 * @param k message size in bit
 * @param n_bits modulus bit size
 * @param prng state for random number generator
 */

void prs_generate_keys(prs_keys_t *keys, unsigned int k, unsigned int n_bits, gmp_randstate_t prng){

    mpz_t tmp, p_m_1, p_m_1_k, d, p_prime, q_prime;
    unsigned int p_bits, q_bits, i;

    //pmesg(msg_verbose, "keys generation");

    assert(keys[0]);
    assert(n_bits > 1);

    p_bits = n_bits >> 1;

    keys[0]->n_bits = n_bits;

    mpz_inits(p_prime, q_prime, NULL);
    mpz_inits(tmp, p_m_1, p_m_1_k, d, NULL);

    keys[0]->k = k;
    // 2^k
    //gettimeofday(&start, NULL);
    mpz_ui_pow_ui(keys[0]->k_2, 2L, k);

    do {
        mpz_urandomb(keys[0]->p, prng, p_bits - k);
        mpz_mul_2exp(keys[0]->p, keys[0]->p, k);
        mpz_setbit(keys[0]->p, 0L);
        mpz_sub_ui(p_prime, keys[0]->p, 1);
        mpz_tdiv_q_2exp(p_prime, p_prime, k);
    } while (mpz_sizeinbase(keys[0]->p, 2) < p_bits || !mpz_probab_prime_p(keys[0]->p, PRS_MR_ITERATIONS) || !mpz_probab_prime_p(p_prime, PRS_MR_ITERATIONS));

    q_bits = mpz_sizeinbase(keys[0]->p, 2);
    /* pick random prime q*/
    do {
        mpz_urandomb(keys[0]->q, prng, q_bits - k);
        mpz_mul_2exp(keys[0]->q, keys[0]->q, k);
        mpz_setbit(keys[0]->q, 0L);
        mpz_sub_ui(q_prime, keys[0]->q, 1);
        mpz_tdiv_q_2exp(q_prime, q_prime, k);
    } while (mpz_sizeinbase(keys[0]->q, 2) < q_bits || !mpz_probab_prime_p(keys[0]->q, PRS_MR_ITERATIONS) || !mpz_probab_prime_p(q_prime, PRS_MR_ITERATIONS));

    /* n = p*q */
    mpz_mul(keys[0]->n, keys[0]->p, keys[0]->q);
    mpz_mul(keys[0]->n_prime, p_prime, q_prime);

    find_generator(keys[0]->g, keys[0]->n, keys[0]->n_prime, prng, keys[0]->k_2);
    //verify_generator(keys[0]->g, keys[0]->n, p_prime, q_prime);

    /**
     * J = { a € Zn: J(a/n) = 1 }
     * J(a/n) = J(a/p) * J(a/q) if n == p*q
     * QRn = { a € Zn: J(a/p) = J(a/q) = 1 }
     *
     * to pick a random y in Jn/QRn
     * J(y/N) == 1 => [J(y/p) = -1 && J(y/q) =-1]
     *
     * J(y/p) is +1 if and only if [y^((p-1)/2^k)) = 1 mod p] -1 otherwise
     *
     * */

    do {
        mpz_urandomb(keys[0]->y, prng, n_bits);
        mpz_gcd(tmp, keys[0]->y, keys[0]->n);
        if(mpz_cmp_ui(tmp, 1L) != 0){
            continue;
        }
    } while (mpz_jacobi(keys[0]->y, keys[0]->p) != -1 || mpz_jacobi(keys[0]->y, keys[0]->q) != -1);

    mpz_sub_ui(p_m_1, keys[0]->p, 1L);
    mpz_div_2exp(p_m_1_k, p_m_1, keys[0]->k);
    mpz_powm(d, keys[0]->y, p_m_1_k, keys[0]->p);
    mpz_invert(d, d, keys[0]->p);
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);

    keys[0]->d = malloc(sizeof(mpz_t) * (k - 1));
    mpz_init(keys[0]->d[0]);
    mpz_set(keys[0]->d[0], d);
    //gettimeofday(&start, NULL);
    for (i = 1; i < keys[0]->k - 1; i++)
    {
        mpz_init(keys[0]->d[i]);
        mpz_powm_ui(keys[0]->d[i], keys[0]->d[i - 1], 2L, keys[0]->p);
    }
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);
    mpz_clears(tmp, p_m_1, p_m_1_k, d, p_prime, q_prime, NULL);
}

/**
 * Encrypt ( pk, m ) Let M = {0, 1}^k .
 * Let M = {0, 1}^k . To encrypt a message m ∈ M (seen as an integer in {0, . . . , 2^k − 1})
 * Encrypt picks a random x ∈ Zn* and returns the ciphertext c = y^m * x^2^k mod N
 * @param ciphertext
 * @param keys
 * @param plaintext
 * @param prng
 */
void prs_encrypt(prs_ciphertext_t ciphertext, unsigned int k, mpz_t y, mpz_t n, mpz_t k_2, prs_plaintext_t plaintext, gmp_randstate_t prng, unsigned int base_size){
    mpz_t x, y_m;
    assert(base_size > 0);
    assert(base_size <= k);
    mpz_inits(x, y_m, NULL);
    mpz_urandomb(x, prng, base_size);
    mpz_powm(y_m, y, plaintext->m, n);
    mpz_powm(x, x,k_2, n);
    mpz_mul(ciphertext->c, x, y_m);
    mpz_mod(ciphertext->c, ciphertext->c, n);
}
/**
 * Decrypt(sk, c) Given c ∈ Zn* and the private key sk = {p}, the algorithm first computes
 * d = y ^ -( (p-1) / (2^k) ) mod p
 * and then recover plaintext m = ( m_k−1 , . . . , m_0 ) base 2
 *
 * m ← 0; B ← 1; D ← D
 * C ← c^((p−1)/(2 ^k)) mod p
 * for j = 1 to k − 1 do
 *    z ← C^(2^(k− j)) mod p
 *    if ( z , 1) then
 *      m ← m + B ; C ← C · D mod p
 *    B ← 2 B ; D ← D 2 mod p
 * end for
 * if ( C , 1) then m ← m + B
 * return m
 *
 * @param plaintext target plaintext
 * @param keys keys
 * @param ciphertext ciphertext to decrypt
 */

void prs_decrypt(prs_plaintext_t plaintext, mpz_t p, unsigned int k, mpz_t *d, prs_ciphertext_t ciphertext)
{
    int i=0;
    mpz_t m, c, b, z, p_m_1, p_m_1_k, k_j;
    mpz_inits(m, c, b, z, p_m_1, p_m_1_k, k_j, NULL);
    mpz_set_ui(m, 0);
    mpz_set_ui(b, 1L);
    //gettimeofday(&start, NULL);
    mpz_sub_ui(p_m_1, p, 1L);
    mpz_div_2exp(p_m_1_k, p_m_1, k);
    mpz_powm(c, ciphertext->c, p_m_1_k, p);
    for (i = 1; i < k; i++)
    {
        mpz_ui_pow_ui(k_j, 2L, (k) - i);
        mpz_powm(z, c, k_j,p);
        if(mpz_cmp_ui(z, 1) != 0){
            mpz_add(m, m, b);
            mpz_mul(c, c, d[i - 1]);
            mpz_mod(c, c, p);
        }
        mpz_mul_2exp(b, b, 1);
    }
    if(mpz_cmp_ui(c, 1L) != 0){
        mpz_add(m, m, b);
    }
    //gettimeofday(&end, NULL);
    //total_time += get_time_elapsed(start, end);
    mpz_set(plaintext->m, m);
    mpz_clears(m, c, b, z, p_m_1, p_m_1_k, k_j, NULL);
}
