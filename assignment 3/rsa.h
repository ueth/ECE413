#include <gmp.h>

/*
 * Generate a random prime number
 */
int generate_random_prime();

/*
 * Calculate and set e  and d.
 */
void calculate_e_d(mpz_t e, mpz_t lambda_n, mpz_t d);

/*
 * Calculate and export public-private keys in 
 * different txt files based on user's input. 
 */
void export_rsa_keys(long a, long b);

/*
 * Handle opt input
 */
void input_control(int argc, char *argv[]);

/*
 * Print Help Message.
 */
void rsa_print_help();

/*
 * Encrypt Message
 * arg0: Input path
 * arg1: Output path
 * arg2: Key path
 */
extern void encrypt(char *input_path, char *output_path, char *key_path);

/*
 * Decrypt Message
 * arg0: Input path
 * arg1: Output path
 * arg2: Key path
 */
void decrypt(char *input_path, char *output_path, char *key_path);