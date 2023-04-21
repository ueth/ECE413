/*
 * Print Help Message.
 */
void dh_print_help();

/*
 * Compute (x^y) mod p.
 */
long long int compute_key(long long int x, long long int y, long long int p);

/*
 * Export keys to the secified file path in the required format.
 * arg0: public key A
 * arg1: public key B
 * arg2: shared secret
 * arg3: export file path
 */
void export_keys(long long int a, long long int b, long long int c, char *filePath);

/*
 * Control input.
 */
void input_control(int argc, char *argv[]);