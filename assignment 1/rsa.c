#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "rsa.h"

int main(int argc, char *argv[]){

    input_control(argc, argv);

    return 0;
}

void input_control(int argc, char *argv[]){
    int opt;
    long long int prime1, prime2;
    char *input_path, *output_path, *key_path;

    input_path = NULL;
    output_path = NULL;
    key_path = NULL;

    while((opt = getopt(argc, argv, "i:o:k:dehg")) != -1){
        switch(opt){
            case 'i':
                input_path = strdup(optarg);
                break;
            case 'o':
                output_path = strdup(optarg);
                break;
            case 'k':
                key_path = strdup(optarg);
                break;
            case 'g':
                export_rsa_keys(generate_random_prime(), generate_random_prime());
                break;
            case 'd':
                decrypt(input_path, output_path, key_path);
                break;
            case 'e':
                encrypt(input_path, output_path, key_path);
                break;
            case 'h':
                rsa_print_help();
                return;
            default:
                fprintf(stderr, "Fatal error.\n");
        }
    }
    free(input_path);
    free(output_path);
    free(key_path);
}

int generate_random_prime(){
    time_t t;
    int rnd;

    srand((unsigned) time(&t));

    rnd = rand() % 1000;

    sleep(1);

    for(int i=2; i<rnd; i++){
        if(rnd % i == 0 || rnd == 2){
            rnd = rand() % 1000;
            i = 2;
        }
    }
    return rnd;
}

void export_rsa_keys(long prime1, long prime2){
    mpz_t n, p, q, e, d, lambda_n, p1, q1;

    printf("Prime chosen for p: %ld\n", prime1);

    while(prime2 == prime1)
        prime2 = generate_random_prime();
    
    printf("Prime chosen for q: %ld\n", prime2);

    /*Initialise variables*/
    mpz_inits(n, p, q, lambda_n, p1, q1, e, d, NULL);

    mpz_set_ui (p, prime1);
    mpz_set_ui (q, prime2);

    if(mpz_probab_prime_p(p, 1000000) && mpz_probab_prime_p(q, 1000000)){
        /*starting with 2*/
        mpz_set_ui (e, 2);

        /*n = p * q*/
        mpz_mul(n, p, q);

        /*p1 = p -1 / q1 = q-1*/
        mpz_sub_ui(p1, p, 1);
        mpz_sub_ui(q1, q, 1);

        /*lambda_n = (p - 1)*(q - 1)*/
        mpz_mul(lambda_n, p1, q1);

        calculate_e_d(e, lambda_n, d);

        FILE *fp_private = fopen("private.key", "w");
        FILE *fp_public = fopen("public.key", "w");

        if(fp_private == NULL || fp_public == NULL){
            fprintf(stderr, "Null pointer file.");
            exit(1);
        }

        /*Exporting keys to the files*/
        mpz_out_str(fp_private, 0, n);
        fprintf(fp_private, " ");
        mpz_out_str(fp_private, 0, e);

        mpz_out_str(fp_public, 0, n);
        fprintf(fp_public, " ");
        mpz_out_str(fp_public, 0, d);

        fclose(fp_private);
        fclose(fp_public);

        /*Clear memory*/
        mpz_clears(n, p, q, lambda_n, p1, q1, e, d, NULL);
    }
    else{
        printf("p and q are not prime numbers.\n");
        exit(1);
    }
}

void encrypt(char *input_path, char *output_path, char *key_path){
    mpz_t input_ch, encrpted_ch, n, d;
    char ch, message[1000];
    size_t counter = 0, output[1], _one = 1;
    int n_num, d_num;

    mpz_inits(input_ch, encrpted_ch, n, d, NULL);

    FILE *input_file = fopen(input_path, "r");
    FILE *key_file = fopen(key_path, "r");
    FILE *output_file = fopen(output_path, "w");

    if(input_file == NULL || key_file == NULL || output_file == NULL){
        fprintf(stderr, "Null pointer file.");
        exit(1);
    }

    while (ch != EOF){
        ch = fgetc(input_file);
        if(ch != EOF)//avoid getting EOF in temp_str
            message[counter++] = ch;
    }

    /*Read keys*/
    fscanf(key_file, "%d", &n_num);
    fscanf(key_file, "%d", &d_num);

    mpz_set_ui(d, d_num);
    mpz_set_ui(n, n_num);

    for(size_t i=0; i<counter; i++){
        mpz_import(input_ch, 1, 1, sizeof(char), 0, 0, &message[i]);
        mpz_powm(encrpted_ch, input_ch, d, n);

        /*Each enctypted characher takes 8 bytes of space (size_t)*/
        mpz_export(output, &_one, 1, sizeof(size_t), 0, 0, encrpted_ch);
        fprintf(output_file, "%zu", output[0]);

        /*Separate each encrypted character with a space*/
        fwrite(" ", sizeof(char), sizeof(char), output_file);
    }

    mpz_clears(input_ch, encrpted_ch, n, d, NULL);

    fclose(input_file);
    fclose(key_file);
    fclose(output_file);
}

void decrypt(char *input_path, char *output_path, char *key_path){
    mpz_t decrypted, e, n, input_text;
    char export_ch;
    int encrypted_words[1000], n_num = 0, e_num = 0;
    size_t _one = 1, count = 1;

    mpz_inits(input_text, decrypted, e, n, NULL);

    FILE *input_file = fopen(input_path, "r");
    FILE *key_file = fopen(key_path, "r");
    FILE *output_file = fopen(output_path, "w");

    if(input_file == NULL || key_file == NULL || output_file == NULL){
        fprintf(stderr, "Null pointer file.");
        exit(1);
    }

    /*Read keys*/
    fscanf(key_file, "%d", &n_num);
    fscanf(key_file, "%d", &e_num);

    /*Adding keys into mpz_t*/
    mpz_set_ui(e, e_num);
    mpz_set_ui(n, n_num);
    
    /*Getting string from into encrypted_words*/
    fscanf(input_file, "%d", &encrypted_words[0]);

    while(!feof(input_file))
      fscanf(input_file, "%d", &encrypted_words[count++]);

    for(size_t i=0; i<(count-1); i++){
        /*Getting each char into mpz_t each iteration*/
        mpz_set_ui(input_text, encrypted_words[i]);
        mpz_powm(decrypted, input_text, e, n);

        /*Exporting 1 character (original space) each iteration*/
        mpz_export(&export_ch, &_one, 0, sizeof(char), 0, 0, decrypted);
        fprintf(output_file, "%c", export_ch);
    }

    mpz_clears(input_text, decrypted, e, n, NULL);

    fclose(input_file);
    fclose(key_file);
    fclose(output_file);
}

void calculate_e_d(mpz_t e, mpz_t lambda_n, mpz_t d){
    mpz_t mod, one, gcd;

    mpz_inits(one, mod, gcd, NULL);

    /*Creating mpz_t 1 constant*/
    mpz_set_ui(one, 1);

    while(mpz_cmp(lambda_n, e) > 0){
        /*e += 1*/
        mpz_add(e, e, one);

        /*temp_mod = e % lambda_n*/
        mpz_mod(mod, e, lambda_n);

        /*calculate gcd*/
        mpz_gcd(gcd, e, lambda_n);

        /*if (e is prime) and (e % lambda_n != 0) and (gcd of e and lambda_n is 1)*/
        if(mpz_probab_prime_p(e, 40) && (mpz_cmp_ui(mod, 0) != 0) && (mpz_cmp_ui(gcd, 1) == 0)){
            /*modular inverse of (e, lambda_n)*/
            mpz_invert(d, e, lambda_n);
            mpz_clears(one, mod, gcd, NULL);
            return;
        }
    }

    /*If program reaches here then e was not found*/
    fprintf(stderr, "e was not found\n");
    exit(1);
}

void rsa_print_help(){
    printf("-i\tpath\tPath to the input file.\n");
    printf("-o\tpath\tPath to the output file.\n");
    printf("-k\tpath\tPath to the key file.\n");
    printf("-g\t\tPerform RSA key-pair generation.\n");
    printf("-d\t\tDecrypt input and store results to output.\n");
    printf("-e\t\tEncrypt input and store results to output.\n");
    printf("-h\t\tHelp message.\n");
}