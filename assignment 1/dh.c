#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <unistd.h>
#include "dh.h"

int main(int argc, char *argv[])
{
    input_control(argc, argv);
    return 0;
}

void input_control(int argc, char *argv[]){
    int opt;
    int o, p, g, a, b;
    char *output_path;
    while((opt = getopt(argc, argv, "o:p:g:a:b:h")) != -1){
        switch(opt){
            case 'o':
                output_path = strdup(optarg);
                break;
            case 'p':
                p = atoi(optarg);
                break;
            case 'g':
                g = atoi(optarg);
                break;
            case 'a':
                a = atoi(optarg);
                break;
            case 'b':
                b = atoi(optarg);
                break;
            case 'h':
                dh_print_help();
                return;
            default:
                fprintf(stderr, "Fatal error.\n");
        }
    }
    export_keys(compute_key(g,a,p), compute_key(g,b,p), compute_key(compute_key(g,b,p),a,p), output_path);
}

void dh_print_help(){
    printf("-o\tpath\tPath to output file.\n");
    printf("-p\tnumber\tPrime Number.\n");
    printf("-g\tnumber\tPrimitive Root for previous prime number.\n");
    printf("-a\tnumber\tPrivate key A.\n");
    printf("-b\tnumber\tPrivate Key B.\n");
    printf("-h\t\tHelp message.\n");
}

long long int compute_key(long long int x, long long int y, long long int p){
    return ((( long long int)pow(x, y)) % p);
}


void export_keys(long long int a, long long int b, long long int c, char *filePath){
    FILE *fp = fopen(filePath, "w");

    if(fp == NULL){
        fprintf(stderr, "Null pointer file.");
        exit(1);
    }

    fwrite("<", sizeof(char), sizeof(char), fp);
    fprintf(fp, "%llu", a);
    fwrite(">, ", sizeof(char), sizeof(char)*3, fp);

    fwrite("<", sizeof(char), sizeof(char), fp);
    fprintf(fp, "%llu", b);
    fwrite(">, ", sizeof(char), sizeof(char)*3, fp);

    fwrite("<", sizeof(char), sizeof(char), fp);
    fprintf(fp, "%llu", c);
    fwrite(">", sizeof(char), sizeof(char), fp);

    fclose(fp);
}