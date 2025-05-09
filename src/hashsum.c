#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

typedef enum {
	SHA256 = 0,
	SHA385,
	SHA512,
	SHA1,
	POSEIDON,
	MD5,
} hashalg_t;

typedef struct
{
    hashalg_t alg;
    char *text;
    char *filename;
} arg_t;

arg_t parse_args(int argc, char *argv[]);


int main(int argc, char *argv[]){

	arg_t args = parse_args(argc, argv);
    printf("Argument %s", args.filename);

    return EXIT_SUCCESS;
}

arg_t parse_args(int argc, char *argv[]){
	
	static struct option long_options[] = {
        {"alg", required_argument, NULL, 'a'},
		{"file",	 required_argument, NULL, 'f'},
		{ "verbose", no_argument, NULL, 'v' },
		{0, 0, NULL, 0}
	};

    int opt, option_index = 0;
    arg_t args = {.text = NULL, .filename = NULL, .alg = NULL};

    while ((opt = getopt_long(argc, argv, "a:f:", long_options, &option_index)) != -1){
		switch (opt){
			case 'f':
				args.filename = optarg;
				break;
			case '?':
			default:
				fprintf(stderr, "Usge: %s [-a|$--algorithm] [-f|--file <filename>] [text]\n", argv[0]);
				exit(EXIT_FAILURE);
		}
	}
	return args;
	
}