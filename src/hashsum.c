#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <zlib.h>  

typedef enum {
	CRC32_ALG,
	SHA256_ALG,
	SHA512_ALG,
	SHA1_ALG,
	POSEIDON_ALG,
	MD5_ALG,
	NONE_ALG,
} hashalg_t;

static struct {
    const char   *name;
    hashalg_t     alg;
} hashalg_map[] = {
    { "sha1", SHA1_ALG},
    { "sha256", SHA256_ALG },
    { "sha512", SHA512_ALG},
    { "md5", MD5_ALG },
    { "poseidon", POSEIDON_ALG },
	{"checksum", CRC32_ALG},
	{ NULL, NONE_ALG }
};

typedef struct
{
    hashalg_t alg;
    char *text;
    char *filename;
} arg_t;

arg_t parse_args(int argc, char *argv[]);
char *hash_buffer(const unsigned char *buf, size_t len, hashalg_t alg);


int main(int argc, char *argv[]){

	arg_t args = parse_args(argc, argv);

	if (args.text){
		// apply the hash using args.alg to algs.text
	}
	else if (args.filename){
		// open the file and hash the content
	}
    printf("Argument %s\n", args.filename);
	printf("%d\n", args.alg);

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
    arg_t args = {.text = NULL, .filename = NULL, .alg = CRC32_ALG};

    while ((opt = getopt_long(argc, argv, "a:f:", long_options, &option_index)) != -1){
		switch (opt){
			case 'a': {
				hashalg_t found = NONE_ALG;
				for (int i = 0; hashalg_map[i].name; i++) {
					if (strcmp(optarg, hashalg_map[i].name) == 0) {
						found = hashalg_map[i].alg;
						break;
					}
				}
				if (found == NONE_ALG) {
					printf("No hashing algorithm provided - using checksum.\n");
;					found = CRC32_ALG;
				}
				args.alg = found;
				break;
			}
			case 'f':
				args.filename = optarg;
				break;
			case '?':
			default:
				fprintf(stderr, "Usge: %s [-a|--algorithm <hashing algorithm>] [-f|--file <filename>] [text]\n", argv[0]);
				exit(EXIT_FAILURE);
		}
	}

	char *t = NULL;
	if (optind < argc){
		args.text = argv[1];
	}
	
	if (args.text == NULL && args.filename == NULL){
		fprintf(stderr, "Error: you must specify either -f/--file <directory> or a text to hash.\n"
				"Usage: %s [-a|--alg <hashing algorithm>][-f|--file <filename>] [text]\n", argv[0]
				);
		exit(EXIT_FAILURE);
	}
	return args;
	
}



char *hash_buffer(const unsigned char *buf, size_t len, hashalg_t alg) {
    unsigned char digest[SHA512_DIGEST_LENGTH]; 
    size_t dlen = 0;
    switch (alg) {
      case CRC32_ALG: {
        uLong crc = crc32(0L, Z_NULL, 0);
        crc = crc32(crc, buf, len);
        char *out = malloc(9);
        if (!out) return NULL;
        sprintf(out, "%08lx", crc);
        return out;
      }
      case SHA1_ALG:
        SHA1(buf, len, digest);
        dlen = SHA_DIGEST_LENGTH; break;
      case SHA256_ALG:
        SHA256(buf, len, digest);
        dlen = SHA256_DIGEST_LENGTH; break;
      case SHA512_ALG:
        SHA512(buf, len, digest);
        dlen = SHA512_DIGEST_LENGTH; break;
      case MD5_ALG:
        MD5(buf, len, digest);
        dlen = MD5_DIGEST_LENGTH; break;
      case POSEIDON_ALG:
        // TODO: call your Poseidon implementation here,
        // fill `digest` and set `dlen` appropriately.
        fprintf(stderr, "POSEIDON not yet implemented\n");
        return NULL;
      default:
        return NULL;
    }

    // convert to hex
    char *out = malloc(dlen * 2 + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < dlen; i++)
        sprintf(out + (i*2), "%02x", digest[i]);
    out[dlen*2] = '\0';
    return out;
}