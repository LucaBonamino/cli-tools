#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <openssl/evp.h>
#include <zlib.h>
#include <assert.h>

typedef enum
{
	CRC32_ALG,
	SHA256_ALG,
	SHA512_ALG,
	SHA1_ALG,
	POSEIDON_ALG,
	MD5_ALG,
	NONE_ALG,
} hashalg_t;

static struct
{
	const char *name;
	hashalg_t alg;
} hashalg_map[] = {
	{"sha1", SHA1_ALG},
	{"sha256", SHA256_ALG},
	{"sha512", SHA512_ALG},
	{"md5", MD5_ALG},
	{"poseidon", POSEIDON_ALG},
	{"checksum", CRC32_ALG},
	{NULL, NONE_ALG}};

typedef struct
{
	hashalg_t alg;
	char *text;
	char *filename;
} arg_t;

arg_t parse_args(int argc, char *argv[]);
int hash_buffer(hashalg_t alg, unsigned char *buf, size_t buf_len, unsigned char *out_digest);
size_t hash_digest_size(hashalg_t alg);

int main(int argc, char *argv[]){

	arg_t args = parse_args(argc, argv);

	size_t dlen = hash_digest_size(args.alg);
	unsigned char *digest = malloc(dlen);
	if (!digest) { 
		perror("malloc"); 
		return EXIT_FAILURE; 
	}

	if (args.text) {
		int hash_func_out = hash_buffer(args.alg, (unsigned char *)args.text, dlen, digest); 
		if (!hash_func_out) {
			fprintf(stderr, "Hashing failed\n");
			free(digest);
			return EXIT_FAILURE;
		}
		
		char *hex = malloc(dlen*2 + 1);
		for (size_t i=0; i<dlen; i++) {
			sprintf(hex + i*2, "%02x", digest[i]);
		}
		hex[dlen*2] = '\0';
		printf("Digest: %s\n", hex);
		free(hex);
	}
	else if (args.filename){
		printf("Unimplemented: Filename hashing is still not implemented\n");
		return EXIT_FAILURE;
	}
	
	free(digest);
	return EXIT_SUCCESS;
}

arg_t parse_args(int argc, char *argv[]){

	static struct option long_options[] = {
		{"alg", required_argument, NULL, 'a'},
		{"file", required_argument, NULL, 'f'},
		{"verbose", no_argument, NULL, 'v'},
		{0, 0, NULL, 0}};

	int opt, option_index = 0;
	arg_t args = {.text = NULL, .filename = NULL, .alg = CRC32_ALG};

	while ((opt = getopt_long(argc, argv, "a:f:", long_options, &option_index)) != -1) {
		switch (opt){
			case 'a':
				hashalg_t found = NONE_ALG;
				for (int i = 0; hashalg_map[i].name; i++) {
					if (strcmp(optarg, hashalg_map[i].name) == 0){
						found = hashalg_map[i].alg;
						break;
					}
				}
				if (found == NONE_ALG){
					printf("No hashing algorithm provided - using checksum.\n");
					found = CRC32_ALG;
				}
				args.alg = found;
				break;
			
			case 'f':
				args.filename = optarg;
				break;
			case '?':
			default:
				fprintf(stderr, "Usge: %s [-a|--algorithm <hashing algorithm>] [-f|--file <filename>] [text]\n", argv[0]);
				exit(EXIT_FAILURE);
			}
	}

	if (optind < argc){
		args.text = argv[1];
	}

	if (args.text == NULL && args.filename == NULL){
		fprintf(stderr, "Error: you must specify either -f/--file <directory> or a text to hash.\n"
						"Usage: %s [-a|--alg <hashing algorithm>][-f|--file <filename>] [text]\n",
				argv[0]);
		exit(EXIT_FAILURE);
	}
	return args;
}

size_t hash_digest_size(hashalg_t alg){
	switch (alg){
		case CRC32_ALG:
			return 4;
		case SHA1_ALG:
			return EVP_MD_size(EVP_sha1());
		case SHA256_ALG:
			return EVP_MD_size(EVP_sha256());
		case SHA512_ALG:
			return EVP_MD_size(EVP_sha512());
		case MD5_ALG:
			return EVP_MD_size(EVP_md5());
		case POSEIDON_ALG:
			printf("Unimplemented: Poseidon hash is still not implemened\n");
			exit(EXIT_FAILURE);
		default:
			exit(EXIT_FAILURE);
	}
}

int hash_buffer(hashalg_t alg, unsigned char *buf, size_t buf_len, unsigned char *out_digest){
	if (alg == CRC32_ALG) {
		uLong crc = crc32(0L, Z_NULL, 0);
		crc = crc32(crc, buf, buf_len);
		out_digest[0] = (crc >> 24) & 0xFF;
		out_digest[1] = (crc >> 16) & 0xFF;
		out_digest[2] = (crc >> 8) & 0xFF;
		out_digest[3] = (crc) & 0xFF;
		return 1;
	}

	const EVP_MD *md = NULL;
	switch (alg){
		case SHA1_ALG:
			md = EVP_sha1();
			break;
		case SHA256_ALG:
			md = EVP_sha256();
			break;
		case SHA512_ALG:
			md = EVP_sha512();
			break;
		case MD5_ALG:
			md = EVP_md5();
			break;
		default:
			// Poseidon or unknown
			return 0;
	}

	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx)
		return 0;
	if (EVP_DigestInit_ex(ctx, md, NULL) != 1 ||
		EVP_DigestUpdate(ctx, buf, buf_len) != 1 ||
		EVP_DigestFinal_ex(ctx, out_digest, NULL) != 1)
	{
		EVP_MD_CTX_free(ctx);
		return 0;
	}
	EVP_MD_CTX_free(ctx);
	return 1;
}