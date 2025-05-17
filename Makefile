.PHONY: compile-hashsum
compile-hashsum:
	@gcc -O2 -Wall \
    -I./c-reference-signer \
    -o hashsum \
    src/hashsum.c \
    c-reference-signer/poseidon.c         \
    c-reference-signer/crypto.c           \
    c-reference-signer/pasta_fp.c         \
    c-reference-signer/pasta_fq.c         \
    c-reference-signer/base10.c           \
    c-reference-signer/base58.c           \
    c-reference-signer/blake2b-ref.c      \
    c-reference-signer/curve_checks.c     \
    c-reference-signer/sha256.c           \
    c-reference-signer/utils.c            \
    -lcrypto -lz -lm