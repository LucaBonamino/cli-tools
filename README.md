# cli-tools
A collection of lightweight, self-contained command-line utilities written in C. Each tool is a single .c file in <code>src/</code>, designed for easy compilation and instant use. Perfect for UNIX-style workflows—just build, drop into <code>~/.local/bin</code> (or <code>/usr/local/bin</code>), and run from anywhere.

## Avaiable tools
1. **`src/replace_spaces.c`**  
   Rename files by replacing spaces with underscores.

2. **`src/hashsum.c`**  
   Compute a hash of input text using one of these algorithms:  
   - `crc32`  
   - `sha256`
   - `sha512`  
   - `sha1`  
   - `md5`  
   - `poseidon`
   
## Installation

Each tool is a single `.c` file in `src/`. To compile and install:

```bash
# 1. Compile (example for replace_spaces.c)
gcc -O2 -Wall -o replace_spaces src/replace_spaces.c

# 2a. Install system‐wide (requires sudo)
sudo mv replace_spaces /usr/local/bin/

# 2b. Or install just for your user
mkdir -p ~/.local/bin
mv replace_spaces ~/.local/bin
```
## Usage

### Replace spaces
```bash
replace_spaces --help
Usage: rename_spaces [-v|--verbose] [-d|--dir <directory>] [filename]
```
- <code>filename</code>: filename of file whose name to modify.
- <code>directory</code>: directory where to locate the files whose names are to be modified.

If both <code>filename</code> and <code>directory</code> are provided, <code>directory</code> is discarded.

### Hashsum
Hash a text of the content of a file with one of the following alorithms
- crc32
- sha256
- sha1
- md5
- poseidon

compile with 
```bash
gcc -O2 -Wall -o hashsum src/hashsum.c -lssl -lcrypto -lz
```
execute
```bash
hashsum --help
Usage: ./hashsum [-a|--algorithm <sha1|sha256|sha512|md5|poseidon|checksum>] [-f|--file <filename>] [text]
```
- <code>text</code>: text to hash.
- <code>algorithm</code>: hashing algorithm to use.
  - checksum: crc32
  - sha256
  - sha1
  - md5
  - poseidon sponge-like hash
- <code>file</code>: file to hash.

If both <code>text</code> and <code>file</code> are provided, <code>file</code> is discarded.</br>

#### How to use Poseidon hash
Get the poseidon required files from the repository [c-reference-signer](https://github.com/MinaProtocol/c-reference-signer).
```bash
git clone https://github.com/MinaProtocol/c-reference-signer.git
```

Compile <i>hashsum.c</i> providing the poseidon and crypto files

```bash
gcc -O2 -Wall \
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
```

