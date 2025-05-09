# cli-tools
A collection of lightweight, self-contained command-line utilities written in C. Each tool is a single .c file in <code>src/</code>, designed for easy compilation and instant use. Perfect for UNIX-style workflows—just build, drop into <code>~/.local/bin</code> (or <code>/usr/local/bin</code>), and run from anywhere.

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

### replace spaces
```bash
replace_spaces --help
Usage: rename_spaces [-v|--verbose] [-d|--dir <directory>] [filename]
```

### Hashsum
Hash a text of the content of a file with one of the following alorithms
- crc32
- sha256
- sha1
- md5
- poseidon

compile with 
```bash
gcc -O2 -Wall src/hashsum.c -lssl -lcrypto -lz
```
execute
```bash
hashsum --help
Usage: hashsum [-a|--alg][-f|--file <filename>] [text]
