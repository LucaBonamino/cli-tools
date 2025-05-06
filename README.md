# cli-tools
A collection of lightweight, self-contained command-line utilities written in C. Each tool is a single .c file in <code>src/</code>, designed for easy compilation and instant use. Perfect for UNIX-style workflows—just build, drop into <code>~/.local/bin</code> (or <code>/usr/local/bin</code>), and run from anywhere.

## Installation

Each tool is a single `.c` file in `src/`. To compile and install:

```bash
# 1. Compile (example for rename_spaces.c)
gcc -O2 -Wall -o replace_spaces src/replace_spaces.c

# 2a. Install system‐wide (requires sudo)
sudo mv replace_spaces /usr/local/bin/

# 2b. Or install just for your user
mkdir -p ~/.local/bin
mv replace_spaces ~/.local/bin
```
## Usage
```bash
replace_spaces --help
Usage: rename_spaces [-v|--verbose] [-d|--dir <directory>] [filename]
```