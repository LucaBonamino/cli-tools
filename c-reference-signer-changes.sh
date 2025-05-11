cd c-reference-signer
# 1. Rename the compress API
# --------------------------------
# In crypto.h: change
#   void compress(Compressed *compressed, const Affine *pt);
# to
#   void compress_point(Compressed *compressed, const Affine *pt);
sed -i "s/\bcompress(Compressed \*compressed/compress_point(Compressed *compressed/" crypto.h

# In crypto.c: change the definition and all calls
sed -i "s/\bcompress(/compress_point(/g" crypto.c

# 2. Replace bzero with memset and pull in <string.h>
# ---------------------------------------------------
# In both poseidon.c and crypto.c:
#  - Add `#include <string.h>` at the top (so memset & strnlen are declared)
#  - Replace all `bzero(` with `memset(`

for f in poseidon.c crypto.c; do
  # 1) insert POSIX macro + string.h at top
  sed -i '1i#define _POSIX_C_SOURCE 200809L\n#include <string.h>\n' $f

  # 2) fix all two-arg memset calls to three-arg
  sed -i -E 's/memset\(([^,]+),[[:space:]]*([^),]+)\);/memset(\1, 0, \2);/g' $f
done

