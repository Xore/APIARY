/* Semantic check for xor_decode_loop.c: XOR is self-inverse, so applying the
 * same key twice must restore the original buffer. */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../src/xor_decode_loop.c"

int main(void) {
    unsigned char buf[] = "Hello!";
    unsigned char original[7];
    memcpy(original, buf, 7);
    xor_decode(buf, 6, 0x5A);
    assert(memcmp(buf, original, 6) != 0);
    xor_decode(buf, 6, 0x5A);
    assert(memcmp(buf, original, 6) == 0);
    printf("PASS\n");
    return 0;
}
