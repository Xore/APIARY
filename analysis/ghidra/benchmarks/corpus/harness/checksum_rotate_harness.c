/* Semantic check for checksum_rotate.c: two hand-computed vectors. Empty
 * input must be 0 (no iterations). A single byte 0x41 must equal 0x41,
 * since rotating an accumulator that is still 0 by any amount is still 0,
 * leaving only the "+ buf[0]" term. */
#include <assert.h>
#include <stdio.h>
#include "../src/checksum_rotate.c"

int main(void) {
    unsigned char one[] = { 0x41 };
    assert(rotate_checksum(one, 0) == 0);
    assert(rotate_checksum(one, 1) == 0x41);
    printf("PASS\n");
    return 0;
}
