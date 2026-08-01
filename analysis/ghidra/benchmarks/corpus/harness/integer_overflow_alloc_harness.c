/* Semantic check for integer_overflow_alloc.c -- SAFE-PATH ONLY, deliberately.
 * Actually feeding this an overflowing count*size would corrupt the heap on
 * purpose; the bug is already known and static, so there is nothing to gain
 * from triggering it and a real risk (a corrupted allocator can crash the
 * whole harness process, not just this one check) from doing so. This only
 * proves the function copies correctly when the multiplication does not
 * overflow. */
#include <assert.h>
#include <stdio.h>
#include "../src/integer_overflow_alloc.c"

int main(void) {
    assert(copy_records("0123456789012345", 4, 4) == 0);
    printf("PASS\n");
    return 0;
}
