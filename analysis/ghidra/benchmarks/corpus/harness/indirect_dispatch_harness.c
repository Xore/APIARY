/* Semantic check for indirect_dispatch.c: exercises all three table entries
 * plus the out-of-range bounds check. */
#include <assert.h>
#include <stdio.h>
#include "../src/indirect_dispatch.c"

int main(void) {
    assert(dispatch(0, 5) == 6);   /* add_one */
    assert(dispatch(1, 5) == -5);  /* negate */
    assert(dispatch(2, 5) == 10);  /* double_it */
    assert(dispatch(3, 5) == -1);  /* out of range */
    printf("PASS\n");
    return 0;
}
