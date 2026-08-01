/* Semantic check for error_handling_alloc.c: exercises only the success
 * path (a real malloc failure is not something a harness can safely force
 * portably) -- verifies the heap copy actually contains the source bytes. */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../src/error_handling_alloc.c"

int main(void) {
    char *out = 0;
    int rc = copy_to_heap("hello", 5, &out);
    assert(rc == 0);
    assert(out != 0);
    assert(memcmp(out, "hello", 5) == 0);
    free(out);
    printf("PASS\n");
    return 0;
}
