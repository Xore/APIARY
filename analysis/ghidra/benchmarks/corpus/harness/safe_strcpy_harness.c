/* Semantic check for safe_strcpy.c: matching input, non-matching input, and
 * -- the entire point of this fixture -- an over-length input that must
 * truncate safely rather than overflow. */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../src/safe_strcpy.c"

int main(void) {
    assert(handle_request_safe("admin") == 0);
    assert(handle_request_safe("guest") != 0);

    char long_input[500];
    memset(long_input, 'A', sizeof(long_input) - 1);
    long_input[sizeof(long_input) - 1] = '\0';
    /* Must not crash. Truncated to 63 chars of 'A', so it cannot equal
     * "admin" either. */
    assert(handle_request_safe(long_input) != 0);
    printf("PASS\n");
    return 0;
}
