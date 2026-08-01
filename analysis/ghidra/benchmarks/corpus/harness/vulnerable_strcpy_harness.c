/* Semantic check for vulnerable_strcpy.c -- SAFE-PATH ONLY, deliberately.
 * This fixture exists to demonstrate a real stack buffer overflow; a
 * harness that actually triggered it would be intentionally corrupting its
 * own stack, which is not something an automated check should ever do for
 * zero informational benefit (the bug is already known and static). This
 * only proves the function behaves correctly on normal, non-overflowing
 * input -- it is not, and must never become, a test of the overflow itself. */
#include <assert.h>
#include <stdio.h>
#include "../src/vulnerable_strcpy.c"

int main(void) {
    assert(handle_request("admin") == 0);
    assert(handle_request("guest") != 0);
    printf("PASS\n");
    return 0;
}
