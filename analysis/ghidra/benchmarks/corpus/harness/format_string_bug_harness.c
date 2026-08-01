/* Semantic check for format_string_bug.c -- SAFE-PATH ONLY, deliberately.
 * Passing a string containing %n/%x/%s would exercise the actual format-
 * string vulnerability (a real stack read, or with %n a real stack write);
 * the bug is already known and static, so there is nothing to gain from
 * triggering it. This only proves the function behaves correctly -- returns
 * the byte count printf itself reports -- on input with no format
 * directives in it. */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../src/format_string_bug.c"

int main(void) {
    int rc = log_message("hello world");
    assert(rc == (int)strlen("hello world"));
    printf("PASS\n");
    return 0;
}
