/* Semantic check for use_after_free.c -- SAFE-PATH ONLY, deliberately.
 * Setting expired=1 would exercise the actual use-after-free (a real
 * dangling-pointer write), which is not something an automated check
 * should ever do on purpose. This only proves the non-buggy path (expired
 * still false, so free() never runs) copies correctly. */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../src/use_after_free.c"

int main(void) {
    struct session s;
    s.token = (char *)malloc(16);
    s.expired = 0;
    assert(refresh_token(&s, "newtoken", 8) == 0);
    assert(memcmp(s.token, "newtoken", 8) == 0);
    free(s.token);
    printf("PASS\n");
    return 0;
}
