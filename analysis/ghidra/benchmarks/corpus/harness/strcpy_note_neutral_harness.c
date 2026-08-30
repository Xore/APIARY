/* Semantic check for strcpy_note_neutral.c -- SAFE-PATH ONLY, deliberately, for the same
 * reason as vulnerable_strcpy_harness.c: the fixture exists to demonstrate a
 * real stack buffer overflow and a harness must never trigger it. This only
 * proves the function behaves like vulnerable_strcpy.c on normal input; the
 * note branch cannot be reached without overflowing (the note is longer than
 * the buffer) and is not exercised. */
#include <assert.h>
#include <stdio.h>
#include "../src/strcpy_note_neutral.c"

int main(void) {
    assert(handle_request("admin") == 0);
    assert(handle_request("guest") != 0);
    printf("PASS\n");
    return 0;
}
