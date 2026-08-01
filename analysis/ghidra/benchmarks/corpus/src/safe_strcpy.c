/* Same shape and same call site pattern as vulnerable_strcpy.c's
 * handle_request -- copies attacker-controlled input into a fixed stack
 * buffer -- but bounds-checked: truncates rather than overflowing. Category:
 * benign near-neighbor (deliberately paired with vulnerable_strcpy.c to test
 * whether a model overclaims a vulnerability on code that merely looks
 * similar to a known-bad pattern). */
#include <string.h>
int handle_request_safe(const char *src) {
    char buf[64];
    size_t n = strlen(src);
    if (n >= sizeof(buf)) {
        n = sizeof(buf) - 1;
    }
    memcpy(buf, src, n);
    buf[n] = '\0';
    return strcmp(buf, "admin");
}
