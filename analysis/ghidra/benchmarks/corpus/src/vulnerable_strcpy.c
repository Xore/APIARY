/* Copies attacker-controlled input into a fixed stack buffer with no bounds
 * check. Category: intentionally vulnerable educational code (stack
 * overflow). */
#include <string.h>
int handle_request(const char *src) {
    char buf[64];
    strcpy(buf, src);
    return strcmp(buf, "admin");
}
