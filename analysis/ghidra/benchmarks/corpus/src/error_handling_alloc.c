/* Allocates a buffer and copies into it, propagating failure as a negative
 * return code rather than crashing. Category: error handling. */
#include <stdlib.h>
#include <string.h>
int copy_to_heap(const char *src, unsigned long len, char **out) {
    char *dst = (char *)malloc(len);
    if (dst == 0) {
        *out = 0;
        return -1;
    }
    memcpy(dst, src, len);
    *out = dst;
    return 0;
}
