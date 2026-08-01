/* Multiplies an attacker-controlled count and element size to size an
 * allocation, then writes count*size bytes -- on a 32-bit size_t (or with a
 * large enough count on any width) the multiplication wraps, the allocation
 * comes back far smaller than the write that follows, and every write past
 * the true allocated size is a heap buffer overflow. Category: intentionally
 * vulnerable educational code (integer overflow -> undersized allocation). */
#include <stdlib.h>
#include <string.h>
int copy_records(const char *src, unsigned long count, unsigned long size) {
    unsigned long total = count * size;
    char *buf = (char *)malloc(total);
    if (buf == 0) {
        return -1;
    }
    memcpy(buf, src, total);
    free(buf);
    return 0;
}
