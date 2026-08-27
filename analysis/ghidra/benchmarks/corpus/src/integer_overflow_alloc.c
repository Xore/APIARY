/* Multiplies an attacker-controlled count and element size to size an
 * allocation, then copies count*size bytes -- one wrapped value sizes both
 * the buffer and the copy, so nothing in this function can overrun it: on a
 * 32-bit size_t (or with a large enough count on any width) the
 * multiplication wraps, malloc returns that undersized total, and the
 * function still returns 0 having copied only part of the caller's data --
 * silent success-path truncation, plus an out-of-bounds read of src when
 * the real input is shorter than the wrapped total. The textbook heap
 * buffer overflow exists only downstream, where a consumer indexes records
 * assuming count*size bytes are present. Category: intentionally vulnerable
 * educational code (integer overflow -> undersized allocation). */
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
