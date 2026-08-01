/* Writes a fixed marker filename into a caller-supplied directory -- a
 * behavior-shaped fixture (file write / persistence-style disk write), safe
 * by the same shape loopback_connect.c's network fixture uses: the thing
 * that could make this dangerous (the destination) is not attacker-
 * controlled -- the filename is fixed by this function, only the containing
 * directory is a parameter, so a caller (or a test harness) decides where,
 * never what. Category: behavior-shaped fixture (persistence). */
#include <stdio.h>
#include <string.h>
int write_marker(const char *dir, const char *content) {
    char path[256];
    if (strlen(dir) + strlen("/.hp-corpus-marker") >= sizeof(path)) {
        return -1;
    }
    strcpy(path, dir);
    strcat(path, "/.hp-corpus-marker");
    FILE *f = fopen(path, "w");
    if (f == 0) {
        return -1;
    }
    fputs(content, f);
    fclose(f);
    return 0;
}
