/* Semantic check for file_write_persist.c: writes into a fixed test
 * directory, reads the fixed-filename marker back, verifies the content,
 * then removes it -- the harness's own responsibility, not the function's,
 * matching how the fixture is documented (only the directory is a
 * parameter; the filename is fixed by the function itself). */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../src/file_write_persist.c"

int main(void) {
    const char *dir = "/tmp";
    const char *marker = "/tmp/.hp-corpus-marker";
    remove(marker);

    assert(write_marker(dir, "semantic-check") == 0);
    FILE *f = fopen(marker, "r");
    assert(f != 0);
    char got[64] = {0};
    fread(got, 1, sizeof(got) - 1, f);
    fclose(f);
    assert(strcmp(got, "semantic-check") == 0);
    remove(marker);
    printf("PASS\n");
    return 0;
}
