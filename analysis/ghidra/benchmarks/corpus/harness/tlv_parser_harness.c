/* Semantic check for tlv_parser.c: one hand-built TLV record (type=0x01,
 * length=3, value="abc"), checking both the found and not-found paths. */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "../src/tlv_parser.c"

int main(void) {
    unsigned char buf[] = { 0x01, 0x03, 0x00, 'a', 'b', 'c' };
    struct tlv_result out;

    assert(find_tlv(buf, sizeof(buf), 0x01, &out) == 0);
    assert(out.length == 3);
    assert(memcmp(out.value, "abc", 3) == 0);

    assert(find_tlv(buf, sizeof(buf), 0x02, &out) == -1);
    printf("PASS\n");
    return 0;
}
