/* Semantic check for linked_list_sum.c: builds a small list and verifies
 * the accumulated sum matches a hand-computed total. */
#include <assert.h>
#include <stdio.h>
#include "../src/linked_list_sum.c"

int main(void) {
    struct node c = { 30, 0 };
    struct node b = { 20, &c };
    struct node a = { 10, &b };
    assert(list_sum(&a) == 60);
    assert(list_sum(0) == 0);
    printf("PASS\n");
    return 0;
}
