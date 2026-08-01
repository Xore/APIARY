/* Sums values in a singly linked list. Category: data structure traversal. */
struct node {
    int value;
    struct node *next;
};
long list_sum(struct node *head) {
    long total = 0;
    while (head != 0) {
        total += head->value;
        head = head->next;
    }
    return total;
}
