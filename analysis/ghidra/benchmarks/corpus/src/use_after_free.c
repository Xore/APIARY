/* Frees a heap buffer on an error path, then falls through to a second
 * write into the same (now-dangling) pointer on a later branch that does not
 * re-check whether the free already happened. Category: intentionally
 * vulnerable educational code (use-after-free). */
#include <stdlib.h>
struct session {
    char *token;
    int expired;
};
int refresh_token(struct session *s, const char *new_value, unsigned long len) {
    if (s->expired) {
        free(s->token);
    }
    /* Missing: s->token = 0; after the free above, and a check for it here.
     * A caller that sets expired on one call, then calls again with expired
     * still set (or any other path that reaches this without knowing the
     * free above already ran) writes through a dangling pointer. */
    for (unsigned long i = 0; i < len; i++) {
        s->token[i] = new_value[i];
    }
    return 0;
}
