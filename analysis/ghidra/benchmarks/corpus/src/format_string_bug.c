/* Passes attacker-controlled input directly as printf's format argument
 * instead of as a %s value -- any %n/%x/%s sequence embedded in the input is
 * interpreted as a format directive, giving an attacker a read (and, with
 * %n, a write) primitive into the caller's stack. Category: intentionally
 * vulnerable educational code (format string). */
#include <stdio.h>
int log_message(const char *msg) {
    return printf(msg);
}
