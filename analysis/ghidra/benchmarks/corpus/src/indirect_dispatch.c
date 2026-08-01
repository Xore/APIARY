/* Dispatches to one of several handlers via a function-pointer table selected
 * by an opcode byte. Category: indirect call. */
typedef int (*handler_fn)(int);
static int add_one(int x) { return x + 1; }
static int negate(int x) { return -x; }
static int double_it(int x) { return x * 2; }
int dispatch(unsigned char opcode, int value) {
    handler_fn table[3] = { add_one, negate, double_it };
    if (opcode >= 3) {
        return -1;
    }
    return table[opcode](value);
}
