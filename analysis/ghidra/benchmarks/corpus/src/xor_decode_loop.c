/* Decodes a buffer in place with a single-byte XOR key. Loop, crypto-like
 * primitive. Category: loop + crypto-like primitive. */
void xor_decode(unsigned char *buf, unsigned long len, unsigned char key) {
    for (unsigned long i = 0; i < len; i++) {
        buf[i] ^= key;
    }
}
