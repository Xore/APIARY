/* Computes a rotate-and-add checksum over a buffer -- a different shape of
 * crypto-like primitive than xor_decode_loop.c's byte-XOR (bit rotation plus
 * accumulation, the pattern behind many simple non-cryptographic hash
 * functions). Category: loop + crypto-like primitive. */
unsigned int rotate_checksum(const unsigned char *buf, unsigned long len) {
    unsigned int acc = 0;
    for (unsigned long i = 0; i < len; i++) {
        acc = ((acc << 5) | (acc >> 27)) + buf[i];
    }
    return acc;
}
