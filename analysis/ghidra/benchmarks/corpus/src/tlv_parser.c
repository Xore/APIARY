/* Parses a sequence of type-length-value records from a buffer, returning the
 * value pointer for a matching type or 0 if not found/malformed. Category:
 * parsing. */
struct tlv_result {
    const unsigned char *value;
    unsigned short length;
};
int find_tlv(const unsigned char *buf, unsigned long len, unsigned char want_type,
              struct tlv_result *out) {
    unsigned long offset = 0;
    while (offset + 3 <= len) {
        unsigned char type = buf[offset];
        unsigned short length = (unsigned short)(buf[offset + 1] | (buf[offset + 2] << 8));
        unsigned long value_offset = offset + 3;
        if (value_offset + length > len) {
            return -1;
        }
        if (type == want_type) {
            out->value = buf + value_offset;
            out->length = length;
            return 0;
        }
        offset = value_offset + length;
    }
    return -1;
}
