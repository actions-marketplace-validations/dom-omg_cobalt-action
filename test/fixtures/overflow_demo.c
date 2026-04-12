/**
 * COBALT Action — Test Fixture
 *
 * Intentionally vulnerable C code used to validate that the COBALT scanner
 * correctly identifies integer overflow patterns.
 *
 * DO NOT USE IN PRODUCTION.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* CWE-190: Integer Overflow — attacker-controlled length * element_size */
void *alloc_buffer(unsigned int count, unsigned int element_size) {
    unsigned int total = count * element_size;  /* overflow if count large */
    return malloc(total);
}

/* CWE-195: Signed-to-unsigned conversion */
void process_data(int user_len, char *buf) {
    unsigned int len = (unsigned int)user_len;  /* negative → huge positive */
    char *out = malloc(len);
    if (out) memcpy(out, buf, len);
    free(out);
}

/* CWE-197: Numeric truncation */
uint16_t truncate_counter(uint32_t counter) {
    return (uint16_t)counter;  /* high bits silently dropped */
}

/* Safe reference — COBALT should NOT flag this */
void safe_alloc(uint32_t count) {
    if (count > 1024) return;  /* guard eliminates overflow */
    uint32_t total = count * sizeof(int);
    free(malloc(total));
}
