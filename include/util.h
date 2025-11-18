#ifndef UTIL_H
#define UTIL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void secure_zero(void *v, size_t n);

void hex_encode(const uint8_t *in, size_t in_len, char *out_hex);
bool hex_decode(const char *hex, uint8_t *out, size_t out_len);

bool read_urandom(uint8_t *out, size_t len);

bool constant_time_eq(const uint8_t *a, const uint8_t *b, size_t len);

#endif // UTIL_H
