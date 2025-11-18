#ifndef QRNG_H
#define QRNG_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Fetch quantum random bytes using external API via curl; returns true on success
bool qrng_fetch_bytes(uint8_t *out, size_t len);

// Generate a quantum password as an ASCII string meeting strength requirements
bool qrng_generate_password(char *out, size_t out_size);

#endif // QRNG_H
