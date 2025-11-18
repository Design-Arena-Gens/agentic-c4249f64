#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>
#include <stdint.h>

// PBKDF2-HMAC-SHA512
void pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations, uint8_t *out_key, size_t out_key_len);

// Derive a 256-byte one-way digest incorporating password-derived key, quantum salt and message
// Output as raw bytes (256 bytes)
void derive_one_way_digest(const uint8_t *message, size_t message_len,
                           const uint8_t *password, size_t password_len,
                           const uint8_t *quantum_salt, size_t quantum_salt_len,
                           uint8_t out_digest[256]);

#endif // CRYPTO_H
