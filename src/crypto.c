#include "crypto.h"

#include "sha512.h"

#include <stdint.h>
#include <string.h>

static void u32_be_encode(uint8_t out[4], uint32_t x) {
    out[0] = (uint8_t)(x >> 24);
    out[1] = (uint8_t)(x >> 16);
    out[2] = (uint8_t)(x >> 8);
    out[3] = (uint8_t)(x);
}

// PBKDF2 per RFC 8018 using HMAC-SHA512
void pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
                        const uint8_t *salt, size_t salt_len,
                        uint32_t iterations, uint8_t *out_key, size_t out_key_len) {
    uint8_t U[SHA512_DIGEST_LENGTH];
    uint8_t T[SHA512_DIGEST_LENGTH];
    uint8_t salt_block[1024];
    size_t hLen = SHA512_DIGEST_LENGTH;
    if (salt_len + 4 > sizeof(salt_block)) return; // simplistic bound

    uint32_t block_count = (uint32_t)((out_key_len + hLen - 1) / hLen);
    for (uint32_t block = 1; block <= block_count; block++) {
        memcpy(salt_block, salt, salt_len);
        u32_be_encode(salt_block + salt_len, block);
        hmac_sha512(password, password_len, salt_block, salt_len + 4, U);
        memcpy(T, U, hLen);
        for (uint32_t i = 1; i < iterations; i++) {
            hmac_sha512(password, password_len, U, hLen, U);
            for (size_t j = 0; j < hLen; j++) T[j] ^= U[j];
        }
        size_t offset = (size_t)(block - 1) * hLen;
        size_t to_copy = (offset + hLen <= out_key_len) ? hLen : (out_key_len - offset);
        memcpy(out_key + offset, T, to_copy);
    }

    memset(U, 0, sizeof(U));
    memset(T, 0, sizeof(T));
    memset(salt_block, 0, sizeof(salt_block));
}

void derive_one_way_digest(const uint8_t *message, size_t message_len,
                           const uint8_t *password, size_t password_len,
                           const uint8_t *quantum_salt, size_t quantum_salt_len,
                           uint8_t out_digest[256]) {
    // 1) Derive 64-byte key from password with PBKDF2 and quantum salt
    uint8_t key64[64];
    const uint32_t iterations = 100000; // strong default
    pbkdf2_hmac_sha512(password, password_len, quantum_salt, quantum_salt_len, iterations, key64, sizeof(key64));

    // 2) Create combined salt: HMAC(key64, quantum_salt || message)
    uint8_t comb_buf[64 + 4096];
    size_t comb_len = 0;
    if (quantum_salt_len > sizeof(comb_buf)) quantum_salt_len = sizeof(comb_buf);
    memcpy(comb_buf + comb_len, quantum_salt, quantum_salt_len);
    comb_len += quantum_salt_len;
    if (comb_len + message_len > sizeof(comb_buf)) message_len = sizeof(comb_buf) - comb_len;
    memcpy(comb_buf + comb_len, message, message_len);
    comb_len += message_len;

    uint8_t salt_hmac[SHA512_DIGEST_LENGTH];
    hmac_sha512(key64, sizeof(key64), comb_buf, comb_len, salt_hmac);

    // 3) Use PBKDF2 again to expand to 256 bytes using (salt_hmac || message) as salt
    uint8_t salt2[SHA512_DIGEST_LENGTH + 64];
    size_t salt2_len = 0;
    memcpy(salt2 + salt2_len, salt_hmac, SHA512_DIGEST_LENGTH);
    salt2_len += SHA512_DIGEST_LENGTH;
    size_t mcopy = message_len > 64 ? 64 : message_len;
    memcpy(salt2 + salt2_len, message, mcopy);
    salt2_len += mcopy;

    pbkdf2_hmac_sha512(key64, sizeof(key64), salt2, salt2_len, 1, out_digest, 256);

    memset(key64, 0, sizeof(key64));
    memset(comb_buf, 0, sizeof(comb_buf));
    memset(salt_hmac, 0, sizeof(salt_hmac));
    memset(salt2, 0, sizeof(salt2));
}
