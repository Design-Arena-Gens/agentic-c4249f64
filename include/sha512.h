#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <stdint.h>

#define SHA512_DIGEST_LENGTH 64

typedef struct {
    uint64_t state[8];
    uint64_t bitcount[2];
    uint8_t buffer[128];
} SHA512_CTX_CUSTOM;

void sha512_init(SHA512_CTX_CUSTOM *ctx);
void sha512_update(SHA512_CTX_CUSTOM *ctx, const uint8_t *data, size_t len);
void sha512_final(SHA512_CTX_CUSTOM *ctx, uint8_t *out_digest);

void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out_mac[SHA512_DIGEST_LENGTH]);

#endif // SHA512_H
