#include "sha512.h"

#include <string.h>

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define Sigma0(x) (ROTR64((x), 28) ^ ROTR64((x), 34) ^ ROTR64((x), 39))
#define Sigma1(x) (ROTR64((x), 14) ^ ROTR64((x), 18) ^ ROTR64((x), 41))
#define sigma0(x) (ROTR64((x), 1) ^ ROTR64((x), 8) ^ ((x) >> 7))
#define sigma1(x) (ROTR64((x), 19) ^ ROTR64((x), 61) ^ ((x) >> 6))

static const uint64_t K[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
    0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
    0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
    0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
    0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
    0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
    0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
    0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
    0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
    0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
    0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
    0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
    0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
    0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

static void be64enc(uint8_t *dst, uint64_t x) {
    dst[0] = (uint8_t)(x >> 56);
    dst[1] = (uint8_t)(x >> 48);
    dst[2] = (uint8_t)(x >> 40);
    dst[3] = (uint8_t)(x >> 32);
    dst[4] = (uint8_t)(x >> 24);
    dst[5] = (uint8_t)(x >> 16);
    dst[6] = (uint8_t)(x >> 8);
    dst[7] = (uint8_t)(x);
}

static uint64_t be64dec(const uint8_t *p) {
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

void sha512_init(SHA512_CTX_CUSTOM *ctx) {
    ctx->state[0] = 0x6a09e667f3bcc908ULL;
    ctx->state[1] = 0xbb67ae8584caa73bULL;
    ctx->state[2] = 0x3c6ef372fe94f82bULL;
    ctx->state[3] = 0xa54ff53a5f1d36f1ULL;
    ctx->state[4] = 0x510e527fade682d1ULL;
    ctx->state[5] = 0x9b05688c2b3e6c1fULL;
    ctx->state[6] = 0x1f83d9abfb41bd6bULL;
    ctx->state[7] = 0x5be0cd19137e2179ULL;
    ctx->bitcount[0] = 0;
    ctx->bitcount[1] = 0;
}

static void sha512_transform(SHA512_CTX_CUSTOM *ctx, const uint8_t block[128]) {
    uint64_t W[80];
    for (int i = 0; i < 16; i++) {
        W[i] = be64dec(block + 8 * i);
    }
    for (int i = 16; i < 80; i++) {
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
    }

    uint64_t a = ctx->state[0];
    uint64_t b = ctx->state[1];
    uint64_t c = ctx->state[2];
    uint64_t d = ctx->state[3];
    uint64_t e = ctx->state[4];
    uint64_t f = ctx->state[5];
    uint64_t g = ctx->state[6];
    uint64_t h = ctx->state[7];

    for (int i = 0; i < 80; i++) {
        uint64_t T1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + W[i];
        uint64_t T2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha512_update(SHA512_CTX_CUSTOM *ctx, const uint8_t *data, size_t len) {
    size_t have = (size_t)((ctx->bitcount[0] >> 3) & 0x7F);
    size_t need = 128 - have;

    uint64_t bitlen = (uint64_t)len << 3;
    ctx->bitcount[0] += bitlen;
    if (ctx->bitcount[0] < bitlen) ctx->bitcount[1]++;

    if (len >= need) {
        if (have) {
            memcpy(ctx->buffer + have, data, need);
            sha512_transform(ctx, ctx->buffer);
            data += need;
            len -= need;
            have = 0;
        }
        while (len >= 128) {
            sha512_transform(ctx, data);
            data += 128;
            len -= 128;
        }
    }

    if (len) memcpy(ctx->buffer + have, data, len);
}

void sha512_final(SHA512_CTX_CUSTOM *ctx, uint8_t *out_digest) {
    uint8_t pad[128];
    size_t padlen;
    size_t r = (size_t)((ctx->bitcount[0] >> 3) & 0x7F);

    pad[0] = 0x80;
    if (r < 112) {
        padlen = 112 - r;
    } else {
        padlen = 128 + 112 - r;
    }
    memset(pad + 1, 0, padlen - 1);

    uint8_t lenbuf[16];
    be64enc(lenbuf, ctx->bitcount[1]);
    be64enc(lenbuf + 8, ctx->bitcount[0]);

    sha512_update(ctx, pad, padlen);
    sha512_update(ctx, lenbuf, 16);

    for (int i = 0; i < 8; i++) {
        be64enc(out_digest + i * 8, ctx->state[i]);
    }
}

void hmac_sha512(const uint8_t *key, size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t out_mac[SHA512_DIGEST_LENGTH]) {
    uint8_t kopad[128];
    uint8_t kipad[128];
    uint8_t tk[SHA512_DIGEST_LENGTH];

    if (key_len > 128) {
        SHA512_CTX_CUSTOM tctx;
        sha512_init(&tctx);
        sha512_update(&tctx, key, key_len);
        sha512_final(&tctx, tk);
        key = tk;
        key_len = SHA512_DIGEST_LENGTH;
    }

    memset(kopad, 0x5c, sizeof(kopad));
    memset(kipad, 0x36, sizeof(kipad));

    for (size_t i = 0; i < key_len; i++) {
        kopad[i] ^= key[i];
        kipad[i] ^= key[i];
    }

    SHA512_CTX_CUSTOM ctx;
    uint8_t inner[SHA512_DIGEST_LENGTH];
    sha512_init(&ctx);
    sha512_update(&ctx, kipad, sizeof(kipad));
    sha512_update(&ctx, data, data_len);
    sha512_final(&ctx, inner);

    sha512_init(&ctx);
    sha512_update(&ctx, kopad, sizeof(kopad));
    sha512_update(&ctx, inner, sizeof(inner));
    sha512_final(&ctx, out_mac);

    // wipe
    memset(tk, 0, sizeof(tk));
    memset(kopad, 0, sizeof(kopad));
    memset(kipad, 0, sizeof(kipad));
    memset(inner, 0, sizeof(inner));
}
