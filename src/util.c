#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void secure_zero(void *v, size_t n) {
    volatile unsigned char *p = (volatile unsigned char *)v;
    while (n--) {
        *p++ = 0;
    }
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

void hex_encode(const uint8_t *in, size_t in_len, char *out_hex) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < in_len; i++) {
        out_hex[2 * i] = hex[(in[i] >> 4) & 0xF];
        out_hex[2 * i + 1] = hex[in[i] & 0xF];
    }
    out_hex[2 * in_len] = '\0';
}

bool hex_decode(const char *hexstr, uint8_t *out, size_t out_len) {
    size_t len = strlen(hexstr);
    if (len != out_len * 2) return false;
    for (size_t i = 0; i < out_len; i++) {
        int hi = hexval(hexstr[2 * i]);
        int lo = hexval(hexstr[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

bool read_urandom(uint8_t *out, size_t len) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return false;
    size_t total = 0;
    while (total < len) {
        ssize_t r = read(fd, out + total, len - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return false;
        }
        if (r == 0) break;
        total += (size_t)r;
    }
    close(fd);
    return total == len;
}

bool constant_time_eq(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}
