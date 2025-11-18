#define _POSIX_C_SOURCE 200809L
#include "qrng.h"

#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *default_qrng_url = "https://qrng.anu.edu.au/API/jsonI.php?length=64&type=hex16&size=8";

static bool parse_hex16_array_to_bytes(const char *json, uint8_t *out, size_t out_len) {
    const char *p = strstr(json, "\"data\"");
    if (!p) return false;
    p = strchr(p, '[');
    if (!p) return false;
    p++;
    size_t out_written = 0;
    while (*p && *p != ']') {
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\"') {
            p++;
            char token[8] = {0};
            size_t ti = 0;
            while (*p && *p != '\"' && ti < sizeof(token) - 1) {
                token[ti++] = *p++;
            }
            if (*p != '\"') return false;
            p++;
            // token is hex string of 16-bit value
            if (ti < 1 || ti > 4) return false;
            char *endptr = NULL;
            unsigned long val = strtoul(token, &endptr, 16);
            if (!endptr || *endptr != '\0' || val > 0xFFFFUL) return false;
            if (out_written + 2 <= out_len) {
                out[out_written++] = (uint8_t)((val >> 8) & 0xFF);
                if (out_written < out_len) out[out_written++] = (uint8_t)(val & 0xFF);
            } else if (out_written + 1 <= out_len) {
                out[out_written++] = (uint8_t)((val >> 8) & 0xFF);
            } else {
                break;
            }
        }
        while (*p && *p != ',' && *p != ']') p++;
        if (*p == ',') p++;
    }
    return out_written == out_len;
}

bool qrng_fetch_bytes(uint8_t *out, size_t len) {
    if (!out || len == 0) return false;

    const char *url = getenv("QRNG_API_URL");
    if (!url || strlen(url) < 8) url = default_qrng_url;

    char cmd[1024];
    int n = snprintf(cmd, sizeof(cmd), "curl -fsSL --max-time 10 '%s'", url);
    if (n <= 0 || (size_t)n >= sizeof(cmd)) return false;

    FILE *fp = popen(cmd, "r");
    if (!fp) return false;
    char *buf = malloc(8192);
    if (!buf) {
        pclose(fp);
        return false;
    }
    size_t total = fread(buf, 1, 8191, fp);
    buf[total] = '\0';
    int rc = pclose(fp);
    if (rc == -1 || total == 0) {
        free(buf);
        return false;
    }

    bool ok = parse_hex16_array_to_bytes(buf, out, len);
    free(buf);

    if (!ok) {
        // fallback to urandom
        return read_urandom(out, len);
    }
    return true;
}

static const char *alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}:,.?/";

bool qrng_generate_password(char *out, size_t out_size) {
    if (!out || out_size < 20) return false;
    uint8_t rnd[48];
    if (!qrng_fetch_bytes(rnd, sizeof(rnd))) return false;
    size_t alpha_len = strlen(alphabet);
    size_t pwd_len = (out_size - 1) < 24 ? (out_size - 1) : 24;
    size_t pos = 0;
    unsigned has_lower = 0, has_upper = 0, has_digit = 0, has_symbol = 0;
    for (size_t i = 0; i < pwd_len; i++) {
        uint8_t b = rnd[i] ^ rnd[(i + 13) % sizeof(rnd)];
        char c = alphabet[b % alpha_len];
        out[pos++] = c;
        if (c >= 'a' && c <= 'z') has_lower = 1;
        else if (c >= 'A' && c <= 'Z') has_upper = 1;
        else if (c >= '0' && c <= '9') has_digit = 1;
        else has_symbol = 1;
    }
    // Ensure complexity by forcing categories if missing
    if (!has_lower) out[0] = 'a';
    if (!has_upper) out[1] = 'Z';
    if (!has_digit) out[2] = '7';
    if (!has_symbol) out[3] = '!';
    out[pos] = '\0';
    return true;
}
