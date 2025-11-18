#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "input.h"
#include "fileio.h"
#include "crypto.h"
#include "qrng.h"
#include "util.h"

int main(void) {
    char username[MAX_USERNAME_LEN + 1];
    char message[MAX_MESSAGE_LEN + 1];
    char password[MAX_PASSWORD_LEN + 1];

    if (!prompt_username(username, sizeof(username))) {
        fprintf(stderr, "Failed to read username.\n");
        return 1;
    }

    if (!prompt_message(message, sizeof(message))) {
        fprintf(stderr, "Failed to read message.\n");
        return 1;
    }

    int use_quantum_pwd = prompt_yes_no("Use quantum-generated strong password?", true);

    if (!prompt_password(use_quantum_pwd, password, sizeof(password))) {
        fprintf(stderr, "Failed to obtain password.\n");
        return 1;
    }

    // Fetch quantum salt
    uint8_t quantum_salt[32];
    if (!qrng_fetch_bytes(quantum_salt, sizeof(quantum_salt))) {
        fprintf(stderr, "Warning: QRNG unavailable, using system entropy.\n");
        if (!read_urandom(quantum_salt, sizeof(quantum_salt))) {
            fprintf(stderr, "Failed to obtain randomness.\n");
            return 1;
        }
    }

    // Derive 256-byte digest
    uint8_t digest[256];
    derive_one_way_digest((const uint8_t *)message, strlen(message),
                          (const uint8_t *)password, strlen(password),
                          quantum_salt, sizeof(quantum_salt),
                          digest);

    // Convert to hex 512 chars
    char hexout[513];
    hex_encode(digest, sizeof(digest), hexout);

    // Replace content in username file atomically
    if (!write_username_file_atomic(username, hexout)) {
        fprintf(stderr, "Failed to write output file.\n");
        secure_zero(password, strlen(password));
        secure_zero(digest, sizeof(digest));
        return 1;
    }

    // Wipe sensitive buffers
    secure_zero(password, strlen(password));
    secure_zero(digest, sizeof(digest));

    printf("Encrypted output written to %s.txt (512 hex chars).\n", username);
    return 0;
}
