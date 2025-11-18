#define _POSIX_C_SOURCE 200809L
#include "fileio.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static bool build_user_filepath(const char *username, char *out_path, size_t out_size) {
    if (!username || !out_path || out_size < 8) return false;
    int n = snprintf(out_path, out_size, "%s.txt", username);
    return n > 0 && (size_t)n < out_size;
}

bool write_username_file_atomic(const char *username, const char *content) {
    if (!username || !content) return false;
    char path[256];
    if (!build_user_filepath(username, path, sizeof(path))) return false;

    // Create temp file
    char tmp_template[300];
    int n = snprintf(tmp_template, sizeof(tmp_template), "%s.tmpXXXXXX", path);
    if (n <= 0 || (size_t)n >= sizeof(tmp_template)) return false;

    int fd = mkstemp(tmp_template);
    if (fd < 0) return false;

    size_t len = strlen(content);
    ssize_t written_total = 0;
    while ((size_t)written_total < len) {
        ssize_t w = write(fd, content + written_total, len - (size_t)written_total);
        if (w < 0) {
            if (errno == EINTR) continue;
            close(fd);
            unlink(tmp_template);
            return false;
        }
        written_total += w;
    }
    // Ensure newline at end
    const char nl = '\n';
    if (write(fd, &nl, 1) != 1) {
        close(fd);
        unlink(tmp_template);
        return false;
    }

    // fsync to ensure content is on disk
    if (fsync(fd) != 0) {
        close(fd);
        unlink(tmp_template);
        return false;
    }

    if (close(fd) != 0) {
        unlink(tmp_template);
        return false;
    }

    // Atomically replace
    if (rename(tmp_template, path) != 0) {
        unlink(tmp_template);
        return false;
    }

    return true;
}

bool read_file(const char *path, char *buffer, size_t buffer_size, size_t *out_len) {
    if (!path || !buffer || buffer_size == 0) return false;
    FILE *f = fopen(path, "rb");
    if (!f) return false;
    size_t n = fread(buffer, 1, buffer_size - 1, f);
    buffer[n] = '\0';
    if (out_len) *out_len = n;
    fclose(f);
    return true;
}
