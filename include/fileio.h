#ifndef FILEIO_H
#define FILEIO_H

#include <stdbool.h>
#include <stddef.h>

bool write_username_file_atomic(const char *username, const char *content);
bool read_file(const char *path, char *buffer, size_t buffer_size, size_t *out_len);

#endif // FILEIO_H
