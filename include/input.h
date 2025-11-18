#ifndef INPUT_H
#define INPUT_H

#include <stdbool.h>
#include <stddef.h>

#define MAX_USERNAME_LEN 64
#define MAX_MESSAGE_LEN 4096
#define MAX_PASSWORD_LEN 256

bool prompt_username(char *out_username, size_t out_size);
bool prompt_message(char *out_message, size_t out_size);
bool prompt_yes_no(const char *question, bool default_yes);
bool prompt_password(bool generate_quantum, char *out_password, size_t out_size);

bool is_strong_password(const char *password);

#endif // INPUT_H
