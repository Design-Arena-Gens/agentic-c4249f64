#include "input.h"

#include "qrng.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static void trim_newline(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    if (n && s[n - 1] == '\n') s[n - 1] = '\0';
}

static bool valid_username_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '_' || c == '-';
}

bool prompt_username(char *out_username, size_t out_size) {
    if (!out_username || out_size < 2) return false;
    while (1) {
        printf("Enter your username (alnum, -, _): ");
        fflush(stdout);
        if (!fgets(out_username, (int)out_size, stdin)) return false;
        trim_newline(out_username);
        size_t n = strlen(out_username);
        if (n == 0 || n > MAX_USERNAME_LEN) {
            fprintf(stderr, "Invalid length.\n");
            continue;
        }
        bool ok = true;
        for (size_t i = 0; i < n; i++) {
            if (!valid_username_char(out_username[i])) {
                ok = false; break;
            }
        }
        if (!ok) {
            fprintf(stderr, "Invalid characters.\n");
            continue;
        }
        return true;
    }
}

bool prompt_message(char *out_message, size_t out_size) {
    if (!out_message || out_size < 2) return false;
    printf("Enter a short message (max %d chars):\n> ", MAX_MESSAGE_LEN);
    fflush(stdout);
    if (!fgets(out_message, (int)out_size, stdin)) return false;
    trim_newline(out_message);
    return strlen(out_message) > 0;
}

bool prompt_yes_no(const char *question, bool default_yes) {
    char line[8];
    printf("%s [%c/%c]: ", question, default_yes ? 'Y' : 'y', default_yes ? 'n' : 'N');
    fflush(stdout);
    if (!fgets(line, sizeof(line), stdin)) return default_yes;
    trim_newline(line);
    if (line[0] == '\0') return default_yes;
    if (line[0] == 'y' || line[0] == 'Y') return true;
    if (line[0] == 'n' || line[0] == 'N') return false;
    return default_yes;
}

static void set_stdin_echo(int enable) {
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable) tty.c_lflag &= ~(ECHO);
    else tty.c_lflag |= ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &tty);
}

bool is_strong_password(const char *p) {
    if (!p) return false;
    size_t n = strlen(p);
    if (n < 12 || n > MAX_PASSWORD_LEN) return false;
    int has_lower = 0, has_upper = 0, has_digit = 0, has_symbol = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c >= 'a' && c <= 'z') has_lower = 1;
        else if (c >= 'A' && c <= 'Z') has_upper = 1;
        else if (c >= '0' && c <= '9') has_digit = 1;
        else if (isprint(c)) has_symbol = 1;
    }
    return has_lower && has_upper && has_digit && has_symbol;
}

bool prompt_password(bool generate_quantum, char *out_password, size_t out_size) {
    if (!out_password || out_size < 16) return false;
    if (generate_quantum) {
        if (!qrng_generate_password(out_password, out_size)) return false;
        printf("Generated strong quantum-backed password: %s\n", out_password);
        return true;
    }
    while (1) {
        char pwd1[MAX_PASSWORD_LEN + 2];
        char pwd2[MAX_PASSWORD_LEN + 2];
        printf("Enter password: ");
        fflush(stdout);
        set_stdin_echo(0);
        if (!fgets(pwd1, sizeof(pwd1), stdin)) { set_stdin_echo(1); return false; }
        set_stdin_echo(1);
        printf("\n");
        trim_newline(pwd1);

        printf("Confirm password: ");
        fflush(stdout);
        set_stdin_echo(0);
        if (!fgets(pwd2, sizeof(pwd2), stdin)) { set_stdin_echo(1); return false; }
        set_stdin_echo(1);
        printf("\n");
        trim_newline(pwd2);

        if (strcmp(pwd1, pwd2) != 0) {
            fprintf(stderr, "Passwords do not match. Try again.\n");
            continue;
        }
        if (!is_strong_password(pwd1)) {
            fprintf(stderr, "Password must be >=12 chars and include upper, lower, digit, symbol.\n");
            continue;
        }
        strncpy(out_password, pwd1, out_size - 1);
        out_password[out_size - 1] = '\0';
        memset(pwd1, 0, sizeof(pwd1));
        memset(pwd2, 0, sizeof(pwd2));
        return true;
    }
}
