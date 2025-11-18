CC = gcc
CFLAGS = -std=c11 -Wall -Wextra -Wpedantic -O2 -Iinclude
LDFLAGS = 

SRC = \
  src/main.c \
  src/input.c \
  src/fileio.c \
  src/util.c \
  src/sha512.c \
  src/crypto.c \
  src/qrng.c

OBJ = $(SRC:.c=.o)
BIN = bin/qrng_cli

TEST_SRC = \
  tests/test_main.c \
  src/input.c \
  src/fileio.c \
  src/util.c \
  src/sha512.c \
  src/crypto.c \
  src/qrng.c

TEST_OBJ = $(TEST_SRC:.c=.o)
TEST_BIN = bin/tests

.PHONY: all clean test

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

$(TEST_BIN): $(TEST_OBJ)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJ) $(LDFLAGS)

clean:
	rm -f $(OBJ) $(TEST_OBJ) $(BIN) $(TEST_BIN)

format:
	clang-format -i $(SRC) include/*.h tests/*.c || true

test: $(TEST_BIN)
	$(TEST_BIN)
