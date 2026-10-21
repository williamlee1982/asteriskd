# Host-side tests for asteriskd. Not part of the Android build: BuildAsteriskdTask
# only compiles the top-level *.c files of the source root.
CC ?= gcc
CFLAGS ?= -std=gnu17 -O0 -g -Wall -Wextra -Wno-unused-function -DASTERISKD_TESTING -I..
LDLIBS ?= -ldl
SRC_DIR := ..
LIB_SOURCES := $(filter-out $(SRC_DIR)/asteriskd.c,$(wildcard $(SRC_DIR)/*.c))
NO_RUNTIME := $(filter-out $(SRC_DIR)/asteriskd_runtime.c,$(LIB_SOURCES))
BUILD := build

all: $(BUILD)/unit_test $(BUILD)/runtime_test

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/unit_test: unit_test.c test_support.h $(LIB_SOURCES) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ unit_test.c $(LIB_SOURCES) $(LDLIBS)

$(BUILD)/runtime_test: runtime_test.c test_support.h $(LIB_SOURCES) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ runtime_test.c $(NO_RUNTIME) $(LDLIBS)

check: all
	./$(BUILD)/unit_test
	./$(BUILD)/runtime_test

clean:
	rm -rf $(BUILD)

.PHONY: all check clean
