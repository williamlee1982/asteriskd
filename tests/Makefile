# Host-side tests for asteriskd. Not part of the Android build: the parent
# project compiles every .c under the source root and its module directories.
CC ?= gcc
CFLAGS ?= -std=gnu17 -O0 -g -Wall -Wextra -Wno-unused-function -DASTERISKD_TESTING -I..
LDLIBS ?= -ldl
SRC_DIR := ..
LIB_SOURCES := $(filter-out $(SRC_DIR)/asteriskd.c,$(wildcard $(SRC_DIR)/core/*.c) $(wildcard $(SRC_DIR)/network/*.c) $(wildcard $(SRC_DIR)/process/*.c) $(wildcard $(SRC_DIR)/resources/*.c) $(wildcard $(SRC_DIR)/rules/*.c) $(wildcard $(SRC_DIR)/runtime/*.c) $(wildcard $(SRC_DIR)/service/*.c) $(wildcard $(SRC_DIR)/supervisor/*.c))
BUILD := build

all: $(BUILD)/unit_test $(BUILD)/runtime_test

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/unit_test: unit_test.c test_support.h $(LIB_SOURCES) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ unit_test.c $(LIB_SOURCES) $(LDLIBS)

$(BUILD)/runtime_test: runtime_test.c test_support.h $(LIB_SOURCES) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ runtime_test.c $(LIB_SOURCES) $(LDLIBS)

check: all
	./$(BUILD)/unit_test
	./$(BUILD)/runtime_test

clean:
	rm -rf $(BUILD)

.PHONY: all check clean
