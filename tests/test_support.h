// Copyright 2026, AsteriskMETA contributors
// SPDX-License-Identifier: GPL-3.0
#ifndef ASTERISKD_TEST_SUPPORT_H
#define ASTERISKD_TEST_SUPPORT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int test_failures;
static int test_checks;

#define CHECK(condition) do { \
    ++test_checks; \
    if (!(condition)) { \
        ++test_failures; \
        fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #condition); \
    } \
} while (0)

#define CHECK_CONTAINS(haystack, needle) do { \
    ++test_checks; \
    if (strstr((haystack), (needle)) == NULL) { \
        ++test_failures; \
        fprintf(stderr, "%s:%d: expected to contain: %s\n", __FILE__, __LINE__, (needle)); \
    } \
} while (0)

#define CHECK_NOT_CONTAINS(haystack, needle) do { \
    ++test_checks; \
    if (strstr((haystack), (needle)) != NULL) { \
        ++test_failures; \
        fprintf(stderr, "%s:%d: expected NOT to contain: %s\n", __FILE__, __LINE__, (needle)); \
    } \
} while (0)

typedef void (*test_fn)(void);
struct test_case { const char *name; test_fn fn; };

static int run_tests(const char *suite, const struct test_case *cases, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        int before = test_failures;
        cases[i].fn();
        printf("%s %s.%s\n", test_failures == before ? "PASS" : "FAIL", suite, cases[i].name);
    }
    printf("%s: %zu tests, %d checks, %d failures\n", suite, count, test_checks, test_failures);
    return test_failures == 0 ? 0 : 1;
}

/* Position of needle in haystack, or -1. */
static long text_index(const char *haystack, const char *needle) {
    const char *found = strstr(haystack, needle);
    return found == NULL ? -1L : (long)(found - haystack);
}

#endif
