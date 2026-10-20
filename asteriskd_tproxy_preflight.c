// Copyright 2026, AsteriskMETA contributors
// SPDX-License-Identifier: GPL-3.0
//
// TPROXY capability preflight, strict listener readiness parsing and the
// supervisor death guard decision. Pure functions; I/O stays in the runtime.

#include "asteriskd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool asteriskd_guard_should_cleanup(long read_result, int byte) {
    return !(read_result == 1 && byte == ASTERISKD_GUARD_ORDERLY_EXIT);
}

static const char *skip_spaces(const char *cursor, const char *end) {
    while (cursor < end && (*cursor == ' ' || *cursor == '\t')) ++cursor;
    return cursor;
}

static const char *token_end(const char *cursor, const char *end) {
    while (cursor < end && *cursor != ' ' && *cursor != '\t') ++cursor;
    return cursor;
}

static bool parse_hex(const char *start, const char *end, unsigned long *value) {
    if (start >= end || end - start > 8) return false;
    unsigned long result = 0UL;
    for (const char *c = start; c < end; ++c) {
        int digit;
        if (*c >= '0' && *c <= '9') digit = *c - '0';
        else if (*c >= 'A' && *c <= 'F') digit = *c - 'A' + 10;
        else if (*c >= 'a' && *c <= 'f') digit = *c - 'a' + 10;
        else return false;
        result = (result << 4U) | (unsigned long)digit;
    }
    *value = result;
    return true;
}

/* Line format: "  sl: LOCAL:PORT REMOTE:PORT ST ..." */
static bool proc_net_line_matches(const char *line, const char *end, uint16_t port, bool udp);

bool asteriskd_proc_net_line_has_socket(const char *line, size_t length, uint16_t port, bool udp) {
    return line != NULL && port != 0U && proc_net_line_matches(line, line + length, port, udp);
}

static bool proc_net_line_matches(const char *line, const char *end, uint16_t port, bool udp) {
    const char *cursor = skip_spaces(line, end);
    const char *sl_end = token_end(cursor, end);
    if (sl_end == cursor || sl_end[-1] != ':') return false;
    const char *local = skip_spaces(sl_end, end);
    const char *local_end = token_end(local, end);
    const char *remote = skip_spaces(local_end, end);
    const char *remote_end = token_end(remote, end);
    const char *state = skip_spaces(remote_end, end);
    const char *state_end = token_end(state, end);
    if (local == local_end || remote == remote_end || state == state_end) return false;
    const char *colon = NULL;
    for (const char *c = local; c < local_end; ++c) if (*c == ':') colon = c;
    unsigned long local_port = 0UL;
    unsigned long socket_state = 0UL;
    if (colon == NULL || !parse_hex(colon + 1, local_end, &local_port) ||
        !parse_hex(state, state_end, &socket_state)) return false;
    return local_port == port && socket_state == (udp ? 0x07UL : 0x0AUL);
}

bool asteriskd_proc_net_has_socket(const char *table, uint16_t port, bool udp) {
    if (table == NULL || port == 0U) return false;
    const char *line = table;
    bool header = true;
    while (*line != '\0') {
        const char *newline = strchr(line, '\n');
        const char *end = newline == NULL ? line + strlen(line) : newline;
        if (!header && asteriskd_proc_net_line_has_socket(line, (size_t)(end - line), port, udp)) {
            return true;
        }
        header = false;
        if (newline == NULL) break;
        line = newline + 1;
    }
    return false;
}

static bool list_has_name(const char *list, const char *name) {
    if (list == NULL) return true; /* unreadable => unknown => do not block */
    size_t length = strlen(name);
    const char *line = list;
    while (*line != '\0') {
        const char *newline = strchr(line, '\n');
        size_t line_length = newline == NULL ? strlen(line) : (size_t)(newline - line);
        while (line_length > 0U && (line[line_length - 1U] == '\r' || line[line_length - 1U] == ' ')) {
            --line_length;
        }
        if (line_length == length && memcmp(line, name, length) == 0) return true;
        if (newline == NULL) break;
        line = newline + 1;
    }
    return false;
}

static void set_text(char *target, size_t size, const char *text) {
    if (target != NULL && size != 0U) (void)snprintf(target, size, "%s", text);
}

static void append_text(char *target, size_t size, const char *text) {
    if (target == NULL || size == 0U) return;
    size_t used = strnlen(target, size);
    if (used + 1U >= size) return;
    (void)snprintf(target + used, size - used, "%s%s", used == 0U ? "" : "; ", text);
}

int asteriskd_tproxy_preflight_evaluate(
    const struct asteriskd_config *config,
    const struct asteriskd_tproxy_preflight_input *input,
    struct asteriskd_tproxy_capabilities *capabilities,
    char *warning, size_t warning_size,
    char *error, size_t error_size) {
    set_text(warning, warning_size, "");
    set_text(error, error_size, "");
    if (config == NULL || input == NULL || capabilities == NULL) return ASTERISKD_CONFIG_INVALID;
    memset(capabilities, 0, sizeof(*capabilities));
    if (!input->have_iptables || !input->have_ip) {
        set_text(error, error_size,
            "TPROXY preflight failed: iptables or ip binary not found; "
            "this ROM cannot run TPROXY mode, use TUN mode");
        return ASTERISKD_CONFIG_UNSUPPORTED_COMBINATION;
    }
    if (!list_has_name(input->ipv4_targets, "TPROXY")) {
        set_text(error, error_size,
            "TPROXY preflight failed: kernel has no TPROXY target (xt_TPROXY); "
            "use TUN or TUN2SOCKS mode");
        return ASTERISKD_CONFIG_UNSUPPORTED_COMBINATION;
    }
    bool ipv6_usable = input->ipv6_stack_present && input->have_ip6tables &&
        list_has_name(input->ipv6_targets, "TPROXY");
    bool ipv6_dns_only = !config->enable_ipv6 && config->enable_local_dns &&
        !config->disable_system_ipv6;
    if (config->enable_ipv6 && !ipv6_usable) {
        set_text(error, error_size,
            "TPROXY preflight failed: IPv6 proxying needs the IPv6 stack, ip6tables and "
            "the IPv6 TPROXY target; disable IPv6 in settings");
        return ASTERISKD_CONFIG_UNSUPPORTED_COMBINATION;
    }
    capabilities->ipv6_available = ipv6_usable;
    if (ipv6_dns_only && !ipv6_usable && input->ipv6_stack_present) {
        /* IPv6 is live but cannot be intercepted: IPv6 DNS would bypass local DNS. */
        set_text(error, error_size,
            "TPROXY preflight failed: IPv6 is active but ip6tables or the IPv6 TPROXY target "
            "is unavailable, so IPv6 DNS would bypass local DNS; enable Disable system IPv6 "
            "or turn off local DNS");
        return ASTERISKD_CONFIG_UNSUPPORTED_COMBINATION;
    }
    if (ipv6_dns_only && !ipv6_usable) {
        append_text(warning, warning_size,
            "IPv6 stack, ip6tables or IPv6 TPROXY unavailable; skipping IPv6 DNS interception");
    }
    capabilities->socket_match_ipv4 = list_has_name(input->ipv4_matches, "socket");
    capabilities->socket_match_ipv6 = ipv6_usable && list_has_name(input->ipv6_matches, "socket");
    if (!capabilities->socket_match_ipv4 || (ipv6_usable && !capabilities->socket_match_ipv6)) {
        append_text(warning, warning_size,
            "xt_socket match unavailable; established transparent-socket guard disabled");
    }
    return 0;
}

bool asteriskd_tproxy_target_listed(const char *targets) {
    return targets != NULL && list_has_name(targets, "TPROXY");
}
