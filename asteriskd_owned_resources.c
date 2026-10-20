// Copyright 2026, Asterisk4Magisk contributors
// SPDX-License-Identifier: GPL-3.0

#include "asteriskd.h"

#include <string.h>

static const char *const owned_pin_paths[ASTERISKD_PIN_COUNT] = {
    [ASTERISKD_PIN_MATCHER_OUTPUT_V4] =
        "/sys/fs/bpf/asterisk/xt_output_v4",
    [ASTERISKD_PIN_MATCHER_OUTPUT_V6] =
        "/sys/fs/bpf/asterisk/xt_output_v6",
    [ASTERISKD_PIN_MATCHER_PREROUTING_V4] =
        "/sys/fs/bpf/asterisk/xt_prerouting_v4",
    [ASTERISKD_PIN_MATCHER_PREROUTING_V6] =
        "/sys/fs/bpf/asterisk/xt_prerouting_v6",
    [ASTERISKD_PIN_MATCHER_DNS_UID] =
        "/sys/fs/bpf/asterisk/xt_dns_uid",
    [ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V4] =
        "/sys/fs/bpf/asterisk/bpf2socks/local_addr_v4",
    [ASTERISKD_PIN_BPF2SOCKS_LOCAL_ADDRESS_V6] =
        "/sys/fs/bpf/asterisk/bpf2socks/local_addr_v6",
    [ASTERISKD_PIN_BPF2SOCKS_TC_INGRESS] =
        "/sys/fs/bpf/asterisk/bpf2socks/tc_ingress",
    [ASTERISKD_PIN_BPF2SOCKS_TC_EGRESS] =
        "/sys/fs/bpf/asterisk/bpf2socks/tc_egress",
};

static const struct asteriskd_owned_chain owned_chains[] = {
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TPROXY_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TPROXY_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_LOCAL4_BEGIN"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_DNS_UID4"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_LOCAL4_END"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TUN_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TUN_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_FILTER,
        "ASTERISK_TUN_FORWARD"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_NAT,
        "ASTERISK_FAKE_IP_ICMP"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_NAT,
        "ASTERISK_FAKE_IP_ICMP_PRE"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TPROXY6_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TPROXY6_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_LOCAL6_BEGIN"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_DNS_UID6"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_LOCAL6_END"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TUN6_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "ASTERISK_TUN6_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_FILTER,
        "ASTERISK_TUN6_FORWARD"},
};

static const struct asteriskd_owned_hook owned_hooks[] = {
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", false, "ASTERISK_TPROXY_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "OUTPUT", false, "ASTERISK_TPROXY_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", false, "ASTERISK_TPROXY6_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "OUTPUT", false, "ASTERISK_TPROXY6_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", false, "ASTERISK_TUN_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_MANGLE,
        "OUTPUT", false, "ASTERISK_TUN_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_FILTER,
        "FORWARD", false, "ASTERISK_TUN_FORWARD"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", false, "ASTERISK_TUN6_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "OUTPUT", false, "ASTERISK_TUN6_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_FILTER,
        "FORWARD", false, "ASTERISK_TUN6_FORWARD"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_NAT,
        "OUTPUT", false, "ASTERISK_FAKE_IP_ICMP"},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_IP_TABLE_NAT,
        "PREROUTING", false, "ASTERISK_FAKE_IP_ICMP_PRE"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", ASTERISKD_DNS_UDP, "DROP"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_FILTER,
        "INPUT", ASTERISKD_DNS_UDP, "REJECT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_FILTER,
        "FORWARD", ASTERISKD_DNS_UDP, "REJECT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_FILTER,
        "OUTPUT", ASTERISKD_DNS_UDP, "REJECT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", ASTERISKD_DNS_UDP, "ASTERISK_TPROXY6_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "OUTPUT", ASTERISKD_DNS_UDP, "ASTERISK_TPROXY6_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", ASTERISKD_DNS_TCP, "ASTERISK_TPROXY6_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "OUTPUT", ASTERISKD_DNS_TCP, "ASTERISK_TPROXY6_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", ASTERISKD_DNS_UDP, "ASTERISK_TUN6_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "OUTPUT", ASTERISKD_DNS_UDP, "ASTERISK_TUN6_OUTPUT"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "PREROUTING", ASTERISKD_DNS_TCP, "ASTERISK_TUN6_PREROUTING"},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_IP_TABLE_MANGLE,
        "OUTPUT", ASTERISKD_DNS_TCP, "ASTERISK_TUN6_OUTPUT"},
};

static const struct asteriskd_owned_policy_rule owned_policy_rules[] = {
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TPROXY_TABLE, ASTERISKD_DNS_ROUTE_RULE_PRIORITY, ASTERISKD_DNS_PROXY_ROUTE_MARK, ASTERISKD_DNS_MARK_MASK, false},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_TPROXY_TABLE, ASTERISKD_DNS_ROUTE_RULE_PRIORITY, ASTERISKD_DNS_PROXY_ROUTE_MARK, ASTERISKD_DNS_MARK_MASK, false},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TUN_TABLE, ASTERISKD_DNS_ROUTE_RULE_PRIORITY, ASTERISKD_DNS_PROXY_ROUTE_MARK, ASTERISKD_DNS_MARK_MASK, false},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_TUN_TABLE, ASTERISKD_DNS_ROUTE_RULE_PRIORITY, ASTERISKD_DNS_PROXY_ROUTE_MARK, ASTERISKD_DNS_MARK_MASK, false},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TPROXY_TABLE,
        ASTERISKD_ROUTE_RULE_PRIORITY, ASTERISKD_PRIMARY_MARK,
        ASTERISKD_MARK_MASK, false},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_TPROXY_TABLE,
        ASTERISKD_ROUTE_RULE_PRIORITY, ASTERISKD_PRIMARY_MARK,
        ASTERISKD_MARK_MASK, false},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TUN_TABLE,
        ASTERISKD_ROUTE_RULE_PRIORITY, ASTERISKD_PRIMARY_MARK,
        ASTERISKD_MARK_MASK, false},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_TUN_TABLE,
        ASTERISKD_ROUTE_RULE_PRIORITY, ASTERISKD_PRIMARY_MARK,
        ASTERISKD_MARK_MASK, false},
    {ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TPROXY_TABLE,
        ASTERISKD_CAPTURE_ROUTE_RULE_PRIORITY, ASTERISKD_PRIMARY_MARK,
        ASTERISKD_MARK_MASK, false},
    {ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_TPROXY_TABLE,
        ASTERISKD_CAPTURE_ROUTE_RULE_PRIORITY, ASTERISKD_PRIMARY_MARK,
        ASTERISKD_MARK_MASK, false},
};

static const struct asteriskd_owned_resource_catalog owned_resource_catalog = {
    .bpf_root = "/sys/fs/bpf/asterisk",
    .b2s_root = "/sys/fs/bpf/asterisk/bpf2socks",
    .fake_dns_output_chain = "ASTERISK_FAKE_IP_ICMP",
    .fake_dns_prerouting_chain = "ASTERISK_FAKE_IP_ICMP_PRE",
    .chains = owned_chains,
    .chain_count = sizeof(owned_chains) / sizeof(owned_chains[0]),
    .hooks = owned_hooks,
    .hook_count = sizeof(owned_hooks) / sizeof(owned_hooks[0]),
    .policy_rules = owned_policy_rules,
    .policy_rule_count =
        sizeof(owned_policy_rules) / sizeof(owned_policy_rules[0]),
    .token_route = {
        .family = ASTERISKD_IP_FAMILY_IPV6,
        .table = 255U,
        .destination = "fd7a:7374:6572:6973::/64",
        .interface_name = "lo",
    },
};

const struct asteriskd_owned_resource_catalog *asteriskd_owned_resource_catalog(void) {
    return &owned_resource_catalog;
}

const char *asteriskd_owned_pin_path(enum asteriskd_pin_id pin_id) {
    if ((unsigned int)pin_id >= ASTERISKD_PIN_COUNT) return NULL;
    return owned_pin_paths[pin_id];
}

static size_t route_next_token(const char *line, size_t length, size_t offset,
    size_t *start, size_t *end) {
    while (offset < length && (line[offset] == ' ' || line[offset] == '\t')) ++offset;
    *start = offset;
    while (offset < length && line[offset] != ' ' && line[offset] != '\t') ++offset;
    *end = offset;
    return offset;
}

static bool route_token_is(const char *line, size_t start, size_t end, const char *word) {
    size_t length = strlen(word);
    return end - start == length && memcmp(line + start, word, length) == 0;
}

/* Recognize the routes asteriskd installs in its tables:
 *   160: "local default dev lo ..."      168: "default dev <if> ..." (no gateway)
 * Everything else belongs to someone else and must not be deleted. */
bool asteriskd_owned_route_line(uint32_t table, const char *line, size_t length,
    bool *local, char *interface_name, size_t interface_size) {
    if (line == NULL || local == NULL || interface_name == NULL || interface_size == 0U) {
        return false;
    }
    size_t start = 0U, end = 0U, offset = 0U;
    *local = false;
    interface_name[0] = '\0';
    offset = route_next_token(line, length, offset, &start, &end);
    if (route_token_is(line, start, end, "local")) {
        *local = true;
        offset = route_next_token(line, length, offset, &start, &end);
    }
    if (!route_token_is(line, start, end, "default")) return false;
    offset = route_next_token(line, length, offset, &start, &end);
    if (!route_token_is(line, start, end, "dev")) return false;
    offset = route_next_token(line, length, offset, &start, &end);
    size_t name_length = end - start;
    if (name_length == 0U || name_length >= interface_size ||
        name_length >= ASTERISKD_MAX_INTERFACE_NAME) return false;
    memcpy(interface_name, line + start, name_length);
    interface_name[name_length] = '\0';
    while (offset < length) {
        offset = route_next_token(line, length, offset, &start, &end);
        if (start == end) break;
        if (route_token_is(line, start, end, "via") ||
            route_token_is(line, start, end, "nexthop")) return false;
    }
    if (table == ASTERISKD_TPROXY_TABLE) return *local && strcmp(interface_name, "lo") == 0;
    if (table == ASTERISKD_TUN_TABLE) return !*local;
    return false;
}
