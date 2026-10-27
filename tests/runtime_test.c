// Copyright 2026, AsteriskMETA contributors
// SPDX-License-Identifier: GPL-3.0
//
// Exercises the real TPROXY rule emitter against the iptables-restore batch
// and a fake rtnetlink ip hook (upstream no longer shells out to ip/iptables
// for these paths).
#include "supervisor/supervisor.h"
#include "test_support.h"

#include <signal.h>

static struct asteriskd_system_supervisor *test_system;

static struct asteriskd_system_supervisor *new_system(void) {
    struct asteriskd_system_supervisor *system = calloc(1U, sizeof(*system));
    struct asteriskd_config *config = &system->loaded_config.config;
    config->mode = ASTERISKD_MODE_TPROXY;
    config->owner = ASTERISKD_OWNER_META;
    config->core_type = ASTERISKD_CORE_MIHOMO;
    config->has_transparent_port = true;
    config->transparent_port = 7895U;
    config->enable_local_dns = true;
    config->app_policy_mode = ASTERISKD_APP_POLICY_GLOBAL;
    system->local_address_snapshot_active = true;
    system->local_ipv4_snapshot.family = ASTERISKD_ADDRESS_IPV4;
    system->local_ipv6_snapshot.family = ASTERISKD_ADDRESS_IPV6;
    system->rule_commands.active = true;
    system->tproxy_capabilities_known = true;
    system->tproxy_capabilities.socket_match_ipv4 = true;
    system->tproxy_capabilities.socket_match_ipv6 = true;
    system->tproxy_capabilities.ipv6_available = true;
    test_system = system;
    return system;
}

static void add_cidr(char (*list)[ASTERISKD_MAX_CIDR], size_t *count, const char *cidr) {
    snprintf(list[*count], ASTERISKD_MAX_CIDR, "%s", cidr);
    ++*count;
}

static char batch_storage[65536];

static const char *batch_text(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family) {
    struct asteriskd_byte_buffer *batch =
        &system->rule_commands.xtables[0][family][ASTERISKD_IP_TABLE_MANGLE];
    size_t length = batch->bytes == NULL ? 0U : batch->length;
    if (length >= sizeof(batch_storage)) length = sizeof(batch_storage) - 1U;
    if (length != 0U) memcpy(batch_storage, batch->bytes, length);
    batch_storage[length] = '\0';
    return batch_storage;
}

static const char *populate(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *chain) {
    struct asteriskd_private_chain_group group;
    memset(&group, 0, sizeof(group));
    group.family = family;
    group.table = ASTERISKD_IP_TABLE_MANGLE;
    group.chain_id = ASTERISKD_CHAIN_TPROXY;
    CHECK(asteriskd_test_populate_private_chain(system, &group, chain) == 0);
    return batch_text(system, family);
}

static void free_system(struct asteriskd_system_supervisor *system) {
    asteriskd_supervisor_rule_batch_destroy(&system->rule_commands);
    free(system);
}

/* Closes the RootTailnetPrivateRoutingTest gap: the real emitter keeps a
 * user /32 inside 100.64/10 proxied while the rest of the tailnet range
 * returns before the catch-all. */
static void test_tailnet_bypass_order_output(void) {
    struct asteriskd_system_supervisor *s = new_system();
    struct asteriskd_config *c = &s->loaded_config.config;
    add_cidr(c->proxy_private_cidrs, &c->proxy_private_cidr_count, "100.100.100.100/32");
    add_cidr(c->bypass_private_cidrs, &c->bypass_private_cidr_count, "100.64.0.0/10");
    add_cidr(c->bypass_private_cidrs, &c->bypass_private_cidr_count, "192.168.0.0/16");
    const char *text = populate(s, ASTERISKD_IP_FAMILY_IPV4, "ASTERISK_TPROXY_OUTPUT");
    long proxied = text_index(text, "-d 100.100.100.100/32 -p tcp");
    long bypass = text_index(text, "-d 100.64.0.0/10 -j RETURN");
    long catch_all = text_index(text, "-A ASTERISK_TPROXY_OUTPUT -p tcp -j MARK");
    CHECK(proxied >= 0);
    CHECK(bypass > proxied);
    CHECK(catch_all > bypass);
    free_system(s);
}

static void test_tailnet_bypass_order_prerouting(void) {
    struct asteriskd_system_supervisor *s = new_system();
    struct asteriskd_config *c = &s->loaded_config.config;
    add_cidr(c->proxy_private_cidrs, &c->proxy_private_cidr_count, "100.100.100.100/32");
    add_cidr(c->bypass_private_cidrs, &c->bypass_private_cidr_count, "100.64.0.0/10");
    const char *text = populate(s, ASTERISKD_IP_FAMILY_IPV4, "ASTERISK_TPROXY_PREROUTING");
    long proxied = text_index(text, "-d 100.100.100.100/32 -p udp -m mark");
    long bypass = text_index(text, "-d 100.64.0.0/10 -j RETURN");
    long catch_all = text_index(text, "-A ASTERISK_TPROXY_PREROUTING -p tcp -m mark");
    CHECK(proxied >= 0);
    CHECK(bypass > proxied);
    CHECK(catch_all > bypass);
    free_system(s);
}

/* The document AsteriskMETA's encoder emits for the tailnet fixture
 * (RootTailnetPrivateRoutingTest asserts byte equality with this file) goes
 * through the daemon's real config parser and the real rule emitter. */
static struct asteriskd_system_supervisor *system_from_fixture(const char *path) {
    struct asteriskd_system_supervisor *s = new_system();
    FILE *file = fopen(path, "rb");
    CHECK(file != NULL);
    if (file == NULL) return s;
    static char json[65536];
    size_t length = fread(json, 1U, sizeof(json) - 1U, file);
    fclose(file);
    json[length] = '\0';
    char message[256] = "";
    struct asteriskd_config *c = &s->loaded_config.config;
    memset(c, 0, sizeof(*c));
    int parsed = asteriskd_config_parse(json, length, c, message, sizeof(message));
    if (parsed != 0) fprintf(stderr, "fixture parse: %s\n", message);
    CHECK(parsed == 0);
    return s;
}

static void test_tailnet_fixture_from_app_encoder(void) {
    struct asteriskd_system_supervisor *s = system_from_fixture("fixtures/tailnet-tproxy.json");
    CHECK(s->loaded_config.config.mode == ASTERISKD_MODE_TPROXY);
    const char *text = populate(s, ASTERISKD_IP_FAMILY_IPV4, "ASTERISK_TPROXY_OUTPUT");
    long proxied = text_index(text, "-d 100.101.102.103/32 -p tcp");
    long bypass = text_index(text, "-d 100.64.0.0/10 -j RETURN");
    long catch_all = text_index(text, "-A ASTERISK_TPROXY_OUTPUT -p tcp -j MARK");
    CHECK(proxied >= 0);
    CHECK(bypass > proxied);
    CHECK(catch_all > bypass);
    free_system(s);

    s = system_from_fixture("fixtures/tailnet-tproxy.json");
    text = populate(s, ASTERISKD_IP_FAMILY_IPV6, "ASTERISK_TPROXY_OUTPUT");
    proxied = text_index(text, "-d fd7a:115c:a1e0::abcd/128 -p tcp");
    bypass = text_index(text, "-d fc00::/7 -j RETURN");
    CHECK(proxied >= 0);
    CHECK(bypass > proxied);
    CHECK(text_index(text, "100.101.102.103") < 0);
    free_system(s);
}

/* H5: established transparent-socket guard before the general TPROXY rule. */
static void test_socket_transparent_guard_both_families(void) {
    for (int f = 0; f < 2; ++f) {
        struct asteriskd_system_supervisor *s = new_system();
        s->loaded_config.config.enable_ipv6 = true;
        enum asteriskd_ip_family family = f ? ASTERISKD_IP_FAMILY_IPV6 : ASTERISKD_IP_FAMILY_IPV4;
        const char *chain = f ? "ASTERISK_TPROXY6_PREROUTING" : "ASTERISK_TPROXY_PREROUTING";
        const char *text = populate(s, family, chain);
        char mark[160], ret[160], general[160];
        snprintf(mark, sizeof(mark), "-A %s -p tcp -m socket --transparent -j MARK --set-xmark 0x20000000/0x60000000", chain);
        snprintf(ret, sizeof(ret), "-A %s -p tcp -m socket --transparent -j RETURN", chain);
        snprintf(general, sizeof(general), "-A %s -p tcp -m mark --mark 0x20000000/0x60000000 -j TPROXY", chain);
        long m = text_index(text, mark), r = text_index(text, ret), g = text_index(text, general);
        CHECK(m >= 0);
        CHECK(r > m);
        CHECK(g > r);
        free_system(s);
    }
}

static void test_socket_guard_skipped_without_xt_socket(void) {
    struct asteriskd_system_supervisor *s = new_system();
    s->tproxy_capabilities.socket_match_ipv4 = false;
    const char *text = populate(s, ASTERISKD_IP_FAMILY_IPV4, "ASTERISK_TPROXY_PREROUTING");
    CHECK_NOT_CONTAINS(text, "--transparent");
    free_system(s);
}

/* H6: core-GID packets carrying the Asterisk primary bit lose it before RETURN. */
static void test_core_gid_clears_primary_mark(void) {
    struct asteriskd_system_supervisor *s = new_system();
    const char *text = populate(s, ASTERISKD_IP_FAMILY_IPV4, "ASTERISK_TPROXY_OUTPUT");
    long clear = text_index(text, "-m owner --gid-owner 3005 -m mark --mark 0x20000000/0x60000000 -j MARK --set-xmark 0x0/0x60000000");
    long ret = text_index(text, "-m owner --gid-owner 3005 -j RETURN");
    CHECK(clear >= 0);
    CHECK(ret > clear);
    free_system(s);
}

/* M4: optional encrypted-DNS (853) block for non-core local traffic. */
static void test_block_encrypted_dns_when_enabled(void) {
    struct asteriskd_system_supervisor *s = new_system();
    s->loaded_config.config.block_encrypted_dns = true;
    uint32_t bypass[] = {10123U};
    s->loaded_config.config.bypass_uids = bypass;
    s->loaded_config.config.bypass_uid_count = 1U;
    const char *text = populate(s, ASTERISKD_IP_FAMILY_IPV4, "ASTERISK_TPROXY_OUTPUT");
    long forced = text_index(text, "--uid-owner 10123 -j RETURN");
    long tcp = text_index(text, "-p tcp -m owner ! --gid-owner 3005 -m tcp --dport 853 -j DROP");
    long udp = text_index(text, "-p udp -m owner ! --gid-owner 3005 -m udp --dport 853 -j DROP");
    long catch_all = text_index(text, "-A ASTERISK_TPROXY_OUTPUT -p tcp -j MARK");
    CHECK(forced >= 0);
    CHECK(tcp > forced);
    CHECK(udp > forced);
    CHECK(catch_all > tcp);
    s->loaded_config.config.bypass_uids = NULL;
    s->loaded_config.config.bypass_uid_count = 0U;
    free_system(s);
    s = new_system();
    text = populate(s, ASTERISKD_IP_FAMILY_IPV4, "ASTERISK_TPROXY_OUTPUT");
    CHECK_NOT_CONTAINS(text, "853");
    free_system(s);
    /* No local DNS enforcement => nothing to fall back to => no block. */
    s = new_system();
    s->loaded_config.config.block_encrypted_dns = true;
    s->loaded_config.config.enable_local_dns = false;
    text = populate(s, ASTERISKD_IP_FAMILY_IPV4, "ASTERISK_TPROXY_OUTPUT");
    CHECK_NOT_CONTAINS(text, "853");
    free_system(s);
}

static void test_block_encrypted_dns_ipv6_dns_only_path(void) {
    struct asteriskd_system_supervisor *s = new_system();
    s->loaded_config.config.block_encrypted_dns = true;
    const char *text = populate(s, ASTERISKD_IP_FAMILY_IPV6, "ASTERISK_TPROXY6_OUTPUT");
    CHECK_CONTAINS(text, "-p tcp -m owner ! --gid-owner 3005 -m tcp --dport 853 -j DROP");
    free_system(s);
}

/* H3: the OUTPUT hook is inserted at the head of mangle OUTPUT. */
static void test_output_hook_inserted_at_head(void) {
    struct asteriskd_system_supervisor *s = new_system();
    struct asteriskd_rule_transaction_plan plan;
    memset(&plan, 0, sizeof(plan));
    CHECK(asteriskd_tproxy_rule_transaction_plan_build(&s->loaded_config.config, false, &plan) == 0);
    CHECK(plan.hook_group_count >= 1U);
    CHECK(asteriskd_supervisor_apply_hook_group(s, &plan.hook_groups[0]) == 0);
    const char *text = batch_text(s, ASTERISKD_IP_FAMILY_IPV4);
    CHECK_CONTAINS(text, "-I OUTPUT 1 -j ASTERISK_TPROXY_OUTPUT");
    CHECK_CONTAINS(text, "-I PREROUTING 1 -j ASTERISK_TPROXY_PREROUTING");
    free_system(s);
}

static void test_hook_order_warning_detects_non_head(void) {
    static const char good[] =
        "-P OUTPUT ACCEPT\n-A OUTPUT -j ASTERISK_TPROXY_OUTPUT\n-A OUTPUT -j oem_out\n";
    static const char bad[] =
        "-P OUTPUT ACCEPT\n-A OUTPUT -j other_vpn\n-A OUTPUT -j ASTERISK_TPROXY_OUTPUT\n";
    struct asteriskd_system_supervisor *s = new_system();
    struct asteriskd_rule_transaction_plan plan;
    memset(&plan, 0, sizeof(plan));
    CHECK(asteriskd_tproxy_rule_transaction_plan_build(&s->loaded_config.config, false, &plan) == 0);
    const struct asteriskd_traffic_hook_group *group = &plan.hook_groups[0];
    size_t misplaced = 99U;
    CHECK(asteriskd_test_hook_group_order_check(group, ASTERISKD_BUILTIN_OUTPUT, good, sizeof(good) - 1U, &misplaced) == 0);
    CHECK(misplaced == 0U);
    CHECK(asteriskd_test_hook_group_order_check(group, ASTERISKD_BUILTIN_OUTPUT, bad, sizeof(bad) - 1U, &misplaced) == 0);
    CHECK(misplaced == 1U);
    free_system(s);
}

/* M3: the IPv6 DNS-only path is skipped when the IPv6 stack is unavailable. */
static void test_ipv6_dns_only_path_skipped_when_unavailable(void) {
    struct asteriskd_system_supervisor *s = new_system();
    struct asteriskd_rule_transaction_plan plan;
    memset(&plan, 0, sizeof(plan));
    CHECK(asteriskd_tproxy_rule_transaction_plan_build(&s->loaded_config.config, false, &plan) == 0);
    size_t with_ipv6 = plan.private_group_count;
    s->loaded_config.config.tproxy_ipv6_unavailable = true;
    memset(&plan, 0, sizeof(plan));
    CHECK(asteriskd_tproxy_rule_transaction_plan_build(&s->loaded_config.config, false, &plan) == 0);
    CHECK(with_ipv6 == 4U);
    CHECK(plan.private_group_count == 2U);
    for (size_t i = 0; i < plan.route_count; ++i) CHECK(plan.routes[i].family == ASTERISKD_IP_FAMILY_IPV4);
    free_system(s);
}

/* H2: optional capture of explicitly bound sockets adds a rule before netd 13000. */
static void test_capture_bound_networks_adds_early_rule(void) {
    struct asteriskd_system_supervisor *s = new_system();
    struct asteriskd_config *c = &s->loaded_config.config;
    c->enable_local_dns = false;
    struct asteriskd_rule_transaction_plan plan;
    memset(&plan, 0, sizeof(plan));
    CHECK(asteriskd_rule_transaction_plan_build(c, false, &plan) == 0);
    for (size_t i = 0; i < plan.route_count; ++i) CHECK(plan.routes[i].priority != ASTERISKD_CAPTURE_ROUTE_RULE_PRIORITY);
    c->capture_bound_networks = true;
    memset(&plan, 0, sizeof(plan));
    CHECK(asteriskd_rule_transaction_plan_build(c, false, &plan) == 0);
    size_t early = 0U;
    for (size_t i = 0; i < plan.route_count; ++i) {
        const struct asteriskd_route_effect *r = &plan.routes[i];
        if (r->kind == ASTERISKD_ROUTE_EFFECT_IP_RULE && r->priority == ASTERISKD_CAPTURE_ROUTE_RULE_PRIORITY) {
            ++early;
            CHECK(r->mark == ASTERISKD_PRIMARY_MARK && r->mark_mask == ASTERISKD_MARK_MASK);
            CHECK(r->table == ASTERISKD_TPROXY_TABLE);
        }
    }
    CHECK(early == 1U); /* IPv4 only: IPv6 proxying off and local DNS off */
    CHECK(ASTERISKD_CAPTURE_ROUTE_RULE_PRIORITY < 13000U);
    CHECK(ASTERISKD_CAPTURE_ROUTE_RULE_PRIORITY > 12500U);
    const struct asteriskd_owned_resource_catalog *catalog = asteriskd_owned_resource_catalog();
    size_t owned = 0U;
    for (size_t i = 0; i < catalog->policy_rule_count; ++i)
        if (catalog->policy_rules[i].priority == ASTERISKD_CAPTURE_ROUTE_RULE_PRIORITY) ++owned;
    CHECK(owned == 2U);
    free_system(s);
}

/* M6: reconcile deletes only owned routes; foreign routes survive. */
static char fake_stdout[4096];
static char fake_log[8192];
static bool fake_missing_table;
static int fake_ip(struct asteriskd_system_supervisor *system,
    enum asteriskd_ip_family family, const char *const *argv, size_t argument_count,
    bool capture, int *exit_status) {
    strncat(fake_log, family == ASTERISKD_IP_FAMILY_IPV6 ? "-6 " : "-4 ",
        sizeof(fake_log) - strlen(fake_log) - 1U);
    for (size_t i = 0; i < argument_count; ++i) {
        strncat(fake_log, argv[i], sizeof(fake_log) - strlen(fake_log) - 2U);
        strncat(fake_log, " ", sizeof(fake_log) - strlen(fake_log) - 2U);
    }
    strncat(fake_log, "\n", sizeof(fake_log) - strlen(fake_log) - 1U);
    system->action_stdout_length = 0U;
    system->action_stdout_overflow = false;
    bool show = false;
    bool del = false;
    for (size_t i = 0; i < argument_count; ++i) {
        if (strcmp(argv[i], "show") == 0) show = true;
        if (strcmp(argv[i], "del") == 0) del = true;
    }
    if (del) {
        /* Simulate the kernel: drop the first owned-looking default line. */
        char *line = strstr(fake_stdout, "default dev ");
        if (line != NULL) {
            while (line > fake_stdout && line[-1] != '\n') --line;
            char *end = strchr(line, '\n');
            end = end == NULL ? line + strlen(line) : end + 1;
            memmove(line, end, strlen(end) + 1U);
        }
    }
    if (capture && show) {
        size_t n = strlen(fake_stdout);
        memcpy(system->action_stdout, fake_stdout, n);
        system->action_stdout_length = n;
    }
    *exit_status = show && fake_stdout[0] == '\0' && fake_missing_table ? 2 : 0;
    return 0;
}

static void test_route_reconcile_keeps_foreign_routes(void) {
    struct asteriskd_system_supervisor *s = new_system();
    s->rule_commands.active = false;
    asteriskd_test_ip_hook = fake_ip;
    fake_log[0] = '\0';
    snprintf(fake_stdout, sizeof(fake_stdout), "%s",
        "local default dev lo scope host\n10.8.0.0/24 dev tun9 scope link\n");
    CHECK(asteriskd_test_reconcile_route_table(s, ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TPROXY_TABLE, true) == 0);
    CHECK_NOT_CONTAINS(fake_log, "flush");
    CHECK_CONTAINS(fake_log, "route del local default dev lo table 160");
    CHECK_NOT_CONTAINS(fake_log, "10.8.0.0/24");
    /* Verification counts owned lines only. */
    snprintf(fake_stdout, sizeof(fake_stdout), "%s", "10.8.0.0/24 dev tun9 scope link\n");
    CHECK(asteriskd_test_reconcile_route_table(s, ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TPROXY_TABLE, false) == 0);
    snprintf(fake_stdout, sizeof(fake_stdout), "%s", "local default dev lo scope host\n");
    CHECK(asteriskd_test_reconcile_route_table(s, ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TPROXY_TABLE, false) != 0);
    asteriskd_test_ip_hook = NULL;
    free_system(s);
}

static void test_route_reconcile_tun_table(void) {
    struct asteriskd_system_supervisor *s = new_system();
    s->rule_commands.active = false;
    asteriskd_test_ip_hook = fake_ip;
    fake_log[0] = '\0';
    snprintf(fake_stdout, sizeof(fake_stdout), "%s",
        "default dev tun2socks scope link\ndefault via 192.168.1.1 dev wlan0\n");
    CHECK(asteriskd_test_reconcile_route_table(s, ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_TUN_TABLE, true) == 0);
    CHECK_CONTAINS(fake_log, "-6 route del default dev tun2socks table 168");
    CHECK_NOT_CONTAINS(fake_log, "192.168.1.1");
    asteriskd_test_ip_hook = NULL;
    free_system(s);
}

/* Review follow-up: with a configured tunnel, table 168 routes on other
 * interfaces are foreign even if they have the same shape. */
static void test_route_reconcile_tun_table_matches_configured_tunnel(void) {
    struct asteriskd_system_supervisor *s = new_system();
    s->rule_commands.active = false;
    s->loaded_config.config.has_tunnel_name = true;
    snprintf(s->loaded_config.config.tunnel_name, sizeof(s->loaded_config.config.tunnel_name), "%s", "tun0");
    asteriskd_test_ip_hook = fake_ip;
    fake_log[0] = '\0';
    snprintf(fake_stdout, sizeof(fake_stdout), "%s", "default dev tun7 scope link\n");
    CHECK(asteriskd_test_reconcile_route_table(s, ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TUN_TABLE, true) == 0);
    CHECK_NOT_CONTAINS(fake_log, " del ");
    snprintf(fake_stdout, sizeof(fake_stdout), "%s", "default dev tun0 scope link\ndefault dev tun7 scope link\n");
    fake_log[0] = '\0';
    CHECK(asteriskd_test_reconcile_route_table(s, ASTERISKD_IP_FAMILY_IPV4, ASTERISKD_TUN_TABLE, true) == 0);
    CHECK_CONTAINS(fake_log, "route del default dev tun0 table 168");
    CHECK_NOT_CONTAINS(fake_log, "dev tun7 table");
    asteriskd_test_ip_hook = NULL;
    free_system(s);
}

/* Review follow-up: a dead guard must not SIGPIPE the supervisor. */
static void test_guard_release_survives_dead_guard(void) {
    struct asteriskd_system_supervisor *s = new_system();
    int fds[2];
    CHECK(pipe(fds) == 0);
    close(fds[0]);
    s->guard_fd = fds[1];
    asteriskd_test_guard_release(s, true);
    CHECK(s->guard_fd == -1);
    sigset_t pending;
    sigemptyset(&pending);
    CHECK(sigpending(&pending) == 0);
    CHECK(!sigismember(&pending, SIGPIPE));
    free_system(s);
}

static void test_route_reconcile_missing_table_is_clean(void) {
    struct asteriskd_system_supervisor *s = new_system();
    s->rule_commands.active = false;
    asteriskd_test_ip_hook = fake_ip;
    fake_log[0] = '\0';
    fake_stdout[0] = '\0';
    fake_missing_table = true;
    CHECK(asteriskd_test_reconcile_route_table(s, ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_TPROXY_TABLE, true) == 0);
    CHECK(asteriskd_test_reconcile_route_table(s, ASTERISKD_IP_FAMILY_IPV6, ASTERISKD_TPROXY_TABLE, false) == 0);
    CHECK_NOT_CONTAINS(fake_log, " del ");
    fake_missing_table = false;
    asteriskd_test_ip_hook = NULL;
    free_system(s);
}

int main(void) {
    static const struct test_case cases[] = {
        {"tailnet_bypass_order_output", test_tailnet_bypass_order_output},
        {"tailnet_bypass_order_prerouting", test_tailnet_bypass_order_prerouting},
        {"tailnet_fixture_from_app_encoder", test_tailnet_fixture_from_app_encoder},
        {"socket_transparent_guard_both_families", test_socket_transparent_guard_both_families},
        {"socket_guard_skipped_without_xt_socket", test_socket_guard_skipped_without_xt_socket},
        {"core_gid_clears_primary_mark", test_core_gid_clears_primary_mark},
        {"block_encrypted_dns_when_enabled", test_block_encrypted_dns_when_enabled},
        {"block_encrypted_dns_ipv6_dns_only_path", test_block_encrypted_dns_ipv6_dns_only_path},
        {"output_hook_inserted_at_head", test_output_hook_inserted_at_head},
        {"hook_order_warning_detects_non_head", test_hook_order_warning_detects_non_head},
        {"ipv6_dns_only_path_skipped_when_unavailable", test_ipv6_dns_only_path_skipped_when_unavailable},
        {"capture_bound_networks_adds_early_rule", test_capture_bound_networks_adds_early_rule},
        {"route_reconcile_keeps_foreign_routes", test_route_reconcile_keeps_foreign_routes},
        {"route_reconcile_tun_table", test_route_reconcile_tun_table},
        {"route_reconcile_missing_table_is_clean", test_route_reconcile_missing_table_is_clean},
        {"route_reconcile_tun_table_matches_configured_tunnel", test_route_reconcile_tun_table_matches_configured_tunnel},
        {"guard_release_survives_dead_guard", test_guard_release_survives_dead_guard},
    };
    return run_tests("runtime", cases, sizeof(cases) / sizeof(cases[0]));
}
