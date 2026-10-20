#include <stdlib.h>
// Copyright 2026, AsteriskMETA contributors
// SPDX-License-Identifier: GPL-3.0
#include "../asteriskd.h"
#include "test_support.h"

/* ---- H1: readiness parser ---------------------------------------------- */
static const char tcp_header[] =
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n";

static void test_tcp_listen_in_local_column(void) {
    char table[1024];
    snprintf(table, sizeof(table), "%s%s", tcp_header,
        "   0: 00000000:1ED7 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n");
    CHECK(asteriskd_proc_net_has_socket(table, 0x1ED7U, false));
}

static void test_tcp_remote_port_does_not_count(void) {
    char table[1024];
    snprintf(table, sizeof(table), "%s%s", tcp_header,
        "   0: 0100007F:9C40 0100007F:1ED7 01 00000000:00000000 00:00000000 00000000     0        0 1 1\n");
    CHECK(!asteriskd_proc_net_has_socket(table, 0x1ED7U, false));
}

static void test_tcp_established_local_port_does_not_count(void) {
    char table[1024];
    snprintf(table, sizeof(table), "%s%s", tcp_header,
        "   0: 0100007F:1ED7 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 1 1\n");
    CHECK(!asteriskd_proc_net_has_socket(table, 0x1ED7U, false));
}

static void test_tcp6_listen(void) {
    char table[1024];
    snprintf(table, sizeof(table), "%s%s", tcp_header,
        "   0: 00000000000000000000000000000000:1ED7 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1\n");
    CHECK(asteriskd_proc_net_has_socket(table, 0x1ED7U, false));
}

static void test_udp_bound_socket(void) {
    char table[1024];
    snprintf(table, sizeof(table), "%s%s", tcp_header,
        "  12: 00000000:1ED7 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 1 2 0\n");
    CHECK(asteriskd_proc_net_has_socket(table, 0x1ED7U, true));
    CHECK(!asteriskd_proc_net_has_socket(table, 0x1ED8U, true));
    CHECK(!asteriskd_proc_net_has_socket(tcp_header, 0x1ED7U, true));
}

/* ---- M3: TPROXY capability preflight ------------------------------------ */
static struct asteriskd_config base_config(void) {
    struct asteriskd_config config;
    memset(&config, 0, sizeof(config));
    config.mode = ASTERISKD_MODE_TPROXY;
    config.enable_local_dns = true;
    return config;
}

static struct asteriskd_tproxy_preflight_input full_input(void) {
    struct asteriskd_tproxy_preflight_input input = {
        .have_iptables = true, .have_ip6tables = true, .have_ip = true,
        .ipv4_targets = "TPROXY\nMARK\n", .ipv6_targets = "TPROXY\nMARK\n",
        .ipv4_matches = "socket\nmark\nowner\n", .ipv6_matches = "socket\nmark\n",
        .ipv6_stack_present = true,
    };
    return input;
}

static void test_preflight_all_present(void) {
    struct asteriskd_config config = base_config();
    struct asteriskd_tproxy_preflight_input input = full_input();
    struct asteriskd_tproxy_capabilities caps;
    char warning[256] = "", error[256] = "";
    CHECK(asteriskd_tproxy_preflight_evaluate(&config, &input, &caps, warning, sizeof(warning), error, sizeof(error)) == 0);
    CHECK(caps.ipv6_available && caps.socket_match_ipv4 && caps.socket_match_ipv6);
    CHECK(warning[0] == '\0');
}

static void test_preflight_missing_tproxy_target_fails(void) {
    struct asteriskd_config config = base_config();
    struct asteriskd_tproxy_preflight_input input = full_input();
    input.ipv4_targets = "MARK\nREJECT\n";
    struct asteriskd_tproxy_capabilities caps;
    char warning[256] = "", error[256] = "";
    CHECK(asteriskd_tproxy_preflight_evaluate(&config, &input, &caps, warning, sizeof(warning), error, sizeof(error)) != 0);
    CHECK_CONTAINS(error, "TPROXY");
}

static void test_preflight_unreadable_targets_is_not_fatal(void) {
    struct asteriskd_config config = base_config();
    struct asteriskd_tproxy_preflight_input input = full_input();
    input.ipv4_targets = NULL;
    input.ipv4_matches = NULL;
    struct asteriskd_tproxy_capabilities caps;
    char warning[256] = "", error[256] = "";
    CHECK(asteriskd_tproxy_preflight_evaluate(&config, &input, &caps, warning, sizeof(warning), error, sizeof(error)) == 0);
    CHECK(caps.socket_match_ipv4);
}

static void test_preflight_missing_iptables_fails(void) {
    struct asteriskd_config config = base_config();
    struct asteriskd_tproxy_preflight_input input = full_input();
    input.have_iptables = false;
    struct asteriskd_tproxy_capabilities caps;
    char warning[256] = "", error[256] = "";
    CHECK(asteriskd_tproxy_preflight_evaluate(&config, &input, &caps, warning, sizeof(warning), error, sizeof(error)) != 0);
    CHECK_CONTAINS(error, "iptables");
}

static void test_preflight_no_ipv6_skips_dns_only_path(void) {
    struct asteriskd_config config = base_config();
    struct asteriskd_tproxy_preflight_input input = full_input();
    input.ipv6_stack_present = false;
    input.have_ip6tables = false;
    struct asteriskd_tproxy_capabilities caps;
    char warning[256] = "", error[256] = "";
    CHECK(asteriskd_tproxy_preflight_evaluate(&config, &input, &caps, warning, sizeof(warning), error, sizeof(error)) == 0);
    CHECK(!caps.ipv6_available);
    CHECK_CONTAINS(warning, "IPv6");
}

/* Review follow-up: an IPv6 stack without usable ip6tables/TPROXY must not
 * silently let IPv6 DNS bypass local DNS. */
static void test_preflight_ipv6_stack_without_ip6tables_fails_closed(void) {
    struct asteriskd_config config = base_config();
    struct asteriskd_tproxy_preflight_input input = full_input();
    input.have_ip6tables = false;
    struct asteriskd_tproxy_capabilities caps;
    char warning[256] = "", error[256] = "";
    CHECK(asteriskd_tproxy_preflight_evaluate(&config, &input, &caps, warning, sizeof(warning), error, sizeof(error)) != 0);
    CHECK_CONTAINS(error, "Disable system IPv6");
    config.disable_system_ipv6 = true;
    CHECK(asteriskd_tproxy_preflight_evaluate(&config, &input, &caps, warning, sizeof(warning), error, sizeof(error)) == 0);
}

static void test_reconcile_report_complete(void) {
    struct asteriskd_reconcile_report report;
    memset(&report, 0, sizeof(report));
    report.failed_phase = ASTERISKD_RECONCILE_PHASE_COUNT;
    report.verified_absent = true;
    CHECK(asteriskd_reconcile_report_complete(&report));
    report.verified_absent = false;
    CHECK(!asteriskd_reconcile_report_complete(&report));
    report.verified_absent = true;
    report.failed_phase = ASTERISKD_RECONCILE_QUIESCE;
    CHECK(!asteriskd_reconcile_report_complete(&report));
    CHECK(!asteriskd_reconcile_report_complete(NULL));
}

static void test_preflight_no_ipv6_with_ipv6_proxy_fails(void) {
    struct asteriskd_config config = base_config();
    config.enable_ipv6 = true;
    struct asteriskd_tproxy_preflight_input input = full_input();
    input.ipv6_targets = "MARK\n";
    struct asteriskd_tproxy_capabilities caps;
    char warning[256] = "", error[256] = "";
    CHECK(asteriskd_tproxy_preflight_evaluate(&config, &input, &caps, warning, sizeof(warning), error, sizeof(error)) != 0);
    CHECK_CONTAINS(error, "IPv6");
}

static void test_preflight_without_xt_socket(void) {
    struct asteriskd_config config = base_config();
    struct asteriskd_tproxy_preflight_input input = full_input();
    input.ipv4_matches = "mark\nowner\n";
    struct asteriskd_tproxy_capabilities caps;
    char warning[256] = "", error[256] = "";
    CHECK(asteriskd_tproxy_preflight_evaluate(&config, &input, &caps, warning, sizeof(warning), error, sizeof(error)) == 0);
    CHECK(!caps.socket_match_ipv4);
    CHECK(caps.socket_match_ipv6);
    CHECK_CONTAINS(warning, "xt_socket");
}

/* ---- H2 / M4: optional network flags ------------------------------------ */
static const char config_prefix[] =
    "{\"schemaVersion\":3,\"owner\":\"asteriskmeta\",\"coreType\":\"mihomo\","
    "\"coreExecutablePath\":\"/data/a/mihomo\",\"coreConfigPath\":\"/data/a/config.yaml\","
    "\"statePath\":\"/data/a/asteriskd.state\",\"logPath\":\"/data/a/logs/asteriskd.log\","
    "\"mode\":\"tproxy\",\"core\":{\"workingDirectory\":\"/data/a\",\"readinessTimeoutMilliseconds\":5000,\"ageSecretKey\":null},"
    "\"network\":{\"enableIpv6\":false,\"disableSystemIpv6\":false,\"enableLocalDns\":true,\"enableFakeDns\":false,"
    "\"fakeDnsIpv4Pool\":null,\"ignoredInterfaces\":[],\"virtualInterfaces\":[],\"hotspotInterfacePrefixes\":[],"
    "\"proxyPrivateCidrs\":[],\"bypassPrivateCidrs\":[\"100.64.0.0/10\"],"
    "\"appPolicy\":{\"mode\":\"global\",\"uids\":[],\"bypassUids\":[],\"directCidrPathV4\":null,\"directCidrPathV6\":null}";
static const char config_suffix[] =
    "},\"modeOptions\":{\"transparentPort\":7895,\"tunnelName\":null},\"matcher\":null,\"helper\":null,"
    "\"serviceControl\":{\"enabled\":false,"
    "\"schedule\":{\"enabled\":false,\"startCron\":\"\",\"stopCron\":\"\"},"
    "\"wifi\":{\"enabled\":false,"
    "\"connectStart\":{\"enabled\":false,\"ssids\":[],\"bssids\":[]},"
    "\"connectStop\":{\"enabled\":false,\"ssids\":[],\"bssids\":[]},"
    "\"disconnectStart\":{\"enabled\":false,\"ssids\":[],\"bssids\":[]},"
    "\"disconnectStop\":{\"enabled\":false,\"ssids\":[],\"bssids\":[]}}}}";

static int parse_with(const char *extra, struct asteriskd_config *config) {
    char json[8192];
    snprintf(json, sizeof(json), "%s%s%s", config_prefix, extra, config_suffix);
    char message[256] = "";
    int result = asteriskd_config_parse(json, strlen(json), config, message, sizeof(message));
    if (result != 0 && getenv("ASTERISKD_TEST_VERBOSE") != NULL) fprintf(stderr, "parse: %s\n", message);
    return result;
}

static void test_config_without_new_flags_still_parses(void) {
    struct asteriskd_config config;
    CHECK(parse_with("", &config) == 0);
    CHECK(!config.capture_bound_networks);
    CHECK(!config.block_encrypted_dns);
    asteriskd_config_destroy(&config);
}

static void test_config_new_flags_parse(void) {
    struct asteriskd_config config;
    CHECK(parse_with(",\"captureBoundNetworks\":true,\"blockEncryptedDns\":true", &config) == 0);
    CHECK(config.capture_bound_networks);
    CHECK(config.block_encrypted_dns);
    asteriskd_config_destroy(&config);
    CHECK(parse_with(",\"captureBoundNetworks\":\"yes\"", &config) != 0);
    CHECK(parse_with(",\"unknownKey\":true", &config) != 0);
}

/* ---- C1: cleanup / guard CLI -------------------------------------------- */
static void test_cli_cleanup_and_guard_parse(void) {
    struct asteriskd_cli_invocation invocation;
    const char *cleanup[] = {"asteriskd", "cleanup", "--config", "/data/a/asteriskd.json", NULL};
    CHECK(asteriskd_cli_parse(4, cleanup, &invocation) == 0);
    CHECK(invocation.command == ASTERISKD_CLI_CLEANUP);
    CHECK(strcmp(invocation.path, "/data/a/asteriskd.json") == 0);
    const char *guard[] = {"asteriskd", "guard", "--config", "/data/a/asteriskd.json", NULL};
    CHECK(asteriskd_cli_parse(4, guard, &invocation) == 0);
    CHECK(invocation.command == ASTERISKD_CLI_GUARD);
    const char *relative[] = {"asteriskd", "cleanup", "--config", "asteriskd.json", NULL};
    CHECK(asteriskd_cli_parse(4, relative, &invocation) != 0);
}

static void test_guard_decision(void) {
    /* EOF without the orderly-exit byte => supervisor died => clean up. */
    CHECK(asteriskd_guard_should_cleanup(0, 0) == true);
    CHECK(asteriskd_guard_should_cleanup(1, 'C') == false);
    CHECK(asteriskd_guard_should_cleanup(-1, 0) == true);
}


/* ---- H1: TPROXY readiness needs TCP LISTEN and a UDP socket ----------- */
static bool fake_tcp_ready, fake_udp_ready;
static int fake_alive(void *c, const struct asteriskd_child_identity *i, bool *alive) {
    (void)c; (void)i; *alive = true; return 0;
}
static int fake_listener(void *c, int pid, uint16_t port, bool *ready) {
    (void)c; (void)pid; (void)port; *ready = fake_tcp_ready; return 0;
}
static int fake_udp(void *c, int pid, uint16_t port, bool *ready) {
    (void)c; (void)pid; (void)port; *ready = fake_udp_ready; return 0;
}
static int fake_iface(void *c, const char *n, bool *e) { (void)c; (void)n; *e = false; return 0; }

static void test_tproxy_readiness_requires_udp(void) {
    struct asteriskd_config config = base_config();
    config.readiness_timeout_milliseconds = 5000U;
    config.has_transparent_port = true;
    config.transparent_port = 7895U;
    struct asteriskd_readiness_backend backend = {
        .context = NULL, .child_alive = fake_alive, .listener_ready = fake_listener,
        .interface_exists = fake_iface, .udp_ready = fake_udp,
    };
    struct asteriskd_readiness_tracker tracker;
    CHECK(asteriskd_readiness_init(&config, ASTERISKD_CHILD_CORE, 0U, &backend, &tracker) == 0);
    struct asteriskd_child_identity identity;
    memset(&identity, 0, sizeof(identity));
    identity.pid = 42;
    fake_tcp_ready = true; fake_udp_ready = false;
    CHECK(asteriskd_readiness_poll(&config, &tracker, &identity, &backend, 1U, false) == ASTERISKD_READINESS_PENDING);
    fake_udp_ready = true;
    CHECK(asteriskd_readiness_poll(&config, &tracker, &identity, &backend, 1U, false) == ASTERISKD_READINESS_READY);
    fake_tcp_ready = false;
    CHECK(asteriskd_readiness_poll(&config, &tracker, &identity, &backend, 1U, false) == ASTERISKD_READINESS_PENDING);
}

int main(void) {
    static const struct test_case cases[] = {
        {"tcp_listen_in_local_column", test_tcp_listen_in_local_column},
        {"tcp_remote_port_does_not_count", test_tcp_remote_port_does_not_count},
        {"tcp_established_local_port_does_not_count", test_tcp_established_local_port_does_not_count},
        {"tcp6_listen", test_tcp6_listen},
        {"udp_bound_socket", test_udp_bound_socket},
        {"preflight_all_present", test_preflight_all_present},
        {"preflight_missing_tproxy_target_fails", test_preflight_missing_tproxy_target_fails},
        {"preflight_unreadable_targets_is_not_fatal", test_preflight_unreadable_targets_is_not_fatal},
        {"preflight_missing_iptables_fails", test_preflight_missing_iptables_fails},
        {"preflight_no_ipv6_skips_dns_only_path", test_preflight_no_ipv6_skips_dns_only_path},
        {"preflight_no_ipv6_with_ipv6_proxy_fails", test_preflight_no_ipv6_with_ipv6_proxy_fails},
        {"preflight_without_xt_socket", test_preflight_without_xt_socket},
        {"preflight_ipv6_stack_without_ip6tables_fails_closed", test_preflight_ipv6_stack_without_ip6tables_fails_closed},
        {"reconcile_report_complete", test_reconcile_report_complete},
        {"config_without_new_flags_still_parses", test_config_without_new_flags_still_parses},
        {"config_new_flags_parse", test_config_new_flags_parse},
        {"cli_cleanup_and_guard_parse", test_cli_cleanup_and_guard_parse},
        {"tproxy_readiness_requires_udp", test_tproxy_readiness_requires_udp},
        {"guard_decision", test_guard_decision},
    };
    return run_tests("unit", cases, sizeof(cases) / sizeof(cases[0]));
}
