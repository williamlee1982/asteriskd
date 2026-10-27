// Copyright 2026, AsteriskMETA contributors
// SPDX-License-Identifier: GPL-3.0

/* Auto-restart policy for an unexpectedly exited core/helper (williamlee1982 fork).
 *
 * Pure state machine without IO so the host tests can drive it. The supervisor
 * consults it after every service cycle; it never restarts after an explicit
 * stop/shutdown/signal, after an incomplete cleanup, or after a startup failure
 * that was not part of an already running restart chain (a broken config must
 * not be retried forever from a cold start). */

#include "asteriskd.h"

#include <string.h>

static const int64_t restart_backoff_ms[] = {1000, 2000, 5000, 10000, 30000};
#define RESTART_BACKOFF_STEPS (sizeof(restart_backoff_ms) / sizeof(restart_backoff_ms[0]))

void asteriskd_restart_policy_init(struct asteriskd_restart_policy *policy) {
    if (policy == NULL) return;
    memset(policy, 0, sizeof(*policy));
}

void asteriskd_restart_policy_on_running(struct asteriskd_restart_policy *policy, int64_t now_ms) {
    if (policy == NULL) return;
    policy->running_since_ms = now_ms;
    policy->has_running_since = true;
}

void asteriskd_restart_policy_cancel(struct asteriskd_restart_policy *policy) {
    if (policy == NULL) return;
    policy->pending = false;
    policy->chain_active = false;
    policy->attempt = 0U;
    policy->has_running_since = false;
}

int64_t asteriskd_restart_policy_backoff_ms(unsigned int attempt) {
    if (attempt >= RESTART_BACKOFF_STEPS) return restart_backoff_ms[RESTART_BACKOFF_STEPS - 1U];
    return restart_backoff_ms[attempt];
}

int64_t asteriskd_restart_policy_on_cycle_end(
    struct asteriskd_restart_policy *policy,
    const struct asteriskd_restart_cycle_outcome *outcome,
    int64_t now_ms) {
    if (policy == NULL || outcome == NULL) return -1;
    bool reached_running = policy->has_running_since;
    int64_t uptime = reached_running ? now_ms - policy->running_since_ms : 0;
    policy->has_running_since = false;
    policy->pending = false;
    bool eligible = outcome->child_exited && outcome->cleanup_complete &&
        !outcome->stop_requested && !outcome->shutdown_requested &&
        (reached_running || policy->chain_active);
    if (!eligible) {
        policy->chain_active = false;
        policy->attempt = 0U;
        return -1;
    }
    if (reached_running && uptime >= ASTERISKD_RESTART_STABLE_UPTIME_MS) policy->attempt = 0U;
    int64_t delay = asteriskd_restart_policy_backoff_ms(policy->attempt);
    if (policy->attempt < UINT32_MAX) ++policy->attempt;
    ++policy->total_restarts;
    policy->chain_active = true;
    policy->pending = true;
    policy->restart_at_ms = now_ms + delay;
    return delay;
}

bool asteriskd_restart_policy_due(const struct asteriskd_restart_policy *policy, int64_t now_ms) {
    return policy != NULL && policy->pending && now_ms >= policy->restart_at_ms;
}
