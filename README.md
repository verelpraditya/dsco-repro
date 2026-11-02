# DSCO capability-gate reproduction

Reproduction for four capability-gate findings in DSCO
(github.com/arthurcolle/dsco), reported to the maintainer on 1 Nov 2026
and shared publicly at the maintainer's request (2 Nov 2026).

## What it does

Clones DSCO at commit `ec8738b05d855782b4df27c0850c97258edd83dd`,
compiles the gate's own source unmodified plus a small harness, and
prints ALLOW/DENY per case. The harness only calls the gate's public
API (it asks "would you allow this?"). It never executes the commands,
never writes files, and never touches the network.

## Run

```sh
bash dsco_repro.sh
```

Requires only `git` and `gcc`.

## What to look for

Under lockdown (`DSCO_ALLOW_NET=0 DSCO_ALLOW_WRITE=0`), every line
should read DENY. Any ALLOW line reproduces a finding:

- Finding 1: lockdown bypass — `/dev/tcp`, `socat`, `openssl s_client`,
  `perl`, `php`, the unspaced `echo hi>/tmp/f` form, and `sed -i` on
  `/etc/hosts` all return ALLOW.
- Finding 2: `.git/hooks` + `.git/config` write guard bypassed via the
  unspaced bash form (`echo x>/repo/.git/hooks/pre-commit` returns ALLOW).
- Finding 3: `killswitch status` returns DENY where the documented
  read-only governance exemption says it should be exempt.

## Files

- `dsco_repro.sh` — one-step runner (clone, build, run).
- `harness.c` — the harness (calls the gate's public API only).
- `stubs.c` — minimal link stubs for symbols in other translation units.
- `dsco_harness_output.txt` — captured output of the reference run.

## Scope

Local reproduction only. No live service was touched.
