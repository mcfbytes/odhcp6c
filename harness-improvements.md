# odhcp6c Integration Harness — Improvement Tasks

Instructions for an AI coding agent (GitHub Copilot / Claude) to strengthen the
`tools/harness` integration suite and its CI wiring
(`.github/workflows/integration.yml`).

Tasks are ordered **highest impact first**. Each is self-contained: do them in
order, open one focused PR per task (or per tier), and do not start a task until
the previous one is green. **When a task lands, update its `Status:` line here
(with the PR number) in the same PR** so this document stays the single source
of truth for harness state.

## Status snapshot

| # | Task | Tier | Status |
|--:|------|:----:|--------|
| 1 | Scenario drift guard + run orphaned scenarios | 0 | ✅ Done — PR #39 |
| 2 | Sanitizer (ASan + UBSan) build/run cell | 1 | Open |
| 3 | Crash-safe absence assertions harness-wide | 1 | Open |
| 4 | `last:` / `count` in the expect grammar | 1 | Open |
| 5 | Seccomp allow-list reconciliation as a gate | 2 | Open |
| 6 | Trustworthy OpenWrt-rootfs cell | 2 | Open |
| 7 | Code-coverage reporting | 2 | Open |
| 8 | Architecture diversity (big-endian; 386 per-PR) | 2 | Open (partial — 386 runs nightly) |
| 9 | Implement or remove `harness_assert_action_order` | 3 | Open |
| 10 | Negative-path backends fail hard | 3 | Open |
| 11 | Record-ordering resolution on musl/BusyBox | 3 | Open |
| 12 | Build-config coverage: `UBUS=OFF` cell | 3 | Open |
| 13 | Remove leftover debug scaffolding | 3 | Open |
| 14 | Pipeline hygiene (pins, timeouts, cache, summary) | 3 | Open |
| 15 | Harness self-test suite (test the tester) | 4 | Open |
| 16 | Shell-lint gate for the POSIX-sh harness | 4 | Open |
| 17 | Hostile-input scenario family | 4 | Open |
| 18 | Coverage ratchet + coverage-driven scenarios | 4 | Open (depends on 7) |
| 19 | Scenario authoring guide + skeleton | 4 | Open |
| 20 | Regression test for SECURITY-REVIEW #13 (ubus presentation bugs) | 4 | Open — test must first FAIL on current HEAD |

## Ground rules for every task

- The harness is high quality and deliberately POSIX-`sh` (it runs under Alpine
  BusyBox `ash` and OpenWrt). **Do not introduce bashisms** into `tools/harness/lib/*.sh`,
  `run-scenario.sh`, or `stub-script.sh`. `seccomp-syscall-report.sh` is `bash` and may stay so.
- Preserve existing behavior and comments unless a task says to change them.
- A test failure you uncover is a **finding to triage, not a thing to silence**.
  Never make a scenario pass by weakening an assertion or adding a skip without
  an explicit, documented reason.
- When you change assertion or capture semantics, update the affected
  `scenarios/*/expect.txt` and the header docs in `lib/assert.sh` — and once
  Task 15 lands, add/extend a self-test case covering the new semantics **in the
  same PR**.
- The `SCENARIOS` env in `integration.yml` and `tools/harness/scenarios/` are
  kept in sync by the `scenario-drift-guard` job. Any task that adds a scenario
  must update both, or CI fails.
- Validate locally where possible: `tools/harness/run-scenario.sh --list` and
  `tools/harness/run-scenario.sh <name>` (needs root/`sudo` for netns).

---

## Tier 0 — Run the tests that already exist ✅ COMPLETE

### Task 1. Stop the CI scenario list from drifting; run the orphaned scenarios

**Status: ✅ Done — PR #39** (commits `0d4e8cf`, `ce2f00c`).

What landed:

- A `scenario-drift-guard` job in `integration.yml` diffs the static `SCENARIOS`
  env against `run-scenario.sh --list`; any mismatch (including duplicates)
  fails CI before the build matrix spends any time. The heavier jobs `needs:` it.
- All 18 authored scenarios are in the per-PR run set, including the five that
  had drifted out (`entry-formatting`, `info-options`, `malformed-dhcpv6`,
  `prefix-renumber`, `ra-holdoff`). `malformed-dhcpv6` — the hostile-TLV
  out-of-bounds-read defense test — now runs in every matrix cell and carries a
  workflow comment saying it must never be dropped.
- Triage of the failures found two **test bugs, not code bugs** (fixed in
  `ce2f00c`): `malformed-dhcpv6` wrongly inferred an early crash by grepping the
  odhcp6c log for SOLICIT lines that are never printed at default verbosity (it
  now proves liveness via the `started` status record), and `prefix-renumber`
  raced the renumbering event.

The acceptance criteria hold: a scenario added to `scenarios/` but not to CI
(or vice-versa) fails CI, and no scenario is excluded.

---

## Tier 1 — Make a passing test mean what a reader assumes

### Task 2. Add a sanitizer (ASan + UBSan) build/run cell

**Status: Open.** No `SANITIZE` build path exists yet — `CMakeLists.txt` only
applies sanitizers to the libFuzzer codec target, and neither harness
Dockerfile accepts a sanitizer build-arg.

**Problem.** `malformed-dhcpv6` asserts "didn't crash, didn't bind" — a behavioral
proxy. An out-of-bounds **read** in the TLV walker that doesn't segfault passes
both checks. There is no memory-safety detector in the integration suite (the
separate `fuzz.yml` covers only `script_codec.c`, not the DHCPv6/RA parsers the
scenarios exercise).

**Change.**
- Add a build path that compiles odhcp6c with `-fsanitize=address,undefined`
  `-fno-sanitize-recover=all -fno-omit-frame-pointer` (a CMake option/build-arg,
  e.g. `SANITIZE=ON`, threaded through `Dockerfile.debian` the same way the
  existing `SECCOMP` and `UBUS` args are).
- Add one matrix cell (glibc/amd64 is sufficient — ASan support on musl is
  unreliable) that runs the **full scenario set** against the sanitized binary.
- Export `ASAN_OPTIONS=abort_on_error=1:detect_leaks=1` and
  `UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1` so a finding aborts the
  worker (the harness already treats an unexpected exit as failure). Upload the
  sanitizer logs as artifacts. Note LeakSanitizer needs ptrace inside the
  container — add `--cap-add=SYS_PTRACE` to the `docker run` for this cell (the
  trace job already does this).
- The privsep worker drops privileges and installs seccomp; ASan needs extra
  syscalls/mmap behavior. Build the sanitizer cell with `SECCOMP=OFF` and run it
  with Docker's seccomp profile relaxed if needed (reuse the existing
  `extra_opts` pattern in the `scenarios` job), so ASan is the confinement under
  test — mirroring how the trace job already runs seccomp-unconfined for
  visibility. Comment the why in the workflow.

**Acceptance criteria.**
- A deliberately introduced 1-byte over-read in the option parser is caught by
  the sanitizer cell (verify once on a throwaway commit, then revert).
- Sanitizer logs are uploaded on failure.

### Task 3. Make absence assertions crash-safe harness-wide

**Status: Open.** The hole is `lib/assert.sh` in `harness_assert_one`: the
"no record with this ACTION" failure is explicitly skipped when the action is
`'*'` (`[ "$_seen_action" = 0 ] && [ "$_a" != "*" ]`), so a wildcard negative
op over an empty capture dir falls through to PASS.

**Problem.** A negative-polarity check on the wildcard action
(`harness_assert_one '*' ADDRESSES empty`) returns **PASS when zero records
exist**, because nothing violated the forbidden condition. Today only
`malformed-dhcpv6` guards this, via a per-scenario liveness pre-check in
`scenario_drive` (`wait_for_action started` + `harness_odhcp6c_running`, added
in PR #39). Any negative-op scenario that forgets the guard mis-passes if
odhcp6c died early.

**Change.**
- In `harness_assert_one`, when the op is negative **and** no records were
  captured at all (`_seen_action == 0`, including the `'*'` case), treat it as a
  **failure**: an absence claim is only meaningful if the binary produced
  evidence of life. Add a clear message ("no records captured; cannot assert
  absence — did odhcp6c start?").
- Alternatively/additionally, add a reusable `harness_require_liveness` helper
  (assert at least one record OR `harness_odhcp6c_running`) and call it from
  `scenario_assert`'s default path before negative checks.
- Keep the existing intended semantics for the case where records **do** exist,
  and keep `malformed-dhcpv6`'s explicit pre-check (defense in depth; its
  comment explains a subtle log-verbosity trap worth preserving).
- Update the polarity documentation in the `lib/assert.sh` header.

**Acceptance criteria.**
- A scenario whose binary exits before writing any record **fails** its `empty` /
  `no_action` assertions instead of passing.
- `malformed-dhcpv6` still passes for the right reason (binary stays alive, emits
  `stopped`, never binds).

### Task 4. Let expect-files assert final state and counts

**Status: Open.** `harness_assert_last` exists in `lib/assert.sh` but
`harness_assert_expect` routes every line to `harness_assert_one` only — `last`
semantics are reachable solely from hand-written `scenario_assert` overrides,
and no count helper exists at all.

**Problem.** The default `expect.txt` path routes through `harness_assert_one`,
which for positive ops passes if **any** record matches ("X happened at some
point"). So most scenarios cannot express "the **final** `bound` record must
contain X" or "there must be exactly N `ra-updated` records," and a regression
that is correct transiently but wrong in steady state passes.

**Change.**
- Extend the expect grammar in `harness_assert_expect` with a per-line modifier
  selecting evaluation scope. Suggested syntax (keep it POSIX-parseable):
  - `last:<action> <key> <op> [value]` → routes to `harness_assert_last`.
  - leave bare `<action> ...` as today (at-least-one).
- Add a count op, e.g. `count <action> <eq|ge|le> <n>`, backed by a new
  `harness_assert_count` helper that counts records with that ACTION.
- Update `lib/assert.sh`'s header grammar docs and convert at least the
  final-state-sensitive existing scenarios (e.g. `pd-exclude`, `prefix-renumber`,
  `renew-rebind`) to use `last:` where the final state is the property under test.
- Note: `last` correctness depends on record filename ordering, which is
  1-second-coarse on BusyBox without `date +%N` — Task 11 fixes the ordering;
  sequence Task 11 before or together with converting timing-dense scenarios.

**Acceptance criteria.**
- `last:` and `count` work from `expect.txt` and are documented in the grammar.
- A regression that appends a spurious wrong final record is now caught by a
  `last:` assertion in at least one scenario.

---

## Tier 2 — Close the CI confidence gaps from the workflow review

### Task 5. Turn the seccomp allow-list reconciliation into a gate

**Status: Open.** `seccomp-syscall-report.sh` **already implements `--strict`**
(exit non-zero on any gap); the `trace` job deliberately omits it ("Diagnostic
only: never fail"). The remaining work is a baseline file plus wiring — not a
new script mode.

**Problem.** The `trace` job runs `seccomp-syscall-report.sh` without
`--strict`, so a syscall the worker issues that is missing from
`src/seccomp.c` is only printed to the job summary — it never fails CI. The
`libcapng-seccomp` cell disables Docker's seccomp so the in-process filter is the
sole confinement, but it only catches a gap if a scenario happens to exercise the
missing syscall (and the `ODHCP6C_SECCOMP_DIAG` re-run only fires *after* such a
failure). So allow-list drift can ship green.

**Change.**
- Add a **strict** reconciliation that fails the job on a newly-missing syscall
  or ioctl command. To avoid false positives from environment noise, compare
  against a checked-in baseline/allow-delta file (e.g.
  `tools/harness/seccomp-known-gaps.txt`) and fail only on entries **not** in the
  baseline; require a PR to update the baseline deliberately. Seed the baseline
  from whatever the current non-strict report prints on a green run (each entry
  with a one-line justification); an empty baseline is the ideal outcome.
- Keep the existing human-readable summary output.

**Acceptance criteria.**
- Removing a required `SCMP_SYS(...)` entry from `src/seccomp.c` fails the trace
  job (verify once, then revert).
- Expected, already-known gaps do not fail the job.

### Task 6. Make the OpenWrt-rootfs cell trustworthy

**Status: Open.** The cell is still `continue-on-error: true` with a hard-coded
example URL (23.05.3), no checksum, no retry.

**Problem.** `openwrt-rootfs` is the "authoritative musl environment" but is
`continue-on-error: true` and points at a hard-coded **example** rootfs URL. The
most deployment-representative cell can never fail the build.

**Change.**
- Pin the rootfs to a specific, currently-supported OpenWrt release via a
  workflow input/`env` (document the chosen release), with the URL and an
  expected SHA256 checksum; verify the checksum after download. (OpenWrt
  publishes `sha256sums` alongside each release's rootfs — take the value from
  there, don't compute it yourself from a first download.)
- Once the image provisions reliably, **remove `continue-on-error: true`** so the
  cell gates (keep it on the nightly/dispatch triggers — it need not block every
  PR, but it must be able to go red).
- Add a retry around the `curl` download to absorb transient network failures
  (`curl --retry 3 --retry-all-errors` is sufficient).

**Acceptance criteria.**
- The cell downloads a checksum-verified, pinned rootfs and a real scenario
  failure inside it turns the run red.

### Task 7. Add code-coverage reporting

**Status: Open.**

**Problem.** Nothing reports which parts of the odhcp6c source the scenarios
exercise, so "what isn't tested" is invisible.

**Change.**
- Add a coverage build (`--coverage` / `-fprofile-arcs -ftest-coverage`, or
  `-fprofile-instr-generate -fcoverage-mapping` for clang) in one glibc/amd64
  cell, run the full scenario set, and aggregate with `gcovr`/`llvm-cov`.
  Note the worker `chdir`s and drops privileges — make sure the profile output
  location (`GCOV_PREFIX` or `LLVM_PROFILE_FILE`) is writable by the dropped
  user, the same way the capture dir already is.
- Publish a coverage summary to `$GITHUB_STEP_SUMMARY` and upload the HTML/XML
  report as an artifact. Focus the report on `src/` (parsing/state machine).
- Do **not** gate on a coverage threshold yet — establish the baseline first
  (the ratchet is Task 18).

**Acceptance criteria.**
- Each run publishes per-file line/branch coverage for `src/` and uploads the
  report.

### Task 8. Add architecture diversity that catches real bugs

**Status: Open (partial).** `linux/386` already runs in the **nightly**
`multiarch` matrix (alongside `linux/arm/v7` and `linux/arm64`); it is not in
the per-PR gate, and no big-endian target exists anywhere.

**Problem.** The per-PR gate is amd64-only; all nightly QEMU targets are
little-endian. odhcp6c does heavy byte-order work and OpenWrt's historical core
targets are big-endian MIPS — `htons`/`ntohl` mistakes have no cell to surface in.

**Change.**
- Add a **big-endian** target to the nightly `multiarch` matrix
  (`linux/mips64le` is still LE — use a genuinely big-endian QEMU platform such as
  `linux/s390x`, or a MIPS BE rootfs cell, whichever buildx/QEMU supports
  reliably here; Alpine publishes s390x images, so the existing
  `tools/harness/Dockerfile` should build unmodified).
- Promote the cheap 32-bit `linux/386` cell from nightly-only into the
  **per-PR** gate so 32-bit/`time_t`/alignment regressions are caught before
  merge (keep it in a single privsep mode to bound cost; nightly keeps both).

**Acceptance criteria.**
- Nightly runs include at least one big-endian execution of the scenario set.
- `linux/386` runs on pull requests.

---

## Tier 3 — Correctness and hygiene of the harness itself

### Task 9. Implement or remove `harness_assert_action_order`

**Status: Open.** The `lib/assert.sh` header (line ~39) still advertises the
helper; it is defined nowhere.

**Problem.** A scenario calling `harness_assert_action_order` would error out.
Ordering properties (e.g. SOLICIT→ADVERTISE→REQUEST→`bound`, or renew before
rebind) currently cannot be asserted.

**Change.**
- Implement `harness_assert_action_order <action1> <action2> ...`: confirm the
  first capture of each listed ACTION appears in the given order (records sort by
  filename = timestamp.pid — see Task 11 for the resolution caveat; do Task 11
  first or together). Then add an ordering assertion to a scenario where order
  is meaningful (e.g. `renew-rebind`).
- If you choose not to implement it, **delete the reference** from the header so
  the docs match the code.

**Acceptance criteria.**
- The helper either exists and is exercised by a scenario, or no longer appears in
  the docs.

### Task 10. Make negative-path backends fail hard

**Status: Open.** `servers/scapy_server.py` still logs and continues on an
invalid hex string in both the ADVERTISE and REPLY paths ("invalid
--reply-raw-trailer hex" → packet sent without the trailer).

**Problem.** A typo in `--reply-raw-trailer` (or `--raw-trailer`) would send a
**valid** packet; odhcp6c would correctly bind; and the negative scenario would
mis-pass while believing it proved defensive parsing.

**Change.**
- Validate malformation flags **once at startup** (argument parsing time), not
  per-packet: if a malformation flag is supplied but cannot be constructed (bad
  hex, odd length, etc.), **exit non-zero** with a clear error. The harness
  already treats a dead backend as a setup failure, and failing at startup
  avoids a half-run scenario.

**Acceptance criteria.**
- A malformed `--reply-raw-trailer` value aborts the backend and fails the
  scenario instead of silently sending a valid packet.

### Task 11. Fix record-ordering resolution on the musl/BusyBox path

**Status: Open.** `stub-script.sh` still uses
`stamp="$(date +%s%N 2>/dev/null || date +%s)"`.

**Problem.** `harness_assert_last` (and any future ordering helper — Task 9)
determines "most recent" by sorting record filenames `rec.<stamp>.<pid>`. Where
`%N` is unavailable the stub falls back to `date +%s` (1-second resolution);
records in the same second then sort by **PID**, not time — so "last" can be
wrong. This is exactly the Alpine/OpenWrt environment the harness targets.
(A second, subtler hazard even with `%N`: some `date` implementations print a
literal `N`, which still sorts but is worth handling explicitly.)

**Change.**
- Make ordering robust to coarse timestamps: have the stub write a monotonic
  per-capture sequence number into the record filename (e.g. an atomically
  incremented, zero-padded counter file in the capture dir — `mkdir`-based
  locking is the portable primitive if needed), and sort on that sequence.
  Ensure it works when the script is exec'd by the unprivileged privsep worker
  (the capture dir is already mode 0777).
- Update the "unique, sortable filename" comment in `stub-script.sh` and any
  sort logic in `lib/assert.sh` to match.

**Acceptance criteria.**
- With `date +%N` unavailable, multiple records emitted within the same second
  still sort in true emission order, and `harness_assert_last` is correct.

### Task 12. Build-config coverage: exercise `UBUS=OFF`

**Status: Open.** Both harness Dockerfiles already accept `--build-arg UBUS=OFF`;
no CI cell uses it.

**Problem.** Images always build **with** ubus; the `UBUS=OFF` configuration is
never compiled or run in this workflow, even though `ubus-reconnect` self-skips on
it. A compile break or behavior change under `UBUS=OFF` is invisible here.

**Change.**
- Add a small matrix axis or a dedicated cell that builds with `--build-arg UBUS=OFF`
  and runs the scenario set (the ubus broker autostart is a no-op there, and
  `ubus-reconnect` self-skips — confirm the skip is reported, not silently passed,
  per Task 1's triage rule).

**Acceptance criteria.**
- A `UBUS=OFF` build is compiled and runs the suite in CI.

### Task 13. Remove leftover debug scaffolding

**Status: Open.** `harness_dump_privsep_state` is still in `lib/common.sh`
(marked "[privsep-debug]") and still called from
`scenarios/privsep-signals/scenario.sh`; `Dockerfile.debian` also prints
`[privsep-debug]` libseccomp-link lines at build time.

**Problem.** Debug dumps run on every `privsep-signals` execution, emitting
`[privsep-debug]` noise — a sign of an investigation never closed out.

**Change.**
- Resolve the underlying single-process-under-privsep question if still open, then
  remove the `[privsep-debug]` dump calls from the scenarios and either delete the
  helper or gate it behind an explicit `HARNESS_DEBUG=1`. Clean the build-time
  `[privsep-debug]` echoes in `Dockerfile.debian` at the same time (or rename
  them — they are genuinely useful build provenance, just mislabeled as debug).

**Acceptance criteria.**
- Normal runs no longer emit `[privsep-debug]` output; the helper, if kept, is
  opt-in.

### Task 14. Pipeline hygiene

**Status: Open.** Only the `scenario-drift-guard` job has `timeout-minutes`;
actions are on mutable tags (and inconsistently — `integration.yml` uses
`checkout@v4` while `ci.yml`/`fuzz.yml` use `@v5`); there is no concurrency
group, no layer caching, and no per-scenario summary table.

**Problem.** Standard CI hardening/efficiency items are missing.

**Change.**
- **Pin actions to commit SHAs** (`actions/checkout`, `actions/upload-artifact`,
  `docker/setup-qemu-action`, `docker/setup-buildx-action`) instead of mutable
  tags — across **all** workflows, not just `integration.yml`, and normalize the
  checkout major version while doing it.
- Add **`timeout-minutes`** to every job (the per-scenario `--timeout` does not
  bound a hung `docker build` or QEMU step).
- Add a **`concurrency`** group keyed on workflow + ref to cancel superseded PR
  runs.
- Add **Docker layer caching** (buildx `--cache-from`/`--cache-to` with the GHA
  cache backend) so the wide matrix rebuilds less and broader coverage stays
  affordable.
- Add a **per-scenario result table** to `$GITHUB_STEP_SUMMARY` in the
  `scenarios` job (the `trace` job already writes a summary), and consider
  emitting JUnit XML for the Checks UI.

**Acceptance criteria.**
- Actions are SHA-pinned, jobs have timeouts, superseded PR runs cancel, builds
  use a layer cache, and the gate job prints a scenario × cell result table.

---

## Tier 4 — Keep the harness strong as the code evolves

The tiers above fix what exists. This tier makes the harness **stay** correct
and grow with the daemon: tests for the test framework itself, lint gates that
protect its portability contract, systematic hostile-input coverage, and the
docs/scaffolding that make "new feature ⇒ new scenario" the path of least
resistance.

### Task 15. Harness self-test suite (test the tester)

**Status: Open.** Do this **before or alongside** Tasks 3, 4, 9, and 11 — all
four change assertion/ordering semantics, and today nothing would catch a
regression in the assertion library itself.

**Problem.** `lib/assert.sh` implements non-trivial semantics (op polarity,
wildcard actions, last-record selection, the expect-file grammar) with zero
tests. A subtle bug here silently weakens **every** scenario at once — the
Task 3 wildcard hole is exactly this class of defect, and it shipped. The
library needs no root, no netns, and no Docker to test: it only reads record
files from `$HARNESS_CAPTURE`.

**Change.**
- Add `tools/harness/selftest/` with a POSIX-sh runner (`run-selftest.sh`) that:
  - builds synthetic capture dirs (hand-written `rec.*` files) covering: empty
    capture dir, single record, multiple records per action, records with
    missing keys, values containing `=` and spaces, and shell-dangerous bytes
    for `sanitized`;
  - sources `lib/assert.sh` and asserts each helper's PASS/FAIL verdict against
    a table of expected outcomes — including the **negative** expectations
    (e.g. "wildcard `empty` over zero records must FAIL" once Task 3 lands, and
    the `last:`/`count` grammar once Task 4 lands);
  - exercises `harness_assert_expect` end-to-end with fixture expect files,
    including comment/blank-line handling and the column-aligned value parsing.
- Wire it into CI as a fast job (seconds, plain `ubuntu-latest`, no Docker) that
  gates every PR touching `tools/harness/**`. Run it under **BusyBox `ash`**
  too (a one-line `docker run alpine` step) so the POSIX-sh contract is tested
  where it matters, not just under dash/bash.
- From then on (see ground rules): any PR changing `lib/assert.sh` semantics
  must extend the self-test in the same PR.

**Acceptance criteria.**
- The self-test runs per-PR in under a minute without root or netns.
- Deliberately re-introducing the Task 3 wildcard hole (or breaking positive-op
  at-least-one semantics) fails the self-test (verify once, then revert).
- The suite passes under both a POSIX shell on the runner and BusyBox `ash`.

### Task 16. Shell-lint gate for the POSIX-sh harness

**Status: Open.** `formal.yml` only runs OpenWrt's commit-formality checks —
nothing lints the harness shell code, so the "no bashisms" ground rule is
enforced only by review.

**Problem.** The harness's portability contract (BusyBox `ash`, OpenWrt) is
load-bearing and easy to break invisibly: a bashism works fine in the
glibc/dash CI cells and only fails on the musl/BusyBox path — or worse, only on
a user's router.

**Change.**
- Add a lint job (can live in the same fast CI job as Task 15's self-test) that
  runs over `tools/harness/lib/*.sh`, `run-scenario.sh`, `stub-script.sh`, and
  `scenarios/*/scenario.sh`:
  - `shellcheck --shell=sh` (the `lib/` files already carry
    `# shellcheck shell=sh` directives; add the directive to the scenario
    scripts, which mostly lack it); triage existing findings once, then gate;
  - `checkbashisms` (from `devscripts`) as a second, cheaper net for constructs
    shellcheck's sh mode permits.
- Keep `seccomp-syscall-report.sh` linted as bash (`--shell=bash`), per the
  ground rules.
- Document any deliberately suppressed findings inline
  (`# shellcheck disable=SCnnnn` + reason), never in a global ignore file.

**Acceptance criteria.**
- Introducing a bashism (e.g. `local -a`, `[[ ]]`, `${var^^}`) into
  `lib/common.sh` fails CI (verify once, then revert).
- The lint job runs per-PR and completes in under a minute.

### Task 17. Hostile-input scenario family

**Status: Open.** Depends on Task 2 (the sanitizer cell is what turns "didn't
crash" into "didn't even read out of bounds") and benefits from Task 10 (fail-hard
backend).

**Problem.** `malformed-dhcpv6` covers exactly one malformation (a TLV whose
declared length overruns the datagram) and `ra-options-edge` covers RA option
edges. The parsers in `src/dhcpv6.c` and `src/ra.c` are the daemon's entire
hostile-input attack surface — a WAN-facing DHCPv6 server or on-link RA sender
is untrusted by definition — and one probe each is not systematic coverage.

**Change.**
- Grow a **family** of negative-path scenarios, one malformation per scenario
  (so a failure names its trigger), reusing the existing
  `--reply-raw-trailer`/`--raw-trailer` mechanism and extending
  `scapy_server.py` with new malformation flags only where a raw trailer cannot
  express the case. Candidate set, in rough priority order:
  1. zero-length option repeated to datagram end (parser-loop/livelock probe);
  2. truncated option header (1–3 bytes remaining, less than the 4-byte TLV
     header);
  3. nested-option length overflow — IA_NA/IA_PD whose *inner* IAADDR/IAPREFIX
     declares a length exceeding the enclosing option (the outer walk is
     already probed by `malformed-dhcpv6`; the inner walk is not);
  4. malformed S46 (MAP-E/MAP-T/LW4o6) container options — `s46-mape` proves
     the happy path; nothing probes hostile encodings of the same options;
  5. malformed domain-name encodings in DNS-search/NTP-FQDN options
     (label length overruns, missing root terminator);
  6. hostile RA options beyond `ra-options-edge`'s current set (option length
     0, RDNSS/route-info lengths inconsistent with the option size).
- Every scenario in the family asserts the `malformed-dhcpv6` triple: liveness
  (records still emitted / process alive), **no bind** on the hostile payload,
  and clean exit on stop — plus sanitizer-cleanliness for free once Task 2's
  cell runs the full set.
- Add each scenario to `SCENARIOS` (the drift guard enforces this).

**Acceptance criteria.**
- At least the first four malformation classes above run per-PR in every matrix
  cell and in the sanitizer cell.
- Each scenario's header comment states the exact malformation and the parser
  property it probes (mirroring `malformed-dhcpv6`'s documentation style).

### Task 18. Coverage ratchet + coverage-driven scenario backlog

**Status: Open.** Depends on Task 7 (baseline must exist first).

**Problem.** Task 7 makes untested code visible; nothing then stops coverage
from silently eroding, and the visibility is wasted if nobody turns the gaps
into scenarios.

**Change.**
- Once Task 7 has produced a stable baseline over a few runs, add a **ratchet**:
  fail the coverage job if line coverage of `src/` drops more than a small
  epsilon (~0.5%) below the checked-in baseline value; update the baseline file
  deliberately in PRs that raise it. A ratchet (not a fixed threshold) means
  new code must arrive with scenarios without demanding retroactive perfection.
- Do one triage pass over the baseline report and record the top uncovered
  regions of `src/` **as concrete scenario ideas appended to this document**
  (or as tracked issues) — likely candidates: error/retry paths in the state
  machine, `RELEASE`/`DECLINE` flows, and option encodings no scenario sends yet.

**Acceptance criteria.**
- A PR that meaningfully drops `src/` coverage fails the coverage job until the
  baseline is deliberately updated.
- The uncovered-region triage exists in written form with at least three
  actionable scenario candidates.

### Task 19. Scenario authoring guide + skeleton

**Status: Open.**

**Problem.** Adding a scenario currently requires reverse-engineering the
contract from `lib/` sources and an existing scenario: which hook functions
exist (`scenario_backend`, `scenario_odhcp6c`, `scenario_drive`,
`scenario_assert`), what the expect-grammar offers, which env vars the harness
provides, and the drift-guard's two-place registration. Friction here is what
made five scenarios drift out of CI in the first place — the harness stays
strong only if the next contributor (or AI agent) can add a correct scenario in
minutes.

**Change.**
- Add a "Writing a new scenario" section to `tools/harness/README.md` covering:
  the hook functions and their contracts, the expect grammar (kept in sync with
  `lib/assert.sh`'s header — including Task 4's `last:`/`count` once landed),
  the liveness rule for negative-path scenarios (Task 3), the two-place
  registration (`scenarios/` dir + `SCENARIOS` env) and how the drift guard
  enforces it, and how to run one scenario locally under `sudo`.
- Add a commented skeleton (e.g. `tools/harness/scenario-template/` —
  deliberately **outside** `scenarios/` so `run-scenario.sh --list` and the
  drift guard never see it) with a `scenario.sh` and `expect.txt` a new
  scenario can be copied from.
- Cross-link this document from the README so the improvement backlog is
  discoverable.

**Acceptance criteria.**
- A contributor can create a passing scenario from the template + README alone,
  without reading `lib/*.sh` source.
- The template directory is invisible to `--list` and the drift guard.

### Task 20. Regression test for SECURITY-REVIEW.md finding #13 (ubus presentation bugs)

**Status: Open.** This tests **known, currently-unfixed bugs** — write the test
first, prove it fails on current HEAD, then land it (see the failure-handling
note below). Everything it needs already exists in the harness: `lib/ubus.sh`
provides `harness_ubus call` and `harness_ubus_object_name` (the
`ubus-reconnect` scenario already drives methods on the `odhcp6c.<iface>`
object), and `get_state` is registered at `ubus.c:173`.

**Problem.** SECURITY-REVIEW.md #13 documents two correctness defects in the
ubus presentation path (`src/ubus.c`) that **no scenario can currently catch**,
because every existing assertion reads the status-script environment — whose
builders (`script_worker.c`) are correct. The bugs live only in the parallel
ubus builders:

- **MAP-T DMR is always `::`** — `s46_to_blob()`'s DMR branch never copies the
  prefix bytes before `inet_ntop()` (the `memcpy` present in the script-env
  equivalent is missing), so `get_state` reports `"dmr": "::"` regardless of
  what the server sent.
- **`fqdn_to_blob()` truncates compressed names** — it does `buf[l] = '\0'`
  where `l` is `dn_expand()`'s *wire bytes consumed*, not the expanded string
  length. Any name encoded with a DNS compression pointer (`l` < expanded
  length) is silently truncated — a 2-byte pointer yields a 2-character name.
  This affects the `NTP_FQDN`, `SIP_DOMAIN`, and `AFTR` fields of `get_state`.

**Change.**
- Add a scenario (suggested name: `ubus-get-state`) that binds normally, waits
  for the ubus object, calls `get_state`, and asserts the ubus JSON **against
  the same values already proven correct in the script-env records** — making
  the scenario double as a general env↔ubus equivalence check, which is the
  invariant #13 says must hold. Cover both bugs:
  - **DMR:** extend `scapy_server.py` with a `--mapt` flag mirroring
    `build_s46_mape_bytes()` — an `OPTION_S46_CONT_MAPT` (95) container whose
    `OPTION_S46_DMR` (91) carries a real prefix (e.g. `2001:db8:ffff::/64`).
    Assert the scenario's `MAPT=` env record contains that prefix (guards that
    the payload parsed at all), then assert `get_state`'s `dmr` field equals it.
    **Fails today** (`"::"`).
  - **FQDN truncation:** no new server code needed — append a hand-crafted
    domain-list option via the existing `--reply-raw-trailer`, encoding the
    second name as a compression pointer to the first (e.g. payload
    `\x03foo\x00` + `\xc0\x00`, both expanding to `foo`). Assert the env record
    shows both names in full, then assert the corresponding `get_state` array
    does too. **Fails today** (the pointer entry truncates to 2 characters).
    Verify odhcp6c accepts the chosen option without requesting it via ORO;
    if not, pick whichever of the three affected options it stores
    unconditionally.
  - Parse the ubus JSON with the tools already in the images (`jsonfilter` on
    the Alpine/OpenWrt side or `ubus call` + `grep -F` on the raw output —
    keep it POSIX-sh; do not add a jq dependency without updating both
    Dockerfiles).
- Like `ubus-reconnect`, the scenario must **self-skip with a reported skip**
  on a `UBUS=OFF` build (reuse the `harness_odhcp6c_has_ubus` gate), so it
  composes with Task 12.
- **Handling the expected failure** (the ground rules forbid a permanently red
  gate, and the drift guard forbids parking the scenario out of `SCENARIOS`):
  1. Open a PR with **only the scenario** and let CI run red once — that run is
     the recorded proof the test detects the live bugs; link it from the PR.
  2. Then add the two fixes from #13 to the **same PR** (a one-line `memcpy` in
     `s46_to_blob()`'s DMR branch; drop the `buf[l] = '\0'` in `fqdn_to_blob()`
     or use `strlen(buf)`) and confirm the scenario — and the rest of the suite
     — goes green.
  Only if the fix must be deferred, add an explicit expected-fail mechanism
  (e.g. an `xfail` marker in the scenario that inverts the verdict and fails
  loudly on unexpected PASS) — never a skip, and never weakened assertions.

**Acceptance criteria.**
- A CI run exists showing the scenario failing on the unfixed tree, on both
  assertions (DMR and FQDN).
- After the #13 fixes land, the scenario passes in every ubus-enabled cell and
  reports (not hides) its skip on `UBUS=OFF`.
- The scenario asserts env↔ubus equivalence, so a future divergence between
  `script_worker.c` and `ubus.c` builders for these fields is caught even after
  the original bugs are gone.

---

## Suggested PR sequencing

| Order | Tasks | Theme | Status |
|------:|-------|-------|--------|
| 1 | 1 | Run the orphaned scenarios + drift guard | ✅ Done (PR #39) |
| 2 | 15, 16 | Test-the-tester + lint gate (protects everything after it) | Open |
| 3 | 2, 3, 4 | Real teeth: sanitizer + crash-safe absence + final-state assertions | Open |
| 4 | 5, 6, 7, 8 | CI confidence: seccomp gate, OpenWrt gate, coverage, arch diversity | Open |
| 5 | 9, 10, 11, 12, 13, 14 | Harness correctness + hygiene | Open |
| 6 | 17, 18, 19 | Grow the suite: hostile-input family, ratchet, authoring docs | Open |
| — | 20 | Regression test + fix for SECURITY-REVIEW #13 (independent — can land anytime) | Open |

Notes on ordering:
- Task 15 (self-tests) moved ahead of the Tier 1 assertion changes on purpose:
  Tasks 3/4/9/11 all modify assertion semantics, and each should land with a
  self-test case proving the new behavior. Doing 15 first makes that cheap.
- Task 11 should land before or with Task 4's `last:` conversions and Task 9's
  ordering helper — both depend on record order being trustworthy.
- Task 17 lands after Task 2 so every hostile-input scenario is born with
  memory-safety teeth, and after Task 10 so a backend typo cannot mis-pass it.
- Task 18 waits for Task 7's baseline.

Tiers 1 and the self-test/lint pair deliver the great majority of the remaining
confidence improvement; do not let the later tiers delay them.
