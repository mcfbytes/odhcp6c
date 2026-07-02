# odhcp6c Security Review

**Date:** 2026-07-01
**Scope:** Full source tree under `src/` (DHCPv6 + RA parsers, privilege-separation
monitor/worker split, seccomp filter, ubus RPC surface, config/CLI parsing, build
configuration).
**Method:** Manual read of every translation unit with a focus on the untrusted
input paths (DHCPv6 replies, ICMPv6 Router Advertisements), the privilege-separation
trust boundary, and the syscall/capability confinement. Cross-checked bounds on
every option parser and the IPC codec, and every cited line reference against the
current tree.

---

## Bottom line

This codebase is **already very well hardened** — materially more so than upstream
odhcp6c. The privilege-separation design, seccomp allow-list (incl. the `ioctl`
argument filter), capability drop, `getrandom`-based CSPRNG, per-state size caps,
the pure/fuzzable IPC codec, defense-in-depth env sanitization on both sides of the
trust boundary, and the default exploit-mitigation build flags are all in place and
implemented carefully.

One deployment-level caveat matters more than any code finding: **all of the
process-level mitigations are build-time opt-in, and a default CMake configuration
enables none of them** — `LIBCAP_NG` and `SECCOMP` are `OFF` by default, and without
`WITH_LIBCAP_NG` the daemon silently runs as a single root process (finding #2).

I found **no high- or critical-severity issues**, and no exploitable memory-safety
bug in the network-facing parsers: every option iterator is bounds-checked, every
`memcpy`/VLA is sized against a validated length, and received datagrams are capped
at the 1536-byte receive buffer. The remaining opportunities are **low-severity,
defense-in-depth hardening** — several are in the exact same spirit as work already
done here (e.g., the `ioctl` argument filter). They are worth doing but none
represents a live, remotely-exploitable vulnerability.

---

## Baseline: hardening already present (for context)

> **Caveat:** the process-level rows below describe a build configured with
> `-DLIBCAP_NG=ON -DSECCOMP=ON`. Both options default to **OFF**
> (`CMakeLists.txt:138`, `:156`), in which case none of the privilege-separation,
> capability-drop, or seccomp rows apply — see finding #2. Only the compiler/linker
> mitigations (`HARDENING=ON`) are on by default.

| Control | Where |
|---|---|
| Privilege separation (root monitor / unprivileged worker) | `script_monitor.c`, `script_common.c`, `odhcp6c.c` |
| Root TCB re-validates everything from the worker | `script_codec.c: script_req_decode()` |
| seccomp-BPF allow-list, fail-closed, `ioctl` arg-filtered | `seccomp.c` |
| Capability drop to `nobody`, `NO_NEW_PRIVS`, drop verified, re-root refused | `odhcp6c.c: drop_privileges()` |
| Core dumps / `PR_SET_DUMPABLE` disabled in worker | `odhcp6c.c: drop_privileges()` |
| CSPRNG (`getrandom`) for transaction IDs + retransmit jitter | `odhcp6c.c: odhcp6c_random()`, `dhcpv6.c` |
| Fully-random transaction IDs (anti-spoofing) | `dhcpv6.c: dhcpv6_send_request()` |
| Reconfigure replay protection (RFC 8415 §20.4.3) | `dhcpv6.c: dhcpv6_response_is_valid()` |
| Per-state 1024-byte caps (memory-exhaustion bound) | `odhcp6c.c: odhcp6c_resize_state()` |
| Env sanitized on producer **and** re-sanitized in root monitor | `script_codec.c: script_sanitize_env()` |
| Pure, unit-testable + fuzzed IPC codec | `script_codec.c`, `tools/fuzz/` |
| Exploit mitigations on by default (PIE, full RELRO, `-z now`, noexecstack, stack-protector-strong, stack-clash-protection, `_FORTIFY_SOURCE`) | `CMakeLists.txt` |
| Observable "silent drop" diagnostics | `script_worker.c` (`debug()` at each drop) |

---

## Findings (ranked)

| # | Severity | Finding | Location |
|---|----------|---------|----------|
| 1 | Low | Non-constant-time comparison of authentication material | `dhcpv6.c:1184`, `dhcpv6.c:1197` |
| 2 | Low (deployment) | Privsep, capability drop and seccomp are all `OFF` in a default build; fallback is silent | `CMakeLists.txt:138,156`, `odhcp6c.c:259-262` |
| 3 | Low (def-in-depth) | `seccomp` allows `socket()` for any domain; worker retains `CAP_NET_RAW` | `seccomp.c:147` |
| 4 | Low | Monitor may `kill()` a recycled PID during teardown (worker PID not cleared on reap) | `script_common.c:76`, `script_monitor.c:42` |
| 5 | Low | Network-length-driven VLA + stack allocations in the DHCPv6 path | `dhcpv6.c:2026`, `:771/796/887/921` |
| 6 | Very low | `config_parse_opt_u8()` passes source length (not buffer size) as the unhexlify cap | `config.c:344` |
| 7 | Very low | `ubus_init()` returns "success" on connect failure → NULL deref at startup | `ubus.c:206`, `odhcp6c.c:815` |
| 8 | Very low | Option-iteration idiom computes out-of-bounds/NULL-based pointers before checking them (UB hygiene) | `odhcp6c.h:388`, `dhcpv6.c:1225`, `ra.h:62` |
| 9 | Info | Add `-Wvla`/`-Walloca` as a regression guard | `CMakeLists.txt` |
| 10 | Info | Worker stages retained caps as `CAPNG_INHERITABLE`; code comment claims ambient raise | `odhcp6c.c:302-305` |
| 11 | Info | Secrets (`auth_token`) freed without zeroization | `config.c:112,324`, `odhcp6c.c:100` |
| 12 | Info | Env-value sanitizer still permits shell metacharacters (by design) | `script_codec.c:110` |
| 13 | Info (correctness) | Two non-security data bugs in the ubus presentation path (DMR prefix always `::`; FQDN truncated at wire length) | `ubus.c:489`, `ubus.c:278` |

---

### 1. Non-constant-time comparison of authentication material — **Low**

`dhcpv6.c:1184` (ReconfigureKeyAuthentication, RFC 8415 §20.4) and `dhcpv6.c:1197`
(ConfigurationToken, RFC 3118) verify authentication with `memcmp()`, which returns
as soon as the first differing byte is found:

```c
/* :1184 */ rcauth_ok = !memcmp(hash, serverhash, sizeof(hash));      /* HMAC-MD5 */
/* :1197 */ rcauth_ok = !memcmp(r->data, config_dhcp->auth_token, token_len); /* shared token */
```

Both compare a secret-derived value against attacker-supplied bytes. `memcmp` has
data-dependent timing, which in principle leaks how many leading bytes matched and
enables a byte-at-a-time forgery instead of a full brute force. `rcauth_ok` gates
acceptance of Reconfigure messages (which can force RENEW/REBIND/INFORMATION-REQUEST),
so a successful forgery is a limited redirection/DoS primitive — not code execution.

**Impact:** Low. The DHCPv6 threat model is on-link/off-path; measuring the
nanosecond-scale timing delta of a ≤28-byte `memcmp` across a network is extremely
difficult, and RKAP additionally requires a monotonically increasing replay counter.
The ConfigurationToken path is the more relevant one because it compares a *static
shared secret*.

**Why worth fixing:** Constant-time comparison is the standard, expected practice in
any authentication code path, and the fix is trivial and risk-free.

**Recommendation:** Add a small constant-time comparator and use it at both sites:

```c
static bool ct_equal(const void *a, const void *b, size_t n) {
    const volatile uint8_t *x = a, *y = b; uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= x[i] ^ y[i];
    return d == 0;
}
```

(The length pre-checks that already guard the token path stay as-is; only the byte
comparison changes.)

---

### 2. Privilege separation, capability drop and seccomp are opt-in at build time; a default build is a single root process — **Low (deployment)**

The headline mitigations of this tree are gated behind CMake options that default
to **OFF**:

- `option(LIBCAP_NG "Drop privileges using libcap-ng" OFF)` — `CMakeLists.txt:138`
- `option(SECCOMP "Confine the worker with a seccomp-BPF syscall filter" OFF)` — `CMakeLists.txt:156`

Without `WITH_LIBCAP_NG`, `privsep_should_enable()` compiles to `return false`
(`odhcp6c.c:259-262`), so the monitor/worker split never happens, no privileges are
dropped, and `seccomp_apply()` is a no-op stub. A plain `cmake && make` build
therefore runs exactly like upstream odhcp6c: **one process, as root, parsing
attacker-controlled DHCPv6/RA input with no syscall filter** — only the
compiler/linker mitigations (`HARDENING=ON` by default) apply.

Two aggravating details:

- **The fallback is silent.** The `WITH_LIBCAP_NG` build logs
  `"privsep: not running as root, staying single-process"` when applicable, but a
  build without the option says nothing at all — an operator cannot tell from the
  logs that the hardened mode is absent.
- The review above (and any security claims derived from it) describes the
  fully-enabled configuration; nothing in the build fails or warns if a packager
  omits the flags.

**Impact:** Low as a code matter (it is working as configured), but it is the
single highest-leverage decision for the real-world security posture of a deployment.

**Recommendation:**
1. Enable `-DLIBCAP_NG=ON -DSECCOMP=ON` in release packaging/CI defaults, and
   consider flipping the CMake defaults to ON once the libcap-ng/libseccomp
   dependencies are acceptable for the target distros (keeping `-DLIBCAP_NG=OFF`
   as the documented opt-out).
2. In builds compiled without `WITH_LIBCAP_NG`, log a startup `notice()` that the
   daemon is running without privilege separation, mirroring the message the
   capable build emits when started as non-root.
3. State the required build flags in `README.md` next to any description of the
   privsep/seccomp design.

---

### 3. `seccomp` permits `socket()` with any domain while the worker keeps `CAP_NET_RAW` — **Low (defense-in-depth)**

`seccomp.c:147` allows `socket()` unconditionally. The worker deliberately retains
`CAP_NET_RAW` (to re-create the DHCPv6 socket after `DHCPV6_RESET`). The combination
means a worker compromised via a parser bug could open, e.g., an `AF_PACKET` socket
and sniff/inject arbitrary layer-2 frames — capability that the retained
`CAP_NET_RAW` would otherwise gate, but that seccomp could block first.

The post-seccomp `socket()` callers are (verified):

- the DHCPv6 `AF_INET6/SOCK_DGRAM` re-create on `DHCPV6_RESET` (`dhcpv6.c:580`);
- the `AF_INET6` address-generation sockets (`ra.c:393`, `ra.c:441`);
- **on `WITH_UBUS` builds, `AF_UNIX`**: libubus `ubus_reconnect()` opens a fresh
  unix-domain socket to ubusd after a broker restart (`ubus.c:195`, reached from the
  `connection_lost` callback in the worker's main loop — the same path whose
  `epoll_ctl` re-arm is already allow-listed, `seccomp.c:126-135`);
- **`AF_UNIX` from libc syslog**: if the `/dev/log` connection is lost (syslogd
  restart), the next `vsyslog()` inside the worker re-opens it.

The `AF_NETLINK` socket is created in `ra_init()` (`ra.c:115`) *before*
`drop_privileges()`/`seccomp_apply()` (`odhcp6c.c:792` vs `832/845`) and is never
re-created, so it does not need to be allowed.

**Recommendation:** Narrow `socket()` with an argument filter, exactly as was
already done for `ioctl` — but it must allow **both** `AF_INET6` and `AF_UNIX`
(an `AF_INET6`-only rule would kill the worker on a ubusd restart or a syslogd
restart):

```c
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
                 SCMP_A0(SCMP_CMP_EQ, AF_INET6));
seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(socket), 1,
                 SCMP_A0(SCMP_CMP_EQ, AF_UNIX));
```

This still blocks `AF_PACKET`/`AF_NETLINK`/`AF_INET` raw sockets — precisely the
domains a hijacked `CAP_NET_RAW` worker would want.

**Caveat (same as the `ioctl` work):** validate empirically across glibc and musl
over a full lifecycle (`ODHCP6C_SECCOMP_DIAG=1`), including the ubus-reconnect and
syslog-restart harness scenarios, before tightening. If a further domain surfaces,
add it explicitly with a comment; otherwise keep `socket` broad and leave a TODO
enumerating the requirement. Note `socketcall` (32-bit multiplexer) cannot be
argument-filtered the same way, so document that arches routing through
`socketcall` fall back to the broad allow.

---

### 4. Monitor can signal a recycled PID during teardown — **Low**

When the SIGCHLD handler reaps the worker it records the status but **does not clear
`monitor_worker_pid`**:

```c
/* script_common.c:76 */
if (monitor_worker_pid > 0 && child == monitor_worker_pid) {
    monitor_worker_status = status;
    monitor_worker_reaped = 1;          /* monitor_worker_pid left set */
}
```

`monitor_sighandle()` (`script_monitor.c:42`) still forwards signals to that stale
PID:

```c
if (monitor_worker_pid <= 0) return;
... kill(monitor_worker_pid, signal);
```

After the worker is reaped, the monitor runs a bounded teardown/drain that can last
up to ~15 s (`script_monitor.c:203-228`) with these handlers still installed. If an
administrator sends SIGTERM/SIGUSR to the monitor in that window and the kernel has
recycled the worker's PID, the monitor (running as **root**) delivers the signal to
an unrelated process.

**Impact:** Low — narrow window, requires PID reuse plus an externally-delivered
signal during shutdown.

**Recommendation:** Clear `monitor_worker_pid` when the worker is reaped (in
`script_sighandle`), and/or gate `monitor_sighandle()` on `!monitor_worker_reaped`.
Guard the store/clear consistently (it is already `volatile`).

---

### 5. Network-length-driven VLA and stack allocations in the DHCPv6 path — **Low (latent)**

- `dhcpv6.c:2026`: `char buf[len + 3];` where `len` derives from a server-supplied
  status-message option length.
- `dhcpv6.c:771,796,921`: `alloca()` sized from state entry counts.
- `dhcpv6.c:887`: `struct dhcpv6_ia_addr ia_na_array[ia_na_entry_cnt];` (VLA).

All are currently **bounded**: the status message is capped by the 1536-byte receive
buffer (`dhcpv6.c:2363`), and the `alloca`/VLA counts come from per-state buffers
capped at 1024 bytes (`odhcp6c_resize_state()`), so each allocation is at most a
couple of KB. `-fstack-clash-protection` (on by default) further mitigates the
stack-probe risk.

**Why still worth addressing:** sizing a stack object directly from
attacker-influenced input is a latent class of bug — it silently becomes dangerous
if any upstream cap is ever loosened (e.g., the receive buffer grows). Converting
`dhcpv6_log_status_code`'s VLA to a fixed buffer (cap the printed message length,
e.g. 256 bytes) and the `dhcpv6_send` allocations to a small fixed/heap buffer would
remove the class and allow enabling `-Wvla`/`-Walloca` (see #9).

---

### 6. `config_parse_opt_u8()` passes the wrong length to `script_unhexlify()` — **Very low**

`config.c:335-345`:

```c
int len = strlen(src);
uint8_t *tmp = realloc(*dst, len/2);     /* buffer is len/2 bytes */
...
return script_unhexlify(*dst, len, src); /* cap passed = len, not len/2 */
```

The destination cap handed to `script_unhexlify()` is the *source string length*,
while the buffer is only `len/2`. This is **currently safe** because the decoder
consumes at least two input characters per output byte, so it can never write more
than `len/2` bytes — but the safety is an accident of the consumer's internals, not
an explicit contract. It only affects CLI/ubus-supplied option data (locally
trusted), not network input.

**Recommendation:** Pass the true buffer capacity (`len/2`) so the bound is
self-evident and robust against future changes to `script_unhexlify()`.

---

### 7. `ubus_init()` reports success when the ubus connection fails → NULL deref — **Very low (robustness)**

`ubus.c:206`:

```c
if (!(ubus = ubus_connect(NULL)))
    return NULL;      /* NULL == "no error string" to the caller */
```

The caller treats a NULL return as success (`odhcp6c.c:809`), then unconditionally
dereferences the context:

```c
struct ubus_context *ubus = ubus_get_ctx();   /* NULL */
int ubus_socket = ubus->sock.fd;              /* NULL deref -> crash */
```

**Impact:** Very low — startup-only crash, on `WITH_UBUS` builds, only when `ubusd`
is unavailable at launch (normally ordered after ubus on OpenWrt). Not
runtime/attacker-triggerable.

**Recommendation:** Return a non-NULL error string from `ubus_init()` on
`ubus_connect()` failure (or have the caller treat a NULL context as fatal).

---

### 8. Option-iteration idiom computes out-of-range pointers before bounds-checking them — **Very low (UB hygiene)**

Two related instances of technically-undefined pointer arithmetic, both inherited
from upstream and both harmless on every flat-memory target this runs on:

- The iteration macros validate options with pointer *comparison after* pointer
  *construction*: `dhcpv6_for_each_option` (`odhcp6c.h:388-394`) computes
  `odata + olen` (up to `NULL_option_len = 65535` bytes past the end of a 1536-byte
  buffer) before testing `<= end`; `icmpv6_for_each_option` (`ra.h:62-65`) does the
  same with `opt + opt->len` (up to 2040 bytes past a 1500-byte buffer). C only
  defines pointer arithmetic within (or one past) the underlying object.
- `dhcpv6_response_is_valid()` initializes `odata = NULL, olen = UINT16_MAX`
  (`dhcpv6.c:1109-1111`) and evaluates `(odata + olen) > end` after the loop
  (`dhcpv6.c:1225`). For a reply carrying zero options the loop body never runs and
  this computes `NULL + 65535` — UB, and the check itself is unreachable-by-design
  for iterated options (the macro already guarantees `odata + olen <= end`), so the
  only case it ever evaluates is the UB one.

**Impact:** Very low. No compiler miscompiles this today, and the values are used
only in comparisons. But the codec fuzz target already builds with
`-fsanitize=undefined` (`CMakeLists.txt:191`); if fuzzing is ever extended to the
DHCPv6/RA parsers (a natural next step), UBSan's pointer-overflow checks will flag
these immediately.

**Recommendation:** Rewrite the checks length-first — e.g.
`(olen) <= (size_t)((uint8_t*)(end) - (odata))` in the macro — and guard or delete
the dead post-loop check (`odata && odata + olen > end`). Behavior is unchanged;
the parsers become sanitizer-clean and fuzz-ready.

---

### 9. Add `-Wvla` / `-Walloca` as a build guard — **Info**

The build already uses `-Wall -Wextra -Werror` and a strong hardening set, but does
not flag VLAs/`alloca`. After addressing #5, adding `-Wvla` (and optionally
`-Walloca`) would prevent reintroduction of stack allocations sized from untrusted
lengths. Introduce it *after* the #5 cleanup so the build stays green.

---

### 10. Worker stages retained capabilities as `CAPNG_INHERITABLE`; comment claims ambient raise — **Info**

`drop_privileges()` stages `CAP_NET_RAW` and `CAP_NET_BIND_SERVICE` with
`CAPNG_EFFECTIVE | CAPNG_PERMITTED | CAPNG_INHERITABLE` (`odhcp6c.c:302-305`), and
the comment at `odhcp6c.c:307-308` says `capng_change_id()` "re-raises the staged
caps as ambient where supported".

The worker never `exec`s (and with `SECCOMP=ON`, `execve` is not in the allow-list),
so the inheritable set serves no purpose for its own operation — inheritable and
ambient capabilities only matter *across an exec*. In a `LIBCAP_NG=ON`/`SECCOMP=OFF`
build (plausible, since seccomp is separately opt-in — see #2), a compromised worker
that execs a binary carrying file-inheritable capability bits could convey
`CAP_NET_RAW` into the new program; and if any libcap-ng version does raise the
staged caps as ambient (as the comment asserts), they would survive *any* exec, since
`NO_NEW_PRIVS` does not strip ambient capabilities.

**Recommendation:** Stage only `CAPNG_EFFECTIVE | CAPNG_PERMITTED`, and correct (or
verify against the pinned libcap-ng version) the ambient claim in the comment. If
ambient retention is genuinely needed on some target, add it deliberately with
`CAPNG_AMBIENT` and a comment explaining which path requires it.

---

### 11. Authentication secrets freed without zeroization — **Info**

`config_dhcp.auth_token` (the RFC 3118 shared secret) is released with a plain
`free()` in three places (`config.c:112`, `config.c:324`, `odhcp6c.c:100`), leaving
the secret bytes in freed heap memory. `reconf_key` is correctly re-zeroed when a
new server is promoted (`dhcpv6.c:2224`) and must otherwise stay live for the
binding, so it needs no change.

**Impact:** Info-only. The worker is already non-dumpable with core dumps disabled,
so this only narrows what a *future in-process* memory-disclosure bug could leak
from freed allocations.

**Recommendation:** `explicit_bzero(token, strlen(token))` before each `free()` of
`auth_token` (glibc ≥2.25 and musl both provide it; the build already requires
`_GNU_SOURCE`).

---

### 12. Env-value sanitizer still permits shell metacharacters — **Info (by design)**

`script_sanitize_env()` (`script_codec.c:110`) replaces non-printable/non-ASCII
bytes, backtick, `$`, `\`, quotes, and non-space whitespace, but intentionally
leaves other shell metacharacters (`; | & < > ( ) { } * ? ! #`) intact in *values*.
This is safe at the exec boundary — values cross via `execv`'s `envp`, not a shell —
and is documented as relying on the consuming script to quote its variables. No
change recommended; noted so the residual reliance on script hygiene is explicit. If
maximum paranoia is ever desired, the shipped `odhcp6c-example-script.sh` is the
right place to confirm every `$VAR` is quoted.

---

### 13. Non-security correctness defects in the ubus presentation path — **Info (correctness, not security)**

Found while verifying the bounds of the `*_to_blob()` builders; both are
memory-safe but publish wrong data over ubus:

- **MAP-T DMR prefix is always `::`** — `s46_to_blob()`'s DMR branch
  (`ubus.c:480-493`) zeroes `in6`, bounds-checks `prefix6len`, then calls
  `inet_ntop()` **without ever copying the prefix**: the
  `memcpy(&in6, dmr->dmr_ipv6_prefix, prefix6len)` present in the equivalent
  script-env builder (`script_worker.c:564`) is missing. Every `get_state` reply
  reports `"dmr": "::"`.
- **`fqdn_to_blob()` truncates at the wire length, not the string length** —
  `ubus.c:272-278` does `buf[l] = '\0'` where `l` is `dn_expand()`'s return value
  (bytes *consumed from the wire*), not the length of the expanded name.
  `dn_expand` already NUL-terminates its output, and a successful expansion consumes
  ≤255 wire bytes < the 257-byte blobmsg allocation, so the write is always
  in-bounds — but any name using DNS compression pointers (`l` < expanded length)
  gets silently truncated (e.g. a 2-byte pointer yields a 2-character name). The
  script-env counterpart `fqdn_to_env()` correctly uses `strlen`. Drop the
  `buf[l] = '\0'` write (or replace `l` with `strlen(buf)`).

Neither is attacker-leverageable (worst case: a server mangles the presentation of
its own data), but both should be fixed for correctness and to keep the two
presentation layers equivalent.

---

## Reviewed and found robust (assurance)

- **DHCPv6 option iteration** (`dhcpv6_for_each_option`, `odhcp6c.h:388`): checks both
  the 4-byte header and `odata + olen <= end` before each body; no integer overflow
  (lengths are `uint16_t`). All option handlers respected the invariants. (See #8
  for a pedantic UB note on *how* the check is phrased; the bound itself is correct.)
- **RA ingress gate** (`ra_icmpv6_valid`, `ra.c:322`): requires hop-limit 255 and a
  link-local source, and demands the option area consume the datagram exactly
  (`opt == end`), which also rejects any RA shorter than a full
  `nd_router_advert` header before any header field is read.
- **RA option iteration** (`icmpv6_for_each_option`, `ra.h:62`): rejects zero-length
  options (no infinite loop) and validates the full `len*8` span; every RA sub-parser
  (MTU, RIO, PIO, RDNSS, DNSSL, captive-portal) re-checks `... > &buf[len]` before
  reads/`memcpy`, and `dn_expand` is capped by `RA_DNSSL_MAXNAME`, matching the
  `alloca`'d entry buffer.
- **rtnetlink link watcher** (`ra_link_up`): `NLMSG_OK`/`RTA_OK`-bounded parsing; a
  short/malformed message yields a negative payload length that `RTA_OK` rejects.
  Spoofing unicast rtnetlink to the worker's socket requires `CAP_NET_ADMIN`, so
  carrier events are effectively kernel-trusted.
- **IPC codec** (`script_req_decode`): magic/padding/resume/caps checks, exact
  size-match (`len == sizeof(req) + action_len + env_total`), `env_count <= env_cap`,
  per-entry NUL via `memchr`, full-consumption check, action allow-list, and per-entry
  re-sanitization. Pure and fuzzed. No over-read path found. A datagram truncated by
  the transport fails the exact-size check, so `MSG_TRUNC` needs no special handling.
- **RKAP HMAC verification**: correctly zeroes the auth key field in the received
  buffer before hashing; option bounds (`olen == 28`) make the `rkap` struct fit
  exactly within the validated span.
- **Env builders** (`script_worker.c`): `ipv6_to_env`/`bin_to_env`/`fqdn_to_env`/
  `entry_to_env`/`s46_to_env`/PASSTHRU — every allocation size was checked against
  what is written (including the hexlify `+1` NUL and the `open_memstream` dynamic
  paths); no off-by-one found. `fqdn_to_env`'s compression-driven expansion is
  bounded by the running `buf_size - buf_len` cap, so pointer games can only truncate,
  never overflow.
- **ubus RPC surface** (`ubus.c`): all methods use typed `blobmsg_policy` parsing;
  nested rtx tables re-check attribute types per entry; every config setter
  range-validates its input. The `*_to_blob()` builders re-run the bounds-checked
  option iterator over state data, `blobmsg_alloc_string_buffer(..., n)` reserves
  `n+1` internally so the hexlify/`inet_ntop` writes fit, and the captive-portal URI
  is copied with an explicit length + NUL instead of `strlen` on unterminated state
  (`ubus.c:606-615`). The reconnect/teardown path clears the global context and the
  main loop re-fetches it every iteration (`odhcp6c.c:1096-1107`), so no stale-fd
  poll or freed-context dereference. (Two data-correctness bugs noted as #13.)
- **fork/SIGCHLD discipline** (`script_spawn`, `script_common.c`): SIGCHLD blocked
  across `fork()`, `running` snapshotted before `kill()` (never signals PID 0/group),
  fork-failure leaves `running` intact, drains bounded and escalate SIGTERM→SIGKILL.
  The monitor's delayed script child `putenv`s from its own copy-on-write copy of the
  receive buffer, so the parent's next datagram cannot race it.
- **Signal handlers**: all async-signal-safe (flag stores, `waitpid`, `kill`, `write`).
- **Randomness**: `getrandom` loop handles EINTR/short reads and rejects `len > INT_MAX`.
- **Privilege drop**: fail-closed, refuses uid/gid 0, verifies the drop and that root
  cannot be regained.
- **No banned primitives**: no `strcpy`/`sprintf`/`system`/`popen`/`gets` anywhere in
  `src/`.

---

## Suggested sequencing

1. **#1 constant-time auth compare** — trivial, correct-by-construction, auth path.
2. **#2 build defaults** — packaging/CI change only; highest real-world leverage.
3. **#4 clear worker PID on reap** — small, removes a root-`kill` foot-gun.
4. **#7 / #6 / #13** — one-line robustness/correctness fixes; #8's `odata` guard can
   ride along.
5. **#5 then #9** — de-VLA the DHCPv6 path, then enable `-Wvla`/`-Walloca` to lock it in.
6. **#3 seccomp `socket()` AF filter** — highest validation cost; do it as its own
   change with a full glibc+musl lifecycle check under `ODHCP6C_SECCOMP_DIAG`,
   including the ubus-reconnect scenario, and remember it must allow `AF_UNIX` as
   well as `AF_INET6`.

#10 and #11 are independent one-liners that can land anytime.

*None of the above blocks release; the current posture is strong. These are
incremental defense-in-depth improvements.*
