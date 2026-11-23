# nginx-error-abuse-module

[![Build&Test](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/build-test.yml/badge.svg)](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/build-test.yml)
[![Security Scanners](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/security-scanners.yml/badge.svg)](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/security-scanners.yml)
[![Fuzzing](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/fuzzing.yml/badge.svg)](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/fuzzing.yml)
[![Valgrind](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/valgrind.yml/badge.svg)](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/valgrind.yml)
[![CodeQL](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/codeql.yml/badge.svg)](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/codeql.yml)
[![A/UBSan](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/asan.yml/badge.svg)](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/asan.yml)
[![Lint](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/lint.yml/badge.svg)](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/lint.yml)
[![Windows](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/windows.yml/badge.svg)](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/windows.yml)
[![CI Deep](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/ci-deep.yml/badge.svg)](https://github.com/myguard-labs/nginx-error-abuse-module/actions/workflows/ci-deep.yml)

## CI

| Workflow | What it gates |
|---|---|
| `ci.yml` | orchestrator; the only `pull_request` entry point, calls the seven PR members below |
| `build-test.yml` | build, `.so` dlopen, bad-config rejection, `-Werror`, Test::Nginx runtime suite |
| `security-scanners.yml` | flawfinder, clang-tidy, Semgrep |
| `fuzzing.yml` | manual regression diagnostic; replay all recorded regressions then fuzz all discovered targets for 120s |
| `valgrind.yml` | memcheck soak |
| `codeql.yml` | CodeQL over the module TU |
| `asan.yml` | ASan+UBSan request-storm soak (static `--add-module` build), single-process + multi-worker/reload lanes |
| `lint.yml` | `ci/linter/` — shellcheck, ruff, perlcritic, yamllint/actionlint/zizmor, nginx-convention and repo-policy checks; same entry point as `.githooks/pre-commit` |
| `windows.yml` | MinGW-w64 static build on PRs |
| `windows-msvc.yml` | monthly/manual MSVC build, directive, persistence, restart and two-worker ownership controls |
| `ci-deep.yml` | monthly/manual four-slot sweep: fuzz regression + long campaign, MSVC, Memcheck, Helgrind, deep scanners and CodeQL |

### CI caching

`ci/tools/ci-build.sh` is the single chokepoint every build-test/asan/codeql/
fuzzing/ci-deep(fuzz) job goes through — no workflow duplicates cache logic.
Layers, cheapest first: package presence checks, compiler objects through ccache
(`CCACHE_COMPILERCHECK=content`), mold (skipped under `asan`), eatmydata
(wraps `./configure` only), and digest-verified source tarballs. Tarballs are
verified against `.github/versions.env` after every restore or download.

Executable trees are reused only after a fresh exact Actions cache restore on
`main` for a push, schedule or manual run. The action removes old disk state
before restoring and uses a full build identity with no fallback key. The
identity includes source and patches, build scripts/configuration, compiler,
flags, platform and installed Debian packages. PRs rebuild from pinned source
and neither restore nor save compiler objects; other refs cannot reuse executable
trees. Same-run ASan reload uses a separately verified producer-bound artifact.

Set compiler/header/library search overrides, including `LD_LIBRARY_PATH`,
`PKG_CONFIG_PATH`, `CFLAGS`, `CPPFLAGS` and `LDFLAGS`, disable executable-tree
reuse even when empty: paths in these variables can name mutable contents.
These overrides remain usable for fresh builds. `NO_CACHE=1` also forces a
fresh build; source verification remains required.

nginx's `configure` ignores a bare `CC=`, so ccache is wired through
`--with-cc="ccache $BASE_CC"`. Local builds default to
`CCACHE_DIR=$HOME/.cache/ccache`; Actions uses an empty ref/variant-specific
runner-temp directory before restoring eligible compiler objects. Export the
actual `CCACHE_DIR` when inspecting statistics. The cache action documents each
layer's key and trust boundary.

## What is this?

Imagine someone keeps poking your website with requests that don't exist —
hammering random URLs (lots of `404`s), banging on stuff they're not allowed to
see (lots of `403`s), or spamming requests until your server starts coughing up
`500` errors. That's abuse, and it wastes your server's time.

This is a small NGINX module, written in plain C, that watches those error
responses and **bans the troublemaker automatically**. Think of it like
fail2ban, except it lives *inside* NGINX — no extra daemon reading log files, no
Lua, no JavaScript. You pick which error codes count, how many are allowed, and
for how long the offender gets locked out.

When a client crosses the line, it starts getting `429 Too Many Requests`
(or any status you choose) until the ban expires. Counters are shared across all
NGINX worker processes, can survive a restart (disk snapshots), and can even be
shared between multiple servers using Redis.

## Full configuration example

```nginx
load_module modules/ngx_http_error_abuse_module.so;

http {
    # Optional: share bans across servers (see the Redis section).
    error_abuse_redis host=127.0.0.1 port=6379 prefix=ea_ timeout=100ms;

    # Define a zone: a shared-memory area that holds the counters.
    error_abuse_zone zone=client_errors:10m
                     key=$binary_remote_addr
                     statuses=403,404,500-599
                     interval=300s
                     threshold=100
                     block=60m
                     inactive=1h
                     persist=/var/lib/nginx/error-abuse-client_errors.state
                     persist_interval=5s;

    # Handy log line so you can see what the module decided.
    log_format main '$remote_addr $request $status '
                    'error_abuse=$error_abuse_status '
                    'count=$error_abuse_count';

    server {
        location / {
            error_abuse zone=client_errors log_level=notice; # turn it on here
        }
    }
}
```

Read that zone line as: *"if one IP causes 100 of these error responses within
any 5-minute window, ban it for 60 minutes."* The `persist=` file lets bans
survive a full NGINX restart; the directory must already exist and be writable
by the worker user. **Keep that directory private** (owned by the worker user,
not group/world-writable): the snapshot's CRC32 detects corruption but is *not*
tamper protection, so anyone who can write the file can forge or remove bans.
Temp snapshots are created with `O_EXCL|O_NOFOLLOW` and `fsync`'d before the
atomic rename, so a hostile symlink cannot redirect the write and a crash cannot
leave a truncated state file. On builds with `--with-threads` the snapshot file
I/O runs on a thread pool, so a slow disk never stalls the worker event loop.
Restore accepts only regular files. POSIX restores use nonblocking opens and
reject final-component symlinks with `O_NOFOLLOW`; FIFO inputs cannot wait for
a writer. If either safety flag is unavailable, restore logs a warning and is
skipped; snapshot writes remain enabled. Windows retains its native open
semantics (including symlink resolution) and checks the opened file type.
The type check happens after open, so it does not prevent device-open side
effects; keeping the persistence directory private remains necessary.
The on-disk format is a portable little-endian byte stream (not a native struct
dump). Set `persist_secret=<hex>` to additionally authenticate the file with
HMAC-SHA256. The key must be at least 16 bytes (32 hex characters); 32 bytes
(64 hex characters) is recommended. Generate with `openssl rand -hex 32`.

The HMAC binds a snapshot to its zone name and `key` expression (snapshot
format version 3), so a file copied from another zone, or written under a
different `key`, fails verification and is ignored even when both zones share
the secret and threshold. Upgrading from a version 2 module resets the saved
bans of authenticated zones once: their version 2 snapshot is not bound to a
zone, so it is ignored with a "legacy version 2 authenticated snapshot" warning
(the file is kept) and replaced by a version 3 snapshot on the next save.
Zones without `persist_secret` still restore version 2 snapshots.

Client identities are stored as a fixed 32-byte SHA-256 digest of the `key`, so
a large key variable (`$request_uri`, `$http_*`) costs the same memory and Redis
traffic as a small one — there is no per-key amplification. The digest is
unkeyed, so `client_sha256` is a pseudonymous identifier, not anonymization:
with the default `key=$binary_remote_addr` the input space is only the IPv4 or
IPv6 address space, and a digest can be reversed by brute force. Module log
records use the 64-character lowercase digest as `client_sha256` and do not
write the raw key bytes themselves. However, nginx appends request context to
error-log lines written while a request is active (for example
`client: <addr>, server: ..., request: ...`), so the client address and request
line may still appear in the error log. The module does not suppress this;
control it through nginx's error-log configuration and log file permissions.
Redis and hiredis failures retain numeric status, reply type and detail length
for diagnosis, but omit backend-provided error text.

When `nginx -t` rejects an invalid or duplicate parameter of `error_abuse_zone`,
`error_abuse` or `error_abuse_redis`, the error log shows the full token only
for that directive's known non-secret options (for example `threshold=0`).
Every other token prints as `name=<redacted>`: `persist_secret=`, `password=`,
`user=`, the zone's `redis=`, any unknown name, such as `passwd=`, and a known
option whose value holds another `=`, such as `port=6390password=...`. A token
with no `=`, or whose name is not 1–32 lowercase letters, digits or
underscores starting with a letter (for example `PASSWORD=`), prints as
`<redacted>`. The `in file:line` suffix still locates it.

**Good news:** almost everything has a sensible default. The shortest config
that actually works is just:

```nginx
error_abuse_zone zone=client_errors:10m;     # uses all defaults below
location / { error_abuse zone=client_errors; }
```

## Synopsis (directives + defaults)

### `error_abuse_zone zone=name:size [...]` — context: `http`

Declares a zone. Only `zone=name:size` is required; the rest default to a
deliberately relaxed policy that catches *sustained* abuse, not the odd 404.

| Parameter          | Default               | Meaning                                            |
| ------------------ | --------------------- | -------------------------------------------------- |
| `zone`             | *(required)*          | Name and shared-memory size, e.g. `client:10m`.    |
| `key`              | `$binary_remote_addr` | What identifies a client (an NGINX variable).      |
| `statuses`         | `403,404,500-599`     | Which status codes count. Exact codes or ranges.   |
| `interval`         | `300s`                | Sliding time window the counting happens over.     |
| `threshold`        | `100`                 | Hits in the window before a ban (max `1024`).       |
| `block`            | `60m`                 | How long the ban lasts.                            |
| `inactive`         | max(1h, interval, block) | Idle clients are forgotten after this. An explicit value must be `>=` both `interval` and `block` (otherwise live windows/bans would expire early — rejected at config time). |
| `redis`            | `off`                 | Share this zone's state via Redis.                 |
| `persist`          | *(none)*              | File path to snapshot state to disk.               |
| `persist_interval` | `5s`                  | How often to write the snapshot.                   |
| `persist_secret`   | *(none)*              | Hex-encoded HMAC-SHA256 key (min. 32 hex chars / 16 bytes, recommended 64 hex chars / 32 bytes); when set, the snapshot is authenticated and a tampered/forged file is rejected on load. Requires `persist`. Generate with `openssl rand -hex 32`. |
| `on_full`          | `allow`               | What happens to a new (not-yet-tracked) identity's error response when the zone's shared memory is full: `allow` passes that one response through untracked (the historical behaviour; identities already tracked with an active ban are still rejected as normal); `reject` applies the location's configured rejection status instead, so a full zone fails closed. An **active ban is never evicted** to make room, under either setting — only unblocked, aged-out identities can be reclaimed. |

### `error_abuse zone=name [status=code] [dry_run=on|off] [log_level=level]` — context: `http`, `server`, `location`

Switches a declared zone on for that location. `error_abuse off;` turns it back
off (a second declaration in the same block is a duplicate error, in either
order). Default ban response is `429`; log levels are `info`, `notice`, `warn`,
`error`. `dry_run=on` is **observation-only**: it logs (at `log_level`) what
*would* happen but never writes shared-memory or Redis ban state, so an
enforcing sibling location on the same zone is never contaminated. The module
never counts its own ban responses or subrequests.

Every ban response the module generates carries `Cache-Control: private,
no-store` so a downstream shared cache can never replay one client's ban to
another; `429`/`503` responses also get a `Retry-After` reflecting the ban
deadline. If nginx cannot allocate either rejection header, the header filter
returns `NGX_ERROR` and aborts the response instead of sending a partial ban
response; `Retry-After` is advisory, but follows nginx's normal allocation-
failure convention rather than being silently omitted.

An `error_page` internal redirect (either a URI target or a named
`@location`) does not lose enforcement: the identity, counter and ban status
earned at the ORIGIN location follow the redirect to the destination even
when the destination has `error_abuse off`, is bound to a different zone, or
serves a custom rejection page. The destination's `dry_run=` is ignored in
that case — the origin's `dry_run` wins for the whole request.

### `error_abuse_redis host=name|tls://name|rediss://name [port=number] [user=name] [password=value] [db=number] [prefix=value] [timeout=time]` — context: `http`

Points the module at one Redis server (see below). `host=` is required; every
other option is optional and must use the `key=value` form shown above.
`host=` accepts a DNS name, an IPv4 address, or a bracketed IPv6 address
(for example `[::1]`). DNS labels contain ASCII letters, digits and interior
hyphens, with at most 63 characters per label and 253 characters overall,
excluding an optional final root dot. Set the TCP port only with `port=`
(1–65535, default 6379). Embedded ports are rejected even when they match a
separate `port=`. URLs, paths, queries, fragments, userinfo, unbracketed IPv6
and IPv6 scope identifiers are rejected. Only the optional `tls://` and
`rediss://` prefixes are accepted; both enable TLS. TLS verifies the peer's
certificate chain against `/etc/ssl/certs` and checks the original `host=`
identity before sending Redis commands (including AUTH). DNS names use hostname
verification and SNI; numeric IPv4/IPv6 hosts require a matching IP SAN and do
not send SNI. A final DNS root dot is retained for resolution and removed for
TLS verification and SNI. IPv4 literals use four decimal octets; shorthand
numeric forms such as `127.1` are rejected for TLS. A trusted certificate for a
different endpoint is rejected.

`host=` is resolved to a numeric address **once, at config load**, so the worker
event loop never blocks on `getaddrinfo()` when (re)connecting. Two consequences:
a name with several A records is pinned to its **first** address for the life of
the config (no client-side DNS failover — reload to re-resolve), and if the name
cannot be resolved at load time the module logs a warning and falls back to
resolving it in the worker (which can briefly block the event loop on reconnect
during an outage) rather than failing the reload. **Prefer a numeric IP** for a
Redis behind volatile DNS.

### Variables

- `$error_abuse_status` — `BYPASSED`, `PASSED`, `COUNTED`, `BLOCKED`, or `DRY_RUN`.
- `$error_abuse_count` — matching responses currently in the window.
- `$error_abuse_blocked_until` — Unix timestamp the ban ends, or `0`. Populated
  for both local and Redis bans (Redis stores the absolute deadline as the block
  value, rounded up to a whole second so a live ban never reports a past
  deadline).
- `$error_abuse_matched` — `1` when the request matched the zone's rule
  (`$error_abuse_status` is `COUNTED`, `BLOCKED` or `DRY_RUN`), otherwise
  empty. Use it with `access_log ... if=` to log only matching requests. That
  is handy in a dry run, where a full access log is too large to review:

  ```nginx
  log_format error_abuse '$remote_addr [$time_local] "$request" $status '
                         '$error_abuse_status count=$error_abuse_count';

  location / {
      error_abuse zone=client_errors dry_run=on;
      # An access_log here replaces the inherited ones, so repeat your
      # normal log next to the filtered one.
      access_log /var/log/nginx/access.log main;
      access_log /var/log/nginx/error-abuse.log error_abuse
                 if=$error_abuse_matched;
  }
  ```

  Requests that pass untouched (`PASSED`) or are not covered by a zone
  (`BYPASSED`) are not written to the filtered log.
  The "would block" decisions also appear in the error log at `log_level`.

### `error_abuse_stats zone;` — context: `location`

Turns the location into a read-only counters endpoint for a zone declared with
`error_abuse_zone`. It uses the same format negotiation as
nginx-http-shield-module's `shield_ban_status`. JSON is the default:

```json
{"zone":"client_errors","requests":1520,"matched":233,"blocked":41,
 "would_block":0,"bans":3,"evictions":0,"alloc_failures":0,
 "nodes":187,"blocked_clients":2,"used":69632,"size":10485760}
```

| JSON field        | Prometheus metric                          | Type    | Meaning |
| ----------------- | ------------------------------------------ | ------- | ------- |
| `requests`        | `error_abuse_requests_total`               | counter | Requests checked against the zone (once per request). |
| `matched`         | `error_abuse_matched_responses_total`      | counter | Responses with a tracked status that were checked against the threshold (enforcing and dry-run). Responses from a client that is already banned are not counted here; they normally show up under `blocked` or `would_block`. One exception: in an enforcing location that answers before preaccess (`return 404;`), a banned client's response is neither rejected nor counted in `matched`, `blocked` or `would_block`. |
| `blocked`         | `error_abuse_blocked_total`                | counter | Requests the module rejected: active bans, local or Redis, and `on_full=reject`. |
| `would_block`     | `error_abuse_dry_run_would_block_total`    | counter | Dry-run decisions that would have blocked: a request from a banned client, or a response that would reach the threshold. |
| `bans`            | `error_abuse_bans_total`                   | counter | Bans armed by this instance's local tracker when a client reached the threshold. A ban armed only in Redis (from responses counted on other instances) is not included; it shows up under `blocked` when the client returns. |
| `evictions`       | `error_abuse_zone_evictions_total`         | counter | Unblocked clients evicted to make room for a new one. |
| `alloc_failures`  | `error_abuse_zone_alloc_failures_total`    | counter | Tracked responses not recorded because the zone was full. |
| `nodes`           | `error_abuse_zone_nodes`                   | gauge   | Clients held in the zone, including expired entries not yet reclaimed. |
| `blocked_clients` | `error_abuse_blocked_clients`              | gauge   | Clients with an unexpired ban. |
| `used`            | `error_abuse_zone_used_bytes`              | gauge   | Zone bytes in use, including slab overhead. |
| `size`            | `error_abuse_zone_size_bytes`              | gauge   | Zone size in bytes. |

Every metric has a `zone` label. Client identities are never exported, so the
series count does not grow with traffic. Counters live in the zone's shared
memory and survive `nginx -s reload` when the zone size is unchanged. They are
not written to the `persist=` snapshot, so they restart from zero when nginx
restarts; Prometheus `rate()` and `increase()` handle that. Gauges come from one
locked snapshot. Ban expiry is compared with nginx's cached time, as it is on
the enforcement path, so `blocked_clients` is an event-loop-tick approximation
rather than a wall-clock point-in-time measurement.

### `error_abuse_stats_format json|prometheus;` — context: `http`, `server`, `location`

Default output format for `error_abuse_stats`. The default is `json`. For one
request, `?format=json` or `?format=prometheus` overrides it. Query names and
values are case-sensitive and are not percent-decoded. An empty, unknown or
repeated `format` argument, or a query string over 8192 bytes, returns `400`.
Other arguments are ignored. Methods other than `GET` and `HEAD` return `405`
with `Allow: GET, HEAD`. The zone name must be valid UTF-8.

```nginx
location = /error-abuse-metrics {
    error_abuse_stats client_errors;
    error_abuse_stats_format prometheus;
    error_abuse off;
    allow 127.0.0.1;
    deny all;
}
```

Metrics use Prometheus 0.0.4 (`text/plain; version=0.0.4; charset=utf-8`).
OpenMetrics 1.0 (`application/openmetrics-text; version=1.0.0;
charset=utf-8`, ending in `# EOF`) is used only when `Accept` names
`application/openmetrics-text` with a positive `q` at least as high as
`text/plain`. Wildcards never select OpenMetrics, and a malformed `Accept`
falls back to 0.0.4. Responses carry `Vary: Accept`.

> **Turn enforcement off here.** A stats location inherits `error_abuse` from
> its server or parent location like any other location. Without
> `error_abuse off;`, each scrape is counted as a request, its error responses
> (`400`, `405`) can count towards a ban, and a banned scraper gets
> `reject_status` instead of the counters.

> **Restrict this location.** The module applies no access control of its own.
> Use `allow`/`deny`, `auth_basic` or a management-only listener. Each scrape
> walks the zone under its lock, which takes O(clients) time, so scrape at a
> normal interval (15 s or more), not continuously.

## About Redis (optional)

By default each NGINX server bans on its own. If you run several servers behind
a load balancer, an attacker banned on one could just hit another. Add
`error_abuse_redis` and set `redis=on` on a zone, and all servers sharing the
same `prefix` and zone settings count together and share bans. It speaks plain
RESP, so **Valkey works too**. Connections are non-blocking, so a slow or dead
Redis never freezes a request — the module just falls back to its own local
counters (fail-open), and a circuit breaker pauses Redis for 30s after repeated
failures so your logs don't fill up. You can lock it down with AUTH
(`user=`/`password=`), pick a database (`db=N`), and encrypt with TLS by
prefixing the host: `host=tls://redis.internal` (or
`host=rediss://redis.internal`). **Treat Redis as a trust
boundary** — a compromised Redis could inject fake bans, so keep it on a private
network.

## Excluding clients (allowlists)

The module ignores **empty keys**. So the cleanest way to allowlist someone is a
`map` that returns an empty string for trusted IPs:

```nginx
map $remote_addr $error_abuse_key {
    127.0.0.1   "";            # localhost: never banned
    10.0.0.0/8  "";            # internal network: never banned
    default     $binary_remote_addr;
}

error_abuse_zone zone=client_errors:10m key=$error_abuse_key;
```

**Behind a proxy or CDN?** Don't trust `X-Forwarded-For` directly — that's
spoofable. Set up the standard `realip` module so `$binary_remote_addr` becomes
the *real* client IP:

```nginx
set_real_ip_from 10.0.0.0/8;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```

## Requirements

Build against an nginx or Angie source tree with a C compiler and the usual
PCRE2 and zlib development headers. The module also links against hiredis with
TLS support and OpenSSL 1.0.2 or newer (`libhiredis-dev` and `libssl-dev` on
Debian/Ubuntu). Older OpenSSL versions fail compilation because they lack the
required peer identity verification APIs.

Windows supports a static nginx module with either MSVC or MinGW-w64. MSVC
uses vcpkg's `hiredis[ssl]:x64-windows-static` triplet and `/MT`; MinGW-w64
uses the SSL-enabled MSYS2 hiredis package. A Win32 dynamic module is supported
only by nginx's GCC/Clang build path, not by MSVC.

## Building from source

```bash
apt-get install libhiredis-dev        # provides hiredis + its TLS lib

./configure --with-compat \
    --add-dynamic-module=/path/to/nginx-error-abuse-module
make modules
```

Copy `objs/ngx_http_error_abuse_module.so` into your NGINX module directory and
`load_module` it. The full CI/sanitizer matrix lives in
[`.github/CI.md`](.github/CI.md).

For MSVC, set `NGX_ERROR_ABUSE_INCS` to the vcpkg include directory and
`NGX_ERROR_ABUSE_LIBS` to absolute paths for the hiredis and OpenSSL static
libraries plus `crypt32`, `advapi32`, and `ws2_32`. Configure nginx with
`--crossbuild=win32 --with-cc=cl`, an x64 `vcvars64` environment, and `/MT`.
Nginx 1.31.x also needs its private XP-compatibility `WSAPoll` pointer renamed
before compilation because static hiredis imports the SDK symbol with that
name; the Windows workflow contains the exact source-local substitution. The
[`windows.yml`](.github/workflows/windows.yml) workflow is the executable build
recipe for both Windows toolchains.

## Linting

Enable the repository hook once with
`git config core.hooksPath .githooks`, then stage the files you want checked.
Run `bash ci/linter/run-all.sh` for a full-tree pass. The checker inventory,
requirements, and selective-run syntax are documented in
[`ci/linter/README.md`](ci/linter/README.md).

## See also

- Project article: [Auto-Ban Abusive Clients in NGINX with the error-abuse module](https://deb.myguard.nl/2026/06/auto-ban-abusive-clients-in-nginx-with-the-error-abuse-module/)
- Docker integration README: TODO
- Docker Hub overview: TODO
