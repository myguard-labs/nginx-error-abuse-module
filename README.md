# nginx-error-abuse-module

[![Build and Test](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/build-test.yml/badge.svg)](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/build-test.yml)
[![CodeQL](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/codeql.yml/badge.svg)](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/codeql.yml)
[![Security Scanners](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/security-scanners.yml/badge.svg)](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/security-scanners.yml)
[![Fuzzing](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/fuzzing.yml/badge.svg)](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/fuzzing.yml)
[![Valgrind](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/valgrind.yml/badge.svg)](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/valgrind.yml)

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
            error_abuse zone=client_errors;   # turn it on here
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
The on-disk format is a portable little-endian byte stream (not a native struct
dump). Set `persist_secret=<hex>` to additionally authenticate the file with
HMAC-SHA256.

Client identities are stored as a fixed 32-byte SHA-256 digest of the `key`, so
a large key variable (`$request_uri`, `$http_*`) costs the same memory and Redis
traffic as a small one — there is no per-key amplification.

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
| `persist_secret`   | *(none)*              | Hex-encoded key; when set, the snapshot is authenticated with HMAC-SHA256 and a tampered/forged file is rejected on load. Requires `persist`. |

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
deadline.

### `error_abuse_redis host=[tls://]name [port] [user] [password] [db] [prefix] [timeout]` — context: `http`

Points the module at one Redis server (see below).

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
  value).

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
prefixing the host: `host=tls://redis.internal`. **Treat Redis as a trust
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

## See also

- Project article: [Auto-Ban Abusive Clients in NGINX with the error-abuse module](https://deb.myguard.nl/2026/06/auto-ban-abusive-clients-in-nginx-with-the-error-abuse-module/)
- Docker integration README: TODO
- Docker Hub overview: TODO
