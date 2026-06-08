# nginx-error-abuse-module

[![Build and Test](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/build-test.yml/badge.svg)](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/build-test.yml)
[![Valgrind](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/valgrind.yml/badge.svg)](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/valgrind.yml)
[![CodeQL](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/codeql.yml/badge.svg)](https://github.com/eilandert/nginx-error-abuse-module/actions/workflows/codeql.yml)

**What it is:** a dynamic NGINX module, written in C (no Lua, no JavaScript),
that automatically blocks clients who trigger too many HTTP errors. Think
fail2ban for `403`/`404`/`5xx` storms, but enforced inside NGINX itself with no
external log-scanning daemon.

**What it does:** you choose which status codes count as abuse, how many are
allowed, over what time window, and how long the block lasts. When a client
crosses the threshold it starts receiving `429 Too Many Requests` (or a status
you pick) until the block expires. Example: after five `403` or `404` responses
within ten seconds, further requests from that client get `429` for twenty
minutes.

Clients are identified by IP address by default, but the key can also be an
account ID or any other NGINX variable. Counters are shared by all workers, can
optionally survive a full restart, and can be aggregated across multiple NGINX
hosts through Redis.

Local shared-memory and disk persistence work without a Redis server; building
the module requires `libhiredis`.

## Features

- Counts configurable status codes and ranges, such as `403,404,429` or
  `400-499`.
- Uses an exact sliding window rather than a fixed window.
- Stores state in an NGINX shared-memory zone across all workers.
- Supports multiple independently configured zones.
- Preserves state across graceful reloads automatically.
- Can optionally persist state to disk across stop/start and host restarts
  with CRC32 corruption detection.
- Can aggregate counters and blocks across multiple NGINX hosts with Redis.
- Circuit breaker pattern: automatically suspends Redis operations after
  consecutive failures to prevent log spam and wasted syscalls.
- Supports dry-run mode and logging variables.
- Uses non-blocking Redis I/O and retains local protection if Redis is down.
- Optimized for the common case: minimal overhead for non-error responses.

## Configuration

```nginx
load_module modules/ngx_http_error_abuse_module.so;

http {
    error_abuse_redis host=127.0.0.1 port=6379
                      prefix=ea_ timeout=100ms;
    # TLS + ACL auth example:
    # error_abuse_redis host=tls://redis.internal port=6380
    #                   user=erroruser password=secret db=3 prefix=ea_;

    error_abuse_zone zone=client_errors:10m
                     key=$binary_remote_addr
                     statuses=403,404,429,500-599
                     interval=10s
                     threshold=5
                     block=20m
                     inactive=1h
                     redis=on
                     persist=/var/lib/nginx/error-abuse-client_errors.state
                     persist_interval=5s;

    log_format main '$remote_addr $request $status '
                    'error_abuse=$error_abuse_status '
                    'count=$error_abuse_count';

    server {
        location / {
            error_abuse zone=client_errors status=429;
        }
    }
}
```

The state directory must already exist and be writable by the NGINX worker
user. Persistence and Redis are independent and optional. Without `persist=`,
local state survives graceful reloads but not a full process restart. With
`redis=on`, active Redis blocks survive an NGINX restart and are shared by
every host using the same prefix and zone configuration.

### Excluding clients

The module ignores empty keys. This makes `map` the preferred integration
point for allowlists and other modules:

```nginx
map $remote_addr $error_abuse_key {
    127.0.0.1  "";
    10.0.0.0/8 "";
    default    $binary_remote_addr;
}

error_abuse_zone zone=client_errors:10m
                 key=$error_abuse_key
                 statuses=403,404
                 interval=30s
                 threshold=10
                 block=15m;
```

When NGINX is behind a trusted proxy or CDN, configure the standard
`real_ip` module correctly and keep `$binary_remote_addr` as the key. Do not
use an untrusted `X-Forwarded-For` header directly.

## Directives

### `error_abuse_zone`

Syntax:

```nginx
error_abuse_zone zone=name:size
                 key=complex_value
                 statuses=code[,code|range...]
                 interval=time
                 threshold=number
                 block=time
                 [inactive=time]
                 [redis=on|off]
                 [persist=path]
                 [persist_interval=time];
```

Context: `http`

All required parameters are zone-specific. `threshold` is limited to 1024 to
keep per-key shared-memory use bounded. `inactive` defaults to the larger of
one hour, `interval`, or `block`.

The status list accepts exact codes and inclusive ranges from 100 through
599. Example: `statuses=403,404,429,500-599`.

`persist_interval` defaults to 5 seconds when `persist` is configured. The
file is replaced atomically. A crash can lose changes since the last
snapshot; graceful worker shutdown also writes a final snapshot.

`redis=on` enables cluster-wide counting for this zone and requires an
`error_abuse_redis` directive in the same `http` block. Every NGINX host
participating in a zone must use the same zone name, interval, threshold,
block duration, and Redis prefix.

### `error_abuse_redis`

Syntax:

```nginx
error_abuse_redis host=[tls://]name [port=6379]
                  [user=name] [password=secret] [db=0]
                  [prefix=ea_] [timeout=100ms];
```

Context: `http`

Configures one Redis (or Valkey — same RESP protocol) endpoint per NGINX
configuration. `prefix` namespaces all module keys, defaults to `ea_`, and may
not contain `{` or `}`. Event and block keys use the same Redis hash tag, which
keeps each client's keys in one slot when the configured endpoint provides
Redis Cluster routing.

**Authentication** (optional): `password=` sends `AUTH` after connect; add
`user=` as well for Redis 6+ ACL authentication (`AUTH user password`). `user=`
requires `password=`. Both default to empty (no `AUTH` sent), so an
unauthenticated server still connects.

**Database** (optional): `db=N` issues `SELECT N` after connect (after `AUTH`).
Defaults to `0` (no `SELECT`; the default database is used).

**TLS** (optional): prefix the host with `tls://` (or `rediss://`) to wrap the
connection in TLS, e.g. `host=tls://redis.internal`. The server certificate is
verified against the system CA store (`/etc/ssl/certs`) and the hostname.
Self-signed server certificates are not yet supported (no `cacert=` parameter).
Requires `libhiredis_ssl` at build and run time.

Each worker maintains one asynchronous Redis connection. Block lookups pause
the request phase without blocking the worker; matching responses queue an
atomic sliding-window update. Redis errors are fail-open and the local
shared-memory zone continues to enforce its own counters.

**Circuit breaker**: After 5 consecutive Redis failures, the module
automatically suspends Redis operations for 30 seconds to prevent log spam
and wasted syscalls. Local shared-memory protection remains active.

### `error_abuse`

Syntax:

```nginx
error_abuse zone=name [status=code] [dry_run=on|off] [log_level=level];
error_abuse off;
```

Context: `http`, `server`, `location`

Enables a previously declared zone. The default block response is `429`.
Supported log levels are `info`, `notice`, `warn`, and `error`.

Subrequests are not counted. A response generated by the module itself is
also not counted, so a blocked request does not extend its own block.

## Variables

- `$error_abuse_status`: `BYPASSED`, `PASSED`, `COUNTED`, `BLOCKED`, or
  `DRY_RUN`.
- `$error_abuse_count`: number of matching responses currently in the
  sliding window.
- `$error_abuse_blocked_until`: Unix timestamp at which the block expires,
  or `0`.

## Building

```bash
apt-get install libhiredis-dev

./configure --with-compat \
    --add-dynamic-module=/path/to/nginx-error-abuse-module
make modules
```

Install `objs/ngx_http_error_abuse_module.so` in the NGINX module directory.

The `config` links `-lhiredis_ssl` for the `tls://` Redis transport, so a build
host needs the hiredis TLS library as well (Debian/Ubuntu ship it inside
`libhiredis-dev`; on some distros it is a separate `libhiredis-ssl` package).

The automated test and sanitizer matrix is documented in
[`.github/CI.md`](.github/CI.md).

## Operational notes

- Shared-memory exhaustion is fail-open: the response is served and an error
  is logged, but that event cannot be recorded.
- A zone's `key` and `threshold` cannot change during a graceful reload.
  Declare a new zone name when either value must change.
- Each persistent zone must use its own persistence file.
- Persistence files include CRC32 checksums. Corrupted files are automatically
  deleted and logged as errors.
- Persistence files are local snapshots, not a cluster synchronization
  mechanism.
- Redis synchronizes thresholds across multiple NGINX hosts. Disk snapshots
  still preserve each host's local fallback.
- Redis event keys expire after `inactive`; block keys expire after the
  configured block duration.
- A key is removed after `inactive` when it has no live block. Choose a zone
  size appropriate for the number of distinct clients and threshold.
- The persistence format is versioned but intentionally local and binary.
  Delete an incompatible file after changing to a future module version.
- Debug logging is available at `error_log ... debug;` level for
  troubleshooting. Logs track Redis circuit breaker state, shared-memory
  operations, and per-request decision flow.

## Security Notes

### Redis Trust Boundary

When using Redis cluster mode (`redis=on`), the Redis server becomes a trust
boundary. A compromised Redis instance could inject false block states or
manipulate event counters.

**Mitigation**: Ensure Redis runs on a trusted network isolated from potential
attackers. Use firewalls, VPNs, Redis AUTH (`user=`/`password=`), and TLS
(`tls://` host prefix) to restrict and encrypt access. Future versions may add
HMAC-SHA256 integrity protection for an additional security layer.

### Persistence File Integrity

Persistence files include CRC32 checksums to detect corruption (disk errors,
incomplete writes, crashes during write). Corrupted files are automatically
deleted and logged as errors. The module starts fresh with an empty zone state.

### Variable Key Sources

The module trusts the `key` value from the configured nginx variable. Best
practices:

**Recommended**: Use `$binary_remote_addr` with the `ngx_http_realip_module`
when behind a trusted proxy/CDN:

```nginx
set_real_ip_from 10.0.0.0/8;
set_real_ip_from 2001:db8::/32;
real_ip_header X-Forwarded-For;
real_ip_recursive on;

error_abuse_zone zone=client:10m
                 key=$binary_remote_addr
                 statuses=404 interval=30s threshold=10 block=15m;
```

**Not recommended**: Directly using untrusted headers like `X-Forwarded-For`
without `ngx_http_realip_module` allows client IP spoofing.

**Allowlists**: Empty keys bypass tracking. Use `map` to implement allowlists:

```nginx
map $remote_addr $error_abuse_key {
    127.0.0.1  "";      # Localhost bypassed
    10.0.0.0/8 "";      # Internal network bypassed
    default    $binary_remote_addr;
}

error_abuse_zone zone=external:10m
                 key=$error_abuse_key
                 statuses=403,404 interval=30s threshold=10 block=15m;
```

## See also

- Project article: [Auto-Ban Abusive Clients in NGINX with the error-abuse module](https://deb.myguard.nl/2026/06/auto-ban-abusive-clients-in-nginx-with-the-error-abuse-module/)
- Docker integration README: TODO
- Docker Hub overview: TODO
