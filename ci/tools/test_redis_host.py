#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Check Redis address-only hosts against production C and nginx configuration.

--core names a configured nginx source tree for the focused unit binary.
--nginx-binary/--module exercise nginx -t without starting a worker or Redis.
--only selects a named config case for an independently rebuilt module control.
"""

import argparse
import os
import pathlib
import shlex
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]


def hosts():
    """Name, address text, expected validity; no test depends on external DNS."""
    return [
        ("dns", "localhost", True),
        ("dns-root", "localhost.", True),
        ("dns-mixed", "Redis-1.Example", True),
        ("dns-label-max", "a" * 63, True),
        ("dns-name-max", ".".join(["a" * 63] * 3 + ["a" * 61]), True),
        ("dns-root-max", ".".join(["a" * 63] * 3 + ["a" * 61]) + ".", True),
        ("ipv4", "127.0.0.1", True),
        ("ipv6", "[::1]", True),
        ("ipv6-mapped", "[::ffff:127.0.0.1]", True),
        ("ipv6-full", "[2001:db8:0:0:0:0:0:1]", True),
        ("ipv6-unspecified", "[::]", True),
        ("ipv6-trailing-double-colon", "[2001:db8::]", True),
        ("empty", "", False),
        ("embedded-ipv4", "127.0.0.1:6380", False),
        ("embedded-dns", "localhost:6380", False),
        ("embedded-ipv6", "[::1]:6380", False),
        ("embedded-empty-port", "localhost:", False),
        ("embedded-zero-port", "localhost:0", False),
        ("embedded-max-port", "localhost:65535", False),
        ("embedded-overflow-port", "localhost:65536", False),
        ("bare-ipv6", "::1", False),
        ("bad-ipv6", "[not-an-ip]", False),
        ("unclosed-ipv6", "[::1", False),
        ("ipv6-suffix", "[::1]extra", False),
        ("ipv6-scope", "[fe80::1%lo]", False),
        ("ipv6-leading-colon", "[:0:0:0:0:0:0:0:1]", False),
        ("ipv6-leading-colon-compressed", "[:1::]", False),
        ("ipv6-trailing-colon", "[1::2:]", False),
        ("ipv6-single-colon", "[:]", False),
        ("ipv4-brackets", "[127.0.0.1]", False),
        ("root-only", ".", False),
        ("empty-label", "local..host", False),
        ("leading-dot", ".localhost", False),
        ("double-root", "localhost..", False),
        ("leading-hyphen", "-localhost", False),
        ("trailing-hyphen", "localhost-", False),
        ("interior-trailing-hyphen", "local-.host", False),
        ("label-overflow", "a" * 64, False),
        ("name-overflow", ".".join(["a" * 63] * 4), False),
        ("underscore", "local_host", False),
        ("path", "localhost/private", False),
        ("query", "localhost?password=fixture-value", False),
        ("fragment", "localhost#fixture-value", False),
        ("userinfo", "user:fixture-value@localhost", False),
        ("url", "redis://user:fixture-value@localhost:6380/0", False),
        ("http-url", "http://localhost", False),
        ("unix", "unix:/private/socket", False),
        ("percent", "local%68ost", False),
        ("space", "local host", False),
        ("tab", "local\thost", False),
        ("unicode", "lócálhost", False),
    ]


def unit(core, root, negative_controls):
    source = (ROOT / "src/ngx_http_error_abuse_module.c").read_text()
    start = source.index("static ngx_int_t\nngx_http_error_abuse_redis_host_valid(")
    body = source[start : source.index("\n}\n", start) + 3]
    generated = root / "host.c"
    prefix = "#include <ngx_config.h>\n#include <ngx_core.h>\n"
    suffix = """
int main(int argc, char **argv) {
    ngx_str_t host;
    if (argc != 3) { return 2; }
    host.data = (u_char *) argv[1];
    host.len = strlen(argv[1]);
    if ((ngx_http_error_abuse_redis_host_valid(&host) == NGX_OK)
        != (argv[2][0] == '1')) {
        fprintf(stderr, "FAIL: host validity differs from expected %s\\n", argv[2]);
        return 1;
    }
    return 0;
}
"""

    def build(text, label):
        generated.write_text(prefix + text + suffix)
        binary = root / label
        command = [
            *shlex.split(os.environ.get("CC", "cc")),
            "-O2",
            "-g",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-ffunction-sections",
            "-fdata-sections",
            "-Wl,--gc-sections",
            *[
                f"-I{core / p}"
                for p in ("src/core", "src/event", "src/os/unix", "objs")
            ],
            str(generated),
            str(core / "src/core/ngx_inet.c"),
            "-o",
            str(binary),
        ]
        print(shlex.join(command), flush=True)
        subprocess.run(command, check=True)
        info = binary.stat()
        print(
            f"binary={binary} mtime_ns={info.st_mtime_ns} size={info.st_size}",
            flush=True,
        )
        return binary

    def check(binary, case):
        name, host, valid = case
        result = subprocess.run(
            [str(binary), host, str(int(valid))],
            capture_output=True,
            text=True,
            check=False,
        )
        print(f"{name}: exit={result.returncode} {result.stderr}", flush=True)
        return result

    binary = build(body, "green")
    for case in hosts():
        check(binary, case).check_returncode()
    if negative_controls:
        mutant = build(body.replace("return NGX_ERROR;", "return NGX_OK;"), "mutant")
        case = next(case for case in hosts() if case[0] == "embedded-ipv4")
        result = check(mutant, case)
        assert result.returncode == 1 and "FAIL: host validity" in result.stderr
        print("OK: embedded-ipv4 control observed red", flush=True)
        check(build(body, "restored"), case).check_returncode()


def configs(binary, module, root, only):
    cases = [(name, f"host={host}", valid, not valid) for name, host, valid in hosts()]
    for scheme in ("tls://", "rediss://"):
        for host in ("localhost", "localhost.", "127.0.0.1", "[::1]"):
            cases.append(
                (f"{scheme}-{host}", f"host={scheme}{host} port=6380", True, False)
            )
        for host in (
            "",
            "localhost:6380",
            "[::1]:6380",
            "user:fixture-value@localhost",
            "localhost/0",
            "redis://localhost",
        ):
            cases.append(
                (f"{scheme}-invalid-{host}", f"host={scheme}{host}", False, True)
            )
    for port in (1, 6379, 6380, 65535):
        cases.append((f"port-{port}", f"host=127.0.0.1 port={port}", True, False))
    for port in (0, 65536, -1, "abc"):
        cases.append(
            (f"invalid-port-{port}", f"host=127.0.0.1 port={port}", False, False)
        )
    for host in ("localhost:6380", "127.0.0.1:6380", "[::1]:6380"):
        for port in (6380, 6381):
            cases.append(
                (f"conflict-{host}-{port}", f"host={host} port={port}", False, True)
            )
            cases.append(
                (
                    f"reverse-conflict-{host}-{port}",
                    f"port={port} host={host}",
                    False,
                    True,
                )
            )
    cases.append(
        (
            "duplicate-secret-host",
            "host=localhost host=user:fixture-value@localhost",
            False,
            False,
        )
    )
    cases = [case for case in cases if only is None or case[0] == only]
    assert cases, f"unknown config case: {only}"
    (root / "logs").mkdir()
    for name, parameters, valid, host_error in cases:
        # Quote each option to pass spaces and tabs through nginx's config lexer.
        options = " ".join(f'"{option}"' for option in parameters.split(" "))
        if name in ("space", "tab"):
            options = f'"{parameters}"'
        config = root / "nginx.conf"
        config.write_text(f"""load_module {module};
error_log stderr;
pid {root}/nginx.pid;
events {{}}
http {{ access_log off; error_abuse_redis {options}; }}
""")
        result = subprocess.run(
            [binary, "-p", str(root), "-c", str(config), "-t"],
            capture_output=True,
            text=True,
            check=False,
        )
        expected = 0 if valid else 1
        assert result.returncode == expected, (
            f"{name}: expected nginx -t exit {expected}, "
            f"got {result.returncode}: {result.stderr}"
        )
        if name == "duplicate-secret-host":
            assert "duplicate error_abuse_redis parameter host" in result.stderr
            assert "fixture-value" not in result.stderr
        if host_error:
            assert "invalid error_abuse_redis parameter host;" in result.stderr, name
            assert parameters not in result.stderr, f"{name}: raw host echoed"
            assert "fixture-value" not in result.stderr, (
                f"{name}: secret-like host echoed"
            )
        print(f"OK: config {name}", flush=True)


def main():
    if not __debug__:
        raise SystemExit("Redis host probe requires Python without optimization")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", type=pathlib.Path)
    parser.add_argument("--negative-controls", action="store_true")
    parser.add_argument("--nginx-binary")
    parser.add_argument("--module")
    parser.add_argument("--only")
    args = parser.parse_args()
    assert args.core or args.nginx_binary
    assert bool(args.nginx_binary) == bool(args.module)
    with tempfile.TemporaryDirectory(prefix="redis-host-") as directory:
        root = pathlib.Path(directory)
        if args.core:
            unit(args.core.resolve(), root, args.negative_controls)
        if args.nginx_binary:
            configs(args.nginx_binary, args.module, root, args.only)


if __name__ == "__main__":
    main()
