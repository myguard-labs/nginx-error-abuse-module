#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise certificate identity and capture Redis bytes from a real TLS peer.

Run in a disposable container. With --nginx-binary/--module, installs an ephemeral
CA in /etc/ssl/certs for the module and removes it afterward. Otherwise compile
and exercise the production TLS helper through hiredis' blocking public API.
"""

import argparse
import os
import pathlib
import shlex
import signal
import socket
import ssl
import subprocess
import tempfile
import threading


def command(*args: str) -> None:
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def certificates(root: pathlib.Path) -> None:
    command(
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "1",
        "-subj",
        "/CN=Redis TLS test CA",
        "-keyout",
        str(root / "ca.key"),
        "-out",
        str(root / "ca.pem"),
    )
    for name, san in (
        ("dns", "DNS:localhost"),
        ("wrong-dns", "DNS:other.invalid"),
        ("ip", "IP:127.0.0.1"),
        ("wrong-ip", "IP:127.0.0.2"),
        ("dns-ip", "DNS:127.0.0.1"),
        ("ipv6", "IP:::1"),
        ("partial", "DNS:local*"),
    ):
        command(
            "openssl",
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(root / f"{name}.key"),
            "-out",
            str(root / f"{name}.csr"),
        )
        ext = root / "extensions"
        ext.write_text(f"subjectAltName={san}\nextendedKeyUsage=serverAuth\n")
        command(
            "openssl",
            "x509",
            "-req",
            "-in",
            str(root / f"{name}.csr"),
            "-CA",
            str(root / "ca.pem"),
            "-CAkey",
            str(root / "ca.key"),
            "-CAcreateserial",
            "-days",
            "1",
            "-extfile",
            str(ext),
            "-out",
            str(root / f"{name}.pem"),
        )
    command("openssl", "rehash", str(root))


class Peer:
    def __init__(self, root: pathlib.Path, cert: str, address: str):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(root / f"{cert}.pem", root / f"{cert}.key")
        self.sni: list[str | None] = []
        self.context.set_servername_callback(lambda _s, name, _c: self.sni.append(name))
        self.listener = socket.socket(
            socket.AF_INET6 if ":" in address else socket.AF_INET
        )
        self.listener.bind((address, 0))
        self.listener.listen()
        self.listener.settimeout(6)
        self.port = self.listener.getsockname()[1]
        self.data = bytearray()
        self.error: BaseException | None = None
        self.thread = threading.Thread(target=self.serve)

    def serve(self) -> None:
        try:
            with self.listener:
                conn, _ = self.listener.accept()
                with conn:
                    conn.settimeout(4)
                    try:
                        with self.context.wrap_socket(conn, server_side=True) as tls:
                            while chunk := tls.recv(16384):
                                self.data.extend(chunk)
                                if b"SCRIPT" in self.data:
                                    break
                    except ssl.SSLError:
                        # A verification alert/EOF is the expected negative outcome.
                        pass
        except (OSError, ValueError) as exc:
            self.error = exc

    def finish(self) -> None:
        self.thread.join(8)
        assert not self.thread.is_alive(), "TLS peer did not finish"
        if self.error:
            raise self.error


def peer_address(identity: str, *, nginx: bool, is_ip: bool) -> str:
    if not nginx:
        return "127.0.0.1"
    if is_ip:
        return identity
    # Match nginx's ngx_inet_resolve_host hints and first-address choice.
    return str(
        socket.getaddrinfo(
            identity,
            None,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            flags=getattr(socket, "AI_ADDRCONFIG", 0),
        )[0][4][0]
    )


def probe(
    args: argparse.Namespace,
    root: pathlib.Path,
    scenario: tuple[str, str, bool, bool],
    trusted: bool = True,
) -> None:
    name, identity, is_ip, success = scenario
    peer = Peer(
        root, name, peer_address(identity, nginx=bool(args.nginx_binary), is_ip=is_ip)
    )
    peer.thread.start()
    if args.nginx_binary:
        case = root / f"case-{name}-{trusted}"
        case.mkdir()
        (case / "logs").mkdir()
        host = f"[{identity}]" if ":" in identity else identity
        config = case / "nginx.conf"
        config.write_text(f"""load_module {args.module};
error_log {case}/error.log debug;
pid {case}/nginx.pid;
worker_processes 1;
events {{ worker_connections 64; }}
http {{
  access_log off;
  error_abuse_redis host=tls://{host} port={peer.port}
                    password=fixture-only db=1 timeout=500ms;
  error_abuse_zone zone=tls:1m key=$remote_addr redis=on;
}}
""")
        with subprocess.Popen(
            [
                args.nginx_binary,
                "-p",
                str(case),
                "-c",
                str(config),
                "-g",
                "daemon off; master_process off;",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        ) as process:
            try:
                peer.finish()
                assert process.stderr is not None
                assert process.poll() is None, process.stderr.read().decode()
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGQUIT)
                process.communicate(timeout=10)
    else:
        capath = root if trusted else root / "empty"
        result = subprocess.run(
            [
                str(root / "client"),
                str(capath),
                identity,
                str(int(is_ip)),
                str(peer.port),
            ],
            capture_output=True,
            check=False,
        )
        peer.finish()
        assert (result.returncode == 0) == success, (
            f"{name}: unexpected client status {result.returncode}: {result.stderr!r}"
        )
    if success:
        assert (
            b"AUTH" in peer.data and b"SELECT" in peer.data and b"SCRIPT" in peer.data
        ), f"{name}: verified peer did not receive handshake commands"
        assert (
            peer.data.index(b"AUTH")
            < peer.data.index(b"SELECT")
            < peer.data.index(b"SCRIPT")
        )
        assert peer.sni == ([None] if is_ip else [identity]), f"{name}: incorrect SNI"
    else:
        assert not peer.data, (
            f"{name}: unverified peer received Redis application bytes"
        )
        assert peer.sni, f"{name}: negative control never reached TLS"
    print(
        f"OK: {name} identity={identity} trusted={trusted} accepted={success}; "
        f"application_bytes={len(peer.data)}",
        flush=True,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx-binary")
    parser.add_argument("--module")
    parser.add_argument("--only", choices=("wrong-dns", "wrong-ip"))
    args = parser.parse_args()
    assert bool(args.nginx_binary) == bool(args.module)
    if args.nginx_binary:
        assert pathlib.Path("/.dockerenv").exists(), "nginx TLS probe requires Docker"
    with tempfile.TemporaryDirectory(prefix="redis-tls-") as directory:
        root = pathlib.Path(directory)
        (root / "empty").mkdir()
        certificates(root)
        installed = pathlib.Path("/etc/ssl/certs") / f"redis-tls-{root.name}.pem"
        if args.nginx_binary:
            installed.write_bytes((root / "ca.pem").read_bytes())
            command("openssl", "rehash", "/etc/ssl/certs")
        else:
            repo = pathlib.Path(__file__).resolve().parents[2]
            command(
                *shlex.split(os.environ.get("CC", "cc")),
                "-Wall",
                "-Wextra",
                "-Werror",
                "-O2",
                f"-I{repo / 'src'}",
                str(repo / "ci/tests/unit/test_tls.c"),
                "-lhiredis_ssl",
                "-lhiredis",
                "-lssl",
                "-lcrypto",
                "-o",
                str(root / "client"),
            )
            print(
                subprocess.check_output(
                    ["stat", "-c", "%y %s %n", str(root / "client")]
                ).decode(),
                end="",
            )
        try:
            for name, identity, is_ip, success in (
                ("dns", "localhost", False, True),
                ("wrong-dns", "localhost", False, False),
                ("ip", "127.0.0.1", True, True),
                ("wrong-ip", "127.0.0.1", True, False),
                ("dns-ip", "127.0.0.1", True, False),
                ("partial", "localhost", False, False),
                ("ipv6", "::1", True, True),
            ):
                if args.only and args.only != name:
                    continue
                probe(args, root, (name, identity, is_ip, success))
            if not args.only:
                if args.nginx_binary:
                    installed.unlink()
                    command("openssl", "rehash", "/etc/ssl/certs")
                probe(args, root, ("dns", "localhost", False, False), trusted=False)
        finally:
            if args.nginx_binary:
                installed.unlink(missing_ok=True)
                command("openssl", "rehash", "/etc/ssl/certs")


if __name__ == "__main__":
    main()
