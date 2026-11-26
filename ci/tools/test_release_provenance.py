#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
"""Exercise release authentication using real gpg and curl against local fixtures."""

import functools
import hashlib
import http.server
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NGINX = "43387825DDB1BB97EC36BA5D007C8D7C15D87369"
ANGIE = "EB8EAF3D4EF1B1ECF34865A2617AB978CB849A76"
MAIN = "/nginx.org/download/nginx-1.31.3.tar.gz"
STABLE = "/nginx.org/download/nginx-1.30.4.tar.gz"
LATEST = "/download.angie.software/files/angie-1.12.1.tar.gz"
PAGE = "/nginx.org/en/download.html"
API = "/api.github.com/repos/webserver-llc/angie/releases/latest"


def command(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs).stdout


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        fixture = self.server.fixture
        fixture.requests.append((self.server.secure, self.path))
        if self.server.secure and self.path == fixture.redirect_path:
            scheme = fixture.redirect_scheme
            port = (
                fixture.https.server_port
                if scheme == "https"
                else fixture.http.server_port
            )
            self.send_response(302)
            self.send_header(
                "Location", f"{scheme}://localhost:{port}/redirected{self.path}"
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        path = self.path.removeprefix("/redirected")
        body = fixture.responses.get(path)
        self.send_response(404 if body is None else 200)
        self.send_header("Content-Length", str(len(body) if body is not None else 0))
        self.end_headers()
        if body is not None:
            self.wfile.write(body)

    def log_message(self, *_args):
        pass


class ReleaseProvenance(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage = tempfile.TemporaryDirectory(prefix="release-provenance-")
        cls.base = Path(cls.storage.name)
        cls.addClassCleanup(cls.storage.cleanup)
        cls.gpg = shutil.which("gpg")
        cls.curl = shutil.which("curl")
        cls.home = cls.base / "signing"
        cls.home.mkdir(mode=0o700)
        cls.addClassCleanup(
            lambda: command(
                ["gpgconf", "--homedir", str(cls.home), "--kill", "gpg-agent"]
            )
        )
        cls.gpg_args = [
            cls.gpg,
            "--no-options",
            "--homedir",
            str(cls.home),
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
        ]
        cls.fingerprints = []
        cls.public_keys = []
        for name in ("Allowed release fixture", "Unknown release fixture"):
            command(
                [*cls.gpg_args, "--quick-generate-key", name, "ed25519", "cert", "0"]
            )
            listing = command(
                [*cls.gpg_args, "--with-colons", "--list-keys", name]
            ).decode()
            fingerprint = next(
                line.split(":")[9]
                for line in listing.splitlines()
                if line.startswith("fpr:")  # codespell:ignore fpr
            )
            command(
                [*cls.gpg_args, "--quick-add-key", fingerprint, "ed25519", "sign", "0"]
            )
            cls.fingerprints.append(fingerprint)
            cls.public_keys.append(
                command([*cls.gpg_args, "--armor", "--export", fingerprint])
            )
        cls.payloads = {
            path: f"authenticated fixture archive {path}\n".encode()
            for path in (MAIN, STABLE, LATEST)
        }
        cls.signatures = {}
        for path, body in cls.payloads.items():
            archive = cls.base / Path(path).name
            archive.write_bytes(body)
            cls.signatures[path] = command(
                [
                    *cls.gpg_args,
                    "--armor",
                    "--local-user",
                    cls.fingerprints[0],
                    "--detach-sign",
                    "--output",
                    "-",
                    str(archive),
                ]
            )
        cls.unknown_signature = command(
            [
                *cls.gpg_args,
                "--armor",
                "--local-user",
                cls.fingerprints[1],
                "--detach-sign",
                "--output",
                "-",
                str(cls.base / Path(MAIN).name),
            ]
        )
        cls.cert = cls.base / "tls.pem"
        key = cls.base / "tls.key"
        command(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-keyout",
                str(key),
                "-out",
                str(cls.cert),
            ]
        )
        cls.http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.https = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cls.cert, key)
        cls.https.socket = context.wrap_socket(cls.https.socket, server_side=True)
        for server, secure in ((cls.http, False), (cls.https, True)):
            server.fixture = cls
            server.secure = secure
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            cls.addClassCleanup(functools.partial(cls.stop_server, server, thread))

    @staticmethod
    def stop_server(server, thread):
        server.shutdown()
        server.server_close()
        thread.join()

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(dir=self.base)
        self.addCleanup(self.work.cleanup)
        self.repo = Path(self.work.name)
        self.scripts = self.repo / ".github/scripts"
        shutil.copytree(ROOT / ".github/scripts", self.scripts)
        self.fetch = self.scripts / "fetch-verify.sh"
        self.fetch.write_text(
            self.fetch.read_text()
            .replace(NGINX, self.fingerprints[0])
            .replace(ANGIE, self.fingerprints[0])
        )
        self.keys = self.scripts / "release-keys"
        for name in ("nginx", "angie"):
            (self.keys / f"{name}.gpg").write_bytes(self.public_keys[0])
        self.pins = self.repo / ".github/versions.env"
        self.original_pins = (ROOT / ".github/versions.env").read_bytes()
        self.pins.write_bytes(self.original_pins)
        type(self).responses = {
            **self.payloads,
            PAGE: b"nginx-1.31.3 nginx-1.30.4",
            API: b'{"tag_name":"Angie-1.12.1"}',
        }
        type(self).responses.update(
            {path + ".asc": signature for path, signature in self.signatures.items()}
        )
        type(self).redirect_path = None
        type(self).redirect_scheme = "https"
        type(self).requests = []
        self.bin = self.repo / "bin"
        self.bin.mkdir()
        # Rewrite only the fixed upstream URLs to a loopback TLS fixture. Actual
        # transport, protocol restrictions and certificate validation use curl.
        wrapper = f"""#!/usr/bin/env python3
# Copyright (C) 2026 Thijs Eilander
# SPDX-License-Identifier: BSD-2-Clause
import os
import sys
from urllib.parse import urlsplit
args = sys.argv[1:]
url = urlsplit(args[-1])
if url.hostname in ("nginx.org", "download.angie.software", "api.github.com"):
    args[-1] = f"{{url.scheme}}://localhost:{self.https.server_port}/{{url.hostname}}{{url.path}}"
os.execv({self.curl!r}, [{self.curl!r}, *args, "--noproxy", "*", "--cacert", {str(self.cert)!r}])
"""
        self.executable("curl", wrapper)
        self.env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "GNUPGHOME": str(self.home),
        }
        self.env.pop("GITHUB_TOKEN", None)
        # A poisoned ambient keyring must not grant release trust.
        (self.home / "gpg.conf").write_text("auto-key-retrieve\n")

    def executable(self, name, text):
        path = self.bin / name
        path.write_text(text)
        path.chmod(0o755)

    def run_script(self, path, *args):
        return subprocess.run(
            ["bash", str(path), *args],
            cwd=self.repo,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
            timeout=40,
        )

    def compute(self):
        return self.run_script(self.scripts / "compute-versions.sh")

    def harvest(self):
        return self.run_script(
            self.fetch,
            "https://nginx.org/download/nginx-1.31.3.tar.gz",
            "-",
            str(self.repo / "archive"),
            "nginx",
        )

    def assert_rejected(self, result, message):
        self.assertNotEqual(
            result.returncode, 0, "unauthenticated or insecure release was accepted"
        )
        self.assertIn(message, result.stderr)
        self.assertEqual(
            self.pins.read_bytes(),
            self.original_pins,
            "failed resolution changed versions.env",
        )

    def test_allowed_signing_subkey_and_resolver_format(self):
        result = self.compute()
        self.assertEqual(result.returncode, 0, result.stderr)
        pins = dict(
            line.split("=", 1)
            for line in self.pins.read_text().splitlines()
            if line and not line.startswith("#")
        )
        self.assertEqual(pins["NGINX_MAINLINE"], "1.31.3")
        self.assertEqual(pins["NGINX_STABLE"], "1.30.4")
        self.assertEqual(pins["ANGIE_VERSION"], "1.12.1")
        for key, path in (
            ("NGINX_MAINLINE_SHA256", MAIN),
            ("NGINX_STABLE_SHA256", STABLE),
            ("ANGIE_SHA256", LATEST),
        ):
            self.assertEqual(pins[key], hashlib.sha256(self.payloads[path]).hexdigest())
            self.assertIn((True, path + ".asc"), self.requests)
        self.assertEqual(pins["NGINX_VERSION_SHA256"], pins["NGINX_MAINLINE_SHA256"])
        self.assertIn("----- resolved -----", result.stdout)
        first = self.pins.read_bytes()
        self.assertEqual(self.compute().returncode, 0)
        self.assertEqual(
            self.pins.read_bytes(), first, "repeated resolution is not deterministic"
        )

    def test_harvest_stdout_is_only_digest(self):
        result = self.harvest()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            f"{hashlib.sha256(self.payloads[MAIN]).hexdigest()}  {self.repo / 'archive'}\n",
        )

    def test_valid_unknown_signer_is_rejected_even_when_imported(self):
        (self.keys / "nginx.gpg").write_bytes(b"".join(self.public_keys))
        self.responses[MAIN + ".asc"] = self.unknown_signature
        self.assert_rejected(self.compute(), "signer not allowed")

    def test_expired_allowed_key_is_rejected(self):
        self.addCleanup(
            command, [*self.gpg_args, "--quick-set-expire", self.fingerprints[0], "0"]
        )
        command([*self.gpg_args, "--quick-set-expire", self.fingerprints[0], "1d"])
        (self.keys / "nginx.gpg").write_bytes(
            command([*self.gpg_args, "--export", self.fingerprints[0]])
        )
        # gpg returns zero and emits VALIDSIG even with EXPKEYSIG. Exercise the
        # actual verifier past the key's expiry, without changing the host clock.
        future = int(time.time()) + 3 * 86400
        self.executable(
            "gpg", f'#!/bin/sh\nexec {self.gpg} --faked-system-time {future} "$@"\n'
        )
        self.assert_rejected(self.compute(), "release signature is expired or revoked")

    def test_revoked_allowed_key_is_rejected(self):
        revoked = self.repo / "revoked-keyring"
        revoked.mkdir(mode=0o700)
        args = [self.gpg, "--no-options", "--homedir", str(revoked), "--batch"]
        subprocess.run(
            [*args, "--import"],
            input=self.public_keys[0],
            check=True,
            capture_output=True,
        )
        revocation = (
            self.home / "openpgp-revocs.d" / f"{self.fingerprints[0]}.rev"
        ).read_bytes()
        revocation = revocation[revocation.index(b":-----BEGIN") :].replace(
            b":-----BEGIN", b"-----BEGIN", 1
        )
        subprocess.run(
            [*args, "--import"], input=revocation, check=True, capture_output=True
        )
        (self.keys / "nginx.gpg").write_bytes(
            command([*args, "--export", self.fingerprints[0]])
        )
        self.assert_rejected(self.compute(), "release signature is expired or revoked")

    def test_mutated_archive_and_bad_signature(self):
        self.responses[MAIN] += b"tampered"
        self.assert_rejected(self.compute(), "signature verification failed")
        self.responses[MAIN] = self.payloads[MAIN]
        self.responses[MAIN + ".asc"] = self.signatures[STABLE]
        self.assert_rejected(self.compute(), "signature verification failed")

    def test_missing_and_malformed_signature(self):
        del self.responses[MAIN + ".asc"]
        self.assert_rejected(self.compute(), "404")
        self.responses[MAIN + ".asc"] = b"not a detached signature\n"
        self.assert_rejected(self.compute(), "signature verification failed")

    def test_missing_and_malformed_key(self):
        key = self.keys / "nginx.gpg"
        key.unlink()
        self.assert_rejected(self.compute(), "release key unavailable")
        key.write_bytes(b"invalid key\n")
        self.assert_rejected(self.compute(), "release key unavailable")

    def test_unavailable_verifier_and_verifier_error(self):
        self.executable(
            "gpg", "#!/bin/sh\necho 'fixture verifier unavailable' >&2\nexit 127\n"
        )
        self.assert_rejected(self.compute(), "release key unavailable")
        self.executable(
            "gpg",
            f'#!/bin/bash\nfor arg; do\n  if [ "$arg" = --verify ]; then echo "fixture verifier error" >&2; exit 2; fi\ndone\nexec {self.gpg} "$@"\n',
        )
        self.assert_rejected(self.compute(), "signature verification failed")

    def test_late_archive_failure_preserves_all_pins(self):
        self.responses[LATEST] += b"late tampering"
        self.assert_rejected(self.compute(), "signature verification failed")
        self.assertIn((True, MAIN + ".asc"), self.requests)
        self.assertIn((True, STABLE + ".asc"), self.requests)
        self.assertIn((True, LATEST + ".asc"), self.requests)

    def test_https_redirects_for_metadata_archive_and_signature(self):
        for path in (PAGE, API, MAIN, MAIN + ".asc"):
            with self.subTest(path=path):
                type(self).redirect_path = path
                result = self.compute()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn((True, "/redirected" + path), self.requests)

    def test_http_downgrade_for_metadata_archive_and_signature(self):
        type(self).redirect_scheme = "http"
        for path in (PAGE, API, MAIN, MAIN + ".asc"):
            with self.subTest(path=path):
                type(self).redirect_path = path
                self.assert_rejected(self.compute(), "disabled")
                self.assertNotIn((False, "/redirected" + path), self.requests)

    def test_non_https_initial_url_refused_before_cache(self):
        out = self.repo / "cached"
        out.write_bytes(self.payloads[MAIN])
        sha = hashlib.sha256(out.read_bytes()).hexdigest()
        for scheme in ("http", "file", "ftp"):
            with self.subTest(scheme=scheme):
                result = self.run_script(
                    self.fetch,
                    f"{scheme}://localhost:{self.http.server_port}{MAIN}",
                    sha,
                    str(out),
                )
                self.assert_rejected(result, "HTTPS URL required")
        self.assertEqual(self.requests, [])

    def test_pinned_hash_and_cache_poisoning(self):
        out = self.repo / "cached"
        url = "https://nginx.org/download/nginx-1.31.3.tar.gz"
        sha = hashlib.sha256(self.payloads[MAIN]).hexdigest()
        out.write_bytes(self.payloads[MAIN])
        result = self.run_script(self.fetch, url, sha, str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cache hit (sha ok)", result.stdout)
        self.assertEqual(self.requests, [])
        out.write_bytes(b"poisoned cache")
        result = self.run_script(self.fetch, url, sha, str(out))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(out.read_bytes(), self.payloads[MAIN])
        self.responses[MAIN] = b"poisoned upstream"
        out.write_bytes(b"poisoned cache")
        self.assert_rejected(
            self.run_script(self.fetch, url, sha, str(out)), "sha256 MISMATCH"
        )

    def test_hash_harvest_requires_known_upstream(self):
        for name in ("", "unreviewed"):
            with self.subTest(upstream=name):
                self.assert_rejected(
                    self.run_script(
                        self.fetch,
                        "https://nginx.org/download/nginx-1.31.3.tar.gz",
                        "-",
                        str(self.repo / "archive"),
                        name,
                    ),
                    "requires nginx or angie",
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
