#!/usr/bin/env bash
# sync-sha: 14e9f4330dcb516b3dad379e90769720ed066d0e35c8aba318eca3074b3055e9
# fetch-verify.sh URL EXPECTED_SHA256 OUTFILE [nginx|angie]
#
# Download URL to OUTFILE and verify its sha256 against EXPECTED_SHA256.
# On mismatch: print the actual sha and exit 1 (fails the CI job — a changed
# or tampered upstream archive never reaches the build).
#
# Pass EXPECTED_SHA256="-" with an upstream name to authenticate the archive
# against its pinned release key before printing the computed sha for a bump.
#
# If OUTFILE already exists with the right sha (warm actions/cache hit) the
# download is skipped — the sha check still runs, so a poisoned cache is caught.
set -euo pipefail

url="${1:?usage: fetch-verify.sh URL SHA256 OUTFILE}"
want="${2:?missing expected sha256}"
out="${3:?missing output path}"

# Refuse unsupported initial URLs even on a cache hit.
case "$url" in
  https://*) ;;
  *) echo "::error::HTTPS URL required: $url" >&2; exit 1 ;;
esac

sha_of() { sha256sum "$1" | cut -d' ' -f1; }

if [ -f "$out" ] && [ "$want" != "-" ] && [ "$(sha_of "$out")" = "$want" ]; then
  echo "cache hit (sha ok): $out"
  exit 0
fi

# stderr, not stdout: in "-" mode stdout must carry ONLY the final
# "$got  $out" line, which compute-versions.sh reads as the digest.
echo "downloading: $url" >&2
# -f: fail on HTTP errors; -S: show errors; -L: follow redirects; retries.
# --connect-timeout/--max-time: a stalled upstream must not hold a runner open.
curl --disable --proto '=https' --proto-redir '=https' -fSL --retry 3 --retry-delay 2 \
  --connect-timeout 30 --max-time 300 -o "$out" "$url"

if [ "$want" = "-" ]; then
  # Only reviewed repository keys are eligible. Never fetch keys at runtime or
  # use the caller's keyring/configuration/keyservers to establish trust.
  case "${4:-}" in
    nginx) fingerprint=43387825DDB1BB97EC36BA5D007C8D7C15D87369 ;;
    angie) fingerprint=EB8EAF3D4EF1B1ECF34865A2617AB978CB849A76 ;;
    *) echo "::error::hash harvest requires nginx or angie release trust" >&2; exit 1 ;;
  esac
  key="$(dirname "${BASH_SOURCE[0]}")/release-keys/$4.gpg"
  verify_dir="$(mktemp -d)"
  trap 'rm -rf "$verify_dir"' EXIT
  # mktemp's private directory also isolates gpg's trustdb and keyring.
  gpg_opts=(--no-options --homedir "$verify_dir" --batch --no-tty
    --no-auto-key-retrieve --auto-key-locate clear)
  if ! gpg "${gpg_opts[@]}" --import "$key" >&2; then
    echo "::error::release key unavailable for $4" >&2
    exit 1
  fi
  curl --disable --proto '=https' --proto-redir '=https' -fSL --retry 3 --retry-delay 2 \
    --connect-timeout 30 --max-time 300 -o "$verify_dir/release.asc" "$url.asc"
  if ! gpg "${gpg_opts[@]}" --status-fd 1 --verify "$verify_dir/release.asc" "$out" \
    > "$verify_dir/status"; then
    echo "::error::release signature verification failed for $url" >&2
    exit 1
  fi
  # gpg can return zero and emit VALIDSIG alongside an expired/revoked key
  # status. Reject those statuses explicitly before accepting signer identity.
  if ! awk '
    $1 == "[GNUPG:]" && $2 ~ /^(EXPSIG|EXPKEYSIG|REVKEYSIG|KEYEXPIRED|SIGEXPIRED|KEYREVOKED)$/ { exit 1 }
  ' "$verify_dir/status"; then
    echo "::error::release signature is expired or revoked for $url" >&2
    exit 1
  fi
  # VALIDSIG binds a signing subkey to its validated full primary fingerprint.
  # GOODSIG/key IDs/issuer packets alone do not authenticate an allowed signer.
  if ! awk -v want="$fingerprint" '
    $1 == "[GNUPG:]" && $2 == "VALIDSIG" && $NF == want { valid++ }
    END { exit (valid != 1) }
  ' "$verify_dir/status"; then
    echo "::error::release signature signer not allowed for $4" >&2
    exit 1
  fi
fi

got="$(sha_of "$out")"
if [ "$want" = "-" ]; then
  echo "$got  $out"
  exit 0
fi

if [ "$got" != "$want" ]; then
  echo "::error::sha256 MISMATCH for $url" >&2
  echo "  expected: $want" >&2
  echo "  actual:   $got" >&2
  exit 1
fi
echo "sha256 verified: $out"
