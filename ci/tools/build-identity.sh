#!/usr/bin/env bash
# Exact build inputs, not an authentication token. Call from the module root.
set -euo pipefail
export LC_ALL=C

if [[ "${1:-}" == --portable-asan ]]; then
    # Same-run consumers verify source inputs without inheriting the producer's
    # workspace, compiler, installed packages or optional build accelerators.
    # The full producer identity and binary digest are bound separately.
    {
        printf 'asan-artifact-inputs-v1\0%s\0%s\0' "${2:?nginx version}" "${TEST_HARNESS:-0}"
        sha256sum .github/versions.env ci/tools/ci-build.sh \
            ci/tools/build-identity.sh ci/tools/ci-build-artifact.sh config
        find -L src -type f -print0 | sort -z | xargs -0 -r sha256sum
        if [[ -d patches ]]; then
            find -L patches -type f -print0 | sort -z | xargs -0 -r sha256sum
        fi
    } | sha256sum | cut -d' ' -f1
    exit 0
fi

# GCC and module overrides can select tools, headers and libraries from mutable
# directories. Hashing path text does not fingerprint their contents, so these
# overrides are unsupported for cross-run executable reuse, even when empty.
# Only unset variables are eligible.
toolchain_overrides=(GCC_EXEC_PREFIX COMPILER_PATH LIBRARY_PATH CPATH
    C_INCLUDE_PATH CPLUS_INCLUDE_PATH OBJC_INCLUDE_PATH)
if [[ "${1:-}" == --executable-cache-eligible ]]; then
    for override in "${toolchain_overrides[@]}" NGX_ERROR_ABUSE_INCS NGX_ERROR_ABUSE_LIBS; do
        if [[ -v "$override" ]]; then
            printf 'false\n'
            exit 0
        fi
    done
    printf 'true\n'
    exit 0
fi

compiler="${1:?compiler}"
shift
# Local identities always fingerprint installed Debian packages, including
# identity-only and NO_CACHE builds. Portable artifact consumers exit above.
if ! command -v dpkg-query >/dev/null 2>&1; then
    echo 'build-identity: dpkg-query is required; install Debian dpkg tooling and ensure dpkg-query is on PATH' >&2
    exit 2
fi
if ! packages="$(dpkg-query -W -f='${binary:Package}=${Version}:${Architecture}\n' 2>/dev/null)"; then
    echo 'build-identity: dpkg-query failed; verify the Debian package database is readable' >&2
    exit 2
fi
{
    printf 'build-identity-v1\0%s\0' "$PWD" "$@"
    printf '%s\0' "${CFLAGS:-}" "${CPPFLAGS:-}" "${LDFLAGS:-}" \
        "${LD_LIBRARY_PATH:-}" "${PKG_CONFIG_PATH:-}"
    for override in "${toolchain_overrides[@]}"; do
        printf '%s\0%s\0%s\0' "$override" "${!override+x}" "${!override-}"
    done
    uname -srm
    cat /etc/os-release
    compiler_path="$(command -v "$compiler")"
    sha256sum "$(readlink -f "$compiler_path")"
    "$compiler" --version
    "$compiler" -dumpmachine
    # Include the installed headers/libraries and linker, rather than assuming
    # that equal runner labels imply equal dependency/toolchain versions.
    printf '%s\n' "$packages" | sort
    ld --version
    for tool in ccache mold; do
        if command -v "$tool" >/dev/null 2>&1; then
            sha256sum "$(readlink -f "$(command -v "$tool")")"
        fi
    done
    sha256sum .github/versions.env ci/tools/ci-build.sh \
        ci/tools/build-identity.sh config
    find -L src -type f -print0 | sort -z | xargs -0 -r sha256sum
    if [[ -d patches ]]; then
        find -L patches -type f -print0 | sort -z | xargs -0 -r sha256sum
    fi
} | sha256sum | cut -d' ' -f1
