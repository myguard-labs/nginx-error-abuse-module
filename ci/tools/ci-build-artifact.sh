#!/usr/bin/env bash
# Same-run plain ASan handoff. Expected values MUST come from producer job
# outputs, not from the downloaded directory. A colocated seal is not trust.
set -euo pipefail

operation="${1:?export or import}"
version="${2:?nginx version}"
artifact="${3:?artifact directory}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    echo 'invalid ASan artifact version' >&2; exit 2;
}
artifact_identity="$(bash ci/tools/build-identity.sh --portable-asan "$version")"
tree="${BUILD_ROOT:-$PWD/.build}/nginx-${version}-asan"

producer_binding() {
    printf 'asan-artifact-binding-v1\0%s\0%s\0%s\0' "$1" "$2" "$3" \
        | sha256sum | cut -d' ' -f1
}

case "$operation" in
    export)
        identity="$(CI_BUILD_IDENTITY_ONLY=1 bash ci/tools/ci-build.sh nginx "$version" asan)"
        [[ -f "$tree/.build-identity" && ! -L "$tree/.build-identity" ]]
        [[ "$(cat "$tree/.build-identity")" == "$identity" ]] || {
            echo 'ASan producer build identity mismatch' >&2; exit 1;
        }
        [[ -f "$tree/objs/nginx" && ! -L "$tree/objs/nginx" ]]
        mkdir -p "$artifact"
        cp --remove-destination "$tree/objs/nginx" "$artifact/nginx"
        digest="$(sha256sum "$artifact/nginx" | cut -d' ' -f1)"
        binding="$(producer_binding "$identity" "$artifact_identity" "$digest")"
        printf 'identity=%s\nsha256=%s\nartifact-identity=%s\nartifact-sha256=%s\n' \
            "$identity" "$digest" "$artifact_identity" "$binding" >> "${GITHUB_OUTPUT:?job output file}"
        ;;
    import)
        [[ "${EXPECTED_BUILD_IDENTITY:-}" =~ ^[0-9a-f]{64}$
            && "${EXPECTED_BINARY_SHA256:-}" =~ ^[0-9a-f]{64}$
            && "${EXPECTED_ARTIFACT_IDENTITY:-}" =~ ^[0-9a-f]{64}$
            && "${EXPECTED_ARTIFACT_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || {
            echo 'missing or malformed ASan producer outputs' >&2; exit 1;
        }
        [[ "$EXPECTED_ARTIFACT_IDENTITY" == "$artifact_identity" ]] || {
            echo 'ASan consumer build identity mismatch' >&2; exit 1;
        }
        [[ -f "$artifact/nginx" && ! -L "$artifact/nginx" ]] || {
            echo 'missing or non-regular ASan artifact' >&2; exit 1;
        }
        digest="$(sha256sum "$artifact/nginx" | cut -d' ' -f1)"
        [[ "$digest" == "$EXPECTED_BINARY_SHA256" ]] || {
            echo 'ASan artifact SHA-256 mismatch' >&2; exit 1;
        }
        [[ "$(producer_binding "$EXPECTED_BUILD_IDENTITY" "$artifact_identity" "$digest")" \
            == "$EXPECTED_ARTIFACT_SHA256" ]] || {
            echo 'ASan artifact producer binding mismatch' >&2; exit 1;
        }
        rm -rf "${tree:?}"
        mkdir -p "$tree/objs"
        cp --remove-destination "$artifact/nginx" "$tree/objs/nginx"
        chmod +x "$tree/objs/nginx"
        printf 'ASan artifact verified: %s\n' "$artifact_identity"
        ;;
    *) echo "unsupported artifact operation: $operation" >&2; exit 2 ;;
esac
