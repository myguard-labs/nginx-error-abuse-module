#!/usr/bin/env bash

set -euo pipefail

FLAVOR="${1:-nginx}"
VERSION="${2:-1.31.1}"
MODE="${3:-debug}"
ROOT="${BUILD_ROOT:-$PWD/.build}"
MODULE_DIR="$PWD"

case "$FLAVOR" in
    nginx)
        URL="https://nginx.org/download/nginx-${VERSION}.tar.gz"
        DIR="nginx-${VERSION}"
        BINARY="nginx"
        ;;
    angie)
        URL="https://download.angie.software/files/angie-${VERSION}.tar.gz"
        DIR="angie-${VERSION}"
        BINARY="angie"
        ;;
    *)
        echo "unsupported flavor: $FLAVOR" >&2
        exit 2
        ;;
esac

mkdir -p "$ROOT"
if [ ! -f "$ROOT/${DIR}.tar.gz" ]; then
    curl -fsSL "$URL" -o "$ROOT/${DIR}.tar.gz"
fi
if [ ! -d "$ROOT/$DIR" ]; then
    tar -xzf "$ROOT/${DIR}.tar.gz" -C "$ROOT"
fi

CC_OPT="-DNGX_DEBUG_PALLOC=1 -g3 -O0 -fno-omit-frame-pointer -funwind-tables"
LD_OPT=""
ADD_MODULE="--add-dynamic-module=$MODULE_DIR"
if [ "$MODE" = "asan" ]; then
    SAN="-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer -g3 -O1"
    CC_OPT="$SAN"
    LD_OPT="$SAN"
    ADD_MODULE="--add-module=$MODULE_DIR"
fi

cd "$ROOT/$DIR"
./configure \
    --with-compat \
    --with-debug \
    --with-http_realip_module \
    --without-http_rewrite_module \
    --with-cc-opt="$CC_OPT" \
    --with-ld-opt="$LD_OPT" \
    "$ADD_MODULE"

if [ "$MODE" != "asan" ]; then
    make -j"$(nproc)" modules
fi
make -j"$(nproc)"

printf 'binary=%s\n' "$ROOT/$DIR/objs/$BINARY"
if [ "$MODE" != "asan" ]; then
    printf 'module=%s\n' "$ROOT/$DIR/objs/ngx_http_error_abuse_module.so"
fi
