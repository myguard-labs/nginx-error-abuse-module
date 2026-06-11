#!/usr/bin/env bash
#
# Slice the verbatim bodies of the untrusted-input parsers out of the
# shipped ../ngx_http_error_abuse_module.c into generated_parser.inc:
#
#   ngx_http_error_abuse_parse_statuses()     - the "404,500-599" status
#       list parser; walks attacker-shaped bytes with ngx_strlchr/ngx_atoi
#       and sets bits in zone->statuses[status >> 3] (an OOB-WRITE surface).
#   ngx_http_error_abuse_validate_snapshot()  - the on-disk snapshot gate;
#       pointer arithmetic over the persistence buffer before load() reads it.
#
# This keeps the fuzz targets locked to production code: there is no
# hand-maintained copy. If a signature or body changes upstream, the next
# fuzz build picks it up. If a function can no longer be found, we fail
# loudly rather than fuzz nothing.

set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$FUZZ_DIR/../ngx_http_error_abuse_module.c"
OUT="$FUZZ_DIR/generated_parser.inc"

if [ ! -f "$SRC" ]; then
    echo "✗ cannot find $SRC" >&2
    exit 1
fi

# Capture each function from its `static ngx_int_t` return-type line
# (whose following definition line names a target parser) through the
# matching closing brace in column 1 (nginx style: a bare `}`). Both share
# the return-type line, so match on the definition line that follows.
# Emitted in source order (parse_statuses precedes validate_snapshot).
awk '
    /^static ngx_int_t$/ { pending = 1; buf = $0 ORS; next }
    pending && /^ngx_http_error_abuse_(parse_statuses|validate_snapshot)\(/ {
        capture = 1; pending = 0; print buf; print; next
    }
    pending { pending = 0; buf = "" }
    capture {
        print
        if ($0 == "}") { capture = 0 }
    }
' "$SRC" > "$OUT"

if ! grep -q 'ngx_http_error_abuse_parse_statuses' "$OUT" \
   || ! grep -q 'ngx_http_error_abuse_validate_snapshot' "$OUT" \
   || [ "$(tail -n1 "$OUT")" != "}" ]; then
    echo "✗ failed to extract the parsers from $SRC" >&2
    echo "  (source layout changed? update extract_parser.sh)" >&2
    rm -f "$OUT"
    exit 1
fi

LINES=$(wc -l < "$OUT")
echo "✓ extracted parse_statuses() + validate_snapshot() — $LINES lines -> $OUT"
