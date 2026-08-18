# Configuration parser regression seeds

`seeds.json` is a finite regression corpus for the `error_abuse_zone`,
`error_abuse`, and `error_abuse_redis` option parsers. Configuration is trusted
administrator input; these cases are defensive checks for malformed config,
not a remotely reachable attack harness.

The replay path is production-linked: `test_runtime.py` loads the built module
into nginx and passes each seed through `nginx -t`. It does not copy or
reimplement any parser. Cases cover duplicate options, numeric boundaries,
empty TLS scheme hosts, secret redaction, and cross-option dependencies.

Run only this bounded corpus with:

```bash
python3 ci/tools/test_runtime.py \
  --nginx-binary "$PWD/.build/nginx-1.31.3-debug/objs/nginx" \
  --module "$PWD/.build/nginx-1.31.3-debug/objs/ngx_http_error_abuse_module.so" \
  --config-seeds-only
```

Every reject seed names a diagnostic substring. `forbidden` values are secret
canaries that must not occur in captured nginx output. At least one accept seed
is mandatory so an unloaded or stale module cannot make the reject corpus pass
vacuously. The loader rejects more than 64 cases to keep this seam deterministic
and bounded; coverage-guided discovery remains a separate CI task.
