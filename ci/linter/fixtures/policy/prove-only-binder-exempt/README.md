# fixture: prove-only-binder-exempt

`check_ports()`'s declaration-required branch — the one its own comment calls
"THE CHECK THAT MATTERS MOST" — keyed on `starts_runtime`
(`RUNTIME_DRIVER in body`, i.e. `ci/tools/test_runtime.py`) rather than on
`BINDERS`/`BINDER_RE`. A job whose only binder is `prove` was therefore exempt
from the "declare `TEST_BASE_PORT`" requirement, even though `prove` is already
a `BINDERS` member and `_order_finding()` already treats it as one thing that
binds the band. The two halves of the same check disagreed about what a binder
is.

The exemption is invisible from every other angle. Such a job declares no band,
so the uniqueness check has nothing to collide with; it silently takes
Test::Nginx's hardcoded `TEST_NGINX_PORT` default of 1984 and collides with any
other binding job on the same runner. On builder02, where six ci-ephemeral
slots share one network, two concurrent runs then die with
`bind() to 127.0.0.1:1984 failed (98: Address already in use)` — which reads as
a module regression and is not one.

This was live in this repo, not hypothetical: `build-test.yml`'s `test-nginx`
job ran `prove -v ci/t/basic.t` with no band, no width and no `max-port.sh`
verify, while `ports` reported "3 runtime job(s), all with distinct port bands"
and exited 0. With the fix it reports 4.

`ports` must go red here.

Workflow: `.github/workflows/runtime.yml` — a job that runs `prove -v ci/t/`
and declares no `TEST_BASE_PORT`.
