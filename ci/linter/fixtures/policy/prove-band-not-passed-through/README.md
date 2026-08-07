# fixture: prove-band-not-passed-through

A `prove` job that declares a unique `TEST_BASE_PORT` and never passes it on.

Every check above this one is satisfied: the band is declared, it is distinct
from every sibling, its width does not overrun a neighbour. The job still binds
1984, because Test::Nginx reads `TEST_NGINX_PORT` and has never heard of
`TEST_BASE_PORT`. A declaration nothing consumes is decoration.

`check_ports()` had the equivalent guard for the runtime driver
(`--port "$TEST_BASE_PORT"`) but keyed it on `starts_runtime`, so the `prove`
path had no pass-through check at all. Raised by CodeRabbit on PR #48, against
the commit that had just made `prove` a first-class binder for the
declaration-required branch: the fix extended what must declare a band without
extending what must pass it through.

`ports` must go red here.

Workflow: `.github/workflows/runtime.yml`.
