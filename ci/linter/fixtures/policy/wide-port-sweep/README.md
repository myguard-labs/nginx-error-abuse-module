# fixture: wide-port-sweep

Encodes the bypass where **every band declaration is correct and the cleanup
step is still destructive**.

`runtime-a` and `runtime-b` declare disjoint, explicitly-sized bands
(19200-19231 and 19232-19263), so the uniqueness check, the width check and
the overlap check are all satisfied. The defect is in the sweep step:

```sh
for p in $(seq 19200 19263); do fuser -k -TERM "${p}/tcp"; done
```

That literal range spans both bands, and `fuser -k` kills by port, not by PID.
When both jobs land on the same self-hosted runner with nothing serialising
them, `runtime-a`'s cleanup TERMs `runtime-b`'s live listeners. The victim
reports a connection-refused failure, which reads as test flakiness rather
than as another job's cleanup, so it gets rerun instead of fixed.

Bands prevent two jobs from BINDING the same port. They do nothing about one
job killing across all of them, which is why this needs its own check.

Expected: `ports` exits 1, naming the literal `seq` range.
