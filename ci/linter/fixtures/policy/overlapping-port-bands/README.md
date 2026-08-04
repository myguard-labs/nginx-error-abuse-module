# fixture: overlapping-port-bands

Encodes the bypass where **distinct bases are mistaken for disjoint bands**.

`runtime-a` claims 19200 and `runtime-b` claims 19232. The uniqueness check
compares the first port of each band and sees two different numbers, so it
passes. Neither job declares `TEST_PORT_WIDTH`, and `max-port.sh` falls back
to a width of 64:

    runtime-a: 19200 .. 19263   <- reaches 32 ports into its neighbour
    runtime-b: 19232 .. 19295

So `runtime-a`'s pre-flight check inspects 19232 and finds `runtime-b`
listening there legitimately. The band verifier exists to catch a stale
process squatting the band; here it fails the build on a sibling that is doing
exactly what it should, and the error names a port the job never intended to
use.

This is the shape the live tree had: three bands 32 apart against an assumed
width of 64. The fix is to declare the real width, which is why the check
demands one only where the assumed width actually overruns. Bands with room to
spare (the `clean` fixture's, 100 apart) stay legal without declaring
anything.

Expected: `ports` exits 1, naming both spans and the assumed width.
