# fixture: member-with-repository-dispatch

A `workflow_call` member that also carries its own `repository_dispatch:`.
`workflow_call` does not suppress a member's own triggers, so an external
dispatch (or a bot/automation firing `repository_dispatch` on the same event
that already drives the PR through ci.yml) runs this member twice against the
same tree, on two concurrency keys that `cancel-in-progress` cannot collapse --
the same duplicate-run shape `member-with-push` encodes, one trigger over.

Before this fixture, `check_cadence()` only matched `{"push", "pull_request"}`,
so a member carrying `repository_dispatch:` (or `pull_request_target:`)
alongside `workflow_call:` sailed through cadence green while running twice
per change -- the exact defect class PR #48 closed for `push`, left open for
its siblings.

`cadence` must go red here. Its pair, `member-with-repository-dispatch-ok`, is
the same file with `schedule:` instead -- without that twin, this red would be
equally consistent with "any member carrying a second trigger is flagged",
which is not the rule.

Workflow: `.github/workflows/build-test.yml`.
