# Review records

Any change under `crates/crypto` or `backends/tls`, or one that touches
certificate or signature validation anywhere else, gets an independent review
before it merges. The review is written down here, because a session
transcript cannot be audited.

Name the file `NNNN-<slug>.md` after the pull request number. Records from before the public root commit use the private repository's PR numbers and merge commits, which no longer resolve; a change that first landed in the root commit is `root-<slug>.md`. A record holds:

- **Change.** The pull request and its merge commit.
- **Reviewers.** Each reviewer, its model, the revision it read, and what it
  ran.
- **Scope.** What the reviewer was asked to check, and what it left out.
- **Findings.** Each finding with its severity, as the reviewer reported it.
- **Resolution.** For each finding, the commit that fixed it, or the reason it
  stands.

The author of the change never counts as its reviewer. Neither do passing
tests.
