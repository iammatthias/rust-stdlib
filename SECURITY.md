# Security and release status

Experimental unpublished library. Executed tests, dependency-policy checks,
negative certificate tests and fuzz campaigns are reproducible with the
commands in VERIFICATION.md and docs/FUZZING.md. These are engineering evidence rather than an external
security audit or complete standards-conformance guarantee.

First-party crates forbid unsafe code. Protocol parsers enforce explicit
byte/count/depth/work budgets. HTTP rejects ambiguous framing and isolates
trailers. Template values cannot opt out of contextual escaping; code positions
without a safe contract fail. Streaming decoded data remains provisional until
its documented finish/verification step succeeds.

The optional TLS adapter delegates cryptography and certificate validation to
the explicitly pinned Rustls/ring graph. Caller-supplied DER trust anchors are
required; there is no bypass, downgrade, bundled root snapshot or configured
revocation policy. Test fixture keys and roots are public local-demo material.

Applications own authentication/authorization, cookie domain/public-suffix
policy, network destination allowlists, driver I/O deadlines and transactional
side effects. Native handlers and blocking OS DNS are cooperative cancellation
boundaries. Trusted template functions can run arbitrary application code.

Before public 1.0: pass macOS/Linux/Windows release gates, run longer fuzz/load
campaigns, obtain independent protocol/security review, configure private
vulnerability reporting, and assign durable advisory/update/release ownership.
The repository owner must configure the private reporting channel; no address
or operational commitment has been invented. Publishing remains disabled.
