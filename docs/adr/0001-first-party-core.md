# ADR 0001: first-party core and synchronous initial transport

Status: adopted for bootstrap scope.

The goal is Go-like application-library breadth with minimal external dependencies. Implement missing application primitives in one first-party crate and compose them with Rust std. Keep all third-party Cargo dependency categories empty. Generic Read/BufRead/Write APIs form the protocol boundary. The initial native transport is blocking, with a bounded queue and a fixed worker count.

This gives a directly inspectable core and prevents a short root manifest from concealing a large transitive graph. It creates substantial first-party testing, security and maintenance responsibilities. An optional TLS implementation will require a separate reviewed exception. No TLS engine, cryptography provider, async runtime or template framework is approved by this decision.

The package remains experimental and unpublished. Name/license/MSRV/stability commitments require decisions and executed verification before public release.
