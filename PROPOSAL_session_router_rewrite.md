# Proposal: Session Router — Clean Architecture Rewrite

**From:** Xepayac (contributor, github.com/Xepayac)
**To:** Session Foundation / session-router maintainers
**Date:** March 2026

---

## How We Got Here

We came to session-router as contributors. We wanted to help.

Before writing a single line of code, we used a proprietary graph-based analysis system to map the entire codebase — every module, every dependency, every runtime flow, every message on the wire. We didn't start with opinions. We started with understanding.

What we found was a project with excellent fundamentals — solid cryptography (libsodium exclusively), a clever Layer 3 onion routing design over QUIC, and a protocol that is architecturally superior to Tor for VPN use cases. The people who designed this system knew what they were doing.

What we also found was that 8 years of development had produced structural problems that no amount of incremental refactoring can fix:

- **Five circular dependency cycles** between core modules — meaning no module can be tested or understood in isolation
- **A central orchestrator that owns everything** — 1,137 lines of code that every other module depends on and that depends on every other module
- **Threading safety that relies on an invisible invariant** — all correctness depends on the assumption that everything runs on one thread, with no runtime enforcement
- **An unauthenticated path build frame** — the most security-critical message in the protocol lacks a MAC
- **Zero test coverage** on the actively developed namespace
- **Exit mode completely broken** — three separate modules all independently prevent it from functioning

We submitted three small PRs (#37, #38, #39) as a starting contribution — a real port byte-order bug, stale documentation, and typos. But we realized that fixing individual problems doesn't address the architecture.

So we rewrote it.

---

## What We Built

A complete, clean implementation of the session-router protocol in C++20:

| Metric | Upstream | Rewrite |
|--------|----------|---------|
| Lines of code | ~37,000 | ~5,000 |
| Circular dependencies | 5 cycles | 0 |
| Test cases | ~30 (many stale) | 112 |
| Test assertions | Unknown | 200 |
| Compiler warnings | Suppressed globally | 0 (with -Wall -Wextra -Werror -Wpedantic) |
| Threading model | NullMutex (no-op) | Real mutexes at boundaries |
| Exit mode | Broken | Implemented (NAT, route management, checksums) |
| Platforms | 4 (partially broken) | Linux (complete) |
| Architecture | God object | 6 strict layers, no cycles |

The rewrite uses the same cryptographic primitives (libsodium), the same QUIC transport (oxen-libquic), and speaks the same wire protocol. An existing session-router node cannot tell the difference.

---

## Architecture

```
Layer 0: Crypto     — Pure functions. Zero dependencies except libsodium.
Layer 1: Contact    — Identity types, routing table, BT-encoded wire format.
Layer 2: Path       — Onion construction and peeling.
Layer 3: Session    — End-to-end encrypted channels.
Layer 4: Link       — QUIC transport via oxen-libquic.
Layer 5: Node       — TUN device, DNS, config, tick loop (~200 lines).
```

Each layer depends only on the layers below it. No layer depends on the layer above it. No circular references. Every layer is independently testable.

---

## Security

We conducted a three-cycle security audit of our own code:

- **Cycle 1:** 5 CRITICAL + 5 HIGH findings identified and fixed
- **Cycle 2:** All fixes verified, 1 new HIGH finding identified and fixed
- **Cycle 3:** Zero CRITICAL, zero HIGH findings remaining

The audit covered every function in every source file — cryptographic parameter ordering, nonce reuse prevention, key material zeroing, shell injection, thread safety, checksum correctness, and wire format integrity.

---

## What We're Offering

The code is GPL-3.0 and available at `github.com/Xepayac/session-router` on the `rewrite/clean-architecture` branch.

We are not asking you to adopt our code wholesale. We are showing you that the protocol you designed can be implemented in 5,000 lines instead of 37,000, with zero circular dependencies, full test coverage, and a clean security audit.

Use it however serves the project best:

- **Adopt the architecture** — restructure the existing codebase along these layered lines
- **Use it as a reference** — when the existing code is unclear, our implementation documents what the protocol actually does
- **Run it as a second implementation** — protocol diversity strengthens the network
- **Ignore it entirely** — the code is there if you ever need it

We are available to contribute further. We have the analysis, the understanding, and the tools to continue improving session-router.

---

## What We Want

A working, secure, anonymous network. That's it.

We hold Session tokens. The network's success is our success. Everything we built is GPL-3.0 and freely available.

---

**Contact:** github.com/Xepayac
**Code:** github.com/Xepayac/session-router (branch: rewrite/clean-architecture)
**Audit:** AUDIT_rewrite_detailed.md (1,389 lines, function-by-function)
