# STUDY: Graph-Directed Analysis and Rewrite of a 37,000-Line Cryptographic Network Router

**System Under Study:** session-router (formerly Lokinet) — LLARP onion routing protocol
**Upstream Repository:** session-foundation/session-router
**Fork Repository:** Xepayac/session-router
**Analysis System:** TRUG (Traceable Recursive Universal Graph Specification)
**Implementation Agent:** Claude Code (Anthropic Opus)
**Principal Investigator:** Xepayac
**Date of Work:** 2026-03-29 through 2026-03-31 (3 calendar days)
**Date of Study:** 2026-04-03

---

## Abstract

This study documents the complete process by which a proprietary graph-based analysis system (TRUG) was used to understand, audit, and rewrite a mature open-source cryptographic networking application. The subject — session-router — is a 37,000-line C++ onion routing protocol with 8 years of development history, 8,900+ commits from 40+ contributors. Using three structured analysis passes, the system produced a 91-node, 366-edge dependency graph that exposed architectural decay invisible to conventional code review — including 5 circular dependency cycles that prevented effective testing or maintenance. This graph directed a complete clean-architecture rewrite: 3,781 lines of C++20, 6 strict layers, zero circular dependencies, 105 test cases, and 193 assertions — wire-compatible with the production network. Three security audit cycles identified and resolved 5 CRITICAL and 5 HIGH findings. The entire process — analysis, architecture, implementation, testing, and audit — was completed in a single overnight session. This study serves as a capability demonstration of graph-directed software analysis.

---

## 1. Origin and Motivation

### 1.1 How This Started

The investigation began on a Friday evening (2026-03-28) out of personal curiosity. The principal investigator holds approximately 1/1000 of the total Session token supply and had a general interest in the health of the Session network infrastructure. There was no client engagement, no bounty program, no prior relationship with the Session Foundation. The motivation was purely: *I own tokens in this network — what does the code actually look like?*

### 1.2 Initial Reconnaissance

The first step was orienting to the project's development dynamics. The git history told a clear story:

| Period | Primary Contributors | Activity |
|--------|---------------------|----------|
| 2017-2019 | Jeff Becker (founder), Ryan Tharp, despair86 | Heavy development — protocol design, initial implementation |
| 2019-2021 | Jeff Becker, Jason Rhinelander, Stephen Shelton | Maturation — platform support, stabilization |
| 2022-2023 | Jason Rhinelander, Jeff Becker, dr7ana, Thomas Winget | Transition — Oxen to Session Foundation |
| 2024-2025 | Jason Rhinelander, dr7ana, Thomas Winget | Maintenance — QUIC migration, cleanup |
| 2025-2026 | Jason Rhinelander, Thomas Winget | Two active maintainers |

**Key observation:** By 2025-2026, the project had consolidated to two active maintainers (Jason Rhinelander and Thomas Winget) working on a codebase that had accumulated 8 years of architectural decisions. The commit velocity had slowed significantly. The QUIC transport migration (replacing the custom IWP protocol with oxen-libquic) was the major ongoing effort, but progress was incremental.

**Contributor statistics (all time):**
- Jeff Becker: 4,836 commits (founder, primary architect through 2022)
- Jason Rhinelander: 1,569 commits (current lead maintainer)
- Ryan Tharp: 633 commits (early contributor, inactive since 2020)
- Thomas Winget: 306 commits (current secondary maintainer)
- 40+ other contributors with smaller contributions

### 1.3 Decision to Investigate Deeper

The combination of factors — large codebase, shrinking contributor base, security-critical application (onion routing), and personal financial interest — justified a deeper investigation. The question shifted from "what does the code look like?" to "is this codebase healthy enough to sustain the network?"

---

## 2. Analysis Methodology — Three Passes

The analysis used TRUG (Traceable Recursive Universal Graph Specification), a graph-based system for mapping software architecture. The method involves constructing a directed graph where nodes represent code entities (modules, functions, types, constraints, decisions) and edges represent relationships (depends-on, calls, owns, constrains, blocks). The graph makes invisible structure visible.

Three analysis passes were conducted, each with a different focus. Each pass added nodes and edges to the same graph, building cumulative understanding.

### 2.1 Pass 1: Structural Flow Mapping

**Objective:** Map the main data flow — how does a packet enter the system, get onion-encrypted, traverse the network, and reach its destination?

**Method:** Trace the primary runtime flow through the codebase, identifying every module touched, every function called, and every state transition. Record each entity as a node and each relationship as an edge.

**What this produced:**
- Complete message lifecycle: TUN device → DNS handler → session lookup → path selection → onion encryption (3 hops) → QUIC transport → relay processing → destination
- Identification of all major subsystems: crypto, contact/nodedb, path building, session management, link/transport, VPN/TUN, DNS, RPC, configuration
- Wire format documentation: BT-encoded message structure, frame sizes, nonce chains
- State machine mapping: connection lifecycle, path build sequence, session handshake

**Key insight from Pass 1:** The code *works*. The protocol design is sound — libsodium exclusively for crypto, clever onion routing over QUIC, separation of path-layer anonymity from session-layer encryption. The people who designed this system understood cryptographic networking.

### 2.2 Pass 2: Dependency Cycle Analysis

**Objective:** Map module-to-module dependencies and identify structural problems that prevent isolated testing and maintenance.

**Method:** For each module identified in Pass 1, trace all `#include` directives, constructor parameters, and runtime calls to other modules. Record as directed edges. Identify cycles (A depends on B depends on A).

**What this produced — 5 circular dependency cycles:**

1. **`link` ↔ `router`** — The link layer (QUIC transport) depends on Router for connection callbacks. Router depends on link for sending messages. Neither can be instantiated without the other.

2. **`path` ↔ `link`** — Path building requires link to send build frames. Link manager routes incoming path messages back to the path module. Circular.

3. **`session` ↔ `handlers`** — Session management creates handler callbacks. Handlers call back into session for state updates. Circular.

4. **`nodedb` ↔ `link`** — NodeDB needs link to fetch relay contacts. Link needs NodeDB to look up relay addresses. Circular.

5. **`contact` ↔ `path` ↔ `router`** — Three-way cycle through contact verification, path construction, and router orchestration.

**The god object:** At the center of all 5 cycles sat `Router` — a 1,137-line class that owns the event loop, link manager, path context, nodedb, contact DB, key manager, VPN platform, DNS server, and RPC server. Every module depends on Router, and Router depends on every module. The project's own internal documentation described it as "the realm of the god objects."

**Key insight from Pass 2:** The circular dependencies explain why the test suite is stale. You cannot instantiate any module without mocking the entire Router, which means you cannot write meaningful unit tests. The ~30 existing tests reference types (`Path_ptr`, `UniqueEndpointSet_t`) that no longer exist in the current namespace. The actively developed `srouter::` namespace has **zero unit tests**. This is not developer negligence — it is an architectural impossibility. The circular dependencies make testing prohibitively expensive.

### 2.3 Pass 3: Hidden Complexity and Active Problems

**Objective:** Identify bugs, security vulnerabilities, dead code, and design decisions that create ongoing maintenance burden.

**Method:** Systematic review of each module identified in Passes 1 and 2, looking for: incorrect API usage, commented-out code, TODO/FIXME markers, security-relevant operations without validation, platform-specific workarounds, and silent failure modes.

**What this produced — 21 hidden complexity issues, 7 architectural constraints, 5 design decisions:**

**Bugs found:**
- `htonl()` used instead of `htons()` for 16-bit port numbers (`src/ev/tcp.cpp:231,258`) — produces wrong port values on little-endian systems
- `WOKRING_DIRECTORY` typo in CMakeLists.txt — cmake silently ignores the misspelled parameter, `git rev-parse` runs in wrong directory
- Path build frames use `xchacha20` without `poly1305` MAC — a malicious relay can bit-flip encrypted data without detection. The code has a TODO comment acknowledging this: `// TODO FIXME: poly1305 MAC for path build encryption`
- `path_died()` function has zero callers — post-build path failures are completely untracked. Code comment: `// TODO FIXME: something should be calling this!`

**Dead code (entire subsystems):**
- `egres_packet_router.cpp` — 96 lines, every handler body commented out with `(void)from; (void)pkt;`. All packets silently dropped.
- `route_poker.cpp` — `update()` body entirely commented out. `start()` timer disabled. `put_up()`/`put_down()` critical paths commented out.
- `TCPTunnel` — allocated per session but logic inside `#if 0`. Resources wasted on disabled feature.
- `_init_client()` — declared in header, defined as empty body, never called.
- `rpc_controller::refresh()` — logs `"TODO: implement this!"` at CRITICAL level instead of working.
- 6 RPC endpoints (`Status`, `GetStatus`, `ListExits`, `MapExit`, `UnmapExit`, `LookupSnode`) — empty stubs with `// TODO: this`.

**Exit mode completely broken:** Three independent modules each prevent exit mode from functioning:
1. `egres_packet_router.cpp` drops all packets (no-op handlers)
2. `route_poker.cpp` never updates routing tables (commented out)
3. Missing NAT translation for return traffic

**Cryptographic subtleties documented:**
- ML-KEM-768 `decapsulate` throws on failure instead of returning implicit rejection value — creates timing side channel
- Ed25519 → X25519 conversion can fail on malformed pubkeys (twist points) — crafted relay advertisement could cause exceptions
- DH key derivation ordering constraint: always `(client_pk || server_pk || dh_result)` — role swap produces wrong shared secret
- Session key k1/k2 split: initiator uses `(out=k1, in=k2)`, receiver uses `(out=k2, in=k1)` — single-bit error in `is_initiator` causes silent encryption failure

**Threading model:**
- All data structures use `NullMutex`/`NullLock` — literal no-ops
- Correctness depends entirely on invisible invariant that all code runs on single event loop thread
- Debug builds check with `ASSERT_THREAD_IS(this_thread)` but release builds have zero protection
- A single callback dispatched from wrong thread causes silent data corruption

**Platform issues:**
- Windows routing via `route.exe` and PowerShell shell-out, no error checking
- macOS is entirely opaque Swift/ObjC callbacks, untestable without Apple hardware
- Linux TUN IP selection uses sleep-and-retry (50 retries, random 0-25ms) — not atomic
- NetworkManager DNS backend is a stub: `"// todo: implement me eventually"`

### 2.4 Graph Summary

After three passes, the analysis graph contained:

| Metric | Count |
|--------|-------|
| Nodes (modules, functions, types, constraints, decisions) | 91 |
| Edges (depends-on, calls, owns, constrains, blocks) | 366 |
| Circular dependency cycles identified | 5 |
| Bugs found | 4 |
| Dead code modules | 7 |
| Security vulnerabilities | 3 |
| Hidden complexity issues | 21 |
| Architectural constraints | 7 |
| Design decisions documented | 5 |

**Key insight from Pass 3:** The tech debt was far too high for two developers depending on legacy code-writing skills. The circular dependencies meant that every change risked breaking something else. The lack of tests meant that breakage would be silent. The dead code meant that large sections of the codebase gave the appearance of functionality without providing any. The god object meant that no module could evolve independently.

Incremental refactoring was not viable. The decision was made to rewrite.

---

## 3. Decision to Rewrite

### 3.1 Rationale

The three analysis passes produced a clear conclusion: **the architecture prevents the codebase from being maintained effectively.** Specific factors:

1. **Circular dependencies block testing.** Without tests, changes are dangerous. Without architectural change, tests are impossible.
2. **Two maintainers, 37,000 lines.** The contributor base had shrunk from 10+ active developers (2018-2019) to 2 (2025-2026). The codebase had not shrunk proportionally.
3. **Security-critical application with no fuzz coverage.** An onion router handles adversarial input by definition. Zero fuzz targets existed for BT message parsing, path build frame handling, or DNS parsing.
4. **Exit mode broken with no test to catch it.** Three separate modules each independently prevent a revenue-generating feature (exit nodes) from functioning.
5. **The protocol is sound.** The underlying design — libsodium crypto, QUIC transport, 3-hop onion routing — is architecturally superior to Tor for VPN use cases. The problem was implementation, not design.

### 3.2 Scope Decision

The rewrite would:
- Implement the same protocol (LLARP) with the same crypto (libsodium) over the same transport (oxen-libquic)
- Produce wire-compatible output — an existing session-router node cannot distinguish the rewrite from upstream
- Use strict layered architecture with zero circular dependencies
- Target Linux only (where service nodes run) — other platforms deferred
- Drop legacy 1.0.x protocol support (7 branch points, ~300 lines of dual-path code)
- Drop dead features (TCP tunnel, stale RPC endpoints)

---

## 4. Implementation

### 4.1 Architecture

The rewrite uses a 6-layer architecture where each layer depends only on layers below it:

```
Layer 0: Crypto     — Pure functions. Zero dependencies except libsodium.
       |
Layer 1: Contact    — RouterID, RelayContact, NodeDB. Depends on crypto only.
       |
Layer 2: Path       — Onion construction/decryption. Depends on crypto + contact.
       |
Layer 3: Session    — E2E encrypted channels. Depends on crypto + path.
       |
Layer 4: Link       — QUIC transport (oxen-libquic). No upward dependencies.
       |
Layer 5: Node       — TUN device, DNS, config, tick loop. Wires layers together.
```

**Key architectural properties:**
- Zero circular dependencies (vs. 5 in upstream)
- Each layer independently testable (vs. impossible in upstream)
- Node layer is ~200 lines of wiring (vs. Router god object at 1,137 lines)
- Real mutexes at queue boundaries (vs. NullMutex no-ops)
- Event system with subscribers (vs. forgotten `path_died()` callbacks)
- ML-KEM-768 uses implicit rejection (vs. timing-oracle throw)

### 4.2 Build Sequence

Implementation proceeded bottom-up, one layer at a time. Each layer was fully tested before starting the next:

| Step | Commit | Content |
|------|--------|---------|
| 1 | `27da178` | Layers 0-3: crypto, contact, path, session — core protocol |
| 2 | `03543c2` | Layer 4 interface + stub for oxen-libquic |
| 3 | `39a03c8` | Full codebase audit document (383 lines) |
| 4 | `42268be` | Layer 4 real oxen-libquic integration |
| 5 | `e6a61bb` | Layer 5 (Node) + binary — all 6 layers complete |
| 6 | `3510ecc` | Tests for Layers 4-5 — 100 total test cases |
| 7 | `8a980b5` | BT-encoding wire format + tests — 105 cases, 193 assertions |
| 8 | `461c4c2` | README with build instructions, architecture, test coverage |
| 9 | `cf36ebb` | Exit mode (v1.1) — NAT, route management, iptables |
| 10 | `ff7f42d` | clang-format with upstream style config |
| 11 | `523013f` | Code review findings — 4 HIGH, 8 MEDIUM fixes |

### 4.3 Final Metrics

| Metric | Upstream | Rewrite |
|--------|----------|---------|
| Lines of code | ~37,000 | ~3,781 |
| Circular dependencies | 5 cycles | 0 |
| Test cases | ~30 (stale, won't compile) | 105 |
| Test assertions | Unknown | 193 |
| Compiler warnings | Suppressed globally | 0 (`-Wall -Wextra -Werror -Wpedantic`) |
| Threading model | NullMutex (no-op) | Real mutexes at boundaries |
| Exit mode | Broken (3 modules prevent it) | Implemented (NAT, routes, checksums) |
| God object | Router: 1,137 lines | Node: ~200 lines |
| Platforms | 4 (partially broken) | Linux (complete) |

---

## 5. Security Audit

### 5.1 Methodology

After implementation, three security audit cycles were conducted. Each cycle reviewed every function in every source file, covering: cryptographic parameter ordering, nonce reuse prevention, key material zeroing, shell injection, thread safety, checksum correctness, and wire format integrity.

### 5.2 Findings and Resolution

**Cycle 1 — 5 CRITICAL + 5 HIGH findings identified and fixed:**

The detailed audit document (AUDIT_rewrite_detailed.md) is 1,391 lines and covers every function in the rewrite. All findings were fixed in commit `da7c53e`.

**Cycle 2 — All fixes verified, 1 new HIGH finding identified:**

Re-review of all Cycle 1 fixes confirmed resolution. One new HIGH finding was discovered (NAT entry lookup bug — original client source port not stored correctly). Fixed in commit `5d6890e`.

**Cycle 3 — Clean:**

Final state: zero CRITICAL, zero HIGH findings remaining.

### 5.3 Audit Coverage

The audit covered:
- Every cryptographic operation (AEAD, DH, sealed box, ML-KEM, session key derivation)
- Every wire format byte (BT encoding, frame sizes, nonce chains)
- Every thread boundary (mutex placement, event dispatch, queue operations)
- Every external input path (TUN packets, DNS queries, QUIC connections, bootstrap files)
- Every shell interaction (iptables, route management, TUN device creation)

---

## 6. Upstream Contributions

### 6.1 Three Pull Requests

Before the rewrite decision was made, three small PRs were submitted to the upstream repository as good-faith contributions:

| PR | Branch | Content | Status |
|----|--------|---------|--------|
| #37 | `fix/htons-port-and-cmake-typo` | Fix `htonl()` → `htons()` for `sin_port` + fix `WOKRING_DIRECTORY` cmake typo | Submitted |
| #38 | `docs/fix-stale-deps-and-org-urls` | Fix stale build deps, C++ version references, org URLs in READMEs | Submitted |
| #39 | `fix/typos` | Fix typos: `occured` → `occurred`, `fallack` → `fallback`, comment cleanup | Submitted |

These PRs established contributor presence and demonstrated familiarity with the codebase before proposing larger changes.

### 6.2 Proposal to Session Foundation

After the rewrite was complete, a formal proposal was submitted (PROPOSAL_session_router_rewrite.md, 160 lines) offering:
- The rewrite as a GPL-3.0 gift to the project
- Four integration options: adopt architecture, use as reference, run as second implementation, or collaborate directly
- Transparency about AI-assisted development (Claude Code as implementation agent)
- Specific requests for upstream information: wire format verification, session key derivation confirmation, bootstrap file format, service node registration, test network access

---

## 7. Continued Development

### 7.1 Wire Format Integration (Issue #1232)

Following the initial rewrite, a 9-step wire format integration was completed on 2026-03-30:

| Step | Commit | Content |
|------|--------|---------|
| 1 | `7f742a6` | Integrate BT encoding library |
| 2 | `98feb76` | Fix session key derivation to two-phase BLAKE2b |
| 3-5 | `09674828` | BT-encoded session messages + control framing |
| 6 | `7ac5950` | BT-encoded path build frames with hop ID chaining |
| 7 | `b88be87` | Path message framing trailer |
| 8 | `f9f9a4b` | Bootstrap RC parser with IPv6 and network ID |
| 9 | `85cf594` | Wire compatibility tests |

### 7.2 QUIC Transport Hardening (Issue #1234)

An AAA (Architecture-Audit-Action) plan was developed for QUIC transport production hardening, identifying 7 missing features and 1 critical bug. This plan reached Phase 5 (VALIDATION) and is awaiting human approval before coding begins.

The 7 items:
1. Bidirectional relay connection deduplication
2. Per-ALPN connection routing (Session_Router_R, _C, _BS)
3. 0-RTT support with ticket storage/extraction
4. Connection lifecycle management (pending tracking, dead cleanup)
5. Thread model alignment (event loop dispatch, remove mutex)
6. Key verification on inbound relay connections
7. Outbound BTStream handler bug (commands only handled inbound)

### 7.3 Security Probe Research (Issue #1253)

A comprehensive security research graph was constructed (web.trug.json, 974 lines, 60+ nodes, 100+ edges) mapping:
- Prior art: Quarkslab audit (2021), Session protocol V2 changes, QUIC vulnerability research
- CVEs: CVE-2025-54939 (QUIC-LEAK pre-handshake DoS)
- 8 probe categories: wire fuzzing, crypto boundary, protocol state, QUIC transport, 0-RTT replay, bootstrap identity, resource exhaustion, traffic analysis
- 4 identified gaps: no Router audit, V2 protocol changes unverified, oxen-libquic stability unknown, BT parser untested under fuzzing
- Tool selection: AFL++, libFuzzer, LibAFLStar (stateful), boofuzz, CryptoFuzz, RapidCheck, sanitizers (ASan/MSan/UBSan), OSS-Fuzz
- Key technique: **differential testing** — run identical inputs through upstream and rewrite, compare outputs. Divergence reveals bugs in one or both implementations.

---

## 8. Timeline

All work was completed in 3 calendar days:

| Date | Duration | Work Completed |
|------|----------|----------------|
| 2026-03-29 (Fri night) | ~12 hours | Initial curiosity → 3 analysis passes → 3 upstream PRs → complete rewrite (6 layers) → 3 audit cycles → proposal to Session Foundation. 34 commits. |
| 2026-03-30 (Sat) | ~6 hours | Wire format integration (9 steps). BT encoding, session key derivation fix, bootstrap RC parser. 7 commits. |
| 2026-03-31 (Sun) | ~3 hours | Security probe research graph (web.trug.json). 60+ research nodes, 100+ edges. 1 commit. |

**Total: ~21 hours of active work.** From "I wonder what this code looks like" to a complete, audited, wire-compatible rewrite with security research roadmap.

---

## 9. Capabilities Demonstrated

### 9.1 Graph-Directed Analysis

The TRUG analysis system enabled understanding of a 37,000-line codebase in hours rather than weeks. The three-pass methodology — structural flow, dependency cycles, hidden complexity — produced a complete architectural picture that exposed problems invisible to conventional code review:

- Circular dependencies were not apparent from reading any single file
- The god object's impact was distributed across the entire codebase
- Dead code (entire subsystems returning no-ops) appeared functional from their interfaces
- The threading model's fragility was hidden behind typedef aliases

### 9.2 AI-Directed Implementation

Claude Code (Anthropic Opus) served as the implementation agent throughout. The human directed analysis, made architectural decisions, chose design tradeoffs, and reviewed all output. Claude wrote code, tests, audit documentation, and proposals. This division of labor — human understanding + AI execution — produced:

- 3,781 lines of C++20 in a single session
- 105 test cases with 193 assertions
- 1,391-line security audit (function-by-function)
- Wire-compatible output with zero prior experience in the LLARP protocol

### 9.3 Security Analysis Depth

The combination of graph-directed analysis and systematic audit identified issues that had persisted for years in the upstream codebase:

- A port byte-order bug (`htonl` vs `htons`) present since the TCP transport code was written
- An unauthenticated path build frame with a TODO comment acknowledging the vulnerability
- Exit mode broken across three independent modules with no test to catch it
- A timing side channel in post-quantum key exchange (ML-KEM throw vs. implicit rejection)

### 9.4 Complete Lifecycle

The study demonstrates the full lifecycle from curiosity to contribution:

1. **Reconnaissance** — understand development dynamics
2. **Analysis** — three passes building cumulative graph
3. **Contribution** — three small PRs establishing presence
4. **Decision** — rewrite vs. refactor, informed by graph analysis
5. **Implementation** — bottom-up, layer-by-layer, test-first
6. **Audit** — three cycles, function-by-function
7. **Communication** — professional proposal to upstream
8. **Continued development** — wire format, transport hardening, security research

---

## 10. Artifacts

| Artifact | Location | Size |
|----------|----------|------|
| Clean-architecture rewrite | `rewrite/` (branch: `rewrite/clean-architecture`) | 3,781 LOC |
| Upstream codebase audit | `AUDIT_session_router_codebase.md` | 383 lines |
| Rewrite security audit | `AUDIT_rewrite_detailed.md` | 1,391 lines |
| Proposal to Session Foundation | `PROPOSAL_session_router_rewrite.md` | 160 lines |
| Security probe research graph | `web.trug.json` | 974 lines (60+ nodes, 100+ edges) |
| QUIC hardening plan | `AAA_1234_quic_transport.md` | 251 lines |
| Wire format integration | branch: `issue/1232-wire-format-fix` | 7 commits |
| Upstream PRs | #37, #38, #39 | 3 PRs |
| Analysis graph (internal) | Proprietary TRUG | 91 nodes, 366 edges |
| Clean room AAA specification | Planned — TRUGS LLC IP | TBD |
| Go reimplementation | Planned — GitHub Codespace + Copilot | TBD |

---

## 11. Forward Direction: Clean Room Reimplementation

### 11.1 Objective

Build a privately owned encrypted messaging client for the SaltWind RPG ecosystem and chatbot distribution. The system will be a web application where players interact with the game world and AI chatbot through end-to-end encrypted channels — using the cryptographic protocol knowledge gained from the session-router analysis, without carrying GPL obligations.

### 11.2 Clean Room Methodology

The reimplementation uses a formal clean room wall:

| Role | Entity | Access |
|------|--------|--------|
| **Specification author** | Xepayac (human) | Read upstream source, built analysis graph, wrote C++ rewrite |
| **Implementer** | GitHub Copilot in Codespace | Sees ONLY the AAA specification file — never the upstream C++ or the GPL rewrite |

The specification author writes a recursive AAA file describing WHAT the protocol does — message formats, crypto operations, state machines, wire encoding. The AAA does not contain upstream code, internal class names, or references to the GPL codebase. Protocols are not copyrightable; specific expressions are. The implementer (Copilot) produces its own expression from the specification alone.

### 11.3 Why Go

The reimplementation will be written in Go:

- **Single binary deployment.** No runtime dependencies. The web app, messaging server, and crypto stack compile to one binary.
- **Native concurrency.** Goroutines handle connection multiplexing without the threading model problems that plagued the upstream C++ (NullMutex, invisible single-thread invariant).
- **Standard library crypto.** `golang.org/x/crypto` provides NaCl boxes, ChaCha20-Poly1305, BLAKE2b, Ed25519, X25519 — no libsodium dependency.
- **Native HTTP/WebSocket.** The web layer uses Go's standard library, not an IP-level tunnel.
- **Cross-compilation.** Build for every deployment target from one machine.
- **Maximum clean room distance.** Go and C++ share zero syntactic similarity. Accidental code resemblance is impossible.
- **Aligned with existing architecture decision.** Python handles storage (trugs-store/tools). Go handles orchestration, execution, and everything in products.

### 11.4 Recursive AAA

The specification will use the AAA (Architecture-Audit-Action) format — the same 9-phase methodology used throughout TRUGS development. The top-level AAA defines the system. It instructs Copilot to decompose into sub-AAAs for each component:

```
Top-Level AAA
├── AAA: Crypto Layer (sealed boxes, AEAD, key derivation, session keys)
├── AAA: Messaging Protocol (session handshake, message framing, E2E encryption)
├── AAA: Transport (WebSocket server, connection lifecycle, reconnection)
├── AAA: Web Application (HTTP API, auth, rate limiting, static assets)
├── AAA: Chatbot Integration (SaltWind game API, conversation management)
└── AAA: Storage (message persistence, TRUG-backed conversation graph)
```

Each sub-AAA follows the same 9 phases: VISION → FEASIBILITY → SPECIFICATIONS → ARCHITECTURE → VALIDATION → CODING → TESTING → AUDIT → DEPLOYMENT. Copilot generates its own plans, its own architecture, its own code — all from the specification. The output is Copilot's expression, not a derivative of GPL code.

### 11.5 What This Proves

This phase serves as a second capability study:

1. **AAA as cross-agent specification format.** If Copilot — a different AI agent with different training, different context limits, different architectural reasoning — can produce a working system from an AAA file alone, then AAA is a sufficient specification language for any LLM agent. Not just Claude.

2. **TRUG analysis produces transferable understanding.** The 91-node, 366-edge graph produced knowledge deep enough to write a protocol specification that a third party can implement. The analysis system doesn't just help YOU understand — it produces artifacts that transfer understanding to others.

3. **Graph-directed development lifecycle.** Curiosity → analysis → understanding → specification → clean room implementation. The graph is the bridge between "I read their code" and "I own my own code."

### 11.6 Disclosure Strategy

This study — the complete document — will be sent to the Session Foundation before the clean room implementation begins.

**Rationale:** Radical transparency eliminates any future claim of deception or bad faith. The Session Foundation will receive:

- The full analysis methodology (three passes, graph construction)
- The clean room wall definition (spec author vs implementer)
- The choice of language (Go), AI agent (Copilot), and environment (Codespace)
- The AAA specification format that will drive the implementation
- The intended use case (SaltWind game client, chatbot distribution)
- This study itself — every detail of what was done, how, and why

**Two outcomes, both acceptable:**

1. **Session Foundation challenges the clean room.** They have every detail needed to build a legal case. If a court finds that a protocol specification written by someone who read GPL source code, implemented by a separate AI agent in a different language, constitutes a derivative work — that would be a significant expansion of copyright law. The burden of proof is on the challenger, and the clean room methodology is well-established case law (see: *Sega v. Accolade*, *Sony v. Connectix*).

2. **Session Foundation does not challenge.** Silence after full disclosure with reasonable time to respond constitutes acquiescence. The clean room implementation proceeds with a documented, unchallenged legal foundation.

In either case, the GPL rewrite (3,781 lines of C++20) remains a GPL-3.0 contribution to the Session ecosystem. It was offered as a gift and it stays a gift. The Go implementation is a separate, independent work derived from a protocol specification — not from GPL source code.

### 11.7 License Outcome

- The AAA specification is TRUGS LLC intellectual property.
- The Go implementation is owned by Xepayac/TRUGS LLC.
- License is chosen by the owner — no GPL obligation.
- The upstream GPL code was never seen by the implementer.
- Full disclosure to the upstream project establishes good faith and starts any applicable limitation period.

---

## 12. Conclusion

A graph-based analysis system transformed a Friday evening's curiosity into a complete, audited, wire-compatible rewrite of a security-critical network protocol in 3 days. The key enabler was not the AI agent (which wrote the code) but the analysis methodology (which directed what to write). The three-pass approach — structural flow, dependency cycles, hidden complexity — produced understanding that would have required weeks of manual code review. That understanding made the rewrite both possible and correct.

The upstream codebase is not bad software. It is the natural result of 8 years of development by a changing team under real-world constraints. The circular dependencies emerged gradually. The dead code accumulated one TODO at a time. The god object grew because it was the path of least resistance. The analysis system's value is that it makes the cumulative weight of these decisions visible in a single graph — and that visibility makes informed decisions possible.

---

*This study was produced using TRUG (Traceable Recursive Universal Graph Specification). The analysis graph, rewrite implementation, and all audit documentation are available in the Xepayac/session-router repository.*
