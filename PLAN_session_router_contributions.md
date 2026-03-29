# PLAN: Session Router Contributions

## Context

Session Router (formerly Lokinet) is an onion routing IP network. We forked it
to `Xepayac/session-router` and pulled it into TRUGS-DEVELOPMENT for development.
Two active upstream developers: jagerman (Jason Rhinelander) and tewinget (Thomas Winget).

Goal: contribute upstream via PRs. Start with unglamorous janitor work to build
trust. Progress to security-critical tests. Do not swamp them.

## Strategy

Start with work nobody wanted to do. Small PRs, obvious value, zero controversy.
Build relationship before touching anything architectural.

---

## Phase 1: Janitor PRs (no emotional attachment, immediately mergeable)

### PR 1: Fix actual bugs

- `src/ev/tcp.cpp:231,258` — `htonl()` used on `sin_port` instead of `htons()`.
  This is a real bug. 16-bit port field getting 32-bit byte swap. Two-line fix.
- `CMakeLists.txt:221` — `WOKRING_DIRECTORY` typo (should be `WORKING_DIRECTORY`).
  Means `git rev-parse` runs in wrong directory. One-character fix.

### PR 2: Fix documentation rot

- `docs/install.md:63` — says "C++ 17", project requires C++20.
- `docs/install.md:64-76` — lists libuv, libzmq, cppzmq, libcurl, libssl as deps.
  None are used. Actual deps: libevent, libsodium, libzstd, libunbound, oxen-libquic.
- `readme_ru.md`, `readme_fr.md`, `readme_es.md` — still reference `oxen-io` URLs
  instead of `session-foundation`.

### PR 3: Fix typos in code

- `occured` → `occurred` (4 instances across link_manager, session.hpp, session.cpp)
- `fallack` → `fallback` (session.cpp:1829)
- `src/ev/tcp.cpp:149` — "ass number" comment → "arbitrary number"

### PR 4: Build system cleanup

- `CMakeLists.txt:28` — `SROUTER_GRAPH_DEPENDENCIES` option set but never used. Remove.
- `CMakeLists.txt:82-83` — `option()` used for string values. Should be `set(CACHE STRING)`.
- `CMakeLists.txt:99-103` — commented-out debug block. Remove.
- `CMakeLists.txt:73` — `SROUTER_PEERSTATS` option — no code references it. Remove or document.

### PR 5: Memory leaks

- `src/daemon/session_router.cpp:122,154,311,518` — four `strdup()` calls with no `free()`.
  Windows service code. Replace with `std::string` or add proper cleanup.

---

## Phase 2: Dead code removal (still safe, but larger scope)

### PR 6: Remove dead egres packet router

- `src/vpn/egres_packet_router.cpp` — every handler method body is commented out.
  All methods silently discard packets. Entire file is a functional no-op.

### PR 7: Remove deprecated 1.0.x handshake code

- `src/session/session.hpp:571-572` — `_old_accept` marked deprecated.
- `handle_session_accept_deprecated()` and ~15 locations in session.cpp.
- Ask upstream first: "Is the 1.0.x compat code still needed or safe to remove?"

### PR 8: Clean up route_poker

- `src/router/route_poker.cpp` — `update()` entirely commented out, `start()` timer
  commented out, `put_up()`/`put_down()` critical paths commented out.
- Exit mode fundamentally cannot work. Document this or remove the dead code.

---

## Phase 3: Security-critical tests (after trust is established)

Start with simple pure-function tests, no mocking needed:

### PR 9: xchacha20-poly1305 AEAD round-trip tests

- Encrypt/decrypt round-trip
- Wrong key → failure
- Tampered ciphertext → MAC rejection
- Allocating vs in-place variants agree

### PR 10: Sealed box tests

- seal/unseal round-trip with Ed25519 keys
- Wrong key → throw
- Truncated ciphertext → throw
- Tampered ciphertext → throw

### PR 11: ML-KEM-768 post-quantum tests

- Generate, encapsulate, decapsulate, verify shared secrets match
- Wrong secret key → different shared secret (implicit rejection)
- Modified ciphertext → different shared secret

### PR 12: Session key derivation tests

- Both sides derive same keys (initiator vs receiver)
- Swapped RouterIDs → different keys
- Different tags → different keys

### PR 13: Blinded key signing tests

- Sign with blinded key, verify with blinded pubkey
- Different domains → different blinded keys
- Blinded signature does NOT verify with root pubkey (unlinkability)

### PR 14: Path onion tests (hardest, most valuable)

- Build path with known keys, peel layers, verify each hop
- Path message encrypt/decrypt round-trip
- Nonce XOR mutation correctness

---

## Noted issues for later (do not PR yet)

These are real problems but touching them early would be overstepping:

- `path_handler.cpp:772` — `path_died()` has zero callers (path failure silently lost)
- `session.cpp:174-175` — timers attached to wrong loop (acknowledged by devs)
- `session.cpp:151` — meaningless error code `11223322`
- `tun.cpp:448-450` — traffic type parameter silently discarded
- `route_poker.cpp:215` — "FIXME TODO: not adding default route yet because ???"
- `session_router.cpp:499` — ring buffer log sink disabled due to segfault
- Blanket `-Wno-deprecated-declarations` hides all deprecation warnings

---

## Open upstream issue

- **#31**: "Is there any way to host a private session network?" — unanswered since
  2026-02-22. Could answer with a doc PR. Good community gesture.

---

## Approach

1. Message jagerman first. Show we've read the code.
2. Phase 1 PRs one at a time. Not a dump.
3. Wait for feedback before Phase 2.
4. Phase 3 only after we're a known contributor.
5. Never touch architecture without asking.
