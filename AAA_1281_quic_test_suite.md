# AAA: Session Router QUIC Layer — Test Suite and Fix

**Issue:** TRUGS-DEVELOPMENT#1281
**Sub-issue:** TRUGS-DEVELOPMENT#1282 (TRUG analysis — COMPLETE)
**Supersedes:** AAA_1234_quic_transport.md
**Status:** PLANNING — Phase 5 VALIDATION approved
**Analysis:** quic_layer.trug.json (37 nodes, 38 edges)
**Audits:** 3 completed (coverage gaps, insidious weirdness, structural consolidation)

---

## Phase 1: VISION
**Status:** COMPLETE

### What We're Doing

Write a comprehensive test suite for the session-router QUIC transport layer (`src/link/`), then fix everything that fails.

### Why Test-First

The upstream has zero test coverage on its active QUIC namespace (`srouter::link`). Our rewrite's link layer tests (test_manager.cpp, 9 tests) only cover null safety — no actual connections, no lifecycle, no protocol behavior.

Test-first is the right approach because:

1. **Tests are the most valuable contribution.** A test suite that covers the QUIC layer is what prevents the codebase from rotting further. The upstream can't maintain what they can't test.
2. **Tests prove the bugs.** Each known issue becomes a failing test. Undeniable, reproducible, specific.
3. **Tests are non-controversial.** "Here are tests" gets merged. "I rewrote your code" starts a fight.
4. **Tests enable everything else.** Our C++ rewrite validates against the same tests. The Go clean room targets the same behaviors. The security audit verifies against the same assertions.

### What We're Testing

From quic_layer.trug.json analysis, the QUIC layer has 6 connection maps, 2 tickers, 3 ALPN types, a bidirectional dedup algorithm, key verification, 0-RTT support, ordered shutdown, and a dual-loop threading model. All of it untested.

---

## Phase 2: FEASIBILITY
**Status:** COMPLETE

### Can We Test Without a Live Network?

Yes. The Catch2 framework is already in place and all 9 existing test suites pass. The QUIC layer can be tested at three levels:

1. **Unit tests (no network).** Test data structures in isolation: relay_conn winner selection, connection map operations, static secret derivation. These run instantly.

2. **Loopback tests (localhost QUIC).** Create two Endpoint instances on localhost, connect them, and exercise the full lifecycle. This tests real QUIC connections without any external dependency. oxen-libquic supports this — the existing endpoint test proves it compiles and links.

3. **Integration tests (two-node).** Two full Node instances on localhost, building paths, exchanging messages. This is the hardest to set up but tests the full stack.

### Build Dependencies

- Catch2 (already linked)
- oxen-libquic (already linked)
- libsodium (already linked)
- No additional dependencies required

### GO/NO-GO

**GO.** Testing infrastructure exists. No new dependencies. Loopback testing is viable.

---

## Phase 3: SPECIFICATIONS
**Status:** COMPLETE (consolidated from 3 audit passes — 112 tests)

### Required Upstream Code Changes

Two changes required to make the QUIC layer testable:

**Change 1: Configurable ticker constants (for CI speed)**

```cpp
// endpoint.hpp — change from:
inline constexpr auto REDUNDANT_LINGER = 20s;
inline constexpr auto DEREGGED_LINGER = 30min;

// to:
#ifndef SROUTER_TEST_TIMING
inline constexpr auto REDUNDANT_LINGER = 20s;
inline constexpr auto DEREGGED_LINGER = 30min;
#else
inline constexpr auto REDUNDANT_LINGER = 200ms;
inline constexpr auto DEREGGED_LINGER = 500ms;
#endif
```

**Change 2: Test accessor for private connection maps**

```cpp
// endpoint.hpp — add inside class Endpoint:
#ifdef SROUTER_TESTING
    friend class QuicTestAccessor;
#endif
```

Both changes are behind `#ifdef` guards — zero impact on production code.

### Test Categories

Each test maps to nodes and edges in quic_layer.trug.json. Traceability column shows the TRUG node.

#### Category 1: relay_conn Data Structure (Unit — 15 tests)

Tests for the `relay_conn` struct (endpoint.hpp:49-79). No network required.

| # | Test | Verifies | TRUG Node |
|---|------|----------|-----------|
| 1.1 | Winner selection: A < B | `relay_conn(true)` when remote < local → `inbound_wins == true` | relay_conn_struct |
| 1.2 | Winner selection: A > B | `relay_conn(false)` when remote > local → `inbound_wins == false` | relay_conn_struct |
| 1.3 | Winner symmetry | Both sides compute same physical winner | relay_conn_struct |
| 1.4 | set_conn inbound only | Set inbound, no outbound → `conn == inbound.get()` | relay_conn_struct |
| 1.5 | set_conn outbound only | Set outbound, no inbound → `conn == outbound.get()` | relay_conn_struct |
| 1.6 | set_conn both — inbound wins | Set both when inbound_wins=true → `conn == inbound.get()` | relay_conn_struct |
| 1.7 | set_conn both — outbound wins | Set both when inbound_wins=false → `conn == outbound.get()` | relay_conn_struct |
| 1.8 | set_conn replaces existing | Set inbound when inbound already exists → old closed, new set | relay_conn_struct |
| 1.9 | close inbound, outbound remains | Close inbound direction → `conn == outbound.get()` | relay_conn_struct |
| 1.10 | close outbound, inbound remains | Close outbound direction → `conn == inbound.get()` | relay_conn_struct |
| 1.11 | close both | close_all() → `conn == nullptr`, both ptrs null | relay_conn_struct |
| 1.12 | close_redundant — inbound wins | close_redundant() when inbound_wins → outbound closed with errcode 6 | relay_conn_struct |
| 1.13 | close_redundant — outbound wins | close_redundant() when !inbound_wins → inbound closed with errcode 6 | relay_conn_struct |
| 1.14 | Static secret determinism | Same key → same secret, different key → different secret | ep_constructor |
| 1.15 | Connection wrapper construction | Connection(conn, stream) initializes datagrams from conn->datagrams() | subsys_connection |

#### Category 2: Connection Map Operations (Loopback — 14 tests)

Tests for the 6-map data model. Uses QuicTestAccessor to verify internal state via public query functions.

| # | Test | Verifies | TRUG Node |
|---|------|----------|-----------|
| 2.1 | Relay connection storage | Store and retrieve from relay_conns via get_relay_conn() | map_relay_conns |
| 2.2 | Relay bidir tracking | Entry added when both directions exist | map_relay_bidir |
| 2.3 | Pending outbound tracking | Store pre-establishment, remove on establish | map_pending_outbound |
| 2.4 | Pending outbound dedup | Second connect to same peer reuses pending | map_pending_outbound |
| 2.5 | Client connection storage | Store outbound edge connections via get_client_conn() | map_client_conns |
| 2.6 | Inbound client by CID | Store by ConnectionID, not RouterID | map_inbound_clients |
| 2.7 | Pending dead tracking | Add with timestamp, retrieve for age check | map_pending_dead |
| 2.8 | Pending dead resurrection | Remove if relay re-registers | map_pending_dead |
| 2.9 | get_current_relays | Returns all connected, optionally pending | ep_queries |
| 2.10 | connected_to_relay with pending | Includes pending when flag set | ep_queries |
| 2.11 | relay_connection_counts | Correct breakdown: total, out, in, pending, clients | ep_queries |
| 2.12 | num_relay_conns no double count | Pending relay already in relay_conns not double counted | ep_queries |
| 2.13 | unique_edge_range grouping | Client with same-subnet edges → returns range, mixed → nullopt | ep_queries |
| 2.14 | have_client_connection_to | Manager query delegates to endpoint correctly | mgr_connect_keepalive |

#### Category 3: ALPN Routing (Loopback — 14 tests)

Tests for per-ALPN connection handling. Requires localhost QUIC connections.

| # | Test | Verifies | TRUG Node |
|---|------|----------|-----------|
| 3.1 | Relay ALPN → relay_conns | Inbound relay connection stored in relay_conns | ep_on_inbound |
| 3.2 | Client ALPN → inbound_clients | Inbound client connection stored in inbound_clients | ep_on_inbound |
| 3.3 | Bootstrap ALPN → untracked | Bootstrap connection NOT stored in any map | ep_special_connect |
| 3.4 | Relay ALPN timeout | Keep-alive 10s, idle 33s | ep_constructor |
| 3.5 | Client ALPN timeout | Keep-alive 20s, idle 63s | ep_constructor |
| 3.6 | Bootstrap ALPN timeout | No keep-alive, idle 10s | ep_special_connect |
| 3.7 | Relay ALPN commands registered | path_build, fetch_rcs, gossip_rc, publish_cc, find_cc, ping | mgr_register_commands |
| 3.8 | Client ALPN commands registered | path_control, session_control only | mgr_register_commands |
| 3.9 | Bootstrap ALPN commands registered | bfetch_rcs only | mgr_register_bootstrap |
| 3.10 | make_control inbound: queue_incoming_stream | Inbound: stream ID = 0, BTRequestStream type | ep_make_control |
| 3.11 | make_control outbound: open_stream | Outbound: BTRequestStream with stream_notify | ep_make_control |
| 3.12 | make_control relay uses RouterID as remote | RELAY_ALPN: remote = RouterID. CLIENT_ALPN: remote = ConnectionID | ep_make_control |
| 3.13 | testing_client_connect untracked | Connection not in any map, uses CLIENT_ALPN, no keep_alive | ep_special_connect |
| 3.14 | connect_to_keep_alive filters connected | Connects to N random relays, skips already-connected/pending | mgr_connect_keepalive |

#### Category 4: Key Verification (Loopback — 8 tests)

Tests for the TLS key verification callback (endpoint.cpp:130-181).

| # | Test | Verifies | TRUG Node |
|---|------|----------|-----------|
| 4.1 | Relay ALPN: registered key accepted | Registered RouterID → connection accepted | ep_key_verify |
| 4.2 | Relay ALPN: unregistered key rejected | Unknown RouterID → connection rejected | ep_key_verify |
| 4.3 | Relay ALPN: missing key rejected | No key provided → connection rejected | ep_key_verify |
| 4.4 | Relay ALPN: wrong size key rejected | Key != 32 bytes → connection rejected | ep_key_verify |
| 4.5 | Relay ALPN: own key rejected | Self-connection → connection rejected | ep_key_verify |
| 4.6 | Client ALPN: no key accepted | Anonymous client → connection accepted | ep_key_verify |
| 4.7 | Client ALPN: valid key accepted | Client with key → connection accepted | ep_key_verify |
| 4.8 | Client ALPN: wrong size key rejected | Invalid key size → connection rejected | ep_key_verify |

#### Category 5: Bidirectional Dedup (Loopback — 9 tests)

Tests for relay_conn lifecycle with two relay instances.

| # | Test | Verifies | TRUG Node |
|---|------|----------|-----------|
| 5.1 | Single direction works | A connects to B → A has outbound, B has inbound | ep_on_outbound |
| 5.2 | Both directions established | A→B and B→A both connect → both have relay_conns | ep_on_inbound |
| 5.3 | Bidir tracked | Both directions → relay_bidir has entry with timestamp | map_relay_bidir |
| 5.4 | Winner selected correctly | A < B → A's inbound wins, B's outbound wins | relay_conn_struct |
| 5.5 | Redundant closed after linger | After REDUNDANT_LINGER, loser closed with errcode 6 | ticker_redundancy |
| 5.6 | Messages flow on winner | After dedup, commands sent on preferred connection | relay_conn_struct |
| 5.7 | Loser close doesn't disrupt | Closing redundant doesn't affect the winner | relay_conn_struct |
| 5.8 | CONN_CLOSE_REDUNDANT recognized | Errcode 6 close doesn't trigger warning log | ep_conn_closed |
| 5.9 | Datagram queue limit | Queue at 2,000,000 bytes — verify behavior near limit | ep_constructor |

#### Category 6: Connection Lifecycle (Loopback — 13 tests)

Tests for pending → established → closed lifecycle.

| # | Test | Verifies | TRUG Node |
|---|------|----------|-----------|
| 6.1 | Outbound starts in pending | connect() creates entry in pending_outbound | ep_ctrl_stream_impl |
| 6.2 | Establishment moves to relay_conns | on_conn_established → moved from pending to relay_conns | ep_on_outbound |
| 6.3 | Establishment moves to client_conns | Client mode: moved from pending to client_conns | ep_on_outbound |
| 6.4 | Failed connection cleaned | Connection fails → removed from pending_outbound | ep_conn_closed |
| 6.5 | Close inbound relay | Relay close → direction removed from relay_conn | ep_conn_closed |
| 6.6 | Close outbound relay | Outbound close → direction removed, conn switches | ep_conn_closed |
| 6.7 | Close both → erase relay_conn | Both directions closed → relay_conn entry removed | ep_conn_closed |
| 6.8 | Close client conn | Client close → removed from client_conns | ep_conn_closed |
| 6.9 | Close inbound client | Relay side: removed from inbound_clients | ep_conn_closed |
| 6.10 | Pre-negotiation failure | ALPN empty → cleaned from pending_outbound | ep_conn_closed |
| 6.11 | Edge conn change callback | Client: on_edge_conn_change called on establish/close | ep_on_outbound |
| 6.12 | Single close no double-close (W2) | One close event with matching reference_id doesn't close both directions | ep_conn_closed |
| 6.13 | Control stream exists pre-establishment (W3) | Rapid connect + command: control stream usable before establishment | ep_ctrl_stream_impl |

#### Category 7: Tickers (Loopback — 9 tests)

Tests for the two periodic lifecycle managers.

| # | Test | Verifies | TRUG Node |
|---|------|----------|-----------|
| 7.1 | Redundancy ticker fires | close_redundant() called every REDUNDANT_LINGER | ticker_redundancy |
| 7.2 | Redundancy closes correct direction | Loser direction closed, winner untouched | ticker_redundancy |
| 7.3 | Redundancy cleans relay_bidir | Entry removed after close | ticker_redundancy |
| 7.4 | Dereg ticker detects unregistered | Newly unregistered relay added to pending_dead | ticker_dereg |
| 7.5 | Dereg ticker linger period | Connection NOT closed before DEREGGED_LINGER | ticker_dereg |
| 7.6 | Dereg ticker closes expired | Connection closed after DEREGGED_LINGER | ticker_dereg |
| 7.7 | Dereg resurrection | Re-registered relay removed from pending_dead without closing | ticker_dereg |
| 7.8 | Dereg cleans all maps | Dead relay cleaned from relay_conns, pending_outbound, relay_bidir | ticker_dereg |
| 7.9 | close_redundant iteration safe (W7) | Closing during iteration completes without crash | ticker_redundancy |

#### Category 8: Command Dispatch (Loopback — 16 tests)

Tests for Manager command registration and response handling.

| # | Test | Verifies | TRUG Node |
|---|------|----------|-----------|
| 8.1 | Send command to connected relay | Command reaches remote, response received | ep_send_command |
| 8.2 | Send command initiates connection | Command to unconnected relay creates pending_outbound | ep_ctrl_stream_impl |
| 8.3 | Response on router loop | Response handler executes in router loop, not network loop | ep_send_command |
| 8.4 | Send datagram to connected | Datagram delivered to connected peer | ep_send_datagram |
| 8.5 | Send datagram to unconnected drops | Datagram to unknown peer returns false, no connection initiated | ep_send_datagram |
| 8.6 | Send command while stopping | is_stopping=true → command silently dropped | mgr_stop |
| 8.7 | Gossip RC to peers | gossip_rc sends to all relay peers except origin and sender | mgr_gossip |
| 8.8 | Ping/pong | Ping command returns "pong" | mgr_register_commands |
| 8.9 | for_each_relay_conn preferred only | Only preferred connection visited, not both directions | ep_queries |
| 8.10 | Send command to client by CID | Command reaches inbound client, response on router loop | ep_send_command |
| 8.11 | Gossip dedup — known RC not re-gossipped | Duplicate RC not forwarded to peers | mgr_gossip |
| 8.12 | Bootstrap fetch returns compressed RCs | bfetch_rcs returns zstd-compressed BT-encoded RC list | mgr_register_bootstrap |
| 8.13 | path_build remote identity correct (W4) | path_build handler receives captured remote, not m.conn_rid() | mgr_register_commands |
| 8.14 | Outbound commands work after establishment (W5) | Handlers registered pre-establishment function post-establishment | ep_ctrl_stream_impl |
| 8.15 | connect_to with custom callbacks | Custom establish/close callbacks fire correctly | mgr_connect_keepalive |
| 8.16 | Bootstrap fetch edge cases | Empty RC list, single RC, large RC list compression | mgr_register_bootstrap |

#### Category 9: Shutdown and Safety (Loopback — 6 tests)

Tests for ordered teardown and lifetime safety.

| # | Test | Verifies | TRUG Node |
|---|------|----------|-----------|
| 9.1 | Ordered shutdown | All maps cleared in correct order | ep_shutdown |
| 9.2 | Double stop is safe | stop() called twice, no crash | mgr_stop |
| 9.3 | Canary prevents use-after-free | Callback fires after Endpoint destroyed → early return | ep_conn_closed |
| 9.4 | Control stream before loop transfer | Inbound: BTRequestStream queued before data processed | ep_conn_established |
| 9.5 | Weak_from_this handles death | Connection dies between callback and router loop → no crash | ep_conn_established |
| 9.6 | Datagram in-flight during destruction (W6) | Datagram queued when Endpoint destroyed → no crash (may expose bug) | ep_constructor |

#### Category 10: 0-RTT (Loopback — 4 tests)

| # | Test | Verifies | TRUG Node |
|---|------|----------|-----------|
| 10.1 | Ticket stored on first connect | 0-RTT store callback fires, ticket in NodeDB | ep_0rtt |
| 10.2 | Ticket extracted on reconnect | 0-RTT extract callback returns stored ticket | ep_0rtt |
| 10.3 | Expired ticket not used | Ticket past expiry → extract returns empty | ep_0rtt |
| 10.4 | Inbound 0-RTT enabled for relay | enable_inbound_0rtt(0s, 48h) configured | ep_0rtt |

#### Category 11: Threading (Loopback — 4 tests)

| # | Test | Verifies | TRUG Node |
|---|------|----------|-----------|
| 11.1 | Network callback transfers to router loop | on_conn_established fires in network loop, state change visible in router loop | ep_conn_established |
| 11.2 | call_get returns value across loops | get_relay_conn() returns correct value from outside router loop | ep_queries |
| 11.3 | Concurrent access doesn't corrupt | Rapid connect/disconnect while querying connection counts | ep_queries |
| 11.4 | call_get from inside loop executes inline (W1) | No deadlock when ctrl_stream_impl calls get_relay_conn | ep_ctrl_stream_impl |

---

### Test Count Summary

| Category | Tests | Level | Network Required |
|----------|-------|-------|-----------------|
| 1. relay_conn struct | 15 | Unit | No |
| 2. Connection maps | 14 | Loopback | Yes |
| 3. ALPN routing | 14 | Loopback | Yes |
| 4. Key verification | 8 | Loopback | Yes |
| 5. Bidirectional dedup | 9 | Loopback | Yes |
| 6. Connection lifecycle | 13 | Loopback | Yes |
| 7. Tickers | 9 | Loopback | Yes |
| 8. Command dispatch | 16 | Loopback | Yes |
| 9. Shutdown and safety | 6 | Loopback | Yes |
| 10. 0-RTT | 4 | Loopback | Yes |
| 11. Threading | 4 | Loopback | Yes |
| **Total** | **112** | | |

### TRUG Node Coverage Verification

All 37 TRUG nodes mapped to at least one test:

| TRUG Node | Tests |
|-----------|-------|
| root | (structural — covered by subsystem tests) |
| subsys_endpoint | 1.14, 2.1-2.13, 3.1-3.14, 5.1-5.9, 6.1-6.13, 9.1 |
| subsys_manager | 3.7-3.9, 8.1-8.16 |
| subsys_connection | 1.15 |
| ep_constructor | 1.14, 3.4-3.6, 5.9, 9.6 |
| ep_connection_maps | 2.1-2.14 |
| map_relay_conns | 2.1, 3.1, 5.2 |
| map_relay_bidir | 2.2, 5.3, 7.3 |
| map_pending_outbound | 2.3-2.4, 6.1, 6.4 |
| map_pending_dead | 2.7-2.8, 7.4-7.8 |
| map_client_conns | 2.5, 6.3, 6.8 |
| map_inbound_clients | 2.6, 3.2, 6.9 |
| relay_conn_struct | 1.1-1.13, 5.4, 5.6-5.7 |
| ep_tickers | 7.1-7.9 |
| ticker_redundancy | 5.5, 7.1-7.3, 7.9 |
| ticker_dereg | 7.4-7.8 |
| ep_conn_established | 9.4-9.5, 11.1 |
| ep_on_inbound | 3.1-3.2, 5.2 |
| ep_on_outbound | 5.1, 6.2-6.3, 6.11 |
| ep_conn_closed | 5.8, 6.4-6.10, 6.12, 9.3 |
| ep_make_control | 3.10-3.12 |
| ep_send_datagram | 8.4-8.5 |
| ep_send_command | 8.1, 8.3, 8.10 |
| ep_ctrl_stream_impl | 6.1, 6.13, 8.2, 8.14, 11.4 |
| ep_special_connect | 3.3, 3.6, 3.13 |
| ep_shutdown | 9.1 |
| ep_queries | 2.9-2.13, 8.9, 11.2-11.3 |
| ep_key_verify | 4.1-4.8 |
| ep_0rtt | 10.1-10.4 |
| mgr_register_commands | 3.7-3.8, 8.8, 8.13 |
| mgr_register_bootstrap | 3.9, 8.12, 8.16 |
| mgr_gossip | 8.7, 8.11 |
| mgr_path_handlers | 8.13 |
| mgr_session_handlers | (tested indirectly via datagram/path_control flow) |
| mgr_connect_keepalive | 2.14, 3.14, 8.15 |
| mgr_stop | 8.6, 9.2 |

---

## Phase 4: ARCHITECTURE
**Status:** COMPLETE

### File Structure

```
rewrite/test/
├── test_relay_conn.cpp        — Category 1: relay_conn struct + statics (15 unit tests)
├── test_quic_maps.cpp         — Category 2: connection map operations (14 loopback)
├── test_quic_alpn.cpp         — Category 3: ALPN routing + make_control (14 loopback)
├── test_quic_keys.cpp         — Category 4: key verification (8 loopback)
├── test_quic_dedup.cpp        — Category 5: bidirectional dedup (9 loopback)
├── test_quic_lifecycle.cpp    — Category 6: connection lifecycle (13 loopback)
├── test_quic_tickers.cpp      — Category 7: ticker systems (9 loopback)
├── test_quic_commands.cpp     — Category 8: command dispatch (16 loopback)
├── test_quic_shutdown.cpp     — Category 9: shutdown and safety (6 loopback)
├── test_quic_0rtt.cpp         — Category 10: 0-RTT (4 loopback)
├── test_quic_threading.cpp    — Category 11: threading model (4 loopback)
└── helpers/
    └── quic_test_harness.hpp  — Shared loopback test infrastructure
```

### Test Harness Design

```cpp
// quic_test_harness.hpp

// Accessor for private Endpoint members (requires friend declaration)
class QuicTestAccessor {
public:
    static auto& relay_conns(link::Endpoint& ep);
    static auto& relay_bidir(link::Endpoint& ep);
    static auto& pending_outbound(link::Endpoint& ep);
    static auto& pending_dead(link::Endpoint& ep);
    static auto& client_conns(link::Endpoint& ep);
    static auto& inbound_clients(link::Endpoint& ep);
};

struct MockJobQueue {
    quic::Loop& loop;
    
    template <typename F> void call(F&& f) { loop.call(std::forward<F>(f)); }
    
    template <typename F> auto call_get(F&& f) {
        // CRITICAL (W1): if already inside the loop, execute inline.
        // The real JobQueue does this implicitly. Without this,
        // ctrl_stream_impl → get_relay_conn deadlocks.
        if (loop.inside())
            return f();
        return loop.call_get(std::forward<F>(f));
    }
};

struct MockNodeDB {
    std::unordered_set<RouterID> registered;
    std::unordered_map<RouterID, std::vector<unsigned char>> stored_0rtt;
    
    bool is_registered(const RouterID& rid) const { return registered.contains(rid); }
    void store_0rtt(const RouterID& rid, std::vector<unsigned char> data, auto expiry) {
        stored_0rtt[rid] = std::move(data);
    }
    std::optional<std::vector<unsigned char>> extract_0rtt(const RouterID& rid) {
        if (auto it = stored_0rtt.find(rid); it != stored_0rtt.end()) {
            auto data = std::move(it->second);
            stored_0rtt.erase(it);
            return data;
        }
        return std::nullopt;
    }
    // For connect_to_keep_alive:
    std::vector<const RelayContact*> get_n_random_edge_rcs(int n, bool, auto filter) { /*...*/ }
    // For check_deregged_conns:
    std::unordered_set<RouterID> get_registered_relay_set() const { return registered; }
};

struct MockRouter {
    Ed25519KeyPair keys;
    RouterID _id;
    bool is_service_node;
    MockJobQueue _jq;
    MockNodeDB _node_db;
    quic::Address _listen_addr;     // localhost:0 (OS-assigned port)
    int edge_conn_changes = 0;
    int test_pings = 0;
    
    const RouterID& id() const { return _id; }
    const Ed25519SecretKey& secret_key() const { return keys.sk; }
    const quic::Address& listen_addr() const { return _listen_addr; }
    quic::Loop& loop() { return _jq.loop; }
    MockNodeDB& node_db() { return _node_db; }
    void on_edge_conn_change() { ++edge_conn_changes; }
    void on_test_ping() { ++test_pings; }
};

struct QuicTestHarness {
    MockRouter router_a;  // Guarantee: router_a.id < router_b.id
    MockRouter router_b;
    link::Manager manager_a;
    link::Manager manager_b;
    
    // Constructor: generates keys, sorts by RouterID, registers each
    // in the other's NodeDB, binds to localhost:0
    QuicTestHarness();
    
    void connect_a_to_b();
    void connect_b_to_a();
    void wait_established(std::chrono::milliseconds timeout = 5s);
    void run_for(std::chrono::milliseconds);
    void tick();  // Advance one event loop cycle on both loops
};
```

### Port Allocation

Each `MockRouter` binds to `127.0.0.1:0` (OS assigns port). After bind, read actual port via `endpoint->local().port()`. No port conflicts possible.

### CMake Changes

Add to `rewrite/CMakeLists.txt`:
```cmake
add_executable(test_quic
    test/test_relay_conn.cpp
    test/test_quic_maps.cpp
    test/test_quic_alpn.cpp
    test/test_quic_keys.cpp
    test/test_quic_dedup.cpp
    test/test_quic_lifecycle.cpp
    test/test_quic_tickers.cpp
    test/test_quic_commands.cpp
    test/test_quic_shutdown.cpp
    test/test_quic_0rtt.cpp
    test/test_quic_threading.cpp
)
target_compile_definitions(test_quic PRIVATE SROUTER_TESTING SROUTER_TEST_TIMING)
target_link_libraries(test_quic PRIVATE sr_link sr_crypto sr_contact Catch2::Catch2WithMain oxen-quic)
add_test(NAME quic COMMAND test_quic)
```

### Execution Order

| Step | Files | Depends On | Tests |
|------|-------|------------|-------|
| 1 | test_relay_conn.cpp | Nothing | 15 unit tests |
| 2 | helpers/quic_test_harness.hpp | Step 1 passing | Harness infrastructure |
| 3 | test_quic_maps.cpp | Harness | 14 map tests |
| 4 | test_quic_lifecycle.cpp | Harness | 13 lifecycle tests |
| 5 | test_quic_alpn.cpp | Harness | 14 ALPN tests |
| 6 | test_quic_keys.cpp | Harness | 8 key verification tests |
| 7 | test_quic_dedup.cpp | Harness + lifecycle | 9 dedup tests |
| 8 | test_quic_tickers.cpp | Harness + dedup | 9 ticker tests |
| 9 | test_quic_commands.cpp | Harness | 16 command tests |
| 10 | test_quic_shutdown.cpp | Harness | 6 shutdown tests |
| 11 | test_quic_0rtt.cpp | Harness | 4 0-RTT tests |
| 12 | test_quic_threading.cpp | Harness | 4 threading tests |
| 13 | Fix all failures | All tests written | Bug fixes |
| 14 | Audit fixes | All fixes committed | Security review |

---

## Phase 5: VALIDATION
**Status:** APPROVED (HITM 2026-04-03)

### Alignment Check

| Check | Status | Notes |
|-------|--------|-------|
| Vision → Specs consistent? | PASS | 112 tests cover all 37 TRUG nodes (verified in traceability matrix) |
| Enough detail to code? | PASS | Every test has ID, description, expected result, TRUG node |
| Technology choices verified? | PASS | Catch2 + oxen-libquic loopback proven viable |
| Risks identified? | PASS | See below |
| Architecture delivers specs? | PASS | 11 files + 1 harness + accessor, no over-engineering |
| Execution order defined? | PASS | Unit → Harness → Loopback → Fix → Audit (14 steps) |

### Risks

| Risk | Mitigation |
|------|------------|
| oxen-libquic loopback may not support two endpoints in same process | Test with separate threads + ports. Fallback: fork to separate processes with pipe IPC. |
| MockJobQueue call_get inline behavior may not match real JobQueue (W1) | Verify against oxen-libquic source. This is the #1 risk in the plan. |
| Mock NodeDB may not satisfy all code paths | Start minimal, expand mock as tests reveal requirements |
| Ticker timing tests may be flaky even at 200ms/500ms | Use generous assertion margins (2x expected) |
| Some tests may require additional upstream code changes | Document as findings — each is a PR opportunity |
| Datagram destruction test (9.6) may crash if W6 is a real bug | Run under ASan. A crash IS the test result — it proves the bug. |

---

## Phase 6: CODING
**Status:** NOT STARTED — Phase 5 approved, ready to begin

---

## Phase 7: TESTING
**Status:** NOT STARTED

The tests ARE the deliverable. Phase 7 validates that:
- All 112 tests compile and run
- Unit tests (15) pass on current code
- Loopback tests (97) document which pass and which fail on current code
- Each failure is traced to a specific code issue with TRUG node reference
- Fix commits make each test pass

---

## Phase 8: AUDIT
**Status:** NOT STARTED

Each fix commit gets a security review:
- Does the fix introduce new vulnerabilities?
- Does the fix change wire format or crypto behavior?
- Is the fix minimal (no unnecessary changes)?
- Does the fix have its own test?
- Each AUDIT round fixes ALL findings AND writes tests for uncovered findings.

---

## Phase 9: DEPLOYMENT
**Status:** NOT STARTED

Deliverables:
1. Test suite PR to Xepayac/session-router (our fork)
2. Fix PRs to session-foundation/session-router (upstream)
3. Updated STUDY_session_router_rewrite.md with test results
4. Updated quic_layer.trug.json with findings from test development

---

## Appendix A: Upstream Bugs Found During Analysis

| # | Location | Severity | Description |
|---|----------|----------|-------------|
| B1 | endpoint.cpp:92-97 | MEDIUM | Datagram handler captures `this` without canary — use-after-free on Endpoint destruction during datagram processing. Test 9.6 will verify. |
| B2 | link_manager.cpp:649 | LOW | find_cc legacy path (`lookup_index < 0`): when all forwarded requests fail, `respond()` never called — request hangs forever. Out of QUIC test scope but documented. |

## Appendix B: Insidious Findings (W1-W8)

| # | Finding | Severity | Impact on Tests |
|---|---------|----------|-----------------|
| W1 | call_get from inside router loop must execute inline | CRITICAL | MockJobQueue must replicate. Test 11.4. |
| W2 | on_conn_closed checks both if, not else-if | LOW | Test 6.12 verifies no double-close. |
| W3 | Outbound make_control cross-loop race window | MEDIUM | Test 6.13 verifies pre-establishment safety. |
| W4 | path_build captures remote by value, others use m.conn_rid() | LOW | Test 8.13 verifies captured identity. |
| W5 | Two different control stream creation paths | MEDIUM | Test 8.14 verifies pre-registration works post-establishment. |
| W6 | Datagram handler lacks canary protection | MEDIUM | Test 9.6 — crash = confirmed bug. |
| W7 | close_redundant iterates while triggering async closes | LOW | Test 7.9 verifies iteration safety. |
| W8 | find_cc legacy path leaks requests | LOW | Out of scope — documented in Appendix A as B2. |

## Appendix C: Audit History

| Date | Audit | Scope | Result |
|------|-------|-------|--------|
| 2026-04-03 | Audit 1: Coverage gaps | 85 tests vs 37 TRUG nodes | +14 tests, 3 structural issues |
| 2026-04-03 | Audit 2: Insidious weirdness | Adversarial code review | +7 tests, 2 upstream bugs |
| 2026-04-03 | Audit 3: Structural consolidation | AAA protocol compliance | +6 tests, all phases updated, single source of truth |

---

*Analysis source: quic_layer.trug.json (37 nodes, 38 edges)*
*Supersedes: AAA_1234_quic_transport.md*
