# Session Router — Clean Architecture Rewrite

A clean C++20 implementation of the LLARP onion routing protocol, wire-compatible
with [session-foundation/session-router](https://github.com/session-foundation/session-router).

## What It Is

A 6-layer implementation of the Session Router protocol with zero circular
dependencies, full test coverage on crypto and protocol layers, and a clean
separation between transport, routing, and application logic.

Same wire format, same crypto (libsodium), same QUIC transport (oxen-libquic).
An existing session-router node cannot tell the difference.

## Architecture

```
Layer 0: Crypto     — Pure functions. libsodium only.
Layer 1: Contact    — RouterID, RelayContact, NodeDB.
Layer 2: Path       — Onion construction and peeling.
Layer 3: Session    — E2E encrypted channels (1.1+ only).
Layer 4: Link       — QUIC transport via oxen-libquic.
Layer 5: Node       — TUN device, DNS, config, tick loop.
```

## Prerequisites

- Linux (x86_64)
- CMake >= 3.16
- GCC 12+ or Clang 15+ (C++20 required)
- libsodium >= 1.0.18
- libgnutls
- libevent >= 2.1
- libnettle
- oxen-libquic (built from source)

```bash
sudo apt install -y cmake g++ libsodium-dev libgnutls28-dev libevent-dev pkg-config
```

## Building

```bash
# 1. Build oxen-libquic (one-time)
git clone https://github.com/session-foundation/libquic.git /tmp/oxen-libquic
cd /tmp/oxen-libquic && git submodule update --init --recursive
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
    -DCMAKE_MODULE_PATH=/tmp/oxen-libquic/cmake
make -j$(nproc)

# 2. Build session-router
mkdir -p /path/to/rewrite/build && cd /path/to/rewrite/build
cmake -S /path/to/rewrite -B . -DCMAKE_BUILD_TYPE=Debug
make -j$(nproc)
```

## Running Tests

```bash
cd build
ctest --output-on-failure
# Or individually:
./test_crypto
./test_contact
./test_path
./test_session
./test_link
./test_node
./test_bt
```

## Running

```bash
# Client mode (needs root for TUN device)
sudo ./session-router --config session-router.ini

# Relay mode
sudo ./session-router --config relay.ini --relay
```

## Configuration

INI format. Example:

```ini
[router]
data-dir = ~/.session-router
is-relay = false

[network]
port = 1090

[tun]
name = sr0
ip = 10.0.0.1
netmask = 16

[dns]
bind = 127.0.0.1:1053
upstream = 1.1.1.1

[paths]
hops = 3
target = 6

[bootstrap]
file = /path/to/bootstrap.signed
```

## Test Coverage

| Layer | Cases | Assertions |
|-------|-------|------------|
| Crypto | 33 | 48 |
| Contact | 19 | 43 |
| Path | 10 | 19 |
| Session | 7 | 17 |
| Link | 9 | 8 |
| Node | 22 | 45 |
| BT | 5 | 13 |
| **Total** | **105** | **193** |

## License

GPL-3.0 (derived from session-foundation/session-router)
