#pragma once

#include <sr/contact/router_id.hpp>
#include <sr/crypto/types.hpp>

#include <array>
#include <chrono>
#include <cstdint>

namespace sr::path {

// HopID is a random 16-byte identifier for each direction of a hop.
using HopID = sr::crypto::Bytes<16>;

HopID random_hop_id();

// A single hop in a path, from the client's perspective.
// The client knows the full chain of hops and their shared secrets.
struct Hop {
    sr::contact::RouterID router_id;
    sr::crypto::SharedSecret shared_secret;
    sr::crypto::XorNonce xor_nonce;
    HopID rxid;  // ID this hop uses for receiving
    HopID txid;  // ID this hop uses for forwarding
};

// A transit hop, from a relay's perspective.
// The relay knows only its own hop, not the full path.
struct TransitHop {
    HopID rxid;
    HopID txid;
    sr::contact::RouterID upstream;
    sr::crypto::SharedSecret shared_secret;
    sr::crypto::XorNonce xor_nonce;
    std::chrono::steady_clock::time_point expires;
};

}  // namespace sr::path
