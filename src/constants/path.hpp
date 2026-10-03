#pragma once

#include "util/time.hpp"

#include <array>
#include <chrono>
#include <cstddef>

namespace srouter::path
{
    /// pad messages to the nearest this many bytes
    inline constexpr std::size_t PAD_SIZE{128};

    /// Number of encryption "frames" inside path builds.  This implicitly defines the maximum
    /// length of a path: shorter path builds still put data in all frames, but frame data beyond
    /// the last hop are random unused data (so that the length of the path build message does not
    /// reveal anything about the total number of hops for the path, and so that the final target
    /// cannot tell how long the path was).
    inline constexpr int BUILD_LENGTH = 8;

    /// Length of each frame of an unauthenticated path build (bare XChaCha20).
    /// Relays that do not advertise path-build authentication still use this size, and a new
    /// relay still accepts it.
    inline constexpr size_t BUILD_FRAME_SIZE = 169;

    /// Length of each frame of an authenticated path build.  The inner record is the same, sealed
    /// with XChaCha20-Poly1305.  The extra 17 bytes are the 16-byte tag plus one length digit,
    /// because the ciphertext crosses 100 bytes.
    inline constexpr size_t BUILD_FRAME_SIZE_MAC = 186;

    /// Lowest relay contact "v" (major, minor, patch) that understands BUILD_FRAME_SIZE_MAC.
    /// This tree used to write 1.1.0.  It now writes 1.1.1.  A hop is new only when its signed
    /// "v" is greater than or equal to 1.1.1.  RelayContact::VERSION (the empty-string key) is
    /// not this value and is not changed.
    inline constexpr std::array<uint8_t, 3> BUILD_FRAME_MAC_VERSION{{1, 1, 1}};

    inline constexpr bool router_version_at_least(
        const std::array<uint8_t, 3>& v, const std::array<uint8_t, 3>& min)
    {
        if (v[0] != min[0])
            return v[0] > min[0];
        if (v[1] != min[1])
            return v[1] > min[1];
        return v[2] >= min[2];
    }

    inline constexpr bool relay_supports_mac_build(const std::array<uint8_t, 3>& v)
    {
        return router_version_at_least(v, BUILD_FRAME_MAC_VERSION);
    }

    /// Max base lifetime of paths.  This is the lifetime of outbound paths, and is the maximum
    /// target lifetime of inbound paths.  Inbound paths also have up some random fuzz added to
    /// this, and so the actual maximum allowed by a relay is be slightly higher than this; see
    /// next two variables.
    inline constexpr std::chrono::seconds MAX_LIFETIME = 20min;

    /// Maximum path expiry randomness: when building paths we add a random value up to this amount
    /// to the path lifetime, and so relays will accept paths of up to MAX_LIFETIME plus this value.
    inline constexpr std::chrono::seconds MAX_LIFETIME_FUZZ = 3min;

    /// The maximum path life accepted by a relay: this is the maximum life plus the maximum amount
    /// of random fuzz.
    inline constexpr std::chrono::seconds MAX_LIFETIME_ACCEPTED = MAX_LIFETIME + MAX_LIFETIME_FUZZ;

    /// The minimum expiry time slots for inbound paths.  See detailed comments in
    /// SessionEndpoint::update_paths().
    inline constexpr auto MAX_LIFETIME_SLOTS = 4;

    static_assert(
        std::chrono::seconds{MAX_LIFETIME} % MAX_LIFETIME_SLOTS == 0s,
        "MAX_LIFETIME_SLOTS must evenly divide MAX_LIFETIME seconds");

    /// How many locations a client contact gets published to.  The contact gets published to the
    /// "closest" [this number] relays, using a metric based on the CC and relay IDs, for short term
    /// redundancy for relays become unreachable or inactive via the Oxen chain.
    ///
    /// (Note that this value cannot be changed without upgrading relays and clients).
    inline constexpr int CC_PUBLISH_LOCATIONS = 4;

    /// after this many ms a path build times out
    inline constexpr auto BUILD_TIMEOUT{10s};

    inline constexpr auto MIN_PATH_BUILD_INTERVAL{500ms};

    inline constexpr auto PATH_BUILD_RATE{100ms};

    /// measure latency every this interval ms
    inline constexpr std::chrono::milliseconds LATENCY_INTERVAL{20s};

    /// if a path is inactive for this amount of time it's dead
    inline constexpr std::chrono::milliseconds ALIVE_TIMEOUT{LATENCY_INTERVAL * 3 / 2};

    /// how big transit hop traffic queues are
    inline constexpr std::size_t TRANSIT_HOP_QUEUE_SIZE{256};

}  // namespace srouter::path
