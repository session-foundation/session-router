#pragma once

namespace srouter::consensus
{
    // Core-side interface for reachability (service-node uptime) testing.  Router holds and drives an
    // IReachability; the concrete implementation (reachability_testing, a relay-only full component)
    // is constructed via the full-only seam.  In embedded/core-only builds Router never constructs one
    // (the pointer stays null), so core references only this interface.
    struct IReachability
    {
        virtual ~IReachability() = default;

        // Start/stop the reachability testing timers.
        virtual void start() = 0;
        virtual void stop() = 0;

        // Called when this router receives an incoming ping test request.
        virtual void incoming_ping() = 0;
    };

}  // namespace srouter::consensus
