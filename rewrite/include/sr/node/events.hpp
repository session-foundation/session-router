#pragma once

#include <sr/contact/router_id.hpp>
#include <sr/path/path.hpp>

#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

namespace sr::node
{

    // Event system — replaces the "path_died has zero callers" pattern.
    // Components emit events, other components subscribe.

    enum class Event
    {
        PATH_BUILT,
        PATH_DIED,
        PATH_EXPIRED,
        SESSION_ESTABLISHED,
        SESSION_FAILED,
        SESSION_CLOSED,
        CONNECTION_ESTABLISHED,
        CONNECTION_CLOSED,
        BOOTSTRAP_COMPLETE,
        RC_UPDATED,
    };

    using EventData = std::variant<
        std::monostate,
        sr::contact::RouterID,
        size_t  // index or count
        >;

    using EventHandler = std::function<void(Event, const EventData&)>;

    class EventBus
    {
      public:
        // Subscribe to an event
        void on(Event event, EventHandler handler) { _handlers[event].push_back(std::move(handler)); }

        // Emit an event
        void emit(Event event, const EventData& data = {})
        {
            auto it = _handlers.find(event);
            if (it != _handlers.end())
            {
                for (auto& h : it->second)
                    h(event, data);
            }
        }

      private:
        std::unordered_map<Event, std::vector<EventHandler>> _handlers;
    };

}  // namespace sr::node
