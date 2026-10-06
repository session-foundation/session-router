#pragma once

#include "contact/router_id.hpp"
#include "path/hopid.hpp"
#include "util/time.hpp"

#include <oxenc/bt.h>

namespace srouter
{
    struct ClientIntro
    {
        RouterID relay;
        HopID hop;
        std::chrono::sys_seconds expiry;

        ClientIntro() = default;
        ClientIntro(oxenc::bt_dict_consumer&&);
        ClientIntro(std::string_view buf);

        std::chrono::milliseconds expires_in(sys_ms now = srouter::time_now_ms()) const { return expiry - now; }

        bool is_expired(sys_ms now = srouter::time_now_ms()) const { return expires_in(now) <= 0ms; }

        void bt_encode(oxenc::bt_dict_producer&& subdict) const;

        bool operator==(const ClientIntro& other) const = default;

        std::string to_string() const;
        static constexpr bool to_string_formattable = true;
    };

}  //  namespace srouter
