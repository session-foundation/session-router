#pragma once

// Re-export BT encoding utilities from sr::encoding.
// This header exists for backward compatibility — new code should
// include <encoding/bt.hpp> directly.

#include <encoding/bt.hpp>

#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sr::bt
{

    using namespace sr::encoding;

}  // namespace sr::bt
