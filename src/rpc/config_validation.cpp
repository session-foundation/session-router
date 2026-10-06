#include "config/config.hpp"

#include <oxenmq/address.h>

namespace srouter::config
{
    // Strict validation of the [oxend]:rpc address: constructing an oxenmq::address throws if the
    // value is malformed.  This lives in the full (rpc) library so that oxenmq is not a dependency of
    // the core config library; core falls back to a cheap scheme check (see config.cpp).
    static void validate_oxend_rpc_addr_full(const std::string& arg) { oxenmq::address{arg}; }

    void install_full_config_validators() { oxend_rpc_addr_validator = &validate_oxend_rpc_addr_full; }

}  // namespace srouter::config
