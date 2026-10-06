#include "full/init.hpp"

#include "config/config.hpp"
#include "net/platform.hpp"
#include "util/service_manager.hpp"
#include "vpn/platform.hpp"

namespace srouter::full
{
    void initialize()
    {
        sys::install_native_service_manager();
        config::install_full_config_validators();
        install_rpc_backend();
        net::native_net_platform = net::Platform::Default_ptr();
        vpn::make_native_platform = &vpn::MakeNativePlatform;
    }

}  // namespace srouter::full
