#include "service_manager.hpp"

namespace srouter::sys
{
    // This platform has no native service manager, so installing leaves the core default (no-op)
    // handler in place.
    void install_native_service_manager() {}

}  // namespace srouter::sys
