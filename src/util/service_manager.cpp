#include "service_manager.hpp"

namespace srouter::sys
{
    // The default system-layer manager: a no-op handler that is always available in the core
    // library.  This is what embedded usage gets (it never calls install_native_service_manager()),
    // and the fallback for platforms with no native manager.  Full builds override this pointer via
    // install_native_service_manager().
    static NOP_SystemLayerHandler _nop_manager{};
    I_SystemLayerManager* service_manager = &_nop_manager;

}  // namespace srouter::sys
