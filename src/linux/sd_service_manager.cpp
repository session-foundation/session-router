#include "router/router.hpp"
#include "util/logging.hpp"
#include "util/service_manager.hpp"

#include <session/router_context.hpp>
#include <systemd/sd-daemon.h>

#include <cassert>

namespace srouter::sys
{
    class SD_Manager : public I_SystemLayerManager
    {
        srouter::sys::ServiceState m_State{ServiceState::Initial};

      public:
        /// change our state and report it to the system layer
        void we_changed_our_state(ServiceState st) override
        {
            m_State = st;
            report_changed_state();
        }

        void report_changed_state() override
        {
            if (m_State == ServiceState::Running)
            {
                ::sd_notify(0, "READY=1");
                return;
            }
            if (m_State == ServiceState::Stopping)
            {
                ::sd_notify(0, "STOPPING=1");
                return;
            }
        }

        void report_periodic_stats(const std::string& stats) override
        {
            auto status = fmt::format("WATCHDOG=1\nSTATUS={}", stats);
            ::sd_notify(0, status.c_str());
        }

        void system_changed_our_state(ServiceState) override
        {
            // not applicable on systemd
        }
    };

    SD_Manager _manager{};

    void install_native_service_manager() { service_manager = &_manager; }

}  // namespace srouter::sys
