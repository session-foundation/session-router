#pragma once

#include <string>

namespace srouter
{
    struct Context;
}

namespace srouter::sys
{

    // what state Session Router will report we are in to the system layer
    enum class ServiceState
    {
        Initial,
        Starting,
        Running,
        Stopping,
        Stopped,
        HardStop,
        Failed,
    };

    /// interface type for interacting with the os dependant system layer
    class I_SystemLayerManager
    {
      protected:
        bool m_disable{false};
        srouter::Context* m_Context{nullptr};

        /// change our state and report it to the system layer
        virtual void we_changed_our_state(ServiceState st) = 0;

      public:
        virtual ~I_SystemLayerManager() = default;

        /// disable all reporting to system layer
        inline void disable() { m_disable = true; }

        /// give our current Session Router context to the system layer manager
        inline void give_context(srouter::Context* ctx) { m_Context = ctx; }

        /// system told us to enter this state
        virtual void system_changed_our_state(ServiceState st) = 0;

        /// report our current state to the system layer
        virtual void report_changed_state() = 0;

        /// report our stats on each timer tick
        virtual void report_periodic_stats([[maybe_unused]] const std::string& stats) {};

        void starting()
        {
            if (m_disable)
                return;
            we_changed_our_state(ServiceState::Starting);
        }

        void ready()
        {
            if (m_disable)
                return;
            we_changed_our_state(ServiceState::Running);
        }

        void stopping()
        {
            if (m_disable)
                return;
            we_changed_our_state(ServiceState::Stopping);
        }

        void stopped()
        {
            if (m_disable)
                return;
            we_changed_our_state(ServiceState::Stopped);
        }

        void failed()
        {
            if (m_disable)
                return;
            we_changed_our_state(ServiceState::Failed);
        }
    };

    // Global system-layer manager.  Defaults to a no-op handler (used for embedded usage and for
    // platforms without a native service manager); full builds install a native implementation via
    // install_native_service_manager().
    extern I_SystemLayerManager* service_manager;

    // Installs the platform's native service manager into the `service_manager` global, replacing the
    // default no-op handler.  Provided by the full platform library (a no-op on platforms without a
    // native service manager).  Must be called before the service manager is first used, i.e. by the
    // daemon before it constructs the Context.
    void install_native_service_manager();

    class NOP_SystemLayerHandler : public I_SystemLayerManager
    {
      protected:
        void we_changed_our_state(ServiceState) override {}

      public:
        void report_changed_state() override {};
        void system_changed_our_state(ServiceState) override{};
    };
}  // namespace srouter::sys
