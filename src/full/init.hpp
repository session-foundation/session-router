#pragma once

namespace srouter::full
{
    // Full (non-embedded) application setup.  Installs the full library's overrides -- the native
    // service manager, stricter config validators, and (in future) other full-only hooks -- over the
    // no-op/lightweight defaults that the core library provides.
    //
    // A full application (e.g. the session-router daemon) MUST call this exactly once, early in
    // main(), before it loads any config or constructs a Context.  It is deliberately a plain call
    // rather than static-init registration: the core defaults are dynamically initialised, so a
    // static-init override would race with them across translation units; running here, after all
    // static initialisation, is deterministic.
    void initialize();

    // Installs the rpc/oxend/omq/reachability construction hooks (RpcBackendHooks) so Router can
    // build those full-only objects.  Implementation detail of initialize(); not called directly.
    void install_rpc_backend();

}  // namespace srouter::full
