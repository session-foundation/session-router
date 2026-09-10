include(Version)

# Add an internal Session Router static library target, enables LTO (if enabled) on the target,
# and links it to the common session-router-base interface.
# Invoke with the target/library name (e.g. "session-router-foo") and list of source files, e.g.
#     session_router_add_library(session-router-foo foo/source1.cpp foo/source2.cpp)
function(session_router_add_library libname)
    add_library(${libname} STATIC ${ARGN})
    target_link_libraries(${libname} PUBLIC session-router-base PRIVATE session-router-base-internal)
    target_include_directories(${libname} PUBLIC ${CMAKE_CURRENT_LIST_DIR})
    enable_lto(${libname})
endfunction()

# Link the given internal (static) component libraries into `target`.
#
# For a SHARED aggregate the components are whole-archived (all object files included, not just the
# referenced ones) so the resulting .so is self-complete -- nothing in the aggregate's own translation
# unit references the component objects, so otherwise the linker would prune them.  This uses the
# portable $<LINK_LIBRARY:WHOLE_ARCHIVE> on CMake >= 3.24 (which maps to --whole-archive / -force_load /
# /WHOLEARCHIVE per linker), falling back to the GNU-ld --whole-archive flag on older CMake (so pre-3.24
# shared builds require a GNU-compatible linker).
#
# For a STATIC aggregate whole-archiving is neither needed nor wanted: consumers cherry-pick from the
# component archives at their final link.  (It must be avoided here -- for a static library the PRIVATE
# link items propagate to every executable that links the aggregate, which would both bloat those
# executables and put the WHOLE_ARCHIVE feature on their link lines where it collides with the same
# components arriving via ordinary transitive links.)
function(srouter_link_whole target)
  if(NOT BUILD_SHARED_LIBS)
    target_link_libraries(${target} PRIVATE ${ARGN})
  elseif(CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
    target_link_libraries(${target} PRIVATE "$<LINK_LIBRARY:WHOLE_ARCHIVE,${ARGN}>")
  else()
    target_link_libraries(${target} PRIVATE -Wl,--whole-archive ${ARGN} -Wl,--no-whole-archive)
  endif()
endfunction()

session_router_add_library(session-router-cryptography
  crypto/crypto.cpp
  crypto/key_manager.cpp
  crypto/keys.cpp
  crypto/session_keys.cpp
)

if(SROUTER_FULL)
  session_router_add_library(session-router-exit-auth
    auth/auth.cpp
    auth/file.cpp
    auth/session.cpp
  )
endif()

# Functional objects use by session-router-core and other libraries
# needed by vpn/ router/ rpc/ handlers/ net/ link/
session_router_add_library(session-router-core-utils
  handlers/session.cpp

  messages/common.cpp
)

session_router_add_library(session-router-core
  context.cpp
  
  link/connection.cpp
  link/endpoint.cpp
  link/link_manager.cpp

  router/router.cpp

  session/session.cpp
  session/tcp_tunnel.cpp
)

if (SROUTER_FULL)
  session_router_add_library(session-router-rpc
    rpc/json_binary_proxy.cpp
    rpc/json_conversions.cpp
    rpc/config_validation.cpp
    rpc/oxend_rpc.cpp
    rpc/rpc_request_parser.cpp
    rpc/rpc_server.cpp
  )
endif()

if(SROUTER_FULL)
  # Full (non-embedded) application support: the single srouter::full::initialize() entry point that
  # installs full-only overrides (native service manager, stricter config validators, ...) over their
  # core defaults.  A full application must call it early in main().  This is also where the phase-4
  # full-backend factory will live.
  # Full-only concrete implementations behind the core interfaces (constructed via the backend
  # hooks), plus the srouter::full::initialize() entry point.  Relocated here out of the core
  # libraries so the core stays free of the platform/vpn layer.
  session_router_add_library(session-router-full
    full/init.cpp
    full/rpc_backend.cpp

    handlers/tun.cpp
    vpn/egres_packet_router.cpp
    router/route_poker.cpp
    consensus/reachability_testing.cpp
  )
  target_link_libraries(session-router-full PRIVATE
    session-router-core session-router-dns session-router-exit-auth
    session-router-platform session-router-rpc session-router-base-full)
endif()

# config, crypto, timeplace, nodedb, net, router
session_router_add_library(session-router-utils
  ${CMAKE_CURRENT_BINARY_DIR}/constants/version.cpp
  util/cleared.cpp
  util/file.cpp
  util/logging.cpp
  util/service_manager.cpp
  util/str.cpp
  util/thread/queue_manager.cpp  
  util/thread/threading.cpp
  util/time.cpp
  util/zstd.cpp
)

add_dependencies(session-router-utils genversion)

session_router_add_library(session-router-contact
  contact/client_contact.cpp
  contact/client_intro.cpp
  contact/contactdb.cpp
  contact/relay_contact.cpp
  contact/router_id.cpp
  contact/sns.cpp
)

# Network interface files used for mediating ip traffic
session_router_add_library(session-router-ip
  net/ip_packet.cpp
  net/policy.cpp
)

# Addressing and event loop files used by session-router-core and other libraries
# needed by rpc/ link/ config/ path/ dht/
session_router_add_library(session-router-addressing
  address/address.cpp
  address/ip_range.cpp

  ev/fd_poller.cpp
  ev/tcp.cpp
)

session_router_add_library(session-router-dns-data
  dns/srv_data.cpp
)

if (SROUTER_FULL)
  # session-router-platform holds all platform specific code
  session_router_add_library(session-router-platform
    vpn/packet_router.cpp
    vpn/platform.cpp
  )

  if (ANDROID)
    target_sources(session-router-platform PRIVATE android/ifaddrs.c util/nop_service_manager.cpp)
  endif()

  if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    target_sources(session-router-platform PRIVATE linux/dbus.cpp)
    if(WITH_SYSTEMD)
      target_sources(session-router-platform PRIVATE linux/sd_service_manager.cpp)
    else()
      target_sources(session-router-platform PRIVATE util/nop_service_manager.cpp)
    endif()
  endif()

  if (WIN32)
    target_sources(session-router-platform PRIVATE
      net/win32.cpp
      vpn/win32.cpp
      win32/service_manager.cpp
      win32/exec.cpp
      win32/dll.cpp
      win32/exception.cpp
      win32/wintun.cpp
      win32/windivert.cpp)
    target_include_directories(session-router-platform PRIVATE ${CMAKE_BINARY_DIR}/wintun/include/ ${CMAKE_BINARY_DIR}/WinDivert-${WINDIVERT_VERSION}/include/)
  else()
    target_sources(session-router-platform PRIVATE
      net/posix.cpp)
  endif()

  if(APPLE)
    add_subdirectory(apple)
    target_sources(session-router-platform PRIVATE util/nop_service_manager.cpp)
  endif()

  # session-router-dns is the (full-only) dns parsing and hooking library that we use to parse,
  # modify and reconstitute dns wire proto, dns queries and RR.  It is kept separate from the core
  # session-router-dns-data (which is just the srv_data stub) so that libunbound stays out of core.
  session_router_add_library(session-router-dns
    dns/encode.cpp
    dns/handler.cpp
    dns/listener.cpp
    dns/message.cpp
    dns/platform.cpp
    dns/question.cpp
    dns/rr.cpp
    dns/unbound.cpp
  )

  # platform specific bits and bobs for setting dns
  if(WITH_SYSTEMD)
    target_sources(session-router-dns PRIVATE dns/nm_platform.cpp dns/sd_platform.cpp)
  endif()
  target_link_libraries(session-router-dns
    PUBLIC session-router-dns-data session-router-platform session-router-base-full
    PRIVATE sessiondep::libevent_core)
endif()

# session-router-nodedb holds all types and logic for storing parsing and constructing
# nodedb data published to the network and versions of it stored locally
session_router_add_library(session-router-nodedb
  nodedb.cpp
  profiling.cpp # path, router, service::endpoint
)

set(BOOTSTRAP_FALLBACKS)
foreach(bs IN ITEMS MAINNET TESTNET)
  if(SROUTER_BOOTSTRAP_FALLBACK_${bs})
    message(STATUS "Building with ${bs} fallback bootstrap path \"${SROUTER_BOOTSTRAP_FALLBACK_${bs}}\"")
    file(READ "${SROUTER_BOOTSTRAP_FALLBACK_${bs}}" bs_data HEX)
    string(REGEX REPLACE "([0-9a-f][0-9a-f])" "\\\\x\\1" bs_data "${bs_data}")
    set(BOOTSTRAP_FALLBACKS "${BOOTSTRAP_FALLBACKS}        {NetID::${bs}, \"${bs_data}\"sv},\n")
  endif()
endforeach()
configure_file("nodedb-bootstraps.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/nodedb-bootstraps.cpp" @ONLY)
target_sources(session-router-nodedb PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/nodedb-bootstraps.cpp")

# session-router-conf is for all configuration types and parsers
session_router_add_library(session-router-conf
  config/config.cpp
  config/definition.cpp
  config/ini.cpp
)

# All path objects; link directly to session-router-core
session_router_add_library(session-router-path
  path/build_stats.cpp
  path/hopid.cpp
  path/path.cpp
  path/path_context.cpp
  path/path_handler.cpp
  path/transit_hop.cpp
)

if(SROUTER_DEBUG_PATH_SEED)
  target_compile_definitions(session-router-nodedb PRIVATE SROUTER_DEBUG_PATH_SEED)
  target_compile_definitions(session-router-conf PRIVATE SROUTER_DEBUG_PATH_SEED)
  target_compile_definitions(session-router-path PRIVATE SROUTER_DEBUG_PATH_SEED)
endif()

# Link libraries to their internals
target_link_libraries(session-router-nodedb PUBLIC session-router-addressing session-router-cryptography)
target_link_libraries(session-router-contact PUBLIC session-router-dns-data)
if(SROUTER_FULL)
  target_link_libraries(session-router-rpc PUBLIC session-router-contact session-router-conf session-router-base-full)
endif()
target_link_libraries(session-router-addressing
    PUBLIC
    session-router-utils
    session-router-cryptography
    session-router-contact
    session-router-ip
    PRIVATE
    sessiondep::libevent_core
)
target_link_libraries(session-router-conf PUBLIC session-router-cryptography session-router-addressing)
if(SROUTER_FULL)
  target_link_libraries(session-router-platform PUBLIC session-router-cryptography session-router-ip)
endif()
target_link_libraries(session-router-dns-data
  PUBLIC
  session-router-cryptography
  session-router-conf
)

target_link_libraries(session-router-path
  PUBLIC
  session-router-addressing
)

target_link_libraries(session-router-core-utils 
  PUBLIC
  session-router-conf
  session-router-dns-data
)

target_link_libraries(session-router-cryptography
  PRIVATE
  mlkem_native::mlkem768
  PUBLIC
  session-router-libcrypt
)

if(SROUTER_FULL)
  target_link_libraries(session-router-exit-auth PUBLIC session-router-core-utils session-router-cryptography)
endif()

target_link_libraries(session-router-utils
  PUBLIC
  session-router-cryptography
  PRIVATE
  sessiondep::libzstd
)

target_link_libraries(session-router-core 
  PUBLIC 
  session-router-core-utils
  session-router-nodedb
  session-router-path
  PRIVATE
  sessiondep::libevent_core
)


target_link_libraries(session-router-base 
  INTERFACE 

  Threads::Threads

  oxenc::oxenc 
  oxen::logging 
  
  sessiondep::libsodium
)





# Core library (libsessionrouter-core.so): the embedded API plus the core component libraries and no
# more.  This is what an embedded consumer -- e.g. libsession-util built with -DSROUTER_FULL=OFF --
# links against; it has no dependency on oxenmq/libunbound or the rpc/platform layer.
add_library(libsessionrouter-core session_router.cpp)
srouter_link_whole(libsessionrouter-core
  session-router-addressing
  session-router-conf
  session-router-contact
  session-router-core
  session-router-core-utils
  session-router-cryptography
  session-router-dns-data
  session-router-ip
  session-router-nodedb
  session-router-path
  session-router-utils)
target_link_libraries(libsessionrouter-core PUBLIC session-router-base)
target_include_directories(libsessionrouter-core PRIVATE ${CMAKE_CURRENT_LIST_DIR})
set_target_properties(libsessionrouter-core PROPERTIES OUTPUT_NAME sessionrouter-core)
add_library(session-router::core ALIAS libsessionrouter-core)

# Full library (libsessionrouter.so): the full-only component libraries layered on top of, and linking
# to, the core library.  This is what the daemon (and any full client/relay application) links.
if(SROUTER_FULL)
  add_library(libsessionrouter full/lib.cpp)
  srouter_link_whole(libsessionrouter
    session-router-full
    session-router-rpc
    session-router-platform
    session-router-exit-auth
    session-router-dns)
  target_link_libraries(libsessionrouter PUBLIC libsessionrouter-core PRIVATE session-router-base-full)
  set_target_properties(libsessionrouter PROPERTIES OUTPUT_NAME sessionrouter)
  add_library(session-router::full ALIAS libsessionrouter)
  add_library(session-router::libsessionrouter ALIAS libsessionrouter)  # backwards-compat alias
  if(WIN32)
    target_link_libraries(libsessionrouter PUBLIC ws2_32 iphlpapi -fstack-protector)
  endif()
endif()

if(BUILD_SHARED_LIBS AND SROUTER_VERSION_SO)
  set(_srtr_libs libsessionrouter-core)
  if(SROUTER_FULL)
    list(APPEND _srtr_libs libsessionrouter)
  endif()
  set_target_properties(${_srtr_libs} PROPERTIES
    VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}"
    SOVERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")
endif()

if(NOT APPLE)
  if(WIN32)
    set(_srtr_lib_dest bin)
    set(_srtr_lib_kind RUNTIME)
  else()
    include(GNUInstallDirs)
    set(_srtr_lib_dest ${CMAKE_INSTALL_LIBDIR})
    set(_srtr_lib_kind LIBRARY)
  endif()
  install(TARGETS libsessionrouter-core ${_srtr_lib_kind} DESTINATION ${_srtr_lib_dest}
    COMPONENT libsessionrouter-core)
  if(SROUTER_FULL)
    install(TARGETS libsessionrouter ${_srtr_lib_kind} DESTINATION ${_srtr_lib_dest}
      COMPONENT libsessionrouter)
  endif()
endif()

file(GLOB_RECURSE docs_SRC */*.hpp *.hpp)
set(DOCS_SRC ${docs_SRC} PARENT_SCOPE)
