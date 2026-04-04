cmake_minimum_required(VERSION 3.16)
project(session-router-rewrite VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Strict warnings
add_compile_options(-Wall -Wextra -Werror -Wpedantic)

# ML-KEM placeholder mode (until real implementation linked)
option(SR_MLKEM_PLACEHOLDER "Allow ML-KEM placeholder implementation" ON)
if(SR_MLKEM_PLACEHOLDER)
    add_compile_definitions(SR_MLKEM_PLACEHOLDER_OK)
endif()

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.18)

# Encoding library (BT encode/decode — wraps oxen-encoding)
set(OXENC_DIR "${LIBQUIC_SRC_DIR}/external/oxen-encoding" CACHE PATH "Path to oxen-encoding source")
add_library(sr_encoding
    src/encoding/bt.cpp
)
target_include_directories(sr_encoding PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${OXENC_DIR})
target_link_libraries(sr_encoding PUBLIC PkgConfig::SODIUM)

# Crypto library (Layer 0)
add_library(sr_crypto
    src/crypto/aead.cpp
    src/crypto/dh.cpp
    src/crypto/keys.cpp
    src/crypto/sealed_box.cpp
    src/crypto/blind.cpp
    src/crypto/mlkem.cpp
    src/crypto/session_keys.cpp
)
target_include_directories(sr_crypto PUBLIC include)
target_link_libraries(sr_crypto PUBLIC PkgConfig::SODIUM sr_encoding)

# oxen-libquic paths (needed for oxen-encoding headers in Layer 1)
set(LIBQUIC_BUILD_DIR "/tmp/oxen-libquic/build" CACHE PATH "Path to oxen-libquic build directory")
set(LIBQUIC_SRC_DIR "/tmp/oxen-libquic" CACHE PATH "Path to oxen-libquic source directory")

# Contact library (Layer 1)
add_library(sr_contact
    src/contact/router_id.cpp
    src/contact/relay_contact.cpp
    src/contact/nodedb.cpp
)
target_include_directories(sr_contact PUBLIC include)
target_include_directories(sr_contact PUBLIC
    ${LIBQUIC_SRC_DIR}/external/oxen-encoding)
target_link_libraries(sr_contact PUBLIC sr_crypto)

# Path library (Layer 2)
add_library(sr_path
    src/path/hop.cpp
    src/path/path.cpp
    src/path/onion.cpp
)
target_include_directories(sr_path PUBLIC include)
target_link_libraries(sr_path PUBLIC sr_contact sr_encoding)

# oxen-libquic (pre-built) — optional, only needed for Layer 4+ targets
option(SR_WITH_QUIC "Build QUIC transport layer (requires oxen-libquic)" ON)
if(SR_WITH_QUIC AND EXISTS "${LIBQUIC_BUILD_DIR}/src/libquic.a")
    set(SR_HAVE_QUIC TRUE)
    add_library(oxen-quic STATIC IMPORTED)
    set_target_properties(oxen-quic PROPERTIES
        IMPORTED_LOCATION "${LIBQUIC_BUILD_DIR}/src/libquic.a"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBQUIC_SRC_DIR}/include;${LIBQUIC_BUILD_DIR}/static-deps/include;${LIBQUIC_SRC_DIR}/external/oxen-encoding;${LIBQUIC_SRC_DIR}/external/oxen-logging/include;${LIBQUIC_BUILD_DIR}/external/oxen-logging/generated;${LIBQUIC_SRC_DIR}/external/oxen-logging/fmt/include;${LIBQUIC_SRC_DIR}/external/oxen-logging/spdlog/include"
    )

    # oxen-logging and its deps (required by libquic headers)
    add_library(oxen-logging STATIC IMPORTED)
    set_target_properties(oxen-logging PROPERTIES IMPORTED_LOCATION "${LIBQUIC_BUILD_DIR}/external/oxen-logging/liboxen-logging.a")
    add_library(spdlog STATIC IMPORTED)
    set_target_properties(spdlog PROPERTIES IMPORTED_LOCATION "${LIBQUIC_BUILD_DIR}/external/oxen-logging/spdlog/libspdlog.a")
    add_library(fmt STATIC IMPORTED)
    set_target_properties(fmt PROPERTIES IMPORTED_LOCATION "${LIBQUIC_BUILD_DIR}/external/oxen-logging/fmt/libfmt.a")

    # ngtcp2 dependencies
    add_library(ngtcp2 STATIC IMPORTED)
    set_target_properties(ngtcp2 PROPERTIES IMPORTED_LOCATION "${LIBQUIC_BUILD_DIR}/static-deps/lib/libngtcp2.a")
    add_library(ngtcp2_crypto STATIC IMPORTED)
    set_target_properties(ngtcp2_crypto PROPERTIES IMPORTED_LOCATION "${LIBQUIC_BUILD_DIR}/static-deps/lib/libngtcp2_crypto_gnutls.a")

    pkg_check_modules(GNUTLS REQUIRED IMPORTED_TARGET gnutls)
    pkg_check_modules(NETTLE REQUIRED IMPORTED_TARGET nettle)
    pkg_check_modules(HOGWEED REQUIRED IMPORTED_TARGET hogweed)
    pkg_check_modules(LIBEVENT REQUIRED IMPORTED_TARGET libevent_core)
    pkg_check_modules(LIBEVENT_PT REQUIRED IMPORTED_TARGET libevent_pthreads)
else()
    set(SR_HAVE_QUIC FALSE)
    message(STATUS "oxen-libquic not found — skipping QUIC transport targets (unit tests still available)")
endif()

# Session library (Layer 3)
add_library(sr_session
    src/session/session.cpp
)
target_include_directories(sr_session PUBLIC include)
target_link_libraries(sr_session PUBLIC sr_path sr_encoding)

# relay_conn library (no QUIC dependency — pure data structure)
add_library(sr_relay_conn
    src/link/relay_conn.cpp
)
target_include_directories(sr_relay_conn PUBLIC include)
target_link_libraries(sr_relay_conn PUBLIC sr_crypto)

# Layers 4-5 and main executable require QUIC
if(SR_HAVE_QUIC)
    # Link library (Layer 4)
    add_library(sr_link
        src/link/endpoint.cpp
        src/link/manager.cpp
        src/link/relay_conn.cpp
    )
    target_include_directories(sr_link PUBLIC include)
    target_link_libraries(sr_link PUBLIC sr_session sr_relay_conn oxen-quic oxen-logging spdlog fmt
        ngtcp2 ngtcp2_crypto PkgConfig::GNUTLS PkgConfig::NETTLE PkgConfig::HOGWEED
        PkgConfig::LIBEVENT PkgConfig::LIBEVENT_PT)

    # Node library (Layer 5)
    add_library(sr_node
        src/node/config.cpp
        src/node/tun.cpp
        src/node/dns.cpp
        src/node/node.cpp
    )
    target_include_directories(sr_node PUBLIC include)
    target_link_libraries(sr_node PUBLIC sr_link)

    # Exit library (v1.1 feature)
    add_library(sr_exit
        src/exit/exit_handler.cpp
    )
    target_include_directories(sr_exit PUBLIC include)
    target_link_libraries(sr_exit PUBLIC sr_node)

    # Main executable
    add_executable(session-router src/main.cpp)
    target_link_libraries(session-router PRIVATE sr_node)
endif()

# Tests
option(SR_TESTS "Build tests" ON)
if(SR_TESTS)
    enable_testing()
    find_package(Catch2 3 QUIET)
    if(NOT Catch2_FOUND)
        include(FetchContent)
        FetchContent_Declare(Catch2
            GIT_REPOSITORY https://github.com/catchorg/Catch2.git
            GIT_TAG v3.5.2
        )
        FetchContent_MakeAvailable(Catch2)
    endif()

    add_executable(test_crypto
        test/test_aead.cpp
        test/test_dh.cpp
        test/test_keys.cpp
        test/test_sealed_box.cpp
        test/test_blind.cpp
        test/test_session_keys.cpp
    )
    target_link_libraries(test_crypto PRIVATE sr_crypto Catch2::Catch2WithMain)
    add_test(NAME crypto COMMAND test_crypto)

    add_executable(test_contact
        test/test_router_id.cpp
        test/test_relay_contact.cpp
        test/test_nodedb.cpp
    )
    target_link_libraries(test_contact PRIVATE sr_contact Catch2::Catch2WithMain)
    add_test(NAME contact COMMAND test_contact)

    add_executable(test_path
        test/test_path.cpp
        test/test_onion.cpp
    )
    target_link_libraries(test_path PRIVATE sr_path Catch2::Catch2WithMain)
    add_test(NAME path COMMAND test_path)

    add_executable(test_session
        test/test_session.cpp
    )
    target_link_libraries(test_session PRIVATE sr_session sr_encoding Catch2::Catch2WithMain)
    add_test(NAME session COMMAND test_session)

    # QUIC transport test suite — Category 1: relay_conn unit tests
    # No QUIC dependency — builds without oxen-libquic
    add_executable(test_relay_conn
        test/test_relay_conn.cpp
    )
    target_link_libraries(test_relay_conn PRIVATE sr_relay_conn Catch2::Catch2WithMain)
    add_test(NAME relay_conn COMMAND test_relay_conn)

    # Tests that require QUIC but use loopback (Categories 2-11)
    if(SR_HAVE_QUIC)
        add_executable(test_quic_maps
            test/test_quic_maps.cpp
        )
        target_link_libraries(test_quic_maps PRIVATE sr_link sr_relay_conn Catch2::Catch2WithMain)
        add_test(NAME quic_maps COMMAND test_quic_maps)

        add_executable(test_quic_lifecycle
            test/test_quic_lifecycle.cpp
        )
        target_link_libraries(test_quic_lifecycle PRIVATE sr_link sr_relay_conn Catch2::Catch2WithMain)
        add_test(NAME quic_lifecycle COMMAND test_quic_lifecycle)

        add_executable(test_quic_keys
            test/test_quic_keys.cpp
        )
        target_link_libraries(test_quic_keys PRIVATE sr_link sr_relay_conn Catch2::Catch2WithMain)
        add_test(NAME quic_keys COMMAND test_quic_keys)

        add_executable(test_quic_dedup
            test/test_quic_dedup.cpp
        )
        target_link_libraries(test_quic_dedup PRIVATE sr_link sr_relay_conn Catch2::Catch2WithMain)
        add_test(NAME quic_dedup COMMAND test_quic_dedup)

        add_executable(test_quic_alpn
            test/test_quic_alpn.cpp
        )
        target_link_libraries(test_quic_alpn PRIVATE sr_link sr_relay_conn Catch2::Catch2WithMain)
        add_test(NAME quic_alpn COMMAND test_quic_alpn)

        add_executable(test_quic_commands
            test/test_quic_commands.cpp
        )
        target_link_libraries(test_quic_commands PRIVATE sr_link sr_relay_conn Catch2::Catch2WithMain)
        add_test(NAME quic_commands COMMAND test_quic_commands)

        add_executable(test_quic_shutdown
            test/test_quic_shutdown.cpp
        )
        target_link_libraries(test_quic_shutdown PRIVATE sr_link sr_relay_conn Catch2::Catch2WithMain)
        add_test(NAME quic_shutdown COMMAND test_quic_shutdown)

        add_executable(test_quic_tickers
            test/test_quic_tickers.cpp
        )
        target_link_libraries(test_quic_tickers PRIVATE sr_link sr_relay_conn Catch2::Catch2WithMain)
        add_test(NAME quic_tickers COMMAND test_quic_tickers)

        add_executable(test_quic_0rtt
            test/test_quic_0rtt.cpp
        )
        target_link_libraries(test_quic_0rtt PRIVATE sr_link sr_relay_conn Catch2::Catch2WithMain)
        add_test(NAME quic_0rtt COMMAND test_quic_0rtt)

        add_executable(test_quic_threading
            test/test_quic_threading.cpp
        )
        target_link_libraries(test_quic_threading PRIVATE sr_link sr_relay_conn Catch2::Catch2WithMain)
        add_test(NAME quic_threading COMMAND test_quic_threading)
    endif()

    add_executable(test_bt
        test/test_bt.cpp
    )
    target_link_libraries(test_bt PRIVATE sr_contact sr_encoding Catch2::Catch2WithMain)
    add_test(NAME bt COMMAND test_bt)

    add_executable(test_wire_compat
        test/test_wire_compat.cpp
    )
    target_link_libraries(test_wire_compat PRIVATE sr_session sr_encoding Catch2::Catch2WithMain)
    add_test(NAME wire_compat COMMAND test_wire_compat)

    # Tests that require QUIC (Layer 4+)
    if(SR_HAVE_QUIC)
        add_executable(test_link
            test/test_manager.cpp
        )
        target_link_libraries(test_link PRIVATE sr_link Catch2::Catch2WithMain)
        add_test(NAME link COMMAND test_link)

        add_executable(test_exit
            test/test_exit.cpp
        )
        target_link_libraries(test_exit PRIVATE sr_exit Catch2::Catch2WithMain)
        add_test(NAME exit COMMAND test_exit)

        add_executable(test_node
            test/test_config.cpp
            test/test_tun.cpp
            test/test_dns.cpp
            test/test_events.cpp
        )
        target_link_libraries(test_node PRIVATE sr_node Catch2::Catch2WithMain)
        add_test(NAME node COMMAND test_node)
    endif()
endif()
