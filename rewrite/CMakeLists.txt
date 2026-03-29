cmake_minimum_required(VERSION 3.16)
project(session-router-rewrite VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Strict warnings
add_compile_options(-Wall -Wextra -Werror -Wpedantic)

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.18)

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
target_link_libraries(sr_crypto PUBLIC PkgConfig::SODIUM)

# Contact library (Layer 1)
add_library(sr_contact
    src/contact/router_id.cpp
    src/contact/relay_contact.cpp
    src/contact/nodedb.cpp
)
target_include_directories(sr_contact PUBLIC include)
target_link_libraries(sr_contact PUBLIC sr_crypto)

# Path library (Layer 2)
add_library(sr_path
    src/path/hop.cpp
    src/path/path.cpp
    src/path/onion.cpp
)
target_include_directories(sr_path PUBLIC include)
target_link_libraries(sr_path PUBLIC sr_contact)

# oxen-libquic (pre-built)
set(LIBQUIC_BUILD_DIR "/tmp/oxen-libquic/build" CACHE PATH "Path to oxen-libquic build directory")
set(LIBQUIC_SRC_DIR "/tmp/oxen-libquic" CACHE PATH "Path to oxen-libquic source directory")

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

# Session library (Layer 3)
add_library(sr_session
    src/session/session.cpp
)
target_include_directories(sr_session PUBLIC include)
target_link_libraries(sr_session PUBLIC sr_path)

# Link library (Layer 4)
add_library(sr_link
    src/link/endpoint.cpp
    src/link/manager.cpp
)
target_include_directories(sr_link PUBLIC include)
target_link_libraries(sr_link PUBLIC sr_session oxen-quic oxen-logging spdlog fmt
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

# Main executable
add_executable(session-router src/main.cpp)
target_link_libraries(session-router PRIVATE sr_node)

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
    target_link_libraries(test_session PRIVATE sr_session Catch2::Catch2WithMain)
    add_test(NAME session COMMAND test_session)
endif()
