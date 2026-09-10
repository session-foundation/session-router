message(STATUS "Checking submodules")
check_submodule(CLI11)
check_submodule(nlohmann)
check_submodule(oxen-libquic)
check_submodule(oxen-mq)
check_submodule(pybind11)
check_submodule(sqlite_orm)
check_submodule(mlkem-native)

if(NOT TARGET oxenc::oxenc)
    sessiondep_or_submodule(liboxenc 1.5.0 oxen-libquic/external/oxen-encoding oxenc::oxenc)
endif()

# oxen::logging (with fmt & spdlog):
include(oxen-libquic/external/oxen-logging/cmake/load.cmake)

if(SROUTER_FULL)
    sessiondep_or_submodule(liboxenmq 1.3 oxen-mq oxenmq::oxenmq)
endif()

set(JSON_BuildTests OFF CACHE INTERNAL "")
set(JSON_Install OFF CACHE INTERNAL "")
if(NOT TARGET nlohmann_json::nlohmann_json)
    sessiondep_or_submodule(nlohmann_json 3.7.0 nlohmann nlohmann_json::nlohmann_json)
endif()


if(SROUTER_HIVE)
  add_subdirectory(pybind11 EXCLUDE_FROM_ALL)
endif()


sessiondep_or_submodule(CLI11 2.5.0 CLI11 CLI11::CLI11)


if(SROUTER_PEERSTATS)
  add_library(sqlite_orm INTERFACE)
  target_include_directories(sqlite_orm SYSTEM INTERFACE sqlite_orm/include)
  if(NOT TARGET sqlite3)
    add_library(sqlite3 INTERFACE)
    pkg_check_modules(SQLITE3 REQUIRED IMPORTED_TARGET sqlite3)
    target_link_libraries(sqlite3 INTERFACE PkgConfig::SQLITE3)
  endif()
  target_link_libraries(sqlite_orm INTERFACE sqlite3)
endif()


set(LIBQUIC_BUILD_TESTS OFF CACHE BOOL "")
sessiondep_or_submodule(liboxenquic 1.9.0 oxen-libquic oxen::quic)


# libcrypt defaults, only on with macos and non static linux
set(default_libcrypt OFF)

if(CMAKE_SYSTEM_NAME MATCHES "Linux" AND NOT STATIC_LINK)
  pkg_check_modules(LIBCRYPT libcrypt IMPORTED_TARGET)
  if(LIBCRYPT_FOUND)
      set(default_libcrypt ON)
  endif()
endif()
if(MACOS)
  set(default_libcrypt ON)
endif()

option(WITH_LIBCRYPT "enable fast password hash with libcrypt" ${default_libcrypt})

add_library(session-router-libcrypt INTERFACE)
if(WITH_LIBCRYPT)
  pkg_check_modules(LIBCRYPT libcrypt IMPORTED_TARGET REQUIRED)
  target_compile_definitions(session-router-libcrypt INTERFACE SROUTER_HAVE_CRYPT)
  target_link_libraries(session-router-libcrypt INTERFACE PkgConfig::LIBCRYPT)
  message(STATUS "using libcrypt ${LIBCRYPT_VERSION}")
else()
  # TODO static build lib crypt?
  message(STATUS "not building with libcrypt")
endif()


if(NOT TARGET mlkem_native::mlkem768)
    file(GLOB_RECURSE mlkem_sources mlkem-native/mlkem/src/*.c mlkem-native/mlkem/src/*.S)

    add_library(mlkem_native768 STATIC ${mlkem_sources})

    target_compile_definitions(mlkem_native768 PUBLIC
        MLK_CONFIG_NO_RANDOMIZED_API
        MLK_CONFIG_PARAMETER_SET=768
        MLK_CONFIG_NAMESPACE_PREFIX=sr_mlkem768
        MLK_CONFIG_NO_SUPERCOP
        MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
        MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202
    )

    target_include_directories(mlkem_native768 PUBLIC mlkem-native/mlkem)

    add_library(mlkem_native::mlkem768 ALIAS mlkem_native768)
endif()
