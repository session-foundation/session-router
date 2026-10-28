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
sessiondep_or_submodule(liboxenquic 1.13.0 oxen-libquic oxen::quic)


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


# ML-KEM-768 from mlkem-native's single-compilation-unit sources, used through crypto/mlkem768.cpp.
#
# mlkem-native only compiles in its x86_64 assembly when the target already has AVX2, and then uses
# it unconditionally, so a build for a baseline x86_64 target (as our release builds are) would never
# use it.  On x86_64 we therefore build it a second time with AVX2 enabled, under a different symbol
# prefix, and crypto/mlkem768.cpp picks between the two from the CPU's features at runtime.  These
# are object libraries so that their code lands in the archive of whatever links them rather than in
# archives of their own.
check_target_condition(MLKEM768_TARGET_X86_64 "defined(__x86_64__)")
# mlkem-native enables its x86_64 backend from __AVX2__ alone (sys.h), while crypto/mlkem768.cpp only
# skips the runtime dispatch when the target also guarantees BMI2 and POPCNT.
check_target_condition(MLKEM768_TARGET_AVX2 "defined(__AVX2__)")
check_target_condition(MLKEM768_TARGET_AVX2_FULL
    "defined(__AVX2__) && defined(__BMI2__) && defined(__POPCNT__)")

function(add_mlkem768_build name with_asm)
    set(tgt mlkem768_${name})
    set(srcs mlkem-native/mlkem/mlkem_native.c)
    if(with_asm)
        list(APPEND srcs mlkem-native/mlkem/mlkem_native_asm.S)
    endif()
    add_library(${tgt} OBJECT ${srcs})
    target_include_directories(${tgt} PRIVATE mlkem-native/mlkem)
    target_compile_definitions(${tgt} PRIVATE
        MLK_CONFIG_PARAMETER_SET=768
        MLK_CONFIG_NAMESPACE_PREFIX=${tgt}
        MLK_CONFIG_NO_RANDOMIZED_API
        MLK_CONFIG_INTERNAL_API_QUALIFIER=static
        MLK_CONFIG_USE_NATIVE_BACKEND_ARITH
        MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202)
    target_compile_options(${tgt} PRIVATE ${ARGN})
endfunction()

set(mlkem768_baseline_asm ON)
if(MLKEM768_TARGET_X86_64 AND NOT MLKEM768_TARGET_AVX2)
    # The x86_64 backend is AVX2-only, so without AVX2 the baseline's assembly would be empty.
    set(mlkem768_baseline_asm OFF)
endif()
add_mlkem768_build(baseline ${mlkem768_baseline_asm})
# Not for MSVC: mlkem-native leaves out its x86_64 assembly there, so the copy would be identical.
# Not when the target already has everything the AVX2 backend needs: the baseline build is then the
# AVX2 build, and crypto/mlkem768.cpp doesn't dispatch.
if(MLKEM768_TARGET_X86_64 AND NOT MSVC AND NOT MLKEM768_TARGET_AVX2_FULL)
    # The AVX2 backend's rejection sampling also uses pext (BMI2) and popcnt.
    add_mlkem768_build(avx2 ON -mavx2 -mbmi2 -mpopcnt)
    target_compile_definitions(mlkem768_avx2 INTERFACE SROUTER_MLKEM768_AVX2_BUILD)
endif()
