cmake_minimum_required(VERSION 3.13...3.24)  # 3.13 is buster's version

# Cmake 3.24+ breaks extraction timestamps by default, hurray, but the option to not break
# timestamps fails in cmake <3.24, extra hurray!
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.24)
    cmake_policy(SET CMP0135 OLD)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Has to be set before `project()`, and ignored on non-macos:
set(CMAKE_OSX_DEPLOYMENT_TARGET 10.15 CACHE STRING "macOS deployment target (Apple clang only)")

set(session-router_full_def ON)
if(IOS)
  set(session-router_full_def OFF)
endif()

# These two are not exclusive: daemon requires full platform, but the main session-router library itself
# can support both.
option(SROUTER_FULL "build with full client/relay support. Disabling this will only allow embedded session-router usage" ${session-router_full_def})
option(SROUTER_DAEMON "build session-router daemon and associated utils (requires SROUTER_FULL)" ${SROUTER_FULL})

if(SROUTER_DAEMON AND NOT SROUTER_FULL)
  message(FATAL_ERROR "Cannot use SROUTER_DAEMON without SROUTER_FULL platform support!")
endif()

option(SROUTER_GRAPH_DEPENDENCIES "Produce graphviz representation of cmake dependencies" OFF)

option(SROUTER_VERSION_SO "Add the project version to the shared library filename, e.g. libsession-router1.2.3.so instead of libsession-router.so" OFF)

set(LANGS C CXX)
if(APPLE AND SROUTER_DAEMON)
  set(LANGS ${LANGS} OBJC Swift)
endif()

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang ${LANGS})
    if(NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()


project(session-router
    VERSION 1.0.0
    DESCRIPTION "Session Router - IP packet onion router"
    LANGUAGES ${LANGS})

if(APPLE)
    # Apple build number: must be incremented to submit a new build for the same session-router version,
    # should be reset to 0 when the session-router version increments.
    set(SROUTER_APPLE_BUILD 5)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# Core options
option(SROUTER_AVX2 "enable avx2 code" OFF)
option(SROUTER_NATIVE_BUILD "optimise for host system and FPU" ON)
option(SROUTER_XSAN "use sanitiser, if your system has it (requires -DCMAKE_BUILD_TYPE=Debug)" OFF)
option(SROUTER_JEMALLOC "Link to jemalloc for memory allocations, if found (requires non-static build)" ON)
option(SROUTER_COVERAGE "generate coverage data" OFF)
option(SROUTER_WARNINGS_AS_ERRORS "treat all warnings as errors. turn off for development, on for release" OFF)
option(SROUTER_TESTS "build unit tests" OFF)
option(SROUTER_HIVE "build simulation stubs" OFF)
option(SROUTER_PACKAGE "builds extra components for making an installer (with 'make package')" OFF)
option(SROUTER_PEERSTATS "build with experimental peerstats db support" OFF)
option(SROUTER_STRIP "strip off all debug symbols into an external archive for all executables built" OFF)
option(SROUTER_DEBUG_PATH_SEED "enable support for the debug-mode [paths]:debug-path-seed option for reproducible, non-random paths" OFF)

set(SROUTER_BOOTSTRAP_FALLBACK_MAINNET "${PROJECT_SOURCE_DIR}/contrib/bootstrap/mainnet.signed" CACHE PATH "Fallback bootstrap path (mainnet)")
set(SROUTER_BOOTSTRAP_FALLBACK_TESTNET "${PROJECT_SOURCE_DIR}/contrib/bootstrap/testnet.signed" CACHE PATH "Fallback bootstrap path (testnet)")

include(cmake/enable_lto.cmake)

option(CROSS_PLATFORM "cross compiler platform" "Linux")
option(CROSS_PREFIX "toolchain cross compiler prefix" "")

option(BUILD_SHARED_LIBS "Build shared library" OFF)
option(BUILD_STATIC_DEPS "Download, build, and statically link against core dependencies" OFF)
option(STATIC_LINK "link statically against dependencies" ${BUILD_STATIC_DEPS})
if(BUILD_STATIC_DEPS AND NOT STATIC_LINK)
  message(FATAL_ERROR "Option BUILD_STATIC_DEPS requires STATIC_LINK to be enabled as well")
endif()

if(BUILD_STATIC_DEPS AND BUILD_SHARED_LIBS)
  message(FATAL_ERROR "Incompatible options: BUILD_STATIC_DEPS cannot be used with BUILD_SHARED_LIBS")
endif()

if(BUILD_STATIC_DEPS)
  set(CMAKE_FIND_PACKAGE_PREFER_CONFIG TRUE)
  include(cmake/StaticBuild.cmake)
endif()

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

# set(debug OFF)
# if(CMAKE_BUILD_TYPE MATCHES "[Dd][Ee][Bb][Uu][Gg]")
#   set(debug ON)
#   add_definitions(-DSROUTER_DEBUG)
# endif()

option(SROUTER_WARN_DEPRECATED "show deprecation warnings" OFF)

include(CheckCXXSourceCompiles)
include(CheckLibraryExists)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(cmake/target_link_libraries_system.cmake)
include(cmake/add_import_library.cmake)
include(cmake/libatomic.cmake)

if (STATIC_LINK)
  set(CMAKE_FIND_LIBRARY_SUFFIXES ${CMAKE_STATIC_LIBRARY_SUFFIX})
  message(STATUS "setting static library suffix search")
endif()

include(cmake/gui-option.cmake)

include(cmake/solaris.cmake)
include(cmake/win32.cmake)
include(cmake/macos.cmake)

# No in-source building
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out-of-source build.  Create a build directory and run 'cmake ${CMAKE_SOURCE_DIR} [options]'.")

# Always build PIC
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include(cmake/unix.cmake)

if(NOT WIN32)
  if(IOS OR ANDROID)
    set(NON_PC_TARGET ON)
  else()
    include(TargetArch)
    target_architecture(COMPILE_ARCH)
    if(COMPILE_ARCH MATCHES i386 OR COMPILE_ARCH MATCHES x86_64)
      set(NON_PC_TARGET OFF)
    else()
      set(NON_PC_TARGET ON)
    endif()
  endif()
endif()

find_package(PkgConfig REQUIRED)

if(NOT TARGET sodium)
  # Allow -DSROUTER_DOWNLOAD_SODIUM=FORCE to download without even checking for a local libsodium
  option(SROUTER_DOWNLOAD_SODIUM "Allow libsodium to be downloaded and built locally if not found on the system" OFF)
  if(NOT SROUTER_DOWNLOAD_SODIUM STREQUAL "FORCE" AND NOT BUILD_STATIC_DEPS)
    pkg_check_modules(SODIUM libsodium>=1.0.18 IMPORTED_TARGET)
  endif()

  add_library(sodium INTERFACE)
  if(SODIUM_FOUND AND NOT SROUTER_DOWNLOAD_SODIUM STREQUAL "FORCE" AND NOT BUILD_STATIC_DEPS)
    target_link_libraries(sodium INTERFACE PkgConfig::SODIUM)
  else()
    if(NOT SROUTER_DOWNLOAD_SODIUM AND NOT BUILD_STATIC_DEPS)
      message(FATAL_ERROR "Could not find libsodium >= 1.0.18; either install it on your system or use -DSROUTER_DOWNLOAD_SODIUM=ON to download and build an internal copy")
    endif()
    message(STATUS "Sodium >= 1.0.18 not found, but SROUTER_DOWNLOAD_SODIUM specified, so downloading it")
    include(DownloadLibSodium)
    target_link_libraries(sodium INTERFACE sodium_vendor)
  endif()

  # Need this target export so that loki-mq properly picks up sodium
  export(TARGETS sodium NAMESPACE sodium:: FILE sodium-exports.cmake)
endif()

set(warning_flags -Wall -Wextra -Wno-unknown-pragmas -Wno-unused-function -Werror=vla)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  list(APPEND warning_flags -Wno-unknown-warning-option)
endif()

if(SROUTER_WARNINGS_AS_ERRORS)
  list(APPEND warning_flags -Werror -Wno-error=array-bounds)
endif()

# GCC 12's stringop-overflow warnings are really broken, with tons and tons of false positives all
# over the place (not just in our code, but also in its own stdlibc++ code).  It's better in 13
# w.r.t. stdlibc++, but our code still throws tons of warnings, so disable it for now.
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 13)
    list(APPEND warning_flags -Wno-stringop-overflow)
endif()
list(APPEND warning_flags -Wno-deprecated-declarations)

add_library(session-router-base-internal_warnings INTERFACE)

# If we blindly add these directly as compile_options then they get passed to swiftc on Apple and
# break, so we use a generate expression to set them only for C++/C/ObjC
target_compile_options(session-router-base-internal_warnings INTERFACE "$<$<OR:$<COMPILE_LANGUAGE:CXX>,$<COMPILE_LANGUAGE:C>,$<COMPILE_LANGUAGE:OBJC>>:${warning_flags}>")

if(SROUTER_XSAN)
  string(APPEND CMAKE_CXX_FLAGS_DEBUG " -fsanitize=${SROUTER_XSAN} -fno-omit-frame-pointer -fno-sanitize-recover")
  foreach(type EXE MODULE SHARED STATIC)
    string(APPEND CMAKE_${type}_LINKER_FLAGS_DEBUG " -fsanitize=${SROUTER_XSAN} -fno-omit-frame-pointer -fno-sanitize-recover")
  endforeach()
  message(STATUS "Doing a ${SROUTER_XSAN} sanitizer build")
endif()

include(cmake/coverage.cmake)

# these vars are set by the cmake toolchain spec
if (WOW64_CROSS_COMPILE OR WIN64_CROSS_COMPILE)
  include(cmake/cross_compile.cmake)
endif()

if(NOT APPLE)
  if(SROUTER_NATIVE_BUILD)
    if(CMAKE_SYSTEM_PROCESSOR STREQUAL ppc64le)
      add_compile_options(-mcpu=native -mtune=native)
    else()
      add_compile_options(-march=native -mtune=native)
    endif()
  elseif(NOT NON_PC_TARGET)
    if (SROUTER_AVX2)
      add_compile_options(-march=haswell -mtune=haswell -mfpmath=sse)
    else()
      # Public binary releases
      add_compile_options(-march=nocona -mtune=haswell -mfpmath=sse)
    endif()
  endif()
endif()

# now have libevent2.21 w/ pthreads
set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

unset(GIT_VERSION)
unset(GIT_VERSION_REAL)

if(NOT GIT_VERSION)
  exec_program("git" ${CMAKE_CURRENT_SOURCE_DIR} ARGS "rev-parse --short HEAD" OUTPUT_VARIABLE GIT_VERSION_UNSTRIP)
  string(STRIP "${GIT_VERSION_UNSTRIP}" GIT_VERSION)
endif()

string(REGEX REPLACE "^fatal.*$" nogit GIT_VERSION_REAL "${GIT_VERSION}")

find_package(PkgConfig REQUIRED)

if (NOT BUILD_STATIC_DEPS)
  pkg_check_modules(UNBOUND libunbound REQUIRED IMPORTED_TARGET)
  add_library(libunbound INTERFACE)
  target_link_libraries(libunbound INTERFACE PkgConfig::UNBOUND)

  pkg_check_modules(SD libsystemd IMPORTED_TARGET)
  # Default WITH_SYSTEMD to true if we found it
  option(WITH_SYSTEMD "enable systemd integration for sd_notify" ${SD_FOUND})
endif()

add_subdirectory(external)

# interface library for setting common includes, linkage and flags
add_library(session-router-base INTERFACE)
target_include_directories(session-router-base INTERFACE include)
target_link_libraries(session-router-base INTERFACE oxen::quic oxen-logging-fmt-spdlog nlohmann_json::nlohmann_json)

target_compile_features(session-router-base INTERFACE cxx_std_20)

add_library(session-router-base-internal INTERFACE)
target_include_directories(session-router-base-internal INTERFACE include/session_router)
if(NOT SROUTER_FULL)
  target_compile_definitions(session-router-base-internal INTERFACE SROUTER_EMBEDDED_ONLY)
endif()

target_link_libraries(session-router-base-internal INTERFACE session-router-base-internal_warnings)

if (TARGET session-router_static_deps)
  target_link_libraries(session-router-base-internal INTERFACE session-router_static_deps)
endif()

if(WITH_SYSTEMD AND (NOT ANDROID))
  if(NOT SD_FOUND)
    message(FATAL_ERROR "libsystemd not found")
  endif()
  target_link_libraries(session-router-base INTERFACE PkgConfig::SD)
  target_compile_definitions(session-router-base INTERFACE WITH_SYSTEMD)
endif()

if(SROUTER_JEMALLOC AND NOT STATIC_LINK)
  pkg_check_modules(JEMALLOC jemalloc IMPORTED_TARGET)
  if(JEMALLOC_FOUND)
    target_link_libraries(session-router-base INTERFACE PkgConfig::JEMALLOC)
  else()
    message(STATUS "jemalloc not found, not linking to jemalloc")
  endif()
else()
  message(STATUS "jemalloc support disabled")
endif()


if(ANDROID)
  target_link_libraries(session-router-base INTERFACE log)
  target_compile_definitions(session-router-base INTERFACE ANDROID)
  set(ANDROID_PLATFORM_SRC android/ifaddrs.c)
endif()

if(SROUTER_HIVE)
  add_definitions(-DSROUTER_HIVE)
endif()

add_subdirectory(src)

if(SROUTER_DAEMON)
  add_subdirectory(src/daemon)
endif()

if(SROUTER_HIVE)
  add_subdirectory(pybind)
endif()
if(SROUTER_TESTS OR SROUTER_HIVE)
  add_subdirectory(test)
endif()
if(ANDROID)
  add_subdirectory(jni)
endif()

add_subdirectory(docs)

include(cmake/gui.cmake)

if(APPLE AND SROUTER_FULL)
  macos_target_setup()
endif()

add_executable(libsession-router_jank_test EXCLUDE_FROM_ALL contrib/libsession-router_jank_test.cpp)
target_include_directories(libsession-router_jank_test PUBLIC include/)
target_link_libraries(libsession-router_jank_test PRIVATE libsessionrouter)

# uninstall target
if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()

if(SROUTER_PACKAGE AND NOT APPLE)
  include(cmake/installer.cmake)
endif()

if(TARGET package)
  add_dependencies(package assemble_gui)
endif()
