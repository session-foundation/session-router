# We do this via a custom command that re-invokes a cmake script because we need the DEPENDS on .git/index so that we will re-run it (to regenerate the commit tag in the version) whenever the current commit changes. If we used a configure_file directly here, it would only re-run when something else causes cmake to re-run.

if(SROUTER_VERSIONTAG)
  set(VERSIONTAG "${SROUTER_VERSIONTAG}")
  configure_file("${CMAKE_CURRENT_SOURCE_DIR}/constants/version.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/constants/version.cpp" @ONLY)
else()
  set(VERSIONTAG "${GIT_VERSION}")
  set(GIT_INDEX_FILE "${PROJECT_SOURCE_DIR}/.git/index")
  find_package(Git)
  if(EXISTS "${GIT_INDEX_FILE}" AND ( GIT_FOUND OR Git_FOUND) )
      message(STATUS "Found Git: ${GIT_EXECUTABLE}")
      set(genversion_args "-DGIT=${GIT_EXECUTABLE}")
      foreach(v MAJOR MINOR PATCH)
          list(APPEND genversion_args "-Dsession-router_VERSION_${v}=${session-router_VERSION_${v}}")
      endforeach()

      add_custom_command(
          OUTPUT            "${CMAKE_CURRENT_BINARY_DIR}/constants/version.cpp"
          COMMAND           "${CMAKE_COMMAND}"
          ${genversion_args}
          "-D" "SRC=${CMAKE_CURRENT_SOURCE_DIR}/constants/version.cpp.in"
          "-D" "DEST=${CMAKE_CURRENT_BINARY_DIR}/constants/version.cpp"
          "-P" "${CMAKE_CURRENT_LIST_DIR}/GenVersion.cmake"
          DEPENDS           "${CMAKE_CURRENT_SOURCE_DIR}/constants/version.cpp.in"
          "${GIT_INDEX_FILE}")
  else()
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/constants/version.cpp.in" "${CMAKE_CURRENT_BINARY_DIR}/constants/version.cpp" @ONLY)
  endif()
endif()


if(WIN32)
  # MinGW/.rc: map project() hyphen vars to underscore names version.rc.in expects.
  set(session_router_VERSION_MAJOR "${session-router_VERSION_MAJOR}")
  set(session_router_VERSION_MINOR "${session-router_VERSION_MINOR}")
  set(session_router_VERSION_PATCH "${session-router_VERSION_PATCH}")
  set(session_router_VERSION "${session-router_VERSION}")
  foreach(exe IN ITEMS session-router session-router-cntrl session-router-config)
    set(session_router_EXE_NAME "${exe}.exe")
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/win32/version.rc.in" "${CMAKE_BINARY_DIR}/${exe}.rc" @ONLY)
    set_property(SOURCE "${CMAKE_BINARY_DIR}/${exe}.rc" PROPERTY GENERATED 1)
  endforeach()
endif()

add_custom_target(genversion_cpp DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/constants/version.cpp")
if(WIN32)
  add_custom_target(genversion_rc DEPENDS "${CMAKE_BINARY_DIR}/session-router.rc" "${CMAKE_BINARY_DIR}/session-router-cntrl.rc" "${CMAKE_BINARY_DIR}/session-router-config.rc")
else()
  add_custom_target(genversion_rc)
endif()
add_custom_target(genversion DEPENDS genversion_cpp genversion_rc)
