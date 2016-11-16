cmake_minimum_required (VERSION 2.6)

macro(use_c99)
  if (CMAKE_VERSION VERSION_LESS "3.1")
    if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
      set (CMAKE_C_FLAGS "--std=gnu99 ${CMAKE_C_FLAGS}")
    endif ()
  else ()
    set (CMAKE_C_STANDARD 99)
  endif ()
endmacro(use_c99)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release
        CACHE STRING "Set build type to Debug o Release (default Release)"
FORCE)
endif()
string(TOLOWER "${CMAKE_BUILD_TYPE}" CMAKE_BUILD_TYPE_LOWER)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
# Project starts
project (cdns C)
use_c99 ()
include(CTest)
 
# The version number.
set (cdns_VERSION_MAJOR 1)
set (cdns_VERSION_MINOR 0)
 
# does this system provide the log and exp functions?
include (CheckFunctionExists)

#check_function_exists (log HAVE_LOG)

# configure a header file to pass some of the CMake settings
# to the source code
configure_file (
  "${PROJECT_SOURCE_DIR}/config.h.in"
  "${PROJECT_BINARY_DIR}/config.h"
  )
 
# add the binary tree to the search path for include files
# so that we will find cdnsConfig.h
include_directories ("${PROJECT_BINARY_DIR}")
if (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
    include_directories ("/usr/local/include")
    link_directories("/usr/local/lib")
endif()
if (${MINGW})
   # to build for windows, you might need to build the following
   # packages:
   #   argp-standalone, openssl, libevent2
   set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
   set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
   set (CMAKE_C_FLAGS "-mno-ms-bitfields ${CMAKE_C_FLAGS}")
   # additional library required for windows socket
   list (APPEND EXTRA_LIBS ws2_32.lib)
endif ()

find_package(argp REQUIRED)
include_directories(${ARGP_INCLUDE_PATH})
list (APPEND EXTRA_LIBS ${ARGP_LIBRARIES})

find_package(Libevent2 REQUIRED)
include_directories(${LIBEVENT2_INCLUDE_DIR})
list (APPEND CMAKE_REQUIRED_LIBRARIES ${LIBEVENT2_LIBRARIES} m)

# add the executable
add_executable (cdns  main.c log.c json.c cfg.c cdns.c dns.c blacklist.c)
target_link_libraries (cdns ${CMAKE_REQUIRED_LIBRARIES} ${EXTRA_LIBS})
 
# add the install targets
install (TARGETS cdns DESTINATION bin)

# build a CPack driven installer package
include (InstallRequiredSystemLibraries)
set (CPACK_RESOURCE_FILE_LICENSE  
     "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set (CPACK_PACKAGE_VERSION_MAJOR "${cdns_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${cdns_VERSION_MINOR}")
include (CPack)
