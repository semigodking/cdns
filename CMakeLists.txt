cmake_minimum_required (VERSION 2.6)
project (cdns)
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
 
set(CMAKE_REQUIRED_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES} event m)
set (EXTRA_LIBS ${EXTRA_LIBS} ${CMAKE_REQUIRED_LIBRARIES})
# add the executable
add_executable (cdns  main.c log.c json.c cfg.c cdns.c)
target_link_libraries (cdns  ${EXTRA_LIBS})
 
# add the install targets
install (TARGETS cdns DESTINATION bin)

# build a CPack driven installer package
include (InstallRequiredSystemLibraries)
set (CPACK_RESOURCE_FILE_LICENSE  
     "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set (CPACK_PACKAGE_VERSION_MAJOR "${cdns_VERSION_MAJOR}")
set (CPACK_PACKAGE_VERSION_MINOR "${cdns_VERSION_MINOR}")
include (CPack)
