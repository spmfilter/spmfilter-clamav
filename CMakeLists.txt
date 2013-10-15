cmake_minimum_required(VERSION 2.6)
project(spmfilter-clamav)

# NO NEED TO CHANGE ANYTHING BELOW

# include modules
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
include(${CMAKE_MODULE_PATH}/GNUInstallDirs.cmake)
include(FindPkgConfig)
include(SMFMacros)

# check for build.properties
include("${CMAKE_SOURCE_DIR}/build.properties" OPTIONAL)

# check prefix
if(PREFIX)
    SET(CMAKE_INSTALL_PREFIX ${PREFIX})
endif(PREFIX)

pkg_search_module(SPMFILTER REQUIRED spmfilter >= 0.6)
if(SPMFILTER_FOUND)
    include_directories(${SPMFILTER_INCLUDE_DIRS})
    link_directories(${SPMFILTER_LIBRARY_DIRS})
endif(SPMFILTER_FOUND)

# check for enabled debugging
if(ENABLE_DEBUG)
    set(CMAKE_VERBOSE_MAKEFILE TRUE)
    add_definitions(-DDEBUG -g -O0 -Wall)
endif(ENABLE_DEBUG)

file(READ ${CMAKE_CURRENT_SOURCE_DIR}/VERSION PLUGIN_VERSION)

add_subdirectory(src)
add_subdirectory(man)

set(CPACK_PACKAGE_NAME "spmfilter-clamav")
set(CPACK_PACKAGE_VENDOR "spmfilter.org")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "check mails for viruses with ClamAV")
set(CPACK_PACKAGE_DESCRIPTION_FILE ${CMAKE_CURRENT_SOURCE_DIR}/README)
set(CPACK_PACKAGE_VERSION ${PLUGIN_VERSION})
set(CPACK_COMPONENTS_ALL applications libraries headers)

set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${PLUGIN_VERSION}")
set(CPACK_SOURCE_GENERATOR TGZ)
set(CPACK_SOURCE_IGNORE_FILES
"\\\\.git"
"build"
"build\\\\.properties"
)

include(CPack)
