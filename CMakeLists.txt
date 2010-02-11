cmake_minimum_required(VERSION 2.6)

project(spmfilter-clamav)

# check for build.properties
include("${CMAKE_SOURCE_DIR}/build.properties" OPTIONAL)

# check prefix
if(PREFIX)
    SET(CMAKE_INSTALL_PREFIX ${PREFIX})
endif(PREFIX)

include(FindPkgConfig)

pkg_search_module(SPMFILTER REQUIRED spmfilter)
if(SPMFILTER_FOUND)
    include_directories(${SPMFILTER_INCLUDE_DIRS})
    link_directories(${SPMFILTER_LIBRARY_DIRS})
endif(SPMFILTER_FOUND)

# check for enabled debugging
if(ENABLE_DEBUG)
    set(CMAKE_VERBOSE_MAKEFILE TRUE)
    add_definitions(-DDEBUG -g -O0 -Wall)
endif(ENABLE_DEBUG)

# check for glib2
pkg_search_module(GLIB2 REQUIRED glib-2.0)
if(GLIB2_FOUND)
    include_directories(${GLIB2_INCLUDE_DIRS})
    link_directories(${GLIB2_LIBRARY_DIRS})
endif(GLIB2_FOUND)

add_subdirectory(src)
