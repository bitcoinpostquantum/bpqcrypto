cmake_minimum_required (VERSION 3.5)

include(ExternalProject)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(BOTAN_DEBUG "--debug")
else()
    set(BOTAN_DEBUG "")
endif()

if(WIN32)
    set(BOTAN_OPTIONS "--enable-static")
elseif(UNIX)
    set(BOTAN_OPTIONS "--enable-shared")
endif()

set(CMAKE_VERBOSE_MAKEFILE on)

ExternalProject_Add(xbotan
        GIT_REPOSITORY "https://github.com/randombit/botan"
        GIT_TAG 66b7c7e1fe6d979fdd9b879b2ec63fe06c1f6fd9
        PREFIX external
        UPDATE_COMMAND ""
        UPDATE_DISCONNECTED 0
        BUILD_IN_SOURCE 1
        CONFIGURE_COMMAND python ./configure.py ${BOTAN_OPTIONS} ${BOTAN_DEBUG} --prefix="${CMAKE_CURRENT_BINARY_DIR}/botan"
        --disable-modules=locking_allocator
        --enable-modules=xmss,shake,sha3,aes
        )


if(WIN32)

    set(BOTAN_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/botan/include/botan-2")
    set(BOTAN_LIBRARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/botan/lib")

    set(BOTAN_LIBRARY_NAME "botan.lib")

    set(BOTAN_LIBRARY "${BOTAN_LIBRARY_DIR}/${BOTAN_LIBRARY_NAME}")
    #find_library(BOTAN_LIBRARY botan PATHS "${BOTAN_LIBRARY_DIR}" NO_DEFAULT_PATH)

    add_library(botan STATIC IMPORTED)
    set_target_properties(botan PROPERTIES IMPORTED_LOCATION "${BOTAN_LIBRARY}")
    set_target_properties(botan PROPERTIES INCLUDE_DIRECTORIES "${BOTAN_INCLUDE_DIR}")

elseif(UNIX)

    set(BOTAN_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/botan/include/botan-2" CACHE STRING "BOTAN_INCLUDE_DIR")
    set(BOTAN_LIBRARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/botan/lib")

    #set(BOTAN_LIBRARY_NAME "libbotan-2.so.7.8.0")
    #set(BOTAN_LIBRARY_NAME "libbotan-2.so")
    set(BOTAN_LIBRARY_NAME "libbotan-2.a")

    set(BOTAN_LIBRARY "${BOTAN_LIBRARY_DIR}/${BOTAN_LIBRARY_NAME}")
    #find_library(BOTAN_LIBRARY botan PATHS "${BOTAN_LIBRARY_DIR}" NO_DEFAULT_PATH)

    add_library(botan STATIC IMPORTED)
    set_target_properties(botan PROPERTIES IMPORTED_LOCATION "${BOTAN_LIBRARY}")
    set_target_properties(botan PROPERTIES INCLUDE_DIRECTORIES "${BOTAN_INCLUDE_DIR}")
endif()

add_dependencies(botan xbotan)

message(STATUS "BOTAN_LIBRARY_DIR=${BOTAN_LIBRARY_DIR}")
message(STATUS "BOTAN_LIBRARY=${BOTAN_LIBRARY}")
#message(STATUS "botan_LIBRARIES=${botan_LIBRARIES}")
