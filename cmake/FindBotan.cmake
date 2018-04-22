cmake_minimum_required (VERSION 3.5)

set(BOTAN_ROOT_DIR $ENV{BOTAN_ROOT} CACHE PATH "")

if (BOTAN_ROOT_DIR)

    set(BOTAN_INCLUDE_DIR "${BOTAN_ROOT_DIR}/include/botan-2")
    set(BOTAN_INCLUDE_DIRS "${BOTAN_INCLUDE_DIR}")
    set(BOTAN_LIBDIR "${BOTAN_ROOT_DIR}/lib")
    set(BOTAN_LIBRARY_DIRS "${BOTAN_LIBDIR}")
    set(BOTAN_LIBRARIES "botan")

    find_library(BOTAN_LIBRARY NAMES ${BOTAN_LIBRARIES}
        HINTS
        ${BOTAN_LIBDIR}
        )

    if(BOTAN_LIBRARY)
        set(BOTAN_FOUND TRUE)
    endif()

else()

    if (UNIX)

        find_package(PkgConfig QUIET)
        pkg_search_module(BOTAN botan-2 QUIET)

        set(BOTAN_DEFINITIONS ${BOTAN_CFLAGS})

        find_path(BOTAN_INCLUDE_DIR botan/botan.h
                HINTS
                ${BOTAN_INCLUDEDIR}
                ${BOTAN_INCLUDE_DIRS}
                )

        find_library(BOTAN_LIBRARY NAMES ${BOTAN_LIBRARIES}
                HINTS
                ${BOTAN_LIBDIR}
                ${BOTAN_LIBRARY_DIRS}
                )

    elseif (WIN32)
    endif()

endif(BOTAN_ROOT_DIR)

if (BOTAN_FOUND)
  if (NOT BOTAN_FIND_QUIETLY)
    message(STATUS "Found botan-2: ${BOTAN_LIBRARY}")
  endif ()
else ()
  if (BOTAN_FIND_REQUIRED)
    message(FATAL_ERROR "Could NOT find botan-2.")
  endif ()
  message(STATUS "botan NOT found.")
endif ()

mark_as_advanced(BOTAN_FOUND BOTAN_LIBRARY BOTAN_INCLUDE_DIR BOTAN_DEFINITIONS)
