cmake_minimum_required(VERSION 3.5)

#set(INSTALL_DIR "${CMAKE_SOURCE_DIR}/build")

project(bpqcrypto)

set(CMAKE_CXX_STANDARD 11)

add_library(bpqcrypto SHARED
    src/bpqcrypto.cpp
    src/bpqhash.cpp
    include/bpqcrypto.hpp
    include/bpqcrypto.h
    src/xmss_address.h
    src/xmss_common_ops.cpp
    src/xmss_common_ops.h
    src/xmss_hash.cpp
    src/xmss_hash.h
    src/xmss_hashtree.h
    src/xmss_index_registry.cpp
    src/xmss_index_registry.h
    src/xmss_key_pair.h
    src/xmss_parameters.cpp
    src/xmss_parameters.h
    src/xmss_privatekey.cpp
    src/xmss_privatekey.h
    src/xmss_publickey.cpp
    src/xmss_publickey.h
    src/xmss_signature.cpp
    src/xmss_signature.h
    src/xmss_signature_operation.cpp
    src/xmss_signature_operation.h
    src/xmss_tools.cpp
    src/xmss_tools.h
    src/xmss_verification_operation.cpp
    src/xmss_verification_operation.h
    src/xmss_wots_addressed_privatekey.h
    src/xmss_wots_addressed_publickey.h
    src/xmss_wots_parameters.cpp
    src/xmss_wots_parameters.h
    src/xmss_wots_privatekey.cpp
    src/xmss_wots_privatekey.h
    src/xmss_wots_publickey.cpp
    src/xmss_wots_publickey.h
        src/aes.cpp src/aes.h)


include(cmake/botan.cmake)

#add_dependencies(bpqcrypto xbotan)

message(STATUS "BOTAN_INCLUDE_DIR=${BOTAN_INCLUDE_DIR}")
message(STATUS "BOTAN_LIBRARY=${BOTAN_LIBRARY}")

target_include_directories(bpqcrypto PRIVATE "${BOTAN_INCLUDE_DIR}")
target_include_directories(bpqcrypto PUBLIC "${CMAKE_SOURCE_DIR}/include")

if (APPLE)
  find_library(SECURITY_FRAMEWORK NAMES Security REQUIRED)
endif(APPLE)

target_link_libraries(bpqcrypto botan ${SECURITY_FRAMEWORK})

if(MSVC)
target_compile_definitions(bpqcrypto PRIVATE "-D_SCL_SECURE_NO_WARNINGS")
endif(MSVC)

install(TARGETS bpqcrypto DESTINATION "${CMAKE_INSTALL_PREFIX}")

if(APPLE)

    find_program(python3 "python3")
    
    if (python3)

        add_custom_command (TARGET bpqcrypto POST_BUILD
                           COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/python/setup.py ${CMAKE_CURRENT_BINARY_DIR}/setup.py
                           COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/python/README.md ${CMAKE_CURRENT_BINARY_DIR}/README.md
                           COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/python/bpqcrypto/__init__.py ${CMAKE_CURRENT_BINARY_DIR}/bpqcrypto/__init__.py
                           COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/python/bpqcrypto/aes.py ${CMAKE_CURRENT_BINARY_DIR}/bpqcrypto/aes.py
                           COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/python/bpqcrypto/test.py ${CMAKE_CURRENT_BINARY_DIR}/bpqcrypto/test.py
                           COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:bpqcrypto> ${CMAKE_CURRENT_BINARY_DIR}/bpqcrypto
                           COMMAND ${python3}
                           ARGS setup.py bdist_wheel
                           WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                           )
    endif()    
    
endif()
