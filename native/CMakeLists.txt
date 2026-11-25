cmake_minimum_required(VERSION 3.20)
project(codex_apdu_native C)

set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
add_subdirectory("${MBEDTLS_SOURCE}" mbedtls EXCLUDE_FROM_ALL)
add_library(codex-apdu-mbedtls SHARED bridge.c)
target_link_libraries(codex-apdu-mbedtls PRIVATE mbedtls mbedx509 mbedcrypto)
