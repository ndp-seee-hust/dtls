cmake_minimum_required(VERSION 3.16.3)
project(DTLS)

include_directories(include)
include_directories(include/mbedtls)
include_directories(include/psa)

set(MBEDTLS_LIBS
    ${CMAKE_CURRENT_SOURCE_DIR}/libmbedtls/libmbedx509.a
    ${CMAKE_CURRENT_SOURCE_DIR}/libmbedtls/libmbedtls.a
    ${CMAKE_CURRENT_SOURCE_DIR}/libmbedtls/libmbedcrypto.a)

add_library(dtls src/dtls.c src/socket.c)
target_link_libraries(dtls ${MBEDTLS_LIBS})

add_executable(server test/server_test.c)
target_link_libraries(server dtls ${MBEDTLS_LIBS})

add_executable(client test/client_test.c)
target_link_libraries(client dtls ${MBEDTLS_LIBS})
