#
# CMakeLists.txt file for generating vaultic_mbedtls library
#

cmake_minimum_required(VERSION 3.5)

set(LIB_NAME vaultic_mbedtls) 
project(${LIB_NAME})

set(TLS_KIT_ROOT_FOLDER ../../..)

# disable useless mbed options to speed up compiling
set(ENABLE_PROGRAMS "no" CACHE STRING "" FORCE)
set(ENABLE_TESTING "no" CACHE STRING "" FORCE)

# use alternate implementations
add_compile_definitions(MBEDTLS_ECDSA_VERIFY_ALT MBEDTLS_ECDSA_SIGN_ALT)

# use specific mbed config file 
add_compile_definitions (MBEDTLS_USER_CONFIG_FILE=<${CMAKE_CURRENT_SOURCE_DIR}/mbed_user_config.h>)

if(NOT ${VAULTIC_NO_ECDH})
    add_compile_definitions(MBEDTLS_ECDH_GEN_PUBLIC_ALT MBEDTLS_ECDH_COMPUTE_SHARED_ALT)
endif()

add_subdirectory(${TLS_KIT_ROOT_FOLDER}/mbedtls mbedtls)

string(SUBSTRING "${VAULTIC_PRODUCT}" 0 1 FAMILY)
string (APPEND FAMILY "xx")
add_subdirectory(../vaultic_tls-${FAMILY}/src vaultic_tls)

add_library (${LIB_NAME} vaultic_mbedtls.c) 

target_link_libraries(${LIB_NAME} mbedtls vaultic_tls_${VAULTIC_PRODUCT})

target_include_directories (${LIB_NAME} PUBLIC .)    

 



 
