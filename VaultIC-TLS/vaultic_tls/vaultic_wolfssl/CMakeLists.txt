#
# CMakeLists.txt file for generating vaultic_wolfssl library
#

cmake_minimum_required(VERSION 3.5)

set(LIB_NAME vaultic_wolfssl) 
project(${LIB_NAME})

set(TLS_KIT_ROOT_FOLDER ../../..)

# disable useless wolfssl options to speed up compiling
set(WOLFSSL_CRYPT_TESTS "no" CACHE STRING "" FORCE)
set(WOLFSSL_EXAMPLES "no" CACHE STRING "" FORCE)

# activate wolfssl call backs
add_compile_options(-DHAVE_PK_CALLBACKS)

add_subdirectory(${TLS_KIT_ROOT_FOLDER}/wolfssl wolfssl)

string(SUBSTRING "${VAULTIC_PRODUCT}" 0 1 FAMILY)
string (APPEND FAMILY "xx")
add_subdirectory(../vaultic_tls-${FAMILY}/src vaultic_tls)

add_library (${LIB_NAME} ${TLS_KIT_ROOT_FOLDER}/wolfssl/wolfcrypt/src/port/wisekey/vaultic.c) 

target_link_libraries(${LIB_NAME} wolfssl vaultic_tls_${VAULTIC_PRODUCT})

target_include_directories (${LIB_NAME} PUBLIC .)    

 



 
