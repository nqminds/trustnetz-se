cmake_minimum_required(VERSION 3.18)

set (EXE wolfvaultutil)
project(${EXE})

set(TLS_KIT_ROOT_FOLDER ../../../../..)

add_subdirectory(${TLS_KIT_ROOT_FOLDER}/VaultIC-TLS/vaultic_tls/vaultic_wolfssl vaultic_wolfssl)

add_executable(${EXE} wolfwk.c)

target_link_libraries(${EXE} vaultic_wolfssl)
