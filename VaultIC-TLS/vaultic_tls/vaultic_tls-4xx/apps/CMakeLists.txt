cmake_minimum_required(VERSION 3.5)
project(apps)
set(VAULTIC_BUILD_CRYPTO_EXT ON)
add_subdirectory(../src vaultic_tls)
add_subdirectory(check_tls_perso)
add_subdirectory(perso_tls)


