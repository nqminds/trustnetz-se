#
# CMakeLists.txt file for VaultIC Check TLS Perso app
#

cmake_minimum_required(VERSION 3.5)

set (NAME check_tls_perso)
project(${NAME})

add_executable(${NAME} main.c)

target_link_libraries(${NAME} vaultic_tls_${VAULTIC_PRODUCT})

install(TARGETS ${NAME}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)






