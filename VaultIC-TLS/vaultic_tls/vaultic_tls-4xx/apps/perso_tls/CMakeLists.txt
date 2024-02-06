#
# CMakeLists.txt file for VaultIC TLS Perso app
#

cmake_minimum_required(VERSION 3.5)

set (NAME perso_tls)
project(${NAME})

add_executable(${NAME} main.c)

target_link_libraries(${NAME} vaultic_tls_${VAULTIC_PRODUCT} vaultic_tls_crypto)

install(TARGETS ${NAME}
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

file(COPY ../../../../certificates/deviceKey.der DESTINATION ./certs)
file(COPY ../../../../certificates/deviceCert.der DESTINATION ./certs)
file(COPY ../../../../certificates/serverKey.der DESTINATION ./certs)
file(COPY ../../../../certificates/serverCert.der DESTINATION ./certs)
file(COPY ../../../../certificates/rootCACert.der DESTINATION ./certs)
file(COPY perso_client.sh DESTINATION .)
file(COPY perso_server.sh DESTINATION .)








