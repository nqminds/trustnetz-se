#!/bin/bash -e
#exit immediately if a command fails

# Go to scripts folder
SCRIPT_DIR=$(dirname "$0")
pushd ${SCRIPT_DIR}

# Go to demos folder
pushd ../../..
ls
# Retrieve settings from config file 
source ./get_config.sh

CMAKE_OPTS="-DVAULTIC_PRODUCT=${PRODUCT} -DVAULTIC_LOGS_LEVEL=${LOG_LEVEL}"
if([ ! -z ${INTERFACE} ] ); then 
    CMAKE_OPTS+=" -DVAULTIC_COMM=${INTERFACE}"
fi

# Go to tls kit root folder
pushd ..
ls
# Build the VaultIC perso apps
echo Building VaultIC perso apps ...
pushd VaultIC-TLS/vaultic_tls/vaultic_tls-${FAMILY}/apps/build
cmake ${CMAKE_OPTS} ..
make
popd

# Return to scripts folder
popd
popd

# Build vaultic client demo
pushd ../build_client_vaultic
cmake ${CMAKE_OPTS} ../src/client_vaultic
make
popd

# Return to initial folder
popd
echo -e "\n"
echo Build done
