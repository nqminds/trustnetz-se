#!/bin/bash -e
#exit immediately if a command fails

# Go to scripts folder
SCRIPT_DIR=$(dirname "$0")
pushd ${SCRIPT_DIR}

# Go to demos folder
pushd ../../..

# Retrieve settings from config file 
source ./get_config.sh

CMAKE_OPTS="-DVAULTIC_PRODUCT=${PRODUCT} -DVAULTIC_LOGS_LEVEL=${LOG_LEVEL}"
if([ ! -z ${INTERFACE} ] ); then 
    CMAKE_OPTS+=" -DVAULTIC_COMM=${INTERFACE}"
fi

# Go to tls kit root folder
pushd ..

# Get WolfSSL
if [ ! -d "wolfssl" ] 
then
    echo Getting WolfSSL ...
    git clone --recursive https://github.com/wolfSSL/wolfssl.git
    pushd wolfssl
    git checkout v5.6.3-stable
    popd
fi

# Install wolfssl patch
echo Installing VaultIC${PRODUCT} patch in WolfSSL
cp -rv VaultIC-TLS/vaultic_tls/vaultic_wolfssl/wolfssl_patch/* wolfssl

# Generate build environment for VaultIC perso apps
pushd VaultIC-TLS/vaultic_tls/vaultic_tls-${FAMILY}/apps
rm -rf build
mkdir build
cd build
cmake ${CMAKE_OPTS} ..
popd

# Return to scripts folder
popd
popd

# Generate build environment for client_vaultic
pushd ..
rm -rf build_client_vaultic
mkdir build_client_vaultic
pushd build_client_vaultic
cmake ${CMAKE_OPTS} ../src/client_vaultic

echo -e "\n"
echo Install done
