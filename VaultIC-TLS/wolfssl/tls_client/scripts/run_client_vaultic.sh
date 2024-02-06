#!/bin/bash -e
#exit immediately if a command fails

# Go to scripts folder
SCRIPT_DIR=$(dirname "$0")
pushd ${SCRIPT_DIR}

# Go to demos folder
pushd ../../..

# Retrieve settings from config file 
source get_config.sh

# Return to scripts folder
popd

echo Running wolfssl vaultic client ...
pushd ../build_client_vaultic
${RUN_MODE} ./client_vaultic 127.0.0.1 "hello from wolfssl vaultic_client in TLS 1.2 (using VaultIC${PRODUCT})" 2
${RUN_MODE} ./client_vaultic 127.0.0.1 "hello from wolfssl vaultic_client in TLS 1.3 (using VaultIC${PRODUCT})" 3

echo Request server shutdown ...
${RUN_MODE} ./client_vaultic 127.0.0.1 shutdown
popd

# Return to initial folder
popd
echo -e "\n"
