#!/bin/bash -e
#exit immediately if a command fails

# Go to scripts folder
SCRIPT_DIR=$(dirname "$0")
pushd ${SCRIPT_DIR}

# Go to demos folder
pushd ../../..

# Retrieve settings from config file 
source get_config.sh

# Go to tls kit root folder
pushd ..

# Personalize the VaultIC with client certificates
pushd VaultIC-TLS/vaultic_tls/vaultic_tls-${FAMILY}/apps/build/
echo -e "\n"

echo Running Perso app with client config ...
pushd perso_tls
chmod +rwx ./perso_client.sh
${RUN_MODE} ./perso_client.sh
popd

# Check the perso of the VaultIC 
echo Running TLS Check app ...
pushd check_tls_perso
${RUN_MODE} ./check_tls_perso
popd


# Return to scripts folder
popd
popd
popd

# Return to initial folder
popd
echo -e "\n"

