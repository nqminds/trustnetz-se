#!/bin/bash -e
#exit immediately if a command fails

devKeyFile=./certs/deviceKey.der
devCertFile=./certs/deviceCert.der
caCertFile=./certs/rootCACert.der

./perso_tls $devKeyFile $devCertFile $caCertFile 
