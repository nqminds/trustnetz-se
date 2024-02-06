#!/bin/bash -e
#exit immediately if a command fails

devKeyFile=./certs/serverKey.der
devCertFile=./certs/serverCert.der
caCertFile=./certs/rootCACert.der

./perso_tls $devKeyFile $devCertFile $caCertFile 
