#!/usr/bin/env bash
set -exo pipefail

#export TPM2TOOLS_TCTI="mssim:host=localhost,port=2321"

# perform tpm startup
tpm2_startup -c
# clear tpm
tpm2_clear -c p
# create primary key under owner hierarchy
tpm2_createprimary -g sha256 -G ecc_nist_p256 -c primary.ctx
# make primary key persisted at handle 0x81000000
tpm2_evictcontrol -c primary.ctx 0x81000000
# remove all transient objects
tpm2_flushcontext -t
# create and output an rsa keypair (rsakey.pub, rsakey.priv) which is protected by the primary key
# tpm2_create -G rsa3072 -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign|noda" -C 0x81000000 -u rsakey.pub -r rsakey.priv
tpm2_create -g sha256 -G ecc_nist_p256 -a "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign|noda" -C 0x81000000 -u ecc_key.pub -r ecc_key.priv

# Attributes: "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|decrypt|sign|noda"

# fixedtpm and fixedparent: These attributes ensure the key cannot be duplicated to another TPM or under another parent key.
# sensitivedataorigin: Indicates that the private portion of the key was generated by the TPM.
# userwithauth: Means that authorization is required to use this key.
# noda: No dictionary attack protection is required for this key.
# decrypt and sign: The key can be used for decryption and signing operations.


# remove all transient objects
tpm2_flushcontext -t
# load the rsa keypair into tpm 
tpm2_load -C primary.ctx -u ecc_key.pub -r ecc_key.priv -c ecc_key.ctx
# make rsa keypair persisted at handle 0x81000001
tpm2_evictcontrol -c ecc_key.ctx 0x81000001
# remove all transient objects
tpm2_flushcontext -t
