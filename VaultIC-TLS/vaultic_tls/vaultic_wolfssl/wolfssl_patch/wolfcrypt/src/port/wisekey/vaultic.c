
#ifndef HAVE_PK_CALLBACKS
#error Please define HAVE_PK_CALLBACKS in compiling options
#endif 

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/port/wisekey/vaultic.h>

#include "vaultic_common.h"
#include "vaultic_tls.h"

#define P256_BYTE_SZ 32

#ifndef VLT_TLS_NO_ECDH
/**
 * \brief Key Gen Callback (used by TLS server)
 */
int WOLFSSL_VAULTIC_EccKeyGenCb(WOLFSSL* ssl, ecc_key* key, word32 keySz, int ecc_curve, void* ctx)
{
    int err;
    byte pubKeyX[P256_BYTE_SZ]={0};
    byte pubKeyY[P256_BYTE_SZ]={0};

    (void)ssl;
    (void)ctx;

    VIC_LOGD("WOLFSSL_VAULTIC_EccKeyGenCb");

    /* check requested curve params */
    if( ecc_curve != ECC_SECP256R1 ){
        VIC_LOGE("ecc_curve != ECC_SECP256R1");
        return( NOT_COMPILED_IN );
    }
    if( keySz != P256_BYTE_SZ ){
        VIC_LOGE("keysize != 32. We are supporting ECC P256 case only");
        return( NOT_COMPILED_IN );
    }

    /* generate new ephemeral key on device */
    if (vlt_tls_keygen_P256(pubKeyX, pubKeyY) != 0) {
        VIC_LOGE("vtls_tls_keygen_P256");
        return WC_HW_E;
    }

    /* load generated public key into key, used by wolfSSL */
    if( (err = wc_ecc_import_unsigned(key, pubKeyX, pubKeyY,  NULL, ecc_curve)) != 0) {
        VIC_LOGE("wc_ecc_import_unsigned");
    }

    return err;
}
#endif

/**
 * \brief Verify Certificate Callback.
 *
 */
int WOLFSSL_VAULTIC_EccVerifyCb(WOLFSSL* ssl,
                                const unsigned char* sig, unsigned int sigSz,
                                const unsigned char* hash, unsigned int hashSz,
                                const unsigned char* keyDer, unsigned int keySz,
                                int* result, void* ctx)
{
    int err;
    byte signature[2*P256_BYTE_SZ]={0};
    byte *r, *s;
    word32 r_len = P256_BYTE_SZ, s_len = P256_BYTE_SZ;
    byte pubKeyX[P256_BYTE_SZ]={0};
    byte pubKeyY[P256_BYTE_SZ]={0};
    word32 pubKeyX_len = sizeof(pubKeyX);
    word32 pubKeyY_len = sizeof(pubKeyY);
    ecc_key key;
    word32 inOutIdx = 0;

    VIC_LOGD("WOLFSSL_VAULTIC_EccVerifyCb");

    (void)ssl;
    (void)ctx;
    *result=0;

    if (keyDer == NULL || sig == NULL || hash == NULL || result == NULL) {
        return BAD_FUNC_ARG;
    }

    if ( (err = wc_ecc_init(&key)) != 0) {
        VIC_LOGE("wc_ecc_init");
        return err;
    }

    /* Decode the public key */
    if( (err = wc_EccPublicKeyDecode(keyDer, &inOutIdx, &key, keySz)) !=0) {
        VIC_LOGE("wc_EccPublicKeyDecode");
        wc_ecc_free(&key);
        return err;
    }

    /* Extract Raw X and Y coordinates of the public key */
    if( (err = wc_ecc_export_public_raw(&key, pubKeyX, &pubKeyX_len,
        pubKeyY, &pubKeyY_len)) !=0) {
        VIC_LOGE("wc_ecc_export_public_raw");
        wc_ecc_free(&key);
        return err;
    }
    
    /* Left pad public key */
    vlt_tls_left_pad_P256(pubKeyX, pubKeyX_len);
    vlt_tls_left_pad_P256(pubKeyY, pubKeyY_len);

    /* Check requested curve */
    if( key.dp->id != ECC_SECP256R1 ){
        VIC_LOGE("id != ECC_SECP256R1");
        wc_ecc_free(&key);
        return NOT_COMPILED_IN ;
    }
        
    /* Extract R and S from signature */
    XMEMSET(signature, 0, sizeof(signature));
    r = &signature[0];
    s = &signature[sizeof(signature)/2];
    err = wc_ecc_sig_to_rs(sig, sigSz, r, &r_len, s, &s_len);
    wc_ecc_free(&key);
    if(err !=0) {
        VIC_LOGE("wc_ecc_sig_to_rs");
        return err;
    }
    
    /* Left pad r & s */
    vlt_tls_left_pad_P256(r, r_len);
    vlt_tls_left_pad_P256(s, s_len);

    /* Verify signature with VaultIC */
    if (vlt_tls_verify_signature_P256(hash, hashSz, signature, pubKeyX, pubKeyY) != 0) {
        VIC_LOGE("vault_tls_verify_signature_P256");
        return WC_HW_E;
    }
    else {
        *result=1;
        return 0;
    }
}


/**
 * \brief Sign Certificate Callback.
 */
int WOLFSSL_VAULTIC_EccSignCb(WOLFSSL* ssl, const byte* in,
                                 word32 inSz, byte* out, word32* outSz,
                                 const byte* key, word32 keySz, void* ctx)
{
    int err;
    (void)ssl;
    (void)ctx;

    byte sig_R[P256_BYTE_SZ]={0};
    byte sig_S[P256_BYTE_SZ]={0};

    VIC_LOGD("WOLFSSL_VAULTIC_EccSignCb");

    /* Sign input message using VaultIC */
    if (vlt_tls_compute_signature_P256(in , inSz, sig_R , sig_S) !=0) {
        VIC_LOGE("vlt_tls_compute_signature_P256");
        return WC_HW_E;
    }

    /* Convert R and S to signature */
    if( (err=wc_ecc_rs_raw_to_sig(sig_R, P256_BYTE_SZ, sig_S, P256_BYTE_SZ, out, outSz)) != 0) {
        VIC_LOGE("wc_ecc_rs_raw_to_sig");
        return err;
    }

    return err;
}

#ifndef VLT_TLS_NO_ECDH
/**
 * \brief Create pre master secret using peer's public key and self private key.
 */
int WOLFSSL_VAULTIC_EccSharedSecretCb(WOLFSSL* ssl, ecc_key* otherPubKey,
                              unsigned char* pubKeyDer, unsigned int* pubKeySz,
                              unsigned char* out, unsigned int* outlen,
                              int side, void* ctx)
{
    VIC_LOGD("WOLFSSL_VAULTIC_EccSharedSecretCb");

    int err;
    byte otherPubKeyX[P256_BYTE_SZ]={0};
    byte otherPubKeyY[P256_BYTE_SZ]={0};
    word32 otherPubKeyX_len = sizeof(otherPubKeyX);
    word32 otherPubKeyY_len = sizeof(otherPubKeyY);
    byte pubKeyX[P256_BYTE_SZ]={0};
    byte pubKeyY[P256_BYTE_SZ]={0};

    ecc_key tmpKey;

    (void)ssl;
    (void)ctx;

    /* check requested curve */
    if( otherPubKey->dp->id != ECC_SECP256R1 ){
        VIC_LOGE("id != ECC_SECP256R1");
        return( NOT_COMPILED_IN );
    }

    /* for client: create and export public key */
    if (side == WOLFSSL_CLIENT_END) {

        /* Export otherPubKey raw X and Y */
        err = wc_ecc_export_public_raw(otherPubKey,
            &otherPubKeyX[0], (word32*)&otherPubKeyX_len,
            &otherPubKeyY[0], (word32*)&otherPubKeyY_len);
        if (err != 0) {
            VIC_LOGE("wc_ecc_export_public_raw");
            return err;
        }
        vlt_tls_left_pad_P256(otherPubKeyX, otherPubKeyX_len);
        vlt_tls_left_pad_P256(otherPubKeyY, otherPubKeyY_len);


        /* TLS v1.2 and older we must generate a key here for the client only.
         * TLS v1.3 calls key gen early with key share */
        if (wolfSSL_GetVersion(ssl) < WOLFSSL_TLSV1_3) {

            if (vlt_tls_keygen_P256(pubKeyX, pubKeyY) != 0) {
                VIC_LOGE("vlt_tls_keygen_P256");
                return WC_HW_E;
            }

            /* convert raw unsigned public key to X.963 format for TLS */
            if ( (err = wc_ecc_init(&tmpKey)) != 0) {
                VIC_LOGE("wc_ecc_init");
                return err;
            }            
            
            if( (err = wc_ecc_import_unsigned(&tmpKey, pubKeyX, pubKeyY,
                NULL, ECC_SECP256R1)) != 0) {
                VIC_LOGE("wc_ecc_import_unsigned");
                wc_ecc_free(&tmpKey);
                return err;
            }                    

            if( (err = wc_ecc_export_x963(&tmpKey, pubKeyDer, pubKeySz)) !=0) {
                VIC_LOGE("wc_ecc_import_unsigned\n");
                wc_ecc_free(&tmpKey);
                return err;
            }

            wc_ecc_free(&tmpKey);
        }
    }

    /* for server: import public key */
    else if (side == WOLFSSL_SERVER_END) {
        if ( (err = wc_ecc_init(&tmpKey)) != 0) {
            VIC_LOGE("wc_ecc_init");
            return err;
        }            

        /* import peer's key and export as raw unsigned for hardware */
        if( (err = wc_ecc_import_x963_ex(pubKeyDer, *pubKeySz, &tmpKey, ECC_SECP256R1))!=0) {
            VIC_LOGE("wc_ecc_import_x963_ex");
            return err;
        }

        if( (err = wc_ecc_export_public_raw(&tmpKey, otherPubKeyX, &otherPubKeyX_len,
            otherPubKeyY, &otherPubKeyY_len)) !=0 ) {
            VIC_LOGE("wc_ecc_export_public_raw");
            wc_ecc_free(&tmpKey);
            return err;
        }
        vlt_tls_left_pad_P256(otherPubKeyX, otherPubKeyX_len);
        vlt_tls_left_pad_P256(otherPubKeyY, otherPubKeyY_len);
        
        wc_ecc_free(&tmpKey);
    }
    else {
        return BAD_FUNC_ARG;
    }

    /* Compute shared secret */
    if (vlt_tls_compute_shared_secret_P256(otherPubKeyX, otherPubKeyY, out)  != 0)  {
        VIC_LOGE("vlt_tls_compute_shared_secret_P256");
        return WC_HW_E;
    }

    *outlen = P256_BYTE_SZ;

    return 0;
}
#endif

/**
 * \brief Read VaultIC Certificates and add them to wolfssl context
 */
int WOLFSSL_VAULTIC_LoadCertificates(WOLFSSL_CTX* ctx) 
{
    int ret = -1;
    
    // CA certificate
    unsigned char *ca_cert= NULL;
    int sizeof_ca_cert=0;

    // Device certificate
    unsigned char *device_cert= NULL;
    int sizeof_device_cert=0;
    
    /* Read Device certificate in VaultIC */
    VIC_LOGD("Read Device Certificate in VaultIC");
    
    if ((sizeof_device_cert = vlt_tls_get_cert_size(SSL_VIC_DEVICE_CERT)) == -1) {
        VIC_LOGE("No Device Certificate found in VaultIC");
        return -1;
    }

    device_cert = XMALLOC(sizeof_device_cert, NULL, DYNAMIC_TYPE_ECC_BUFFER);

    if (vlt_tls_read_cert(device_cert, SSL_VIC_DEVICE_CERT) !=0 ) {
        VIC_LOGE("vlt_tls_read_cert Device");
        goto free_cert_buffers;
    }

    VIC_LOGD("\n[Device certificate]");
    VIC_LOGD_PRINT_BUFFER(device_cert, sizeof_device_cert);

    /* Read CA certificate in VaultIC */
    VIC_LOGD("Read CA Certificate in VaultIC");
    if ((sizeof_ca_cert = vlt_tls_get_cert_size(SSL_VIC_CA_CERT)) == -1) {
        VIC_LOGE("No CA Certificate found in VaultIC");
        goto free_cert_buffers;
    }

    ca_cert = XMALLOC(sizeof_ca_cert, NULL, DYNAMIC_TYPE_ECC_BUFFER);

    if (vlt_tls_read_cert(ca_cert, SSL_VIC_CA_CERT) !=0 ) {
        VIC_LOGE("vlt_tls_read_cert CA");
        goto free_cert_buffers;
    }

    VIC_LOGD("\n[CA certificate]");
    VIC_LOGD_PRINT_BUFFER(ca_cert, sizeof_ca_cert);

    /* Load CA certificate into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_load_verify_buffer(ctx, ca_cert,
        sizeof_ca_cert, WOLFSSL_FILETYPE_ASN1)) != SSL_SUCCESS) {
        VIC_LOGE("failed to load CA certificate %s",wc_GetErrorString(ret));
        goto free_cert_buffers;
    }

    if(ca_cert != NULL) XFREE(ca_cert,NULL, DYNAMIC_TYPE_ECC_BUFFER);

    /* Load Device certificate into WOLFSSL_CTX */
    if ((ret = wolfSSL_CTX_use_certificate_buffer(ctx, device_cert,
        sizeof_device_cert, WOLFSSL_FILETYPE_ASN1)) != SSL_SUCCESS) {
        VIC_LOGE("failed to load Device certificate %s",wc_GetErrorString(ret));
        goto free_cert_buffers;
    }
    
    /* VaultIC certificates successfully injected into wolfSSL */
    ret = 0;

free_cert_buffers:
    if(device_cert != NULL) XFREE(device_cert,NULL, DYNAMIC_TYPE_ECC_BUFFER);
    
    return ret;
}


int WOLFSSL_VAULTIC_SetupPkCallbacks(WOLFSSL_CTX* ctx)
{
    wolfSSL_CTX_SetEccSignCb(ctx, WOLFSSL_VAULTIC_EccSignCb);
    wolfSSL_CTX_SetEccVerifyCb(ctx, WOLFSSL_VAULTIC_EccVerifyCb);
#ifndef VLT_TLS_NO_ECDH
    wolfSSL_CTX_SetEccKeyGenCb(ctx, WOLFSSL_VAULTIC_EccKeyGenCb);    
    wolfSSL_CTX_SetEccSharedSecretCb(ctx, WOLFSSL_VAULTIC_EccSharedSecretCb);
#endif
    return 0;
}

int WOLFSSL_VAULTIC_SetupPkCallbackCtx(WOLFSSL* ssl, void* user_ctx)
{
#ifndef VLT_TLS_NO_ECDH
    wolfSSL_SetEccKeyGenCtx(ssl, user_ctx);
    wolfSSL_SetEccSharedSecretCtx(ssl, user_ctx);
#endif
    wolfSSL_SetEccSignCtx(ssl, user_ctx);
    wolfSSL_SetEccVerifyCtx(ssl, user_ctx);
    return 0;
}

