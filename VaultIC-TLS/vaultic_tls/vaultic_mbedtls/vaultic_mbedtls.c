#include "mbedtls/platform.h"
#include "vaultic_mbedtls.h"

//implementation limited to to support grp->id = MBEDTLS_ECP_DP_SECP256R1

int mbedtls_vic_init(void)
{
    VIC_LOGD("mbedtls_vic_init");
    return vlt_tls_init();
}

int mbedtls_vic_close(void)
{
    VIC_LOGD("mbedtls_vic_close");
    return vlt_tls_close();
}

int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    (void) f_rng; //unused parameter
    (void) p_rng; //unused parameter
    
    unsigned char sig_R[P256_BYTE_SZ];
    unsigned char sig_S[P256_BYTE_SZ];
	
	VIC_LOGD("mbedtls_ecdsa_sign (using VaultIC)");
	
	if (d == NULL) {
		VIC_LOGD( "mbedtls_ecdsa_sign warning: ecdsa_sign_restartable rs_ctx d null \n" );
	}
	
	if( grp->id != MBEDTLS_ECP_DP_SECP256R1 ){
		VIC_LOGE("mbedtls_ecdsa_sign error: id != MBEDTLS_ECP_DP_SECP256R1" );
		return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
	}

	if( vlt_tls_compute_signature_P256(buf, blen, sig_R, sig_S) != 0) {
		VIC_LOGE("mbedtls_ecdsa_sign error: vlt_tls_compute_signature_P256 failure");
	}

	/* Convert signature to MbedTls format */
	mbedtls_mpi_read_binary(r, sig_R, sizeof(sig_R));
	mbedtls_mpi_read_binary(s, sig_S, sizeof(sig_S));

    return( 0 );
}

int mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,
                          const unsigned char *buf, size_t blen,
                          const mbedtls_ecp_point *Q,
                          const mbedtls_mpi *r,
                          const mbedtls_mpi *s)
{
	unsigned char pubKeyX[P256_BYTE_SZ];
	unsigned char pubKeyY[P256_BYTE_SZ];
	unsigned char signature[2*P256_BYTE_SZ];
	
	VIC_LOGD("mbedtls_ecdsa_verify (using VaultIC)");

	if (!grp || !buf || !Q || !r || !s)
    {
		VIC_LOGE("mbedtls_ecdsa_verify error: Bad Input Data" );
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }
	if( grp->id != MBEDTLS_ECP_DP_SECP256R1 ){
		VIC_LOGE("mbedtls_ecdsa_verify error: id != MBEDTLS_ECP_DP_SECP256R1" );
		return( MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE );
	}

	/* Convert public key to VaultIC format */
	mbedtls_mpi_write_binary(&Q->MBEDTLS_PRIVATE(X), pubKeyX, P256_BYTE_SZ);
	mbedtls_mpi_write_binary(&Q->MBEDTLS_PRIVATE(Y), pubKeyY, P256_BYTE_SZ);
	
	/* Convert signature to VaultIC format */
	mbedtls_mpi_write_binary(r, signature, P256_BYTE_SZ);
	mbedtls_mpi_write_binary(s, signature+P256_BYTE_SZ, P256_BYTE_SZ);

    /* Verify signature with VaultIC */
    if (vlt_tls_verify_signature_P256(buf, blen, signature, pubKeyX, pubKeyY) != 0) {
		VIC_LOGE("mbedtls_ecdsa_verify error: vault_tls_verify_signature_P256 ");
		return -1;
    }

	VIC_LOGD("mbedtls_ecdsa_verify VltVerifySignature success");
	
	return( 0 );
}
#ifdef MBEDTLS_ECDH_GEN_PUBLIC_ALT
/*
 * Generate public key
 */
int mbedtls_ecdh_gen_public( mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    (void) f_rng; //unused parameter
    (void) p_rng; //unused parameter

	unsigned char pubKeyX[P256_BYTE_SZ];
	unsigned char pubKeyY[P256_BYTE_SZ];
	unsigned char pubKeyZ=1;

	VIC_LOGD("mbedtls_ecdh_gen_public (using VaultIC)");
	
    if (!grp || !d || !Q)
    {
        VIC_LOGE("mbedtls_ecdh_gen_public error: Bad Input Data" );
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (grp->id != MBEDTLS_ECP_DP_SECP256R1)
    {
        VIC_LOGE("mbedtls_ecdh_gen_public error: id != MBEDTLS_ECP_DP_SECP256R1" );
    	return  MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

    /* Generate new ephemeral key in VaultIC device */
    if (vlt_tls_keygen_P256(pubKeyX, pubKeyY) != 0) {
    	VIC_LOGE("mbedtls_ecdh_gen_public vtls_tls_keygen_P256");
        return -1;
    }

    /* Convert Public Key to MbedTls format */
    mbedtls_mpi_read_binary(&(Q->MBEDTLS_PRIVATE(X)), pubKeyX, P256_BYTE_SZ);
	mbedtls_mpi_read_binary(&(Q->MBEDTLS_PRIVATE(Y)), pubKeyY, P256_BYTE_SZ);
	mbedtls_mpi_read_binary(&(Q->MBEDTLS_PRIVATE(Z)), &pubKeyZ, 1);

    return 0;
}
#endif

#ifdef MBEDTLS_ECDH_COMPUTE_SHARED_ALT
int mbedtls_ecdh_compute_shared( mbedtls_ecp_group *grp, mbedtls_mpi *z, const mbedtls_ecp_point *Q, const mbedtls_mpi *d, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    (void) f_rng; //unused parameter
    (void) p_rng; //unused parameter

	unsigned char otherPubKeyX[P256_BYTE_SZ];
	unsigned char otherPubKeyY[P256_BYTE_SZ];
	unsigned char sharedSecret[P256_BYTE_SZ];
	int ret;
	
	VIC_LOGD("mbedtls_ecdh_compute_shared (using VaultIC)");

    if (!grp || !z || !Q || !d)
    {
    	VIC_LOGE("mbedtls_ecdh_compute_shared error: Bad Input Data" );
        ret = MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    }

    if (grp->id != MBEDTLS_ECP_DP_SECP256R1)
    {
        VIC_LOGE("mbedtls_ecdh_compute_shared error: id != MBEDTLS_ECP_DP_SECP256R1" );
        ret = MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    }

	/* Convert "other" public key to VaultIC format */
	mbedtls_mpi_write_binary(&Q->MBEDTLS_PRIVATE(X), otherPubKeyX, P256_BYTE_SZ);
	mbedtls_mpi_write_binary(&Q->MBEDTLS_PRIVATE(Y), otherPubKeyY, P256_BYTE_SZ);

	/* Compute shared secret with VaultIC*/
	if (vlt_tls_compute_shared_secret_P256( otherPubKeyX, otherPubKeyY, sharedSecret) != 0)  {
		VIC_LOGE("mbedtls_ecdh_compute_shared error: vlt_tls_ecdh_compute_shared");
		return -1;
	}

	/* Convert shared secret to MbedTls format */
	ret = mbedtls_mpi_read_binary(z, sharedSecret, sizeof(sharedSecret));
	
	return( ret );
}
#endif

int mbedtls_vic_read_cert(mbedtls_x509_crt * cert, ssl_vic_cert_type cert_type)
{
	unsigned char * cert_buf=NULL;
	int cert_size;

	VIC_LOGD("Reading Certificate in VaultIC");

	// read certificate size in vaultic
	if ((cert_size = vlt_tls_get_cert_size(cert_type)) <= 0){
		VIC_LOGE("mbedtls_vic_read_cert size error ");
		return -1;
	}

	// allocate buffer to store certificate
	if (NULL == (cert_buf = mbedtls_calloc(1, cert_size)))
	{
		return -1;
	}

	// read certificate in vaultic
	if (vlt_tls_read_cert(cert_buf, cert_type) < 0){
		VIC_LOGE("mbedtls_vic_read_cert error ");
		mbedtls_free(cert_buf);
		return -1;
	}

	// initialize certificate in mbedtls
	VIC_LOGD("Initializing Certificate in MbedTls");
	int ret = mbedtls_x509_crt_parse( cert, cert_buf, cert_size);
	mbedtls_free(cert_buf);

	if(ret !=0)	{
		VIC_LOGE("mbedtls_vic_read_cert error: mbedtls_x509_crt_parse");
		return ret;
	}

	return 0;
}


int mbedtls_vic_get_pk(mbedtls_pk_context *key)
{
    unsigned char au8Qx[P256_BYTE_SZ]={0};
    unsigned char au8Qy[P256_BYTE_SZ]={0};
    mbedtls_ecp_keypair *ecp = NULL;

    // set up ECC key context
    if (mbedtls_pk_setup(key,
                         mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))
                        !=0 )
    {
        VIC_LOGE("mbedtls_vic_read_pub_key error: mbedtls_pk_setup");
        return -1;
    }

    // get pointer on ecc key pair
    if( (ecp=  mbedtls_pk_ec( *key )) == NULL)
    {
        VIC_LOGE("mbedtls_vic_read_pub_key error: mbedtls_pk_ec");
        return -1;
    }

    // Initialize domain parameter
    if(mbedtls_ecp_group_load(&ecp->private_grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
    {
        VIC_LOGE("mbedtls_vic_read_pub_key error: mbedtls_ecp_group_load");
        return -1;
    }

    // Read public key in VaultIC
    if(vlt_tls_read_pub_key_P256(au8Qx, au8Qy) != 0)
	{
        VIC_LOGE("mbedtls_vic_read_pub_key error: vlt_tls_read_pub_key_P256");
        return -1;
	}

	// Import public key in key structure
    if(mbedtls_mpi_read_binary(&(ecp->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X)), au8Qx, P256_BYTE_SZ) != 0)
	{
        VIC_LOGE("mbedtls_vic_read_pub_key error: mbedtls_mpi_read_binary Qx");
        return -1;
	}

    if(mbedtls_mpi_read_binary(&(ecp->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Y)), au8Qy, P256_BYTE_SZ) != 0)
    {
        VIC_LOGE("mbedtls_vic_read_key error: mbedtls_mpi_read_binary Qx");
        return -1;
    }

    if(mbedtls_mpi_lset(&(ecp->MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(Z)), 1 ) != 0)
    {
        VIC_LOGE("mbedtls_vic_read_key error: mbedtls_mpi_lset Qz");
        return -1;
    }

	return 0;
}



