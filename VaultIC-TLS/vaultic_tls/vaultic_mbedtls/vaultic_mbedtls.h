#ifndef VIC_MBEDTLS_HARDWARE_H
#define VIC_MBEDTLS_HARDWARE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "mbedtls/ecp.h"
#include "mbedtls/x509_crt.h"

#include "vaultic_tls.h"

/* Definition of public functions */
int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int mbedtls_ecdh_gen_public( mbedtls_ecp_group *grp, mbedtls_mpi *d, mbedtls_ecp_point *Q, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int mbedtls_ecdsa_verify( mbedtls_ecp_group *grp, const unsigned char *buf, size_t blen, const mbedtls_ecp_point *Q, const mbedtls_mpi *r, const mbedtls_mpi *s);

int mbedtls_ecdh_compute_shared( mbedtls_ecp_group *grp, mbedtls_mpi *z, const mbedtls_ecp_point *Q, const mbedtls_mpi *d, int (*f_rng)(void *, unsigned char *, size_t), void *p_rng );

int mbedtls_vic_read_cert(mbedtls_x509_crt * cert, ssl_vic_cert_type cert_type);
int mbedtls_vic_get_pk(mbedtls_pk_context *key);
int mbedtls_vic_init(void);
int mbedtls_vic_close(void);

#endif /* MBEDTLS_HARDWARE_H */
