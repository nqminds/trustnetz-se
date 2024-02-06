
#include <stdio.h>
#include <stdlib.h>
#include <vaultic_common.h>
#include <vaultic_tls.h>

#define CHECK_STATUS(label,a) {	VIC_LOGD(label);\
								int ret_status= (a);\
							 	if (ret_status!= 0) {VIC_LOGE("%s error %4.4x",label,ret_status);return 1;}\
							}

int main(void)
{

    // CA certificate
    unsigned char *ca_cert= NULL;
    int sizeof_ca_cert=0;
    
    // Device certificate
    unsigned char *device_cert= NULL;
    int sizeof_device_cert=0;
    
    /* Open session with VaultIC */
    CHECK_STATUS("vlt_tls_init", vlt_tls_init());
    
    /* Read Device certificate in VaultIC */
    VIC_LOGD("\nRead Device Certificate in VaultIC\n");
    sizeof_device_cert = vlt_tls_get_cert_size(SSL_VIC_DEVICE_CERT);
    if (sizeof_device_cert > 0) {
        device_cert = malloc(sizeof_device_cert);
        CHECK_STATUS("vlt_tls_read_cert device" , vlt_tls_read_cert(device_cert, SSL_VIC_DEVICE_CERT));

        VIC_LOGD("[Device certificate]");
        VIC_LOGD_PRINT_BUFFER(device_cert, sizeof_device_cert);
    }
    else {
    	VIC_LOGE("(no Device Certificate found in VaultIC)\n");
    }
    
    /* Read CA certificate in VaultIC */
    VIC_LOGD("\nRead CA Certificate in VaultIC\n");
    sizeof_ca_cert = vlt_tls_get_cert_size(SSL_VIC_CA_CERT);
    if (sizeof_ca_cert > 0) {
        ca_cert = malloc(sizeof_ca_cert);
        CHECK_STATUS("vlt_tls_read_cert CA" ,  vlt_tls_read_cert(ca_cert, SSL_VIC_CA_CERT));
        
        VIC_LOGD("[CA certificate]");
        VIC_LOGD_PRINT_BUFFER(ca_cert, sizeof_ca_cert);
    }
    else {
        VIC_LOGE("\n(no CA Certificate found in VaultIC)\n");
    }    

    if(ca_cert != NULL) free(ca_cert);
    if(device_cert != NULL)free(device_cert);

    /* Close session with VaultIC */
    CHECK_STATUS("vlt_tls_close", vlt_tls_close());

    return 0;
}
