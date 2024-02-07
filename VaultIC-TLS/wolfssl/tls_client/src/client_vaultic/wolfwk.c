#include <stdio.h>
#include <string.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include "vaultic_common.h"
#include "vaultic_tls.h"


int generate_key_pair();


int main(int argc, char** argv) {
    if (argc != 2 || strcmp(argv[1], "-genkeypair") != 0) {
        printf("Usage: wolfvaultutil -genkeypair\n");
        return -1;
    }
    
    return generate_key_pair();
}

int generate_key_pair() {
    int ret;
    WOLFSSL_CTX* ctx;
    byte pubKeyX[P256_BYTE_SZ] = {0};
    byte pubKeyY[P256_BYTE_SZ] = {0};

      // Declare signature arrays
    unsigned char pu8SigR[P256_BYTE_SZ] = {0};
    unsigned char pu8SigS[P256_BYTE_SZ] = {0};

    /* Initialize wolfSSL */
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        VIC_LOGE("ERROR: Failed to initialize the library\n");
        return -1;
    }

    /* Create and initialize WOLFSSL_CTX */
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL) {
        VIC_LOGE("ERROR: failed to create WOLFSSL_CTX\n");
        wolfSSL_Cleanup();
        return -1;
    }

    /* Open session with VaultIC */
    if (vlt_tls_init() != 0) {
        VIC_LOGE("ERROR: vlt_tls_init error\n");
        wolfSSL_CTX_free(ctx);
        wolfSSL_Cleanup();
        return -1;
    }

    /* Generate key pair on VaultIC */
    if (vlt_tls_keygen_P256(pubKeyX, pubKeyY) != 0) {
        VIC_LOGE("ERROR: Failed to generate key pair\n");
        goto cleanup;
    }

    /* Print the generated public key */
    printf("Public Key X: ");
    for(int i = 0; i < P256_BYTE_SZ; i++) {
        printf("%02X", pubKeyX[i]);
    }
    printf("\nPublic Key Y: ");
    for(int i = 0; i < P256_BYTE_SZ; i++) {
        printf("%02X", pubKeyY[i]);
    }
    printf("\n");

    // Clear the buffers to demonstrate reading the key
    memset(pubKeyX, 0, P256_BYTE_SZ);
    memset(pubKeyY, 0, P256_BYTE_SZ);

    /* Read the public key from VaultIC and print it */
    if (vlt_tls_read_pub_key_P256(pubKeyX, pubKeyY) != 0) {
        VIC_LOGE("ERROR: Failed to read public key\n");
        goto cleanup;
    }

    /* Print the public key read from VaultIC */
    printf("Read Public Key X: ");
    for(int i = 0; i < P256_BYTE_SZ; i++) {
        printf("%02X", pubKeyX[i]);
    }
    printf("\nRead Public Key Y: ");
    for(int i = 0; i < P256_BYTE_SZ; i++) {
        printf("%02X", pubKeyY[i]);
    }
    printf("\n");

    // here we can also pass in a precomputed hash
    const unsigned char message[] = "This is a test message.";
    int messageLength = sizeof(message) - 1; // Exclude null terminator


    // Sign the message
    if (vlt_tls_compute_signature_P256(message, messageLength, pu8SigR, pu8SigS) != 0) {
        VIC_LOGE("ERROR: Failed to compute signature\n");
        goto cleanup;
    }

    // Print the message
    printf("Message: %s\n", message);

    // Print the signature
    printf("Signature R: ");
    for(int i = 0; i < P256_BYTE_SZ; i++) {
        printf("%02X", pu8SigR[i]);
    }
    printf("\nSignature S: ");
    for(int i = 0; i < P256_BYTE_SZ; i++) {
        printf("%02X", pu8SigS[i]);
    }
    printf("\n");

cleanup:
    /* Close connection with VaultIC */
    if (vlt_tls_close() != 0) {
        VIC_LOGE("ERROR: vlt_tls_close error\n");
    }

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return 0;
}

// output:

// Public Key X: 094E4D1AB86FE858001BCBB515A94D7503C4651A224368B157EB9587BBD90BF7
// Public Key Y: 964DEAF0C6538F77D21A4F46B41F151AAC675C5B6EE756AF74BA4BCDEBD3F34F
// Read Public Key X: B3100BC7F44C0F35B21B881720F7806536D9EEC6EF32A6401EF676053B4567A1
// Read Public Key Y: 9080F55E8F3E76523E7DE573C3C69D17D1B3553068BB80DE82D633045C421EBF
// Message: This is a test message.
// Signature R: 59775226B256E5118D909744D85AC7B937E8DDD42BDD3411362A4FA934303968
// Signature S: A2A3993C9F56103BE8396B355A8E758B7CE0BC6D6E513BC8A9ACD926862D4313