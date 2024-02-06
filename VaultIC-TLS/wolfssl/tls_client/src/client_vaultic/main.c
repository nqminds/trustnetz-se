/* vaultic_client.c
 *
 * Example of TLS client using a VaultIC Secure Element.
 * based on wolfSSL client-tls example
 * https://github.com/wolfSSL/wolfssl-examples/tree/master/tls/client-tls.c
 
 */

/* the usual suspects */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* socket includes */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>

/* wolfSSL */
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>

/* VaultIC TLS */
#include <wolfssl/wolfcrypt/port/wisekey/vaultic.h>
#include <vaultic_tls.h>

#define DEFAULT_PORT 4433



/* Program usage :
 * vaultic_client <ip_address> <message> <version>
 */


int main(int argc, char** argv)
{
    int                sockfd;
    struct sockaddr_in servAddr;
    char               buff[256];
    size_t             len;
    int                ret;
    char *             ip_address=NULL;
    char *             message=NULL;
    WOLFSSL_METHOD  *  wolfTLS_client_method;

#ifdef DEBUG_WOLFSSL
    wolfSSL_Debugging_ON();
#endif

    /* declare wolfSSL objects */
    WOLFSSL_CTX* ctx;
    WOLFSSL*     ssl;
    
    printf( "\n[wolfssl vaultic_client]\n" );

    /* Manage input arguments */
    if (argc >=2) {    
        /* Get ip address from program arguments */
        ip_address = argv[1];
    } 
    else {
        /* Enter ip address in console */
        printf("Please enter IPv4 server address: ");
        fgets(buff, sizeof(buff), stdin);
        buff[strcspn(buff, "\n")] = 0;
        ip_address = buff;
    }
    
    if (argc >=3) {
        /* Get message from program arguments */
        message = argv[2];
    }
    else {
        /* Message retrieved from console some lines below */
    }

    if (argc >=4) {
        /* Get TLS method from program arguments */
        switch(* argv[3]) {
            case '2':
                wolfTLS_client_method = wolfTLSv1_2_client_method();
                break;

            default:
                wolfTLS_client_method = wolfTLSv1_3_client_method();
                break;
        }
    }
    else {
        /* Use TLS 1.3 by default */
        wolfTLS_client_method = wolfTLSv1_3_client_method();
    }
    
    /* Create a socket that uses an internet IPv4 address,
     * Sets the socket to be stream based (TCP),
     * 0 means choose the default protocol. */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        fprintf(stderr, "ERROR: failed to create the socket\n");
        ret = -1;
        goto end;
    }

    /* Initialize the server address struct with zeros */
    memset(&servAddr, 0, sizeof(servAddr));

    /* Fill in the server address */
    servAddr.sin_family = AF_INET;             /* using IPv4      */
    servAddr.sin_port   = htons(DEFAULT_PORT); /* on DEFAULT_PORT */

    /* Get the server IPv4 address entered */
    if (inet_pton(AF_INET, ip_address, &servAddr.sin_addr) != 1) {
        fprintf(stderr, "ERROR: invalid address\n");
        ret = -1;
        goto end;
    }

    /* Connect to the server */
    if ((ret = connect(sockfd, (struct sockaddr*) &servAddr, sizeof(servAddr)))
         == -1) {
        fprintf(stderr, "ERROR: failed to connect\n");
        goto end;
    }

    /*---------------------------------*/
    /* Start of security */
    /*---------------------------------*/
    
    /* Initialize wolfSSL */
    if ((ret = wolfSSL_Init()) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to initialize the library\n");
        goto socket_cleanup;
    }

    /* Create and initialize WOLFSSL_CTX */
    if ((ctx = wolfSSL_CTX_new(wolfTLS_client_method)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL_CTX\n");
        ret = -1;
        goto socket_cleanup;
    }

    /* Open session with VaultIC */
    if(vlt_tls_init() !=0) {
        fprintf(stderr, "ERROR: vic_tls_init error\n");
        ret = -1;
        goto socket_cleanup;
    }
    
    /* Load VaultIC certificates */
    if(( ret = WOLFSSL_VAULTIC_LoadCertificates(ctx)) != 0) {
        fprintf(stderr, "ERROR: failed to load VaultIC certificates.\n");
        goto ctx_cleanup;
    }

    /* Setup wolfSSL VaultIC callbacks */
    WOLFSSL_VAULTIC_SetupPkCallbacks(ctx);

    /* Create a WOLFSSL object */
    if ((ssl = wolfSSL_new(ctx)) == NULL) {
        fprintf(stderr, "ERROR: failed to create WOLFSSL object\n");
        ret = -1;
        goto ctx_cleanup;
    }

    /* Attach wolfSSL to the socket */
    if ((ret = wolfSSL_set_fd(ssl, sockfd)) != WOLFSSL_SUCCESS) {
        fprintf(stderr, "ERROR: Failed to set the file descriptor\n");
        goto cleanup;
    }

    /* Connect to wolfSSL on the server side */
    if ((ret = wolfSSL_connect(ssl)) != SSL_SUCCESS) {
        fprintf(stderr, "ERROR: failed to connect to wolfSSL\n");
        goto cleanup;
    }

    /* Display TLS connection details*/
    showPeer(ssl);

    printf("\nMessage for server: ");
    memset(buff, 0, sizeof(buff));
    
    if (message != NULL) {
        /* Get a message for the server from prog args */
        strcpy(buff, message);
        printf("%s\n",message);
    }
    else {
        /* Get a message for the server from stdin */        
        if (fgets(buff, sizeof(buff), stdin) == NULL) {
            fprintf(stderr, "ERROR: failed to get message for server\n");
            ret = -1;
            goto cleanup;
        }
    }
    len = strnlen(buff, sizeof(buff));

    /* Send the message to the server */
    if ((ret = wolfSSL_write(ssl, buff, len)) != len) {
        fprintf(stderr, "ERROR: failed to write entire message\n");
        fprintf(stderr, "%d bytes of %d bytes were sent", ret, (int) len);
        goto cleanup;
    }

    /* Read the server data into our buff array */
    memset(buff, 0, sizeof(buff));
    if ((ret = wolfSSL_read(ssl, buff, sizeof(buff)-1)) == -1) {
        fprintf(stderr, "ERROR: failed to read\n");
        goto cleanup;
    }

    /* Print to stdout any data the server sends */
    printf("Server said: %s\n", buff);

    /* Bidirectional shutdown */
    while (wolfSSL_shutdown(ssl) == SSL_SHUTDOWN_NOT_DONE) {
    }

    /* Close connection with VaultIC */
    if(vlt_tls_close()!=0) {
        fprintf(stderr, "ERROR: vlt_tls_close error\n");
    }

    printf("Client Shutdown complete\n\n");

    ret = 0;

    /* Cleanup and return */
cleanup:
    wolfSSL_free(ssl);      /* Free the wolfSSL object                  */
ctx_cleanup:
    wolfSSL_CTX_free(ctx);  /* Free the wolfSSL context object          */
    wolfSSL_Cleanup();      /* Cleanup the wolfSSL environment          */
socket_cleanup:
    close(sockfd);          /* Close the connection to the server       */
end:
    return ret;               /* Return reporting a success               */
}



