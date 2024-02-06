/**
* @file	   vaultic_cipher_tests.c
*
* @note    THIS PRODUCT IS SUPPLIED FOR EVALUATION, TESTING AND/OR DEMONSTRATION PURPOSES ONLY.
*
* @note    <b>DISCLAIMER</b>
*
* @note    Copyright (C) 2017 Wisekey
*
* @note    All products are provided by Wisekey subject to Wisekey Evaluation License Terms and Conditions
* @note    and the provisions of any agreements made between Wisekey and the Customer concerning the same
* @note    subject matter.
* @note    In ordering a product covered by this document the Customer agrees to be bound by those Wisekey's
* @note    Evaluation License Terms and Conditions and agreements and nothing contained in this document
* @note    constitutes or forms part of a contract (with the exception of the contents of this disclaimer notice).
* @note    A copy of Wisekey's Evaluation License Terms and Conditions is available on request. Export of any
* @note    Wisekey product outside of the EU may require an export license.
*
* @note    The information in this document is provided in connection with Wisekey products. No license,
* @note    express or implied, by estoppel or otherwise, to any intellectual property right is granted by this
* @note    document or in connection with the provisions of Wisekey products.
*
* @note    Wisekey makes no representations or warranties with respect to the accuracy or completeness of the
* @note    contents of this document and reserves the right to make changes to specifications and product
* @note    descriptions at any time without notice.
*
* @note    THE PRODUCT AND THE RELATED DOCUMENTATION ARE PROVIDED "AS IS", AND CUSTOMER UNDERSTANDS
* @note    THAT IT ASSUMES ALL RISKS IN RELATION TO ITS USE OF THE PRODUCT AND THE PRODUCT'S
* @note    QUALITY AND PERFORMANCE.
*
* @note    EXCEPT AS SET FORTH IN INSIDE SECURE'S EVALUATION LICENSE TERMS AND CONDITIONS OR IN ANY
* @note    AGREEMENTS MADE BETWEEN WISEKEY AND THE CUSTOMER CONCERNING THE SAME SUBJECT MATTER,
* @note    WISEKEY OR ITS SUPPLIERS OR LICENSORS ASSUME NO LIABILITY WHATSOEVER. CUSTOMER
* @note    AGREES AND ACKNOWLEDGES THAT WISEKEY SHALL HAVE NO RESPONSIBILITIES TO CUSTOMER TO
* @note    CORRECT ANY DEFECTS OR PROBLEMS IN THE PRODUCT OR THE RELATED DOCUMENTATION, OR TO
* @note    ENSURE THAT THE PRODUCT OPERATES PROPERLY.  WISEKEY DISCLAIMS ANY AND ALL WARRANTIES
* @note    WITH RESPECT TO THE PRODUCT AND THE RELATED DOCUMENTATION, WHETHER EXPRESS, STATUTORY
* @note    OR IMPLIED INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTY OF MERCHANTABILITY,
* @note    SATISFACTORY QUALITY, FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT.
*
* @note    WISEKEY SHALL HAVE NO LIABILITY WHATSOEVER TO CUSTOMER IN CONNECTION WITH THIS
* @note    WISEKEY'S EVALUATION TERMS AND CONDITIONS, INCLUDING WITHOUT LIMITATION, LIABILITY FOR
* @note    ANY PROBLEMS IN OR CAUSED BY THE PRODUCT OR THE RELATED DOCUMENTATION, WHETHER DIRECT,
* @note    INDIRECT, CONSEQUENTIAL, PUNITIVE, EXEMPLARY, SPECIAL OR INCIDENTAL DAMAGES (INCLUDING,
* @note    WITHOUT LIMITATION, DAMAGES FOR LOSS OF PROFITS, LOSS OF REVENUE, BUSINESS INTERRUPTION,
* @note    LOSS OF GOODWILL, OR LOSS OF INFORMATION OR DATA) NOTWITHSTANDING THE THEORY OF
* @note    LIABILITY UNDER WHICH SAID DAMAGES ARE SOUGHT, INCLUDING BUT NOT LIMITED TO CONTRACT,
* @note    TORT (INCLUDING NEGLIGENCE), PRODUCTS LIABILITY, STRICT LIABILITY, STATUTORY LIABILITY OR
* @note    OTHERWISE, EVEN IF WISEKEY HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
*
*/

#include "vaultic_common.h"
#include "vaultic_symmetric_signer.h"
#include "vaultic_cipher.h"
#include "vaultic_mem.h"
#include "vaultic_AES.h"
#include "vaultic_padding.h"
#include "vaultic_utils.h"
#include "vaultic_signer_aes_cmac.h"


/**
 * TODO: All the tests here are "cut and paste" driven. 
 * These test lend themselves very nicely to being data
 * driven. This is something that MUST be done before
 * we can ship the product out of the door !
 */

/**
 * Conditional Compilation Flag to 
 * add or remove the tests for 
 * all the ciphers supported. 
 */
#if( VLT_ENABLE_CIPHER_TESTS )

#if (VLT_ENABLE_CIPHER_AES == VLT_ENABLE)

VLT_STS DoAES192_CBC_NoPadding()
{
    VLT_STS status = VLT_FAIL ;
    VLT_CIPHER_PARAMS theParams = {0};
    VLT_KEY_BLOB theKey = {0};
    VLT_U32 textCapacity = 64;
    VLT_U32 textLength;
    VLT_U8 text[64];
    
    VLT_U8 vectorIV[] = 
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    VLT_U8 vectorKey[] = 
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x11, 0x13, 0x15, 0x67, 0x89, 0xAB, 0xCD, 0x0F
    };

    VLT_U8 vectorPlainText[] = 
    {
        0x54, 0x68, 0x65, 0x20, 0x67, 0x6f, 0x64, 0x73, 
        0x20, 0x74, 0x6f, 0x6f, 0x20, 0x61, 0x72, 0x65, 
        0x20, 0x66, 0x6f, 0x6e, 0x64, 0x20, 0x6f, 0x66, 
        0x20, 0x61, 0x20, 0x6a, 0x6f, 0x6b, 0x65, 0x00 

    };

    VLT_U8 vectorCipherText[] = 
    {
        0xbc, 0x2b, 0x37, 0x6a, 0x67, 0x2c, 0x28, 0xc5, 
        0x6a, 0xb4, 0x06, 0xc6, 0xda, 0x28, 0xca, 0xc1,
        0xd6, 0x57, 0xbe, 0x9f, 0xe7, 0x19, 0xcb, 0x7d, 
        0xcc, 0x8e, 0x21, 0x9f, 0xe0, 0x97, 0xf8, 0x4f
    };

    /**
     * Algorithm AES 192
     * Padding None
     * Block Mode CBC 
     */
    theParams.enAlgoID = VLT_ALG_CIP_AES;
    theParams.enPaddingScheme = VLT_PADDING_NONE;
    theParams.enChainMode = VLT_BLOCK_MODE_CBC;
    theParams.pIV = vectorIV;
    
    /**
     * Key Type AES 192
     * Key Size 24 Bytes
     */
    theKey.keyType = VLT_KEY_AES_192;
    theKey.keySize = sizeof(vectorKey)/sizeof(VLT_U8);
    theKey.keyValue = vectorKey;

    textLength = ( sizeof(vectorPlainText)/sizeof(VLT_U8) );

    /**
     * Initialise the Cipher
     */
    if( VLT_OK != ( status = CipherInit( VLT_ENCRYPT_MODE , &theKey, &theParams) ) )
    {
        return( status );
    }
    
    /**
     * Copy the plain text vector in the text.
     */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( text, vectorPlainText, textLength );

    /**
     * Encrypt the text
     */
    if( VLT_OK != ( status = CipherDoFinal( text, textLength, textCapacity, text, &textLength, textCapacity ) ) )
    {
        return( status );
    }

    /**
     * Initialise the Cipher
     */
    if( VLT_OK != ( status = CipherInit( VLT_DECRYPT_MODE , &theKey, &theParams ) ) )
    {
        return( status );
    }

    textLength = ( sizeof(vectorCipherText)/sizeof(VLT_U8) );

    if( 0 != host_memcmp( text, vectorCipherText, textLength ) )
    {
        return( VLT_FAIL );
    }

    /**
     * Decrypt the text
     */
    if( VLT_OK != ( status = CipherDoFinal( text, textLength, textCapacity, text, &textLength, textCapacity ) ) )
    {
        return( status );
    }

    textLength = ( sizeof(vectorPlainText)/sizeof(VLT_U8) );

    if( 0 != host_memcmp( text, vectorPlainText, textLength ) )
    {
        return( VLT_FAIL );
    }

    return( VLT_OK );
}

VLT_STS DoAES256_CBC_PKCS5Padding()
{
    VLT_STS status = VLT_FAIL ;
    VLT_CIPHER_PARAMS theParams = {0};
    VLT_KEY_BLOB theKey = {0};
    VLT_U32 textCapacity = 64;
    VLT_U32 textLength;
    VLT_U8 text[64];
    
    VLT_U8 vectorIV[] = 
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    VLT_U8 vectorKey[] = 
    {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x11, 0x13, 0x15, 0x67, 0x89, 0xAB, 0xCD, 0x0F,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };

    VLT_U8 vectorPlainText[] = 
    {
        0x54, 0x68, 0x65, 0x20, 0x67, 0x6f, 0x64, 0x73, 
        0x20, 0x74, 0x6f, 0x6f, 0x20, 0x61, 0x72, 0x65, 
        0x20, 0x66, 0x6f, 0x6e, 0x64, 0x20, 0x6f, 0x66, 
        0x20, 0x61, 0x20, 0x6a, 0x6f, 0x6b, 0x65, 0x00 
    };

    VLT_U8 vectorCipherText[] = 
    {
        0xc8, 0x08, 0xab, 0xa8, 0xdd, 0x75, 0x9e, 0x8e, 
        0x6d, 0x2f, 0x1b, 0x67, 0xaa, 0x55, 0xe5, 0x01,
        0x8b, 0x02, 0x29, 0xf0, 0xe1, 0x03, 0x8a, 0x85, 
        0x2a, 0xf9, 0x50, 0xc7, 0x5f, 0x35, 0x9e, 0x5d,
        0x31, 0xad, 0x5d, 0xdb, 0x4a, 0x88, 0x34, 0x33, 
        0x9c, 0x04, 0x2e, 0xc8, 0xf2, 0xc7, 0x14, 0xd1
    };

    /**
     * Algorithm AES 256
     * Padding None
     * Block Mode CBC 
     */
    theParams.enAlgoID = VLT_ALG_CIP_AES;
    theParams.enPaddingScheme = VLT_PADDING_PKCS5;
    theParams.enChainMode = VLT_BLOCK_MODE_CBC;
    theParams.pIV = vectorIV;
    
    /**
     * Key Type AES 256
     * Key Size 32 Bytes
     */
    theKey.keyType = VLT_KEY_AES_256;
    theKey.keySize = sizeof(vectorKey)/sizeof(VLT_U8);
    theKey.keyValue = vectorKey;

    textLength = ( sizeof(vectorPlainText)/sizeof(VLT_U8) );

    /**
     * Initialise the Cipher
     */
    if( VLT_OK != ( status = CipherInit( VLT_ENCRYPT_MODE , &theKey, &theParams) ) )
    {
        return( status );
    }
    
    /**
     * Copy the plain text vector in the text.
     */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( text, vectorPlainText, textLength );

    /**
     * Encrypt the text
     */
    if( VLT_OK != ( status = CipherDoFinal( text, textLength, textCapacity, text, &textLength, textCapacity ) ) )
    {
        return( status );
    }

    /**
     * Initialise the Cipher
     */
    if( VLT_OK != ( status = CipherInit( VLT_DECRYPT_MODE , &theKey, &theParams ) ) )
    {
        return( status );
    }

    textLength = ( sizeof(vectorCipherText)/sizeof(VLT_U8) );

    if( 0 != host_memcmp( text, vectorCipherText, textLength ) )
    {
        return( VLT_FAIL );
    }

    /**
     * Decrypt the text
     */
    if( VLT_OK != ( status = CipherDoFinal( text, textLength, textCapacity, text, &textLength, textCapacity ) ) )
    {
        return( status );
    }

    textLength = ( sizeof(vectorPlainText)/sizeof(VLT_U8) );

    if( 0 != host_memcmp( text, vectorPlainText, textLength ) )
    {
        return( VLT_FAIL );
    }

    return( VLT_OK );
}
#endif

#endif/*VLT_ENABLE_CIPHER_TESTS*/

VLT_STS DoCipherTests( void )
{
#if( VLT_ENABLE_CIPHER_TESTS == VLT_ENABLE )

    VLT_STS status = VLT_FAIL;

    /**
     * These little cluster of tests are here
     * for debug purposes.
     */
    
#if (VLT_ENABLE_CIPHER_AES == VLT_ENABLE)
    if( VLT_OK != ( status = AesTest() ) )
    {
        return( status );
    }
#endif
    
    if( VLT_OK != ( status = PaddingTests() ) )
    {
        return( status );
    }

#if (VLT_ENABLE_CIPHER_AES == VLT_ENABLE)
    if( VLT_OK != ( status = DoAES192_CBC_NoPadding() ) )
    {
        return( status );
    }

    if( VLT_OK != ( status = DoAES256_CBC_PKCS5Padding() ) )
    {
        return( status );
    }

    if( VLT_OK != ( status = AesCMacTest() ) )
    {
        return( status );
    }
#endif

#endif/*( VLT_ENABLE_CIPHER_TESTS == VLT_ENABLE )*/
    return( VLT_OK );
}
