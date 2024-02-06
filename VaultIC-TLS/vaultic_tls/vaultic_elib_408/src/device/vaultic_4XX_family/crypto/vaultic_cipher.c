/**
* @file	   vaultic_cipher.c
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
#if ( VLT_ENABLE_CIPHER_AES == VLT_ENABLE )
#include "vaultic_cipher.h"
#include "vaultic_AES.h"
#include "vaultic_mem.h"
#include "vaultic_padding.h"

/**
 * Error Codes
 */
#define ECPHIINVLDALGO      VLT_ERROR( VLT_CIPHER, 0u )
#define ECPHINOTSUPPORTED   VLT_ERROR( VLT_CIPHER, 2u )
#define ECPHIIVLDPRM        VLT_ERROR( VLT_CIPHER, 3u )
#define ECPHCLSNOTSUPPORTED VLT_ERROR( VLT_CIPHER, 4u )
#define ECPHDFNOTSUPPORTED  VLT_ERROR( VLT_CIPHER, 5u )
#define ECPHUPDNOTSUPPORTED VLT_ERROR( VLT_CIPHER, 6u )
#define ECPHBLKNOTSUPPORTED VLT_ERROR( VLT_CIPHER, 7u )
#define ECPHICHNMODE        VLT_ERROR( VLT_CIPHER, 8u )
#define ECPHIPADUNKNOWN     VLT_ERROR( VLT_CIPHER, 9u )
#define ECPHUPDINVLDBLOCK   VLT_ERROR( VLT_CIPHER, 10u )
#define ECPHUPDINVLDLEN     VLT_ERROR( VLT_CIPHER, 11u )
#define ECPHUPDNULLPARAM    VLT_ERROR( VLT_CIPHER, 12u )
#define ECPHUPDINVLDCPCT    VLT_ERROR( VLT_CIPHER, 13u )
#define ECPHBLOCKSIZE		VLT_ERROR( VLT_CIPHER, 14u )

/**
 * Private Defs
 */
#define ST_UNKNOWN          0x00u
#define ST_INITIALISED      0x10u
#define ST_UPDATED          0x20u
#define ST_FINALISED        0x30u
#define MAX_BLOCK_SZ        0x20u
#define MAX_IV_SZ           0x10u


typedef VLT_STS (*pfnCipherInit)(VLT_ALGO_MODE opMode, const VLT_KEY_BLOB *pKey, VLT_U8 *pParams );
typedef VLT_STS (*pfnCipherClose)( void );
typedef VLT_STS (*pfnCipherDoFinal)( 
    const VLT_U8 *pDataIn,
    VLT_U32 DataInLen, 
    VLT_U8 *pDataOut, 
    VLT_U32 *pDataOutLen);

typedef VLT_STS (*pfnCipherUpdate)( 
    const VLT_U8 *pDataIn,
    VLT_U32 DataInLen, 
    VLT_U8 *pDataOut, 
    VLT_U32 *pDataOutLen);

typedef VLT_U16 (*pfnCipherGetBlockSize)( void );

/** \cond SHOW_INTERNAL */
typedef struct 
{
    pfnCipherInit cipherInit;
    pfnCipherClose cipherClose;
    pfnCipherDoFinal cipherDoFinal;
    pfnCipherUpdate cipherUpdate;
    pfnCipherGetBlockSize cipherGetBlockSize;

} CIPHER;
/** \endcond */

/**
 * Private Data
 */
static VLT_CIPHER_PARAMS params = {0};

static CIPHER theCipher;
static VLT_U8 chainBlock[MAX_BLOCK_SZ];
static VLT_U8 tempBlock[MAX_BLOCK_SZ];
static VLT_U8 workingBlock[MAX_BLOCK_SZ];
static VLT_ALGO_MODE operationalMode;
static VLT_U8 cipherState = ST_UNKNOWN;


VLT_STS CipherInit(VLT_ALGO_MODE opMode, const VLT_KEY_BLOB *pKey, const VLT_CIPHER_PARAMS *pParams )
{   
    VLT_U8 keyMode ;
    VLT_STS status;

    /**
     * Make sure we have a valid params pointer
     */
    if( NULL == pParams )
    {
        return( ECPHIIVLDPRM );
    }
    else
    {
        /**
         * Cache the parameters.
         */
        params = *pParams;
        
        if (params.enAlgoID != VLT_ALG_CIP_AES )  
        {
            /**
             * Clear the cipherState to signify the
             * fact that something has gone pear
             * shaped and we shouldn't deligate
             * any further calls to the concrete
             * cipher methods.
             */
            cipherState = ST_UNKNOWN;

            /**
             * Return the appropriate error and
             * exit gracefully. 
             */
            return( ECPHIINVLDALGO );
        }
    }

    /**
     * Set all the function pointers
     * to the actual concrete cipher 
     * methods based on the algo Id.
     */
    switch(params.enAlgoID)
    {

#if( VLT_ENABLE_CIPHER_AES == VLT_ENABLE )
        case VLT_ALG_CIP_AES:
			{
            theCipher.cipherInit = AesInit;
            theCipher.cipherDoFinal = AesDoFinal;
            theCipher.cipherGetBlockSize = AesGetBlockSize;         
            theCipher.cipherUpdate = AesUpdate;
            theCipher.cipherClose = AesClose;
            break;
			}
    #endif/*( VLT_ENABLE_CIPHER_AES == VLT_ENABLE )*/
        default:
            return( ECPHINOTSUPPORTED );
			break; //For MISRA compliancy
    }
    
    /**
     * Check and setup the Keying mode.
     */
    switch(params.enAlgoID)
    {
        case VLT_ALG_CIP_AES:
            /**
             * Do nothing for aes the 
             * key mode is not relevant.
             */
            break;
#if( VLT_ENABLE_CIPHER_RSA == VLT_ENABLE ) && IS_RSA_IMPLEMENTED_IN_CIPHER_SERVICE
        case VLT_ALG_CIP_RSAES_PKCS_OAEP:
        case VLT_ALG_CIP_RSAES_PKCS:
        case VLT_ALG_CIP_RSAES_X509:
            /**
             * Do nothing for rsa the 
             * key mode is not relevant.
             */
            break;
#endif
        default:
            return( ECPHINOTSUPPORTED );
			break; //For MISRA compliancy
    }

#if( VLT_ENABLE_CIPHER_RSA == VLT_ENABLE ) && IS_RSA_IMPLEMENTED_IN_CIPHER_SERVICE
    if(     (params.enAlgoID != VLT_ALG_CIP_RSAES_PKCS_OAEP) 
        &&  (params.enAlgoID != VLT_ALG_CIP_RSAES_PKCS)
        &&  (params.enAlgoID != VLT_ALG_CIP_RSAES_X509) )
#endif
	{
		/**
		* Check the chaining mode.
		*/
		switch( params.enChainMode )
		{   
		case VLT_BLOCK_MODE_ECB:        
		case VLT_BLOCK_MODE_CBC:
			break;
		case VLT_BLOCK_MODE_CFB:
		case VLT_BLOCK_MODE_OFB:
		default:
			return(ECPHICHNMODE);
			break; //For MISRA compliancy
		}   
	}

    /**
     * Initialise the chaining block to zeros
     */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memset( chainBlock, 0x00, theCipher.cipherGetBlockSize() );
        
#if( VLT_ENABLE_CIPHER_RSA == VLT_ENABLE ) && ISCIPHER_RSA_IMPLEMENT_IN_THIS_MODULE
    if ((params.enAlgoID != VLT_ALG_CIP_RSAES_PKCS_OAEP)
        && (params.enAlgoID != VLT_ALG_CIP_RSAES_PKCS)
        && (params.enAlgoID != VLT_ALG_CIP_RSAES_X509))
#endif
	{
		/**
		* Check the padding scheme.
		*/
		switch( params.enPaddingScheme )
		{   
		case VLT_PADDING_ISO9797_METHOD2:                   
		case VLT_PADDING_NONE:
		case VLT_PADDING_PKCS5:
		case VLT_PADDING_PKCS7:
			break;
		default:
			return(ECPHIPADUNKNOWN);
			break; //For MISRA compliancy
		}       
	}
    /**
     * Cache the operationalMode, we'll need it
     * when we are doing the padding.
     */
    operationalMode = opMode;

    /**
     * Delegate the call to the initialisation method
     * of the appropriate cipher.
     */
    status = theCipher.cipherInit( opMode, pKey, &keyMode );

    /**
     * Prepare to accept the first block 
     * of data.
     */
    if( VLT_OK == status )
    {
        cipherState = ST_INITIALISED;
    }

    return( status );
}

VLT_STS CipherClose( void )
{
    if( ST_UNKNOWN != cipherState )
    {
        return( theCipher.cipherClose() );
    }
    return( ECPHCLSNOTSUPPORTED );
}

VLT_STS CipherDoFinal( VLT_U8 *pDataIn,
        VLT_U32 DataInLen, 
        VLT_U32 dataInCapacity, 
        VLT_U8 *pDataOut, 
        VLT_U32 *pDataOutLen, 
        VLT_U32 dataOutCapacity )
{
    VLT_STS status;      

    if ( ( ST_UNKNOWN == cipherState ) ||
         ( ST_FINALISED == cipherState ) )

    {
        return( ECPHDFNOTSUPPORTED );   
    }

    /**
     * Ensure we haven't been passed
     * null pointers by the caller.
     */
    if( ( NULL == pDataIn )||
        ( NULL == pDataOutLen ) ||
        ( NULL == pDataOut ) )
    {
        return( ECPHUPDNULLPARAM );
    }
    
    /**
     * Apply the padding if we have been called to
     * encrypt data.
     */
    if( ( VLT_ENCRYPT_MODE == operationalMode ) && 
        (
#if( VLT_ENABLE_CIPHER_RSA == VLT_ENABLE ) && IS_RSA_IMPLEMENTED_IN_CIPHER_SERVICE
            if ((params.enAlgoID != VLT_ALG_CIP_RSAES_PKCS_OAEP)
                && (params.enAlgoID != VLT_ALG_CIP_RSAES_PKCS)
                && (params.enAlgoID != VLT_ALG_CIP_RSAES_X509))
#endif
            VLT_PADDING_NONE != params.enPaddingScheme))
    {
        status = PaddingAdd( params.enPaddingScheme, 
            theCipher.cipherGetBlockSize(), 
            pDataIn,
            &DataInLen, 
            dataInCapacity );
    }
    else
    {
        status = VLT_OK;
    }

    /**
     * Process the data, encrypt/decrypt
     */
    if( VLT_OK == status )
    {
        status = CipherUpdate( 
            pDataIn, 
            DataInLen,
            pDataOut, 
            pDataOutLen,
            dataOutCapacity);
    }
    
    
    if( VLT_OK == status )
    {
        if( VLT_DECRYPT_MODE == operationalMode )
        {
            status = PaddingRemove( params.enPaddingScheme, 
                theCipher.cipherGetBlockSize(), 
                pDataOut, 
                pDataOutLen );
        }
    }

    /**
     * Set the appropriate cipher state;
     */ 
    cipherState = ST_FINALISED;

    return( status );
}

VLT_STS CipherUpdate( VLT_U8 *pDataIn, 
        VLT_U32 DataInLen, 
        VLT_U8 *pDataOut, 
        VLT_U32 *pDataOutLen, 
        VLT_U32 dataOutCapacity )
{
    VLT_STS status;
    VLT_U16 blockSize;
    VLT_U32 byteCount = 0;
    VLT_U32 workingLen;
    

    if ( ( ST_UNKNOWN == cipherState ) ||
         ( ST_FINALISED == cipherState ) )
    {
        return( ECPHUPDNOTSUPPORTED );
    }

    /**
     * Cache the block size, we'll use it 
     * frequently.
     */
    blockSize = theCipher.cipherGetBlockSize( );

	if (blockSize == 0u)
	{
		return( ECPHBLOCKSIZE );
	}

    /**
     * Ensure we haven't been passed
     * null pointers by the caller.
     */
    if( ( NULL == pDataIn )     ||
        ( NULL == pDataOutLen ) ||
        ( NULL == pDataOut ) )
    {
        return( ECPHUPDNULLPARAM );
    }

    /**
     * For the CipherUpdate the capacity of
     * the buffer passed to us by the caller
     * should be equal or larger than that
     * of the data buffer length.
     */

    if( DataInLen > dataOutCapacity ) 
    {
        return( ECPHUPDINVLDCPCT );
    }

    /**
     * Update only deals with data lengths
     * multiple of the block size, if the 
     * client has passed us anything else 
     * other than that then we should exit
     * gracefully-ish!
     */
	if(0u != ( DataInLen % blockSize ) )
    {
        return( ECPHUPDINVLDLEN );
    }

    /**
     * Chunk things up in multiples of the
     * block size.
     */
    while( 0u != ( DataInLen - byteCount ) )
    {
        /*
         * Perform a copy of the input data into a temp buffer
         * this is needed to ensure the input data is not trashed
         * if CBC mode is selected.
         */
        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_memcpy( &workingBlock[0], &pDataIn[byteCount], blockSize );
        
        /**
         * Do the chaining
         */
        if( VLT_ENCRYPT_MODE == operationalMode )
        {
            if( VLT_BLOCK_MODE_CBC == params.enChainMode )
            {
                if( ST_INITIALISED == cipherState )
                {
                    /*
                     * Make a copy of the IV of the first round.
                     */
                    /*
                    * No need to check the return type as pointer has been validated
                    */
                    (void)host_memcpy( chainBlock, &(params.pIV[0]), blockSize );
                    
                    cipherState = ST_UPDATED;
                }

                /*
                * No need to check the return type as pointer has been validated
                */
                (void)host_memxor( &workingBlock[0], chainBlock, blockSize );
            }
        }
        else
        {
            if( VLT_BLOCK_MODE_CBC == params.enChainMode )
            {
                /*
                * No need to check the return type as pointer has been validated
                */
                (void)host_memcpy( tempBlock, &pDataIn[byteCount], blockSize );
            }
        }

        
        /**
         * Set the working length
         */
        workingLen = blockSize;


        /**
         * Do the Encrypt/Decrypt
         */
        if( VLT_OK == ( status = theCipher.cipherUpdate( 
            &workingBlock[0], /* workingBlock is used to ensure the pDataIn is preserved */
            workingLen,
            &pDataOut[byteCount],
            &workingLen) ) )
        {
            /**
             * It should be impossible for the block
             * cipher to return a length not equal to 
             * the blockSize, nevertheless if it does
             * exit with an appropriate error code and 
             * set the chaining block back to the IV 
             * for the next call.
             */
            if( workingLen != blockSize )
            {               
                return( ECPHUPDINVLDBLOCK );
            }                       
            
        }
        else
        {
            return( status );
        }

        /**
         * Do the chaining
         */
        if( VLT_ENCRYPT_MODE == operationalMode )
        {
            if( VLT_BLOCK_MODE_CBC == params.enChainMode )
            {
                /*
                * No need to check the return type as pointer has been validated
                */
                (void)host_memcpy( chainBlock, &pDataOut[byteCount], blockSize );
            }
        }
        else
        {
            if( VLT_BLOCK_MODE_CBC == params.enChainMode )
            {
                if( ST_INITIALISED == cipherState )
                {
                    /*
                    * No need to check the return type as pointer has been validated
                    */
                    (void)host_memxor( &pDataOut[byteCount], &(params.pIV[0]), blockSize );
                    cipherState = ST_UPDATED;
                }
                else
                {
                    /*
                    * No need to check the return type as pointer has been validated
                    */
                    (void)host_memxor( &pDataOut[byteCount], chainBlock, blockSize );             
                }

                /*
                * No need to check the return type as pointer has been validated
                */
                (void)host_memcpy( chainBlock, tempBlock, blockSize );
            }
        }
        
        /**
         * Update the byte count to 
         * move to the next block of data.
         */
        byteCount += workingLen;
    }       
    
    *pDataOutLen = byteCount;

    return( VLT_OK );
}

VLT_U16 CipherGetBlockSize( void )
{
    if( ST_UNKNOWN != cipherState )
    {
        return( theCipher.cipherGetBlockSize() );
    }
    return( ECPHBLKNOTSUPPORTED );
}
#endif
