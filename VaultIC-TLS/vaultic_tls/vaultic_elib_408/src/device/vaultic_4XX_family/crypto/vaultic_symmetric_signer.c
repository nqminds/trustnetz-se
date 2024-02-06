/**
* @file	   vaultic_symmetric_signer.c
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
#include "vaultic_symmetric_signer.h"
#include "vaultic_cipher.h"
#include "vaultic_padding.h"
#include "vaultic_mem.h"
#include "vaultic_utils.h"
#include "vaultic_signer_aes_cmac.h"


/**
 * Error Codes
 */
#define ESGNRIIVLDMODE           VLT_ERROR( VLT_SIGNER, 0u )
#define ESGNRIIVLDPRM            VLT_ERROR( VLT_SIGNER, 1u )
#define ESGNRIINVLDALGO          VLT_ERROR( VLT_SIGNER, 2u )
#define ESGNRINOTSUPPORTED       VLT_ERROR( VLT_SIGNER, 3u )
#define ESGNRIIVLDPAD            VLT_ERROR( VLT_SIGNER, 4u )
#define ESGNRCLSNOTSUPPORTED     VLT_ERROR( VLT_SIGNER, 5u )
#define ESGNRDFNOTSUPPORTED      VLT_ERROR( VLT_SIGNER, 6u )
#define ESGNRUPDNOTSUPPORTED     VLT_ERROR( VLT_SIGNER, 7u )
#define ESGNRUPNULLMSG           VLT_ERROR( VLT_SIGNER, 8u )
#define ESGNRUPZEROMSGLEN        VLT_ERROR( VLT_SIGNER, 9u )
#define ESGNRUPMINVLDLEN         VLT_ERROR( VLT_SIGNER, 10u )
#define ESGNRDFNULLMAC           VLT_ERROR( VLT_SIGNER, 11u )
#define ESGNRDFNULLMACLEN        VLT_ERROR( VLT_SIGNER, 12u )
#define ESGNRDFNULLMSG           VLT_ERROR( VLT_SIGNER, 13u )
#define ESGNRDFZEROMSGLEN        VLT_ERROR( VLT_SIGNER, 14u )

/**
 * Private Defs
 */
#define ST_UNKNOWN          0x00u
#define ST_INITIALISED      0x10u
#define ST_UPDATED          0x20u
#define ST_FINALISED        0x30u

#define VLT_DES_IV_SIZE     0x08u
#define VLT_AES_IV_SIZE     0x10u

typedef VLT_STS (*pfnSignerInit)( VLT_U8 opMode, const VLT_KEY_BLOB *pkey, const VLT_U8 *pParams );
typedef VLT_STS (*pfnSignerClose)( void );

typedef VLT_STS (*pfnSignerDoFinal)( 
    const VLT_U8 *pMessage, 
    VLT_U32 messageLen, 
    VLT_U32 messageCapacity, 
    VLT_U8 *pMac, 
    VLT_U32 *pMacLen, 
    VLT_U32 macCapacity );

typedef VLT_STS (*pfnSignerUpdate)( const VLT_U8 *pMessage, VLT_U32 messageLen, VLT_U32 messageCapacity );
typedef VLT_U16 (*pfnSignerGetBlockSize)( void );

/** \cond SHOW_INTERNAL */
typedef struct 
{
    pfnSignerInit signerInit;
    pfnSignerClose signerClose;
    pfnSignerDoFinal signerDoFinal;
    pfnSignerUpdate signerUpdate;
    pfnSignerGetBlockSize signerGetBlockSize;

} SIGNER;
/** \endcond */

/**
 * The signer function pointer structure will  is set to zero.
 * The SymmetricSignerInit method willsetup the function pointers.
 */
static SIGNER theSigner =
{
    0,
    0,
    0,
    0,
    0
};

/**
 * Private Data
 */
static VLT_U8 signerState = ST_UNKNOWN;
static SIGNER_PARAMS params;



VLT_STS SymmetricSignerInit( VLT_U8 opMode, const VLT_KEY_BLOB *pKey, const VLT_U8 *pParams )
{   
    VLT_STS status;

    /**
     * Our signer supports only one mode, ensure we have
     * been passed the correct one.
     */
    if( VLT_SIGN_MODE != opMode )
    {
        return( ESGNRIIVLDMODE );
    }

    /**
     * Make sure we have a valid params pointer
     */
    if( NULL == pParams )
    {
        return( ESGNRIIVLDPRM );
    }

    /**
     * Make sure we have a valid key pointer
     */
    if (NULL == pKey)
    {
        return(ESGNRIIVLDPRM);
    }

    
    /**
        * Cache the parameters.
        */
    params = *((SIGNER_PARAMS*)((void*)pParams));

    if(  params.enAlgoID != VLT_ALG_SIG_CMAC_AES ) 
    {
        /**
            * Clear the signerState to signify the
            * fact that something has gone pear
            * shaped and we shouldn't deligate
            * any further calls to the concrete
            * cipher methods.
            */
        signerState = ST_UNKNOWN;

        /**
            * Return the appropriate error and
            * exit gracefully. 
            */
        return( ESGNRIINVLDALGO );
    }
   

    /**
     * Set all the function pointers
     * to the actual concrete cipher 
     * methods based on the algo Id.
     */
    switch(params.enAlgoID)
    {
    #if( VLT_ENABLE_CIPHER_AES == VLT_ENABLE )
        case VLT_ALG_SIG_CMAC_AES:  
            theSigner.signerInit = SignerAesCmacInit;
            theSigner.signerClose = SignerAesCmacClose;
            theSigner.signerDoFinal = SignerAesCmacDoFinal;
            theSigner.signerUpdate = SignerAesCmacUpdate;
            theSigner.signerGetBlockSize = SignerAesCmacGetBlockSize;
            break;          
    #endif /* ( VLT_ENABLE_CIPHER_AES == VLT_ENABLE ) */

        default:
            return( ESGNRINOTSUPPORTED );
			break; //For MISRA compliancy
    }   

    /**
     * Check the padding scheme. The only padding scheme 
     * supported by our signers is ISO9797 Padding Method 2.
     */
    if( VLT_PADDING_ISO9797_METHOD2 != params.enPaddingScheme )
    {
        return( ESGNRIIVLDPAD );
    }   

    /**
     * Delegate the call to the initialisation method
     * of the appropriate signer.
     */
    status = theSigner.signerInit( opMode, pKey, pParams );

    /**
     * Prepare to accept the first block 
     * of data.
     */
    if( VLT_OK == status )
    {
        signerState = ST_INITIALISED;
    }

    return( status );
}

VLT_STS SymmetricSignerClose( void )
{
    if( ST_UNKNOWN != signerState )
    {
        return( theSigner.signerClose() );
    }
    return( ESGNRCLSNOTSUPPORTED );
}


VLT_STS SymmetricSignerDoFinal(
    const VLT_U8 *pMessage, 
    VLT_U32 messageLen, 
    VLT_U32 messageCapacity, 
    VLT_U8 *pMac, 
    VLT_U32 *pMacLen, 
    VLT_U32 macCapacity )
{
    VLT_STS status;

    if( ( ST_UNKNOWN == signerState ) ||
        ( ST_FINALISED == signerState ) )
    {
        return( ESGNRDFNOTSUPPORTED );
    }

    /**
     * Ensure we haven't been passed an null 
     * message pointer.
     */
    if( NULL == pMessage )
    {
        return( ESGNRDFNULLMSG );
    }

    /**
     * This signer doesn't deal with zero length
     * messages.
     */
    if( 0u == messageLen )
    {
        return( ESGNRDFZEROMSGLEN );
    }

    /**
     * Ensure we haven't been passed an null 
     * mac pointer.
     */
    if( NULL == pMac )
    {
        return( ESGNRDFNULLMAC );
    }

    /**
     * Ensure we haven't been passed an null 
     * mac pointer.
     */
    if( NULL == pMacLen )
    {
        return( ESGNRDFNULLMACLEN );
    }

    /**
     * Delegate the call to the DoFinal method
     * of the appropriate signer.
     */
    if( VLT_OK == ( status = theSigner.signerDoFinal( 
        pMessage, 
        messageLen, 
        messageCapacity,
        pMac, 
        pMacLen, 
        macCapacity ) ) )
    {
        /**
         * Update the signer state.
         */
        signerState = ST_FINALISED;
    }
    
    return ( status );
}

VLT_STS SymmetricSignerUpdate( const VLT_U8 *pMessage, VLT_U32 messageLen, VLT_U32 messageCapacity )
{
    VLT_STS status;

    if( ( ST_UNKNOWN == signerState ) ||
        ( ST_FINALISED == signerState ) )
    {
        return( ESGNRUPDNOTSUPPORTED );
    }

    /**
     * Ensure we haven't been passed an null 
     * message pointer.
     */
    if( NULL == pMessage )
    {
        return( ESGNRUPNULLMSG );
    }

    /**
     * This signer doesn't deal with zero length
     * messages.
     */
    if( 0u == messageLen )
    {
        return( ESGNRUPZEROMSGLEN );
    }

    /**
     * Update only deals with data lengths
     * multiple of the block size, if the 
     * client has passed us anything else 
     * other than that then we should exit
     * gracefully-ish!
     */
    if( 0u != ( messageLen % SymmetricSignerGetBlockSize() ) )
    {
        return( ESGNRUPMINVLDLEN );
    }

    /**
     * Delegate the call to the Update method
     * of the appropriate signer.
     */
    if( VLT_OK == ( status = theSigner.signerUpdate( pMessage, 
        messageLen, messageCapacity ) ) )
    {
        /**
         * Update the signer state.
         */
        signerState = ST_UPDATED;
    }

    return( status );
}

VLT_U16 SymmetricSignerGetBlockSize( void )
{   
    if( NULL == theSigner.signerGetBlockSize )
    {
        return( EMETHODNOTSUPPORTED );
    }

    /**
     * Delegate the call to the GetBlockSize method
     * of the appropriate signer.
     */
    return( theSigner.signerGetBlockSize() );
}
#endif