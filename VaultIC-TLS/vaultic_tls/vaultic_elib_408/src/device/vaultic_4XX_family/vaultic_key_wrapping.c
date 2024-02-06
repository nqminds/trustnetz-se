/**
* @file	   vaultic_key_wrapping.c
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
*/

#include "vaultic_common.h"
#if( VLT_ENABLE_KEY_WRAPPING == VLT_ENABLE )
#include "vaultic_key_wrapping.h"
#include "vaultic_api.h"
#include "vaultic_cipher.h"
#include "vaultic_mem.h"
#include <auth/vaultic_secure_channel.h>
#include "vaultic_apdu.h"
#include <comms/vaultic_comms.h>
#include "vaultic_utils.h"
#include "vaultic_command.h"
#include "vaultic_crc16.h"

#if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE) || (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE)
#include "vaultic_aes_kw.h"
#endif
/**
 * Externs 
 */
extern VLT_MEM_BLOB Command;                /* declared in vaultic_api.c */
extern VLT_MEM_BLOB Response;               /* declared in vaultic_api.c */
extern VLT_U16 idx;                         /* declared in vaultic_api.c */

/**
 * Private Defs
 */
#define ST_UNINIT       0x00u
#define ST_PARAMS_INIT  0x10u
#define ST_CIPHER_INIT  0x20u

#define NO_MODE         0x00u
#define WRAP_MODE       0x10u
#define UNWRAP_MODE     0x20u

#define KEY_OBJ_HEADER_SIZE 4

/*
* Private Data
*/
static VLT_U8 u8CachedKTSKeyGroup = 0;
static VLT_U8 u8CachedKTSKeyIndex = 0;
static VLT_WRAP_PARAMS theWrapParams;
static VLT_KEY_BLOB theKey;
#if(VLT_ENABLE_NO_WRAPKEY_CRC != VLT_ENABLE)
static VLT_U16 u16ReceivedCrc = 0xFFFFu;
#endif
static VLT_U8 keyWrappingState = ST_UNINIT;
static VLT_U8 keyWrappingMode = NO_MODE;
static VLT_U8 u8KeyWrappingIV[VLT_MAX_IV_LENGTH]; /* Used when intermediate IV must be stored */
static VLT_U8 u8KeyWrapTempBuffer[AES_BLOCK_SIZE]; /* Used when receiving data not multiple of CipherBlockSize */
static VLT_U16 u16KeyWrapTempSize=0; /* size of data stored in u8KeyWrapTempBuffer */

/*
* Local methods
*/
static VLT_STS VltConvWrapToCipher(VLT_CIPHER_PARAMS *pOutCipherParams, VLT_WRAP_PARAMS *pInWrapParams);

static VLT_STS VltReadEncryptedKey( VLT_U8 u8KeyGroup, VLT_U8 u8KeyIndex, VLT_SW *pSW );
static VLT_STS VltPutEncryptedKey(VLT_U8 u8KeyGroup, VLT_U8 u8KeyIndex,  const VLT_FILE_PRIVILEGES *pKeyFilePrivileges, const VLT_KEY_OBJ_RAW* pKeyObj);

static VLT_STS VltReadEncryptedKey_Generic(VLT_U8 u8KeyGroup, VLT_U8 u8KeyIndex, VLT_KEY_OBJ_RAW* pKeyObj);
#if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE) || (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE)
static VLT_STS VltReadEncryptedKey_SP800(VLT_U8 u8KeyGroup, VLT_U8 u8KeyIndex, VLT_KTS_PADDING_MODE kwPaddingMode, VLT_BOOL isP25, VLT_KEY_OBJ_RAW* pKeyObj);
static VLT_STS VltPutEncryptedKey_SP800(VLT_U8 u8KeyGroup, VLT_U8 u8KeyIndex, VLT_KTS_PADDING_MODE kwPaddingMode, VLT_BOOL isP25, const VLT_FILE_PRIVILEGES *pKeyFilePrivileges, const VLT_KEY_OBJ_RAW* pKeyObj);
#endif

#if (VLT_ENABLE_KW_WRAPPING_INIT == VLT_ENABLE)
VLT_STS VltKeyWrappingInit(VLT_U8 u8KTSKeyGroup,
    VLT_U8 u8KTSKeyIndex,
    const VLT_WRAP_PARAMS* pWrapParams,
    const VLT_KEY_OBJECT* pKTSKey)
{
    /*
    * Check the validity of the input parameters
    */
    if ((NULL == pWrapParams) || (
#if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE)
            pWrapParams->enAlgoID != VLT_ALG_KTS_AES_P25 &&         
#endif        
#if (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE)
            pWrapParams->enAlgoID != VLT_ALG_KTS_AES_NIST_KWP &&
#endif        

            pWrapParams->enChainMode != VLT_BLOCK_MODE_ECB &&  NULL == pWrapParams->pIV ) ||
        (NULL == pKTSKey) ||
        (NULL == pKTSKey->data.SecretKey.pu8Key))
    {
        return(EKWINITNULLPARAM);
    }

    /*
    * Check that the Algo ID being passed in is supported
    */
    switch (pWrapParams->enAlgoID)
    {
        case VLT_ALG_KTS_AES:
#if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE) 
        case VLT_ALG_KTS_AES_P25:
#endif    
#if (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE)
        case VLT_ALG_KTS_AES_NIST_KWP:
#endif    
        break;

    default:
        return EKWINITINVLDALGOID;
    }

    /*
    * Check that the Chaining mode ID being passed in is supported
    */
    switch (pWrapParams->enChainMode)
    {
        case VLT_BLOCK_MODE_ECB:
        case VLT_BLOCK_MODE_CBC:
        case VLT_BLOCK_MODE_OFB:
        case VLT_BLOCK_MODE_CFB:
        case VLT_BLOCK_MODE_CTR:
            break;

        default:
            return EKWINITINVLDCHAINID;
    }

    /*
    * Check that the KTS key being passed in is supported
    */
    switch (pKTSKey->enKeyID)
    {
        case VLT_KEY_AES_128:
        case VLT_KEY_AES_192:
        case VLT_KEY_AES_256:
        case VLT_KEY_RAW:
            break;

        default:
            return EKWINITINVLDKTSKEY;
    }

    /*
    * Cache the Key Group and Key Index
    */
    u8CachedKTSKeyGroup = u8KTSKeyGroup;
    u8CachedKTSKeyIndex = u8KTSKeyIndex;

    /*
    * Cache the Wrap Params
    */
    theWrapParams = *pWrapParams;

#if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE) || (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE)
    VLT_BOOL isKtsAesSp80038F = FALSE; 
    #if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE) 
    if (pWrapParams->enAlgoID == VLT_ALG_KTS_AES_P25) {isKtsAesSp80038F = TRUE;}
    #endif
    #if (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE) 
    if (pWrapParams->enAlgoID == VLT_ALG_KTS_AES_NIST_KWP) {
        isKtsAesSp80038F = TRUE; 
    }
    #endif
    if (isKtsAesSp80038F == FALSE)
#endif
    {
        if (theWrapParams.pIV != NULL)
        {
            /* TODO: pIV length is not known, pointed buffer must be at least,
               VLT_MAX_IV_LENGTH size */
            host_memcpy(u8KeyWrappingIV, theWrapParams.pIV, VLT_MAX_IV_LENGTH);
            theWrapParams.pIV = u8KeyWrappingIV;
        }
    }

    /*
    * Cache the key data that will be required.
    */
    theKey.keyType = pKTSKey->enKeyID;
    theKey.keySize = pKTSKey->data.SecretKey.u16KeyLength;
    theKey.keyValue = pKTSKey->data.SecretKey.pu8Key;

    /*
    * Set the state to initialised and the mode to no mode
    */
    keyWrappingState = ST_PARAMS_INIT;
    keyWrappingMode = NO_MODE;

    return( VLT_OK );
}
#endif

#if (VLT_ENABLE_KW_WRAP_KEY == VLT_ENABLE)
VLT_STS VltKeyWrap( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    const VLT_KEY_OBJ_RAW* pKeyObj )
{
    VLT_STS status = VLT_OK;

    /*
    * Check the validity of the input parameters
    */
    if( ( NULL == pKeyFilePrivileges ) || 
        ( NULL == pKeyObj ) || 
        ( NULL == pKeyObj->pu16ClearKeyObjectLen ) || 
        ( NULL == pKeyObj->pu8KeyObject ) )
    {
        return( EKWWKNULLPARAM );
    }

    /*
    * Check that the key wrapping has been initialised
    */
    if( ST_UNINIT == keyWrappingState )
    {
        return ( EKWWKUNINIT );
    }

    if( WRAP_MODE != keyWrappingMode )
    {
        /*
        * Call Initialize Algorithm on the VaultIC to set it up to unwrap the
        * wrapped key we are about to send down. Only do this if it hasn't 
        * already been called
        */
        VLT_ALGO_PARAMS algorithm = {0};

        algorithm.u8AlgoID = (VLT_U8) theWrapParams.enAlgoID;
      
#if( VLT_ENABLE_CIPHER_RSA == VLT_ENABLE ) && IS_RSA_IMPLEMENTED_IN_CIPHER_SERVICE
        if (VLT_ALG_KTS_RSA_OAEP_BASIC ! algorithm.u8AlgoID) /* RSA CIPHER SERVICE NOT IMPLEMENTED */
#endif
        {
            algorithm.data.SymCipher.enPadding = theWrapParams.enPaddingScheme;        
            
#if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE) || (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE)
            VLT_BOOL isKtsAesSp80038F = FALSE;
    #if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE) 
            if (algorithm.u8AlgoID == VLT_ALG_KTS_AES_P25) {isKtsAesSp80038F = TRUE;}
    #endif
    #if (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE) 
            if (algorithm.u8AlgoID == VLT_ALG_KTS_AES_NIST_KWP) {isKtsAesSp80038F = TRUE;}
    #endif
            if (isKtsAesSp80038F == FALSE)
#endif
            {
                algorithm.data.SymCipher.enMode = theWrapParams.enChainMode;

                if (theWrapParams.pIV != NULL)
                {
                    /*
                    * No need to check the return type as pointer has been validated
                    */
                    (void)host_memcpy(&(algorithm.data.SymCipher.u8Iv[0]),
                        theWrapParams.pIV,
                        CipherGetBlockSize());

                    algorithm.data.SymCipher.u8IvLength = (VLT_U8)CipherGetBlockSize();
                }
                else
                {
                    algorithm.data.SymCipher.u8IvLength = 0;
                }
			}
		}

        status = VltInitializeAlgorithm( u8CachedKTSKeyGroup, 
            u8CachedKTSKeyIndex,
            VLT_UNWRAP_KEY_MODE,
            &algorithm );

        if( VLT_OK == status )
        {
            /*
            * Update the mode to wrap
            */
            keyWrappingMode = WRAP_MODE;
        }
    }

    if (VLT_OK == status)
    {
#if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE)
        if (theWrapParams.enAlgoID == VLT_ALG_KTS_AES_P25) 
        {
            status = VltPutEncryptedKey_SP800(u8KeyGroup, u8KeyIndex, theWrapParams.enPaddingScheme, TRUE, pKeyFilePrivileges, pKeyObj);
        }
        else
    #endif
    #if (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE) 
        if (theWrapParams.enAlgoID == VLT_ALG_KTS_AES_NIST_KWP) 
        {
            status = VltPutEncryptedKey_SP800(u8KeyGroup, u8KeyIndex, VLT_KTS_PADDING_MODE_KWP, FALSE, pKeyFilePrivileges, pKeyObj);
        }
        else
#endif
        {
            status = VltPutEncryptedKey(u8KeyGroup, u8KeyIndex, pKeyFilePrivileges, pKeyObj);
        }
    }

    if( VLT_OK != status )
    {
        /*
        * Set the state back to unitialised and the mode to no mode
        */
        keyWrappingState = ST_UNINIT;
        keyWrappingMode = NO_MODE;
    }

    return( status );
}
#endif

#if (VLT_ENABLE_KW_UNWRAP_KEY == VLT_ENABLE)
VLT_STS VltKeyUnwrap( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_RAW* pKeyObj )
{
    VLT_STS status= VLT_OK;
    
    /*
    * Check the validity of the input parameter
    */
    if( ( NULL == pKeyObj ) || 
        ( NULL == pKeyObj->pu16ClearKeyObjectLen ) || 
        ( NULL == pKeyObj->pu8KeyObject ) )
    {
        return( EKWUKNULLPARAM );
    }

    /*
    * Check that the key wrapping has been initialised
    */
    if( ST_UNINIT == keyWrappingState )
    {
        return ( EKWUKUNINIT );
    }


    if( UNWRAP_MODE != keyWrappingMode )
    {
        /*
        * Call Initialize Algorithm  on the VaultIC to set it up to wrap the
        * key we are about to receive and unwrap. Only do this if it hasn't 
        * already been called
        */
        VLT_ALGO_PARAMS algorithm = {0};

        algorithm.u8AlgoID = (VLT_U8) theWrapParams.enAlgoID;

#if( VLT_ENABLE_CIPHER_RSA == VLT_ENABLE ) && IS_RSA_IMPLEMENTED_IN_CIPHER_SERVICE
        if (VLT_ALG_KTS_RSA_OAEP_BASIC !=  algorithm.u8AlgoID)
#endif
		{
    		algorithm.data.SymCipher.enPadding = theWrapParams.enPaddingScheme;
            algorithm.data.SymCipher.enMode = theWrapParams.enChainMode;

            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy(&(algorithm.data.SymCipher.u8Iv[0]),
                theWrapParams.pIV,
                CipherGetBlockSize());

            algorithm.data.SymCipher.u8IvLength = (VLT_U8)CipherGetBlockSize();
        }

        if (VLT_OK == status)
        {
            status = VltInitializeAlgorithm(u8CachedKTSKeyGroup,
                u8CachedKTSKeyIndex,
                VLT_WRAP_KEY_MODE,
                &algorithm);
        }

        if( VLT_OK == status )
        {
            /*
            * Update the mode to unwrap
            */
            keyWrappingMode = UNWRAP_MODE;
        }
    }

    if( VLT_OK == status)
    {   

#if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE) 
        if (theWrapParams.enAlgoID == VLT_ALG_KTS_AES_P25)
        {
            status = VltReadEncryptedKey_SP800(u8KeyGroup, u8KeyIndex, theWrapParams.enPaddingScheme, TRUE, pKeyObj);
        }
        else
#endif
#if (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE) 
        if (theWrapParams.enAlgoID == VLT_ALG_KTS_AES_NIST_KWP)
        {
            status = VltReadEncryptedKey_SP800(u8KeyGroup, u8KeyIndex, VLT_KTS_PADDING_MODE_KWP, FALSE, pKeyObj);
        }
        else
#endif
        {
            status = VltReadEncryptedKey_Generic(u8KeyGroup, u8KeyIndex, pKeyObj);
        }
    }

    if( VLT_OK != status )
    {
        /*
        * Set the state back to unitialised and the mode to no mode
        */
        keyWrappingState = ST_UNINIT;
        keyWrappingMode = NO_MODE;
    }

    return( status );
}
#endif

#if (VLT_ENABLE_KW_WRAPPING_CLOSE == VLT_ENABLE)
VLT_STS VltKeyWrappingClose( void )
{
    VLT_STS status = VLT_OK;

    if( ST_CIPHER_INIT == keyWrappingState )
    {
        status = CipherClose( );
    }

    /*
    * Set the state to uninitialised and the mode to none
    */
    keyWrappingState = ST_UNINIT;
    keyWrappingMode = NO_MODE;
    
    if (VLT_OK != status) return status;


    /*
    * Switch off key wrapping in VaultIC
    */
    status = VltUnInitializeAlgorithm();    
    return( status );
}
#endif

static VLT_STS VltReadEncryptedKey( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,    
    VLT_SW *pSW )
{
    VLT_STS status;
    VLT_U32 u32DataOutLen = 0;
    
    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_READ_KEY;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 
        WRAPPED_BYTE( VltCommsGetMaxReceiveSize() );

    idx = VLT_APDU_DATA_OFFSET;

    /*
    * Send the command
    */
    status = VltCommand( &Command, &Response, idx, 0, pSW );
    if( VLT_OK == status )
    {
        /*
        * Adjust the response size to take in account the status word size
        */
        Response.u16Len -= VLT_SW_SIZE;

        /* Prepend data from previous call if any */
        if (u16KeyWrapTempSize != 0)
        {
            host_memcpy(Response.pu8Data + u16KeyWrapTempSize, Response.pu8Data, Response.u16Len);
            host_memcpy(Response.pu8Data, u8KeyWrapTempBuffer, u16KeyWrapTempSize);
            Response.u16Len += u16KeyWrapTempSize;
            u16KeyWrapTempSize = 0;
        }



        VLT_CIPHER_PARAMS theCipherParams= {0};
        status = VltConvWrapToCipher(&theCipherParams, &theWrapParams);
        if (VLT_OK != status) return status;

        /*
        * Decrypt the received data 
        */
            status = CipherInit(VLT_DECRYPT_MODE,
            &theKey,
            &theCipherParams);
        if (VLT_OK != status) return status;
        keyWrappingState = ST_CIPHER_INIT;

        /* Is IV required for key wrapping? */
        if ((NULL != theWrapParams.pIV) && (VLT_MAX_IV_LENGTH < CipherGetBlockSize()))
        {
            return EKUWKINVLIVSIZE;
        }

        if (*pSW == VLT_STATUS_RESPONDING)
        {
            VLT_U8 au8IVTmp[VLT_MAX_IV_LENGTH];

            /* Check if the length of the data received is compatible with the block size of the cipher algorithm*/
            u16KeyWrapTempSize = Response.u16Len % CipherGetBlockSize();
            if (u16KeyWrapTempSize > sizeof(u8KeyWrapTempBuffer))
            {
                return EKUWKINVLKEYSIZE; // Not expected to happen
            };

            if (u16KeyWrapTempSize != 0)
            {
                // We received more data than required
                // We store the extra data for next call to VltReadEncryptedKey()
                Response.u16Len -= u16KeyWrapTempSize;
                host_memcpy(u8KeyWrapTempBuffer, Response.pu8Data + Response.u16Len, u16KeyWrapTempSize);
            }

            /* Is IV required for key wrapping? */
            if (theWrapParams.pIV)
            {
                VLT_U32 u32LastBlockPos;
                u32LastBlockPos = Response.u16Len - CipherGetBlockSize();
                (void)host_memcpy(au8IVTmp, &Response.pu8Data[u32LastBlockPos], CipherGetBlockSize());
            }

            /*
            * Decrypt the data
            */
            status = CipherUpdate( &(Response.pu8Data[0]),
                Response.u16Len,
                &(Response.pu8Data[0]),
                &u32DataOutLen,
                Response.u16Capacity );

            /* Is IV required for key wrapping? */
            if (theWrapParams.pIV)
            {
                (void)host_memcpy(theWrapParams.pIV, au8IVTmp, CipherGetBlockSize());
            }
        }
        else if( *pSW == VLT_STATUS_SUCCESS )
        {
#if(VLT_ENABLE_NO_WRAPKEY_CRC != VLT_ENABLE)
            /*
            * This is the last block so store the received CRC
            */
            Response.u16Len -= NUM_CRC_BYTES;

            /* Retrieve received CRC */
            u16ReceivedCrc = VltEndianReadPU16( 
                &Response.pu8Data[ Response.u16Len ] );
#endif
            /*
            * Decrypt the data
            */
            status = CipherDoFinal( &(Response.pu8Data[0]),
                Response.u16Len,
                Response.u16Capacity,
                &(Response.pu8Data[0]),
                &u32DataOutLen,
                Response.u16Capacity );

            if( VLT_OK == status )
            {
                /*
                * Adjust the length as some padding may have been removed
                */
                Response.u16Len = (VLT_U16)u32DataOutLen;
            }
        }
        else
        {
            status = EKWRKINVLDRSP;
        }
    }

    return( status );
}

static VLT_STS VltPutEncryptedKey(VLT_U8 u8KeyGroup, VLT_U8 u8KeyIndex, const VLT_FILE_PRIVILEGES *pKeyFilePrivileges, const VLT_KEY_OBJ_RAW* pKeyObj)
{
        VLT_U16 u16Remaining =
                VLT_PUTKEY_FIXED_DATA_LENGTH + *pKeyObj->pu16ClearKeyObjectLen;
        VLT_U16 u16KeyBytesRemaining = *(pKeyObj->pu16ClearKeyObjectLen);
        VLT_U16 u16MaxChunk = VltCommsGetMaxSendSize();
        VLT_U16 u16Offset = 0;
        VLT_STS status= VLT_FAIL;

        while (0u != u16Remaining)
        {
            VLT_SW Sw = VLT_STATUS_NONE;
            VLT_U16 u16Avail;
            VLT_U16 u16PartialKeyLen;
            VLT_U32 u32CipherDataLen = 0;
            VLT_U8 u8Final = 0;

            /*
            * Set index at the start of the data portion of the buffer
            */
            idx = VLT_APDU_DATA_OFFSET;

            /*
            * Build the data in
            */
            if (0u == u16Offset)
            {
                /*
                * Add the Key Privileges
                */
                Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
                Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
                Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
                Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

                /*
                * Add the Key Length
                */
                Command.pu8Data[idx++] =
                    (VLT_U8)((*pKeyObj->pu16ClearKeyObjectLen >> 8) & 0xFFu);

                Command.pu8Data[idx++] =
                    (VLT_U8)((*pKeyObj->pu16ClearKeyObjectLen >> 0) & 0xFFu);
            }

            u16Avail = NumBufferBytesAvail(u16MaxChunk, idx);

            if (u16KeyBytesRemaining > u16Avail)
            {
                /*
                * There is more key data remaining than can be transferred
                * in one transaction
                */
                u16PartialKeyLen = (u16Avail / CipherGetBlockSize())
                    * CipherGetBlockSize();
            }
            else
            {
                /*
                * The remaining data might all be able to be transferred in
                * one transaction
                */
                if (u16Avail >= (u16KeyBytesRemaining + CipherGetBlockSize()))
                {
                    u16PartialKeyLen = u16KeyBytesRemaining;

                    /*
                    * Flag that this will be the final block to be encrypted
                    */
                    u8Final = 1;
                }
                else
                {
                    u16PartialKeyLen =
                        u16KeyBytesRemaining - CipherGetBlockSize();
                }
            }

            /*
            * Copy the number of bytes of the partial key into the buffer
            */
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy(&(Command.pu8Data[idx]),
                &((pKeyObj->pu8KeyObject[u16Offset])),
                u16PartialKeyLen);

            /*
            * Now encrypt the data in the buffer
            */

            VLT_CIPHER_PARAMS theCipherParams= {0};
            status = VltConvWrapToCipher(&theCipherParams, &theWrapParams);
            if (VLT_OK != status) break;

            status = CipherInit(VLT_ENCRYPT_MODE, &theKey, &theCipherParams);
            if (VLT_OK != status) break;
            keyWrappingState = ST_CIPHER_INIT;

            if (1u == u8Final)
            {
                VLT_U16 dataInLen = (Command.u16Capacity - VLT_APDU_DATA_OFFSET);
                VLT_U16 dataOutCapacity = (Command.u16Capacity - VLT_APDU_DATA_OFFSET);

                status = CipherDoFinal(&(Command.pu8Data[idx]),
                    u16PartialKeyLen,
                    dataInLen,
                    &(Command.pu8Data[idx]),
                    &u32CipherDataLen,
                     dataOutCapacity);
            }
            else
            {
                VLT_U16 dataOutCapacity = (Command.u16Capacity - VLT_APDU_DATA_OFFSET);

                status = CipherUpdate(&(Command.pu8Data[idx]),
                    u16PartialKeyLen,
                    &(Command.pu8Data[idx]),
                    &u32CipherDataLen,
                    dataOutCapacity);

                if ((NULL != theWrapParams.pIV) && (VLT_MAX_IV_LENGTH < CipherGetBlockSize()))
                {
                    return EKUWKINVLIVSIZE;
                }

                /* Is IV used for key wrapping operation? */
                if (NULL != theWrapParams.pIV)
                {
                    VLT_U32 u32last_block_pos;

                    /* Get last ciphered block */
                    u32last_block_pos = (idx + u32CipherDataLen) - CipherGetBlockSize();


                    /* Update IV with last cyphered block */
                    host_memcpy(theWrapParams.pIV, &(Command.pu8Data[u32last_block_pos]), CipherGetBlockSize());
                }
            }

            if (VLT_OK == status)
            {
                /*
                * Update the index to reflect the data that has just been added
                */
                idx += (VLT_U16)u32CipherDataLen;

                /*
                * Subtract the number of key bytes that have just been added to
                * the buffer from the number of key bytes remaining to be sent
                */
                u16KeyBytesRemaining -= u16PartialKeyLen;

                /*
                * Decrement the remaining number of bytes to be sent.
                */
                if (0u == u16Offset)
                {
                    /*
                    * The first time the File Privileges and the length are
                    * included so include them plus the partial key length
                    * which won't include any padding bytes if some have been
                    * added
                    */
                    u16Remaining -= VLT_PUTKEY_FIXED_DATA_LENGTH + u16PartialKeyLen;

#if(VLT_ENABLE_NO_WRAPKEY_CRC != VLT_ENABLE)
                    u16Remaining += NUM_CRC_BYTES;
#endif
                }
                else
                {
                    /*
                    * Subtract the partial key length that was added to
                    * the buffer
                    */
                    u16Remaining -= u16PartialKeyLen;
                }

                /*
                * Update the offset into the key
                */
                u16Offset += u16PartialKeyLen;

#if(VLT_ENABLE_NO_WRAPKEY_CRC != VLT_ENABLE)
                /*
                * We need two bytes free in the buffer for the wCRC field.
                */
                if ((NUM_CRC_BYTES == u16Remaining) &&
                    (NumBufferBytesAvail(u16MaxChunk, idx) >= NUM_CRC_BYTES))
                {
                    Command.pu8Data[idx++] =
                        (VLT_U8)((pKeyObj->u16Crc >> 8) & 0xFFu);

                    Command.pu8Data[idx++] =
                        (VLT_U8)((pKeyObj->u16Crc >> 0) & 0xFFu);

                    u16Remaining -= NUM_CRC_BYTES;
                }
#endif
                /*
                * Setup the command header
                */
                if (0u == u16Remaining)
                {
                    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;

                }
                else
                {
                    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
                }
                Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_PUT_KEY;
                Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
                Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
                Command.pu8Data[VLT_APDU_P3_OFFSET] =
                    LIN(WRAPPED_BYTE(NumBytesInBuffer(idx)));

                /*
                * Send the command
                */
                status = VltCommand(&Command, &Response, idx, 0, &Sw);
                if (VLT_OK != status)
                {
                    break;
                }

                if ((VLT_STATUS_COMPLETED != Sw) &&
                    (VLT_STATUS_SUCCESS != Sw))
                {
                    /*
                    * The status word indicates a problem so set that as the
                    * return  value and break out of the while loop
                    */
                    status = Sw;
                    break;
                }
            }
            else
            {
                /*
                * Break out of the loop as the cipher failed
                */
                break;
            }
        }

        return status;
}

VLT_STS VltConvWrapToCipher(VLT_CIPHER_PARAMS *pOutCipherParams, VLT_WRAP_PARAMS *pInWrapParams)
{
    switch(pInWrapParams->enAlgoID)
    {

#if( VLT_ENABLE_CIPHER_RSA == VLT_ENABLE ) && IS_RSA_IMPLEMENTED_IN_CIPHER_SERVICE
        case VLT_ALG_KTS_RSA_OAEP_BASIC:
            pOutCipherParams->enAlgoID = VLT_ALG_CIP_RSAES_PKCS_OAEP;
            break;        
#endif
            
        case VLT_ALG_KTS_AES:
            pOutCipherParams->enAlgoID = VLT_ALG_CIP_AES;
            break;            
            
        default:
            return VLT_FAIL;
    }

    pOutCipherParams->enChainMode = pInWrapParams->enChainMode;
    pOutCipherParams->enPaddingScheme = pInWrapParams->enPaddingScheme;
    pOutCipherParams->pIV = pInWrapParams->pIV;
    
    return VLT_OK;
}

static VLT_STS VltReadEncryptedKey_Generic(VLT_U8 u8KeyGroup, VLT_U8 u8KeyIndex, VLT_KEY_OBJ_RAW* pKeyObj)
{
    VLT_STS status;
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_BOOL bReadComplete = FALSE;
#if(VLT_ENABLE_NO_WRAPKEY_CRC != VLT_ENABLE)
    VLT_U16 u16CalculatedCrc = VLT_CRC16_CCITT_INIT_0s;
#endif
    VLT_U16 u16RequestedLen = *pKeyObj->pu16ClearKeyObjectLen;
    VLT_U16 u16KeyObjLen = 0;
    
    status = VltReadEncryptedKey(u8KeyGroup, u8KeyIndex, &Sw);

    if (VLT_OK == status)
    {
        do
        {
            /*
            * Copy the data into the user's buffer if we have enough space
            */
            if ((u16KeyObjLen + Response.u16Len) <= u16RequestedLen)
            {
                /*
                * No need to check the return type as pointer has been validated
                */
                (void)host_memcpy(&(pKeyObj->pu8KeyObject[u16KeyObjLen]),
                    Response.pu8Data,
                    Response.u16Len);

#if(VLT_ENABLE_NO_WRAPKEY_CRC != VLT_ENABLE)
                /*
                * Update the CRC
                */
                u16CalculatedCrc = VltCrc16Block(u16CalculatedCrc,
                    &(Response.pu8Data[0]),
                    Response.u16Len);
#endif
            }


            /*
            * Update the length
            */
            u16KeyObjLen += Response.u16Len;

            if (Sw == VLT_STATUS_SUCCESS)
            {
                /*
                * We have received the whole key exit the loop
                */
                bReadComplete = TRUE;

#if(VLT_ENABLE_NO_WRAPKEY_CRC != VLT_ENABLE)                /*
                * Assign the received CRC value into the struct
                * returned to the host side caller.
                */
                pKeyObj->u16Crc = u16ReceivedCrc;

                /*
                * Validate received CRC
                */
                if (u16ReceivedCrc != u16CalculatedCrc)
                {
                    status = EKWUKSCIVLDCRC;
                }
#endif
            }
            else if (Sw == VLT_STATUS_RESPONDING)
            {
                /*
                * Read more data
                */
                status = VltReadEncryptedKey(u8KeyGroup,
                    u8KeyIndex,
                    &Sw);

                if (VLT_OK != status)
                {
                    /*
                    * Break out of the while loop as something has gone
                    * wrong
                    */
                    break;
                }
            }
            else
            {
                /*
                * Set the status word as the return value and break out
                * of the while loop
                */
                status = Sw;
                break;
            }
        } while (bReadComplete == FALSE);


        *(pKeyObj->pu16ClearKeyObjectLen) = u16KeyObjLen;

        /*
        * If we have run out of space let the caller know
        * the true length of the key requested and return
        * the appropriate error code.
        */
        if (u16KeyObjLen > u16RequestedLen)
        {
            status = EKWUKWNOROOM;
        }
    }

    
    return(status);
}

#if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE) || (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE)

static VLT_STS VltReadEncryptedKey_SP800(VLT_U8 u8KeyGroup, VLT_U8 u8KeyIndex, VLT_KTS_PADDING_MODE kwPaddingMode, VLT_BOOL isP25, VLT_KEY_OBJ_RAW* pKeyObj )
{
    VLT_STS status;
    VLT_U32 u32DataOutLen = 0;
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_BOOL bReadComplete = FALSE;
    VLT_BOOL bChaining = FALSE;

    VLT_U32 u32MaxOutLen = *pKeyObj->pu16ClearKeyObjectLen;

    status = AesKwInit(VLT_DECRYPT_MODE, &theKey, (kwPaddingMode== VLT_KTS_PADDING_MODE_KWP));
    keyWrappingState = ST_CIPHER_INIT;

    do
    {
        /* Build APDU */
        Command.pu8Data[VLT_APDU_CLASS_OFFSET] = bChaining ? VLT_CLA_CHAINING : VLT_CLA_NO_CHANNEL;
        Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_READ_KEY;
        Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
        Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
        Command.pu8Data[VLT_APDU_P3_OFFSET] =
            WRAPPED_BYTE(VltCommsGetMaxReceiveSize());

        idx = VLT_APDU_DATA_OFFSET;

        /*
        * Send the command
        */
        status = VltCommand(&Command, &Response, idx, 0, &Sw);
        if (VLT_OK == status)
        {
            /*
            * Adjust the response size to take in account the status word size
            */
            Response.u16Len -= VLT_SW_SIZE;

            if (Sw == VLT_STATUS_RESPONDING)
            {
                bChaining = TRUE;

                if (isP25)
                {
                    // should not happen as P25 keys are short
                    status = VLT_FAIL;
                }
                else
                {
                    // Append encrypted key object in aes kw crypto buffer
                    status = AesKwUpdate(Response.pu8Data, Response.u16Len);
                }
            }
            else if (Sw == VLT_STATUS_SUCCESS)
            {
                bReadComplete = TRUE;
            }
            else
            {
                status = EKWRKINVLDRSP;
            }
        }
    } while ((bReadComplete == FALSE) && (status == VLT_OK));

    if (VLT_OK == status)
    {
        if (isP25)
        {
            host_memcpy(pKeyObj->pu8KeyObject, Response.pu8Data, KEY_OBJ_HEADER_SIZE);
            
            /*
            * Decrypt key received
                note: only key field (abKey) is encrypted*/
            status = AesKwDoFinal(Response.pu8Data+ KEY_OBJ_HEADER_SIZE, Response.u16Len - KEY_OBJ_HEADER_SIZE, 
                                  pKeyObj->pu8KeyObject+ KEY_OBJ_HEADER_SIZE, &u32DataOutLen, u32MaxOutLen);

            u32DataOutLen += KEY_OBJ_HEADER_SIZE; // Add key object header
        }
        else
        {
            /*
                * Decrypt key object received
                note: whole keyobject is encrypted*/
            status = AesKwDoFinal(&(Response.pu8Data[0]),
                Response.u16Len, pKeyObj->pu8KeyObject,
                &u32DataOutLen, u32MaxOutLen);
        }

        // Update length
        *(pKeyObj->pu16ClearKeyObjectLen) = (VLT_U16) u32DataOutLen;

        /*
        * If we have run out of space let the caller know
        * the true length of the key requested and return
        * the appropriate error code.
        */
        if (status == EAESKW_DATA_OVERFLOW)
        {
            status = EKWUKWNOROOM;
        }
    }
    
    AesKwClose();

    return(status);
}

static VLT_STS VltPutEncryptedKey_SP800(VLT_U8 u8KeyGroup, VLT_U8 u8KeyIndex, VLT_KTS_PADDING_MODE kwPaddingMode, VLT_BOOL isP25, const VLT_FILE_PRIVILEGES *pKeyFilePrivileges, const VLT_KEY_OBJ_RAW* pKeyObj)
{
    VLT_U32 u32Remaining = 0;
    VLT_U32 u32KeyBytesRemaining = 0;
    VLT_U16 u16MaxChunk = VltCommsGetMaxSendSize();
    VLT_U16 u16Offset = 0;
    VLT_STS status = VLT_FAIL;
    VLT_U8 au8EncryptedKeyBuffer[1024]; // sufficient to store an encrypted RSA CRT 2048 bits

    /*
      Encrypt key value
    */
    status = AesKwInit(VLT_ENCRYPT_MODE, &theKey, kwPaddingMode);
    if (VLT_OK == status)
    {
        if (isP25)
        {

            status = AesKwDoFinal(pKeyObj->pu8KeyObject + KEY_OBJ_HEADER_SIZE, // encrypt key value only
                *pKeyObj->pu16ClearKeyObjectLen - KEY_OBJ_HEADER_SIZE, au8EncryptedKeyBuffer, &u32KeyBytesRemaining, sizeof(au8EncryptedKeyBuffer));

        }
        else
        {
            status = AesKwDoFinal(pKeyObj->pu8KeyObject,  // encrypt whole key object
                *pKeyObj->pu16ClearKeyObjectLen, au8EncryptedKeyBuffer, &u32KeyBytesRemaining, sizeof(au8EncryptedKeyBuffer));
        }
    }

    if (VLT_OK == status)
    {
        // Total length of data to send
        if (isP25)
        {
            u32Remaining = 4 + // key access conditions
                2 + // key obj length
                KEY_OBJ_HEADER_SIZE + // key obj header (id, mask, key len)
                u32KeyBytesRemaining; // size of encrypted key
        }
        else
        {
            // Total length of data to send
            u32Remaining = u32KeyBytesRemaining; // size of encrypted key object
        }


        while (u32Remaining > 0)
        {
            VLT_SW Sw = VLT_STATUS_NONE;
            VLT_U16 u16Avail;
            VLT_U16 u16PartialKeyLen;

            /*
            * Set index at the start of the data portion of the buffer
            */
            idx = VLT_APDU_DATA_OFFSET;

            /*
            * Build the data in
            */
            if (0u == u16Offset)
            {
                /*
                * Add the Key Privileges
                */
                Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
                Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
                Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
                Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

                /*
                * Add the Key Object Length
                */
                Command.pu8Data[idx++] =
                    (VLT_U8)((*pKeyObj->pu16ClearKeyObjectLen >> 8) & 0xFFu);

                Command.pu8Data[idx++] =
                    (VLT_U8)((*pKeyObj->pu16ClearKeyObjectLen >> 0) & 0xFFu);

                if (isP25)
                {
                    /*
                    * Add the Key Object header
                    */
                    (void)host_memcpy(&(Command.pu8Data[idx]), pKeyObj->pu8KeyObject, KEY_OBJ_HEADER_SIZE);
                    idx += KEY_OBJ_HEADER_SIZE;
                }
            }

            // Number of bytes that can still be placed in the apdu buffer
            u16Avail = NumBufferBytesAvail(u16MaxChunk, idx);

            if (u32KeyBytesRemaining > u16Avail)
            {
                /*
                * There is more key data remaining than can be transferred
                * in one transaction
                */
                u16PartialKeyLen = u16Avail;
            }
            else
            {
                u16PartialKeyLen = (VLT_U16)u32KeyBytesRemaining;
            }

            /*
            * Copy the number of bytes of the partial key block into the buffer
            */
            (void)host_memcpy(&(Command.pu8Data[idx]),
                &(au8EncryptedKeyBuffer[u16Offset]),
                u16PartialKeyLen);

            /*
            * Update the index to reflect the data that has just been added
            */
            idx += u16PartialKeyLen;

            /*
            * Subtract the number of key bytes that have just been added to
            * the buffer from the number of key bytes remaining to be sent
            */
            u32KeyBytesRemaining -= u16PartialKeyLen;

            /*
            * Decrement the remaining number of bytes to be sent.
            */
            u32Remaining = u32KeyBytesRemaining;

            /*
            * Update the offset into the enc key buffer
            */
            u16Offset += u16PartialKeyLen;

            /*
            * Setup the command header
            */
            if (0u == u32Remaining)
            {
                Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;

            }
            else
            {
                Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
            }
            Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_PUT_KEY;
            Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
            Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
            Command.pu8Data[VLT_APDU_P3_OFFSET] =
                LIN(WRAPPED_BYTE(NumBytesInBuffer(idx)));

            /*
            * Send the command
            */
            status = VltCommand(&Command, &Response, idx, 0, &Sw);
            if (VLT_OK != status)
            {
                break;
            }

            if ((VLT_STATUS_COMPLETED != Sw) &&
                (VLT_STATUS_SUCCESS != Sw))
            {
                /*
                * The status word indicates a problem so set that as the
                * return  value and break out of the while loop
                */
                status = Sw;
                break;
            }
        }
    }

    AesKwClose();

    return(status);

}
#endif /* #if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE) || (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE) */

#endif /* #if( VLT_ENABLE_KEY_WRAPPING == VLT_ENABLE ) */
