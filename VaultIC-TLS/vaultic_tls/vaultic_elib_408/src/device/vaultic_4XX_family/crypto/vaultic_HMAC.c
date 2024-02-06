/**
* @file	   vaultic_HMAC.c
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


#include "vaultic_HMAC.h"
#if ( VLT_ENABLE_SIGN_HMAC == VLT_ENABLE )
#include "vaultic_utils.h"
#include "vaultic_symmetric_signer.h"
#include "vaultic_digest.h"
#include <string.h>

#define EHMACSIGNER_INVALID_NULL_PARAMS     VLT_ERROR( VLT_HMAC, 0u )
#define EHMACSIGNER_SIGNER_ALGO_ID_NOT_SUP	VLT_ERROR( VLT_HMAC, 1u )
#define EHMACSIGNER_SIGNER_NOT_SETUP		VLT_ERROR( VLT_HMAC, 2u )
#define EHMACSIGNER_SIGNER_NO_MEMORY		VLT_ERROR( VLT_HMAC, 3u )
#define EHMACSIGNER_INIT_NO_MEMORY			VLT_ERROR( VLT_HMAC, 4u )
#define EHMACBADDIGEST                      VLT_ERROR( VLT_HMAC, 5u )
#define EHMACINVALIDCOMPILSETTINGS          VLT_ERROR( VLT_HMAC, 6u )

#define ST_UNKNOWN          0x00u
#define ST_INITIALISED      0x10u
#define ST_FINALISED        0x20u

static VLT_U8 signerState = ST_UNKNOWN;
static VLT_KEY_BLOB theKey = {0};
static VLT_HMAC_PARAMS theParams = {0};
static VLT_U8 u8hashlen;
static VLT_U8 *pu8FinalHash = NULL;

const VLT_U8 u8ipad = (VLT_U8)0x36;
const VLT_U8 u8opad = (VLT_U8)0x5C;


VLT_STS SignerHMACInit(VLT_ALGO_MODE opMode, const VLT_KEY_BLOB *pKey, const VLT_HMAC_PARAMS *pParams )
{
#if (VLT_ENABLE_SHA == VLT_ENABLE) 
    VLT_STS status = VLT_OK;

	/**
	* Make sure we have a valid params pointers
	*/
	if( ( NULL == pParams ) ||
		( NULL == pKey ) )
		return( EHMACSIGNER_INVALID_NULL_PARAMS );
	
    if ( VLT_SIGN_MODE != opMode )
		return ( EHMACSIGNER_SIGNER_ALGO_ID_NOT_SUP );

    /* check digest id*/
    switch (pParams->enDigestID)
    {
#if(VLT_ENABLE_SHA256 == VLT_ENABLE)
        case VLT_ALG_DIG_SHA256:
            u8hashlen = 256/8;
            theParams.u8blockSize = 64;
            break;
#endif

#if(VLT_ENABLE_SHA384 == VLT_ENABLE)
        case VLT_ALG_DIG_SHA384:
            u8hashlen = 384/8;
            theParams.u8blockSize = 128;
            break;
#endif

#if(VLT_ENABLE_SHA512 == VLT_ENABLE)
        case VLT_ALG_DIG_SHA512:
            u8hashlen = 512/8;
            theParams.u8blockSize = 128;
            break;
#endif

        default:
            return EHMACBADDIGEST;
    }
    
	theParams.enDigestID = pParams->enDigestID;
	theParams.u8outputSize = pParams->u8outputSize;

	theKey.keySize = pKey->keySize;
	theKey.keyType = pKey->keyType;
	theKey.keyValue = (VLT_U8 *)malloc(theKey.keySize);
	if (theKey.keyValue != NULL)
	{
		memcpy(theKey.keyValue, pKey->keyValue, theKey.keySize);
	}
	else
	{
		return (EHMACSIGNER_INIT_NO_MEMORY);
	}

	signerState = ST_INITIALISED;

	return status;
#else // #if (VLT_ENABLE_SHA == VLT_ENABLE) 
    return EHMACINVALIDCOMPILSETTINGS;
#endif
}

VLT_U16 SignerHMACGetBlockSize( void )
{
	return theParams.u8blockSize;
}

VLT_STS SignerHMACDoFinal( 
	VLT_U8 *pHMac, 
	VLT_U32 *pHMacLen)
{
	if (pHMac == NULL)
	{
		if (pHMacLen != NULL)
		{
			*pHMacLen = u8hashlen;
		}
		return (VLT_OK);
	}

	memcpy(pHMac,pu8FinalHash,theParams.u8outputSize);

	return (SignerHMACFinal( ));
}

VLT_STS SignerHMACFinal( void )
{
	if( ST_UNKNOWN != signerState )
	{
		signerState = ST_UNKNOWN;
		FREE(pu8FinalHash);
	}

	return SignerHMACClose();
}

VLT_STS SignerHMACUpdate( const VLT_U8 *pMessage, VLT_U32 messageLen)
{
#if (VLT_ENABLE_SHA == VLT_ENABLE) 
	VLT_STS status = VLT_OK;
	unsigned int idx;
	VLT_U8 *k0 = NULL;
	VLT_U8 *k0xoripad = NULL;
	VLT_U8 *k0xoropad = NULL;
	VLT_U8 *pu8intermediateMessage1 = NULL;
	VLT_U8 *pu8interhash = NULL;
	VLT_U8 *pu8intermediateMessage2 = NULL;

	if ( ( ST_UNKNOWN == signerState ) ||
		( ST_FINALISED == signerState ) )
	{
		return( EHMACSIGNER_SIGNER_NOT_SETUP );
	}

	//Step 1
	k0 = (VLT_U8 *)malloc(SignerHMACGetBlockSize());
	if (k0 == NULL)
		return( EHMACSIGNER_SIGNER_NO_MEMORY );

	if (!(theKey.keySize == SignerHMACGetBlockSize()))
	{
		if (theKey.keySize > SignerHMACGetBlockSize()) //Step 2
		{
			//Fill buffer to 0x00 
			memset(k0,0x00,SignerHMACGetBlockSize());

            //Hash the key
            status = DigestInit(theParams.enDigestID);
            if (status == VLT_OK) {
                status = DigestUpdate(theKey.keyValue, theKey.keySize);
            }
            if (status == VLT_OK) {
                status = DigestDoFinal(k0, NULL, SignerHMACGetBlockSize());
            }
		}
		else //Step 3: theKey.keySize < SignerHMACGetBlockSize()
		{
			//Fill buffer to 0x00 
			memset(k0,0x00,SignerHMACGetBlockSize());
			//copy the key value at the beginning
			memcpy(k0,theKey.keyValue,theKey.keySize);
		}
	}

	//Copy the K to k0xoripad and to k0xoropad
	k0xoripad = (VLT_U8 *)malloc(SignerHMACGetBlockSize());
	k0xoropad = (VLT_U8 *)malloc(SignerHMACGetBlockSize());


    if (k0xoripad == NULL || k0xoropad == NULL)
    {
        status = EHMACSIGNER_SIGNER_NO_MEMORY;
    }
    else
    {

        //Step 4 & step 7 (done here to remove one loop)
        //Perform Xor
        for (idx = 0; idx < SignerHMACGetBlockSize(); idx++)
        {
            //step 4
            k0xoropad[idx] = (VLT_U8)(k0[idx] ^ u8opad);
            //step 7
            k0xoripad[idx] = (VLT_U8)(k0[idx] ^ u8ipad);
        }
        FREE(k0);

        //Step 5
        pu8intermediateMessage1 = (VLT_U8 *)malloc(SignerHMACGetBlockSize() + messageLen);
        if (pu8intermediateMessage1 != NULL)
        {
            //copy k0xoripad
            memcpy(pu8intermediateMessage1, k0xoripad, SignerHMACGetBlockSize());
            //copy message
            memcpy(pu8intermediateMessage1 + SignerHMACGetBlockSize(), pMessage, messageLen);
            //release k0xoripad
            FREE(k0xoripad);

            //Step 6 : HASH pu8intermediateMessage1
            pu8interhash = (VLT_U8 *)malloc(u8hashlen);
            if (pu8interhash == NULL)
            {
                status = EHMACSIGNER_SIGNER_NO_MEMORY;
            }
            else if (pu8intermediateMessage1 != NULL)
            {
                /* e or e1 = SHA-(M) */
                status = DigestInit(theParams.enDigestID);
                if (status == VLT_OK) {
                    status = DigestUpdate(pu8intermediateMessage1, SignerHMACGetBlockSize() + messageLen);
                }
                if (status == VLT_OK) {
                    status = DigestDoFinal(pu8interhash, NULL, u8hashlen);
                }

                //Step 8
                pu8intermediateMessage2 = (VLT_U8 *)malloc(SignerHMACGetBlockSize() + u8hashlen);
                if (pu8intermediateMessage2 != NULL)
                {
                    //copy k0xoropad
                    memcpy(pu8intermediateMessage2, k0xoropad, SignerHMACGetBlockSize());
                    //copy message
                    memcpy(pu8intermediateMessage2 + SignerHMACGetBlockSize(), pu8interhash, u8hashlen);
                    //release k0xoropad
                    FREE(k0xoropad);
                    FREE(pu8interhash);

                    //Step 9 HASH pu8intermediateMessage2
                    pu8FinalHash = (VLT_U8 *)malloc(u8hashlen);
                    if (pu8FinalHash != NULL)
                    {
                        status = DigestInit(theParams.enDigestID);
                        if (status == VLT_OK) {
                            status = DigestUpdate(pu8intermediateMessage2, SignerHMACGetBlockSize() + u8hashlen);
                        }
                        if (status == VLT_OK) {
                            status = DigestDoFinal(pu8FinalHash, NULL, u8hashlen);
                        }
                    }
                    else
                    {
                        status = EHMACSIGNER_SIGNER_NO_MEMORY;
                    }
                }
                else
                {
                    status = EHMACSIGNER_SIGNER_NO_MEMORY;
                }
            }
            else
            {
                status = EHMACSIGNER_SIGNER_NO_MEMORY;
            }
        }
        else
        {
            status = EHMACSIGNER_SIGNER_NO_MEMORY;
        }
    }

    FREE(k0);

	FREE(k0xoropad);
	FREE(pu8interhash);
	FREE(k0xoripad);
	FREE(pu8intermediateMessage1);
	FREE(pu8intermediateMessage2);

	return status;
#else // #if (VLT_ENABLE_SHA == VLT_ENABLE) 
    return EHMACINVALIDCOMPILSETTINGS;
#endif
}

VLT_STS SignerHMACClose( void )
{
	theParams.u8blockSize = 0;
	theParams.enDigestID = (VLT_ALG_DIG_ID)0;
	theParams.u8outputSize = 0;

	theKey.keySize = 0;
	theKey.keyType = (VLT_KEY_ID)0;
	FREE(theKey.keyValue);
	return VLT_OK;
}
#endif