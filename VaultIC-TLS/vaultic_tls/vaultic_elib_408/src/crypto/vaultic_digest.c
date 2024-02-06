/**
* @file	   vaultic_digest.c
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
#if (VLT_ENABLE_SHA == VLT_ENABLE) 
#include "vaultic_mem.h"
#include "vaultic_utils.h"
#include "vaultic_digest.h"
#include "vaultic_config.h"

#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
#include <openssl/evp.h>
#include <openssl/sha.h>
#else
#include "vaultic_sha256.h"
#endif

/**
 * Private Defs
 */
#define ST_UNKNOWN				0x00
#define ST_INITIALISED          0x10
#define ST_UPDATED				0x30
#define ST_FINALISED			0x40

/**
 * Private Data
 */
static VLT_U8 digestState = ST_UNKNOWN;

#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
static EVP_MD_CTX *mctx = NULL;
#else

static VLT_ALG_DIG_ID  ctx_digest_id;
#if (VLT_ENABLE_SHA256 == VLT_ENABLE)
static sha256_ctx ctx_sha256;
#endif
#if (VLT_ENABLE_SHA384 == VLT_ENABLE)
static sha384_ctx ctx_sha384;
#endif
#if (VLT_ENABLE_SHA512 == VLT_ENABLE)
static sha384_ctx ctx_sha512;
#endif

#endif


/**
 * Private Functions
 */



/* --------------------------------------------------------------------------
 * DigestInit
 * -------------------------------------------------------------------------- */
VLT_STS DigestInit(VLT_ALG_DIG_ID enDigestId)
{   
#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
    EVP_MD* md;
    int digNid;

    /* Check the requested digest is supported*/
    switch (enDigestId)
    {
#if(VLT_ENABLE_SHA1 == VLT_ENABLE)
        case VLT_ALG_DIG_SHA1:
            digNid = NID_sha1;
            break;
#endif
#if(VLT_ENABLE_SHA224 == VLT_ENABLE)
        case VLT_ALG_DIG_SHA224:
            digNid = NID_sha224;
            break;
#endif
#if(VLT_ENABLE_SHA256 == VLT_ENABLE)
        case VLT_ALG_DIG_SHA256:
            digNid = NID_sha256;
            break;
#endif
#if(VLT_ENABLE_SHA384 == VLT_ENABLE)
        case VLT_ALG_DIG_SHA384:
            digNid = NID_sha384;
            break;
#endif
#if(VLT_ENABLE_SHA512 == VLT_ENABLE)
        case VLT_ALG_DIG_SHA512:
            digNid = NID_sha512;
            break;
#endif
        default:
            return EEDIGESTINVALIDPARAM;
            break;
    }

    /* Init Open SSL*/
    OpenSSL_add_all_digests();

    mctx = EVP_MD_CTX_create();

    if (mctx == NULL) {
        return EEDIGESTEXECUTIONERROR;
    }

    md = (EVP_MD*)EVP_get_digestbynid(digNid);

    if (!EVP_DigestInit_ex(mctx, md, NULL)) {
        return EEDIGESTEXECUTIONERROR;
    }

#else

    /* Check the requested digest is supported*/
    switch (enDigestId)
    {
#if(VLT_ENABLE_SHA256 == VLT_ENABLE)
    case VLT_ALG_DIG_SHA256:
			sha256_begin(&ctx_sha256);
        break;
#endif

#if (VLT_ENABLE_SHA384 == VLT_ENABLE)
    	case VLT_ALG_DIG_SHA384:
    		sha384_begin(&ctx_sha384);
        break;
#endif

#if (VLT_ENABLE_SHA512 == VLT_ENABLE)
    	case VLT_ALG_DIG_SHA512:
    		sha512_begin(&ctx_sha512);
        break;
#endif

    default:
        return EEDIGESTSEQERROR;
        break;
}

     ctx_digest_id = enDigestId;

#endif

     /* Update state */
     digestState = ST_INITIALISED;
    return VLT_OK;
}


/* --------------------------------------------------------------------------
 * DigestUpdate
 * -------------------------------------------------------------------------- */
VLT_STS DigestUpdate(const VLT_U8 *pu8Message, VLT_U32 u32MessageLen)
{
    /* Check state */
    if ( (ST_INITIALISED != digestState) && (ST_UPDATED != digestState))  {
        return EEDIGESTSEQERROR;
    }

#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
    /* Compute Digest  */
    if (!EVP_DigestUpdate(mctx, pu8Message, u32MessageLen))
    {
        return EEDIGESTEXECUTIONERROR;
    }

#else
    /* Compute Digest  */
    switch (ctx_digest_id)
    {
#if(VLT_ENABLE_SHA256 == VLT_ENABLE)
    case VLT_ALG_DIG_SHA256:
			sha256_hash(pu8Message, u32MessageLen, &ctx_sha256);
        break;
#endif

#if (VLT_ENABLE_SHA384 == VLT_ENABLE)
    	case VLT_ALG_DIG_SHA384:
    		sha384_hash(pu8Message, u32MessageLen, &ctx_sha384);
        break;
#endif

#if (VLT_ENABLE_SHA512 == VLT_ENABLE)
    	case VLT_ALG_DIG_SHA512:
    		sha512_hash(pu8Message, u32MessageLen, &ctx_sha512);
        break;
#endif

		default:
			return EECDSAINVALIDPARAM;
			break;
	}

#endif
    /* Update state */
    digestState = ST_UPDATED;

    return VLT_OK;
}


/* --------------------------------------------------------------------------
* DigestDoFinal
* -------------------------------------------------------------------------- */
VLT_STS DigestDoFinal(VLT_U8 *pu8DigestBuffer, VLT_U32 *pu32DigestLen, VLT_U32 u32DigestCapacity)
{
    /* Check state */
    if (ST_UPDATED != digestState) {
        return EEDIGESTSEQERROR;
    }

#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
    
    /* Check digest result buffer is large enough to store digest*/
    if ((VLT_U32)EVP_MD_CTX_size(mctx) > u32DigestCapacity) {
            return EEDIGESTOVERFLOW;
        }

    /* Copy digest in result buffer*/
    if (!EVP_DigestFinal(mctx, pu8DigestBuffer, (unsigned int *) pu32DigestLen)) {
        return EEDIGESTEXECUTIONERROR;
    }
#else

    switch (ctx_digest_id)
    {
#if(VLT_ENABLE_SHA256 == VLT_ENABLE)
        case VLT_ALG_DIG_SHA256:
    	    /* Check digest result buffer is large enough to store digest*/
    		if(u32DigestCapacity < SHA256_DIGEST_LENGTH) return EEDIGESTOVERFLOW;

    		/* Copy digest in result buffer*/
    		sha256_end(pu8DigestBuffer, &ctx_sha256);
    		
            /* Return length */
            if (pu32DigestLen!=NULL) *pu32DigestLen = SHA256_DIGEST_LENGTH;
    		break;
#endif

#if (VLT_ENABLE_SHA384 == VLT_ENABLE)
    	case VLT_ALG_DIG_SHA384:
    	    /* Check digest result buffer is large enough to store digest*/
    		if(u32DigestCapacity < SHA384_DIGEST_LENGTH) return EEDIGESTOVERFLOW;

    		/* Copy digest in result buffer*/
    		sha384_end(pu8DigestBuffer, &ctx_sha384);

            /* Return length */
            if (pu32DigestLen != NULL) *pu32DigestLen = SHA384_DIGEST_LENGTH;
    		break;
#endif

#if (VLT_ENABLE_SHA512 == VLT_ENABLE)
    	case VLT_ALG_DIG_SHA512:
			/* Check digest result buffer is large enough to store digest*/
			if(u32DigestCapacity < SHA512_DIGEST_LENGTH) return EEDIGESTOVERFLOW;

			/* Copy digest in result buffer*/
			sha512_end(pu8DigestBuffer, &ctx_sha512);

            /* Return length */
            if (pu32DigestLen != NULL) *pu32DigestLen = SHA512_DIGEST_LENGTH;
			break;
#endif

    	default:
    		return EEDIGESTEXECUTIONERROR;
    }

#endif

    /* Reset state */
    digestState = ST_UNKNOWN;

    return VLT_OK;
}

#endif

