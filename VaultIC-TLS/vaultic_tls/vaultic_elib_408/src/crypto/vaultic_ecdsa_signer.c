/**
* @file	   vaultic_ecdsa_signer.c
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
#if( VLT_ENABLE_SIGN_xDSA == VLT_ENABLE)
#include "vaultic_mem.h"
#include "vaultic_utils.h"
#include "vaultic_ecdsa_signer.h"
#include "vaultic_digest.h"
#include "vaultic_curves.h"
#include <time.h>
#include <stdlib.h>

#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#endif

#if (HOST_CRYPTO == HOST_CRYPTO_ARM_CRYPTO_LIB)
#include "vaultic_bigdigits.h"
#include "HAL_TYPEDEF.h"
#include "TbxSw_Ecc_Curves_GF2n.h"
#include "TbxSw_EcDsa_GF2n.h"
#include "TbxSw_Rc.h"
#include "TbxSw_Drng.h"
#endif

/**
 * Private Defs
 */
#define ST_UNKNOWN				0x00
#define ST_INITIALISED_SIGN		0x10
#define ST_INITIALISED_VERIFY	0x20
#define ST_UPDATED				0x30
#define ST_FINALISED			0x40

#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
#define MAX_DIGEST_LENGTH   SHA512_DIGEST_LENGTH
#endif

#if (HOST_CRYPTO == HOST_CRYPTO_ARM_CRYPTO_LIB)
#define MAX_DIGITS			(MAX_ECC_KEY_BYTES_SIZE / sizeof(VLT_U32))

#define HASH_SIZE			256			/* SHA-256 bit size */
#define HASH_DIGIT_SIZE		(HASH_SIZE / (sizeof(VLT_U32) * 8))	/* number of big digits in a hash */
#define HASH_BYTE_SIZE		(HASH_SIZE / (sizeof(VLT_U8) * 8))	/* number of bytes in a hash */

#define NUM_DIGITS(n)	((n) % sizeof(VLT_U32) ? ((n) / sizeof(VLT_U32)) + 1 : ((n) / sizeof(VLT_U32)))
#endif

/**
 * Private Data
 */
static VLT_U8 signerState = ST_UNKNOWN;

#if (VLT_ENABLE_ECDSA == VLT_ENABLE)
#if (HOST_CRYPTO != HOST_CRYPTO_NONE)
static int             ctx_curve_id;
#endif
static const VLT_ECDSA_PUBLIC_KEY *ctx_pub_key;
static const VLT_ECDSA_PRIVATE_KEY *ctx_priv_key;
#endif


/* --------------------------------------------------------------------------
 * EcdsaSignerInit
 * -------------------------------------------------------------------------- */
VLT_STS EcdsaSignerInit(
    VLT_ECC_ID enCurveId,
    VLT_ALG_DIG_ID enDigestId,
    const VLT_ECDSA_PRIVATE_KEY* pPrivateKey,
    const VLT_ECDSA_PUBLIC_KEY* pPublicKey,
    VLT_SIGNER_MODE enSignerMode)
{   

#if (VLT_ENABLE_SHA == VLT_ENABLE) && (VLT_ENABLE_ECDSA == VLT_ENABLE)

#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
    /* Check the requested curve is supported*/
    if (VLT_OK != EcdsaGetCurveNID(enCurveId, &ctx_curve_id)) {
        return EECCCURVEIDINVLD;
    }
#endif

#if (HOST_CRYPTO == HOST_CRYPTO_ARM_CRYPTO_LIB)
    /* Check the requested curve is supported*/
    if(enCurveId != VLT_ECC_ID_B163) {
    	return EECCCURVEIDINVLD;
    }
	ctx_curve_id = enCurveId;
#endif

    /* Initialize the digest engine  */
	if (DigestInit(enDigestId) != VLT_OK) {
		return EECCVESINVLDDIGEST;
	}


    /* Check the operation mode is supported */
    if (VLT_SIGNER_MODE_SIGN == enSignerMode)
    {
        /* SIGN needs a valid private key */
        if (NULL == pPrivateKey) {
            return (EECDSAINITNULLPARAM);
        }

        if (NULL == pPrivateKey->pu8D) {
            return EECDSAINITNULLPARAM;
        }
        
        if ((pPrivateKey->u16DLen == 0)
#if (VLT_ENABLE_ECDSA == VLT_ENABLE)            
            || (pPrivateKey->u16DLen > MAX_ECC_KEY_BYTES_SIZE)
#endif            
         ) {
            return EECDSAINVALIDPARAM;
        }

        ctx_priv_key = pPrivateKey;
        signerState = ST_INITIALISED_SIGN;
    }
    else if (VLT_SIGNER_MODE_VERIFY == enSignerMode)
    {
        /* VERIFY needs a public private key */
        if (NULL == pPublicKey ) {
            return (EECDSAINITNULLPARAM);
        }

        if ((NULL == pPublicKey->pu8Qx) || (NULL == pPublicKey->pu8Qy)) {
            return EECDSAINITNULLPARAM;
        }
        
        if (
            (pPublicKey->u16QLen == 0) 
#if (VLT_ENABLE_ECDSA == VLT_ENABLE)
            || (pPublicKey->u16QLen > MAX_ECC_KEY_BYTES_SIZE)
#endif            
            ) {
            return EECDSAINVALIDPARAM;
        }

        ctx_pub_key = pPublicKey;
        signerState = ST_INITIALISED_VERIFY;
    }
    else 
    {
        /* invalid mode */
        return (EECDSAOPMODENOTSUPP);
    }

   return VLT_OK;
#else // #if (VLT_ENABLE_SHA == VLT_ENABLE) && (VLT_ENABLE_ECDSA == VLT_ENABLE)
    return EECDSAINVALIDCOMPILSETTINGS;
#endif
}

/* --------------------------------------------------------------------------
 * EcdsaSignerClose
 * -------------------------------------------------------------------------- */
VLT_STS EcdsaSignerClose( void )
{
    signerState = ST_UNKNOWN;

    return VLT_OK;
}


/* --------------------------------------------------------------------------
 * EcdsaSignerDoFinal
 * -------------------------------------------------------------------------- */
VLT_STS EcdsaSignerDoFinal(
    const VLT_U8 *pu8Message,
    VLT_U32 u32MessageLen, 
    VLT_U8 *pu8Signature, 
    VLT_U16 *pu16SignatureLen, 
    VLT_U32 u32SignatureCapacity )
{

#if (VLT_ENABLE_SHA == VLT_ENABLE) && (VLT_ENABLE_ECDSA == VLT_ENABLE)

    if((ST_INITIALISED_SIGN != signerState) && (ST_INITIALISED_VERIFY != signerState))
    {
        /* not initialised */
        return EECDSAEXECUTIONERROR;
    }

#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
    VLT_STS status = VLT_FAIL;

    EC_KEY *eckey;
    EC_GROUP *ecgroup;
    VLT_U8 pHash[MAX_DIGEST_LENGTH];
    VLT_U32 u32HashLen = 0;

    /* Compute hash of input message */
    if (VLT_OK != (status = DigestUpdate(pu8Message, u32MessageLen))) return status;
    if (VLT_OK != (status = DigestDoFinal(pHash, &u32HashLen, sizeof(pHash) ))) return status;

    eckey = EC_KEY_new();
    ecgroup = EC_GROUP_new_by_curve_name(ctx_curve_id);
    EC_KEY_set_group(eckey, ecgroup);

    switch (signerState)
    {
        /* VERIFY signature */
        case ST_INITIALISED_VERIFY:
        {
            /* set signature */
            BIGNUM *bn_r = BN_new();
            BIGNUM *bn_s = BN_new();
            ECDSA_SIG *signature = ECDSA_SIG_new();

            BN_bin2bn(pu8Signature, *pu16SignatureLen / 2, bn_r);
            BN_bin2bn(pu8Signature + (*pu16SignatureLen / 2), *pu16SignatureLen / 2, bn_s);

            ECDSA_SIG_set0(signature, bn_r, bn_s);

            /* set public key */
            BIGNUM *bn_x = BN_new();
            BIGNUM *bn_y = BN_new();
            BN_bin2bn(ctx_pub_key->pu8Qx, ctx_pub_key->u16QLen, bn_x);
            BN_bin2bn(ctx_pub_key->pu8Qy, ctx_pub_key->u16QLen, bn_y);

            EC_KEY_set_public_key_affine_coordinates(eckey, bn_x, bn_y);

            int isValid = ECDSA_do_verify(pHash, u32HashLen, signature, eckey);

            //Release all openssl objects
            ECDSA_SIG_free(signature); //Release bn_r & bn_s
            EC_KEY_free(eckey);
            EC_GROUP_free(ecgroup);

            BN_free(bn_x);
            BN_free(bn_y);

            if (isValid != 1)
                return VLT_FAIL;

            return VLT_OK;
        }

        /* COMPUTE signature */
        case ST_INITIALISED_SIGN:
        {
            /* set private key */
            BIGNUM *bn_d = BN_new();
            BN_bin2bn(ctx_priv_key->pu8D, ctx_priv_key->u16DLen, bn_d);
            EC_KEY_set_private_key(eckey, bn_d);

            /* compute signature */
            ECDSA_SIG *signature = ECDSA_do_sign(pHash, u32HashLen, eckey);

            if (signature != NULL) {
                BIGNUM *bn_r; 
                BIGNUM *bn_s; 
                ECDSA_SIG_get0(signature, (const BIGNUM **)&bn_r, (const BIGNUM **)&bn_s);

                if ( (VLT_U32)(BN_num_bytes(bn_r) + BN_num_bytes(bn_s)) <= u32SignatureCapacity)
                {
                    *pu16SignatureLen = (VLT_U16) BN_bn2binpad(bn_r, pu8Signature, ctx_priv_key->u16DLen);
                    *pu16SignatureLen += (VLT_U16) BN_bn2binpad(bn_s, pu8Signature + *pu16SignatureLen, ctx_priv_key->u16DLen);

                    status = VLT_OK;
                }
            }

            //Release all openssl objects
            ECDSA_SIG_free(signature);
            EC_KEY_free(eckey);
            EC_GROUP_free(ecgroup);

            BN_free(bn_d);

            return status;
        }

        default:
            return VLT_FAIL;
    }

#elif (HOST_CRYPTO == HOST_CRYPTO_ARM_CRYPTO_LIB)
    VLT_U32 au32N[MAX_DIGITS];
    VLT_U32 au32Tmp[MAX_DIGITS];
    VLT_U32	au32Hash[HASH_DIGIT_SIZE];
    VLT_U32 au32Signature[2*(MAX_DIGITS+1)];

    VLT_U32 au32CryptographicWorkspace[300]; /* define a workspace of 1200 bytes (300 Words) for cryptographic computation*/
    VLT_U16 u16TbxResult;
    VLT_U8 au8Hash[HASH_BYTE_SIZE];

    VLT_STS status = VLT_FAIL;

    if ( ( NULL == pu8Message ) ||
         ( NULL == pu8Signature ) ||
         ( NULL == pu16SignatureLen ) )
    {
        return ( EECDSAINUPNULLPARAM );
    }

    VLT_KEY_OBJECT DomainParams;
    EcdsaSetKeyObjDomainParams((VLT_ECC_ID) ctx_curve_id, &DomainParams);

    /* set-up number of big digits and bytes required to represent field elements */
    VLT_U8 u8NumFieldBytes = (VLT_U8)DomainParams.data.EcdsaParamsKey.u16QLen;
    VLT_U8 u8NumFieldDigits = (VLT_U8)NUM_DIGITS(u8NumFieldBytes);

    if ( (signerState == ST_INITIALISED_SIGN) && (u32SignatureCapacity < (VLT_U32) 2*u8NumFieldBytes) )
    {
        /* signature buffer too small */
        return EECDSAEXECUTIONERROR;
    }

    /* set-up curve order */
    mpConvFromOctets(au32N, u8NumFieldDigits, DomainParams.data.EcdsaParamsKey.pu8N, u8NumFieldBytes);

    /* hash of message used by both signing and verify */

    /* e or e1 = SHA-256(M) */
    VLT_U32 u32HashLen;
    if (VLT_OK != (status = DigestUpdate(pu8Message, u32MessageLen))) return status;
    if (VLT_OK != (status = DigestDoFinal(au8Hash, &u32HashLen, sizeof(au8Hash)))) return status;

    /* convert hash to big digits, 
    same size as base point order if > hash size */
    UINT hashLenDigits = u32HashLen/sizeof(VLT_U32);
    if (u8NumFieldDigits > hashLenDigits)
    	hashLenDigits = u8NumFieldDigits;

    mpConvFromOctets(au32Hash, hashLenDigits, au8Hash, u32HashLen);

    /* ANS X9.62-2005 7.3.e
    // if bit length of hash is > bit length of base point order
    // then truncate hash by removing LSBs until bit length
    // equals the length of the base point order
    */
    UINT len = mpBitLength(au32N, u8NumFieldDigits);
    if (len < HASH_SIZE)
    {	
        /* take leftmost bits of message by shifting right */
        mpShiftRight(au32Tmp, au32Hash, HASH_SIZE - len, hashLenDigits);
        /* truncate to base point order size */
        mpSetEqual(au32Hash, au32Tmp, u8NumFieldDigits);
    }

    au32Hash[u8NumFieldDigits] = 0; // required by crypto library

    if (ST_INITIALISED_SIGN == signerState)
    {
    	VLT_U32 au32PrivateKey[MAX_DIGITS+1];
        VLT_U32 u32EphKey[MAX_DIGITS+1];

        /* setup private key */
        mpConvFromOctets(au32PrivateKey, u8NumFieldDigits, ctx_priv_key->pu8D, ctx_priv_key->u16DLen);
        au32PrivateKey[u8NumFieldDigits]=0; // required by crypto library

        /* signing process as per ANS X9.62 Section 7.3 */
        *pu16SignatureLen = 0;

        /* generate ephemeral private key k such that 0 < k < n */			 
        if (VLT_OK != GenerateRandomBytes((VLT_U8 *)au32Tmp, u8NumFieldDigits*sizeof(VLT_U32)))
            return EECDSAEXECUTIONERROR;
        mpModulo(u32EphKey, au32Tmp, u8NumFieldDigits, au32N, u8NumFieldDigits);
        if (mpIsZero(u32EphKey, u8NumFieldDigits))
        {
            /* probability of a zero is 1/n */
            if (VLT_OK != GenerateRandomBytes((VLT_U8 *)au32Tmp, u8NumFieldDigits*sizeof(VLT_U32)))
                return EECDSAEXECUTIONERROR;
            mpModulo(u32EphKey, au32Tmp, u8NumFieldDigits, au32N, u8NumFieldDigits);
            if (mpIsZero(u32EphKey, u8NumFieldDigits))
            {
                return EECDSAEXECUTIONERROR;
            }
        }

        u32EphKey[u8NumFieldDigits] = 0; // required by crypto library

        u16TbxResult = u16TbxSwSigEcDsaGenerate_GF2n (	au32Hash,
                                                    	au32PrivateKey,
														u32EphKey,
														au32Signature,
														(PCURVE)&B163,
														au32CryptographicWorkspace);
#ifdef DEBUG_TRACE_ECDSA
        printf("\n[u16TbxSwSigEcDsaGenerate_GF2n]\n");
        printf(" Hash         ");PrintHexBuffer((VLT_U8 *)au32Hash , (u8NumFieldDigits+1)*sizeof(VLT_U32));
        printf(" PrivateKey   ");PrintHexBuffer((VLT_U8 *)au32PrivateKey, (u8NumFieldDigits+1)*sizeof(VLT_U32));
        printf(" Ephemeral key"); PrintHexBuffer((VLT_U8 *)u32EphKey, u8NumFieldDigits*sizeof(VLT_U32));
        printf(" Signature    ");PrintHexBuffer((VLT_U8 *)au32Signature, 2*(u8NumFieldDigits+1)*sizeof(VLT_U32));
        printf("\n");
#endif

        if (u16TbxResult!= TBXSW_OK)
        {
            return VLT_FAIL;
        }

        /* set the byte length of the output signature */
        *pu16SignatureLen = (VLT_U16) (u8NumFieldBytes * 2);

        /* signing: convert back to byte format and construct r || s */
        host_memset(pu8Signature, 0, *pu16SignatureLen);
        mpConvToOctets(&au32Signature[0], u8NumFieldDigits, pu8Signature, u8NumFieldBytes); // r
        mpConvToOctets(&au32Signature[u8NumFieldDigits+1], u8NumFieldDigits, pu8Signature + u8NumFieldBytes, u8NumFieldBytes); // s

        status = VLT_OK;
    }
    else
    {
    	/* ANS X9.62-2005 Section 7.4.1: Verification with Public Key */;

    	VLT_U32 au32PublicKey[2*(MAX_DIGITS+1)];

        /* setup public key */
        mpConvFromOctets(&au32PublicKey[0], u8NumFieldDigits, ctx_pub_key->pu8Qx, ctx_pub_key->u16QLen);
        au32PublicKey[u8NumFieldDigits]=0; // required by crypto lib

        mpConvFromOctets(&au32PublicKey[u8NumFieldDigits+1], u8NumFieldDigits, ctx_pub_key->pu8Qy, ctx_pub_key->u16QLen);
        au32PublicKey[2*(u8NumFieldDigits)+1]=0; // required by crypto lib

        /* setup signature */
        mpConvFromOctets(&au32Signature[0], u8NumFieldDigits, pu8Signature, (*pu16SignatureLen)/2); // r
        au32Signature[u8NumFieldDigits]=0; // required by crypto lib
        mpConvFromOctets(&au32Signature[u8NumFieldDigits+1], u8NumFieldDigits, pu8Signature+(*pu16SignatureLen)/2, (*pu16SignatureLen)/2);
        au32Signature[2*(u8NumFieldDigits)+1]=0; // required by crypto lib

#ifdef DEBUG_TRACE_ECDSA
        printf("\n[u16TbxSwSigEcDsaVerify_GF2n]\n");
        printf(" Hash       ");PrintHexBuffer((VLT_U8 *)au32Hash, (u8NumFieldDigits+1)*sizeof(VLT_U32));
        printf(" PublicKey  ");PrintHexBuffer((VLT_U8 *)au32PublicKey, 2*(u8NumFieldDigits+1)*sizeof(VLT_U32));
        printf(" Signature  ");PrintHexBuffer((VLT_U8 *)au32Signature, 2*(u8NumFieldDigits+1)*sizeof(VLT_U32));
        printf("\n");
#endif

        u16TbxResult = u16TbxSwSigEcDsaVerify_GF2n( au32Hash,
                                                    au32PublicKey,
                                                    au32Signature,
                                                    (PCURVE)&B163,
                                                    au32CryptographicWorkspace);

        if (u16TbxResult!= TBXSW_SIGNATUREVERIFIED)
        {
            status = VLT_FAIL;
        }
        else
        {
            status = VLT_OK;
        }

    }

    return ( status );
#else
    return VLT_FAIL;
#endif
#else //#if (VLT_ENABLE_SHA == VLT_ENABLE) && (VLT_ENABLE_ECDSA == VLT_ENABLE)
    return EECDSAINVALIDCOMPILSETTINGS;
#endif
}

/* --------------------------------------------------------------------------
 * EcdsaSignerUpdate - not required at the moment
 * -------------------------------------------------------------------------- */
VLT_STS EcdsaSignerUpdate( VLT_U8 *pu8Message, 
    VLT_U32 u32MessageLen, 
    VLT_U32 u32MessageCapacity )
{
    VLT_STS status = VLT_FAIL;

    
    if (( NULL == pu8Message ) || (u32MessageLen==0) || (u32MessageCapacity==0))
    {
        return ( EECDSAINUPNULLPARAM );
    }

    return( status );
}


#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
VLT_STS EcdsaGetCurveNID(VLT_ECC_ID enCurveId, int *pNID)
{
#if (VLT_ENABLE_ECDSA == VLT_ENABLE)
    switch (enCurveId)
    {
#if (VLT_ENABLE_ECDSA_B163 == VLT_ENABLE)
        case    VLT_ECC_ID_B163:
        {
            *pNID = OBJ_txt2nid("sect163r2");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_K163 == VLT_ENABLE)
        case	VLT_ECC_ID_K163:
        {
            *pNID = OBJ_txt2nid("sect163k1");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_B233 == VLT_ENABLE)
        case	VLT_ECC_ID_B233:
        {
            *pNID = OBJ_txt2nid("sect233r1");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_K233 == VLT_ENABLE)
        case	VLT_ECC_ID_K233:
        {
            *pNID = OBJ_txt2nid("sect233k1");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_B283 == VLT_ENABLE)
        case	VLT_ECC_ID_B283:
        {
            *pNID = OBJ_txt2nid("sect283r1");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_K283 == VLT_ENABLE)
        case	VLT_ECC_ID_K283:
        {
            *pNID = OBJ_txt2nid("sect283k1");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_B409 == VLT_ENABLE)
        case	VLT_ECC_ID_B409:
        {
            *pNID = OBJ_txt2nid("sect409r1");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_K409 == VLT_ENABLE)
        case	VLT_ECC_ID_K409:
        {
            *pNID = OBJ_txt2nid("sect409k1");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_B571 == VLT_ENABLE)
        case	VLT_ECC_ID_B571:
        {
            *pNID = OBJ_txt2nid("sect571r1");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_K571 == VLT_ENABLE)
        case	VLT_ECC_ID_K571:
        {
            *pNID = OBJ_txt2nid("sect571k1");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_P192 == VLT_ENABLE)
        case	VLT_ECC_ID_P192:
        {
            *pNID = OBJ_txt2nid("prime192v1");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_P224 == VLT_ENABLE)
        case	VLT_ECC_ID_P224:
        {
            *pNID = OBJ_txt2nid("secp224r1");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_P256 == VLT_ENABLE)
        case	VLT_ECC_ID_P256:
        {
            *pNID = OBJ_txt2nid("prime256v1");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_P384 == VLT_ENABLE)
        case	VLT_ECC_ID_P384:
        {
            *pNID = OBJ_txt2nid("secp384r1");
            break;
        }
#endif
#if (VLT_ENABLE_ECDSA_P521 == VLT_ENABLE)
        case	VLT_ECC_ID_P521:
        {
            *pNID = OBJ_txt2nid("secp521r1");
            break;
        }
#endif
        default:
            return EECCCURVEIDINVLD;
            break;
    }
 
    return VLT_OK;
#else
    return VLT_FAIL;
#endif
}
#endif

VLT_STS EcdsaIsPcurve(VLT_ECC_ID enCurveId, VLT_BOOL *isPrimeCurve)
{
#if (VLT_ENABLE_ECDSA == VLT_ENABLE)
    switch (enCurveId)
    {
#if (VLT_ENABLE_ECDSA_B163 == VLT_ENABLE)
        case VLT_ECC_ID_B163:
            *isPrimeCurve = 0;
            break;
#endif
#if (VLT_ENABLE_ECDSA_K163 == VLT_ENABLE)
        case	VLT_ECC_ID_K163:
            *isPrimeCurve = 0;
            break;
#endif
#if (VLT_ENABLE_ECDSA_B233 == VLT_ENABLE)
        case	VLT_ECC_ID_B233:
            *isPrimeCurve = 0;
            break;
#endif
#if (VLT_ENABLE_ECDSA_K233 == VLT_ENABLE)
        case	VLT_ECC_ID_K233:
            *isPrimeCurve = 0;
            break;
#endif
#if (VLT_ENABLE_ECDSA_B283 == VLT_ENABLE)
        case	VLT_ECC_ID_B283:
            *isPrimeCurve = 0;
            break;
#endif
#if (VLT_ENABLE_ECDSA_K283 == VLT_ENABLE)
        case	VLT_ECC_ID_K283:
            *isPrimeCurve = 0;
            break;
#endif
#if (VLT_ENABLE_ECDSA_B409 == VLT_ENABLE)
        case	VLT_ECC_ID_B409:
            *isPrimeCurve = 0;
            break;
#endif
#if (VLT_ENABLE_ECDSA_K409 == VLT_ENABLE)
        case	VLT_ECC_ID_K409:
            *isPrimeCurve = 0;
            break;
#endif
#if (VLT_ENABLE_ECDSA_B571 == VLT_ENABLE)
        case	VLT_ECC_ID_B571:
            *isPrimeCurve = 0;
            break;
#endif
#if (VLT_ENABLE_ECDSA_K571 == VLT_ENABLE)
        case	VLT_ECC_ID_K571:
            *isPrimeCurve = 0;
        break;
#endif

#if (VLT_ENABLE_ECDSA_P192 == VLT_ENABLE)
        case	VLT_ECC_ID_P192:
            *isPrimeCurve = 1;
            break;
#endif
#if (VLT_ENABLE_ECDSA_P224 == VLT_ENABLE)
        case	VLT_ECC_ID_P224:
            *isPrimeCurve = 1;
            break;
#endif
#if (VLT_ENABLE_ECDSA_P256 == VLT_ENABLE)
        case	VLT_ECC_ID_P256:
            *isPrimeCurve = 1;
            break;
#endif
#if (VLT_ENABLE_ECDSA_P384 == VLT_ENABLE)
        case	VLT_ECC_ID_P384:
            *isPrimeCurve = 1;
            break;
#endif
#if (VLT_ENABLE_ECDSA_P521 == VLT_ENABLE)
        case	VLT_ECC_ID_P521:
            *isPrimeCurve = 1;
            break;
#endif

        default:
            *isPrimeCurve = 0;
            return EECCCURVEIDINVLD;
    }

    return VLT_OK;
#else
    return VLT_FAIL;
#endif
}

VLT_STS EcdsaSetKeyObjDomainParams(VLT_ECC_ID enCurveId, VLT_KEY_OBJECT *pKeyObj)
{
    VLT_STS status = VLT_FAIL;

    if (NULL == pKeyObj) return ESTRONGINITNULLPARAM;

    pKeyObj->enKeyID = VLT_KEY_ECC_PARAMS;

    switch (enCurveId) {
#if (VLT_ENABLE_ECDSA_B163 == VLT_ENABLE)
    case VLT_ECC_ID_B163:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_B163);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_B163);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_B163;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_B163;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_B163;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_B163;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_B163;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_B163;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_B163;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_B163;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_B233 == VLT_ENABLE)
    case VLT_ECC_ID_B233:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_B233);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_B233);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_B233;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_B233;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_B233;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_B233;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_B233;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_B233;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_B233;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_B233;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_B283 == VLT_ENABLE)
    case VLT_ECC_ID_B283:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_B283);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_B283);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_B283;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_B283;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_B283;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_B283;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_B283;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_B283;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_B283;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_B283;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_B409 == VLT_ENABLE)
    case VLT_ECC_ID_B409:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_B409);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_B409);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_B409;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_B409;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_B409;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_B409;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_B409;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_B409;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_B409;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_B409;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_B571 == VLT_ENABLE)
    case VLT_ECC_ID_B571:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_B571);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_B571);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_B571;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_B571;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_B571;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_B571;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_B571;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_B571;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_B571;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_B571;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_K163 == VLT_ENABLE)
    case VLT_ECC_ID_K163:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_K163);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_K163);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_K163;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_K163;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_K163;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_K163;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_K163;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_K163;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_K163;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_K163;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_K233 == VLT_ENABLE)
    case VLT_ECC_ID_K233:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_K233);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_K233);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_K233;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_K233;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_K233;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_K233;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_K233;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_K233;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_K233;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_K233;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_K283 == VLT_ENABLE)
    case VLT_ECC_ID_K283:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_K283);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_K283);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_K283;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_K283;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_K283;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_K283;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_K283;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_K283;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_K283;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_K283;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_K409 == VLT_ENABLE)
    case VLT_ECC_ID_K409:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_K409);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_K409);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_K409;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_K409;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_K409;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_K409;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_K409;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_K409;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_K409;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_K409;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_K571 == VLT_ENABLE)
    case VLT_ECC_ID_K571:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_K571);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_K571);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_K571;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_K571;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_K571;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_K571;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_K571;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_K571;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_K571;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_K571;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_P192 == VLT_ENABLE)
    case VLT_ECC_ID_P192:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_P192);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_P192);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_P192;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_P192;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_P192;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_P192;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_P192;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_P192;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_P192;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_P192;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_P224 == VLT_ENABLE)
    case VLT_ECC_ID_P224:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_P224);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_P224);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_P224;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_P224;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_P224;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_P224;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_P224;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_P224;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_P224;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_P224;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_P256 == VLT_ENABLE)
    case VLT_ECC_ID_P256:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_P256);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_P256);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_P256;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_P256;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_P256;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_P256;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_P256;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_P256;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_P256;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_P256;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_P384 == VLT_ENABLE)
    case VLT_ECC_ID_P384:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_P384);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_P384);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_P384;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_P384;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_P384;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_P384;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_P384;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_P384;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_P384;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_P384;
        status = VLT_OK;
        break;
#endif

#if (VLT_ENABLE_ECDSA_P521 == VLT_ENABLE)
    case VLT_ECC_ID_P521:
        pKeyObj->data.EcdsaParamsKey.u16QLen = sizeof(primeQ_P521);
        pKeyObj->data.EcdsaParamsKey.u16NLen = sizeof(orderN_P521);
        pKeyObj->data.EcdsaParamsKey.pu8Q = primeQ_P521;
        pKeyObj->data.EcdsaParamsKey.pu8N = orderN_P521;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = xPoint_P521;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = yPoint_P521;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = zPoint_P521;
        pKeyObj->data.EcdsaParamsKey.pu8A = coeffA_P521;
        pKeyObj->data.EcdsaParamsKey.pu8B = coeffB_P521;
        pKeyObj->data.EcdsaParamsKey.u32H = cofactorH_P521;
        status = VLT_OK;
        break;
#endif

    default:
        pKeyObj->data.EcdsaParamsKey.u16QLen = 0;
        pKeyObj->data.EcdsaParamsKey.u16NLen = 0;
        pKeyObj->data.EcdsaParamsKey.pu8Q = NULL;
        pKeyObj->data.EcdsaParamsKey.pu8N = NULL;
        pKeyObj->data.EcdsaParamsKey.pu8Gx = NULL;
        pKeyObj->data.EcdsaParamsKey.pu8Gy = NULL;
        pKeyObj->data.EcdsaParamsKey.pu8Gz = NULL;
        pKeyObj->data.EcdsaParamsKey.pu8A = NULL;
        pKeyObj->data.EcdsaParamsKey.pu8B = NULL;

        status = VLT_FAIL;
    }

    return status;
}

#endif
