/**
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
*
*
* @brief  Implementation of the ECDH utilities function.
*
* @details
*
* @date    16/01/2017
* @author  fmauraton
*/

#include "vaultic_common.h"
#if ( VLT_ENABLE_ECDH == VLT_ENABLE )
#include "vaultic_ecdsa_signer.h"
#include "vaultic_mem.h"
#include "vaultic_ECC.h"
#include "vaultic_ECDH.h"
#include "vaultic_digest.h"

#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
//Specific includes for openssl
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>

static VLT_STS KeyAgreement_ECKA(VLT_ECC_ID enCurveId, const VLT_KEY_BLOB *kbPubKey, const VLT_KEY_BLOB *kbPrivKey, VLT_KEY_BLOB *sharedSecret);
static VLT_STS KeyAgreement_DH(VLT_ECC_ID enCurveId, const VLT_KEY_BLOB *kbPubKey, const VLT_KEY_BLOB *kbPrivKey, VLT_KEY_BLOB *sharedSecret, VLT_BOOL isCDH);
#endif

#if (HOST_CRYPTO == HOST_CRYPTO_ARM_CRYPTO_LIB)
#include "vaultic_bigdigits.h"
#include "HAL_TYPEDEF.h"
#include "TbxSw_Ecc_Curves_GF2n.h"
#include "TbxSw_EcDh_GF2n.h"
#include "TbxSw_Ecc_GF2n.h"
#include "TbxSw_Rc.h"
#define MAX_DIGITS			(MAX_ECC_KEY_BYTES_SIZE / sizeof(VLT_U32))
#define NUM_DIGITS(n)	((n) % sizeof(VLT_U32) ? ((n) / sizeof(VLT_U32)) + 1 : ((n) / sizeof(VLT_U32)))

static VLT_STS KeyAgreement_ECDH_FAST(VLT_ALG_KAS_ID enKeyAgreementAlgoId, VLT_ECC_ID enCurveId, const VLT_KEY_BLOB *kbPubKey, const VLT_KEY_BLOB *kbPrivKey, VLT_KEY_BLOB *sharedSecret);
#endif

VLT_STS KDF_Concat(VLT_ALG_DIG_ID enDigestId,
	VLT_U16 u16SharedSecretLen, const VLT_U8 *pu8SharedSecret,
	VLT_U16 u16KeyDataBitsLen,
	VLT_U16 u16AlgoIDLen, const VLT_U8 *pu8AlgoID,
	VLT_U16 u16partyUInfoLen, const VLT_U8 *partyUInfo,
	VLT_U16 u16partyVInfoLen, const VLT_U8 *partyVInfo,
	VLT_U16 u16suppPubInfoLen, const VLT_U8 *suppPubInfo,
	VLT_U16 u16suppPrivInfoLen, const VLT_U8 *suppPrivInfo,
	VLT_KEY_BLOB *derivedKey)
{
#if (VLT_ENABLE_SHA == VLT_ENABLE) 
    VLT_STS status = VLT_FAIL;
	VLT_U8 u8KeyDataByteLen = (VLT_U8) (u16KeyDataBitsLen / 8);
    
    // Check result buffer is large enough
    if (u8KeyDataByteLen > derivedKey->keySize) return VLT_FAIL;

	VLT_U32 u32Ctr;
    VLT_U32 u32Iterations;

    VLT_U8  u8KeyBuf[32];
    VLT_U16 u16DerivedKeySize=0;
	VLT_U8  au8Ctr[4];

    // Compute nb of iterations required
    u32Iterations = (derivedKey->keySize + 31) / 32;

    // Run KDF loop
    for (u32Ctr = 1L ; u32Ctr <= u32Iterations ; u32Ctr++)
    {
        if( VLT_OK != (status = DigestInit(enDigestId)))
            return status;

    	au8Ctr[0] = (u32Ctr >> 24) & 0xff;
    	au8Ctr[1] = (u32Ctr >> 16) & 0xff;
    	au8Ctr[2] = (u32Ctr >> 8)  & 0xff;
    	au8Ctr[3] =  u32Ctr        & 0xff;

        if (VLT_OK != (status = DigestUpdate(au8Ctr, sizeof(au8Ctr)))) return status;
        if (VLT_OK != (status = DigestUpdate(pu8SharedSecret, u16SharedSecretLen))) return status;
        if (VLT_OK != (status = DigestUpdate(pu8AlgoID, u16AlgoIDLen))) return status;
        if (VLT_OK != (status = DigestUpdate(partyUInfo, u16partyUInfoLen))) return status;
        if (VLT_OK != (status = DigestUpdate(partyVInfo, u16partyVInfoLen))) return status;
        if (VLT_OK != (status = DigestUpdate(suppPubInfo, u16suppPubInfoLen))) return status;
        if (VLT_OK != (status = DigestUpdate(suppPrivInfo, u16suppPrivInfoLen))) return status;

        if (VLT_OK != (status = DigestDoFinal(u8KeyBuf, NULL, sizeof(u8KeyBuf))))
            return status;

		if(derivedKey->keySize - u16DerivedKeySize < 32)
		   host_memcpy(derivedKey->keyValue + (u32Ctr - 1) * 32, u8KeyBuf, derivedKey->keySize - u16DerivedKeySize);
		else
		   host_memcpy(derivedKey->keyValue + (u32Ctr - 1) * 32, u8KeyBuf, 32);
		u16DerivedKeySize += 32;
    }

	return VLT_OK;
#else //#if (VLT_ENABLE_SHA == VLT_ENABLE) 
    return EECDHINVALIDCOMPILSETTINGS;
#endif
}

VLT_STS KeyAgreement_ECDH(VLT_ALG_KAS_ID enKeyAgreementAlgoId, VLT_ECC_ID CurveId, const VLT_KEY_BLOB *kbPubKey, const VLT_KEY_BLOB *kbPrivKey, VLT_KEY_BLOB *sharedSecret)
{
#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
	switch (enKeyAgreementAlgoId) {
        case VLT_ALG_KAS_STATIC_UNIFIED_ECKA_GFp:
        case VLT_ALG_KAS_STATIC_UNIFIED_ECKA_GF2m:
        case VLT_ALG_KAS_ONE_PASS_ECKA_GFp:
        case VLT_ALG_KAS_ONE_PASS_ECKA_GF2m:
            return KeyAgreement_ECKA(CurveId, kbPubKey, kbPrivKey, sharedSecret);
            
        case VLT_ALG_KAS_STATIC_UNIFIED_ECC_DH_GFp:
        case VLT_ALG_KAS_STATIC_UNIFIED_ECC_DH_GF2m:
        case VLT_ALG_KAS_ONE_PASS_ECC_DH_GFp:
        case VLT_ALG_KAS_ONE_PASS_ECC_DH_GF2m:
            return KeyAgreement_DH(CurveId, kbPubKey, kbPrivKey, sharedSecret, FALSE);

        case VLT_ALG_KAS_STATIC_UNIFIED_ECC_CDH_GFp:
        case VLT_ALG_KAS_STATIC_UNIFIED_ECC_CDH_GF2m	:
        case VLT_ALG_KAS_ONE_PASS_ECC_CDH_GFp:
        case VLT_ALG_KAS_ONE_PASS_ECC_CDH_GF2m:
            return KeyAgreement_DH(CurveId, kbPubKey, kbPrivKey, sharedSecret, TRUE);

        default:
            return EECDHECKAINVALIDPARAMS;
    }
#elif (HOST_CRYPTO == HOST_CRYPTO_ARM_CRYPTO_LIB)
	return KeyAgreement_ECDH_FAST( enKeyAgreementAlgoId,  CurveId,  kbPubKey,  kbPrivKey, sharedSecret);
#else
	return EECDHECKAINVALIDPARAMS;
#endif
}

#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
VLT_STS KeyAgreement_ECKA(VLT_ECC_ID enCurveId, const VLT_KEY_BLOB *kbPubKey, const VLT_KEY_BLOB *kbPrivKey, VLT_KEY_BLOB *sharedSecret)
{
    VLT_STS status = VLT_OK;
    int             nid = 0;
    VLT_BOOL		isPrimeCurve = 0;

    //Check params
    if ((kbPubKey->keyType != VLT_KEY_ECC_PUB) || (kbPrivKey->keyType != VLT_KEY_ECC_PRIV))
    {
        return EECDHECKAINVALIDPARAMS;
    }

    //Get curve NID
    if (VLT_OK != (status = EcdsaGetCurveNID(enCurveId, &nid)))
        return status;

    if (VLT_OK != (status = EcdsaIsPcurve(enCurveId, &isPrimeCurve)))
        return status;

    {
        BN_CTX	 *ctx = BN_CTX_new();
        EC_GROUP* ecGroup = EC_GROUP_new_by_curve_name(nid);

        //intermediate result
        BIGNUM *bn_l = BN_new();
        //Cofactor h
        BIGNUM *bn_h = BN_new();
        //Order n
        BIGNUM *bn_n = BN_new();
        //Private key d
        BIGNUM *bn_d = BN_new();
        BIGNUM *bn_dl = BN_new();
        BIGNUM *bn_dl_mod_n = BN_new();

        //Get order n
        if (EC_GROUP_get_order(ecGroup, bn_n, ctx) == 0)
        {
            status = EECDHECKAGETORDERFAILED;
        }

        //Get cofactor h
        if (VLT_OK == status)
        {
            if (EC_GROUP_get_cofactor(ecGroup, bn_h, ctx) == 0)
            {
                status = EECDHECKAGETCOFACTORFAILED;
            }
            
        }

        //Step 1:
        //Calculate: l = h^-1 mod n
        if (VLT_OK == status)
        {
            if (BN_mod_inverse(bn_l, bn_h, bn_n, ctx) == NULL)
            {
                status = EECDHECKAGETORDERFAILED;
            }
        }

        {
            //Step 2:
            //Calculate: Q= [h]P
            int res = 0;
            EC_POINT* P = EC_POINT_new(ecGroup);
            BIGNUM *bn_Px = BN_new();
            BIGNUM *bn_Py = BN_new();
            EC_POINT* Q = EC_POINT_new(ecGroup);

            //Key is on VaultIC format
            VLT_U16 u8PubKeyLength = kbPubKey->keySize / 2;

            BN_bin2bn(kbPubKey->keyValue, u8PubKeyLength, bn_Px);
            BN_bin2bn(&kbPubKey->keyValue[u8PubKeyLength], u8PubKeyLength, bn_Py);

            if (isPrimeCurve)
            {
                res = EC_POINT_set_affine_coordinates_GFp(ecGroup, P, bn_Px, bn_Py, ctx);
            }
            else
            {
                res = EC_POINT_set_affine_coordinates_GF2m(ecGroup, P, bn_Px, bn_Py, ctx);
            }

            if (res == 0)
            {
                status = EECDHKAECKASETPFAILED;
            }

            //Result of the step 2 structure

            if (VLT_OK == status)
            {
                if (EC_POINT_mul(ecGroup, Q, NULL, P, bn_h, ctx) == 0)
                {
                    status = EECDHKAECKASTEPTWOFAILED;
                }
            }

            //Step 3:
            //Calculate: Sab= [d.l mod n]Q
            //Convert private key value to bignumber
            if (VLT_OK == status)
            {
                if (BN_bin2bn(kbPrivKey->keyValue, kbPrivKey->keySize, bn_d) == NULL)
                {
                    status = EECDHECKAGETPRIVKEYFAILED;
                }
            }

            //Perform d.l
            if (VLT_OK == status)
            {
                if (BN_mul(bn_dl, bn_d, bn_l, ctx) == 0)
                {
                    status = EECDHECKAMULFAILED;
                }
            }

            //Perform d.l mod n
            if (VLT_OK == status)
            {
                BN_mod(bn_dl_mod_n, bn_dl, bn_n, ctx);
                /* if () == NULL)
                {
                status = EECDHECKAMODFAILED;
                }*/
            }

            if (VLT_OK == status)
            {
                EC_POINT* Sab = EC_POINT_new(ecGroup);
                if (EC_POINT_mul(ecGroup, Sab, NULL, Q, bn_dl_mod_n, ctx) == 0)
                {
                    status = EECDHECKASTEPTHREEFAILED;
                }
                else if (EC_POINT_is_at_infinity(ecGroup, Sab) == 1)
                {
                    status = EECDHECKASABNULL;
                }
                else
                {
                    //Extract Xsab
                    BIGNUM *bn_x = BN_new();
                    BIGNUM *bn_y = BN_new();
                    if (isPrimeCurve)
                    {
                        EC_POINT_get_affine_coordinates_GFp(ecGroup, Sab, bn_x, bn_y, ctx);
                    }
                    else
                    {
                        EC_POINT_get_affine_coordinates_GF2m(ecGroup, Sab, bn_x, bn_y, ctx);
                    }

                    //Fill result structure
                    sharedSecret->keyType = VLT_KEY_SECRET_VALUE;

                    //Get curve prime 
                    BIGNUM *bn_p = BN_new();

                    if (EC_GROUP_get_curve_GF2m(ecGroup, bn_p, NULL, NULL, NULL) == 0)
                    {
                        status = EECDHECKAGETORDERFAILED;
                    }

                    // Set SS size to prime size 
                    sharedSecret->keySize = (VLT_U16) BN_num_bytes(bn_p);
                    if (sharedSecret->keyValue == NULL)
                    {
                        status = EECDHKAECKANOMEMORY;
                    }
                    else
                    {
                        if (BN_bn2binpad(bn_x, sharedSecret->keyValue, sharedSecret->keySize) == -1) {
                            status = EECDHKAECKANOMEMORY;
                        }
                    }

                    //Release openssl structures
                    BN_free(bn_x);
                    BN_free(bn_y);
                }
            }
        }

        //Release openssl structures
        BN_free(bn_l);
        BN_free(bn_h);
        BN_free(bn_n);
        BN_free(bn_d);
        BN_free(bn_dl);
        BN_free(bn_dl_mod_n);
        BN_CTX_free(ctx);
    }
    return status;

}

VLT_STS KeyAgreement_DH(VLT_ECC_ID enCurveId, const VLT_KEY_BLOB *kbPubKey, const VLT_KEY_BLOB *kbPrivKey, VLT_KEY_BLOB *sharedSecret, VLT_BOOL isCDH)
{
    EC_KEY *key, *peerkey;
    BIGNUM *bn_d, *bn_Px, *bn_Py;
    int field_size;
    VLT_STS status = VLT_OK;
    int nid = 0;
    int secret_len=0;

    key = NULL;
    peerkey = NULL;
    bn_Px = NULL;
    bn_Py = NULL;
    bn_d = NULL;

    //Get curve NID
    if (VLT_OK != (status = EcdsaGetCurveNID(enCurveId, &nid)))
        return status;

    /* Set the Private Key  */
    if (VLT_OK == status) {
       if(  ((key = EC_KEY_new_by_curve_name(nid)) == NULL)
        ||  ((bn_d = BN_bin2bn(kbPrivKey->keyValue, kbPrivKey->keySize, NULL)) == NULL)
        ||  (EC_KEY_set_private_key(key, bn_d) !=1 ) )  status = VLT_FAIL;

       if (isCDH == TRUE) {
           EC_KEY_set_flags(key, EC_FLAG_COFACTOR_ECDH);
       }
    }
    
    /* Set the public key */
    if (VLT_OK == status) {

        //Key is on VaultIC format
        VLT_U16 u8PubKeyLength = kbPubKey->keySize / 2;

        if( ((peerkey = EC_KEY_new_by_curve_name(nid)) == NULL)
         || ((bn_Px = BN_bin2bn(kbPubKey->keyValue, u8PubKeyLength, NULL)) == NULL) 
         || ((bn_Py = BN_bin2bn(&kbPubKey->keyValue[u8PubKeyLength], u8PubKeyLength, NULL)) == NULL)
         || (EC_KEY_set_public_key_affine_coordinates(peerkey, bn_Px, bn_Py) !=1) )
            status = VLT_FAIL;

        if (isCDH == TRUE) {
            EC_KEY_set_flags(peerkey, EC_FLAG_COFACTOR_ECDH);
        }
    }

    /* Calculate the size of the buffer for the shared secret */
    if (VLT_OK == status) {

        field_size = EC_GROUP_get_degree(EC_KEY_get0_group(key));
        secret_len = (field_size + 7) / 8;

        if (secret_len > sharedSecret->keySize) status = VLT_FAIL;
    }

    /* Derive the shared secret */
    if (VLT_OK == status) {

        if( (sharedSecret->keySize = (VLT_U16) ECDH_compute_key(sharedSecret->keyValue, secret_len, EC_KEY_get0_public_key(peerkey), key, NULL))  <= 0) status = VLT_FAIL;
    }

    /* Clean up */
    if(key != NULL) EC_KEY_free(key);
    if(peerkey != NULL) EC_KEY_free(peerkey);
    if(bn_d != NULL) BN_free(bn_d);
    if(bn_Px != NULL) BN_free(bn_Px);
    if(bn_Py != NULL)BN_free(bn_Py);

    return status;
}
#endif

#if (HOST_CRYPTO == HOST_CRYPTO_ARM_CRYPTO_LIB)
VLT_STS KeyAgreement_ECDH_FAST(VLT_ALG_KAS_ID enKeyAgreementAlgoId, VLT_ECC_ID enCurveId, const VLT_KEY_BLOB *kbPubKey, const VLT_KEY_BLOB *kbPrivKey, VLT_KEY_BLOB *sharedSecret)
{
	VLT_U32 au32PublicKey[2*(MAX_DIGITS+1)];
	VLT_U32 au32PrivateKey[MAX_DIGITS+1];
	VLT_U32 au32CryptographicWorkspace[896]; /* define workspace for cryptographic computation*/
	VLT_ECDSA_PUBLIC_KEY pub_key;
	VLT_ECDSA_PRIVATE_KEY priv_key;
	VLT_BOOL isECKA =FALSE;
	VLT_BOOL isEC_DH = FALSE;
	VLT_BOOL isEC_CDH = FALSE;

	/* Check key agreement scheme is supported */
	switch (enKeyAgreementAlgoId) {
        case VLT_ALG_KAS_STATIC_UNIFIED_ECKA_GFp:
        case VLT_ALG_KAS_STATIC_UNIFIED_ECKA_GF2m:
        case VLT_ALG_KAS_ONE_PASS_ECKA_GFp:
        case VLT_ALG_KAS_ONE_PASS_ECKA_GF2m:
        	isECKA = TRUE;
        	break;

        case VLT_ALG_KAS_STATIC_UNIFIED_ECC_DH_GFp:
        case VLT_ALG_KAS_STATIC_UNIFIED_ECC_DH_GF2m:
        case VLT_ALG_KAS_ONE_PASS_ECC_DH_GFp:
        case VLT_ALG_KAS_ONE_PASS_ECC_DH_GF2m:
        	isEC_DH = TRUE;
        	break;

        case VLT_ALG_KAS_STATIC_UNIFIED_ECC_CDH_GFp:
        case VLT_ALG_KAS_STATIC_UNIFIED_ECC_CDH_GF2m	:
        case VLT_ALG_KAS_ONE_PASS_ECC_CDH_GFp:
        case VLT_ALG_KAS_ONE_PASS_ECC_CDH_GF2m:
        	isEC_CDH = TRUE;
        	break;

        default:
            return EECDHECKAINVALIDPARAMS;
	}

	/* set-up number of big digits and bytes required to represent field elements */
	VLT_KEY_OBJECT DomainParams;
	EcdsaSetKeyObjDomainParams(enCurveId, &DomainParams);

	VLT_U8 u8NumFieldBytes = (VLT_U8)DomainParams.data.EcdsaParamsKey.u16QLen;
	VLT_U8 u8NumFieldDigits = (VLT_U8)NUM_DIGITS(u8NumFieldBytes);

	/* setup public key */
	pub_key.u16QLen = kbPubKey->keySize/2;
	pub_key.pu8Qx = kbPubKey->keyValue;
	pub_key.pu8Qy = kbPubKey->keyValue + pub_key.u16QLen;

	mpConvFromOctets(&au32PublicKey[0], u8NumFieldDigits, pub_key.pu8Qx, pub_key.u16QLen);
	au32PublicKey[u8NumFieldDigits]=0; // required by crypto lib

	mpConvFromOctets(&au32PublicKey[u8NumFieldDigits+1], u8NumFieldDigits, pub_key.pu8Qy, pub_key.u16QLen);
	au32PublicKey[2*(u8NumFieldDigits)+1]=0; // required by crypto lib

	/* setup private key */
	priv_key.u16DLen = kbPrivKey->keySize;
	priv_key.pu8D = kbPrivKey->keyValue;

	mpConvFromOctets(&au32PrivateKey[0], u8NumFieldDigits, priv_key.pu8D, priv_key.u16DLen);
	au32PrivateKey[u8NumFieldDigits]=0; // required by crypto lib


	#ifdef DEBUG_TRACE_ECDH
	printf("\n[KeyAgreement_ECDH_FAST]\n");
	printf(" PublicKey  ");PrintHexBuffer((VLT_U8 *)au32PublicKey, 2*(u8NumFieldDigits+1)*sizeof(VLT_U32));
	printf(" PrivateKey ");PrintHexBuffer((VLT_U8 *)au32PrivateKey, (u8NumFieldDigits+1)*sizeof(VLT_U32));
	printf("\n");
	#endif

	/* convert public key from affine to projective coordinates */
	VLT_U32 au32PublicKeyPoint[3*(MAX_DIGITS+1)];
	if (TBXSW_OK != u16TbxSwEcGf2nAffineToProjectiveCoordinates( au32PublicKey,
																 au32PublicKeyPoint,
																 (PCURVE)&B163)) {
		return VLT_FAIL;
	}

	#ifdef DEBUG_TRACE_ECDH
	printf(" PubKeyPoint  ");PrintHexBuffer((VLT_U8 *)au32PublicKeyPoint, 3*(u8NumFieldDigits+1)*sizeof(VLT_U32));
	#endif

	/* Compute Shared Secret */
	VLT_U32 au32SharedSecret[MAX_DIGITS+1];


	if(isECKA ==TRUE) {

		/* Use ECKA */
		if (TBXSW_OK != u16ECKADHAgreement_GF2n((PCURVE)&B163,
												au32PublicKeyPoint,
												au32PrivateKey,
												au32SharedSecret,
												au32CryptographicWorkspace)) {

			return VLT_FAIL;
		}
	}
	else if( (isEC_DH == TRUE)||(isEC_CDH == TRUE) ) {
		/* Use EC DH or CDH */
		CURVE theCurve;
		host_memcpy((VLT_U8 *)&theCurve, (VLT_U8 *)&B163 , sizeof(CURVE));

		if(isEC_DH == TRUE) {
			theCurve.u32H = 1;
		}

		if (TBXSW_OK != u16CDHAgreement_GF2n( 	&theCurve,
												au32PublicKeyPoint,
												au32PrivateKey,
												au32SharedSecret,
												au32CryptographicWorkspace)) {

			return VLT_FAIL;
		}
	}
	else return VLT_FAIL; /* Not supposed to happen */


	#ifdef DEBUG_TRACE_ECDH
	printf(" Shared Secret ");PrintHexBuffer((VLT_U8 *)au32SharedSecret, (u8NumFieldDigits+1)*sizeof(VLT_U32));
	#endif

	// Compute byte length of shared secret
	VLT_U32 au32Q[MAX_DIGITS];
	mpConvFromOctets(au32Q, u8NumFieldDigits, DomainParams.data.EcdsaParamsKey.pu8Q, DomainParams.data.EcdsaParamsKey.u16QLen);

	UINT nbits = mpBitLength(au32Q, u8NumFieldDigits);
	UINT nbytes= (nbits + 7) / 8;

	//Fill result structure
	sharedSecret->keyType = VLT_KEY_SECRET_VALUE;
	sharedSecret->keySize = nbytes;

	mpConvToOctets(au32SharedSecret, u8NumFieldDigits, sharedSecret->keyValue, sharedSecret->keySize);
	return VLT_OK;
}

#endif



VLT_STS KDF_X963(VLT_ALG_DIG_ID enDigestId, VLT_U16 u16SharedSecretLen, const VLT_U8 *pu8SharedSecret, VLT_U16 u16SharedInfoLen, const VLT_U8 *pu8SharedInfo, VLT_KEY_BLOB *derivedKey)
{
#if (VLT_ENABLE_SHA == VLT_ENABLE) 
	VLT_U32 u32Ctr;
    VLT_U32 u32Iterations;
    VLT_U8  u8KeyBuf[32];
    VLT_U16 u16DerivedKeySize=0;
	VLT_U8  au8Ctr[4];
    VLT_STS status;

    // Compute nb of iterations required
    u32Iterations = (derivedKey->keySize + 31) / 32;

    // Run KDF loop
    for (u32Ctr = 1L ; u32Ctr <= u32Iterations ; u32Ctr++)
    {
        if (VLT_OK != (status = DigestInit(enDigestId)))
            return status;

    	au8Ctr[0] = (u32Ctr >> 24) & 0xff;
    	au8Ctr[1] = (u32Ctr >> 16) & 0xff;
    	au8Ctr[2] = (u32Ctr >> 8)  & 0xff;
    	au8Ctr[3] =  u32Ctr        & 0xff;

        if (VLT_OK != (status = DigestUpdate(pu8SharedSecret, u16SharedSecretLen))) return status;
        if (VLT_OK != (status = DigestUpdate(au8Ctr, sizeof(au8Ctr)))) return status;
        if (VLT_OK != (status = DigestUpdate(pu8SharedInfo, u16SharedInfoLen))) return status;

        if (VLT_OK != (status = DigestDoFinal(u8KeyBuf, NULL, sizeof(u8KeyBuf))))
            return status;

		if(derivedKey->keySize - u16DerivedKeySize < 32)
		   host_memcpy(derivedKey->keyValue + (u32Ctr - 1) * 32, u8KeyBuf, derivedKey->keySize - u16DerivedKeySize);
		else
		   host_memcpy(derivedKey->keyValue + (u32Ctr - 1) * 32, u8KeyBuf, 32);
		u16DerivedKeySize += 32;
    }

	return VLT_OK;
#else // #if (VLT_ENABLE_SHA == VLT_ENABLE) 
    return EECDHINVALIDCOMPILSETTINGS;
#endif
}

#endif 
