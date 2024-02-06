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
#if( VLT_ENABLE_SIGN_xDSA == VLT_ENABLE)
#include "vaultic_mem.h"
#include "vaultic_ECC.h"
#include "vaultic_utils.h"
#include "vaultic_ecdsa_signer.h"

#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
//Specific includes for openssl
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/sha.h>

#endif


VLT_STS GenerateECCKeyPair(VLT_ECC_ID CurveId, VLT_KEY_BLOB *pubKey, VLT_KEY_BLOB *privKey)
{
#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
	VLT_STS			status = VLT_OK;
	EC_KEY          *myecc = NULL;
	int             nid = 0;
	VLT_BOOL		isPrimeCurve = 0;
	BIGNUM* bnprivKey;

	/* ---------------------------------------------------------- *
	* These function calls initialize openssl for correct work.  *
	* ---------------------------------------------------------- */
	//OPENSSL_add_all_algorithms_noconf();

	/* ---------------------------------------------------------- *
	* Create a EC key sructure, setting the group type from NID  *
	* ---------------------------------------------------------- */
	status = EcdsaGetCurveNID(CurveId, &nid);
	if (VLT_OK != status)
	{
		return status;
	}

    status = EcdsaIsPcurve(CurveId, &isPrimeCurve);
    if (VLT_OK != status)
    {
        return status;
    }


	myecc = EC_KEY_new_by_curve_name(nid);

	/* -------------------------------------------------------- *
	* Create the public/private EC key pair here               *
	* ---------------------------------------------------------*/
	if (!(EC_KEY_generate_key(myecc)))
	{
		status = EECCGENERATIONERROR;
	}

	//Make private key blob
	privKey->keyType = VLT_KEY_ECC_PRIV;
	bnprivKey = (BIGNUM*)EC_KEY_get0_private_key(myecc);

	privKey->keySize = (VLT_U16) BN_num_bytes(bnprivKey);
	if (privKey->keyValue == NULL)
	{
		status = EECCDHOSTNOMEMORY;
	}
	else
	{
		BN_bn2bin(bnprivKey, privKey->keyValue);
	}

	//Make public key blob
	{
		const EC_POINT* ecPointKey = EC_KEY_get0_public_key(myecc);
		const EC_GROUP* ecGroup = EC_KEY_get0_group(myecc);
		BIGNUM *bn_x = BN_new();
		BIGNUM *bn_y = BN_new();

		//Extract x & y according to curve type
		if (isPrimeCurve)
		{
			EC_POINT_get_affine_coordinates_GFp(ecGroup, ecPointKey, bn_x, bn_y, NULL);
		}
		else
		{
			EC_POINT_get_affine_coordinates_GF2m(ecGroup, ecPointKey, bn_x, bn_y, NULL);
		}

		pubKey->keyType = VLT_KEY_ECC_PUB;
		pubKey->keySize = (VLT_U16) (BN_num_bytes(bn_x) + BN_num_bytes(bn_y));
		if (pubKey->keyValue == NULL)
		{
			status = EECCQHOSTNOMEMORY;
		}
		else
		{
			BN_bn2bin(bn_x, pubKey->keyValue);
			BN_bn2bin(bn_y, pubKey->keyValue + BN_num_bytes(bn_x));
		}

		//Release openssl structures
		BN_free(bn_x);
		BN_free(bn_y);
	}

	EC_KEY_free(myecc);
	
	return status;
#else
	return VLT_FAIL;
#endif
}

VLT_STS VerifyECCSignature(VLT_ECC_ID enCurveId, VLT_ALG_DIG_ID enDigestId, const VLT_U8 *pu8message, VLT_U32 u32messageLen, const VLT_U8 *pu8Signature, VLT_U16 u16SignatureLen, const VLT_KEY_BLOB *pubKey)
{
    VLT_STS	status = VLT_FAIL;
    VLT_ECDSA_PUBLIC_KEY theEcdsaPublicKey;
    theEcdsaPublicKey.u16QLen = pubKey->keySize / 2;
    theEcdsaPublicKey.pu8Qx = pubKey->keyValue;
    theEcdsaPublicKey.pu8Qy = pubKey->keyValue + theEcdsaPublicKey.u16QLen;

    if (VLT_OK != (status = EcdsaSignerInit(
        enCurveId,
        enDigestId,
        NULL,
        &theEcdsaPublicKey,
        VLT_SIGNER_MODE_VERIFY)))
    {
        return status;
    }

    
    // Intermediate buffer to avoid compil warning
    VLT_U8 au8Signature[2*MAX_ECC_KEY_BYTES_SIZE];
    if (u16SignatureLen > sizeof(au8Signature)) {
        return VLT_FAIL;
    }
    host_memcpy(au8Signature, pu8Signature, u16SignatureLen);

    if (VLT_OK != (status = EcdsaSignerDoFinal(
        pu8message,
        u32messageLen,
        au8Signature,
        &u16SignatureLen,
        0)))
    {
        return status;
    }

    /* clear down and free signer resources */
    if (VLT_OK != (status = EcdsaSignerClose()))
    {
        return status;
    }

    return VLT_OK;
}

#endif