/**
* @file	   vaultic_ecdsa_signer.h
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
* @defgroup EcdsaSign ECDSA Signer service
  @brief ECDSA Signer service functions.

* @details 
* The ECDSA Signer service provides a simple means to compute or verify an ECDSA signature on the host side.\n
* It can be used to compute a signature on the host side, and sent it to the VaultIC for verification using VltVerifySignature(),
* or to verify a signature computed by a VaultIC using VltGenerateSignature().
* \note The VaultIC device is not used, all cryptographic operations are performed by the host.
*/

#ifndef VAULTIC_ECDSA_SIGNER_H
#define VAULTIC_ECDSA_SIGNER_H

#include "vaultic_config.h"

#ifdef __cplusplus
    extern "C"
    {
#endif

/** @{ */

/**
 *
 * \brief Initializes the VaultIC API ECDSA Signer Service.
 * \par Description
 *
 * The EcdsaSignerInit() method provides a software implementation for ECDSA 
 * signing and verifying service initialisation. 
 * Upon successful completion a number of internal system resources would be 
 * allocated and used.  These resources will remain in use until a call to the 
 * EcdsaSignerClose() method is made.
 *
 * \param[in] enCurveId  Elliptic Curve Identifier 
 * \param[in] enDigestId Digest algorithm identifier 
 * \param[in] pPrivateKey Private key used for signing
 * \param[in] pPublicKey  Public key used for verifying signature
 * \param[in] enSignerMode The signer operation mode identifier
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.
 *  
 */
VLT_STS EcdsaSignerInit(
    VLT_ECC_ID enCurveId,
    VLT_ALG_DIG_ID enDigestId,
    const VLT_ECDSA_PRIVATE_KEY* pPrivateKey,
    const VLT_ECDSA_PUBLIC_KEY* pPublicKey,
    VLT_SIGNER_MODE enSignerMode);

/**
 *
 * \brief Closes the VaultIC API ECDSA Signing Service.
 * \par Description
 *
 * The EcdsaSignerClose() method provides a software implementation for ECDSA 
 * signing service closure and resource cleanup.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.
 *  
 */
VLT_STS EcdsaSignerClose( void );


/**
 *
 * \brief Performs a signing operation using ECDSA algorithm.
 * \par Description
 *
 * The EcdsaSignerDoFinal() method provides a software implementation for ECDSA 
 * signing and verifying operations.
 *
 * The method can only be called once with the whole message. 
 * #EcdsaSignerInit() must be called first.
 *
 * \param[in] pu8Message         Pointer to a message buffer the ECDSA signer will use.
 * \param[in] u32messageLen      The length of the message.
 * \param[in,out] pu8Signature   Pointer to a signature buffer the ECDSA signer will use.
 * \param[in,out] pu16SignatureLen   The length of the signature.
 * \param[in] u32SignatureCapacity The capacity of the signature buffer.
 *  
 * \return Upon successful completion a #VLT_OK status will be returned 
 * otherwise the appropriate error code will be returned.
 *  
 */ 
VLT_STS EcdsaSignerDoFinal( 
    const VLT_U8 *pu8Message,
    VLT_U32 u32messageLen, 
    VLT_U8 *pu8Signature, 
    VLT_U16 *pu16SignatureLen, 
    VLT_U32 u32SignatureCapacity );

#if (HOST_CRYPTO == HOST_CRYPTO_OPENSSL)
/**
    * \brief Get the curve NID from the curveId.
    *
    * \param[in] enCurveId Curve ID.
    * \param[in, out] pNID The NID of the curve.
    *
    * \return Upon successful completion a VLT_OK status will be returned otherwise
    * the appropriate error code will be returned.
    */
VLT_STS EcdsaGetCurveNID(VLT_ECC_ID enCurveId, int *pNID);
#endif

/**
 * \brief Indicate if the curve is a Prime Curve or not
 *
 * \param[in] enCurveId Curve ID.
 * \param[out] isPrimeCurve Indicate if the curve is a Prime Curve or not.
 *
 * \return Upon successful completion a VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.
 */
VLT_STS EcdsaIsPcurve(VLT_ECC_ID enCurveId, VLT_BOOL *isPrimeCurve);


/**
 * \brief Sets up ECDSA cryptographic domain parameters according to selected curve
 *
 * \par Description
 * The EcdsaSetKeyObjDomainParams method is used to initialise the cryptographic domain parameters structure 
 * with one of the builtin set supported by the device.
 *
 * \param[in] enCurveId ECC curve identifier
 * \param[out] pKeyObj A pointer to a user allocated pKeyObj structure which will receive the domain parameter data
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise the appropriate error code will be returned.
 * \warning This method should only be used when the VaultIC device has been pre-initialised
 * to use one of the built-in default cryptographic parameter sets. Refer to the device
 * technical datasheet for more details.

 */
VLT_STS EcdsaSetKeyObjDomainParams(VLT_ECC_ID enCurveId, VLT_KEY_OBJECT *pKeyObj);

#ifdef __cplusplus
    };
#endif

#endif // VAULTIC_ECDSA_SIGNER_H
/** @} */