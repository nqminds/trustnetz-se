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
* @brief  Implementation of the ECC utilities function. 
*
* @details 
*
* @date    16/01/2017
* @author  fmauraton
*/

#ifndef VAULTIC____ECC_H
#define VAULTIC____ECC_H

#ifdef __cplusplus
    extern "C"
    {
#endif

		
		/**
		 * \fn GenerateECCKeyPair(VLT_ECC_ID CurveId,
		 *	int *pNID, VLT_BOOL *isPrimeCurve)
		 *
		 * \brief Generate an ECC keypair using the specified domain params.
		 *
		 * \param[in] CurveId Curve ID.
		 * \param[in, out] pubKey The generated public key.
		 * \param[in, out] privKey The generated private key.
		 *
		 * \return Upon successful completion a VLT_OK status will be returned otherwise
		 * the appropriate error code will be returned.
		 */
		VLT_STS GenerateECCKeyPair(VLT_ECC_ID CurveId, VLT_KEY_BLOB *pubKey, VLT_KEY_BLOB *privKey);

		/**
		 *
		 * \brief Verify an ECC Signature using the provided public key.
		 *
		 * \param[in] enCurveId The curve identifier.
         * \param[in] enDigestId The digest identifier.
         * \param[in] pu8message The message value.
		 * \param[in] u32messageLen The message length.
		 * \param[in] pu8Signature the signature value.
		 * \param[in] u16SignatureLen The signature length.
		 * \param[in] pubKey The public key to use for signature verification.
		 *
		 * \return Upon successful completion a VLT_OK status will be returned otherwise
		 * the appropriate error code will be returned.
		 */
		VLT_STS VerifyECCSignature(VLT_ECC_ID enCurveId, VLT_ALG_DIG_ID enDigestId, const VLT_U8 *pu8message, VLT_U32 u32messageLen, const VLT_U8 *pu8Signature, VLT_U16 u16SignatureLen, const VLT_KEY_BLOB *pubKey);


#ifdef __cplusplus
    };
#endif


#endif
