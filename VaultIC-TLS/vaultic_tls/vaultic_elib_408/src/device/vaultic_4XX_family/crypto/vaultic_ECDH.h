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

#ifndef VAULTIC_ECDH_H
#define VAULTIC_ECDH_H

#ifdef __cplusplus
    extern "C"
    {
#endif

		/**
		 *
		 * \brief Calculates a Key agreement
		 *
         * \param[in] enKeyAgreementAlgoId Key Agreement algorithm ID.
		 * \param[in] enCurveId Curve ID.
		 * \param[in] kbPubKey The Static initiator public key.
		 * \param[in] kbPrivKey The Static responder private key.
		 * \param[out] sharedSecret The calculated shared secret.
		 *
		 * \return Upon successful completion a VLT_OK status will be returned otherwise
		 * the appropriate error code will be returned.
		 */
        VLT_STS KeyAgreement_ECDH(VLT_ALG_KAS_ID enKeyAgreementAlgoId, VLT_ECC_ID enCurveId,const  VLT_KEY_BLOB *kbPubKey, const VLT_KEY_BLOB *kbPrivKey, VLT_KEY_BLOB *sharedSecret);

		/**
		 *
		 * \brief Calculates the KDF using the X963 algorithm.
		 *
		 * \param[in] enDigest  Digest ID.
		 * \param[in] u16SharedSecretLen Length of the shared secret in bytes.
		 * \param[in] pu8SharedSecret Shared secret value.
		 * \param[in] u16SharedInfoLen Length of shared Info in bytes.
		 * \param[in] pu8SharedInfo Shared Info value.
		 * \param[out] derivedKey The calculated derived key value.
		 *
		 * \return Upon successful completion a VLT_OK status will be returned otherwise
		 * the appropriate error code will be returned.
		 */
		VLT_STS KDF_X963(VLT_ALG_DIG_ID enDigest, VLT_U16 u16SharedSecretLen, const VLT_U8 *pu8SharedSecret, VLT_U16 u16SharedInfoLen, const VLT_U8 *pu8SharedInfo, VLT_KEY_BLOB *derivedKey);

		/**
		 * \brief Calculates the KDF using the Concat algorithm.
		 *
		 * \param[in] enDigestId  Digest ID.
		 * \param[in] u16SharedSecretLen Length of the shared secret in bytes.
		 * \param[in] pu8SharedSecret Shared secret value.
		 * \param[in] u16KeyDataBitsLen Length of the derived key in bits.
		 * \param[in] u16AlgoIDLen Length of the Algo ID in bytes.
		 * \param[in] pu8AlgoID Algo ID value.
		 * \param[in] u16partyUInfoLen Length of PartyU in bytes.
		 * \param[in] partyUInfo PartyU value.
		 * \param[in] u16partyVInfoLen Length of PartyV in bytes.
		 * \param[in] partyVInfo PartyV value.
		 * \param[in] u16suppPubInfoLen Length of the Supp Pub in bytes.
		 * \param[in] suppPubInfo Supp Pub value.
		 * \param[in] u16suppPrivInfoLen Length of the Supp Priv in bytes.
		 * \param[in] suppPrivInfo Supp Priv value.
		 * \param[out] derivedKey The calculated derived key value.
		 *
		 * \return Upon successful completion a VLT_OK status will be returned otherwise
		 * the appropriate error code will be returned.
		 */

        VLT_STS KDF_Concat(VLT_ALG_DIG_ID enDigestId,
            VLT_U16 u16SharedSecretLen, const VLT_U8 *pu8SharedSecret,
            VLT_U16 u16KeyDataBitsLen,
            VLT_U16 u16AlgoIDLen, const VLT_U8 *pu8AlgoID,
            VLT_U16 u16partyUInfoLen, const VLT_U8 *partyUInfo,
            VLT_U16 u16partyVInfoLen, const VLT_U8 *partyVInfo,
            VLT_U16 u16suppPubInfoLen, const VLT_U8 *suppPubInfo,
            VLT_U16 u16suppPrivInfoLen, const VLT_U8 *suppPrivInfo,
            VLT_KEY_BLOB *derivedKey);

#ifdef __cplusplus
    };
#endif


#endif//VAULTIC_ECDH_H
