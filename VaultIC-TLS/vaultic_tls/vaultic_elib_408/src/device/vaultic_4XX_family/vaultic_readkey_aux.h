/**
* @file	   vaultic_readkey_aux.h
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
* @brief Auxiliary functions for key management.
*
* @par Description:
* This file declares functions for key management.
*/

#ifndef VAULTIC_READKEY_AUX_H
#define VAULTIC_READKEY_AUX_H

#include "vaultic_typedefs.h"


/**
 * \fn ReadKeyInitCrc( void )
 *
 * \brief Initialises CRC for reading a key
 *
 * \return The current CRC.
 */
void ReadKeyInitCrc( void );

/**
 * \fn VltReadKeyCommand(VLT_MEM_BLOB *command,
 *         VLT_MEM_BLOB *response,
 *         VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,    
 *         VLT_SW *pSW)
 *
 * \brief Calls VltCommand to read a key, or part of a key.
 *
 * \par Description
 * A hoisted out common call to VltCommand which copes with re-issuing the
 * command when VLT_STATUS_REISSUE is received.
 *
 * \param[in]  command    Command blob.
 * \param[in]  response   Response blob.
 * \param[in]  u8KeyGroup Key Group index.
 * \param[in]  u8KeyIndex Key index.
 * \param[out] pSW        Status word.
 *
 * \return Status.
 */
VLT_STS VltReadKeyCommand(const VLT_MEM_BLOB *command,
    VLT_MEM_BLOB *response,
    VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,    
    VLT_SW *pSW);


/**
 * \fn VltReadKey_Raw(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         VLT_KEY_OBJ_RAW* keyObj,
 *         VLT_SW *pSW)
 * \brief Exports a Raw key from the internal Key Ring.
 * \par Description
 * See VltReadKey().
 */
VLT_STS VltReadKey_Raw(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_RAW* keyObj,
    VLT_SW *pSW);

#if(VLT_ENABLE_KEY_SECRET == VLT_ENABLE)
/**
 * \fn VltReadKey_Secret(
 *         VLT_KEY_OBJ_SECRET* keyObj,
 *         VLT_SW *pSW )
 * \brief Exports a secret key from the internal Key Ring.
 * \par Description
 * See VltReadKey().
 */
VLT_STS VltReadKey_Secret( 
    VLT_KEY_OBJ_SECRET* keyObj,
    VLT_SW *pSW );

#endif /* VLT_ENABLE_KEY_SECRET */


#if(VLT_ENABLE_KEY_HOTP == VLT_ENABLE)

/**
 * \brief Exports an HOTP key from the internal Key Ring.
 * \par Description
 * See VltReadKey().
 */
VLT_STS VltReadKey_Hotp(
    VLT_KEY_OBJ_HOTP* keyObj,
    VLT_SW *pSW);

#endif /* VLT_ENABLE_KEY_HOTP */


#if(VLT_ENABLE_KEY_TOTP == VLT_ENABLE)

/**
 * \brief Exports an TOTP key from the internal Key Ring.
 * \par Description
 * See VltReadKey().
 */
VLT_STS VltReadKey_Totp(
    VLT_KEY_OBJ_TOTP* keyObj,
    VLT_SW *pSW);

#endif /* VLT_ENABLE_KEY_TOTP */


#if(VLT_ENABLE_KEY_RSA == VLT_ENABLE)

/**
 * \fn VltReadKey_RsaPublic(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         VLT_KEY_OBJ_RSA_PUB* keyObj,
 *         VLT_SW *pSW)
 * \brief Exports an RSA public key from the internal Key Ring.
 * \par Description
 * See VltReadKey().
 */
VLT_STS VltReadKey_RsaPublic(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_RSA_PUB* keyObj,
    VLT_SW *pSW);
/**
 * \fn VltReadKey_RsaPrivate(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         VLT_KEY_OBJ_RSA_PRIV* keyObj,
 *         VLT_SW *pSW)
 * \brief Exports an RSA private key from the internal Key Ring.
 * \par Description
 * See VltReadKey().
 */
VLT_STS VltReadKey_RsaPrivate(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_RSA_PRIV* keyObj,
    VLT_SW *pSW);
/**
 * \fn VltReadKey_RsaPrivateCrt(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         VLT_KEY_OBJ_RSA_PRIV_CRT* keyObj,
 *         VLT_SW *pSW)
 * \brief Exports an RSA private CRT key from the internal Key Ring.
 * \par Description
 * See VltReadKey().
 */
VLT_STS VltReadKey_RsaPrivateCrt(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_RSA_PRIV_CRT* keyObj,
    VLT_SW *pSW);

#endif /* VLT_ENABLE_KEY_RSA */

#if(VLT_ENABLE_KEY_ECDSA == VLT_ENABLE)

/**
 * \fn VltReadKey_EcdsaPublic(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         VLT_KEY_OBJ_ECDSA_PUB* keyObj,
 *         VLT_SW *pSW)
 * \brief Exports an ECDSA public key from the internal Key Ring.
 * \par Description
 * See VltReadKey().
 */
VLT_STS VltReadKey_EcdsaPublic(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_ECDSA_PUB* keyObj,
    VLT_SW *pSW);

/**
 * \fn VltReadKey_EcdsaPrivate(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         VLT_KEY_OBJ_ECDSA_PRIV* keyObj,
 *         VLT_SW *pSW)
 * \brief Exports an ECDSA private key from the internal Key Ring.
 * \par Description
 * See VltReadKey().
 */
VLT_STS VltReadKey_EcdsaPrivate(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_ECDSA_PRIV* keyObj,
    VLT_SW *pSW);

/**
 * \fn VltReadKey_EcdsaParams(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         VLT_KEY_OBJ_ECDSA_PARAMS* keyObj,
 *         VLT_SW *pSW)
 * \brief Exports an ECDSA Params key from the internal Key Ring.
 * \par Description
 * See VltReadKey().
 */
VLT_STS VltReadKey_EcdsaParams( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_ECDSA_PARAMS* keyObj,
    VLT_SW *pSW );

#endif /* VLT_ENABLE_KEY_ECDSA */

#if(VLT_ENABLE_KEY_IDENTIFIER == VLT_ENABLE)
/**
 * \fn VltReadKey_IdKey( VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         VLT_KEY_OBJ_ID* keyObj,
 *         VLT_SW *pSW)
 * \brief Exports a Host or Device ID key from the internal Key Ring.
 * \par Description
 * See VltReadKey().
 */
VLT_STS VltReadKey_IdKey( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_ID* keyObj,
    VLT_SW *pSW );
#endif
#endif /* VAULTIC_READKEY_AUX_H */
