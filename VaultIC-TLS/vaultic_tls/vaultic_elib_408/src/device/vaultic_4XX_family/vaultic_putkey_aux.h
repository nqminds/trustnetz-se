/**
* @file	   vaultic_putkey_aux.h
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

#ifndef VAULTIC_KEY_AUX_H
#define VAULTIC_KEY_AUX_H

#include "vaultic_typedefs.h"

/**
 * * \file vaultic_putkey_aux.h
 * \fn VltPutKey_Raw(VLT_U8 u8KeyGroup,
           VLT_U8 u8KeyIndex,
           const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
           const VLT_KEY_OBJ_RAW* pKeyObj,
           VLT_SW *pSW)
 *
 * \brief Imports a raw key into the internal Key Ring.
 * \par Description
 * See VltPutKey().
 */
VLT_STS VltPutKey_Raw(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    const VLT_KEY_OBJ_RAW* pKeyObj,
    VLT_SW *pSW);

#if(VLT_ENABLE_KEY_SECRET == VLT_ENABLE)
/**
 * \fn VltPutKey_Secret(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
 *         VLT_U8 u8KeyID,
 *         const VLT_KEY_OBJ_SECRET* pKeyObj,
 *         VLT_SW *pSW)
 *
 * \brief Imports a secret key into the internal Key Ring.
 * \par Description
 * See VltPutKey().
 */
VLT_STS VltPutKey_Secret(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    VLT_U8 u8KeyID,
    const VLT_KEY_OBJ_SECRET* pKeyObj,
    VLT_SW *pSW);
#endif


#if(VLT_ENABLE_KEY_HOTP == VLT_ENABLE)
/**
 * \fn VltPutKey_Hotp(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
 *         VLT_U8 u8KeyID,
 *         const VLT_KEY_OBJ_HOTP* pKeyObj,
 *         VLT_SW *pSW)
 *
 * \brief Imports an HOTP key into the internal Key Ring.
 * \par Description
 * See VltPutKey().
 */
VLT_STS VltPutKey_Hotp(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    VLT_U8 u8KeyID,
    const VLT_KEY_OBJ_HOTP* pKeyObj,
    VLT_SW *pSW);
#endif

#if(VLT_ENABLE_KEY_TOTP == VLT_ENABLE)
/**
 * \fn VltPutKey_Totp(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
 *         VLT_U8 u8KeyID,
 *         const VLT_KEY_OBJ_TOTP* pKeyObj,
 *         VLT_SW *pSW)
 *
 * \brief Imports an TOTP key into the internal Key Ring.
 * \par Description
 * See VltPutKey().
 */
VLT_STS VltPutKey_Totp(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    VLT_U8 u8KeyID,
    const VLT_KEY_OBJ_TOTP* pKeyObj,
    VLT_SW *pSW);
#endif

#if(VLT_ENABLE_KEY_RSA == VLT_ENABLE)
/**
 * \fn VltPutKey_RsaPublic(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
 *         VLT_U8 u8KeyID,
 *         const VLT_KEY_OBJ_RSA_PUB* pKeyObj,
 *         VLT_SW *pSW)
 *
 * \brief Imports an RSA public key into the internal Key Ring.
 * \par Description
 * See VltPutKey().
 */
VLT_STS VltPutKey_RsaPublic(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    VLT_U8 u8KeyID,
    const VLT_KEY_OBJ_RSA_PUB* pKeyObj,
    VLT_SW *pSW);

/**
 * \fn VltPutKey_RsaPrivate(VLT_U8 u8KeyGroup,
 *          VLT_U8 u8KeyIndex,
 *         const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
 *         VLT_U8 u8KeyID,
 *         const VLT_KEY_OBJ_RSA_PRIV* pKeyObj,
 *         VLT_SW *pSW)
 *
 * \brief Imports an RSA private key into the internal Key Ring.
 * \par Description
 * See VltPutKey().
 */
VLT_STS VltPutKey_RsaPrivate(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    VLT_U8 u8KeyID,
    const VLT_KEY_OBJ_RSA_PRIV* pKeyObj,
    VLT_SW *pSW);

/**
 * \fn VltPutKey_RsaPrivateCrt(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
 *         VLT_U8 u8KeyID,
 *         const VLT_KEY_OBJ_RSA_PRIV_CRT* pKeyObj,
 *         VLT_SW *pSW)
 *
 * \brief Imports an RSA private CRT key into the internal Key Ring.
 * \par Description
 * See VltPutKey().
 */
VLT_STS VltPutKey_RsaPrivateCrt(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    VLT_U8 u8KeyID,
    const VLT_KEY_OBJ_RSA_PRIV_CRT* pKeyObj,
    VLT_SW *pSW);
#endif

#if(VLT_ENABLE_KEY_ECDSA == VLT_ENABLE)
/**
 * \fn VltPutKey_EcdsaPublic(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
 *         VLT_U8 u8KeyID,
 *         const VLT_KEY_OBJ_ECDSA_PUB* pKeyObj,
 *         VLT_SW *pSW)
 *
 * \brief Imports an ECDSA public key into the internal Key Ring.
 * \par Description
 * See VltPutKey().
 */
VLT_STS VltPutKey_EcdsaPublic(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    VLT_U8 u8KeyID,
    const VLT_KEY_OBJ_ECDSA_PUB* pKeyObj,
    VLT_SW *pSW);

/**
 * \fn VltPutKey_EcdsaPrivate(VLT_U8 u8KeyGroup,
 *         VLT_U8 u8KeyIndex,
 *         const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
 *         VLT_U8 u8KeyID,
 *         const VLT_KEY_OBJ_ECDSA_PRIV* pKeyObj,
 *         VLT_SW *pSW)
 *
 * \brief Imports an ECDSA private key into the internal Key Ring.
 * \par Description
 * See VltPutKey().
 */
VLT_STS VltPutKey_EcdsaPrivate(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    VLT_U8 u8KeyID,
    const VLT_KEY_OBJ_ECDSA_PRIV* pKeyObj,
    VLT_SW *pSW);
#endif

#if(VLT_ENABLE_KEY_ECDSA == VLT_ENABLE)
VLT_STS VltPutKey_EcdsaParams( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    VLT_U8 u8KeyID,
    const VLT_KEY_OBJ_ECDSA_PARAMS* pKeyObj,
    VLT_SW *pSW );
#endif

#if(VLT_ENABLE_KEY_IDENTIFIER == VLT_ENABLE)
VLT_STS VltPutKey_IdKey( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    VLT_U8 u8KeyID,
    const VLT_KEY_OBJ_ID* pKeyObj,
    VLT_SW *pSW );
#endif
#endif /* VAULTIC_KEY_AUX_H */
