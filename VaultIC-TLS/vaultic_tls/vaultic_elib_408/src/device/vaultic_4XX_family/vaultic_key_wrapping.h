/**
* @file	   vaultic_key_wrapping.h
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
* @defgroup KeyWrapping Key Wrapping service
* @brief   Interface functions to VaultIC Key Wrapping/Unwrapping Service.
*
* @details The Key Wrapping service provides the ability to
* wrap keys before they are sent to the VaultIC or to unwrap keys
* read from the VaultIC. \n
*
* Use of the service is as follows:
* - Call VltKeyWrappingInit() to initialise the service with the necessary
* parameters to allow the service to wrap/unwrap keys.

* - Call VltKeyWrap() supplying a pointer to the key object to be wrapped and the file privileges for the key, \n
* or call VltKeyUnwrap() supplying a pointer to a key object with the appropriate space to place the key to be unwrapped.
* - Once complete call VltKeyWrappingClose() to close the Key
* Wrapping/Unwrapping service.\n
*
* It should be noted that the Key Wrapping Service cannot be used over a
* Secure Channel
*/

/**@{*/

#ifndef VAULTIC_KEY_WRAPPING_H
#define VAULTIC_KEY_WRAPPING_H

/**
 *
 * \brief Used to initialise the Key Wrapping/Unwrapping Service.
 *
 * \par Description
 *
 * This method is used to initialise the key wrapping/unwrapping service.
 * The #VLT_WRAP_PARAMS structure passed in should be populated with the 
 * appropriate values to select the algorithm used to wrap/unwrap the key
 *
 * \param[in] u8KTSKeyGroup     Key Group index of the Key Transport Scheme.
 * \param[in] u8KTSKeyIndex     Key index of the Key Transport Scheme.
 * \param[in] pWrapParams       The parameters used to wrap/unwrap the key.
 * \param[in] pKTSKey           The KTS key used to encrypt/decrypt the key
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the Vault IC.
 *
 */
VLT_STS VltKeyWrappingInit( VLT_U8 u8KTSKeyGroup,
    VLT_U8 u8KTSKeyIndex,
    const VLT_WRAP_PARAMS* pWrapParams,
    const VLT_KEY_OBJECT* pKTSKey );

/**
 * \brief Used to wrap the key data (when using PUT KEY)
 *
 * \par Description
 *
 * This method is used to wrap the key data (when using PUT KEY)
 *
 * \param[in] u8KeyGroup         Key Group index.
 * \param[in] u8KeyIndex         Key index.
 * \param[in] pKeyFilePrivileges Pointer to the privileges for the key being 
 *                                 put down to the VaultIC.
 * \param[in] pKeyObj            Pointer to the key object to be put down to
 *                                 the VaultIC
 * 
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the Vault IC.
 \see VltKeyUnwrap
 *
 */
VLT_STS VltKeyWrap( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    const VLT_KEY_OBJ_RAW* pKeyObj );

/**
 * \brief Used to unwrap the key data (when using READ KEY)
 *
 * \par Description
 *
 * This method is used to unwrap the key data (when using READ KEY)
 *
 * \param[in] u8KeyGroup          Key Group index.
 * \param[in] u8KeyIndex          Key index.
 * \param[out] pKeyObj            Pointer to a key object to be filled with
 *                                 the key being read from the VaultIC
 * 
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the Vault IC.
 \see VltKeyWrap
 *
 */
VLT_STS VltKeyUnwrap( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_RAW* pKeyObj );

/**
 * \brief Used to close the Key Wrapping/Unwrapping Service.
 *
 * \par Description
 *
 * This method is used to close the Key Wrapping/Unwrapping Service
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the Vault IC.
 *
 */
VLT_STS VltKeyWrappingClose( void );


/**@}*/
#endif /*VAULTIC_KEY_WRAPPING_H*/

