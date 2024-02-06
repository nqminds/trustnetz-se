/**
* @file	   vaultic_identity_authentication.h
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
* @defgroup IdentityAuthentication Identity Authentication service
*
* @brief   Interface functions to VaultIC Identity Authentication Service
*
* @details 
* The identity authentication service provides a simple way to authenticate with the VaultIC Security Module using secure channel.
*
* \note To authenticate a user using a password, the method #VltSubmitPassword should be used. 
*
* @par Conditions of Use
* If the Identity Authentication Service is used the following rules must be adhered to:
*   - If the #VltAuthInit method is successfully called, the #VltAuthClose method must be called to cancel the authentication.
*   - The following Base API methods must not be called when a user has been authenticated using the Identity Authentication Service:
*       - #VltSubmitPassword
*       - #VltCancelAuthentication
*       - #VltInitializeUpdate
*       - #VltExternalAuthenticate
*   . 
* Once authenticated, if any further method call returns an error code, the #VltAuthGetState
* method should be called to check whether the authentication has been cancelled.
*/

/**@{*/

#ifndef VAULTIC_IDENTITY_AUTHENTICATION_H
#define VAULTIC_IDENTITY_AUTHENTICATION_H


/**
 * \brief Initialise the identity authentication service.
 *
 * \par Description
 *
 * This function is used to initialize the authentication service and open a secure channel.
 * On success, the user will be authenticated (logged into) the vaultic
 * target, providing access to most methods.
 *
 * \param[in]   enAuthMethod Authentication Method
 * \param[in]   enUserID    Operator ID 
 * \param[in]   enRoleID    Role ID
 * \param[in]   enSecLevelID Secure Channel Level 
 * \param[in]   keys A structure containing the number of keys and a pointer to an array of type VLT_KEY_BLOB.
 *
 * \return Upon successful completion a VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.
 *  
 * \par Example:
 * \code 
 *  // This example is for an approved user who's auth method is SCP03.
 *  VLT_STS status = VLT_FAIL;
 *  VLT_KEY_BLOB keys[2] =
 *  {
 *      { VLT_KEY_AES_256, AES_256_KEY_SIZE, &aucSMacKey[0] },
 *      { VLT_KEY_AES_256, AES_256_KEY_SIZE, &aucSEncKey[0] }
 *  };
 *
 *  VLT_KEY_BLOB_ARRAY arrayOfKeys = 
 *  {
 *      2, // The number of keys
 *      &keys[0], // VLT_KEY_BLOB 1 : Smac key
 *      &keys[1]  // VLT_KEY_BLOB 2 : Senc key
 *  };
 * 
 *  
 *  status = VltAuthInit(VLT_AUTH_SCP03, 
 *      VLT_USER0, 
 *      VLT_APPROVED_USER, 
 *      VLT_CMAC_CENC_RMAC_RENC, 
 *      arrayOfKeys );
 *  
 *  if( VLT_OK != status )
 *  {
 *      return( VltApiClose() );
 *  }
 * \endcode
 */



VLT_STS VltAuthInit( VLT_AUTH_ID enAuthMethod,
    VLT_USER_ID enUserID, 
    VLT_ROLE_ID enRoleID, 
    VLT_SEC_LEVEL_ID enSecLevelID,
    VLT_KEY_BLOB_ARRAY keys );

/**
 * \brief Close the identity authentication service.
 *
 * \par Description
 *
 * Loggs the current user out of the vaultic and closes an opened secure channel.
 *
 * \return Upon successful completion a VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.
 */
VLT_STS VltAuthClose( void );

/**
 * \brief Returns the state of the identity authentication service.
 *
 * \par Description
 * 
 * Provides the host with the authentication (login) state of the 
 * the current user.

 * \param[out]   enState Authentication State
 *
 * \return Upon successful completion a VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.
 */
VLT_STS VltAuthGetState(VLT_AUTH_STATE *enState);

/**
 * \brief Retrieves the state of the current secure session.
 *
 * \par Description
 *
 * Provides the host with the current state of the secure session which
 * can be later resumed.

 * \param[out]   pSessionState Secure Session Authentication State
 *
 * \return Upon successful completion a VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.
 * \see VltAuthResumeSecureSession
 */
VLT_STS VltAuthGetSecureSession ( VLT_SECURE_SESSION_STATE *pSessionState );

/**
 *
 * \brief Resumes a secure session.
 *
 * \par Description
 *
 * Provides the host with a mean to resume the secure session which was
 * saved using #VltAuthGetSecureSession.  Only works if no transactions have made
 * since the state was saved.
 *
 * \return Upon successful completion a VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.
 * \see VltAuthGetSecureSession
 */
VLT_STS VltAuthResumeSecureSession (const VLT_SECURE_SESSION_STATE *pSessionState );

/**@}*/
#endif /*VAULTIC_IDENTITY_AUTHENTICATION_H*/
