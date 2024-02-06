/**
* @file	   vaultic_api.h
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
* @brief VaultIC API functions definition
*/

/**
* @defgroup VaultIcApi VaultIC base API
* @brief Interface functions to VaultIC security module.
*
* @par Description
*
* This file declares the interface functions for each command that the VaultIC
* supports. There is an approximate 1:1 mapping between functions and VaultIC
* commands. In cases where a VaultIC interface supports multiple modes of
* operation it is presented as two C interfaces for clarity and type safety.
*
*/

#ifndef VAULTIC_API_H
#define VAULTIC_API_H


/* --------------------------------------------------------------------------
 * SESSION MANAGEMENT FUNCTIONS
 * -------------------------------------------------------------------------- */

/** @defgroup vaultic_api_mgr  Session management
 *  @ingroup VaultIcApi
    @brief Functions used to open or close a VaultIC API usage session
    @details Before using the VaultIC API it is necessary to initialize it using #VltApiInit() , in order to allocate and initialize the relevant internal 
    variables.
    The session must be ended by a call to #VltApiClose().
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initializes a VaultIC API session.
 * \par Description
 *
 * The VltApiInit() method provides an initialisation entry point to the 
 * entire VaultIC API library. Upon successful completion a number of internal
 * system resources would be allocated and used by subsequent API calls, these
 * resources will remain in use until a call to the VltApiClose() method is made.
 * If the call to the VltApiInit() is unsuccessful calls to the rest of the API 
 * methods will produced undefined results. 
 *
 * \param[in] pInitCommsParams Parameters passed to communications layer.
 *  
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.
 *
 * \note The VltApiInit method is a helper function that must be called to setup and initialize
*        communications with the VaultIC eLib
 *  
 * \par Example:
 * \code 
 *  VLT_STS status = VLT_FAIL; 
 *  VLT_INIT_COMMS_PARAMS commsParams = {0};
 * 
 *  commsParams.enCommsProtocol = VLT_TWI_COMMS;
 *  commsParams.VltTwiParams.u16BitRate = 100;
 *  commsParams.VltTwiParams.u8Address = 0x5F;
 *  commsParams.VltBlockProtocolParams.u16msSelfTestDelay = 500;
 *  commsParams.VltBlockProtocolParams.u32msTimeout = 5000;
 * 
 *  status = VltApiInit( &params );
 *  if( VLT_OK != status )
 *  {
 *      return( VltApiClose() );
 *  }
 * \endcode
 * \see VltApiClose
 */
VLT_STS VltApiInit(const VLT_INIT_COMMS_PARAMS *pInitCommsParams);


/**
 * \brief Closes down a VaultIC API session.
 *
 * \par Description
 *
 * The VltApiClose() method provides a finalisation entry point to the 
 * entire VaultIC API library. Upon successful completion a number of internal
 * system resources previously allocated will be released, subsequent calls 
 * to the rest of the API methods will produced undefined results.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.
 *
 * \see VltApiInit()
 */
VLT_STS VltApiClose( void );

/** @}*/



/* --------------------------------------------------------------------------
 * IDENTITY AUTHENTICATION
 * -------------------------------------------------------------------------- */

/** @defgroup vaultic_api_auth  Identity Authentication
 *  @ingroup VaultIcApi
 *  @brief Functions used for managing Identity Authentication
 * @{
 */

/**
 * \brief Authenticates an operator using a password.
 *
 * \par Description
 *
 * After successful execution, this command closes any previously opened Secure
 * Channel (i.e. the response is sent applying the current security level, and
 * the security level is reset afterwards). If the submission fails (i.e. wrong
 * password), the previous authentication and secure channel are preserved.  
 *
 * \param[in] enUserID      User ID
 * \param[in] enRoleID      Role ID
 * \param[in] u8PasswordLength  Password length (4..32).
 * \param[in] pu8Password       Password.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC. 
 */
VLT_STS VltSubmitPassword(VLT_USER_ID enUserID, 
    VLT_ROLE_ID enRoleID,
    VLT_U8 u8PasswordLength,
    const VLT_U8 *pu8Password );


/**
 *
 * \brief Performs Secure Channel initiation.
 *
 * \par Description
 *
 * This command is used in conjunction with the VltExternalAuthenticate()
 * command to perform a SCP Secure Channel initiation.
 * This command first closes any current secure channel. The authentication try
 * counter is decremented here, and is reset in the VltExternalAuthenticate()
 * command if successful.
 *
 * \param[in] enUserID      User ID
 * \param[in] enRoleID      Role ID
 * \param[in] u8HostChallengeLength Host challenge length.
 * \param[in] pu8HostChallenge      Host challenge.
 * \param[out] pRespData             VLT_INIT_UPDATE structure to receive SCP response data.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 */
#if (VLT_ENABLE_API_INITIALIZE_UPDATE == VLT_ENABLE)
VLT_STS VltInitializeUpdate(VLT_USER_ID enUserID, 
    VLT_ROLE_ID enRoleID,
    VLT_U8 u8HostChallengeLength,
    const VLT_U8 *pu8HostChallenge,
    VLT_INIT_UPDATE *pRespData );
#endif
/**
 * \brief Completes a secure channel initiation.
 *
 * \par Description
 *
 * Completes a secure channel initiation.
 * The security level is defined and will be applied to subsequent APDU
 * commands.
 * A call to this method typically follows a call to the VltInitializeUpdate() method.
 *
 * \param[in] enAuthMethod          Authentication method
 *
 * \param[in] enChannelLevel        Security level
 *  
 * \param[in] u8CryptogramLength    Cryptogram length.
 * \param[in] pu8Cryptogram         Cryptogram.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 */
VLT_STS VltExternalAuthenticate( VLT_AUTH_ID enAuthMethod,
    VLT_SEC_LEVEL_ID enChannelLevel,
    VLT_U8 u8CryptogramLength,
    const VLT_U8 *pu8Cryptogram );

/**
 * \brief Gets info about authentication data of an operator.
 *
 * \param[in] enUserID      Operator ID. 
 *
 * \param[out] pRespData    Authentication Info data structure ::VLT_AUTH_INFO.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 */
#if (VLT_ENABLE_API_GET_AUTHENTICATION_INFO == VLT_ENABLE)
VLT_STS VltGetAuthenticationInfo(VLT_USER_ID enUserID,
    VLT_AUTH_INFO *pRespData);
#endif

/**
 * \brief Sets or updates authentication data for an operator.
 *
 * \par Description
 *
 * Authenticated operator assuming manufacturer role can conditionally add,
 * delete, modify, lock or unlock any operator authentication data without
 * restriction if the device is in #VLT_STATE_CREATION state.
 * Authenticated operator assuming administrator role can conditionally add,
 * delete, modify, lock, or unlock any operator authentication data without
 * restriction and in any state (except #VLT_STATE_TERMINATED state) if the
 * Administrator Security Policy is set.
 * Any authenticated operator can only modify its own authentication data with
 * some restrictions. Add, delete, lock and unlock operations are not permitted.
 * The supplied authentication data must have the same authentication method,
 * the same assumed roles, the same security level and the same security option.
 * Any mismatch will result in an error.  Authentication data update preserves
 * both try counter and sequence counter.
 *
 * \param[in] pAuthSetup   Manage Authentication Data data structure.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
#if (VLT_ENABLE_API_MANAGE_AUTHENTICATION_DATA == VLT_ENABLE)
VLT_STS VltManageAuthenticationData( const VLT_MANAGE_AUTH_DATA *pAuthSetup );
#endif


/**
 * \brief Resets the VaultIC authentication state and closes secure channel.
 *
 * \par Description
 *  This method resets the VaultIC Security Module authentication state.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 *
 * \note Logs out the currently authenticated user.
 */
VLT_STS VltCancelAuthentication( void );

/**
 * \brief Initiates a generic Host Unilateral Authentication to the VaultIC.
 *
 * \par Description
 *
 * This command is used to initiate a generic Host Unilateral Authentication to
 * the VaultIC chip (i.e. the VaultIC chip authenticates an external entity).
 * The VltInitializeAlgorithm() command shall be previously sent with the
 * algorithm identifier set with a valid #VLT_ALG_SIG_ID Signer Identifier. The signer key is
 * fetched at this time and the signer engine is initialized with specific
 * algorithm parameters.
 * The response to the VltGetChallenge() command contains the VaultIC
 * challenge Cd that will be used by the host in its signature computation
 * during the strong authentication. The length of the challenge is defined by
 * the Generic Strong Authentication parameters ::VLT_GENERIC_AUTH_SETUP_DATA.
 * This command shall be followed by a VltGenericExternalAuthenticate()
 * command. If not, the authentication process is aborted and the command is
 * processed normally.
 *
 * \param[in]   pAuthParameters    Generic Strong Authentication parameters.
 * \param[out]  pu8DeviceChallenge Device challenge (Cd).
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
* \see VltInitializeAlgorithm()
 */
VLT_STS VltGetChallenge( const VLT_GENERIC_AUTH_SETUP_DATA *pAuthParameters, 
    VLT_U8 *pu8DeviceChallenge );

/**
*
 * \brief Performs a generic Device Unilateral Authentication of the VaultIC, or
 * generic Mutual Authentication.
 *
 * \par Description
 *
 * This command can be used alone to perform a generic Device Unilateral
 * Authentication of the VaultIC or may be followed by a 
 * VltGenericExternalAuthenticate() command in order to perform a generic Mutual
 * Authentication.
 *
 * \param[in]   pAuthParameters       Generic Strong Authentication parameters.
 * \param[in]   pu8HostChallenge      Host challenge (Ch).
 * \param[out]  pu8DeviceChallenge    VaultIC challenge (Cd)
 * \param[out]  pu16SignatureLength   Length of signature returned

 * \param[in]   u16SignatureCapacity  Size of the signature buffer 
 * \param[out]  pu8Signature          Buffer to receive VaultIC signature SIGNk.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltGenericInternalAuthenticate( const VLT_GENERIC_AUTH_SETUP_DATA *pAuthParameters,
    const VLT_U8 *pu8HostChallenge,
    VLT_U8 *pu8DeviceChallenge,
    VLT_U16 *pu16SignatureLength,
    VLT_U16 u16SignatureCapacity,
    VLT_U8 *pu8Signature );

/**
 * \brief Used after VltGenericInternalAuthenticate() to complete a generic
 * Mutual Authentication.
 *
 * \par Description
 *
 * This command may be used after a VltGenericInternalAuthenticate() to complete
 * a generic Mutual Authentication protocol, or can be sent after a 
 * VltGetChallenge() command to complete a generic Host Unilateral Authentication
 * to the VaultIC.
 * This command gets a signature from a host and a host challenge Ch, and
 * attempts a verification. It returns the result of this verification. 
 *
 * \param[in]   u8HostChallengeLength   Host challenge (Ch) length.
 * \param[in]   pu8HostChallenge        Host challenge (Ch).
 * \param[in]   u16HostSignatureLength  Host signature (SIGNk) length.
 * \param[in]   pu8HostSignature        Host signature (SIGNk).
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 *
 * \see VltGetChallenge command 
 * \see VltGenericInternalAuthenticate command.
 */
VLT_STS VltGenericExternalAuthenticate(VLT_U8 u8HostChallengeLength,
    const VLT_U8 *pu8HostChallenge,
    VLT_U16 u16HostSignatureLength,
    const VLT_U8 *pu8HostSignature );

/**
 * \brief VltSubmitSecurePasswordInit
 *
 * \par Description
 *
 * First sequence when using Secure Passwords. Get Device Challenge (8 bytes)
 *
 * \param[in] enUserID      User ID
 * \param[in] enRoleID      Role ID
 * \param[out] au8DeviceChallenge
 * 
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 *
 */
VLT_STS VltSubmitSecurePasswordInit(
    VLT_USER_ID enUserID,
    VLT_ROLE_ID enRoleID, 
    VLT_U8 au8DeviceChallenge[VLT_SECURE_PWD_CHALLENGE_LENGTH]);

/**
 * \brief VltSubmitSecurePasswordFinal
 *
 * \par Description
 *
 * Last sequence when using Secure Passwords. 
 *
 * \param[in] enUserID      User ID
 * \param[in] enRoleID      Role ID
 * \param[in] u8EncPwdLen   Encrypted Password length
 * \param[in] pu8EncPwd   Encrypted Password
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 *
 */
VLT_STS VltSubmitSecurePasswordFinal(
    VLT_USER_ID enUserID,
    VLT_ROLE_ID enRoleID,
    VLT_U8 u8EncPwdLen,
    const VLT_U8 *pu8EncPwd);

/** @}*/



/* --------------------------------------------------------------------------
 * CRYPTO SERVICES
 * -------------------------------------------------------------------------- */

 /** @defgroup vaultic_api_crypto  Cryptographic services
  *  @ingroup VaultIcApi
  *  @brief Functions used for performing cryptographic operations
  * @{
  */

/**
 * \brief Initializes a cryptographic algorithm in the VaultIC device.
 *
 * \par Description
 * This method initializes a cryptographic algorithm, a cryptographic key and conditionally
 * some specific algorithm parameters for subsequent cryptographic services.\n
 * The key is identified by the key group index and the key index given by the
 * \a u8KeyGroup and \a u8KeyIndex parameters. The key is fetched from the Internal
 * Key Ring.
 * The command data field optionally carries specific algorithm parameters. They
 * define all algorithm parameters to be applied to any subsequent cryptographic
 * operations.
 * \note The logged-in user must have the Execute privilege on the involved key
 * file.
 * The VltInitializeAlgorithm() *shall* be sent before the following
 * cryptographic services:
 * - VltEncrypt()
 * - VltGenerateSignature() 
 * - VltVerifySignature()
 * - VltComputeMessageDigest()
 * - VltGetChallenge()
 * - VltGenericInternalAuthenticate()
 *
 * The VltInitializeAlgorithm command *may* be sent before the following
 * cryptographic services:
 *
 * - VltPutKey() for key unwrapping (key sent encrypted to the device)
 * - VltReadKey() for key wrapping (key sent encrypted from the device)
 *
 * \note Any other command will discard the algorithm, wipe its parameters and unload
 * the key. Command Chaining is allowed for the underlying cryptographic
 * service.
 * As soon as the service type changes, the algorithm being initialized is
 * discarded. Algorithm parameters cannot be shared between different
 * cryptographic operations.
 * 
 * note A non-approved user must be logged-in to initialize a non-approved
 * algorithm.
 *
 * \param[in] u8KeyGroup    Key Group index. Shall be zero for digest
 *                         initialization.
 * \param[in] u8KeyIndex    Key index. Shall be zero for digest initialization.
 * \param[in] enAlgoMode   Mode of operation for subsequent commands.
 * \param[in] pAlgorithm Algorithm parameters.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
#if (VLT_ENABLE_API_INITIALIZE_ALGORITHM == VLT_ENABLE)
VLT_STS VltInitializeAlgorithm( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_ALGO_MODE enAlgoMode,
    const VLT_ALGO_PARAMS *pAlgorithm );
#endif
/**
  * \brief Uninitializes a cryptographic algorithm in the VaultIC device.
 *
 * \par Description
 *
 */
VLT_STS VltUnInitializeAlgorithm(void);

/**
 * \brief Imports a key into the internal Key Ring.
 *
 * \par Description
 *
 * This method is used to import a key into the internal Key Ring of the VaultIC. The key is identified by the key
 * group index and they key index given by \a u8KeyGroup and \a u8KeyIndex. The
 * key file holding the imported key is automatically created and owned by the
 * currently logged-in user.
 *
 * The key can either be transported in plaintext or encrypted with a cipher
 * available. If key unwrapping is required, the VltInitialiseAlgorithm()
 * command shall be previously sent with the algorithm identifier set with a
 * valid Key Transport Scheme identifier.
 *
 * \note The put key command shall be sent two times to download a key pair.
 *
 * \warning In Approved Mode of operation, secret or private keys cannot be
 * downloaded in plaintext. A secure channel with encrypted command data field
 * C-ENC level shall be opened or a key wrapping mechanism shall be used.
 *
 * \param[in]   u8KeyGroup          Key Group index.
 * \param[in]   u8KeyIndex          Key index.
 * \param[in]   pKeyFilePrivileges Key file Access Conditions. The logged-in
 *                                 user must grant its own user ID write
 *                                 permission on the key file.
 * \param[in]   pKeyObj            Key object.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 *
 * \see VltReadKey()
  */
VLT_STS VltPutKey( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    const VLT_KEY_OBJECT *pKeyObj );


/**
 * \brief Exports a key from the internal Key Ring.
 *
 * \par Description
 *
 * This method is used to export a key from the internal Key Ring of the VaultIC. The key is identified by the key
 * group index and the key index given by \a u8KeyGroup and \a u8KeyIndex.
 *
 * The key can either be transported in plaintext or encrypted by any cipher
 * available. If key wrapping is required, the VltInitializeAlgorithm()
 * command shall be previously sent with the algorithm identifier set with a
 * valid Key Transport Scheme identifier.
 *
 * \note The logged-in user must have the read privilege on the involved key
 * file.
 *
 * \warning In Approved Mode of operation, secret or private keys cannot be
 * extracted in plaintext. A secure channel with encrypted response data field
 * R-ENC level shall be opened or a key unwrapping mechanism shall be used.
 *
 * \param[in]   u8KeyGroup  Key Group index.
 * \param[in]   u8KeyIndex  Key index.
 * \param[out]  pKeyObj     Key object.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 *
 * \see VltPutKey()
  */
VLT_STS VltReadKey( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJECT *pKeyObj );

/**
 * \brief Deletes a key in the internal Key Ring.
 *
 * \par Description
 *
 * Deletes a key in the internal Key Ring. The key is identified by the key
 * group index and the key index given by \a u8KeyGroup and \a u8KeyIndex.
 *
 * \note The logged-in user must have the Delete privilege on the involved key
 * file.
 *
 * \param[in]   u8KeyGroup  Key Group index
 * \param[in]   u8KeyIndex  Key index
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltDeleteKey(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex );

/**
 * \brief Encrypts the provided message.
 *
 * \par Description
 *
 * This command encrypts the provided message and outputs the result.
 *
 * The VltInitializeAlgorithm() command shall be previously sent with the
 * algorithm identifier set with a valid #VLT_ALG_CIP_ID Cipher Identifier. 
 * The cipher key is
 * fetched at this time and the cipher engine is initialized with specific
 * algorithm parameters.
 *
 * \param[in]   u32PlainTextLength      Length of plaintext
 * \param[in]   pu8PlainText            Plaintext
 * \param[out]  pu32CipherTextLength    Length of ciphertext returned
 * \param[in]   u32CipherTextCapacity   Size of Buffer to receive ciphertext.
 * \param[out]  pu8CipherText           Buffer to receive ciphertext.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltEncrypt( VLT_U32 u32PlainTextLength,
    const VLT_U8 *pu8PlainText,
    VLT_U32 *pu32CipherTextLength,
    VLT_U32 u32CipherTextCapacity,
    VLT_U8 *pu8CipherText );

/**
 * \brief Decrypts the provided message.
 *
 * \par Description
 *
 * This command decrypts the provided message and outputs the result.
 *
 * The VltInitializeAlgorithm() command shall be previously sent with the
 * algorithm identifier set with a valid #VLT_ALG_CIP_ID Cipher Identifier. The cipher key is
 * fetched at this time and the cipher engine is initialized with specific
 * algorithm parameters.
 *
 * \param[in]   u32CipherTextLength     Length of ciphertext.
 * \param[in]   pu8CipherText           Ciphertext.
 * \param[out]  pu32PlainTextLength     Length of plaintext returned
 * \param[in]   u32PlainTextCapacity    Size of Buffer to receive plaintext
 * \param[out]  pu8PlainText            Buffer to receive plaintext.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltDecrypt( VLT_U32 u32CipherTextLength,
    const VLT_U8 *pu8CipherText,
    VLT_U32 *pu32PlainTextLength,
    VLT_U32 u32PlainTextCapacity,
    VLT_U8 *pu8PlainText );

/**
 *
 * \brief Generates an assurance message for private key possession assurance.
 *
 * \par Description
 *
 * This command generates a valid assurance message for private key possession
 * assurance.
 *
 * \param[in]       u8KeyGroup          The public key group that will be used in the verify operation
 * \param[in]       u8KeyIndex          The public key index that will be used in the verify operation
 * \param[in,out]   pu8SignerIdLength   The Length of the provided or returned SignerID 
 * \param[in]       pu8SignerID         The SignerID
 * \param[out]      pAssuranceMsg       Returned assurance message.
 * 
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
#if (VLT_ENABLE_API_GENERATE_ASSURANCE_MESSAGE == VLT_ENABLE)
VLT_STS VltGenerateAssuranceMessage( 
    VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_U8 *pu8SignerIdLength,
    const VLT_U8 *pu8SignerID,
    VLT_ASSURANCE_MESSAGE *pAssuranceMsg );
#endif
/**
 * \brief Generates a signature from a message.
 *
 * \par Description
 *
 * This command gets a raw message (or its precomputed hash) and returns its signature.
 *
 * The VltInitializeAlgorithm() command shall be previously sent with the following settings:
 * - algo mode set to #VLT_SIGN_MODE
 * - algorithm identifier set to a value in #VLT_ALG_SIG_ID range
 * - digest identifier set to a value in #VLT_ALG_DIG_ID range or #VLT_ALG_DIG_NONE
 *
 * This command is also used for One Time Password Generation.
 *
 * \note According to the digest identifier value, the provided message must be:
 * - a raw message that will be internally digested by the VaultIC (e.g. #VLT_ALG_DIG_SHA256)
 * - an already digested message (#VLT_ALG_DIG_NONE).
 *
 * \param[in] u32MessageLength          Length of input message.
 * \param[in] pu8Message                Input message.
 * \param[out] pu16SignatureLength      Length of computed signature
 * \param[in] u16SignatureCapacity      Size of the signature buffer
 * \param[out] pu8Signature             Buffer to receive computed signature.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 *
 * \note VltGenerateSignature() is able to compute the signature of a message with any restriction concerning the size of the message,
 * and should be used in most cases.\n 
 * In case the message cannot be provided in a single buffer, the VltUpdateSignature() and VltComputeSignatureFinal() can be used instead.
 *
 * \see VltInitializeAlgorithm()
 * \see EcdsaSign service functions
 */
VLT_STS VltGenerateSignature(VLT_U32 u32MessageLength,
    const VLT_U8 *pu8Message,
    VLT_U16 *pu16SignatureLength,
    VLT_U16 u16SignatureCapacity,
    VLT_U8 *pu8Signature);

/**
 * \brief Provides message in multiple parts before a signature generation.
 *
 * \par Description
 *
 * This method is used to provide the message in multiple parts for a signature generation operation.
 *
 * It has to be repeated for each part of the message, and then be followed by a VltComputeSignatureFinal() to actually get the signature.
 *
 * \note This method is useful in case the message can not be provided in a single buffer, otherwise the VltGenerateSignature() can be used instead
 * to perform the whole operation in one single step.
 *
 * The VltInitializeAlgorithm() command shall be previously sent with the following settings:
 * - algo mode set to #VLT_SIGN_MODE
 * - algorithm identifier set to a value in #VLT_ALG_SIG_ID range
 * - digest identifier set to a value in #VLT_ALG_DIG_ID range or #VLT_ALG_DIG_NONE
 *
 * \note According to the digest identifier value, the provided message must be:
 * - a raw message that will be internally digested by the VaultIC (#VLT_ALG_DIG_SHA256)
 * - an already digested message (#VLT_ALG_DIG_NONE).
 *
 * \param[in] u32MessagePartLength     Length of input message part.
 * \param[in] pu8MessagePart           Input message part.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 *
 * \see VltInitializeAlgorithm()
 * \see VltComputeSignatureFinal()
 * \see EcdsaSign service functions
 */
VLT_STS VltUpdateSignature(VLT_U32 u32MessagePartLength,
    const VLT_U8 *pu8MessagePart);

/**
 * \brief Computes the signature of a message (last step when message provided in multiple parts).
 *
 * \par Description
 *
 * This method finishes a multiple-part message signing operation, generating and returning the signature.
 *
 * It has to be preceded with several calls to VltUpdateSignature() to provide the different parts of the input message.
 *
 * \note This method is useful in case the message can not be provided in a single buffer, otherwise the VltGenerateSignature() can be used instead
 * to perform the whole operation in one single step.
 *
 * \param[out] pu16SignatureLength      Length of the computed signature
 * \param[in] u16SignatureCapacity      Size of the signature buffer
 * \param[out] pu8Signature             Buffer to receive computed signature.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 *
 * \see VltInitializeAlgorithm()
 * \see VltUpdateSignature()
 * \see EcdsaSign service functions
 */
VLT_STS VltComputeSignatureFinal(VLT_U16 *pu16SignatureLength,
    VLT_U16 u16SignatureCapacity,
    VLT_U8 *pu8Signature);


/**
 * \brief Verifies the signature of a message.
 *
 * \par Description
 *
 * This command gets a raw message (or its precomputed hash) and verifies its signature.
 *
 * The VltInitializeAlgorithm() command shall be previously sent with the following settings:
 * - algo mode set to #VLT_VERIFY_MODE
 * - algorithm identifier set to a value in #VLT_ALG_SIG_ID range
 * - digest identifier set to a value in #VLT_ALG_DIG_ID range or #VLT_ALG_DIG_NONE
 *
 * \note According to the digest identifier value, the provided message must be:
 * - a raw message that will be internally digested by the VaultIC (e.g. #VLT_ALG_DIG_SHA256)
 * - an already digested message (#VLT_ALG_DIG_NONE).
 *
 * \param[in] u32MessageLength     Length of input message.
 * \param[in] pu8Message           Input message.
 * \param[in] u16SignatureLength   Length of input signature.
 * \param[in] pu8Signature         Signature to verify.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 *
 * \note VltVerifySignature() is able to compute the signature of a message with any restriction concerning the size of the message,
 * and should be used in most cases.\n In case the message cannot be provided in a single buffer, the VltUpdateVerify() and VltComputeVerifyFinal() can be used instead. 
 *
 * \see VltInitializeAlgorithm()
 * \see EcdsaSign service functions
 */
VLT_STS VltVerifySignature(VLT_U32 u32MessageLength,
    const VLT_U8 *pu8Message,
    VLT_U16 u16SignatureLength,
    const VLT_U8 *pu8Signature );

/**
 * \brief Provides message in multiple parts before a signature verification 
 *
 * \par Description
 *
 * This method is used to provide the message in multiple parts for a signature verification operation.
 *
 * It has to be repeated for each part of the message, and then be followed by a VltComputeVerifyFinal() to actually verify the signature.
 *
 * \note This method is useful in case the message can not be provided in a single buffer, otherwise the VltVerifySignature() can be used instead
 * to perform the whole operation in one single step.
 *
 * The VltInitializeAlgorithm() command shall be previously sent with the following settings:
 * - algo mode set to #VLT_VERIFY_MODE
 * - algorithm identifier set to a value in #VLT_ALG_SIG_ID range
 * - digest identifier set to a value in #VLT_ALG_DIG_ID range or #VLT_ALG_DIG_NONE
*
 *
 * \note According to the digest identifier value, the provided message must be:
 * - a raw message that will be internally digested by the VaultIC (e.g. #VLT_ALG_DIG_SHA256)
 * - an already digested message (#VLT_ALG_DIG_NONE).
 *
 * \param[in] u32MessagePartLength     Length of input message part.
 * \param[in] pu8MessagePart           Input message part.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 *
 *
 * \see VltInitializeAlgorithm()
 * \see VltComputeVerifyFinal()
 * \see EcdsaSign service functions
 */
VLT_STS VltUpdateVerify(VLT_U32 u32MessagePartLength,
    const VLT_U8 *pu8MessagePart);

/**
 * \brief Verifies the signature of a message (last step when message provided in multiple parts).
 *
 * \par Description
 *
 * This method finishes a multiple-part verification operation, checking the signature.
 *
 * It has to be preceded with several calls to VltUpdateVerify() to provide the different parts of the input message.
 *
 * \note This method is useful in case the message can not be provided in a single buffer, otherwise the VltVerifySignature() can be used instead
 * to perform the whole operation in one single step.
 *
 * \param[in] u32SignatureLength   Length of buffer to receive signature.
 * \param[in] pu8Signature         Buffer to receive signature.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 *
 * \see VltInitializeAlgorithm()
 * \see VltUpdateVerify()
  * \see EcdsaSign service functions
 */
VLT_STS VltComputeVerifyFinal(VLT_U32 u32SignatureLength,
    const VLT_U8 *pu8Signature);


/**
 * \brief Computes the digest of a message.
 *
 * \par Description
 *
 * This method computes the digest of a provided message.
 *
 * The VltInitializeAlgorithm() command shall be previously sent with the following settings:
 * - algo mode set to #VLT_DIGEST_MODE
 * - key group set to 0
 * - key index set to 0
 * - algorithm identifier set to a value in #VLT_ALG_DIG_ID range
 *
 * \param[in] u32MessageLength      Length of input message.
 * \param[in] pu8Message            Input message.
 * \param[out] pu8DigestLength      Length of computed digest
 * \param[in] u8DigestCapacity      Size of digest buffer
 * \param[out] pu8Digest            Buffer to receive digest.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 *
  * \note VltComputeMessageDigest() is able to compute the digest of a message with any restriction concerning the size of the message,
 * and should be used in most cases.\n
 * In case the message cannot be provided in a single buffer, the VltUpdateMessageDigest() and VltComputeMessageDigestFinal() can be used instead.
 *
 * \see VltInitializeAlgorithm()
 */
VLT_STS VltComputeMessageDigest(VLT_U32 u32MessageLength,
    const VLT_U8 *pu8Message,
    VLT_U8 *pu8DigestLength,
    VLT_U8  u8DigestCapacity,
    VLT_U8 *pu8Digest);

/**
 * \brief Provides message in multiple parts before a compute digest operation.
 *
 * \par Description
 *
 * This method is used to provide the message in multiple parts for a compute digest  operation.
 *
 * It has to be repeated for each part of the message, and then be followed by a VltComputeMessageDigestFinal() to actually get the digest.
 *
 * \note This method is useful in case the message can not be provided in a single buffer, otherwise the VltComputeMessageDigest() can be used instead
 * to perform the whole operation in one single step.
 *
 * The VltInitializeAlgorithm() command shall be previously sent with the following settings:
 * - algo mode set to #VLT_DIGEST_MODE
 * - key group set to 0
 * - key index set to 0
 * - algorithm identifier set to a value in #VLT_ALG_DIG_ID range
 *
 * \param[in] u32MessageLength      Length of input message.
 * \param[in] pu8Message            Input message.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 *
 * \see VltInitializeAlgorithm()
 * \see VltComputeMessageDigestFinal()
 */
VLT_STS VltUpdateMessageDigest(VLT_U32 u32MessageLength,
    const VLT_U8 *pu8Message);


/**
 * \brief Computes the digest of a message (last step when message provided in multiple parts).
 *
 * \par Description
 *
 * This method finishes a multiple-part compute digest operation, computing and returning the digest.
 *
 * It has to be preceded with several calls to VltUpdateMessageDigest() to provide the different parts of the input message.
 *
 * \note This method is useful in case the message can not be provided in a single buffer, otherwise the VltComputeMessageDigest() can be used instead
 * to perform the whole operation in one single step.
 *
 *
 * \param[out] pu8DigestLength      Length of computed digest
 * \param[in] u8DigestCapacity      Size of digest buffer
 * \param[out] pu8Digest            Buffer to receive digest.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 *
 * \see VltInitializeAlgorithm()
 * \see VltUpdateMessageDigest()
 */
VLT_STS VltComputeMessageDigestFinal(VLT_U8 *pu8DigestLength,
    VLT_U8 u8DigestCapacity,
    VLT_U8 *pu8Digest);


/**
 * \brief Do a key confirmation on the specified derived key
 *
 * \par Description
 * The VltKeyConfirmation method verifies the MacTag and on success, unlocks the access to the specified derived key.  
 *
 * \param[in]   u8KeyGroup      Group index of derived key to confirm.
 * \param[in]   u8KeyIndex      Index of derived key to confirm.
 * \param[in]   pMacTagU        MacTagU object value.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 * 
 * \see VltDeriveKey()
 */
#if( VLT_ENABLE_API_KEY_CONFIRMATION == VLT_ENABLE)
VLT_STS VltKeyConfirmation(VLT_U8 u8KeyGroup, VLT_U8 u8KeyIndex,VLT_MAC_TAG *pMacTagU);
#endif

/**
 * \brief Derive a key using DH agreement 
 *
 * \par Description
 * The VltDeriveKey method derives a key using a DH agreement specified in \a pKeyDerivationParams parameters
 *
 * \param[in]   u8KeyGroup              Group of derived key.
 * \param[in]   u8KeyIndex              Index of derived key.
 * \param[in]   pKeyFilePrivileges      Privileges of derived key.
 * \param[in]   enDerivatedKeyType      Derived key type.
 * \param[in]   u16DerivatedKeyBitLen   Expected Derived Key Length (in bits)
 * \param[in]   pKeyDerivationParams    Key derivation parameters.
 * \param[in]   enPolicy                Key Confirmation Policy
 * \param[out]  pKeyDerivationResp      Key derivation response
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 *
 * \see VltKeyConfirmation()
 */
#if( VLT_ENABLE_API_DERIVE_KEY == VLT_ENABLE)
VLT_STS VltDeriveKey(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    VLT_KEY_ID enDerivatedKeyType, 
    VLT_U16 u16DerivatedKeyBitLen,
    const VLT_KEY_DERIVATION *pKeyDerivationParams,
    VLT_KEY_CONFIRM_POLICY enPolicy, 
    VLT_KEY_DERIVATION_RESP *pKeyDerivationResp
    );
#endif

/**
 * \brief Constructs a DH agreement.
 *
 * \par Description
 * The VltConstructDHAgreement method constructs a DH agreement
 *
 * \param[in] u8ResultKeyGroup		Group index of result key.
 * \param[in] u8ResultKeyIndex		Index of result key.
 * \param[in] pKeyFilePrivileges	Privileges of result key.
 * \param[in] pKeyMaterial			Key material for DH agreement construction.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
#if( VLT_ENABLE_API_CONSTRUCT_AGREEMENT == VLT_ENABLE)
VLT_STS VltConstructDHAgreement(
	VLT_U8 u8ResultKeyGroup,
    VLT_U8 u8ResultKeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
	const VLT_KEY_MATERIAL *pKeyMaterial );
#endif

/**
 * \brief Generates random bytes.
 *
 * \par Description
 *
 * This command fills the buffer with the requested number of random bytes.
 *
 * \param[in] u8NumberOfCharacters  Number of random characters to generate (1..255)
 * \param[out] pu8RandomCharacters  Buffer to receive random characters.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltGenerateRandom( VLT_U8 u8NumberOfCharacters, 
    VLT_U8 *pu8RandomCharacters );

/**
 * \brief Generates a public/private key pair and stores it in the key ring.
 *
 * \par Description
 *
 * Generates a public key pair and stores it in the key ring. This command can
 * generate DSA, ECDSA and RSA keys. The key files holding the generated key
 * pair are automatically created and owned by the currently logged-in user.
 *
 * \param[in] u8PublicKeyGroup              Public key group index.
 * \param[in] u8PublicKeyIndex              Public key index.
 * \param[in] pPublicKeyFilePrivileges      Public key file Access Conditions. The
 *                                          logged-in operator must grant its own 
 *                                          user ID write permission on the key file.
 * \param[in] u8PrivateKeyGroup             Private key group index.
 * \param[in] u8PrivateKeyIndex             Private key index.
 * \param[in] pPrivateKeyFilePrivileges     Private key file Access Conditions. The
 *                                          logged-in operator must grant its own
 *                                          user ID write permission on the key
 *                                          file.
 * \param[in] pKeyGenData                   Algorithm Parameters Object.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
#if (VLT_ENABLE_API_GENERATE_KEY_PAIR == VLT_ENABLE)
VLT_STS VltGenerateKeyPair( VLT_U8 u8PublicKeyGroup,
    VLT_U8 u8PublicKeyIndex,
    const VLT_FILE_PRIVILEGES *pPublicKeyFilePrivileges,
    VLT_U8 u8PrivateKeyGroup,
    VLT_U8 u8PrivateKeyIndex,
    const VLT_FILE_PRIVILEGES *pPrivateKeyFilePrivileges,
    const VLT_KEY_GEN_DATA *pKeyGenData );
#endif

/**
 * \brief Generates a Symmetric key and stores it in the key ring.
 *
 * \par Description
 *
 * Generates a symmetric key and stores it in the key ring. This command can
 * generate AES-128, AES-192, AES-256 keys. The key file holding the generated key
 * is automatically created and owned by the currently logged-in user.
 *
 * \param[in] u8KeyGroup                    Key group index.
 * \param[in] u8KeyIndex                    Key index.
 * \param[in] pKeyFilePrivileges            Key file Access Conditions. The
 *                                          logged-in operator must grant its own 
 *                                          user ID write permission on the key file.
 * \param[in] enAesKeyId                    Aes Key type ID
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
#if (VLT_ENABLE_API_GENERATE_SYMMETRIC_KEY == VLT_ENABLE)
VLT_STS VltGenerateSymmetricKey(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    VLT_AES_ID enAesKeyId);
#endif
/** @}*/

/* --------------------------------------------------------------------------
 * FILE SYSTEM SERVICES
 * -------------------------------------------------------------------------- */

 /** @defgroup filesystem_ll  File System 
  *  @ingroup VaultIcApi
  *  @brief Low level Functions used for managing VaultIC file system
  *  \see FileSystem
  * @{
  */

/**
 * \brief Starts an atomic transaction on file system updates.
 *
 * \par Description
 *
 * Starts Transactions mechanism on file system updates.
 *
 * VltBeginTransaction command shall be invoked prior to start sensitive file
 * update operations. All the following file system updates will be protected
 * against power-loss event. File system integrity and data consistency will be
 * guaranteed,
 *
 * If a tear event occurs while a transaction is in progress, any updates to
 * files content and file system structure are discarded. VaultIC anti-tearing
 * engine will restore the file system as it was when VltBeginTransaction
 * command has been received. The transaction is committed by 
 * VltEndTransaction() command.
 *
 * \warning When a transaction is started, the currently selected file or folder
 * is unselected. A VltSelectFileOrDirectory() command shall be sent inside
 * the transaction.
 *
 * \warning The content of the file system which is update outside a secure
 * transaction is not predictable following a tear or reset during the update.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltBeginTransaction( void );

/**
 * \brief Completes an atomic transaction on file system updates.
 *
 * \par Description
 *
 * Commits Transactions mechanism on file system updates, previously started with #VltBeginTransaction
 *
 * Any file system updates during a transaction are only done conditionally. All
 * these conditional updates shall be committed at the very end of the
 * transaction sending VltEndTransaction command.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltEndTransaction( void );

/**
 *
 * \brief Selects a file or directory.
 *
 * \par Description
 *
 * This method selects a file or directory and retrieves the file size and the access
 * conditions.
 *
 * \note When selecting a file, the Current File Position is initialized to the first
 * byte of the file.
 *
 * \note Secure Transaction is supported.
 *
  * \param[in] pu8Path        Path of the file to select (char string terminated by a NULL terminator)
 * \param[in] u8PathLength Path length, including NULL terminator.
 * \param[out] pRespData   Returned file size, access conditions and attributes.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltSelectFileOrDirectory(const VLT_U8 *pu8Path, 
    VLT_U8 u8PathLength, 
    VLT_SELECT *pRespData );

/**
 * \brief Returns a list of files in the currently selected directory.
 *
 * \par Description
 *
 * Returns a multi-string containing the names of files and directories located
 * in the currently selected directory.
 *
 * Files or directories with the hidden attribute are skipped out the listing.
 *
 * \note A multi-string is a sequence of NULL-terminated strings. The sequence is
 * terminated by a NULL byte, therefore the multi-string ends up by two
 * consecutive NULL bytes.
 *
 * \note The order in which files are reported may be different before and after
 * a secure transaction performed on the selected directory.
 *
 * \note The logged-in operator must have the List privilege on the selected
 * directory.
 *
 * \note A single NULL byte is returned if the current directory does not contain any
 * files or sub-directories.
 *
 * An error code is returned if the buffer passed in is not large enough to 
 * accomodate all of the data returned by the VaultIC.  The pu16ListRespLength
 * parameter is updated to the size of the buffer required to return the full 
 * directory listing.  A partial directory listing will be contained within the
 * buffer, but this should be ignored.  A buffer of the size reported  back by 
 * the updated pu16ListRespLength should be constructed and passed as the input
 * parameters to VltListFiles.
 *
 * \param[out]  pu16ListRespLength      Size of the file list response
 * \param[in]   u16ListRespCapacity     Size of allocated buffer to receive the file list.
 * \param[out]  pu8RespData             Buffer to receive file list response
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltListFiles(VLT_U16 *pu16ListRespLength, 
    VLT_U16 u16ListRespCapacity,
    VLT_U8 *pu8RespData );

/**
 *
 * \brief Creates a new file.
 *
 * \par Description
 *
 * Creates a new file in the currently selected directory. The newly created
 * file becomes the currently selected file.
 *
 * \note The logged-in operator must have the Create privilege on the selected
 * directory.
 *
 * \param[in]   enUserID            Operator ID
 * \param[in]   u32FileSize         Initial file size in bytes. Maximum file size is 65535 bytes
 * \param[in]   pFilePriv           Access conditions (cf #VLT_FILE_PRIVILEGES for details)
 * \param[in]   u8FileAttributes    Bitfield representing File attributes: \n
                                    - b7..b4: Reserved (set to 0000) 
                                    - b3: DIRECTORY attribute bit 
                                        - 0 = Is a file 
                                    - b2: HIDDEN attribute bit 
                                        - 0 = Do not hide
                                        - 1 = Hides from a directory listing
                                    - b1: SYSTEM attribute bit 
                                        - 0 = Is not a system file 
                                        - 1 = Is a system file 
                                    - b0: READ-ONLY attribute bit 
                                        - 0 = Write operation is granted
                                        - 1 = File is write-protected
 *
 * \param[in]   u16FileNameLength   Length of file name (1..8).
 * \param[in]   pu8FileName         File name.
 *
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 * \see VltCreateFolder
 */
VLT_STS VltCreateFile( VLT_USER_ID enUserID,
    VLT_U32 u32FileSize, 
    const VLT_FILE_PRIVILEGES *pFilePriv,
    VLT_U8 u8FileAttributes,
    VLT_U16 u16FileNameLength,
    const VLT_U8 *pu8FileName );

/**
 * \brief Creates a new folder.
 *
 * \par Description
 *
 * Creates a new sub-directory in the currently selected directory.
 *
 * \note The logged-in operator must have the Create privilege on the selected
 * directory.
 *
 * \param[in]   enUserID            Operator ID
 * \param[in]   pFilePriv           Access conditions (cf #VLT_FILE_PRIVILEGES for details)
 * \param[in]   u8FolderAttributes  Bitfield representing Folder Attributes: \n
                                    - b7..b4: Reserved (set to 0000)
                                    - b3: DIRECTORY attribute bit
                                        - 1 = Is a directory or sub-directory)
                                    - b2: HIDDEN attribute bit
                                        - 0 = Do not hide
                                        - 1 = Hides from a directory listing
                                    - b1: SYSTEM attribute bit
                                        - 0 = Is not a system file
                                        - 1 = Is a system file
                                    - b0: READ-ONLY attribute bit
                                        - 0 = Write operation is granted
                                        - 1 = File is write-protected
 * \param[in]   u16FolderNameLength Length of folder name (1..8)
 * \param[in]   pu8FolderName       Folder name
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 * \see VltCreateFile
 */
VLT_STS VltCreateFolder( VLT_USER_ID enUserID,
    const VLT_FILE_PRIVILEGES *pFilePriv,                                   
    VLT_U8 u8FolderAttributes,
    VLT_U16 u16FolderNameLength,
    const VLT_U8 *pu8FolderName );

/**

 * \brief Deletes the current file.
 *
 * \par Description
 *
 * Deletes the current file. Read-only files are protected against deletion.
 *
 * \note Once the file is deleted. The parent directory is still the current directory
 * but no file is selected.
 *
 * \note The logged-in operator must have the Delete privilege on the selected
 * directory.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 * \see VltDeleteFolder
 */

VLT_STS VltDeleteFile( void );

/**
* \brief Deletes the current directory.
*
* \par Description
*
* Deletes the current directory.
*
* Once the folder is deleted, the root directory becomes the current directory.
*
* \note The logged-in operator must have the Delete privilege on the selected
* directory.
*
* \note If recursion is required, Delete privilege must be granted on all files
* and directories located under the selected directory.
*
* \param bRecursion            Specifies whether a recursive delete of files and folders
*                              should take place. Possibles values are:
*                               - #FALSE Delete the folder non recursively
*                               - #TRUE  Delete the folder and any contained files and folders
*
* \return Upon successful completion a #VLT_OK status will be returned otherwise
* the appropriate error code will be returned.\n Please note, status values 
* larger than #VLT_OK are errors that have originated in the API library while 
* status values smaller than #VLT_OK are the APDU status words that are returned 
* by the VaultIC.
* \see VltDeleteFile
*/
VLT_STS VltDeleteFolder( VLT_BOOL bRecursion );

/**
 * \brief Sets the current file position.
 *
 * \par Description
 *
 * This method sets the current file position.
 *
 * \note If the provided offset is beyond the End Of File, a specific status is
 * returned, and the current file position is set just after the last byte of
 * the file (so that a write operation can be performed to append data to the
 * file).
 *
 * \warning The logged-in operator must have read or write privilege on the
 * selected file.
 *
 * \param[in] u32SeekOffset   The new file position relative to the beginning of
 *                            the file.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 * \see VltReadFile
 * \see VltWriteFile
 */
VLT_STS VltSeekFile(VLT_U32 u32SeekOffset);

/**
 * \brief Updates part of the contents of the current file.
 *
 * \par Description
 *
 * This method updates part of the contents of the current file, from the current file
 * position. Write operation is not allowed on read-only files.
 *
 * \note If the provided data goes beyond the End Of File, the file will grow
 * automatically provided there is enough space in the file system. \n
 * It is also possible to shrink the file and discard previous data that were beyond the
 * new End Of File by setting \a bReclaimSpace to TRUE.\n
 * File system space is allocated/reclaimed accordingly.
 *
 * \note The current file position is set at the end of the written data.
 *
 * \param[in]   pu8Data         Data to write.
 * \param[in]   u8DataLength    Length of data (1..255).
 * \param[in]   bReclaimSpace   Space Reclaim Indicator
 *                              - #FALSE : data after the new end of file should not be reclaimed 
 *                              - #TRUE  : data after the new end of file should be reclaimed 
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 * \see VltSeekFile
 */
VLT_STS VltWriteFile( const VLT_U8 *pu8Data,
    VLT_U8 u8DataLength,
    VLT_BOOL bReclaimSpace );

/**
 * \brief Reads part of the contents of the current file.
 *
 * \par Description
 *
 * This method reads part of the contents of the current file from the current file
 * position.
 *
 * \note If the requested length goes beyond the End of File, only the available data
 * are returned and a specific status is returned.
 *
 * \note The current file position is set at the end of the read data.
 *
 * \warning
 * If \a pu8ReadLength specifies a value larger than the VaultIC can return, an
 * error will be returned and \a pu8ReadLength will be set to the maximum number
 * of bytes that can be read.
 *
 * \warning
 * If the user's authentication method is SCP0x and the channel level is CMAC
 * or higher, the \a *pu8ReadLength value will be ignored due to the mechanics of
 * the secure channel.
 * The VaultIC will return 256 bytes or the whole file if the file size is 
 * less than 256 bytes.
 *
 * \param[in,out] pu16ReadLength  On entry this holds the maximum size of the
 *                                buffer. On exit it is set to the amount of
 *                                buffer received. 256 bytes is the max requested
 *                                size, values larger will generate an error.
 * \param[out] pu8RespData        Ptr to a buffer where the data read will be
 *                                stored.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 * \see VltSeekFile
 */
VLT_STS VltReadFile(VLT_U16 *pu16ReadLength,
    VLT_U8 *pu8RespData);



/**
 * \brief Updates Access Conditions of the currently selected file or folder.
 *
 * \par Description
 *
 * Updates Access Conditions of the currently selected file or folder.
 *
 * \warning The logged-in operator must be the owner of the selected file or
 * folder.
 *
 * \note This operation is protected against tear event without the need to
 * initiate a transaction.
 *
 * \param[in] pFilePriv File or folder Access Conditions.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltSetPrivileges( const VLT_FILE_PRIVILEGES *pFilePriv );

/**
 * \brief Updates Attributes of the currently selected file.
 *
 * \par Description
 *
 * Updates Attributes of the currently selected file.
 *
 * \warning The logged-in operator must be the owner of the selected file.
 *
 * \note This operation is protected against tear event without the need to
 * initiate a transaction.
 *
 * \param[in]   u8Attribute         Bitfield representing File or Folder attributes: \n
                                    - b7..b4: Reserved (set to 0000)
                                    - b3: DIRECTORY attribute bit
                                        - 0 = Is a file
                                        - 1 = Is a directory or sub-directory)
                                    - b2: HIDDEN attribute bit
                                        - 0 = Do not hide
                                        - 1 = Hides from a directory listing
                                    - b1: SYSTEM attribute bit
                                        - 0 = Is not a system file
                                        - 1 = Is a system file
                                    - b0: READ-ONLY attribute bit
                                        - 0 = Write operation is granted
                                        - 1 = File is write-protected
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltSetAttributes( VLT_U8 u8Attribute );

/** @}*/

/* --------------------------------------------------------------------------
 * MANUFACTURING SERVICES
 * -------------------------------------------------------------------------- */

 /** @defgroup vaultic_api_manuf  Manufacturing services
  *  @ingroup VaultIcApi
  *  @brief Functions used for managing manufacturing services.
  * @{
  */

 /**
  * \brief Returns information about the security module.
  *
  * \par Description
  *
  * This command returns some information about the security module: chip
  * identifiers, unique serial number, life cycle state and available file system
  * space.
  *
  * \param[out] pRespData Structure to receive information.
  *
  * \return Upon successful completion a #VLT_OK status will be returned otherwise
  * the appropriate error code will be returned.\n Please note, status values
  * larger than #VLT_OK are errors that have originated in the API library while
  * status values smaller than #VLT_OK are the APDU status words that are returned
  * by the VaultIC.
  */
VLT_STS VltGetInfo(VLT_TARGET_INFO *pRespData);


/**

 * \brief Initiates and runs self testing.
 *
 * \par Description
 *
 * Self-tests sequence ensures that VaultIC is working properly and is
 * automatically performed at each power-up or reset. The self-tests command
 * allows any user, authenticated or not, to initiate the same test flow
 * on-demand for periodic test of the VaultIC.
 *
 * \note During self-tests operation, all approved cryptographic algorithms are tested
 * using known-answer and firmware integrity is checked using CRC-16 CCITT.
 *
 * \warning If self-tests failed, any authentication is cancelled, any secure channel is
 * closed and the VaultIC is automatically switched to TERMINATED state.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltSelfTest( void );

/**
 * \brief Changes Life Cycle state.

 * \par Description
 * This method changes the life cycle state of the VaultIC.
 *
 * \param[in] enState  New state value
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 */
VLT_STS VltSetStatus(VLT_STATE enState);


/**
 * \brief Sets VaultIC configuration parameters.
 *
 * \par Description
 *
 * This method is used to set internal parameters of the VaultIC chip. These settings are applied
 * using the anti-tearing mechanism and permanently stored into the internal
 * memory.
 *
 * \warning Setting wrong values may damage the VaultIC chip. Use with caution.\n
 *
 * \param[in] enConfigItemId    Identifier of item to configure
 * \param[in] enConfigItemSize  Size of item to configure
 * \param[in] pu8ConfigData     Data buffer containing configuration value. 
 * \note Please refer to VaultIC technical data sheet for further details.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 */
VLT_STS VltSetConfig(VLT_SET_CFG enConfigItemId,
    VLT_SET_CFG_SZ enConfigItemSize,
    const VLT_U8 *pu8ConfigData);


/**
 * \brief Sets the FIPS level
 *
 * \par Description
 *
 *  Changes the FIPS level with the requested value.
 * 
 * \param[in] enFipsLevel  The fips level to set
 * 
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltSetFipsLevel(VLT_FIPS_LEVEL enFipsLevel );

/**
 * \brief Sets the FIPS algorithms
 *
 * \par Description
 *
 *  Declares the list of algorithms used in Approved (FIPS) mode
 *
 * \param[in] punFipsAlgos The list of algos used in FIPS mode
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values
 * larger than #VLT_OK are errors that have originated in the API library while
 * status values smaller than #VLT_OK are the APDU status words that are returned
 * by the VaultIC.
 */
VLT_STS VltSetFipsAlgos(const VLT_FIPS_ALGOS *punFipsAlgos);

/**
 * \brief Dummy APDU case 1 command for integration testing.
 *
 * \par Description
 *
 * This command is a dummy APDU case 1 command for integration testing purposes.
 *
 * When a secure channel has been initiated, this command must be sent INSIDE
 * the secure channel, i.e. applying the security level required by the current
 * secure channel. Not doing so will close the secure channel and
 * de-authenticate the user.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltTestCase1( void );

/**
 * \brief Dummy APDU case 2 command for integration testing.
 *
 * \par Description
 *
 * This command is a dummy APDU case 2 command for integration testing purposes.
 *
 * When a secure channel has been initiated, this command must be sent INSIDE
 * the secure channel, i.e. applying the security level required by the current
 * secure channel. Not doing so will close the secure channel and
 * de-authenticate the user.
 *
 * \param[in]   u8RequestedDataLength Number of output bytes (1..255).
 * \param[out]  pu8RespData           Buffer to receive output bytes.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltTestCase2( VLT_U8 u8RequestedDataLength, 
    VLT_U8 *pu8RespData );

/**
 * \brief Dummy APDU case 3 command for integration testing.
 *
 * \par Description
 *
 * This command is a dummy APDU case 3 command for integration testing purposes.
 *
 * When a secure channel has been initiated, this command must be sent INSIDE
 * the secure channel, i.e. applying the security level required by the current
 * secure channel. Not doing so will close the secure channel and
 * de-authenticate the user.
 *
 * \param[in] u8DataLength      Number of input bytes (1..255).
 * \param[in] pu8Data           Input bytes.
 * 
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltTestCase3(VLT_U8 u8DataLength,
     const VLT_U8 *pu8Data );

/**
 * \brief Dummy APDU case 4 command for integration testing.
 *
 * \par Description
 *
 * This command is a dummy APDU case 4 command for integration testing purposes.
 *
 * When a secure channel has been initiated, this command must be sent INSIDE
 * the secure channel, i.e. applying the security level required by the current
 * secure channel. Not doing so will close the secure channel and
 * de-authenticate the user.
 *
 * \param[in] u8DataLength              Number of input bytes (1..255).
 * \param[in] pu8Data                   Input bytes.
 * \param[in] u8RequestedDataLength     Number of output bytes (1..255).
 * \param[out] pu8RespData              Buffer to receive output bytes.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the VaultIC.
 */
VLT_STS VltTestCase4(VLT_U8 u8DataLength,
    const VLT_U8 *pu8Data, 
    VLT_U8 u8RequestedDataLength,
    VLT_U8 *pu8RespData );


/** @}*/

#ifdef __cplusplus
}
#endif

#endif /*VAULTIC_API_H*/

