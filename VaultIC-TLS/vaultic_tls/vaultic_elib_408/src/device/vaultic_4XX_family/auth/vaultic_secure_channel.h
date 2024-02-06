/**
* @file	   vaultic_secure_channel.h
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
* @brief   Interface to secure channel.
*
* @details Interface to secure channel.
*/

#ifndef VAULTIC_SECURE_CHANNEL_H
#define VAULTIC_SECURE_CHANNEL_H

/*
* Defines
*/

#define SECURE_CHANNEL_SEND       (VLT_U8)0x00
#define SECURE_CHANNEL_RECEIVE    (VLT_U8)0x01

/**
 *
 * \brief Initialise the Secure Channel.
 *
 * \return Status.
 */
VLT_STS VltScpInit( VLT_USER_ID enUserID,
    VLT_ROLE_ID enRoleID, 
    VLT_SEC_LEVEL_ID enChannelLevel,
    const VLT_KEY_BLOB *pSMac, 
    const VLT_KEY_BLOB *pSEnc );

/**
 * \fn VltScpClose( void )
 *
 * \brief Close the Secure Channel.
 *
 * \return Status.
 */
VLT_STS VltScpClose( void );

/**
 * \fn VltScpGetState( VLT_U8 *pu8State )
 *
 * \brief Returns the state of the Secure Channel.
 *
 * \return state of the Secure Channel.
 */
VLT_STS VltScpGetState(VLT_AUTH_STATE *enState);

/**
 * \fn VltScpWrap( VLT_MEM_BLOB *pCmd )
 *
 * \brief Wrap the command being sent to the VaultIC.
 *
 * \return Status.
 */
VLT_STS VltScpWrap( VLT_MEM_BLOB *pCmd );

/**
 * \fn VltScpUnwrap( VLT_MEM_BLOB *pRsp )
 *
 * \brief Unwrap the response from the VaultIC.
 *
 * \return Status.
 */
VLT_STS VltScpUnwrap( VLT_MEM_BLOB *pRsp );

/**
 * \fn VltScpGetChannelOverhead( VLT_U8 u8Mode, VLT_U8 *pu8Overhead )
 *
 * \brief Get the number of bytes required by the currently active channel.
 *
 * \return Status.
 */
VLT_STS VltScpGetChannelOverhead( VLT_U8 u8Mode, VLT_U8 *pu8Overhead );

/**
 * \fn VltScpGetChannelSession( VLT_SECURE_SESSION_STATE *pState )
 *
 * \brief Get full state of the secure channel.
 *
 * \return status
 */
VLT_STS VltScpGetChannelSession( VLT_SECURE_SESSION_STATE *pState );

/**
 * \fn VltScpSetChannelSession( VLT_SECURE_SESSION_STATE *pState )
 *
 * \brief Set full state of the secure channel.
 *
 * \return status
 */
VLT_STS VltScpSetChannelSession( const VLT_SECURE_SESSION_STATE *pState );

#endif /*VAULTIC_SECURE_CHANNEL_H*/
