/**
* @file	   vaultic_scp_utils.h
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
* @brief   Utils for SCP authentication.
*
* @details
*
*/

#ifndef VAULTIC___SCP__UTILS_H__
#define VAULTIC___SCP__UTILS_H__


#if ( VLT_ENABLE_SCP03 == VLT_ENABLE)

#define SCPUTILS_CMAC_RMAC_LEN       (VLT_U8)0x08
#define SCPUTILS_CENC_LEN            (VLT_U8)0x10
#define SCPUTIL_MAX_SESSION_KEY_LEN SCPXX_MAX_SESSION_KEY_LEN
#define AES_CMAC_LEN              (VLT_U8)0x10
#define MAX_MESSAGE_LEN           (VLT_U8)0xFF
#define CALC_CMAC                 (VLT_U8)0x00
#define CALC_RMAC                 (VLT_U8)0x01
#define AES_INIT_VECT_LEN         SCPXX_MAX_CMAC_LEN

#define SW_INVALID_MAC_HIGH       (VLT_U8)0x69
#define SW_INVALID_MAC_LOW        (VLT_U8)0x88

/*
* External Variables
*/
extern VLT_SEC_LEVEL_ID enSecureChannelLevel; /* Declared in vaultic_secure_channel.c */
extern VLT_AUTH_STATE enSecureChannelState; /* Declared in vaultic_secure_channel.c */

extern VLT_U8 au8CMacKey[SCPXX_MAX_SESSION_KEY_LEN]; /* Declared in vaultic_secure_channel.c */
extern VLT_U8 au8RMacKey[SCPXX_MAX_SESSION_KEY_LEN]; /* Declared in vaultic_secure_channel.c */
extern VLT_U8 au8CEncKey[SCPXX_MAX_SESSION_KEY_LEN]; /* Declared in vaultic_secure_channel.c */

extern VLT_U8 au8CMac[SCPXX_MAX_CMAC_LEN]; /* Declared in vaultic_secure_channel.c */
extern VLT_U8 au8RMac[SCPXX_MAX_RMAC_LEN]; /* Declared in vaultic_secure_channel.c */

/*
* Private Data
*/
static VLT_KEY_BLOB theCMacKey = { VLT_KEY_AES_128, AES_128_KEY_SIZE, au8CMacKey };
static VLT_KEY_BLOB theRMacKey = { VLT_KEY_AES_128, AES_128_KEY_SIZE, au8RMacKey };
static VLT_KEY_BLOB theCEncKey = { VLT_KEY_AES_128, AES_128_KEY_SIZE, au8CEncKey };

static VLT_U8 au8AesIV[AES_INIT_VECT_LEN];
#endif


VLT_STS CalculateMac(VLT_MEM_BLOB *pCmd, VLT_U8 u8MacMode);

VLT_STS EncryptCommandData( VLT_MEM_BLOB *pCmd);

VLT_STS DecryptResponseData( VLT_MEM_BLOB *pRsp);

void ResetChannel(void);

#endif /*VAULTIC___SCP__UTILS_H__*/
