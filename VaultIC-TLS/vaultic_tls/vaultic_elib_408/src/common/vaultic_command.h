/**
* @file	   vaultic_command.h
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
* @brief Functions for issuing the VaultIC commands.
*
* @par Description:
* This file declares functions used to issue commands to the VaultIC.
*/

#ifndef VAULTIC_COMMAND_H
#define VAULTIC_COMMAND_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \fn VltCommand(VLT_MEM_BLOB *command, 
 *         VLT_MEM_BLOB *response,
 *         VLT_U16 u16Send, 
 *         VLT_U16 u16Require, 
 *         VLT_SW *pSW)
 *
 * \brief Issues a VaultIC command.
 *
 * \par Description
 * This issues a command to the VaultIC and deals with calling Get Response
 * where appropriate.
 *
 * \param[in]  command    Command blob.
 * \param[in]  response   Response blob.
 * \param[in]  u16Send    Amount of data to send.
 * \param[in]  u16Require Amount of data to require. Will return an error if
 *                        this amount is not returned.
 * \param[out] pSW        Status word.
 *
 * \return Status.
 */
VLT_STS VltCommand(VLT_MEM_BLOB *command, 
    VLT_MEM_BLOB *response,
    VLT_U16 u16Send, 
    VLT_U16 u16Require, 
    VLT_SW *pSW);

/**
 *
 * \brief Common implementation for Case 4 commands.
 *
 * \par Description
 * This provides a common implementation for case 4 commands.
 *
 * \param[in]  u8Ins      INS
 * \param[in]  u8P2       P2
 * \param[in]  u32SrcLen  Bytes to send.
 * \param[in]  pu8Src     Buffer to send bytes from.
 * \param[out] pu32DstLen On entry this holds the maximum size of the receive
 *                        buffer. On exit it is set to the amount of receive
 *                        buffer used.
 * \param[out] pu8Dst     Buffer to receive bytes.
 * \param[out] pSW        Status word
 *
 * \return Status.
 */
VLT_STS VltCase4(VLT_U8 u8Ins,
    VLT_U8 u8P2,
    VLT_U32 u32SrcLen,
    const VLT_U8 *pu8Src,
    VLT_U32 *pu32DstLen,
    VLT_U32 u32DstCapacity,
    VLT_U8 *pu8Dst,
    VLT_SW *pSW);

#ifdef __cplusplus
}
#endif

#endif /* VAULTIC_COMMAND_H */
