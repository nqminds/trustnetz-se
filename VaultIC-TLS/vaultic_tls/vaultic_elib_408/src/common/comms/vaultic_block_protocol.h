/**
* @file	   vaultic_block_protocol.h
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
* @brief Interface of block protocol.
*
* @par Description:
*/

#ifndef VAULTIC_BLOCK_PROTOCOL_H
#define VAULTIC_BLOCK_PROTOCOL_H

/*=========================================================================================================================*/
/*=========================================================================================================================*/

/**
 * @defgroup    VLT_BLOCK_PROTOCOL  Block Protocol
 * @ingroup     VLT_COMMS
 */

/**
 * @defgroup    VLT_BLOCK_PROTOCOL_API_FIELD  Field Summary
 * @ingroup     VLT_BLOCK_PROTOCOL
 */

/**
 * @defgroup    VLT_BLOCK_PROTOCOL_API_METHOD  Method Summary
 * @ingroup     VLT_BLOCK_PROTOCOL
 */

/*=========================================================================================================================*/
/*=========================================================================================================================*/

/**
 * @ingroup     VLT_BLOCK_PROTOCOL_API_FIELD
 * @{
 */

#define VLT_BLK_PTCL_ERROR_INIT_NULL_PARAM      VLT_ERROR( VLT_BLKPTCL, 0u )       /*!< @brief Bad parameters in VltBlkPtclInit() */
#define VLT_BLK_PTCL_ERROR_INVLD_COMMS_MD       VLT_ERROR( VLT_BLKPTCL, 1u )       /*!< @brief Invalid communication mode in VltBlkPtclInit() */
#define VLT_BLK_PTCL_ERROR_SND_RCV_NULL_IO      VLT_ERROR( VLT_BLKPTCL, 2u )       /*!< @brief Bad Input Output in VltBlkPtclSendReceiveData() */
#define VLT_BLK_PTCL_ERROR_MAX_RSYNC            VLT_ERROR( VLT_BLKPTCL, 3u )       /*!< @brief Maximum resynchronizations attempts */
#define VLT_BLK_PTCL_ERROR_RCV_DATA_LEN         VLT_ERROR( VLT_BLKPTCL, 4u )       /*!< @brief Invalid receive data length */
#define VLT_BLK_PTCL_ERROR_PERIPHERAL           VLT_ERROR( VLT_BLKPTCL, 5u )       /*!< @brief Peripheral Communication error */
#define VLT_BLK_PTCL_ERROR_INVLD_RESP           VLT_ERROR( VLT_BLKPTCL, 6u )       /*!< @brief Invalid data received */
#define VLT_BLK_PTCL_ERROR_INVLD_BIT_RATE       VLT_ERROR( VLT_BLKPTCL, 7u )       /*!< @brief Invalid bit rate requested */
#define VLT_BLK_PTCL_ERROR_INVLD_STATE          VLT_ERROR( VLT_BLKPTCL, 8u )       /*!< @brief Invalid state */


/** @} */

/*=========================================================================================================================*/
/*=========================================================================================================================*/

#define VLT_BLOCK_PROTOCOL_HDR_SZ (VLT_U8)0x03
#define VLT_BLOCK_PROTOCOL_TRL_SZ (VLT_U8)0x02
#define VLT_BLOCK_PROTOCOL_OH     (VLT_U16)VLT_BLOCK_PROTOCOL_HDR_SZ + VLT_BLOCK_PROTOCOL_TRL_SZ

#define BLK_PTCL_BLOCK_TYPE_OFFSET   (VLT_U8)0u
#define BLK_PTCL_LEN_MSB_OFFSET      (VLT_U8)1u
#define BLK_PTCL_LEN_LSB_OFFSET      (VLT_U8)2u

/*=========================================================================================================================*/
/*=========================================================================================================================*/

/**
 * @ingroup     VLT_BLOCK_PROTOCOL_API_METHOD
 * @{
 */

VLT_STS VltBlkPtclInit(const VLT_INIT_COMMS_PARAMS *pInitCommsParams, VLT_MEM_BLOB *pOutData, const VLT_MEM_BLOB *pInData);
VLT_STS VltBlkPtclClose(void);
VLT_STS VltBlkPtclSendReceiveData(VLT_MEM_BLOB *pOutData, VLT_MEM_BLOB *pInData);

/** @} */

#endif /* VAULTIC_BLOCK_PROTOCOL_H */
