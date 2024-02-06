/**
* @file	   vaultic_peripheral.h
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
* @brief Peripheral interface for the VaultIC API.
*
*/

#ifndef VAULTIC_PERIPHERAL_H
#define VAULTIC_PERIPHERAL_H

#include "vaultic_common.h"

/**
 * @brief           Definition of pointer on the Device initialization function
 *
 * @param[in]       pInitCommsParams    Protocol initialization parameters
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          A status
 */

typedef VLT_STS (*pfnVltPtclInit)( const VLT_INIT_COMMS_PARAMS *pInitCommsParams );

/**
 * @brief           Definition of pointer on the Device close function
 *
 * @param[in]       -
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          A status
 */
typedef VLT_STS (*pfnVltPtclClose)( void );

/**
 * @brief           Definition of pointer on the device IO control function
 *
 * @param[in]       u32Id           The action to perform
 * @param[in]       pConfigData     The data to use (if needed)
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          A status
 */
typedef VLT_STS (*pfnVltPeripheralIoctl)( VLT_U32 u32Id, const void* pConfigData );
typedef VLT_STS (*pfnVltPeripheralSendData)( const VLT_MEM_BLOB *pOutData);

/**
 * @brief           Definition of pointer on the device receive function
 *
 * @param[in]       pInData         Pointer on where store the received data
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          A status
 */
typedef VLT_STS (*pfnVltPeripheralReceiveData)( VLT_MEM_BLOB* pInData );

/**
 * @brief Structure of function pointers used by the comms peripherals.
 */
typedef struct _VltPeripheral
{
    pfnVltPtclInit PeripheralInit;                          /*!< @brief Pointer on the initialization function */
    pfnVltPtclClose PeripheralClose;                        /*!< @brief Pointer on the close function */
    pfnVltPeripheralIoctl PeripheralIoctl;                  /*!< @brief Pointer on the IO control function */
    pfnVltPeripheralSendData PeripheralSendData;            /*!< @brief Pointer on the send function */
    pfnVltPeripheralReceiveData PeripheralReceiveData;      /*!< @brief Pointer on the receive function */
} VltPeripheral;

/**
 * Defines
 */
#define VLT_AWAIT_DATA        (VLT_U32)0x00000000
#define VLT_RESET_PROTOCOL    (VLT_U32)0x00000001
#define VLT_UPDATE_BITRATE    (VLT_U32)0x00000002
#define VLT_POWER_OFF         (VLT_U32)0x00000003
#define VLT_POWER_ON          (VLT_U32)0x00000004

#endif /*VAULTIC_PERIPHERAL_H*/
