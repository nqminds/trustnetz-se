/**
* @file	   vaultic_mem.h
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
* @brief Interface to host memory functions.
* 
* @par Description:
* The VaultIC API calls these functions instead of directly calling memcpy,
* memset and memcmp to allow the customer to provide alternative
* implementations.
*/

#ifndef VAULTIC_MEM_H
#define VAULTIC_MEM_H

/**
* Copies len bytes from "src" to "dest" buffer.
* \todo To be implemented by the target platform.
*/
VLT_STS host_memcpy(VLT_U8 *dest, const VLT_U8 *src, VLT_U32 len);

/**
* Sets len bytes in "src" buffer to the specified value.
* \todo To be implemented by the target platform.
*/
VLT_STS host_memset(VLT_U8 *dest, VLT_U8 value, VLT_U32 len);

/**
* Compares len bytes between "src1" and "src2" buffers.
* \retval 0 if buffers are equal
* \retval !=0 if buffers are different
* \todo To be implemented by the target platform.
*/
VLT_U8 host_memcmp(const VLT_U8 *src1, const VLT_U8 *src2, VLT_U32 len);

/**
*  XORs  "dest" and "src" buffers and places the contents in the dest buffer.
* \retval VLT_OK if successful otherwise an appropriate error code
* \todo To be implemented by the target platform.
*/
VLT_STS host_memxor(VLT_U8 *dest, const VLT_U8 *src, VLT_U32 len);

/**
 * \fn host_memcpyxor(VLT_U8 *dest, const VLT_U8 *src, VLT_U32 len, VLT_U8 mask)
 * \brief memcpy with bytewise exclusive or.
 * \todo To be implemented by the target platform.
 */
VLT_STS host_memcpyxor(VLT_U8 *dest, const VLT_U8 *src, VLT_U32 len, VLT_U8 mask);

/**
 * Left bit shifts the "arrayIn" the number of bit positions specified by "bitsToShift".
 * \param arrayIn holds a pointer to the array that will be shifted, the shifting is 
 * done in place. 
 * \param arrayInLen the length of the array passed in. 
 * \param bitsToShift the number of bits to left shift, it cannot exceed 8.
 * \retval If successful it return VLT_OK otherwise VLT_FAIL.
 * \todo To be implemented by the target platform.
 */
VLT_STS host_lshift( VLT_U8 *arrayIn, VLT_U32 arrayInLen, VLT_U8 bitsToShift );

#endif/*VAULTIC_MEM_H*/
