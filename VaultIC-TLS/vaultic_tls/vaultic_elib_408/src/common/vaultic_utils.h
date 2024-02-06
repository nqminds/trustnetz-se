/**
* @file	   vaultic_utils.h
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
*/

#ifndef VAULTIC_UTILS_H
#define VAULTIC_UTILS_H

#include <stdlib.h>

/**
 * \brief Reads a big endian U16 from the specified pointer.
 */
VLT_U16 VltEndianReadPU16(const VLT_U8 *p);

/**
 * \brief Reads a big endian U32 from the specified pointer.
 */
VLT_U32 VltEndianReadPU32(const VLT_U8 *p);

/**
 * \brief Convert data from the specified pointer to a big endian
 */
void VltEndianWritePU32(VLT_U8 *p, VLT_U32 value);


/**
 * \macro NELEMS
 * \brief Returns the number of elements in an array.
 */
#define NELEMS(array) ((VLT_U32)(sizeof(array) / sizeof(array[0])))


/**
 * \macro WRAPPED_BYTE
 * \brief To fit in a byte, lengths of 256 must be encoded as zero.
 */
#define WRAPPED_BYTE(b) ((VLT_U8) ((b) & 0xFFu))

/**
 * \macro UNWRAPPED_BYTE
 * \brief Reverses the action of WRAPPED_BYTE.
 */
#define UNWRAPPED_BYTE(b) (((b) != 0) ? (b) : 0x100)


/**
 * \macro LIN
 * \brief No-op macro for source level documentation purposes. Signifies that
 * the P3 argument is LIN.
 */
#define LIN(b) (b)

/**
 * \macro LEXP
 * \brief No-op macro for source level documentation purposes. Signifies that
 * the P3 argument is LEXP.
 */
#define LEXP(b) (b)

/**
 * \macro FREE
 * \brief Release properly a buffer
 */
#define FREE(a) if (a!= NULL) {free(a); a= NULL;}

VLT_U16 NumBytesInBuffer( VLT_U16 u16Idx );

VLT_U16 NumBufferBytesAvail( VLT_U16 u16MaxBytes, VLT_U16 u16Idx );

void ApduBufferToHexString(VLT_U8 *value, VLT_U16 ulLen, VLT_U8 *szValue, VLT_U16 szValueSize);

/**
 * \function GenerateRandomBytes
 */
VLT_STS GenerateRandomBytes(VLT_U8 *pBuffer, VLT_U16 numBytes);

/**
 * \function PrintHexBuffer
 */
void PrintHexBuffer(const VLT_U8 *pu8Buffer, VLT_U32 ulTextSize);

void PrintHex(const VLT_U8 *pu8Buffer, VLT_U32 ulTextSize);

#ifndef VALID_HOOKS
#define logger_print(...) printf(__VA_ARGS__)
#else
int logger_print(const char* msg, ...);
#endif

#endif /*VAULTIC_UTILS_H*/

