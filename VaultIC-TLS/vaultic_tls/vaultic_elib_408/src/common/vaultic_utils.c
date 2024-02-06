/**
* @file	   vaultic_utils.c
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

#include "vaultic_common.h"
#include "vaultic_mem.h"
#include "vaultic_utils.h"
#include "vaultic_apdu.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

#if (HOST_CRYPTO == HOST_CRYPTO_ARM_CRYPTO_LIB)
#include "HAL_TYPEDEF.h"
#include "TbxSw_Drng.h"
#endif


#if( VLT_PLATFORM == VLT_WINDOWS )
#pragma warning(disable : 4996)
#endif


VLT_U16 VltEndianReadPU16(const VLT_U8 *p)
{
    return (((VLT_U16)p[0]) << 8) | p[1];
}

VLT_U32 VltEndianReadPU32(const VLT_U8 *p)
{
    return ((VLT_U32) p[0] << 24) |
           ((VLT_U32) p[1] << 16) |
           ((VLT_U32) p[2] <<  8) |
           ((VLT_U32) p[3] <<  0);
}

void VltEndianWritePU32(VLT_U8 *p, VLT_U32 value)
{
    *p++ = (VLT_U8)((value >> 0) & 0xFF);
    *p++ = (VLT_U8)((value >> 8) & 0xFF);
    *p++ = (VLT_U8)((value >> 16) & 0xFF);
    *p++ = (VLT_U8)((value >> 24) & 0xFF);
}

VLT_U16 NumBytesInBuffer( VLT_U16 u16Idx )
{
    return ( u16Idx - VLT_APDU_DATA_OFFSET );
}

VLT_U16 NumBufferBytesAvail( VLT_U16 u16MaxBytes, VLT_U16 u16Idx )
{
    return u16MaxBytes - NumBytesInBuffer( u16Idx );
}


void ApduBufferToHexString(VLT_U8 *value, VLT_U16 ulLen, VLT_U8 *szValue, VLT_U16 szValueSize)
{
    if (value != NULL)
    {
        VLT_U8 mess[3];
        VLT_U32 i;
        VLT_U32 maxIdx = (ulLen > szValueSize) ? szValueSize : ulLen;

        host_memset(mess, 0x00, 3);

        for (i = 0; i<maxIdx; i++)
        {
            sprintf((char*)mess, "%02X", value[i]);
            strcat((char*)szValue, (char*)mess);
        }
    }
}

/* print a buffer of hex bytes */
void PrintHexBuffer(const VLT_U8 *pu8Buffer, VLT_U32 ulTextSize)
{
    const unsigned char ucLineLength = 16;

    if (0 == pu8Buffer || ulTextSize == 0)
    {
        return ;
    }

    unsigned long numberOfLine = (ulTextSize%ucLineLength) ? ulTextSize / ucLineLength + 1 : ulTextSize / ucLineLength;
    unsigned long ctr = 0;

    printf("\n");

    for (unsigned int line = 0; line < numberOfLine; line++)
    {
        printf("[ ");
        for (unsigned int j = 0; j < ucLineLength; j++, ctr++)
        {
            if (ctr >= ulTextSize)
            {
                break;
            }
            // print each character
            printf("%2.2X ", pu8Buffer[ctr]);
        }
        // new line
        printf("]\n");
    }
    printf("\n");
}

/* print of hex bytes without any formatting*/
void PrintHex(const VLT_U8 *pu8Buffer, VLT_U32 ulTextSize)
{
    if (0 == pu8Buffer || ulTextSize == 0)
    {
        return;
    }

    for (unsigned int j = 0; j < ulTextSize; j++)
    {
        // print each character
        printf("%2.2X ", pu8Buffer[j]);
    }
}

/* Generate Random bytes */
VLT_STS GenerateRandomBytes(VLT_U8 *pBuffer, VLT_U16 numBytes)
{
    VLT_U32 i;
    VLT_U32 seed;
    static VLT_BOOL seed_done;

    /* Seed the random-number generator with current time so that
     * the numbers will be different every time we run.
     */
    if (seed_done == FALSE)
    {
        seed = (VLT_U32)time(NULL);

#if (HOST_CRYPTO == HOST_CRYPTO_ARM_CRYPTO_LIB)
        vTbxSwDrngSeed(seed);
#else
        srand(seed);
#endif
        seed_done = TRUE;
    }
    
    if (NULL == pBuffer)
        return VLT_FAIL;


    for (i = 0; i < numBytes; i++)
    {
    	do {
#if (HOST_CRYPTO == HOST_CRYPTO_ARM_CRYPTO_LIB)
    		*pBuffer = u32TbxSwDrngByte();
#else
    		*pBuffer = (VLT_U8)rand();
#endif
    	} while ( (i != 0) && (*pBuffer == *(pBuffer - 1)) );
    	pBuffer++;
    }
    return VLT_OK;
}
