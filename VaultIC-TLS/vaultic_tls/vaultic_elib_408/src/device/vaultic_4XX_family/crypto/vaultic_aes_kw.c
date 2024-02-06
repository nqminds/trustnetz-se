/**
* @file	   vaultic_aes_kw.c
*
* @note    THIS PRODUCT IS SUPPLIED FOR EVALUATION, TESTING AND/OR DEMONSTRATION PURPOSES ONLY.
*
* @note    <b>DISCLAIMER</b>
*
* @note    Copyright (C) 2021 Wisekey
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
*/

#include "vaultic_aes_kw.h"
#include "vaultic_AES.h"

#define VLT_AES_KW_ICV_LENGTH                         (VLT_U8)  0x08
/** The AES block size */
#define VLT_AES_KW_BLOCK_SIZE                                   (16)
/** The AES block size */
#define VLT_AES_KW_SEMIBLOCK_SIZE                       (VLT_AES_KW_BLOCK_SIZE / 2)
/** The AES Max data length */
#define VLT_AES_KW_INPUT_DATA_MAX_LENGTH                        800

/*! The 64-bit default integrity check value (ICV) for KW mode. */
static const VLT_U8 NIST_KW_ICV1[] = { 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6 };
/*! The 32-bit default integrity check value (ICV) for KWP mode. */
static const VLT_U8 NIST_KW_ICV2[] = { 0xA6, 0x59, 0x59, 0xA6 };

typedef struct
{
	VLT_U8 u8Initialize;

	VLT_U8 u8usePadding;

	/** \brief Chaining mode identifier */
	VLT_U8 u8Mode;

	/** \brief Padding method identifier */
	VLT_U16 u16BlockSize;

	/** \brief Length of initial vector */
	VLT_U8 u8IvLength;

	/** \brief Initial vector, unused in ECB mode */
	VLT_U8 u8Iv[VLT_AES_KW_ICV_LENGTH];

	VLT_U8 pu8Data[VLT_AES_KW_INPUT_DATA_MAX_LENGTH];

	VLT_U32 u32TotalSize;

    VLT_KEY_BLOB wrappingKey;

} VLT_AESKW_CTX;

static VLT_AESKW_CTX aesKwCtx;

VLT_STS AesKwInit(VLT_ALGO_MODE opMode, const VLT_KEY_BLOB *pKey, VLT_BOOL kwpMode)
{
    aesKwCtx.u8Mode = opMode;
	aesKwCtx.u16BlockSize = VLT_AES_KW_BLOCK_SIZE;
	//Init ICV to 0
	(void)host_memset(&aesKwCtx.u8Iv[0], 0x00, sizeof(aesKwCtx.u8Iv));

	//Init pu8Data
	(void)host_memset(&aesKwCtx.pu8Data[0], 0x00, sizeof(aesKwCtx.pu8Data));

	// Copy ICV
	if (kwpMode == FALSE)
	{
		(void)host_memcpy(&aesKwCtx.u8Iv[0], &NIST_KW_ICV1[0], sizeof(NIST_KW_ICV1));
		
		// No padding in KW padding mode
		aesKwCtx.u8usePadding = 0;
		aesKwCtx.u8IvLength = sizeof(NIST_KW_ICV1);
	}
	else
	{
		(void)host_memcpy(&aesKwCtx.u8Iv[0], &NIST_KW_ICV2[0], sizeof(NIST_KW_ICV2));

		// Padding shall be used in KWP padding mode
		aesKwCtx.u8usePadding = 1;
		aesKwCtx.u8IvLength = sizeof(NIST_KW_ICV2);
	}

	// Initialise accumulated bytes
	aesKwCtx.u32TotalSize = 0;

	// Initialize wrapping key
    aesKwCtx.wrappingKey = *pKey;
	aesKwCtx.u8Initialize = 1;
	return VLT_OK;
}

VLT_STS AesKwClose(void)
{
	aesKwCtx.u8Initialize = 0;
	AesClose();
	return VLT_OK;
}

VLT_STS AesKwBlockModeUpdate(VLT_U8 *pu8DataIn, VLT_U32 u32DataInLen,VLT_U8 *pu8OutBuffer)
{
	VLT_STS status = VLT_OK;
	VLT_U32 dataOutLen = VLT_AES_KW_BLOCK_SIZE;

	// Calculate number of semi-blocks
	VLT_U16 u16NumSemiBlocks = (aesKwCtx.u8Mode == VLT_ENCRYPT_MODE) ? (VLT_U16)(u32DataInLen / VLT_AES_KW_SEMIBLOCK_SIZE + 1)
		: (VLT_U16)(u32DataInLen / VLT_AES_KW_SEMIBLOCK_SIZE);

	// Let s = 6(n-1)
	// Calculate number of loops
	VLT_U16 u16S = (u16NumSemiBlocks == 0) ? 0
		: 6 * (u16NumSemiBlocks - 1);

	// Initialize input adresses
	VLT_U8 u8OffSetMSBIn;
	VLT_U8 *pu1CurrentMSBIn;
	VLT_U8 *pu1CurrentLSBIn;
	VLT_U8 pu8DataBuffer[VLT_AES_KW_BLOCK_SIZE];

	// We set the value t as an 8 bytes buffer
	// Increase security against fault + easier xor with "CopyXorMask" routine
	VLT_U8 pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE];
	VLT_U8 u1OffsetXor = 0x00;

	(void)host_memset(&pu8TValueXor[0], 0x00, VLT_AES_KW_SEMIBLOCK_SIZE);

	if (aesKwCtx.u8Mode == VLT_ENCRYPT_MODE)
	{
		u8OffSetMSBIn = 1;
		pu1CurrentMSBIn = pu8DataIn + u8OffSetMSBIn * VLT_AES_KW_SEMIBLOCK_SIZE;
		pu1CurrentLSBIn = pu8DataIn;
		pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 1] = 0x01;

		// If padding and small input size, it's just an AES-ECB encipher
		if (u32DataInLen <= VLT_AES_KW_SEMIBLOCK_SIZE && aesKwCtx.u8usePadding)
		{
			// Create input buffer to encipher
			(void)host_memcpy(&pu8DataBuffer[0], pu1CurrentLSBIn, VLT_AES_KW_SEMIBLOCK_SIZE);
			(void)host_memcpy(&pu8DataBuffer[VLT_AES_KW_SEMIBLOCK_SIZE],pu1CurrentMSBIn, VLT_AES_KW_SEMIBLOCK_SIZE);

			// Get AES ECB cipher
			status = AesDoFinal(&pu8DataBuffer[0], VLT_AES_KW_BLOCK_SIZE, &pu8DataIn[0], &dataOutLen);
		}

		// If no padding selected or input size > 64 bits
		else
		{
			// Main loop
			for (VLT_U16 t = 1; t < u16S + 1; t++)
			{
				// Verify the loop counter consistency
				VLT_U16 u16Counter = (pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 1]) ^ ((VLT_U16)pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 2] << 8);
				if (t != u16Counter)
				{
					status = EAESKW_ENC_LOOP_CNT;
					break;
				}

				// Create input buffer to encipher
				(void)host_memcpy(&pu8DataBuffer[0], pu1CurrentLSBIn, VLT_AES_KW_SEMIBLOCK_SIZE);
				(void)host_memcpy(&pu8DataBuffer[VLT_AES_KW_SEMIBLOCK_SIZE], pu1CurrentMSBIn, VLT_AES_KW_SEMIBLOCK_SIZE);

				// Use cipher engine
				status = AesDoFinal(&pu8DataBuffer[0], VLT_AES_KW_BLOCK_SIZE, &pu8OutBuffer[0], &dataOutLen);

				// Move output to the right buffers
				(void)host_memxor(pu8OutBuffer, pu8TValueXor, VLT_AES_KW_SEMIBLOCK_SIZE);

				(void)host_memcpy(pu1CurrentLSBIn, &pu8OutBuffer[0], VLT_AES_KW_SEMIBLOCK_SIZE);
				(void)host_memcpy(pu1CurrentMSBIn, &pu8OutBuffer[VLT_AES_KW_SEMIBLOCK_SIZE], VLT_AES_KW_SEMIBLOCK_SIZE);


				// Update the input pointers
				u8OffSetMSBIn = ((u8OffSetMSBIn + 1) % u16NumSemiBlocks == 0) ? 1
					: (u8OffSetMSBIn + 1) % u16NumSemiBlocks;
				pu1CurrentMSBIn = pu8DataIn + u8OffSetMSBIn * VLT_AES_KW_SEMIBLOCK_SIZE;

				// Increment t value for xor
				if (pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 1 - u1OffsetXor] == 0xFF)
				{
					pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 1 - u1OffsetXor] = 0x00;
					u1OffsetXor += 1;
					pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 1 - u1OffsetXor] = 0x01;
				}
				else
				{
					pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 1] += 0x01;
				}
			}
		}
	}

	else if (aesKwCtx.u8Mode == VLT_DECRYPT_MODE)
	{
		u8OffSetMSBIn = (u16S % (u16NumSemiBlocks - 1) == 0) ? (VLT_U8)(u16NumSemiBlocks - 1)
			: (VLT_U8)(u16S % (u16NumSemiBlocks - 1));
		pu1CurrentMSBIn = pu8DataIn + u8OffSetMSBIn * VLT_AES_KW_SEMIBLOCK_SIZE;
		pu1CurrentLSBIn = pu8DataIn;
		pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 1] = u16S % 0x100;
		pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 2] = (VLT_U8)((u16S - (u16S % 0x100)) >> 8);
		u1OffsetXor = (VLT_U8)(u16S / 0x100);

		// If padding and small input size, it's just an AES-ECB encipher
		if (u32DataInLen <= 2 * VLT_AES_KW_SEMIBLOCK_SIZE && aesKwCtx.u8usePadding)
		{
			// Create input buffer to encipher
			(void)host_memcpy(&pu8DataBuffer[0], pu1CurrentLSBIn, VLT_AES_KW_SEMIBLOCK_SIZE);
			(void)host_memcpy(&pu8DataBuffer[VLT_AES_KW_SEMIBLOCK_SIZE], pu1CurrentMSBIn, VLT_AES_KW_SEMIBLOCK_SIZE);

			// Get AES cipher
			status = AesDoFinal(&pu8DataBuffer[0], VLT_AES_KW_BLOCK_SIZE, &pu8DataIn[0], &dataOutLen);
		}

		// If no padding selected or input size > 64 bits
		else
		{
			// Main loop
			for (VLT_U16 t = u16S; t > 0; t--)
			{
				VLT_U16 u16Counter = (pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 1]) ^ ((VLT_U16)pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 2] << 8);

				// Verify the loop counter consistency
				if (t != (VLT_U32)u16Counter)
				{
					status = EAESKW_DEC_LOOP_CNT;
					break;
				}

				// Create input buffer to encipher
				(void)host_memxor(pu1CurrentLSBIn, pu8TValueXor, VLT_AES_KW_SEMIBLOCK_SIZE);
				(void)host_memcpy(&pu8DataBuffer[0], pu1CurrentLSBIn, VLT_AES_KW_SEMIBLOCK_SIZE);
				(void)host_memcpy(&pu8DataBuffer[VLT_AES_KW_SEMIBLOCK_SIZE], pu1CurrentMSBIn, VLT_AES_KW_SEMIBLOCK_SIZE);

				// Use cipher engine
				status = AesDoFinal(&pu8DataBuffer[0], VLT_AES_KW_BLOCK_SIZE, &pu8DataBuffer[0], &dataOutLen);

				// Move output to the right buffers
				(void)host_memcpy(pu1CurrentLSBIn,&pu8DataBuffer[0], VLT_AES_KW_SEMIBLOCK_SIZE);
				(void)host_memcpy(pu1CurrentMSBIn,&pu8DataBuffer[VLT_AES_KW_SEMIBLOCK_SIZE], VLT_AES_KW_SEMIBLOCK_SIZE);

				// Update the input pointers
				u8OffSetMSBIn = ((u8OffSetMSBIn - 1) % (u16NumSemiBlocks - 1) == 0) ? (VLT_U8)(u16NumSemiBlocks - 1)
					: (VLT_U8)((u8OffSetMSBIn - 1) % (u16NumSemiBlocks - 1));
				pu1CurrentMSBIn = pu8DataIn + u8OffSetMSBIn * VLT_AES_KW_SEMIBLOCK_SIZE;

				// Decrement t value for xor
				if (pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 1] == 0x00)
				{
					if (pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 1 - u1OffsetXor] != 0x00)
					{
						pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 1 - u1OffsetXor] -= 0x01;
						pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 1] = 0xFF;
					}
					else
					{
						u1OffsetXor -= 0x01;
					}
				}
				else
				{
					pu8TValueXor[VLT_AES_KW_SEMIBLOCK_SIZE - 1] -= 0x01;
				}
			}
		}

		// Verify we have the correct ICV
		// If no padding (i.e KW)
		if (!aesKwCtx.u8usePadding)
		{
			// We must find 0xA6A6A6A6A6A6A6A6
			for (VLT_U8 i = 0; (i < 8); i++)
			{
				if (pu8DataIn[i] != 0xA6)
				{
					status = EAESKW_DEC_ICV_INV;
				}
			}
		}

		// If padding (i.e KWP)
		else
		{
			// Only check the constant value, length is checked in DoFinal
			// We must find 0xA65959A6
			if (pu8DataIn[0] != 0xA6 ||
				pu8DataIn[1] != 0x59 ||
				pu8DataIn[2] != 0x59 ||
				pu8DataIn[3] != 0xA6)
			{
				status = EAESKW_DEC_CONST_INV;
			}
		}
	}

	// Copy the result to the output buffer
	(void)host_memcpy(&pu8OutBuffer[0], &pu8DataIn[0], u16NumSemiBlocks * VLT_AES_KW_SEMIBLOCK_SIZE);

	// Status
	return status;
}

VLT_STS AesKwDoFinal(const VLT_U8 *pDataIn, VLT_U32 DataInLen, VLT_U8 *pDataOut, VLT_U32 *pDataOutLen, VLT_U32 capacity)
{
	VLT_STS status = VLT_FAIL;

	// If the initialisation is complete
	if (aesKwCtx.u8Initialize == 1)
	{
        // Set AES key
        status = AesInit(aesKwCtx.u8Mode, &aesKwCtx.wrappingKey, NULL);
        if (status != VLT_OK) return status;

		// Update with the current input block
		status = AesKwUpdate(pDataIn, DataInLen);

		// Calculate number of semi-blocks for the output
		VLT_U16 u16NumSemiBlocks = (aesKwCtx.u8Mode == VLT_ENCRYPT_MODE) ? (VLT_U16)(aesKwCtx.u32TotalSize / VLT_AES_KW_SEMIBLOCK_SIZE + 1)
			: (VLT_U16)(aesKwCtx.u32TotalSize / VLT_AES_KW_SEMIBLOCK_SIZE);

		// If all ok
		if (VLT_OK == status)
		{
			// If encrypting we add padding to the accumulated block and update it
			if (aesKwCtx.u8Mode == VLT_ENCRYPT_MODE)
			{
				//Set ICV
				(void)host_memcpy(&aesKwCtx.pu8Data[0], &aesKwCtx.u8Iv[0], aesKwCtx.u8IvLength);

				// Convert to u2, anyway this length can't exceed 1024 bytes
				VLT_U16 u16TotalSize = (VLT_U16)aesKwCtx.u32TotalSize;

				// Padding requires the total length of the input
				if (aesKwCtx.u8usePadding)
				{
					aesKwCtx.pu8Data[aesKwCtx.u8IvLength + 2] = (u16TotalSize >> 8) & 0xff;
					aesKwCtx.pu8Data[aesKwCtx.u8IvLength + 3] = u16TotalSize & 0xff;
				}

				VLT_U8 u8NbBytesToAdd = 0u;

				// Add padding
				if (aesKwCtx.u32TotalSize > 0)
				{
					if (aesKwCtx.u32TotalSize % VLT_AES_KW_SEMIBLOCK_SIZE != 0)
					{
						u8NbBytesToAdd = VLT_AES_KW_SEMIBLOCK_SIZE - aesKwCtx.u32TotalSize % VLT_AES_KW_SEMIBLOCK_SIZE;
					}
					else
					{
						u8NbBytesToAdd = 0;
					}
				}
				else
				{
					u8NbBytesToAdd = VLT_AES_KW_SEMIBLOCK_SIZE;
				}

				if ((u8NbBytesToAdd + aesKwCtx.u32TotalSize) <= VLT_AES_KW_INPUT_DATA_MAX_LENGTH)
				{
					(void)host_memset(&aesKwCtx.pu8Data[aesKwCtx.u32TotalSize + aesKwCtx.u8IvLength + 4], 0x00, u8NbBytesToAdd);
					aesKwCtx.u32TotalSize += u8NbBytesToAdd;
				}
				else
				{
					status = EAESKW_PADDING_LEN;
				}

				// If all ok
				if (VLT_OK == status)
				{
					// Check length is >= 64 bits and also a multiple of this size
					if ((aesKwCtx.u32TotalSize >= VLT_AES_KW_SEMIBLOCK_SIZE) && ((aesKwCtx.u32TotalSize % VLT_AES_KW_SEMIBLOCK_SIZE) == 0))
					{
                        *pDataOutLen = aesKwCtx.u32TotalSize + VLT_AES_KW_SEMIBLOCK_SIZE;
                        if (*pDataOutLen > capacity) return EAESKW_DATA_OVERFLOW;
                        
                        // Do final block
						status = AesKwBlockModeUpdate(&aesKwCtx.pu8Data[0], aesKwCtx.u32TotalSize, pDataOut);

					}
					else
					{
						status = EAESKW_ENC_LEN_INVLD;
					}
				}
			}

			// If decrypting	
			else
			{
				// Have to have decrypted at least the block size and in multiples of it before unpadding
				if ((aesKwCtx.u32TotalSize >= VLT_AES_KW_BLOCK_SIZE) && ((aesKwCtx.u32TotalSize % VLT_AES_KW_SEMIBLOCK_SIZE) == 0))
				{
					//we have the final ciphertext block in the accumulating buffer so decipher it
					status = AesKwBlockModeUpdate(&aesKwCtx.pu8Data[0], aesKwCtx.u32TotalSize, &aesKwCtx.pu8Data[0]);

					if (VLT_OK == status)
					{
						// Remove Padding from the plaintext output
						if (aesKwCtx.u8usePadding)
						{
							// Get payload size (without padding)
							VLT_U16 u16Plen = aesKwCtx.pu8Data[7] ^ ((VLT_U16)aesKwCtx.pu8Data[6]) << 8;
							VLT_U8 u8PadLen = (VLT_U8)(8 * (u16NumSemiBlocks - 1) - u16Plen);

							// Reject a weird padding length
							if (u8PadLen > 7)
								status = EAESKW_DEC_PADDING_INVLD;

							// Update output size
							*pDataOutLen = u16Plen;

                            if (*pDataOutLen > capacity) return EAESKW_DATA_OVERFLOW;

							if (VLT_OK == status)
							{
								/* REMARK: + 4 for encoding real key length */
								(void)host_memcpy(&pDataOut[0], &aesKwCtx.pu8Data[aesKwCtx.u8IvLength + 4], *pDataOutLen);
							}
						}
						else
						{
							*pDataOutLen = 8 * (u16NumSemiBlocks - 1);
                            if (*pDataOutLen > capacity) return EAESKW_DATA_OVERFLOW;
							(void)host_memcpy(&pDataOut[0], &aesKwCtx.pu8Data[aesKwCtx.u8IvLength], *pDataOutLen);
						}
					}
				}
				else
				{
					status = EAESKW_DEC_DATA_LEN_INV;
				}
			}
		}
	}

	// Status
	return status;
}

VLT_STS AesKwUpdate(const VLT_U8 *pDataIn, VLT_U32 DataInLen)
{
	VLT_STS status = VLT_FAIL;

	// Don't process a zero length block here
	if (DataInLen > 0)
	{
		// Reject a length of more than the specified limit
		VLT_U16 u16Tmp = (VLT_U16)(aesKwCtx.u32TotalSize + DataInLen);
		if (u16Tmp > VLT_AES_KW_INPUT_DATA_MAX_LENGTH)
		{
			status = EAESKW_DATA_LEN_TOO_LONG;
		}

		else
		{
			// Copy required bytes into accumulating buffer
			if (aesKwCtx.u8Mode == VLT_ENCRYPT_MODE)
			{
				if (aesKwCtx.u8usePadding)
				{
					(void)host_memcpy(&aesKwCtx.pu8Data[aesKwCtx.u8IvLength + 4 + aesKwCtx.u32TotalSize], &pDataIn[0], DataInLen);

				}
				else
				{
					(void)host_memcpy(&aesKwCtx.pu8Data[aesKwCtx.u8IvLength + aesKwCtx.u32TotalSize], &pDataIn[0], DataInLen);
				}
			}

			else
			{
				(void)host_memcpy(&aesKwCtx.pu8Data[0 + aesKwCtx.u32TotalSize], &pDataIn[0], DataInLen);
			}

			// Update total length
			aesKwCtx.u32TotalSize += DataInLen;

			status = VLT_OK;
		}
	}
	return status;
}


VLT_U16 AesKwGetBlockSize(void)
{
	return VLT_AES_KW_BLOCK_SIZE;
}
