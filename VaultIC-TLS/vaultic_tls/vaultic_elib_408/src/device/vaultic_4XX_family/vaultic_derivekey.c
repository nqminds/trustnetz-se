/**
* @file	   vaultic_derivekey.c
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
*/

#include "vaultic_common.h"
#if( VLT_ENABLE_API_DERIVE_KEY == VLT_ENABLE)
#include "vaultic_apdu.h"
#include "vaultic_derivekey.h"
#include "vaultic_mem.h"
#include "vaultic_utils.h"
#include "vaultic_command.h"
#include <comms/vaultic_comms.h>

/**
* Externs 
*/
extern VLT_MEM_BLOB Command;                            /* declared in vaultic_api.c */
extern VLT_MEM_BLOB Response;                           /* declared in vaultic_api.c */

VLT_STS VltDeriveKey_HashMode(VLT_U8 u8keyGroup,
	VLT_U8 u8keyIndex, const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
	VLT_U8 u8DerivatedKeyType,
	VLT_U16 u16WDerivatedKeyLen,
	const VLT_KEY_DERIVATION *pKeyDerivation,
    VLT_KEY_CONFIRM_POLICY enPolicy, 
	VLT_SW *pSW)
{
	VLT_STS status = VLT_FAIL;
	
	VLT_U16 u16MaxChunk;
	VLT_U32 u32remaining;
	VLT_U32 u32keyDerivationdataLen = 16 + pKeyDerivation->data.hashMode.u16prependLen + pKeyDerivation->data.hashMode.u16appendLen;
	VLT_U8 *pu8keyDerivationData;
	VLT_U8 *pu8Buffer;
	VLT_U32 idx = 0;
	VLT_U16 u16CommandIdx;

	//Check prepend parameter
	if (pKeyDerivation->data.hashMode.u16prependLen > 0u && pKeyDerivation->data.hashMode.pu8prependData == NULL)
	{
		return (ERR_DRV_HASH_PREPEND_NULL);
	}
	
	//Check append parameter
	if (pKeyDerivation->data.hashMode.u16appendLen > 0u && pKeyDerivation->data.hashMode.pu8appendData == NULL)
	{
		return (ERR_DRV_HASH_APPEND_NULL);
	}

	pu8keyDerivationData = (VLT_U8 *)malloc(u32keyDerivationdataLen);

	//Check memory allocation is OK
	if (pu8keyDerivationData == NULL)
	{
		return (ERR_DRV_HASH_HOST_MEMORY);
	}

	pu8keyDerivationData[idx++] = (VLT_U8)pKeyDerivation->enAlgoID;
	pu8keyDerivationData[idx++] = (VLT_U8)(pKeyDerivation->data.hashMode.enDigestId);
	pu8keyDerivationData[idx++] = (VLT_U8)(u8DerivatedKeyType);
	pu8keyDerivationData[idx++] = (VLT_U8)((u16WDerivatedKeyLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((u16WDerivatedKeyLen >> 0) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)enPolicy;
	pu8keyDerivationData[idx++] = (VLT_U8)(u8keyGroup);
	pu8keyDerivationData[idx++] = (VLT_U8)(u8keyIndex);

	/* bmPubAccess */
	pu8keyDerivationData[idx++] = pKeyFilePrivileges->u8Read;
	pu8keyDerivationData[idx++] = pKeyFilePrivileges->u8Write;
	pu8keyDerivationData[idx++] = pKeyFilePrivileges->u8Delete;
	pu8keyDerivationData[idx++] = pKeyFilePrivileges->u8Execute;

	//Optional param
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.hashMode.u16prependLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.hashMode.u16prependLen >> 0) & 0xFFu);
	if (pKeyDerivation->data.hashMode.u16prependLen > 0u)
	{
		//Prepend
		(void)host_memcpy(&pu8keyDerivationData[idx],
			pKeyDerivation->data.hashMode.pu8prependData,
			pKeyDerivation->data.hashMode.u16prependLen);
		idx += pKeyDerivation->data.hashMode.u16prependLen;
	}

	//Optional param
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.hashMode.u16appendLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.hashMode.u16appendLen >> 0) & 0xFFu);
	if (pKeyDerivation->data.hashMode.u16appendLen > 0u)
	{
		//Append
		(void)host_memcpy(&pu8keyDerivationData[idx],
			pKeyDerivation->data.hashMode.pu8appendData,
			pKeyDerivation->data.hashMode.u16appendLen);
		idx += pKeyDerivation->data.hashMode.u16appendLen;
	}

	/* We need to split the data up into chunks, the size of which the comms
	* layer tells us. */
	u16MaxChunk = VltCommsGetMaxSendSize();
	u32remaining = u32keyDerivationdataLen;
	

	//Index for browsing pu8keyDerivationData buffer
	idx = 0;

	while (0u != u32remaining)
	{
		VLT_U16 u16Chunk;
		u16CommandIdx = VLT_APDU_DATA_OFFSET;
		
		pu8Buffer = &pu8keyDerivationData[idx];

		if (u32remaining > u16MaxChunk)
		{
			u16Chunk = u16MaxChunk;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
		}
		else
		{
			u16Chunk = (VLT_U16)u32remaining;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
		}

		Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_DERIVE_KEY;
		Command.pu8Data[VLT_APDU_P1_OFFSET] = pKeyDerivation->u8SecretKeyGroup;
		Command.pu8Data[VLT_APDU_P2_OFFSET] = pKeyDerivation->u8SecretKeyIndex;
		Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

		//Copy buffer to command buffer 
		(void)host_memcpy(&(Command.pu8Data[u16CommandIdx]),
			&(pu8Buffer[0]),
			u16Chunk);

		u16CommandIdx += u16Chunk;

		u32remaining -= u16Chunk;
		idx += u16Chunk;

		/* Send the command */
		status = VltCommand(&Command, &Response, u16CommandIdx, 0, pSW);
		if (VLT_OK != status) {
			break;
		}

		/* React to the status word */
		switch (*pSW)
		{
			case VLT_STATUS_COMPLETED:
			case VLT_STATUS_SUCCESS:
				break;

			default:
				status = VLT_FAIL; /* unexpected status word */
				break;
		}
	}
	free(pu8keyDerivationData);
	return status;
}


VLT_STS VltDeriveKey_Concatenation_NIST(VLT_U8 u8keyGroup,
	VLT_U8 u8keyIndex, const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
	VLT_U8 u8DerivatedKeyType,
	VLT_U16 u16WDerivatedKeyLen,
	const VLT_KEY_DERIVATION *pKeyDerivation,
	VLT_KEY_CONFIRM_POLICY enPolicy,
	VLT_SW *pSW)
{
	VLT_STS status = VLT_FAIL;

	VLT_U16 u16MaxChunk;
	VLT_U32 u32remaining;
	VLT_U32 u32keyDerivationdataLen = 24 +
		pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen +
		pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen +
		pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen +
		pKeyDerivation->data.concatenation_SP800_56A.u16algoIdLen +
		pKeyDerivation->data.concatenation_SP800_56A.u16UInfoLen +
		pKeyDerivation->data.concatenation_SP800_56A.u16VInfoLen;
	VLT_U8 *pu8keyDerivationData;
	VLT_U8 *pu8Buffer;
	VLT_U32 idx = 0;
	VLT_U16 u16CommandIdx;

	//Check Supp Public Info parameter
	if (pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen > 0u && pKeyDerivation->data.concatenation_SP800_56A.pu8suppPubInfo == NULL)
	{
		return (ERR_DRV_CONCAT_NIST_SUPPPUB_NULL);
	}

	//Check Supp Priv Info parameter
	if (pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen > 0u && pKeyDerivation->data.concatenation_SP800_56A.pu8suppPrivInfo == NULL)
	{
		return (ERR_DRV_CONCAT_NIST_SUPPPRIV_NULL);
	}

	//Check NonceU parameter
	if (pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen > 0u && pKeyDerivation->data.concatenation_SP800_56A.pu8nonceU == NULL)
	{
		return (ERR_DRV_CONCAT_NIST_NONCEU_NULL);
	}

	//Check AlgoID parameter
	if (pKeyDerivation->data.concatenation_SP800_56A.pu8algoId == NULL)
	{
		return (ERR_DRV_CONCAT_NIST_ALGOID_NULL);
	}

	//Check PartyU parameter
	if (pKeyDerivation->data.concatenation_SP800_56A.pu8UInfo == NULL)
	{
		return (ERR_DRV_CONCAT_NIST_PARTYU_NULL);
	}

	//Check PartyV parameter
	if (pKeyDerivation->data.concatenation_SP800_56A.pu8VInfo == NULL)
	{
		return(ERR_DRV_CONCAT_NIST_PARTYV_NULL);
	}

	pu8keyDerivationData = (VLT_U8 *)malloc(u32keyDerivationdataLen);

	//Check memory allocation is OK
	if (pu8keyDerivationData == NULL)
	{
		return (ERR_DRV_CONCAT_NIST_HOST_MEMORY);
	}

	pu8keyDerivationData[idx++] = (VLT_U8)pKeyDerivation->enAlgoID;
	pu8keyDerivationData[idx++] = (VLT_U8)(pKeyDerivation->data.concatenation_SP800_56A.enDigestId);
	pu8keyDerivationData[idx++] = (VLT_U8)(u8DerivatedKeyType);
	pu8keyDerivationData[idx++] = (VLT_U8)((u16WDerivatedKeyLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((u16WDerivatedKeyLen >> 0) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)enPolicy;
	pu8keyDerivationData[idx++] = (VLT_U8)(u8keyGroup);
	pu8keyDerivationData[idx++] = (VLT_U8)(u8keyIndex);

	/* bmPubAccess */
	pu8keyDerivationData[idx++] = pKeyFilePrivileges->u8Read;
	pu8keyDerivationData[idx++] = pKeyFilePrivileges->u8Write;
	pu8keyDerivationData[idx++] = pKeyFilePrivileges->u8Delete;
	pu8keyDerivationData[idx++] = pKeyFilePrivileges->u8Execute;

	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16algoIdLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16algoIdLen >> 0) & 0xFFu);
	(void)host_memcpy(&pu8keyDerivationData[idx],
		pKeyDerivation->data.concatenation_SP800_56A.pu8algoId,
		pKeyDerivation->data.concatenation_SP800_56A.u16algoIdLen);
	idx += pKeyDerivation->data.concatenation_SP800_56A.u16algoIdLen;

	//Party U info
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16UInfoLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16UInfoLen >> 0) & 0xFFu);
	(void)host_memcpy(&pu8keyDerivationData[idx],
		pKeyDerivation->data.concatenation_SP800_56A.pu8UInfo,
		pKeyDerivation->data.concatenation_SP800_56A.u16UInfoLen);
	idx += pKeyDerivation->data.concatenation_SP800_56A.u16UInfoLen;

	//Party V info
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16VInfoLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16VInfoLen >> 0) & 0xFFu);
	(void)host_memcpy(&pu8keyDerivationData[idx],
		pKeyDerivation->data.concatenation_SP800_56A.pu8VInfo,
		pKeyDerivation->data.concatenation_SP800_56A.u16VInfoLen);
	idx += pKeyDerivation->data.concatenation_SP800_56A.u16VInfoLen;

	//Optional Party pub supp info
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen >> 0) & 0xFFu);
	if (pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen > 0u)
	{
		(void)host_memcpy(&pu8keyDerivationData[idx],
			pKeyDerivation->data.concatenation_SP800_56A.pu8suppPubInfo,
			pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen);

		idx += pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen;
	}

	//Optional Party pub supp info
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen >> 0) & 0xFFu);
	if (pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen > 0u)
	{
		(void)host_memcpy(&pu8keyDerivationData[idx],
			pKeyDerivation->data.concatenation_SP800_56A.pu8suppPrivInfo,
			pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen);

		idx += pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen;
	}
	//Optional nonceU
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen >> 0) & 0xFFu);
	if (pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen > 0u)
	{
		(void)host_memcpy(&pu8keyDerivationData[idx],
			pKeyDerivation->data.concatenation_SP800_56A.pu8nonceU,
			pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen);

		idx += pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen;
	}

	/* We need to split the data up into chunks, the size of which the comms
	* layer tells us. */
	u16MaxChunk = VltCommsGetMaxSendSize();
	u32remaining = u32keyDerivationdataLen;

	//Index for browsing pu8keyDerivationData buffer
	idx = 0;

	while (0u != u32remaining)
	{
		VLT_U16 u16Chunk;
		u16CommandIdx = VLT_APDU_DATA_OFFSET;

		pu8Buffer = &pu8keyDerivationData[idx];

		if (u32remaining > u16MaxChunk)
		{
			u16Chunk = u16MaxChunk;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
		}
		else
		{
			u16Chunk = (VLT_U16)u32remaining;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
		}

		Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_DERIVE_KEY;
		Command.pu8Data[VLT_APDU_P1_OFFSET] = pKeyDerivation->u8SecretKeyGroup;
		Command.pu8Data[VLT_APDU_P2_OFFSET] = pKeyDerivation->u8SecretKeyIndex;
		Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

		//Copy buffer to command buffer 
		(void)host_memcpy(&(Command.pu8Data[u16CommandIdx]),
			&(pu8Buffer[0]),
			u16Chunk);

		u16CommandIdx += u16Chunk;

		u32remaining -= u16Chunk;
		idx += u16Chunk;

		/* Send the command */
		status = VltCommand(&Command, &Response, u16CommandIdx, 0, pSW);
		if (VLT_OK != status) {
			break;
		}

		/* React to the status word */
		switch (*pSW)
		{
			case VLT_STATUS_COMPLETED:
			case VLT_STATUS_SUCCESS:
				break;

			default:
				status = VLT_FAIL; /* unexpected status word */
				break;
		}
	}
	free(pu8keyDerivationData);
	return status;

}

VLT_STS VltDeriveKey_X963(VLT_U8 u8keyGroup,
	VLT_U8 u8keyIndex, const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
	VLT_U8 u8DerivatedKeyType,
	VLT_U16 u16WDerivatedKeyLen,
	const VLT_KEY_DERIVATION *pKeyDerivation,
    VLT_KEY_CONFIRM_POLICY enPolicy,
	VLT_SW *pSW)
{
	VLT_STS status = VLT_FAIL;

	VLT_U16 u16MaxChunk;
	VLT_U32 u32remaining;
	VLT_U32 u32keyDerivationdataLen = 24 +
		pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen +
		pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen +
		pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen +
		pKeyDerivation->data.concatenation_SP800_56A.u16algoIdLen +
		pKeyDerivation->data.concatenation_SP800_56A.u16UInfoLen +
		pKeyDerivation->data.concatenation_SP800_56A.u16VInfoLen;
	VLT_U8 *pu8keyDerivationData;
	VLT_U8 *pu8Buffer;
	VLT_U32 idx = 0;
	VLT_U16 u16CommandIdx;

	//Check Supp Public Info parameter
	if (pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen > 0u && pKeyDerivation->data.concatenation_SP800_56A.pu8suppPubInfo == NULL)
	{
		return (ERR_DRV_X963_SUPPPUB_NULL);
	}
	
	//Check Supp Priv Info parameter
	if (pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen > 0u && pKeyDerivation->data.concatenation_SP800_56A.pu8suppPrivInfo == NULL)
	{
		return (ERR_DRV_X963_SUPPPRIV_NULL);
	}
	
	//Check NonceU parameter is not provided
	if (pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen != 0)
	{
		return (ERR_DRV_X963_NONCEU_LENGTH_NOT_NULL);
	}
	
	//Check AlgoID parameter
	if (pKeyDerivation->data.concatenation_SP800_56A.u16algoIdLen > 0u && pKeyDerivation->data.concatenation_SP800_56A.pu8algoId == NULL)
	{
		return (ERR_DRV_X963_ALGOID_NULL);
	}
	
	//Check PartyU parameter
	if (pKeyDerivation->data.concatenation_SP800_56A.u16UInfoLen > 0u && pKeyDerivation->data.concatenation_SP800_56A.pu8UInfo == NULL)
	{
		return (ERR_DRV_X963_PARTYU_NULL);
	}
	
	//Check PartyV parameter
	if (pKeyDerivation->data.concatenation_SP800_56A.u16VInfoLen > 0u && pKeyDerivation->data.concatenation_SP800_56A.pu8VInfo == NULL)
	{
		return(ERR_DRV_X963_PARTYV_NULL);
	}

	pu8keyDerivationData = (VLT_U8 *)malloc(u32keyDerivationdataLen);

	//Check memory allocation is OK
	if (pu8keyDerivationData == NULL)
	{
		return (ERR_DRV_X963_HOST_MEMORY);
	}

	pu8keyDerivationData[idx++] = (VLT_U8)pKeyDerivation->enAlgoID;
	pu8keyDerivationData[idx++] = (VLT_U8)(pKeyDerivation->data.concatenation_SP800_56A.enDigestId);
	pu8keyDerivationData[idx++] = (VLT_U8)(u8DerivatedKeyType);
	pu8keyDerivationData[idx++] = (VLT_U8)((u16WDerivatedKeyLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((u16WDerivatedKeyLen >> 0) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)enPolicy;
	pu8keyDerivationData[idx++] = (VLT_U8)(u8keyGroup);
	pu8keyDerivationData[idx++] = (VLT_U8)(u8keyIndex);

	/* bmPubAccess */
	pu8keyDerivationData[idx++] = pKeyFilePrivileges->u8Read;
	pu8keyDerivationData[idx++] = pKeyFilePrivileges->u8Write;
	pu8keyDerivationData[idx++] = pKeyFilePrivileges->u8Delete;
	pu8keyDerivationData[idx++] = pKeyFilePrivileges->u8Execute;

	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16algoIdLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16algoIdLen >> 0) & 0xFFu);
	(void)host_memcpy(&pu8keyDerivationData[idx],
		pKeyDerivation->data.concatenation_SP800_56A.pu8algoId,
		pKeyDerivation->data.concatenation_SP800_56A.u16algoIdLen);
	idx += pKeyDerivation->data.concatenation_SP800_56A.u16algoIdLen;

	//Party U info
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16UInfoLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16UInfoLen >> 0) & 0xFFu);
	(void)host_memcpy(&pu8keyDerivationData[idx],
		pKeyDerivation->data.concatenation_SP800_56A.pu8UInfo,
		pKeyDerivation->data.concatenation_SP800_56A.u16UInfoLen);
	idx += pKeyDerivation->data.concatenation_SP800_56A.u16UInfoLen;

	//Party V info
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16VInfoLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16VInfoLen >> 0) & 0xFFu);
	(void)host_memcpy(&pu8keyDerivationData[idx],
		pKeyDerivation->data.concatenation_SP800_56A.pu8VInfo,
		pKeyDerivation->data.concatenation_SP800_56A.u16VInfoLen);
	idx += pKeyDerivation->data.concatenation_SP800_56A.u16VInfoLen;

	//Optional Party pub supp info
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen >> 0) & 0xFFu);
	if (pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen > 0u)
	{
		(void)host_memcpy(&pu8keyDerivationData[idx],
			pKeyDerivation->data.concatenation_SP800_56A.pu8suppPubInfo,
			pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen);

		idx += pKeyDerivation->data.concatenation_SP800_56A.u16suppPubInfoLen;
	}

	//Optional Party pub supp info
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen >> 0) & 0xFFu);
	if (pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen > 0u)
	{
		(void)host_memcpy(&pu8keyDerivationData[idx],
			pKeyDerivation->data.concatenation_SP800_56A.pu8suppPrivInfo,
			pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen);

		idx += pKeyDerivation->data.concatenation_SP800_56A.u16suppPrivInfoLen;
	}
	//Optional nonceU
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen >> 8) & 0xFFu);
	pu8keyDerivationData[idx++] = (VLT_U8)((pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen >> 0) & 0xFFu);
	if (pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen > 0u)
	{
		(void)host_memcpy(&pu8keyDerivationData[idx],
			pKeyDerivation->data.concatenation_SP800_56A.pu8nonceU,
			pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen);

		idx += pKeyDerivation->data.concatenation_SP800_56A.u16nonceULen;
	}

	/* We need to split the data up into chunks, the size of which the comms
	* layer tells us. */
	u16MaxChunk = VltCommsGetMaxSendSize();
	u32remaining = u32keyDerivationdataLen;

	//Index for browsing pu8keyDerivationData buffer
	idx = 0;

	while (0u != u32remaining)
	{
		VLT_U16 u16Chunk;
		u16CommandIdx = VLT_APDU_DATA_OFFSET;

		pu8Buffer = &pu8keyDerivationData[idx];

		if (u32remaining > u16MaxChunk)
		{
			u16Chunk = u16MaxChunk;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
		}
		else
		{
			u16Chunk = (VLT_U16)u32remaining;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
		}

		Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_DERIVE_KEY;
		Command.pu8Data[VLT_APDU_P1_OFFSET] = pKeyDerivation->u8SecretKeyGroup;
		Command.pu8Data[VLT_APDU_P2_OFFSET] = pKeyDerivation->u8SecretKeyIndex;
		Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

		//Copy buffer to command buffer 
		(void)host_memcpy(&(Command.pu8Data[u16CommandIdx]),
			&(pu8Buffer[0]),
			u16Chunk);
		
		u16CommandIdx += u16Chunk;

		u32remaining -= u16Chunk;
		idx += u16Chunk;

		/* Send the command */
		status = VltCommand(&Command, &Response, u16CommandIdx, 0, pSW);
		if (VLT_OK != status) {
			break;
		}

		/* React to the status word */
		switch (*pSW)
		{
			case VLT_STATUS_COMPLETED:
			case VLT_STATUS_SUCCESS:
				break;

			default:
				status = VLT_FAIL; /* unexpected status word */
				break;
		}
	}
	free(pu8keyDerivationData);
	return status;
}
#endif