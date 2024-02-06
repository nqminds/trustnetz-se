/**
* @file	   vaultic_putkey_aux.c
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

#include "vaultic_apdu.h"
#include "vaultic_common.h"
#if( VLT_ENABLE_API_PUT_KEY == VLT_ENABLE ) 
#include "vaultic_api.h"
#include <comms/vaultic_comms.h>
#include "vaultic_utils.h"
#include "vaultic_mem.h"
#include "vaultic_cipher.h"
#include <tests/vaultic_cipher_tests.h>
#include "vaultic_crc16.h"
#include "vaultic_command.h"
#include "vaultic_putkey_aux.h"


/* VltPutKey aux functions
* =======================
*
* The VltPutKey aux functions marshal the input key data into a fixed-size
* command buffer, packing the buffer so that it is completely filled where
* possible then issuing the command using VltCommand.
*
* The cases listed earlier in the source are 'simple' and involve packing only
* fixed-size data. The later cases, especially the private key cases, are more
* complex and must cope with stopping and re-starting the packing of data
* within individual fields. 
*
* The routines are mostly very similar and could be merged together to save
* space at the expense of making the simple cases use the more generic code.
*
* State variables are maintained which tell us which field we're processing and
* the offset within that field. The routines are structured so that when we run
* out of space packing a buffer we send the buffer then immediately resume
* packing the next input byte. This keeps the buffers as full as possible,
* minimising the number of chunks/commands which need sending.
*
* Common variables:
*
* u16KeyObjLen is the length of the key object.
* u16Remaining holds the total number of bytes remaining to be sent. This does
*              not include the size of any APDUs.
* u16MaxChunk  is the largest number of bytes we can dispatch in a single
*              VltCommand call.
* u16Chunk     is the number of bytes we will be sending this iteration.
* field        records which field of the input structure we're packing.
* u16Offset    records the offset within that field.
* pu8Data      points to the next available free byte in the output buffer.
*
* Chaining
* --------
* While u16Remaining exceeds u16MaxChunk there's still data to be sent. In this
* case we set the chaining flag. Otherwise we leave it clear.
*
* APDU
* ----
* To reduce buffer overhead the comms layer may use a single buffer for both
* input and output buffers. For this reason we must re-build the APDU on every
* iteration, even though it's always the same.
*
* Field Packing
* -------------
* Fields are packed either by outputting the individual bytes to ensure correct
* endian ordering (all VaultIC data uses big endian ordering) or by copying the
* raw data across directly, in the case of arrays.
*
* Fields of the same size within a structure are treated identically by the
* code.
*
* If the field requires key masking then the host_memcpyxor function is used.
*
* When the end of the field is met, the field variable is incremented which
* causes the code to move onto the next field. The outer while loop ensures
* that data continues to be packed as long as there is space in the buffer.
*
* CRCs
* ----
* The final two bytes of every put key data is the CRC of the plaintext key
* object. This isn't computed for the entire input data, but just the key
* object.
*
* Variables:
*
* u16Crc       holds the current CRC.
*
* The CRC is computed on the data prior to it being sent. When there are only
*  two bytes remaining to be sent the CRC data is written out.
*
* Limitations
* -----------
* Two byte fields can't be resumed (if there's only one byte free in the buffer
* it won't use that then later come back and write the second) as it's not
* worth the effort. In these cases the outer loop ensures that the loop is
* terminated early if there aren't two bytes available.
*/

/**
* Externs 
*/
extern VLT_MEM_BLOB Command;                            /* declared in vaultic_api.c */
extern VLT_MEM_BLOB Response;                           /* declared in vaultic_api.c */
extern VLT_U16 idx;                                     /* declared in vaultic_api.c */

#if( ( VLT_ENABLE_KEY_SECRET == VLT_ENABLE ) ||\
	( VLT_ENABLE_KEY_HOTP == VLT_ENABLE ) ||\
	( VLT_ENABLE_KEY_TOTP == VLT_ENABLE ) ||\
	( VLT_ENABLE_KEY_RSA == VLT_ENABLE ) ||\
	( VLT_ENABLE_KEY_ECDSA == VLT_ENABLE ) ||\
	( VLT_ENABLE_KEY_IDENTIFIER == VLT_ENABLE ) )
static VLT_U16 crcStartPos;
#endif

#if (VLT_ENABLE_PUT_KEY_RAW == VLT_ENABLE )
VLT_STS VltPutKey_Raw( VLT_U8 u8KeyGroup,
					  VLT_U8 u8KeyIndex,
					  const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
					  const VLT_KEY_OBJ_RAW* pKeyObj,
					  VLT_SW *pSW )
{
	VLT_STS status = VLT_FAIL;
	VLT_U16 u16Remaining;
	VLT_U16 u16MaxChunk;
	VLT_U16 u16Offset = 0;
	VLT_U16 u16KeyBytesRemaining;

	/*
	* Validate all input parameters.
	*/
	if( ( NULL == pKeyFilePrivileges ) ||
		( NULL == pKeyObj ) ||
		( NULL == pSW ) ||
		( NULL == pKeyObj->pu8KeyObject ) ||
		(NULL == pKeyObj->pu16ClearKeyObjectLen))
	{
		return ( EPKRAWNULLPARA );
	}

	if ( TRUE == pKeyObj->isEncryptedKey && NULL == pKeyObj->pu16EncKeyObjectLen)
	{
		return ( EPKRAWNULLPARA );
	}

	/* We need to split the data up into chunks, the size of which the comms
	* layer tells us. */
	u16MaxChunk = VltCommsGetMaxSendSize();

	if ( TRUE == pKeyObj->isEncryptedKey )
	{
		u16Remaining = VLT_PUTKEY_FIXED_DATA_LENGTH + *pKeyObj->pu16EncKeyObjectLen;
#if(VLT_ENABLE_NO_WRAPKEY_CRC == VLT_ENABLE)
        u16Remaining -= NUM_CRC_BYTES; // No CRC if wrapping key on VaultIC408
#endif        
		u16KeyBytesRemaining = *pKeyObj->pu16EncKeyObjectLen;
	}
	else
	{
		u16Remaining = VLT_PUTKEY_FIXED_DATA_LENGTH + *pKeyObj->pu16ClearKeyObjectLen;
		u16KeyBytesRemaining = *pKeyObj->pu16ClearKeyObjectLen;
	}

	while( 0u != u16Remaining )
	{
		VLT_U16 u16Chunk;
		VLT_U16 u16PartialKeyLen;
		VLT_U16 u16Avail;

		/* Build APDU. We have to do this on every iteration as the output
		* of the previous iteration will have overwritten it (assuming a
		* shared buffer). */
		idx = VLT_APDU_DATA_OFFSET;

		if(u16Remaining > u16MaxChunk)
		{
			u16Chunk = u16MaxChunk;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
		}
		else
		{
			u16Chunk = u16Remaining;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL; 
		}
		Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_PUT_KEY;
		Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
		Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
		Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

		/* Build Data In */
		if(u16Offset == 0u) /* building the first part of the data */
		{
			/* bmAccess */
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

			/* wKeyObjectLength */
			Command.pu8Data[idx++] = 
				(VLT_U8)( (*pKeyObj->pu16ClearKeyObjectLen >> 8 ) & 0xFFu );

			Command.pu8Data[idx++] = 
				(VLT_U8)( (*pKeyObj->pu16ClearKeyObjectLen >> 0 ) & 0xFFu );
		}


		/* How much space is available for the key data? */
		u16Avail = NumBufferBytesAvail( u16Chunk, idx );

		if(u16KeyBytesRemaining > u16Avail)
		{
			u16PartialKeyLen = u16Avail;
		}
		else
		{
			u16PartialKeyLen = u16KeyBytesRemaining;
		}


		/* If 'u16Offset' has maxed out then u16PartialKeyLen could now be zero.
		* We need to cope with such cases as it's possible that the key data
		* will finish on an exact chunk boundary, leaving only the CRC to be
		* sent in its own chunk. */
		(void)host_memcpy( &(Command.pu8Data[idx]),
			&( (pKeyObj->pu8KeyObject[u16Offset]) ), 
			u16PartialKeyLen  );

		idx += u16PartialKeyLen;

		/* If the remaining data is too big we'll need to send it in multiple
		* chunks. */
		if( 0u == u16Offset )
		{
			u16KeyBytesRemaining -= u16Avail; /* bytes of key remaining to be sent. */
		}
		else
		{
			u16KeyBytesRemaining -= NumBytesInBuffer( idx );
		}

		/* Decrement the remaining number of bytes to be sent. */
		u16Remaining -= NumBytesInBuffer( idx );

		/* Update the offset into the key*/
		u16Offset += u16PartialKeyLen;

        /* It's entirely possible that we will fall through the above code with
        * 'u16Remaining' at zero and enter here where we construct a data block
        * only containing the wCRC data. */

        /* We need two bytes free in the buffer for the wCRC field. */
        if ((NUM_CRC_BYTES == u16Remaining) &&
            (NumBufferBytesAvail(u16Chunk, idx) >= NUM_CRC_BYTES))
        {
#if(VLT_ENABLE_NO_WRAPKEY_CRC == VLT_ENABLE)
            if (TRUE != pKeyObj->isEncryptedKey)
#endif
            {
                Command.pu8Data[idx++] = (VLT_U8)((pKeyObj->u16Crc >> 8) & 0xFFu);
                Command.pu8Data[idx++] = (VLT_U8)((pKeyObj->u16Crc >> 0) & 0xFFu);
            }
            u16Remaining -= NUM_CRC_BYTES;
        }

		/* Send the command */
		status = VltCommand( &Command, &Response, idx, 0, pSW );
		if(VLT_OK != status)
		{
			return status;
		}

		/* React to the status word */
		switch (*pSW)
		{
		case VLT_STATUS_COMPLETED:
		case VLT_STATUS_SUCCESS:
			break;

		default:
			return VLT_OK; /* unexpected status word */
			break; //For MISRA compliancy
		}
	}

	return ( status );
}
#endif /*(VLT_ENABLE_PUT_KEY_RAW == VLT_ENABLE )*/

#if( VLT_ENABLE_KEY_SECRET == VLT_ENABLE )
#if (VLT_ENABLE_PUT_KEY_SECRET == VLT_ENABLE )
VLT_STS VltPutKey_Secret(VLT_U8 u8KeyGroup,
						 VLT_U8 u8KeyIndex,
						 const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
						 VLT_U8 u8KeyID,
						 const VLT_KEY_OBJ_SECRET* pKeyObj,
						 VLT_SW *pSW)
{
	VLT_STS status = VLT_FAIL;
	VLT_U16 u16MaxChunk;
	VLT_U16 u16KeyObjLen;
	VLT_U16 u16Offset;
	VLT_U16 u16Remaining;
	VLT_U16 u16KeyBytesRemaining;
	VLT_U16 u16Crc = VLT_CRC16_CCITT_INIT_0s;

	/*
	* Validate all input parameters.
	*/
	if ( ( NULL == pKeyFilePrivileges ) ||
		( NULL == pKeyObj ) ||
		( NULL == pSW ) ||
		( NULL == pKeyObj->pu8Key ) ||
		( 0u == pKeyObj->u16KeyLength ) )
	{
		return ( ERKSECNULLPARA );
	}


	/* We need to split the data up into chunks, the size of which the comms
	* layer tells us. */
	u16MaxChunk = VltCommsGetMaxSendSize();

	/* Work out the size of abKeyObject. */    
	u16KeyObjLen = VLT_SECRET_KEY_STATIC_PART_LENGTH + pKeyObj->u16KeyLength;

	/* The 'u16Offset' variable controls the offset within that field when we
	* are marshalling variable-sized buffers. */
	u16Offset = 0; /* 0 => first chunk */

	u16Remaining = VLT_PUTKEY_FIXED_DATA_LENGTH + u16KeyObjLen;
	u16KeyBytesRemaining = pKeyObj->u16KeyLength;

	while( 0u != u16Remaining )
	{
		VLT_U16 u16Chunk;
		VLT_U16 u16PartialKeyLen;
		VLT_U16 u16Avail;

		/* Build APDU. We have to do this on every iteration as the output
		* of the previous iteration will have overwritten it (assuming a
		* shared buffer). */
		idx = VLT_APDU_DATA_OFFSET;

		if(u16Remaining > u16MaxChunk)
		{
			u16Chunk = u16MaxChunk;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
		}
		else
		{
			u16Chunk = u16Remaining;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL; 
		}
		Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_PUT_KEY;
		Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
		Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
		Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

		/* Build Data In */
		if(u16Offset == 0u) /* building the first part of the data */
		{
			/* bmAccess */
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

			/* wKeyObjectLength */
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 0) & 0xFFu);
		}

		/* abKeyObject data */
		crcStartPos = idx;

		/* 'field' is not used in this case as there's only one variable-length
		* field at the end of the structure. We make the assumption that the
		* initial parts (total: 4 bytes) will all fit in the first buffer we
		* receive. */

		if(u16Offset == 0u) /* if we're building the first, fixed, part */
		{
			/* bKeyID */
			Command.pu8Data[idx++] = u8KeyID;

			/* bMask */
			Command.pu8Data[idx++] = pKeyObj->u8Mask; 

			/* wKLen */
			Command.pu8Data[idx++] = 
				(VLT_U8)( ( pKeyObj->u16KeyLength >> 8 ) & 0xFFu ); 

			Command.pu8Data[idx++] = 
				(VLT_U8)( ( pKeyObj->u16KeyLength >> 0 ) & 0xFFu );
		}

		/* How much space is available for the key data? */
		u16Avail = NumBufferBytesAvail( u16Chunk, idx );

		if(u16KeyBytesRemaining > u16Avail)
		{
			u16PartialKeyLen = u16Avail;
		}
		else
		{
			u16PartialKeyLen = u16KeyBytesRemaining;
		}

		/* If 'u16Offset' has maxed out then u16PartialKeyLen could now be zero.
		* We need to cope with such cases as it's possible that the key data
		* will finish on an exact chunk boundary, leaving only the CRC to be
		* sent in its own chunk. */

		/*
		* No need to check the return type as pointer has been validated
		*/
		(void)host_memcpyxor( &(Command.pu8Data[idx]),
			&( (pKeyObj->pu8Key[u16Offset]) ), 
			u16PartialKeyLen,
			pKeyObj->u8Mask );

		idx += u16PartialKeyLen;

		/* If the remaining data is too big we'll need to send it in multiple
		* chunks. */
		if( 0u == u16Offset )
		{
			u16KeyBytesRemaining -= u16Avail; /* bytes of key remaining to be sent. */
		}
		else
		{
			u16KeyBytesRemaining -= NumBytesInBuffer( idx );
		}

		/* Decrement the remaining number of bytes to be sent. */
		u16Remaining -= NumBytesInBuffer( idx );

		/* Update the offset into the key*/
		u16Offset += u16PartialKeyLen;

		/* Update the CRC-16 with the (partial) data. */
		u16Crc = VltCrc16Block( u16Crc, 
			&(Command.pu8Data[crcStartPos]), 
			( idx - crcStartPos ) );

		/* Emit the CRC-16 once there's no data remaining. */

		/* It's entirely possible that we will fall through the above code with
		* 'u16Remaining' at zero and enter here where we construct a data block
		* only containing the wCRC data. */

		/* We need two bytes free in the buffer for the wCRC field. */
		if( ( NUM_CRC_BYTES == u16Remaining ) &&
			( NumBufferBytesAvail( u16Chunk, idx ) >= NUM_CRC_BYTES ) )
		{
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 0) & 0xFFu);
			u16Remaining -= NUM_CRC_BYTES;
		}

		/* Send the command */
		status = VltCommand( &Command, &Response, idx, 0, pSW );
		if(VLT_OK != status)
		{
			return status;
		}

		/* React to the status word */
		switch (*pSW)
		{
		case VLT_STATUS_COMPLETED:
		case VLT_STATUS_SUCCESS:
			break;

		default:
			return VLT_OK; /* unexpected status word */
			break; //For MISRA compliancy
		}
	}

	return status;
}
#endif /*(VLT_ENABLE_PUT_KEY_SECRET == VLT_ENABLE )*/
#endif /* ( VLT_ENABLE_KEY_SECRET == VLT_ENABLE ) */

#if( VLT_ENABLE_KEY_HOTP == VLT_ENABLE )
VLT_STS VltPutKey_Hotp(VLT_U8 u8KeyGroup,
					   VLT_U8 u8KeyIndex,
					   const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
					   VLT_U8 u8KeyID,
					   const VLT_KEY_OBJ_HOTP* pKeyObj,
					   VLT_SW *pSW)
{
	VLT_STS       status;
	VLT_U16       u16KeyObjLen;
	VLT_U16       u16Crc = VLT_CRC16_CCITT_INIT_0s;

	/*
	* Validate all input parameters.
	*/     
	if ( ( NULL == pKeyFilePrivileges ) ||
		( NULL == pKeyObj ) ||
		( NULL == pSW ) ||
		( NULL == pKeyObj->pu8Key ) ||
		( NULL == pKeyObj->pu8MovingFactor ) )
	{
		return ( EPKHPNULLPARA );
	}
    
	/* Work out the size of abKeyObject. */
	u16KeyObjLen = pKeyObj->u16KeyLength + VLT_HOTP_KEY_STATIC_PART_LENGTH;

	/* Build APDU */
	idx = VLT_APDU_DATA_OFFSET;

	Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL; 
	Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_PUT_KEY;
	Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
	Command.pu8Data[VLT_APDU_P2_OFFSET]= u8KeyIndex;
	Command.pu8Data[VLT_APDU_P3_OFFSET] =
		(VLT_U8) LIN(VLT_PUTKEY_FIXED_DATA_LENGTH + u16KeyObjLen);

	/* Build Data In */

	/* bmAccess */
	Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
	Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
	Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
	Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

	/* wKeyObjectLength */
	Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 8) & 0xFFu);
	Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 0) & 0xFFu);

	/* abKeyObject data */
	crcStartPos = idx;

	/* bKeyID */
	Command.pu8Data[idx++] = u8KeyID;

	/* bMask */
	Command.pu8Data[idx++] = pKeyObj->u8Mask; 

	/* wKeyLength */
	Command.pu8Data[idx++] = (VLT_U8)( ( pKeyObj->u16KeyLength >> 8 ) & 0xFFu ); 
	Command.pu8Data[idx++] = (VLT_U8)( ( pKeyObj->u16KeyLength >> 0 ) & 0xFFu );

	/* abKey */
	/*
	* No need to check the return type as pointer has been validated
	*/
	(void)host_memcpyxor(&(Command.pu8Data[idx]), 
		pKeyObj->pu8Key, 
		pKeyObj->u16KeyLength, 
		pKeyObj->u8Mask);

	idx += pKeyObj->u16KeyLength;

	/* abMovingFactor */
	/*
	* No need to check the return type as pointer has been validated
	*/
	(void)host_memcpy(&(Command.pu8Data[idx]), 
		pKeyObj->pu8MovingFactor,
		VLT_KEY_HOTP_MOVINGFACTOR_LENGTH);

	idx += VLT_KEY_HOTP_MOVINGFACTOR_LENGTH;

	/* Update the CRC-16 with the (partial) data. */
	u16Crc = VltCrc16Block( u16Crc,
		&(Command.pu8Data[crcStartPos]),
		( idx - crcStartPos ) );

	/* Emit the CRC-16. */
	Command.pu8Data[idx++] = (VLT_U8)( ( u16Crc >> 8 ) & 0xFFu );
	Command.pu8Data[idx++] = (VLT_U8)( ( u16Crc >> 0 ) & 0xFFu );

	/* Send the command */
	status = VltCommand(&Command, &Response, idx, 0, pSW );
	if(VLT_OK != status)
	{
		return status;
	}

	/* React to the status word */
	switch (*pSW)
	{
	case VLT_STATUS_COMPLETED:
	case VLT_STATUS_SUCCESS:
		break;

	default:
		return VLT_OK; /* unexpected status word */
		break; //For MISRA compliancy
	}

	return status;
}
#endif /* ( VLT_ENABLE_KEY_HOTP == VLT_ENABLE ) */

#if( VLT_ENABLE_KEY_TOTP == VLT_ENABLE )
VLT_STS VltPutKey_Totp(VLT_U8 u8KeyGroup,
					   VLT_U8 u8KeyIndex,
					   const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
					   VLT_U8 u8KeyID,
					   const VLT_KEY_OBJ_TOTP* pKeyObj,
					   VLT_SW *pSW)
{
	VLT_STS       status;
	VLT_U16       u16KeyObjLen;
	VLT_U16       u16Crc = VLT_CRC16_CCITT_INIT_0s;

	/*
	* Validate all input parameters.
	*/
	if ( ( NULL == pKeyFilePrivileges )|| 
		( NULL == pKeyObj )||
		( NULL == pSW )||
		( NULL == pKeyObj->pu8Key ) )
	{
		return ( EPKTPNULLPARA );
	}

	/* Work out the size of abKeyObject. */
	u16KeyObjLen = VLT_TOTP_KEY_STATIC_PART_LENGTH;

	/* Build APDU */
	idx = VLT_APDU_DATA_OFFSET;

	Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL; 
	Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_PUT_KEY;
	Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
	Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
	Command.pu8Data[VLT_APDU_P3_OFFSET] =
		(VLT_U8) LIN(VLT_PUTKEY_FIXED_DATA_LENGTH + u16KeyObjLen);

	/* Build Data In */

	/* bmAccess */
	Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
	Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
	Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
	Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

	/* wKeyObjectLength */
	Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 8) & 0xFFu);
	Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 0) & 0xFFu);

	/* abKeyObject data */
	crcStartPos = idx;

	/* bKeyID */
	Command.pu8Data[idx++] = u8KeyID;

	/* bMask */
	Command.pu8Data[idx++] = pKeyObj->u8Mask; 

	/* wKeyLength */
	Command.pu8Data[idx++] = (VLT_U8)( (pKeyObj->u16KeyLength >> 8 ) & 0xFFu ); 
	Command.pu8Data[idx++] = (VLT_U8)( (pKeyObj->u16KeyLength >> 0 ) & 0xFFu );

	/* abKey */
	/*
	* No need to check the return type as pointer has been validated
	*/
	(void)host_memcpyxor( &(Command.pu8Data[idx]),
		pKeyObj->pu8Key,
		pKeyObj->u16KeyLength,
		pKeyObj->u8Mask );

	idx += pKeyObj->u16KeyLength;

	/* Update the CRC-16 with the (partial) data. */
	u16Crc = VltCrc16Block( u16Crc, 
		&(Command.pu8Data[crcStartPos]),
		( idx - crcStartPos ) );

	/* Emit the CRC-16. */
	Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 8) & 0xFFu);
	Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 0) & 0xFFu);

	/* Send the command */
	status = VltCommand( &Command, &Response, idx, 0, pSW );
	if(VLT_OK != status)
	{
		return status;
	}

	/* React to the status word */
	switch (*pSW)
	{
	case VLT_STATUS_COMPLETED:
	case VLT_STATUS_SUCCESS:
		break;

	default:
		return VLT_OK; /* unexpected status word */
		break; //For MISRA compliancy
	}

	return status;
}
#endif /* ( VLT_ENABLE_KEY_TOTP == VLT_ENABLE ) */

#if( VLT_ENABLE_KEY_RSA == VLT_ENABLE )
VLT_STS VltPutKey_RsaPublic(VLT_U8 u8KeyGroup,
							VLT_U8 u8KeyIndex,
							const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
							VLT_U8 u8KeyID,
							const VLT_KEY_OBJ_RSA_PUB* pKeyObj,
							VLT_SW *pSW)
{

	enum RsaPublicField { Initial=0x00, NLen, N, ELen, E, Assurance, End };
	//RsaPublicField field;

	VLT_U8 field;


	VLT_STS       status = VLT_FAIL;
	VLT_U16       u16MaxChunk;
	VLT_U16       u16KeyObjLen;
	VLT_U16       u16Offset;
	VLT_U16       u16Remaining;
	VLT_U16       u16Crc = VLT_CRC16_CCITT_INIT_0s;

	/*
	* Validate all input parameters.
	*/
	if ( ( NULL == pKeyFilePrivileges ) ||
		( NULL == pKeyObj ) ||
		( NULL == pSW ) ||
		( NULL == pKeyObj->pu8E ) ||
		( NULL == pKeyObj->pu8N ) )
	{
		return (EPKRPUBBADPARAM);
	}

    /* Check key components */
    if ((pKeyObj->u16NLen % 4 != 0) || (pKeyObj->u16ELen % 4 != 0))
    {
        return (EPKRPUBBADPARAM); // Modulus and exponent lengths must be a multiple of 4 bytes
    }

	/* We need to split the data up into chunks, the size of which the comms
	* layer tells us. */
	u16MaxChunk = VltCommsGetMaxSendSize();

	/* Work out the size of abKeyObject. */
	u16KeyObjLen = VLT_RSA_PUBLIC_STATIC_PART_LENGTH + pKeyObj->u16NLen + 
		pKeyObj->u16ELen;

	/* The field and u16Offset variables control which field we're working on
	* and the offset within that field when we are marshalling variable-sized
	* buffers. */
	field     = (VLT_U8)Initial;
	u16Offset = 0; /* 0 => first chunk */

	u16Remaining = VLT_PUTKEY_FIXED_DATA_LENGTH + u16KeyObjLen;

	while( 0u != u16Remaining )
	{
		VLT_U16 u16Chunk;

		/* Build APDU. We have to do this on every iteration as the output
		* of the previous iteration will have overwritten it (assuming a
		* shared buffer). */
		idx = VLT_APDU_DATA_OFFSET;

		if(u16Remaining > u16MaxChunk)
		{
			u16Chunk = u16MaxChunk;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
		}
		else
		{
			u16Chunk = u16Remaining;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL; 
		}
		Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_PUT_KEY;
		Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
		Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
		Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

		/* Build Data In */
		if(field == (VLT_U8)Initial) /* building the first part of the data */
		{
			/* bmAccess */
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

			/* wKeyObjectLength */
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 0) & 0xFFu);
		}

		/* abKeyObject data */
		crcStartPos = idx;

		if(field == (VLT_U8)Initial) /* building the first part of the data */
		{
			/* bKeyID */
			Command.pu8Data[idx++] = u8KeyID;
			field++; /* proceed to next field */
		}

		/* Need at least two bytes to proceed (due to two-byte fields not being
		* resumable). */
		while ( ( field <= (VLT_U8)Assurance ) && 
			( NumBufferBytesAvail( u16Chunk, idx ) >= 2u ) )
		{
			VLT_U16       u16Len;
			const VLT_U8 *pu8Data;

			if( field <= (VLT_U8)N )
			{
				u16Len = pKeyObj->u16NLen;
				pu8Data = pKeyObj->pu8N;
			}
			else
			{
				u16Len = pKeyObj->u16ELen;
				pu8Data = pKeyObj->pu8E;
			}

			switch(field)
			{
			case NLen:
			case ELen:
				Command.pu8Data[idx++] = (VLT_U8)( (u16Len >> 8 ) & 0xFFu ); 
				Command.pu8Data[idx++] = (VLT_U8)( (u16Len >> 0 ) & 0xFFu );
				field++; /* proceed to next field */
				break;
			case N:
			case E:
				{
					VLT_U16 u16Avail;
					VLT_U16 u16RemainingLen;
					VLT_U16 u16PartialLen;

					u16RemainingLen = u16Len - u16Offset;

					u16Avail = NumBufferBytesAvail( u16Chunk, idx );
					if(u16RemainingLen > u16Avail)
					{
						u16PartialLen = u16Avail; /* bytes of 'X' remaining to be sent */
					}
					else
					{
						u16PartialLen = u16RemainingLen;
						field++; /* proceed to next field */
					}

					if(u16PartialLen > 0u)
					{
						(void)host_memcpy( &(Command.pu8Data[idx]),
							&pu8Data[u16Offset],
							u16PartialLen );

						idx += u16PartialLen;
						u16Offset += u16PartialLen;

						if(u16Offset == u16Len) /* end of field */
						{
							u16Offset = 0u;
						}
					}
					break;
				}
			case Assurance:
				Command.pu8Data[idx++] = (VLT_U8) pKeyObj->enAssurance;
				field++; /* proceed to next field */
				break;
			default:
				field++; //Never happen
				break;
			}
		}

		/* Decrement the remaining number of bytes to be sent. */
		u16Remaining -= NumBytesInBuffer( idx );

		/* Update the CRC-16 with the (partial) data. */
		u16Crc = VltCrc16Block( u16Crc, 
			&(Command.pu8Data[crcStartPos]),
			(idx - crcStartPos) );

		/* Emit the CRC-16 once there's no data remaining. */

		/* It's entirely possible that we will fall through all of the above
		* code with 'u16Remaining' at zero and enter here where we construct a
		* data block only containing the wCRC data. */

		/* We need two bytes free in the buffer for the wCRC field. */
		if( ( NUM_CRC_BYTES == u16Remaining ) && 
			( NumBufferBytesAvail( u16Chunk, idx ) >= NUM_CRC_BYTES ) )
		{
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 0) & 0xFFu);
			u16Remaining -= NUM_CRC_BYTES;
		}

		/* Send the command */
		status = VltCommand( &Command, &Response, idx, 0, pSW );
		if(VLT_OK != status)
		{
			return status;
		}

		/* React to the status word */

		switch (*pSW)
		{
		case VLT_STATUS_COMPLETED:
		case VLT_STATUS_SUCCESS:
			break;

		default:
			return VLT_OK; /* unexpected status word */
			break; //For MISRA compliancy
		}
	}

	return status;
}

VLT_STS VltPutKey_RsaPrivate(VLT_U8 u8KeyGroup,
							 VLT_U8 u8KeyIndex,
							 const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
							 VLT_U8 u8KeyID,
							 const VLT_KEY_OBJ_RSA_PRIV* pKeyObj,
							 VLT_SW *pSW)
{    
	enum { Initial, Mask, NLen, N, DLen, D, PubGroup, PubIndex, End };
	VLT_U8 field;

	VLT_STS       status = VLT_FAIL;
	VLT_U16       u16MaxChunk;
	VLT_U16       u16KeyObjLen;
	VLT_U16       u16Offset;
	VLT_U16       u16Remaining;
	VLT_U16       u16Crc = VLT_CRC16_CCITT_INIT_0s;

	/*
	* Validate all input parameters.
	*/
	if ( ( NULL == pKeyFilePrivileges ) ||
		( NULL == pKeyObj ) ||
		( NULL == pSW ) ||
		( NULL == pKeyObj->pu8D ) ||
		( NULL == pKeyObj->pu8N ) )
	{
		return ( ERKRPRIVNULLPARA );
	}

    /* Check key components */
    if ((pKeyObj->u16NLen % 4 != 0) || (pKeyObj->u16DLen % 4 != 0))
    {
        return (EPKRPUBBADPARAM); // Modulus and exponent lengths must be a multiple of 4 bytes
    }
    
	/* We need to split the data up into chunks, the size of which the comms
	* layer tells us. */

	u16MaxChunk = VltCommsGetMaxSendSize();

	/* Work out the size of abKeyObject. */
	u16KeyObjLen = VLT_RSA_PRIVATE_STATIC_PART_LENGTH + pKeyObj->u16NLen +
		pKeyObj->u16DLen;

	/* The field and u16Offset variables control which field we're working on
	* and the offset within that field when we are marshalling variable-sized
	* buffers. */
	field     = (VLT_U8)Initial;
	u16Offset = 0u; /* 0 => first chunk */

	u16Remaining = VLT_PUTKEY_FIXED_DATA_LENGTH + u16KeyObjLen;

	while( 0u != u16Remaining )
	{
		VLT_U16 u16Chunk;

		/* Build APDU. We have to do this on every iteration as the output
		* of the previous iteration will have overwritten it (assuming a
		* shared buffer). */

		idx = VLT_APDU_DATA_OFFSET;

		if(u16Remaining > u16MaxChunk)
		{
			u16Chunk = u16MaxChunk;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
		}
		else
		{
			u16Chunk = u16Remaining;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL; 
		}

		Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_PUT_KEY;
		Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
		Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
		Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

		/* Build Data In */
		if(field == (VLT_U8)Initial) /* building the first part of the data */
		{
			/* bmAccess */
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

			/* wKeyObjectLength */
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 0) & 0xFFu);
		}

		/* abKeyObject data */
		crcStartPos = idx;

		if(field == (VLT_U8)Initial) /* building the first part of the data */
		{
			/* bKeyID */
			Command.pu8Data[idx++] = u8KeyID;

			field++; /* proceed to next field */
		}

		/* Need at least two bytes to proceed (due to two-byte fields not being
		* resumable). */
		while( ( field <= (VLT_U8)PubIndex ) && 
			( NumBufferBytesAvail( u16Chunk, idx ) >= 2u ) )
		{
			VLT_U16 u16Len;
			const VLT_U8 *pu8Data;

			if(field <= (VLT_U8)N)
			{
				u16Len = pKeyObj->u16NLen;
				pu8Data = pKeyObj->pu8N;
			}
			else
			{
				u16Len = pKeyObj->u16DLen;
				pu8Data    = pKeyObj->pu8D;
			}

			switch(field)
			{

			case Mask:
			{
				Command.pu8Data[idx++] = pKeyObj->u8Mask;
				field++;
				break;
			}

			case NLen:
			case DLen:
			{
				Command.pu8Data[idx++] = (VLT_U8) ((u16Len >> 8) & 0xFFu); 
				Command.pu8Data[idx++] = (VLT_U8) ((u16Len >> 0) & 0xFFu);

				field++; /* proceed to next field */
				break;
			}

			case N:
			case D:
			{
				VLT_U16 u16Avail;
				VLT_U16 u16RemainingLen;
				VLT_U16 u16PartialLen;

				u16RemainingLen = u16Len - u16Offset;

				u16Avail = NumBufferBytesAvail( u16Chunk, idx );
				if(u16RemainingLen > u16Avail)
				{
					u16PartialLen = u16Avail; /* bytes of 'X' remaining to be sent */
				}
				else
				{
					u16PartialLen = u16RemainingLen;
				}

				if(u16PartialLen > 0u)
				{
					if( (VLT_U8)N == field )
					{
						/*
						* No need to check the return type as pointer has been validated
						*/
						(void)host_memcpy( &(Command.pu8Data[idx]),
							&pu8Data[u16Offset],
							u16PartialLen );
					}
					else/* ( D == field )*/
					{
						/*
						* No need to check the return type as pointer has been validated
						*/
						(void)host_memcpyxor( &(Command.pu8Data[idx]),
							&pu8Data[u16Offset],
							u16PartialLen, 
							pKeyObj->u8Mask );
					}

					idx += u16PartialLen;
					u16Offset += u16PartialLen;

					if(u16Offset == u16Len) /* end of field */
					{
						u16Offset = 0;

						/*
						* proceed to next field now that all data has been 
						* copied
						*/
						field++;
					}
				}
				break;
			}
			case PubGroup:
			{
				Command.pu8Data[idx++] = pKeyObj->u8PublicKeyGroup;
				field++; /* proceed to next field*/
				break;
			}
			case PubIndex:
			{
				Command.pu8Data[idx++] = pKeyObj->u8PublicKeyIndex;
				field++; /* proceed to next field*/
				break;
			}
			default:
				field++; /* proceed to next field*/
				break;
			}
		}

		/* Decrement the remaining number of bytes to be sent. */
		u16Remaining -= NumBytesInBuffer( idx );

		/* Update the CRC-16 with the (partial) data. */
		u16Crc = VltCrc16Block( u16Crc, 
			&(Command.pu8Data[crcStartPos]),
			( idx - crcStartPos ) );

		/* Emit the CRC-16 once there's no data remaining. */

		/* It's entirely possible that we will fall through all of the above
		* code with 'u16Remaining' at zero and enter here where we construct a
		* data block only containing the wCRC data. */

		/* We need two bytes free in the buffer for the wCRC field. */
		if( ( NUM_CRC_BYTES == u16Remaining ) && 
			( NumBufferBytesAvail( u16Chunk, idx ) >= NUM_CRC_BYTES ) )
		{
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 0) & 0xFFu);
			u16Remaining -= NUM_CRC_BYTES;
		}

		/* Send the command */

		status = VltCommand( &Command, &Response, idx, 0, pSW );
		if(VLT_OK != status)
		{
			return status;
		}

		/* React to the status word */

		switch (*pSW)
		{
		case VLT_STATUS_COMPLETED:
		case VLT_STATUS_SUCCESS:
			break;

		default:
			return VLT_OK; /* unexpected status word */
			break; //For MISRA compliancy
		}
	}

	return status;
}

VLT_STS VltPutKey_RsaPrivateCrt(VLT_U8 u8KeyGroup,
								VLT_U8 u8KeyIndex,
								const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
								VLT_U8 u8KeyID,
								const VLT_KEY_OBJ_RSA_PRIV_CRT* pKeyObj,
								VLT_SW *pSW)
{
	enum { Initial, Mask, PLen, P, Q, DP, DQ, IP, PubGroup, PubIndex, End };
	VLT_U8 field;

	VLT_STS       status = VLT_FAIL;
	VLT_U16       u16MaxChunk;
	VLT_U16       u16KeyObjLen;
	VLT_U16       u16Offset;
	VLT_U16       u16Remaining;
	VLT_U16       u16Crc = VLT_CRC16_CCITT_INIT_0s;

	/*
	* Validate all input parameters.
	*/
	if ( ( NULL == pKeyFilePrivileges ) ||
		( NULL == pKeyObj ) ||
		( NULL == pSW )||
		( NULL == pKeyObj->pu8Dp ) ||
		( NULL == pKeyObj->pu8Dq ) ||
		( NULL == pKeyObj->pu8Ip ) ||
		( NULL == pKeyObj->pu8P ) ||
		( NULL == pKeyObj->pu8Q ) )
	{
		return ( EPKRCRTNULLPARA );
	}

    /* Check key components */
    if (pKeyObj->u16PLen % 4 != 0) 
    {
        return (EPKRPUBBADPARAM); // Prime length must be a multiple of 4 bytes
    }
    
	/* We need to split the data up into chunks, the size of which the comms
	* layer tells us. */

	u16MaxChunk = VltCommsGetMaxSendSize();

	/* Work out the size of abKeyObject. */
	u16KeyObjLen = VLT_RSA_CRT_PRIVATE_STATIC_PART_LENGTH + 
		( pKeyObj->u16PLen * 5u );

	/* The field and u16Offset variables control which field we're working on
	* and the offset within that field when we are marshalling variable-sized
	* buffers. */
	field     = (VLT_U8)Initial;
	u16Offset = 0; /* 0 => first chunk */

	u16Remaining = VLT_PUTKEY_FIXED_DATA_LENGTH + u16KeyObjLen;

	while( 0u != u16Remaining )
	{
		VLT_U16 u16Chunk;

		/* Build APDU. We have to do this on every iteration as the output
		* of the previous iteration will have overwritten it (assuming a
		* shared buffer). */
		idx = VLT_APDU_DATA_OFFSET;

		if(u16Remaining > u16MaxChunk)
		{
			u16Chunk = u16MaxChunk;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
		}
		else
		{
			u16Chunk = u16Remaining;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL; 
		}
		Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_PUT_KEY;
		Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
		Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
		Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

		/* Build Data In */
		if(field == (VLT_U8)Initial) /* building the first part of the data */
		{
			/* bmAccess */
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

			/* wKeyObjectLength */
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 0) & 0xFFu);
		}

		/* abKeyObject data */
		crcStartPos = idx;

		if(field == (VLT_U8)Initial) /* building the first part of the data */
		{
			/* bKeyID */
			Command.pu8Data[idx++] = u8KeyID;

			field++; /* proceed to next field */
		}

		/* Need at least three bytes to proceed (due to three-byte fields not
		* being resumable). */
		while( ( field <= (VLT_U8)PubIndex ) && 
			( NumBufferBytesAvail( u16Chunk, idx ) >= 3u ) )
		{
			VLT_U8        u8Mask;
			VLT_U16       u16PLen;
			const VLT_U8 *pu8Data = NULL;

			u8Mask  = pKeyObj->u8Mask;
			u16PLen = pKeyObj->u16PLen;

			switch (field)
			{
			case P: 
				pu8Data = pKeyObj->pu8P;
				break;
			case Q: 
				pu8Data = pKeyObj->pu8Q;
				break;
			case DP: 
				pu8Data = pKeyObj->pu8Dp;
				break;
			case DQ: 
				pu8Data = pKeyObj->pu8Dq;
				break;
			case IP: 
				pu8Data = pKeyObj->pu8Ip;
				break;
			default:
				/* Do nothing */
				break;
			}

			switch(field)
			{
			case Mask:
				{
					/* bMask */
					Command.pu8Data[idx++] = u8Mask;
					field++; /* proceed to next field */
					break;
				}
			case PLen:
				{
					/* wPLen */
					Command.pu8Data[idx++] = (VLT_U8) ((u16PLen >> 8) & 0xFFu); 
					Command.pu8Data[idx++] = (VLT_U8) ((u16PLen >> 0) & 0xFFu);
					field++; /* proceed to next field */
					break;
				}
			case P:
			case Q:
			case DP:
			case DQ:
			case IP:
				{
					VLT_U16 u16Avail;
					VLT_U16 u16RemainingPLen;
					VLT_U16 u16PartialPLen;

					u16RemainingPLen = u16PLen - u16Offset;

					u16Avail = NumBufferBytesAvail( u16Chunk, idx );
					if(u16RemainingPLen > u16Avail)
					{
						u16PartialPLen = u16Avail; /* bytes of 'P' remaining to be sent */
					}
					else
					{
						u16PartialPLen = u16RemainingPLen;
						field++; /* proceed to next field */
					}

					if(u16PartialPLen>0u)
					{
						/*
						* No need to check the return type as pointer has been validated
						*/
						(void)host_memcpyxor( &Command.pu8Data[idx] , 
							&pu8Data[u16Offset], 
							u16PartialPLen, 
							u8Mask );

						idx += u16PartialPLen;
						u16Offset += u16PartialPLen;

						if(u16Offset == u16PLen) /* end of field */
						{
							u16Offset = 0;
						}
					}
					break;
				}
			case PubGroup:
				{
					Command.pu8Data[idx++] = pKeyObj->u8PublicKeyGroup;
					field++; /* proceed to next field*/
					break;
				}
			case PubIndex:
				{
					Command.pu8Data[idx++] = pKeyObj->u8PublicKeyIndex;
					field++; /* proceed to next field*/
					break;
				}
			default:
				/* Do nothing */
				field++; /* proceed to next field*/
				break;
			}
		}

		/* Decrement the remaining number of bytes to be sent. */
		u16Remaining -= NumBytesInBuffer( idx );

		/* Update the CRC-16 with the (partial) data. */
		u16Crc = VltCrc16Block( u16Crc, 
			&(Command.pu8Data[crcStartPos]), 
			( idx - crcStartPos ) );

		/* Emit the CRC-16 once there's no data remaining. */

		/* It's entirely possible that we will fall through all of the above
		* code with 'u16Remaining' at zero and enter here where we construct a
		* data block only containing the wCRC data. */

		/* We need two bytes free in the buffer for the wCRC field. */
		if( ( NUM_CRC_BYTES == u16Remaining ) && 
			( NumBufferBytesAvail( u16Chunk, idx ) >= NUM_CRC_BYTES ) )
		{
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 0) & 0xFFu);
			u16Remaining -= NUM_CRC_BYTES;
		}

		/* Send the command */

		status = VltCommand( &Command, &Response, idx, 0, pSW );
		if(VLT_OK != status)
		{
			return status;
		}

		/* React to the status word */

		switch (*pSW)
		{
		case VLT_STATUS_COMPLETED:
		case VLT_STATUS_SUCCESS:
			break;

		default:
			return VLT_OK; /* unexpected status word */
			break; //For MISRA compliancy
		}
	}

	return status;
}

#endif /* ( VLT_ENABLE_KEY_RSA == VLT_ENABLE ) */

#if ( VLT_ENABLE_KEY_ECDSA == VLT_ENABLE )
#if(VLT_ENABLE_PUT_KEY_ECC_PUB == VLT_ENABLE)
VLT_STS VltPutKey_EcdsaPublic(VLT_U8 u8KeyGroup,
							  VLT_U8 u8KeyIndex,
							  const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
							  VLT_U8 u8KeyID,
							  const VLT_KEY_OBJ_ECDSA_PUB* pKeyObj,
							  VLT_SW *pSW)
{
	enum { Initial, QLen, Qx, Qy, DpGroup, DpIndex, Assurance, End };
	VLT_U8 field;

	VLT_STS       status = VLT_FAIL;
	VLT_U16       u16MaxChunk;
	VLT_U16       u16KeyObjLen;
	VLT_U16       u16Offset;
	VLT_U16       u16Remaining;
	VLT_U16       u16Crc = VLT_CRC16_CCITT_INIT_0s;

	/*
	* Validate all input parameters.
	*/
	if ( ( NULL == pKeyFilePrivileges ) ||
		( NULL == pKeyObj ) ||
		( NULL == pSW )||
		( NULL == pKeyObj->pu8Qx ) ||
		( NULL == pKeyObj->pu8Qy ) )
	{
		return ( EPKEPUBNULLPARA );
	}

	/* We need to split the data up into chunks, the size of which the comms
	* layer tells us. */

	u16MaxChunk = VltCommsGetMaxSendSize();

	/* Work out the size of abKeyObject. */
	u16KeyObjLen = VLT_ECDSA_PUBLIC_STATIC_PART_LENGTH + ( pKeyObj->u16QLen * 2u );

	/* The field and u16Offset variables control which field we're working on
	* and the offset within that field when we are marshalling variable-sized
	* buffers. */
	field     = (VLT_U8)Initial;
	u16Offset = 0; /* 0 => first chunk */

	u16Remaining = VLT_PUTKEY_FIXED_DATA_LENGTH + u16KeyObjLen;

	while( 0u != u16Remaining )
	{
		VLT_U16 u16Chunk;

		/* Build APDU. We have to do this on every iteration as the output
		* of the previous iteration will have overwritten it (assuming a
		* shared buffer). */

		idx = VLT_APDU_DATA_OFFSET;

		if(u16Remaining > u16MaxChunk)
		{
			u16Chunk = u16MaxChunk;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
		}
		else
		{
			u16Chunk = u16Remaining;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL; 
		}
		Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_PUT_KEY;
		Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
		Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
		Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

		/* Build Data In */
		if(field == (VLT_U8)Initial) /* building the first part of the data */
		{
			/* bmAccess */
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

			/* wKeyObjectLength */
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 0) & 0xFFu);
		}

		/* abKeyObject data */
		crcStartPos = idx;

		if(field == (VLT_U8)Initial) /* building the first part of the data */
		{
			/* bKeyID */
			Command.pu8Data[idx++] = u8KeyID;

			field++; /* proceed to next field */
		}

		/* Need at least two bytes to proceed (due to two-byte fields not
		* being resumable). */
		while( ( field <= (VLT_U8)Assurance ) && 
			( NumBufferBytesAvail( u16Chunk, idx ) >= 2u ) )
		{
			VLT_U16       u16Len = 0;
			const VLT_U8 *pu8Data = NULL;

			switch (field)
			{
			case QLen:
			case Qx:
				u16Len = pKeyObj->u16QLen;
				pu8Data = pKeyObj->pu8Qx;
				break;
			case Qy:
				u16Len = pKeyObj->u16QLen;
				pu8Data = pKeyObj->pu8Qy;
				break;
			default:
				/* Do nothing */
				break;
			}

			switch(field)
			{
			case QLen:
				{
					Command.pu8Data[idx++] = (VLT_U8) ((u16Len >> 8) & 0xFFu); 
					Command.pu8Data[idx++] = (VLT_U8) ((u16Len >> 0) & 0xFFu);

					field++; /* proceed to next field */
					break;
				}

			case Qx:
			case Qy:
				{
					VLT_U16 u16Avail;
					VLT_U16 u16RemainingQLen;
					VLT_U16 u16PartialQLen;

					u16RemainingQLen = u16Len - u16Offset;

					u16Avail = NumBufferBytesAvail( u16Chunk, idx );
					if(u16RemainingQLen > u16Avail)
					{
						u16PartialQLen = u16Avail; /* bytes of 'Q' remaining to be sent */
					}
					else
					{
						u16PartialQLen = u16RemainingQLen;
						field++; /* proceed to next field */
					}

					if(u16PartialQLen > 0u)
					{
						/*
						* No need to check the return type as pointer has been validated
						*/
						(void)host_memcpy( &(Command.pu8Data[idx]),
							&pu8Data[u16Offset],
							u16PartialQLen);

						idx += u16PartialQLen;
						u16Offset += u16PartialQLen;

						if( u16Offset == u16Len ) /* end of field */
						{
							u16Offset = 0;
						}
					}
					break;
				}
			case DpGroup:
				{
					Command.pu8Data[idx++] = pKeyObj->u8DomainParamsGroup;
					field++; /* proceed to next field */
					break;
				}
			case DpIndex:
				{
					Command.pu8Data[idx++] = pKeyObj->u8DomainParamsIndex;
					field++; /* proceed to next field */
					break;
				}
			case Assurance:
				{
					Command.pu8Data[idx++] = (VLT_U8)pKeyObj->enAssurance;
					field++; /* proceed to next field */
					break;
				}
			default:
				field++; /* proceed to next field */
				break;
			}
		}

		/* Decrement the remaining number of bytes to be sent. */
		u16Remaining -= NumBytesInBuffer( idx );

		/* Update the CRC-16 with the (partial) data. */
		u16Crc = VltCrc16Block( u16Crc,
			&(Command.pu8Data[crcStartPos]),
			( idx  - crcStartPos ) );

		/* Emit the CRC-16 once there's no data remaining. */

		/* It's entirely possible that we will fall through all of the above
		* code with 'u16Remaining' at zero and enter here where we construct a
		* data block only containing the wCRC data. */

		/* We need two bytes free in the buffer for the wCRC field. */
		if( ( NUM_CRC_BYTES == u16Remaining ) && 
			( NumBufferBytesAvail( u16Chunk, idx ) >= NUM_CRC_BYTES ) )
		{
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 0) & 0xFFu);
			u16Remaining -= NUM_CRC_BYTES;
		}

		/* Send the command */

		status = VltCommand( &Command, &Response, idx, 0, pSW );
		if(VLT_OK != status)
		{
			return status;
		}

		/* React to the status word */

		switch (*pSW)
		{
		case VLT_STATUS_COMPLETED:
		case VLT_STATUS_SUCCESS:
			break;

		default:
			return VLT_OK; /* unexpected status word */
			break; //For MISRA compliancy
		}
	}

	return status;
}
#endif /*(VLT_ENABLE_PUT_KEY_ECC_PUB == VLT_ENABLE)*/

#if (VLT_ENABLE_PUT_KEY_ECC_PRIV == VLT_ENABLE)

VLT_STS VltPutKey_EcdsaPrivate(VLT_U8 u8KeyGroup,
							   VLT_U8 u8KeyIndex,
							   const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
							   VLT_U8 u8KeyID,
							   const VLT_KEY_OBJ_ECDSA_PRIV* pKeyObj,
							   VLT_SW *pSW)
{

	enum { Initial, Mask, DLen, D, DpGroup, DpIndex, PubGroup, PubIndex, Assurance, End };
	VLT_U8 field;
	VLT_STS       status = VLT_FAIL;
	VLT_U16       u16MaxChunk;
	VLT_U16       u16KeyObjLen;
	VLT_U16       u16Offset;
	VLT_U16       u16Remaining;
	VLT_U16       u16Crc = VLT_CRC16_CCITT_INIT_0s;

	/*
	* Validate all input parameters.
	*/
	if ( ( NULL == pKeyFilePrivileges ) ||
		( NULL == pKeyObj ) ||
		( NULL == pSW )||
		( NULL == pKeyObj->pu8D ) )
	{
		return ( EPKEPRIVNULLPARA );
	}

	/* We need to split the data up into chunks, the size of which the comms
	* layer tells us. */

	u16MaxChunk = VltCommsGetMaxSendSize();

	/* Work out the size of abKeyObject. */
	u16KeyObjLen = VLT_ECDSA_PRIVATE_STATIC_PART_LENGTH + pKeyObj->u16DLen;

	/* The field and u16Offset variables control which field we're working on
	* and the offset within that field when we are marshalling variable-sized
	* buffers. */
	field     = (VLT_U8)Initial;
	u16Offset = 0; /* 0 => first chunk */

	u16Remaining = VLT_PUTKEY_FIXED_DATA_LENGTH + u16KeyObjLen;

	while( 0u != u16Remaining )
	{
		VLT_U16 u16Chunk;

		/* Build APDU. We have to do this on every iteration as the output
		* of the previous iteration will have overwritten it (assuming a
		* shared buffer). */
		idx = VLT_APDU_DATA_OFFSET;

		if(u16Remaining > u16MaxChunk)
		{
			u16Chunk = u16MaxChunk;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
		}
		else
		{
			u16Chunk = u16Remaining;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL; 
		}
		Command.pu8Data[VLT_APDU_INS_OFFSET]= VLT_INS_PUT_KEY;
		Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
		Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
		Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

		/* Build Data In */
		if(field == (VLT_U8)Initial) /* building the first part of the data */
		{
			/* bmAccess */
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

			/* wKeyObjectLength */
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 0) & 0xFFu);
		}

		/* abKeyObject data */
		crcStartPos = idx;

		if(field == (VLT_U8)Initial) /* building the first part of the data */
		{
			/* bKeyID */
			Command.pu8Data[idx++] = u8KeyID;

			field++; /* proceed to next field */
		}

		/* Need at least three bytes to proceed (due to two-byte fields not
		* being resumable). */
		while( (field <= (VLT_U8)Assurance )&& ( NumBufferBytesAvail( u16Chunk, idx ) >= 2u ) )
		{
			VLT_U16       u16Len = 0;
			const VLT_U8 *pu8Data = NULL;

			if( field <= (VLT_U8)D )
			{
				u16Len = pKeyObj->u16DLen;
				pu8Data = pKeyObj->pu8D;
			}


			switch(field)
			{
			case Mask:
				{
					Command.pu8Data[idx++] = pKeyObj->u8Mask;
					field++; /* proceed to next field */
					break;
				}
			case DLen:
				{
					Command.pu8Data[idx++] = (VLT_U8) ((u16Len >> 8) & 0xFFu); 
					Command.pu8Data[idx++] = (VLT_U8) ((u16Len >> 0) & 0xFFu);
					field++; /* proceed to next field */
					break;
				}
			case D:
				{
					VLT_U16 u16Avail;
					VLT_U16 u16RemainingDLen;
					VLT_U16 u16PartialDLen;
                    VLT_U8 u8Mask;

					u16RemainingDLen = u16Len - u16Offset;

					u16Avail = NumBufferBytesAvail( u16Chunk, idx );
					if(u16RemainingDLen > u16Avail)
					{
						u16PartialDLen = u16Avail; /* bytes of 'D' remaining to be sent */
					}
					else
					{
						u16PartialDLen = u16RemainingDLen;
						field++; /* proceed to next field */
					}

					if(u16PartialDLen>0u)
					{
						u8Mask = pKeyObj->u8Mask;

						/*
						* No need to check the return type as pointer has been validated
						*/
						(void)host_memcpyxor( &(Command.pu8Data[idx]), 
							&pu8Data[u16Offset], 
							u16PartialDLen, 
							u8Mask);

						idx += u16PartialDLen;
						u16Offset += u16PartialDLen;

						if(u16Offset == u16Len) /* end of field */
						{
							u16Offset = 0;
						}
					}
					break;
				}
			case DpGroup:
				{
					Command.pu8Data[idx++] = pKeyObj->u8DomainParamsGroup;
					field++; /* proceed to next field */
					break;
				}
			case DpIndex:
				{
					Command.pu8Data[idx++] = pKeyObj->u8DomainParamsIndex;
					field++; /* proceed to next field */
					break;
				}
			case PubGroup:
				{
					Command.pu8Data[idx++] = pKeyObj->u8PublicKeyGroup;
					field++; /* proceed to next field */
					break;
				}
			case PubIndex:
				{
					Command.pu8Data[idx++] = pKeyObj->u8PublicKeyIndex;
					field++; /* proceed to next field */
					break;
				}

			case Assurance:
				{
					Command.pu8Data[idx++] = (VLT_U8)pKeyObj->enAssurance;
					field++; /* proceed to next field */
					break;
				}
			default:
				field++; /* proceed to next field */
				break;
			}
		}

		/* Decrement the remaining number of bytes to be sent. */
		u16Remaining -= NumBytesInBuffer( idx );

		/* Update the CRC-16 with the (partial) data. */
		u16Crc = VltCrc16Block( u16Crc,
			&(Command.pu8Data[crcStartPos]),
			( idx - crcStartPos ) );

		/* Emit the CRC-16 once there's no data remaining. */

		/* It's entirely possible that we will fall through all of the above
		* code with 'u16Remaining' at zero and enter here where we construct a
		* data block only containing the wCRC data. */

		/* We need two bytes free in the buffer for the wCRC field. */
		if( ( NUM_CRC_BYTES == u16Remaining ) && 
			( NumBufferBytesAvail( u16Chunk, idx ) >= NUM_CRC_BYTES ) )
		{
			Command.pu8Data[idx++]= (VLT_U8) ((u16Crc >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 0) & 0xFFu);
			u16Remaining -= NUM_CRC_BYTES;
		}

		/* Send the command */

		status = VltCommand( &Command, &Response, idx, 0, pSW );
		if(VLT_OK != status)
		{
			return status;
		}

		/* React to the status word */

		switch (*pSW)
		{
		case VLT_STATUS_COMPLETED:
		case VLT_STATUS_SUCCESS:
			break;

		default:
			return VLT_OK; /* unexpected status word */
			break; //For MISRA compliancy
		}
	}

	return status;
} 
#endif /*(VLT_ENABLE_PUT_KEY_ECC_PRIV == VLT_ENABLE)*/

#if ( VLT_ENABLE_PUT_KEY_ECC_PARAMS == VLT_ENABLE )
VLT_STS VltPutKey_EcdsaParams( VLT_U8 u8KeyGroup,
							  VLT_U8 u8KeyIndex,
							  const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
							  VLT_U8 u8KeyID,
							  const VLT_KEY_OBJ_ECDSA_PARAMS* pKeyObj,
							  VLT_SW *pSW )
{
	enum { Init, QLen, Q, Gx, Gy, Gz, A, B, NLen, N, H, Assurance, End };
	VLT_U8 field;

	VLT_STS status = VLT_FAIL;
	VLT_U16 u16MaxChunk;
	VLT_U16 u16KeyObjLen;
	VLT_U16 u16Offset;
	VLT_U16 u16Remaining;
	VLT_U16 u16Crc = VLT_CRC16_CCITT_INIT_0s;

	/*
	* Validate all input parameters.
	*/
	if ( ( NULL == pKeyFilePrivileges ) ||
		( NULL == pKeyObj ) ||
		( NULL == pSW ) ||
		( NULL == pKeyObj->pu8Q ) ||
		( NULL == pKeyObj->pu8Gx) ||
		( NULL == pKeyObj->pu8Gy) ||
		( NULL == pKeyObj->pu8Gz ) ||
		( NULL == pKeyObj->pu8A ) ||
		( NULL == pKeyObj->pu8B ) ||
		( NULL == pKeyObj->pu8N ) )
	{
		return ( EPKECDSAPRMNULLPARA );
	}

	/* We need to split the data up into chunks, the size of which the comms
	* layer tells us. */

	u16MaxChunk = VltCommsGetMaxSendSize();

	/*
	* Work out the size of abKeyObject.
	*/
	u16KeyObjLen = VLT_ECDSA_PARAMS_STATIC_PART_LENGTH + ( pKeyObj->u16QLen * 6u ) 
		+ pKeyObj->u16NLen;

	/* 
	* The field and u16Offset variables control which field we're working on
	* and the offset within that field when we are marshalling variable-sized
	* buffers.
	*/
	field = (VLT_U8)Init;
	u16Offset = 0; /* 0 => first chunk */

	u16Remaining = VLT_PUTKEY_FIXED_DATA_LENGTH + u16KeyObjLen;

	while( 0u != u16Remaining )
	{
		VLT_U16 u16Chunk;

		/* Build APDU. We have to do this on every iteration as the output
		* of the previous iteration will have overwritten it (assuming a
		* shared buffer). */

		idx = VLT_APDU_DATA_OFFSET;

		if( u16Remaining > u16MaxChunk )
		{
			u16Chunk = u16MaxChunk;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
		}
		else
		{
			u16Chunk = u16Remaining;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL; 
		}
		Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_PUT_KEY;
		Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
		Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
		Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

		/* Build Data In */
		if( field == (VLT_U8)Init ) /* building the first part of the data */
		{
			/* bmAccess */
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

			/* wKeyObjectLength */
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 0) & 0xFFu);
		}

		/* abKeyObject data */
		crcStartPos = idx;

		if( field == (VLT_U8)Init ) /* building the first part of the data */
		{
			/* bKeyID */
			Command.pu8Data[idx++] = u8KeyID;

			field++; /* proceed to next field */
		}

		/* Need at least two bytes to proceed (due to two-byte fields not
		* being resumable). */
		while( ( field <= (VLT_U8)Assurance) && 
			( NumBufferBytesAvail( u16Chunk, idx ) >= 2u ) )
		{
			VLT_U16 u16Len = 0;
			const VLT_U8 *pu8Data = NULL;

			switch (field)
			{
			case QLen:
				u16Len = pKeyObj->u16QLen;
				pu8Data = pKeyObj->pu8Q;
				break;
			case Q:
				u16Len = pKeyObj->u16QLen;
				pu8Data = pKeyObj->pu8Q;
				break;
			case Gx:
				u16Len = pKeyObj->u16QLen;
				pu8Data = pKeyObj->pu8Gx;
				break;
			case Gy:
				u16Len = pKeyObj->u16QLen;
				pu8Data = pKeyObj->pu8Gy;
				break;
			case Gz:
				u16Len = pKeyObj->u16QLen;
				pu8Data = pKeyObj->pu8Gz;
				break;
			case A:
				u16Len = pKeyObj->u16QLen;
				pu8Data = pKeyObj->pu8A;
				break;
			case B:
				u16Len = pKeyObj->u16QLen;
				pu8Data = pKeyObj->pu8B;
				break;
			case NLen:
			case N:
				u16Len = pKeyObj->u16NLen;
				pu8Data = pKeyObj->pu8N;
				break;
			default:
				/* No need to do anything*/
				break;
			}

			switch(field)
			{
			case QLen:
			case NLen:
				{
					Command.pu8Data[idx++] = (VLT_U8)((u16Len >> 8) & 0xFFu); 
					Command.pu8Data[idx++] = (VLT_U8)((u16Len >> 0) & 0xFFu);

					field++; /* proceed to next field */
					break;
				}
			case Q:
			case Gx:
			case Gy:
			case Gz: 
			case A:
			case B:
			case N:
				{
					VLT_U16 u16Avail;
					VLT_U16 u16RemainingLen;
					VLT_U16 u16PartialLen;

					u16RemainingLen = u16Len - u16Offset;

					u16Avail = NumBufferBytesAvail( u16Chunk, idx );
					if(u16RemainingLen > u16Avail)
					{
						u16PartialLen = u16Avail; /* bytes of data remaining to be sent */
					}
					else
					{
						u16PartialLen = u16RemainingLen;
						field++; /* proceed to next field */
					}

					if( u16PartialLen > 0u)
					{
						/*
						* No need to check the return type as pointer has been validated
						*/
						(void)host_memcpy( &(Command.pu8Data[idx]),
							&pu8Data[u16Offset],
							u16PartialLen );

						idx += u16PartialLen;
						u16Offset += u16PartialLen;

						if( u16Offset == u16Len ) /* end of field */
						{
							u16Offset = 0;
						}
					}
					break;
				}
			case H:
				{
					Command.pu8Data[idx++] = (VLT_U8)((pKeyObj->u32H >> 24) & 0xFFu); 
					Command.pu8Data[idx++] = (VLT_U8)((pKeyObj->u32H >> 16) & 0xFFu);
					Command.pu8Data[idx++] = (VLT_U8)((pKeyObj->u32H >> 8) & 0xFFu); 
					Command.pu8Data[idx++] = (VLT_U8)((pKeyObj->u32H >> 0) & 0xFFu);
					field++; /* proceed to next field */
					break;
				}
			case Assurance:
				{
					Command.pu8Data[idx++] = (VLT_U8)pKeyObj->enAssurance;
					field++; /* proceed to next field */
					break;
				}
			default:
				field++; /* proceed to next field */
				break;
			}
		}

		/* Decrement the remaining number of bytes to be sent. */
		u16Remaining -= NumBytesInBuffer( idx );

		/* Update the CRC-16 with the (partial) data. */
		u16Crc = VltCrc16Block( u16Crc,
			&(Command.pu8Data[crcStartPos]),
			( idx  - crcStartPos ) );

		/* Emit the CRC-16 once there's no data remaining. */

		/* It's entirely possible that we will fall through all of the above
		* code with 'u16Remaining' at zero and enter here where we construct a
		* data block only containing the wCRC data. */

		/* We need two bytes free in the buffer for the wCRC field. */
		if( ( NUM_CRC_BYTES == u16Remaining ) && 
			( NumBufferBytesAvail( u16Chunk, idx ) >= NUM_CRC_BYTES ) )
		{
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 0) & 0xFFu);
			u16Remaining -= NUM_CRC_BYTES;
		}

		/* Send the command */

		status = VltCommand( &Command, &Response, idx, 0, pSW );
		if(VLT_OK != status)
		{
			return status;
		}

		/* React to the status word */

		switch (*pSW)
		{
		case VLT_STATUS_COMPLETED:
		case VLT_STATUS_SUCCESS:
			break;

		default:
			return VLT_OK; /* unexpected status word */
			break; //For MISRA compliancy
		}
	}

	return( status );
}
#endif /*VLT_ENABLE_PUT_KEY_ECC_PARAMS*/

#endif /* ( VLT_ENABLE_KEY_ECDSA == VLT_ENABLE ) */

#if( VLT_ENABLE_KEY_IDENTIFIER == VLT_ENABLE )
#if( VLT_ENABLE_PUT_KEY_IDENTIFIER == VLT_ENABLE )

VLT_STS VltPutKey_IdKey( VLT_U8 u8KeyGroup,
						VLT_U8 u8KeyIndex,
						const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
						VLT_U8 u8KeyID,
						const VLT_KEY_OBJ_ID* pKeyObj,
						VLT_SW *pSW )
{
	enum { Init, StringLen, StringId, End };
	VLT_U8 field;

	VLT_STS status = VLT_FAIL;
	VLT_U16 u16MaxChunk;
	VLT_U16 u16KeyObjLen;
	VLT_U16 u16Offset;
	VLT_U16 u16Remaining;
	VLT_U16 u16Crc = VLT_CRC16_CCITT_INIT_0s;

	/*
	* Validate all input parameters.
	*/
	if ( ( NULL == pKeyFilePrivileges ) ||
		( NULL == pKeyObj ) ||
		( NULL == pSW ) ||
		( NULL == pKeyObj->pu8StringId ) )
	{
		return ( EPKIDNULLPARA );
	}

	/* We need to split the data up into chunks, the size of which the comms
	* layer tells us. */

	u16MaxChunk = VltCommsGetMaxSendSize();

	/*
	* Work out the size of abKeyObject.
	*/
	u16KeyObjLen = VLT_IDENTIFIER_STATIC_PART_LENGTH + pKeyObj->u16StringLen;

	/* 
	* The field and u16Offset variables control which field we're working on
	* and the offset within that field when we are marshalling variable-sized
	* buffers.
	*/
	field = (VLT_U8)Init;
	u16Offset = 0; /* 0 => first chunk */

	u16Remaining = VLT_PUTKEY_FIXED_DATA_LENGTH + u16KeyObjLen;

	while( 0u != u16Remaining )
	{
		VLT_U16 u16Chunk;

		/* Build APDU. We have to do this on every iteration as the output
		* of the previous iteration will have overwritten it (assuming a
		* shared buffer). */

		idx = VLT_APDU_DATA_OFFSET;

		if( u16Remaining > u16MaxChunk )
		{
			u16Chunk = u16MaxChunk;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHAINING;
		}
		else
		{
			u16Chunk = u16Remaining;
			Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL; 
		}
		Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_PUT_KEY;
		Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
		Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
		Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

		/* Build Data In */
		if( field == (VLT_U8)Init ) /* building the first part of the data */
		{
			/* bmAccess */
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
			Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

			/* wKeyObjectLength */
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16KeyObjLen >> 0) & 0xFFu);
		}

		/* abKeyObject data */
		crcStartPos = idx;

		if( field == (VLT_U8)Init ) /* building the first part of the data */
		{
			/* bKeyID */
			Command.pu8Data[idx++] = u8KeyID;

			field++; /* proceed to next field */
		}

		/* Need at least two bytes to proceed (due to two-byte fields not
		* being resumable). */
		while( ( field <= (VLT_U8)StringId) && 
			( NumBufferBytesAvail( u16Chunk, idx ) >= 2u ) )
		{
			VLT_U16 u16Len = pKeyObj->u16StringLen;
			const VLT_U8 *pu8Data = pKeyObj->pu8StringId;

			if( (VLT_U8)StringLen == field )
			{
				Command.pu8Data[idx++] = (VLT_U8)((u16Len >> 8) & 0xFFu); 
				Command.pu8Data[idx++] = (VLT_U8)((u16Len >> 0) & 0xFFu);

				field++; /* proceed to next field */
			}

			else
			{
				if( (VLT_U8)StringId == field )
				{
					VLT_U16 u16Avail;
					VLT_U16 u16RemainingLen;
					VLT_U16 u16PartialLen;

					u16RemainingLen = u16Len - u16Offset;

					u16Avail = NumBufferBytesAvail( u16Chunk, idx );
					if(u16RemainingLen > u16Avail)
					{
						u16PartialLen = u16Avail; /* bytes of data remaining to be sent */
					}
					else
					{
						u16PartialLen = u16RemainingLen;
						field++; /* proceed to next field */
					}

					if( u16PartialLen > 0u)
					{
						/*
						* No need to check the return type as pointer has been validated
						*/
						(void)host_memcpy( &(Command.pu8Data[idx]),
							&pu8Data[u16Offset],
							u16PartialLen );

						idx += u16PartialLen;
						u16Offset += u16PartialLen;

						if( u16Offset == u16Len ) /* end of field */
						{
							u16Offset = 0;
						}
					}
				}
			}
		}

		/* Decrement the remaining number of bytes to be sent. */
		u16Remaining -= NumBytesInBuffer( idx );

		/* Update the CRC-16 with the (partial) data. */
		u16Crc = VltCrc16Block( u16Crc,
			&(Command.pu8Data[crcStartPos]),
			( idx  - crcStartPos ) );

		/* Emit the CRC-16 once there's no data remaining. */

		/* It's entirely possible that we will fall through all of the above
		* code with 'u16Remaining' at zero and enter here where we construct a
		* data block only containing the wCRC data. */

		/* We need two bytes free in the buffer for the wCRC field. */
		if( ( NUM_CRC_BYTES == u16Remaining ) && 
			( NumBufferBytesAvail( u16Chunk, idx ) >= NUM_CRC_BYTES ) )
		{
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((u16Crc >> 0) & 0xFFu);
			u16Remaining -= NUM_CRC_BYTES;
		}

		/* Send the command */

		status = VltCommand( &Command, &Response, idx, 0, pSW );
		if(VLT_OK != status)
		{
			return status;
		}

		/* React to the status word */

		switch (*pSW)
		{
		case VLT_STATUS_COMPLETED:
		case VLT_STATUS_SUCCESS:
			break;

		default:
			return VLT_OK; /* unexpected status word */
			break; //For MISRA compliancy
		}
	}

	return( status );
}
#endif  /* ( VLT_ENABLE_PUT_KEY_IDENTIFIER == VLT_ENABLE ) */
#endif /* ( VLT_ENABLE_KEY_IDENTIFIER == VLT_ENABLE ) */
#endif