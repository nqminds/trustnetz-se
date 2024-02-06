/**
* @file	   vaultic_readkey_aux.c
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
#if( VLT_ENABLE_API_READ_KEY == VLT_ENABLE ) 
#include "vaultic_api.h"
#include <comms/vaultic_comms.h>
#include "vaultic_utils.h"
#include "vaultic_mem.h"
#include "vaultic_cipher.h"
#include <tests/vaultic_cipher_tests.h>
#include "vaultic_crc16.h"
#include "vaultic_command.h"
#include "vaultic_readkey_aux.h"


/* VltReadKey aux functions
 * ========================
 *
 * The VltReadKey aux functions retrieve key data from the VaultIC and unpack it
 * into a structure which is assumed to have been appropriately allocated by the
 * client.
 *
 * The cases listed earlier in the source are 'simple' and involve unpacking
 * only fixed-size data. The later cases, especially the private key cases, are
 * more complex and must cope with repeatedly re-issuing commands to VaultIC
 * until the decoding is complete.
 *
 * The routines are mostly very similar and could be merged together to save
 * space at the expense of making the simple cases use the more generic code.
 *
 * State variables are maintained which tell us which field we're processing and
 * the offset within that field. The routines are structured so that we unpack
 * until we run out of bytes at which point we fetch another full buffer. This
 * keeps the buffer requests as big as possible, minimising the number of
 * chunks/commands which need to be received. (The alternative would be to try
 * to receive one field at a time).
 *
 * Common variables:
 *
 * field        records the field of the output structure we're unpacking.
 * pu8Data      points to the next byte to be consumed in the input buffer.
 * u16Offset    records the offset within that field.
 * u16Avail     holds the number of available input bytes.
 * u16BufLen    holds the number of bytes in the buffer.
 * pu8Buf       points to the next available free byte in the output buffer. 
 *
 * Field Unpacking
 * ---------------
 * Fields are treated identically by the code. They're unpacked by copying the
 * bytes across into the output buffer. Where appropriate and when the buffer is
 * full the buffer contents are then endian-swapped in place.
 *
 * host_memcpyxor is often used irrespective of a field which requires masking.
 * For non-masked fields u8Mask will be zero.
 *
 * Strings
 * -------
 * Strings received from VaultIC are terminated and the size of the terminator
 * is included in the string length field. To ensure consistency with VltPutKey
 * the string length is decremented before being returned. (We don't attempt to
 * /not/ copy the terminator).
 *
 */

/**
 * Externs 
 */
extern VLT_MEM_BLOB Command;                            /* declared in vaultic_api.c */
extern VLT_MEM_BLOB Response;                           /* declared in vaultic_api.c */
extern VLT_U16 idx;                                     /* declared in vaultic_api.c */

/**
 * Local Static Variables
 */
static VLT_U16 u16CalculatedCrc = VLT_CRC16_CCITT_INIT_0s;
static VLT_U16 u16ReceivedCrc = 0xFFFFu;
#if(VLT_ENABLE_NO_WRAPKEY_CRC == VLT_ENABLE)
extern VLT_BOOL bSkipCRC ;
#endif

void ReadKeyInitCrc( void )
{
    u16CalculatedCrc = VLT_CRC16_CCITT_INIT_0s;
}

VLT_STS VltReadKeyCommand( const VLT_MEM_BLOB *command,
    VLT_MEM_BLOB *response,
    VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,    
    VLT_SW *pSW )
{
    VLT_STS status;        
    idx = VLT_APDU_DATA_OFFSET;

    /* Check the pointers are valid */
    if ( ( NULL == command ) ||
         ( NULL == response ) ||
         ( NULL == pSW ) )
    {
        return ( ERKCMDNULLPARA );
    }

    /* Check the command and response buffer pointers are vaild.*/
    if ( ( NULL == Command.pu8Data ) ||
         ( NULL == Response.pu8Data ) )
    {
        return ( ERKCMDNULLPARA );
    }
    
    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_READ_KEY;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = WRAPPED_BYTE(256u); /* request as much as possible */

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, pSW );

    /* adjust the response size to take in account the status word size */
    Response.u16Len -= VLT_SW_SIZE;
         
    if( VLT_OK != status)
    {
        return( status );
    }

    if( ( *pSW != VLT_STATUS_RESPONDING ) &&
        ( *pSW != VLT_STATUS_SUCCESS ) )
    {
        return ERKINVLDRSP;
    }

	if( *pSW == VLT_STATUS_NONE )
	{
		return( status );
	}

#if(VLT_ENABLE_NO_WRAPKEY_CRC == VLT_ENABLE)
    if (bSkipCRC == FALSE)
#endif    
    {
        /* Update the CRC */
        if (*pSW == VLT_STATUS_SUCCESS)
        {
            Response.u16Len -= NUM_CRC_BYTES;

            u16CalculatedCrc = VltCrc16Block(u16CalculatedCrc,
                Response.pu8Data,
                Response.u16Len);

            /* Retrieve received CRC */
            u16ReceivedCrc = VltEndianReadPU16(
                &Response.pu8Data[Response.u16Len]);

        }
        else
        {
            if (*pSW == VLT_STATUS_RESPONDING)
            {
                u16CalculatedCrc = VltCrc16Block(u16CalculatedCrc,
                    Response.pu8Data,
                    Response.u16Len);
            }
        }
    }

	return VLT_OK;
}

#if(VLT_ENABLE_READ_KEY_RAW == VLT_ENABLE)
VLT_STS VltReadKey_Raw( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_RAW* keyObj,
    VLT_SW *pSW )
{
    VLT_STS status;
    VLT_U16 u16KeyObjLen = 0;
    VLT_U8 bReadComplete = FALSE;
    VLT_U16 u16RequestedLen;
    
    if( ( NULL == keyObj ) ||
        ( NULL == pSW ) ||
        ( NULL == keyObj->pu8KeyObject ) )
    {
        return ( ERKRAWNULLPARA );
    }


	if (TRUE==keyObj->isEncryptedKey)
	{
		if ( NULL == keyObj->pu16EncKeyObjectLen )
		{
			 return ( ERKRAWNULLPARA );
		}
		// Safe to use the ptr to the key object length
		u16RequestedLen = *keyObj->pu16EncKeyObjectLen;
	}
	else
	{
		if ( NULL == keyObj->pu16ClearKeyObjectLen )
		{
			 return ( ERKRAWNULLPARA );
		}  
		// Safe to use the ptr to the key object length
		u16RequestedLen = *keyObj->pu16ClearKeyObjectLen;
	}
    
    do
    {
        /* Copy the data in the user's buffer if we have enough space */
        if( ( u16KeyObjLen + Response.u16Len ) <= u16RequestedLen )
        {
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy( &keyObj->pu8KeyObject[ u16KeyObjLen ], 
                Response.pu8Data, 
                Response.u16Len );
        }        

        /* Update the length */
        u16KeyObjLen += Response.u16Len;

        if( *pSW == VLT_STATUS_SUCCESS )
        {
            /* We have received the whole key exit the loop */
            bReadComplete = TRUE;

#if(VLT_ENABLE_NO_WRAPKEY_CRC == VLT_ENABLE)
            if (bSkipCRC == FALSE)
#endif    
            {
                /* Assign the received CRC value into the struct returned to the host side caller. */
                keyObj->u16Crc = u16ReceivedCrc;

                /* Validate received CRC (except if it's encrypted as we don't know the decryption key here) */
                if (keyObj->isEncryptedKey == FALSE)
                {
                    if (u16ReceivedCrc != u16CalculatedCrc)
                        return(ERKSCIVLDCRC);
                }
            }
        }
        else if( *pSW == VLT_STATUS_RESPONDING )
        {
            /* read more data */
            status = VltReadKeyCommand( &Command, 
                &Response, 
                u8KeyGroup,
                u8KeyIndex, 
                pSW );

            if( VLT_OK != status )
            {
                return( status );
            }
        }
        else
        {
            return( *pSW );
        }
    }
    while( bReadComplete == FALSE );

    /** 
     * If we have run out of space let the caller know
     * the true length of the key requested and return
     * the appropriate error code.
     */

	if( FALSE == keyObj->isEncryptedKey ) 
	{
		*keyObj->pu16ClearKeyObjectLen = u16KeyObjLen;
	}
	else
	{
		*keyObj->pu16EncKeyObjectLen = u16KeyObjLen;
	}

    if( u16KeyObjLen > u16RequestedLen )
    {
        return( ERKRAWNOROOM );
    }

    return( VLT_OK );
}
#endif //(VLT_ENABLE_READ_KEY_RAW == VLT_ENABLE)

/* The VltReadKey_* functions are called once a first buffer of data is
 * available. If there are more than '256' bytes to receive (i.e. more than a
 * single chunk of data) these function will make more requests to retrieve it.
 */

#if( VLT_ENABLE_KEY_SECRET == VLT_ENABLE )

#if(VLT_ENABLE_READ_KEY_SECRET == VLT_ENABLE)
VLT_STS VltReadKey_Secret(
    VLT_KEY_OBJ_SECRET* keyObj,
    VLT_SW *pSW)
{    
    /* Start unpacking after the bKeyID */
    idx = 1;

    if ( ( NULL == keyObj ) ||
         ( NULL == pSW ) ||
         ( NULL == keyObj->pu8Key ) ||
         ( 0u == keyObj->u16KeyLength ) )
    {
        return ( ERKSECNULLPARA );
    }
    
    /* We're expecting the entire response to be in the buffer */
    if (*pSW != VLT_STATUS_SUCCESS)
    {
        return ERKINVLDRSP;
    }        

    /* Unpack the key object */
    keyObj->u8Mask = Response.pu8Data[idx++];

    /* Check there is enough room to store the key object in the host buffer.*/
    /* the actual length is stored in keyObj->u16KeyLength. */ 
    if ( keyObj->u16KeyLength < VltEndianReadPU16( &Response.pu8Data[idx] ) )
    {
        return ( ERKSECNOROOM );
    }

    keyObj->u16KeyLength = VltEndianReadPU16( &Response.pu8Data[idx] );
    idx += 2u;

    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpyxor( keyObj->pu8Key, 
        &Response.pu8Data[idx], 
        keyObj->u16KeyLength, 
        keyObj->u8Mask );
    
    /* Validate received CRC */
    if( u16ReceivedCrc != u16CalculatedCrc )
    {
        return( ERKSCIVLDCRC );
    }
     
    return VLT_OK;
}
#endif // (VLT_ENABLE_READ_KEY_SECRET == VLT_ENABLE)
#endif /* ( VLT_ENABLE_KEY_SECRET == VLT_ENABLE ) */

#if( VLT_ENABLE_KEY_HOTP == VLT_ENABLE )

VLT_STS VltReadKey_Hotp(
    VLT_KEY_OBJ_HOTP* keyObj,
    VLT_SW *pSW)
{    
    /* Start unpacking after the bKeyID */
    idx = 1;

    /*
     * Validate all input parameters.
     */
    if ( ( NULL == keyObj ) ||
         ( NULL == pSW ) ||
         ( NULL == keyObj->pu8Key ) ||
         ( NULL == keyObj->pu8MovingFactor ) )
    {
        return ( ERKHPNULLPARA );
    }

    /* We're expecting the entire response to be in the buffer */
    if (*pSW != VLT_STATUS_SUCCESS)
    {
        return ERKINVLDRSP;
    }

    /* Unpack the key object */
    keyObj->u8Mask = Response.pu8Data[idx++];

    /* Check there is enough room to store the key object in the host buffer.*/
    if ( keyObj->u16KeyLength < VltEndianReadPU16( &Response.pu8Data[idx] ) )
    {
        return ( ERKHPNOROOM );
    }

    keyObj->u16KeyLength = VltEndianReadPU16( &Response.pu8Data[idx] );
    idx += 2u;

    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpyxor( keyObj->pu8Key, 
        &Response.pu8Data[idx], 
        keyObj->u16KeyLength, 
        keyObj->u8Mask );

    idx += keyObj->u16KeyLength;

    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( keyObj->pu8MovingFactor, 
        &Response.pu8Data[idx],  
        VLT_KEY_HOTP_MOVINGFACTOR_LENGTH );

    /* Validate received CRC */
    if( u16ReceivedCrc != u16CalculatedCrc )
    {
        return( ERKHOTPIVLDCRC );
    }
     
    return VLT_OK;
}

#endif /* ( VLT_ENABLE_KEY_HOTP == VLT_ENABLE ) */

#if( VLT_ENABLE_KEY_TOTP == VLT_ENABLE )

VLT_STS VltReadKey_Totp( 
    VLT_KEY_OBJ_TOTP* keyObj,
    VLT_SW *pSW )
{
    /* Start unpacking after the bKeyID */
    idx = 1;

    /*
     * Validate all input parameters.
     */
    if ( ( NULL == keyObj ) ||
         ( NULL == pSW ) ||
         ( NULL == keyObj->pu8Key ) )
    {
        return ( ERKTPNULLPARA );
    }

    /* We're expecting the entire response to be in the buffer */
    if (*pSW != VLT_STATUS_SUCCESS)
    {
        return ERKINVLDRSP;
    }
    

    /* Unpack the key object */
    keyObj->u8Mask = Response.pu8Data[idx++];

    /* Check there is enough room to store the key object in the host buffer.*/
    if ( keyObj->u16KeyLength < VltEndianReadPU16( &Response.pu8Data[idx] ) )
    {
        return ( ERKTPNOROOM );
    }
    
    keyObj->u16KeyLength = VltEndianReadPU16( &Response.pu8Data[idx] );
    idx += 2u;
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpyxor( keyObj->pu8Key, 
        &Response.pu8Data[idx], 
        keyObj->u16KeyLength, 
        keyObj->u8Mask );

    /* Validate received CRC */
    if( u16ReceivedCrc != u16CalculatedCrc )
    {
        return( ERKTOTPIVLDCRC );
    }

    return VLT_OK;
}

#endif /* ( VLT_ENABLE_KEY_TOTP == VLT_ENABLE ) */

#if( VLT_ENABLE_KEY_RSA == VLT_ENABLE )

VLT_STS VltReadKey_RsaPublic( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_RSA_PUB* keyObj,
    VLT_SW *pSW )
{
    enum { NLen, N, ELen, E, Assurance, End };
	VLT_U8 field;
    VLT_STS status;    
    VLT_U16 u16Offset;
    VLT_U16 u16Avail;

    /*
     * Validate all input parameters.
     */
    if ( ( NULL == keyObj ) ||
         ( NULL == pSW ) ||
         ( NULL == keyObj->pu8E ) ||
         ( NULL == keyObj->pu8N ) )
    {
        return ( ERKRPUBNULLPARA );
    }

    
    /* offset into output buffer */
    u16Offset = 0;                     

    /* skip bKeyID since caller handles it */    
    idx = 1;    
    u16Avail  = Response.u16Len - 1u;

    /* Unpack the key object */

    /* We loop until we step beyond the last field. Buffers are incrementally
     * filled with data as it arrives. We can spend multiple iterations filling
     * in a single field. We must cope with values arriving in awkward ways,
     * e.g. a 2-byte field could arrive as the final byte and initial byte of
     * two separate requests. */

    field = (VLT_U8)NLen;
	while (field <= (VLT_U8)E)
    {
        VLT_U16 u16BufLen;
        VLT_U16 u16BufferSize = 0u;
        VLT_U8 *pu8Buf;

        /* Fill the buffer up if it's empty */

        if (u16Avail == 0u)
        {

            status = VltReadKeyCommand( &Command, 
                &Response, 
                u8KeyGroup,
                u8KeyIndex, pSW );

            if (VLT_OK != status)
            {
                return status;
            }

            /* use entire buffer this iteration */            
            idx = 0;
            u16Avail = Response.u16Len;
        }

        /* Turn each field into a buffer length and pointer */

        switch (field)
        {
        case NLen:
            u16BufLen = 2;
            pu8Buf = (VLT_U8 *)((void*)&keyObj->u16NLen);
            u16BufferSize = keyObj->u16NLen;
            break;

        case N:
            u16BufLen = keyObj->u16NLen;
            pu8Buf = keyObj->pu8N;
            break;

        case ELen:
            u16BufLen = 2;
            pu8Buf = (VLT_U8 *)((void*)&keyObj->u16ELen);
            u16BufferSize = keyObj->u16ELen;
            break;

        case E:
            u16BufLen = keyObj->u16ELen;
            pu8Buf = keyObj->pu8E;
            break;

     /*   case Assurance:
            u16BufLen = 1;
            pu8Buf = (VLT_U8 *)&keyObj->u8Assurance;
            break;*/

        default:
            return ERKBADFIELD;
			break; //For MISRA compliancy
        }

        /* Fill the buffer as much as possible */

        {
            VLT_U16 u16Remain;
            VLT_U16 u16Copy;

            u16Remain = u16BufLen - u16Offset;
            if (u16Avail > u16Remain)
            {
                u16Copy = u16Remain;
            }
            else
            {
                u16Copy = u16Avail;
            }

            /* Check there is enough room to store the N - Modulus, 
               and E - Public Exponent before updating NLen or ELen. */ 
            if ( ( ( field == (VLT_U8)NLen ) ||
                   ( field == (VLT_U8)ELen ) ) &&
                   ( u16BufferSize < VltEndianReadPU16( &Response.pu8Data[idx] ) ) )
            {
                return ( ERKRPUBNOROOM );
            }            
            
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy(&pu8Buf[u16Offset], &Response.pu8Data[idx], u16Copy);
            idx += u16Copy;
            u16Offset += u16Copy;
            u16Avail -= u16Copy;

            if (u16Offset == u16BufLen) /* buffer full? */
            {
                /* When reading the length values we accumulate the bytes
                 * piecemeal in the 2-byte value itself, treating it as a small
                 * buffer. Once enough bytes are ready we (may) need to endian
                 * swap them, which we do here. */
                if (field == (VLT_U8)NLen)
                {
                    keyObj->u16NLen = VltEndianReadPU16(pu8Buf);
                }
                if (field == (VLT_U8)ELen)
                {
                    keyObj->u16ELen = VltEndianReadPU16(pu8Buf);
                }

                u16Offset = 0;

                field++; /* move to next field */
            }
        }
    }
    
    /* Validate received CRC */
    if( u16ReceivedCrc != u16CalculatedCrc )
    {
        return( ERKRSAPBIVLDCRC );
    }

    return VLT_OK;
}

VLT_STS VltReadKey_RsaPrivate(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_RSA_PRIV* keyObj,
    VLT_SW *pSW)
{
    enum { Mask, NLen, N, DLen, D, PbGroup, PbIndex, End } ;

	VLT_U8 field;
    VLT_STS status;    
    VLT_U16 u16Offset;
    VLT_U16 u16Avail;
    VLT_U8 u8Mask;

    /*
     * Validate all input parameters.
     */
    if ( ( NULL == keyObj ) ||
         ( NULL == pSW ) ||
         ( NULL == keyObj->pu8D ) ||
         ( NULL == keyObj->pu8N ) )
    {
        return ( ERKRPRIVNULLPARA );
    }

    
    u16Offset = 0;                     /* offset into output buffer */
    
    /* skip bKeyID since caller handles it */
    idx = 1;
    u16Avail = Response.u16Len - 1u ;

    /* Unpack the key object */

    /* We loop until we step beyond the last field. Buffers are incrementally
     * filled with data as it arrives. We can spend multiple iterations filling
     * in a single field. We must cope with values arriving in awkward ways,
     * e.g. a 2-byte field could arrive as the final byte and initial byte of
     * two separate requests. */

    field = (VLT_U8)Mask;
	while(field <= (VLT_U8)PbIndex)
    {
        VLT_U16 u16BufLen;
        VLT_U16 u16BufferSize = 0;
        VLT_U8 *pu8Buf;

        /* Fill the buffer up if it's empty */

        if (u16Avail == 0u)
        {
            status = VltReadKeyCommand( &Command, &Response, u8KeyGroup,
                u8KeyIndex, pSW );
            if (VLT_OK != status)
            {
                return status;
            }

            /* use entire buffer this iteration */
            idx = 0;
            u16Avail = Response.u16Len;
        }

        /* Turn each field into a buffer length and pointer */
        u8Mask = 0;

        switch (field)
        {
            case Mask:
                u16BufLen = 1;
                pu8Buf = &keyObj->u8Mask;
                break;

            case NLen:
                u16BufLen = 2;
                pu8Buf = (VLT_U8 *) ((void*)&keyObj->u16NLen);
                u16BufferSize = keyObj->u16NLen;
                break;

            case N:
                u16BufLen = keyObj->u16NLen;
                pu8Buf = keyObj->pu8N;
                break;

            case DLen:
                u16BufLen = 2;
                pu8Buf = (VLT_U8 *) ((void*)&keyObj->u16DLen);
                u16BufferSize = keyObj->u16DLen;
                break;

            case D:
                u16BufLen = keyObj->u16DLen;
                pu8Buf = keyObj->pu8D;
                u8Mask = keyObj->u8Mask;
                break;

            case PbGroup:
                u16BufLen = 1;
                pu8Buf = (VLT_U8 *)&keyObj->u8PublicKeyGroup;                
                break;

            case PbIndex:
                u16BufLen = 1;
                pu8Buf = (VLT_U8 *)&keyObj->u8PublicKeyIndex;                
                break;

            default:
                return ERKBADFIELD;
				break; //For MISRA compliancy
        }

        /* Fill the buffer as much as possible */
        {
            VLT_U16 u16Remain;
            VLT_U16 u16Copy;

            u16Remain = u16BufLen - u16Offset;
            if( u16Avail > u16Remain )
            {
                u16Copy = u16Remain;
            }
            else
            {
                u16Copy = u16Avail;
            }

            /* Check there is enough room to store the N - Modulus, 
               and D - Private Exponent before updating NLen or DLen. */ 
            if ( ( ( field == (VLT_U8)NLen ) ||
                   ( field == (VLT_U8)DLen ) ) &&
                   ( u16BufferSize < VltEndianReadPU16( &Response.pu8Data[idx] ) ) )
            {
                return ( ERKRPRIVNOROOM );
            } 

            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpyxor( &pu8Buf[u16Offset], &Response.pu8Data[idx], u16Copy, u8Mask );
            idx += u16Copy;
            u16Offset += u16Copy;
            u16Avail -= u16Copy;

            if( u16Offset == u16BufLen ) /* buffer full? */
            {
                /* When reading the length values we accumulate the bytes
                 * piecemeal in the 2-byte value itself, treating it as a small
                 * buffer. Once enough bytes are ready we (may) need to endian
                 * swap them, which we do here. */

                if (field == (VLT_U8)NLen)
                {
                    keyObj->u16NLen = VltEndianReadPU16(pu8Buf);
                }
                if (field == (VLT_U8)DLen)
                {
                    keyObj->u16DLen = VltEndianReadPU16(pu8Buf);
                }

                u16Offset = 0;

                /* move to next field */
                field++; 
            }
        }
    }

    /* Validate received CRC */
    if( u16ReceivedCrc != u16CalculatedCrc )
    {
        return( ERKRSAPRIVLDCRC );
    }
    
    return VLT_OK;
}

VLT_STS VltReadKey_RsaPrivateCrt( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_RSA_PRIV_CRT* keyObj,
    VLT_SW *pSW )
{    
    enum { Mask, PLen, P, Q, DP, DQ, IP, PbGroup, PbIndex, End };
	VLT_U8			field;
    VLT_STS       status;
    VLT_U16       u16Offset;
    VLT_U16       u16Avail;
    VLT_U8        u8Mask;

    /*
     * Validate all input parameters.
     */
    if ( ( NULL == keyObj ) ||
         ( NULL == pSW ) ||
         ( NULL == keyObj->pu8Dp ) ||
         ( NULL == keyObj->pu8Dq ) ||
         ( NULL == keyObj->pu8Ip ) ||
         ( NULL == keyObj->pu8P ) ||
         ( NULL == keyObj->pu8Q ) )
    {
        return ( ERKRCRTNULLPARA );
    }


    /* offset into output buffer */
    u16Offset = 0;                     
    
    /* skip bKeyID since caller handles it */        
    idx = 1;
    u16Avail = Response.u16Len - 1u ;

    /* Unpack the key object */

    /* We loop until we step beyond the last field. Buffers are incrementally
     * filled with data as it arrives. We can spend multiple iterations filling
     * in a single field. We must cope with values arriving in awkward ways,
     * e.g. a 2-byte field could arrive as the final byte and initial byte of
     * two separate requests. */

    field = (VLT_U8)Mask;
	while (field <= (VLT_U8)PbIndex)
    {
        VLT_U16 u16BufLen;
        VLT_U8 *pu8Buf;

        /* Fill the buffer up if it's empty */

        if( 0u == u16Avail )
        {

            status = VltReadKeyCommand( &Command, &Response, u8KeyGroup,
                u8KeyIndex, pSW);

            if (VLT_OK != status)
            {
                return status;
            }

            /* use entire buffer this iteration */
            idx = 0;
            u16Avail = Response.u16Len ;
        }

        /* Turn each field into a buffer length and pointer */
        u8Mask = 0;

        switch (field)
        {
            case Mask:
                u16BufLen = 1;
                pu8Buf    = &keyObj->u8Mask;
                break;

            case PLen:
                u16BufLen = 2;
                pu8Buf    = (VLT_U8 *) ((void*)&keyObj->u16PLen);
                break;

            case P:
                u16BufLen = keyObj->u16PLen;
                pu8Buf    = keyObj->pu8P;
                u8Mask    = keyObj->u8Mask;
                break;

            case Q:
                u16BufLen = keyObj->u16PLen;
                pu8Buf    = keyObj->pu8Q;
                u8Mask    = keyObj->u8Mask;
                break;

            case DP:
                u16BufLen = keyObj->u16PLen;
                pu8Buf    = keyObj->pu8Dp;
                u8Mask    = keyObj->u8Mask;
                break;

            case DQ:
                u16BufLen = keyObj->u16PLen;
                pu8Buf    = keyObj->pu8Dq;
                u8Mask    = keyObj->u8Mask;
                break;

            case IP:
                u16BufLen = keyObj->u16PLen;
                pu8Buf    = keyObj->pu8Ip;
                u8Mask    = keyObj->u8Mask;
                break;

            case PbGroup:
                u16BufLen = 1;
                pu8Buf = (VLT_U8 *)&keyObj->u8PublicKeyGroup;                
                break;

            case PbIndex:
                u16BufLen = 1;
                pu8Buf = (VLT_U8 *)&keyObj->u8PublicKeyIndex;                
                break;

            default:
                return ERKBADFIELD;
				break; //For MISRA compliancy
        }

        /* Fill the buffer as much as possible */

        {
            VLT_U16 u16Remain;
            VLT_U16 u16Copy;

            u16Remain = u16BufLen - u16Offset;
            if (u16Avail > u16Remain)
            {
                u16Copy = u16Remain;
            }
            else
            {
                u16Copy = u16Avail;
            }

            /* Check there is enough room to store the prime P 
               before updating PLen. */
            if ( ( field == (VLT_U8)PLen ) &&
                 ( keyObj->u16PLen < 
                   VltEndianReadPU16( &Response.pu8Data[idx] ) ) )
            {
                return ( ERKRCRTNOROOM );
            }

            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpyxor( &pu8Buf[u16Offset], &Response.pu8Data[idx], u16Copy, u8Mask);
            idx += u16Copy;
            u16Offset += u16Copy;
            u16Avail -= u16Copy;

            if (u16Offset == u16BufLen) /* buffer full? */
            {
                /* When reading the length values we accumulate the bytes
                 * piecemeal in the 2-byte value itself, treating it as a small
                 * buffer. Once enough bytes are ready we (may) need to endian
                 * swap them, which we do here. */

                if (field == (VLT_U8)PLen)
                {
                    keyObj->u16PLen = VltEndianReadPU16(pu8Buf);
                }

                u16Offset = 0;

                field++; /* move to next field */
            }
        }
    }
    
    /* Validate received CRC */
    if( u16ReceivedCrc != u16CalculatedCrc )
    {
        return( ERKRSACRIVLDCRC );
    }

    return VLT_OK;
}

#endif /* ( VLT_ENABLE_KEY_RSA == VLT_ENABLE ) */

#if( VLT_ENABLE_KEY_ECDSA == VLT_ENABLE )
#if(VLT_ENABLE_READ_KEY_ECC_PUB == VLT_ENABLE)
VLT_STS VltReadKey_EcdsaPublic(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_ECDSA_PUB* keyObj,
    VLT_SW *pSW)
{    
    enum { QLen, Qx, Qy, DpGroup, DpIndex,/* Assurance,*/ End };

	VLT_U8 field;
    VLT_STS       status; 
    VLT_U16       u16Offset;
    VLT_U16       u16Avail;

    /*
     * Validate all input parameters.
     */
    if ( ( NULL == keyObj ) ||
         ( NULL == pSW ) ||
         ( NULL == keyObj->pu8Qx ) ||
         ( NULL == keyObj->pu8Qy ) )
    {
        return ( ERKEPUBNULLPARA );
    }


    /* offset into output buffer */
    u16Offset = 0;                     

    /* skip bKeyID since caller handles it */
    idx = 1;    
    u16Avail  = Response.u16Len  - 1u;

    /* Unpack the key object */

    /* We loop until we step beyond the last field. Buffers are incrementally
     * filled with data as it arrives. We can spend multiple iterations filling
     * in a single field. We must cope with values arriving in awkward ways,
     * e.g. a 2-byte field could arrive as the final byte and initial byte of
     * two separate requests. */
	
	field = (VLT_U8)QLen;
	while( field < (VLT_U8)End)
    {
        VLT_U16 u16BufLen;
        VLT_U16 u16BufferSize = 0u;
        VLT_U8 *pu8Buf;

        /* Fill the buffer up if it's empty */

        if (u16Avail == 0u)
        {
            status = VltReadKeyCommand( &Command, &Response, u8KeyGroup,
                u8KeyIndex, pSW );

            if (VLT_OK != status)
            {
                return status;
            }

            /* use entire buffer this iteration */
            idx = 0; 
            u16Avail = Response.u16Len;
        }

        /* Turn each field into a buffer length and pointer */

        switch( field )
        {
            case QLen:
                u16BufLen = 2;
                pu8Buf = (VLT_U8 *) ((void*)&keyObj->u16QLen);
                u16BufferSize = keyObj->u16QLen;
                break;

            case Qx:
                u16BufLen = keyObj->u16QLen;
                pu8Buf = keyObj->pu8Qx;
                break;

            case Qy:
                u16BufLen = keyObj->u16QLen;
                pu8Buf = keyObj->pu8Qy;
                break;

            case DpGroup:
                u16BufLen = 1;
                pu8Buf = (VLT_U8 *)((void*)&keyObj->u8DomainParamsGroup);                
                break;

            case DpIndex:
                u16BufLen = 1;
                pu8Buf = (VLT_U8 *)((void*)&keyObj->u8DomainParamsIndex);                
                break;

         /*   case Assurance:
                u16BufLen = 1;
                pu8Buf = (VLT_U8 *)&keyObj->u8Assurance;
                break;*/

            default:
                return ERKBADFIELD;
				break; //For MISRA compliancy
        }

        /* Fill the buffer as much as possible */

        {
            VLT_U16 u16Remain;
            VLT_U16 u16Copy;

            u16Remain = u16BufLen - u16Offset;
            if (u16Avail > u16Remain)
            {
                u16Copy = u16Remain;
            }
            else
            {
                u16Copy = u16Avail;
            }

            if( ( field == (VLT_U8)QLen ) &&
                ( u16BufferSize < VltEndianReadPU16( &Response.pu8Data[idx] ) ) )
            {
                return ( ERKEPUBNOROOM );
            }

            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy(&pu8Buf[u16Offset], &Response.pu8Data[idx], u16Copy);
            idx += u16Copy;
            u16Offset += u16Copy;
            u16Avail -= u16Copy;

            if (u16Offset == u16BufLen) /* buffer full? */
            {
                /* When reading the length values we accumulate the bytes
                 * piecemeal in the 2-byte value itself, treating it as a small
                 * buffer. Once enough bytes are ready we (may) need to endian
                 * swap them, which we do here. */

                if (field == (VLT_U8)QLen)
                {
                    keyObj->u16QLen = VltEndianReadPU16(pu8Buf);
                }

                u16Offset = 0;

                /* move to next field */
                field++; 
            }
        }
    }

    /* Validate received CRC */
    if( u16ReceivedCrc != u16CalculatedCrc )
    {
        return( ERKECDSAPBIVLDCRC );
    }

    return VLT_OK;
}
#endif

#if(VLT_ENABLE_READ_KEY_ECC_PRIV == VLT_ENABLE)
VLT_STS VltReadKey_EcdsaPrivate( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_ECDSA_PRIV* keyObj,
    VLT_SW *pSW )
{    
    enum { Mask, DLen, D, DpGroup, DpIndex, PubGroup, PubIndex, End };
	VLT_U8 field;
    VLT_STS       status;    
    VLT_U16       u16Offset;
    VLT_U16       u16Avail;
    VLT_U8        u8Mask;

    /*
     * Validate all input parameters.
     */
    if ( ( NULL == keyObj ) ||
         ( NULL == pSW ) ||         
         ( NULL == keyObj->pu8D ) )
    {
        return ( ERKEPRIVNULLPARA );
    }


    /* offset into output buffer */
    u16Offset = 0;                     
    
    /* skip bKeyID since caller handles it */
    idx = 1;
    u16Avail  = Response.u16Len - 1u;
    /* Unpack the key object */

    /* We loop until we step beyond the last field. Buffers are incrementally
     * filled with data as it arrives. We can spend multiple iterations filling
     * in a single field. We must cope with values arriving in awkward ways,
     * e.g. a 2-byte field could arrive as the final byte and initial byte of
     * two separate requests. */

    field = (VLT_U8)Mask;
	while (field <= (VLT_U8)PubIndex)
    {
        VLT_U16 u16BufLen;
        VLT_U16 u16BufferSize = 0;
        VLT_U8 *pu8Buf;

        /* Fill the buffer up if it's empty */

        if (u16Avail == 0u)
        {
            status = VltReadKeyCommand( &Command, &Response, u8KeyGroup,
                u8KeyIndex, pSW );

            if (VLT_OK != status)
            {
                return status;
            }

            /* use entire buffer this iteration */
            idx = 0; 
            u16Avail = Response.u16Len;
        }

        /* Turn each field into a buffer length and pointer */
        u8Mask = 0;

        switch( field )
        {
            case Mask:
                u16BufLen = 1;
                pu8Buf    = &keyObj->u8Mask;
                break;

            case DLen:
                u16BufLen = 2;
                pu8Buf    = (VLT_U8 *)((void*)&keyObj->u16DLen);
                u16BufferSize = keyObj->u16DLen;
                break;

            case D:
                u16BufLen = keyObj->u16DLen;
                pu8Buf    = keyObj->pu8D;
                u8Mask    = keyObj->u8Mask;
                break;

            case DpGroup:
                u16BufLen = 1;
                pu8Buf = (VLT_U8 *)((void*)&keyObj->u8DomainParamsGroup);
                break;

            case DpIndex:
                u16BufLen = 1;
                pu8Buf = (VLT_U8 *)((void*)&keyObj->u8DomainParamsIndex);
                break;

            case PubGroup:
                u16BufLen = 1;
                pu8Buf = (VLT_U8 *)((void*)&keyObj->u8PublicKeyGroup);
                break;

            case PubIndex:
                u16BufLen = 1;
                pu8Buf = (VLT_U8 *)((void*)&keyObj->u8PublicKeyIndex);
                break;

            default:
                return ERKBADFIELD;
				break;
        }

        /* Fill the buffer as much as possible */

        {
            VLT_U16 u16Remain;
            VLT_U16 u16Copy;

            u16Remain = u16BufLen - u16Offset;
            if( u16Avail > u16Remain )
            {
                u16Copy = u16Remain;
            }
            else
            {
                u16Copy = u16Avail;
            }

            if( ( field == (VLT_U8)DLen ) &&
                ( u16BufferSize < VltEndianReadPU16( &Response.pu8Data[idx] ) ) )
            {
                return ( ERKEPRIVNOROOM );
            }

            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpyxor( &pu8Buf[u16Offset], &Response.pu8Data[idx], u16Copy, u8Mask );
            idx += u16Copy;
            u16Offset += u16Copy;
            u16Avail  -= u16Copy;

            if (u16Offset == u16BufLen) /* buffer full? */
            {
                /* When reading the length values we accumulate the bytes
                 * piecemeal in the 2-byte value itself, treating it as a small
                 * buffer. Once enough bytes are ready we (may) need to endian
                 * swap them, which we do here. */
                if( field == (VLT_U8)DLen )
                {
                    keyObj->u16DLen = VltEndianReadPU16(pu8Buf);
                }  

                u16Offset = 0;

                /* move to next field */
                field++; 
            }
        }
    }

    /* Validate received CRC */
    if( u16ReceivedCrc != u16CalculatedCrc )
    {
        return( ERKECDSAPRIVLDCRC );
    }

    return VLT_OK;
}
#endif //(VLT_ENABLE_READ_KEY_ECC_PRIV == VLT_ENABLE)

#if(VLT_ENABLE_READ_KEY_ECC_PARAMS == VLT_ENABLE)
VLT_STS VltReadKey_EcdsaParams( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_ECDSA_PARAMS* keyObj,
    VLT_SW *pSW )
{    
    enum { QLen, Q, Gx, Gy, Gz, A, B, NLen, N, H, Assurance, End };

	VLT_U8 field;
    VLT_STS status;
    VLT_U16 u16Offset;
    VLT_U16 u16Avail;


    /*
     * Validate all input parameters.
     */
    if( ( NULL == keyObj ) ||
        ( NULL == pSW ) ||
        ( NULL == keyObj->pu8A ) ||
        ( NULL == keyObj->pu8B ) ||
        ( NULL == keyObj->pu8Gx )||
        ( NULL == keyObj->pu8Gy )||
        ( NULL == keyObj->pu8Gz )||
        ( NULL == keyObj->pu8N ) ||
        ( NULL == keyObj->pu8Q ) )
    {
        return ( ERKECDSAPARAMSNULLPARA );
    }

    /* offset into output buffer */
    u16Offset = 0;                     
    
    /* skip bKeyID since caller handles it */
    idx = 1;
    u16Avail  = Response.u16Len - 1u;

    /* Unpack the key object */

    /* We loop until we step beyond the last field. Buffers are incrementally
     * filled with data as it arrives. We can spend multiple iterations filling
     * in a single field. We must cope with values arriving in awkward ways,
     * e.g. a 2-byte field could arrive as the final byte and initial byte of
     * two separate requests. */

    field = (VLT_U8)QLen; 
	while (field <= (VLT_U8)Assurance)
    {
        VLT_U16 u16BufLen;
        VLT_U16 u16BufferSize=0;
        VLT_U8 *pu8Buf;

        /* Fill the buffer up if it's empty */

        if( u16Avail == 0u )
        {
            status = VltReadKeyCommand( &Command, &Response, u8KeyGroup,
                u8KeyIndex, pSW );

            if (VLT_OK != status)
            {
                return status;
            }

            /* use entire buffer this iteration */
            idx = 0; 
            u16Avail = Response.u16Len;
        }

        /* Turn each field into a buffer length and pointer */
        switch( field )
        {
            case QLen:
                u16BufLen = 2;
                pu8Buf = (VLT_U8 *)((void*)&keyObj->u16QLen);
                u16BufferSize = keyObj->u16QLen;
                break;

            case Q:
                u16BufLen = keyObj->u16QLen;
                pu8Buf = (VLT_U8 *)((void*)keyObj->pu8Q);
                break;

            case Gx:
                u16BufLen = keyObj->u16QLen;
                pu8Buf = (VLT_U8 *)((void*)keyObj->pu8Gx);
                break;

            case Gy:
                u16BufLen = keyObj->u16QLen;
                pu8Buf = (VLT_U8 *)((void*)keyObj->pu8Gy);
                break;

            case Gz:
                u16BufLen = keyObj->u16QLen;
                pu8Buf = (VLT_U8 *)((void*)keyObj->pu8Gz);
                break;

            case A:
                u16BufLen = keyObj->u16QLen;
                pu8Buf = (VLT_U8 *)((void*)keyObj->pu8A);
                break;

            case B:
                u16BufLen = keyObj->u16QLen;
                pu8Buf = (VLT_U8 *)((void*)keyObj->pu8B);
                break;

            case NLen:
                u16BufLen = 2;
                pu8Buf = (VLT_U8 *)((void*)&keyObj->u16NLen);
                u16BufferSize = keyObj->u16NLen;
                break;

            case N:
                u16BufLen = keyObj->u16NLen;
                pu8Buf = (VLT_U8 *)((void*)keyObj->pu8N);
                break;

            case H:
                u16BufLen = 4;
                pu8Buf = (VLT_U8 *)((void*)&keyObj->u32H);
                break;

            case Assurance:
                u16BufLen = 1;
                pu8Buf = (VLT_U8 *)((void*)&keyObj->enAssurance);
                break;

            default:
                return ERKECDSAPARAMSBADFIELD;
				break; //For MISRA compliancy
        }

        /* Fill the buffer as much as possible */
        {
            VLT_U16 u16Remain;
            VLT_U16 u16Copy;

            u16Remain = u16BufLen - u16Offset;
            if (u16Avail > u16Remain)
            {
                u16Copy = u16Remain;
            }
            else
            {
                u16Copy = u16Avail;
            }

            if( ( ( field == (VLT_U8)QLen ) ||
                ( field == (VLT_U8)NLen ) ) &&
                ( u16BufferSize < VltEndianReadPU16( &Response.pu8Data[idx] ) ) )
            {
                return ( ERKECDSAPARAMSNOROOM );
            }
            
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy( &pu8Buf[u16Offset], &Response.pu8Data[idx], u16Copy );
            idx += u16Copy;
            u16Offset += u16Copy;
            u16Avail -= u16Copy;

             /* buffer full? */
            if( u16Offset == u16BufLen )
            {
                /* When reading the length values we accumulate the bytes
                 * piecemeal in the 2-byte value itself, treating it as a small
                 * buffer. Once enough bytes are ready we (may) need to endian
                 * swap them, which we do here. */

                if( field == (VLT_U8)QLen )
                {
                    keyObj->u16QLen = VltEndianReadPU16(pu8Buf);                   
                }

                if( field == (VLT_U8)NLen )
                {
                    keyObj->u16NLen = VltEndianReadPU16(pu8Buf);
                }
                
                if( field == (VLT_U8)H )
                {
                    keyObj->u32H = VltEndianReadPU32(pu8Buf);
                }
                
                u16Offset = 0;

                field++; /* move to next field */
            }
        }
    }
    
    /* Validate received CRC */
    if( u16ReceivedCrc != u16CalculatedCrc )
    {
        return( ERKECDSAPARAMSIVLDCRC );
    }

    return VLT_OK;
}
#endif /* ( VLT_ENABLE_KEY_ECDSA == VLT_ENABLE ) */
#endif


#if( VLT_ENABLE_KEY_IDENTIFIER == VLT_ENABLE )
#if(VLT_ENABLE_READ_KEY_IDENTIFIER == VLT_ENABLE)
VLT_STS VltReadKey_IdKey( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJ_ID* keyObj,
    VLT_SW *pSW )
{    
    enum { StrLen, String, End };

	VLT_U8 field;
    VLT_STS status;
    VLT_U16 u16Offset;
    VLT_U16 u16Avail;

    /*
     * Validate all input parameters.
     */
    if( ( NULL == keyObj ) ||
        ( NULL == pSW ) ||
        ( NULL == keyObj->pu8StringId ) )
    {
        return ( ERKIDNULLPARA );
    }

    /* offset into output buffer */
    u16Offset = 0;                     
    
    /* skip bKeyID since caller handles it */
    idx = 1;
    u16Avail  = Response.u16Len - 1u;

    /* Unpack the key object */

    /* We loop until we step beyond the last field. Buffers are incrementally
     * filled with data as it arrives. We can spend multiple iterations filling
     * in a single field. We must cope with values arriving in awkward ways,
     * e.g. a 2-byte field could arrive as the final byte and initial byte of
     * two separate requests. */

    field = (VLT_U8)StrLen;
	while (field <= (VLT_U8)String)
    {
        VLT_U16 u16BufLen;
        VLT_U16 u16BufferSize = 0u;
        VLT_U8 *pu8Buf;

        /* Fill the buffer up if it's empty */

        if( u16Avail == 0u )
        {
            status = VltReadKeyCommand( &Command, &Response, u8KeyGroup,
                u8KeyIndex, pSW );

            if (VLT_OK != status)
            {
                return status;
            }

            /* use entire buffer this iteration */
            idx = 0; 
            u16Avail = Response.u16Len;
        }

        /* Turn each field into a buffer length and pointer */
        switch( field )
        {
            case StrLen:
                u16BufLen = 2;
                pu8Buf = (VLT_U8 *)((void*)&keyObj->u16StringLen);
                u16BufferSize = keyObj->u16StringLen;
                break;

            case String:
                u16BufLen = keyObj->u16StringLen;
                pu8Buf = (VLT_U8 *)((void*)keyObj->pu8StringId);
                break;

            default:
                return ERKIDBADFIELD;
				break; //For MISRA compliancy
        }

        /* Fill the buffer as much as possible */
        {
            VLT_U16 u16Remain;
            VLT_U16 u16Copy;

            u16Remain = u16BufLen - u16Offset;
            if (u16Avail > u16Remain)
            {
                u16Copy = u16Remain;
            }
            else
            {
                u16Copy = u16Avail;
            }

            if( ( field == (VLT_U8)StrLen ) &&
                ( u16BufferSize < VltEndianReadPU16( &Response.pu8Data[idx] ) ) )
            {
                return ( ERKIDNOROOM );
            }
            
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy( &pu8Buf[u16Offset], &Response.pu8Data[idx], u16Copy );
            idx += u16Copy;
            u16Offset += u16Copy;
            u16Avail -= u16Copy;

             /* buffer full? */
            if( u16Offset == u16BufLen )
            {
                /* When reading the length values we accumulate the bytes
                 * piecemeal in the 2-byte value itself, treating it as a small
                 * buffer. Once enough bytes are ready we (may) need to endian
                 * swap them, which we do here. */

                if( field == (VLT_U8)StrLen )
                {
                    keyObj->u16StringLen = VltEndianReadPU16(pu8Buf);                   
                }
                               
                u16Offset = 0;

                field++; /* move to next field */
            }
        }
    }
    
    /* Validate received CRC */
    if( u16ReceivedCrc != u16CalculatedCrc )
    {
        return( ERKIDIVLDCRC );
    }

    return VLT_OK;
}
#endif //(VLT_ENABLE_READ_KEY_IDENTIFIER == VLT_ENABLE)
#endif /* ( VLT_ENABLE_KEY_IDENTIFIER == VLT_ENABLE ) */
#endif