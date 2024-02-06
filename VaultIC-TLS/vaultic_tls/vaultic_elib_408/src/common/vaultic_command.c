/**
* @file	   vaultic_command.c
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

#include "vaultic_common.h"
#include "vaultic_apdu.h"
#include "vaultic_api.h"
#include <comms/vaultic_comms.h>
#include "vaultic_utils.h"
#include "vaultic_mem.h"
#include "vaultic_command.h"

/**
 * Externs 
 */
extern VLT_MEM_BLOB Command;                            /* declared in vaultic_api.c */
extern VLT_MEM_BLOB Response;                           /* declared in vaultic_api.c */


#if(VLT_ENABLE_NO_GET_RESPONSE  != VLT_ENABLE)                                                        
/* -------------------------------------------------------------------------- */
/**
 * \fn VltGetResponse
 *
 * \brief Issues a Get Response command.
 *
 * \param[in]  command  Command blob.
 * \param[in]  response Response blob.
 * \param[out] pSW      Status word.
 *
 * \return Status.
 */
static VLT_STS VltGetResponse(VLT_MEM_BLOB *command, 
    VLT_MEM_BLOB *response,
    VLT_SW *pSW)
{
    VLT_STS status;
    VLT_U8 *pu8Data;
    VLT_U16 idx;

    if ((*pSW & 0xFF00u) != VLT_STATUS_GET_RESPONSE)
    {
        return EGTBADSW;
    }

    /* Build APDU for Get Response */

    pu8Data = command->pu8Data;
    idx = 0;

    pu8Data[idx++] = 0x00;
    pu8Data[idx++] = VLT_INS_GET_RESPONSE;
    pu8Data[idx++] = 0x00;
    pu8Data[idx++] = 0x00;
    pu8Data[idx++] = (VLT_U8)LEXP(*pSW & 0xFFu);

    /* Send the command */
    *pSW = VLT_STATUS_NONE;
    command->u16Len = (VLT_U16) (idx);

    status = VltCommsDispatchCommand(command, response);
    if (VLT_OK != status)
    {
        return status;
    }

    if (response->u16Len < VLT_SW_SIZE)
    {
        return EGTINVLDSWSZ;
    }

    *pSW = VltEndianReadPU16(response->pu8Data + response->u16Len - VLT_SW_SIZE);

    return status;
}
#endif

/* -------------------------------------------------------------------------- */


VLT_STS VltCommand(VLT_MEM_BLOB *command,
    VLT_MEM_BLOB *response,
    VLT_U16 u16Send,
    VLT_U16 u16Require,
    VLT_SW *pSW)
{
    VLT_STS status;
    VLT_U16 u16Len;    
#if (VLT_ENABLE_NO_GET_RESPONSE  != VLT_ENABLE)
    VLT_U8 u8SWHi;
#endif
    VLT_U8 abHeader[VLT_APDU_TYPICAL_HEADER_SZ];

    *pSW = VLT_STATUS_NONE;

    /* Save a copy of the APDU in case it needs to be re-issued. */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( abHeader, command->pu8Data, NELEMS(abHeader) );

#if (VLT_ENABLE_NO_GET_RESPONSE != VLT_ENABLE)
    do
    {
#endif
        /* Send the command */

        command->u16Len = u16Send;

        status = VltCommsDispatchCommand(command, response);

        if( status != VLT_OK )
        {
            return status;
        }

        if( response->u16Len < VLT_SW_SIZE )
        {
            return ECINVLDSWSZ;
        }

        u16Len = response->u16Len - VLT_SW_SIZE;

        *pSW = VltEndianReadPU16(response->pu8Data + u16Len);

#if (VLT_ENABLE_NO_GET_RESPONSE  != VLT_ENABLE)

        /* We may have an immediate response, or be instructed to call Get
         * Response, or be instructed to re-issue the command with a corrected
         * P3 value.
         */
        u8SWHi = (VLT_U8)(*pSW >> 8);

        switch (u8SWHi)
        {
        case VLT_STATUS_GET_RESPONSE >> 8:            

            /* Retrieve response data then check its size. */
            status = VltGetResponse(command, response, pSW);

            if (status != VLT_OK)
            {
                return status;
            }

            u16Len = response->u16Len - VLT_SW_SIZE;

            break;

        case VLT_STATUS_REISSUE >> 8:

            command->pu8Data[4] = (VLT_U8)(*pSW & 0xFFu);      

            /* Re-issue the command with the corrected P3. */
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy(command->pu8Data, abHeader, VLT_APDU_TYPICAL_HEADER_SZ - 1u);
            command->pu8Data[4] = (VLT_U8)(*pSW & 0xFFu);
            *pSW = VLT_STATUS_NONE;

            break;

        default:
            break;
        }

    }
    while (u8SWHi == (VLT_STATUS_REISSUE >> 8));
#endif

    if( u16Len < u16Require )
    {
        return ECINVLDRSP;
    }

    return status;
}

/* -------------------------------------------------------------------------- */
#if (VLT_ENABLE_NO_CMD_CHAINING != VLT_ENABLE)
    VLT_STS VltCase4(VLT_U8 u8Ins,
    VLT_U8 u8P2,
    VLT_U32 u32SrcLen,
    const VLT_U8 *pu8Src,
    VLT_U32 *pu32DstLen,
    VLT_U32 u32DstCapacity,
    VLT_U8 *pu8Dst,
    VLT_SW *pSW)
{
    VLT_STS status;
    VLT_U16 u16MaxChunk;
    VLT_U32 u32Remaining;
    VLT_U8 *pu8Out;
    VLT_U8 *pu8OutEnd;
    VLT_U16 u16Idx; 
	VLT_U8 lastCmdClass = VLT_CLA_NO_CHANNEL;
    VLT_U32 u32ResponseLen;

    if ((0u == u32SrcLen && NULL != pu8Src) ||
        (0u != u32SrcLen && NULL == pu8Src) ||
        NULL == pu32DstLen  ||
        0u    == u32DstCapacity ||
        NULL == pu8Dst      ||
        NULL == pSW)
    {
        return EC4NULLPARA;
    }

    *pSW = VLT_STATUS_NONE;

    /* We need to split the data up into chunks, the size of which the comms
     * layer tells us. */

    u16MaxChunk  = VltCommsGetMaxSendSize();

    u32Remaining = u32SrcLen;

    pu8Out = pu8Dst;
    pu8OutEnd = &pu8Dst[u32DstCapacity];
    u32ResponseLen = 0;

    do
    {
        VLT_U16 u16Chunk;

        /* Build APDU. We have to do this on every iteration as the output of
         * the previous iteration will have overwritten it (assuming a shared
         * buffer). */
		u16Idx = VLT_APDU_DATA_OFFSET ;

		if ( VLT_STATUS_RESPONDING == *pSW )
		{
			u16Chunk =  0; 
			Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = lastCmdClass; 
			Command.pu8Data[ VLT_APDU_INS_OFFSET ] = u8Ins;
			Command.pu8Data[ VLT_APDU_P1_OFFSET ] = 0;
			Command.pu8Data[ VLT_APDU_P2_OFFSET ] = u8P2;
			Command.pu8Data[ VLT_APDU_P3_OFFSET ] = 0;
			Command.pu8Data[ VLT_APDU_P3_OFFSET ] = LIN(WRAPPED_BYTE(u16Chunk));
		}
		else
		{
			if (u32Remaining > u16MaxChunk)
			{
				u16Chunk = u16MaxChunk;

//#if(VAULT_IC_TARGET == VAULTIC4XX)
#if (VAULT_IC_VERSION == VAULTIC_420_1_2_X)
				//Workaround for GCM encryption issue : JIRA SDAT98FW-660 (VIC_420_1_2_X only)
				if (u8Ins == VLT_INS_ENCRYPT_DECRYPT)
				{
					VLT_U32 nextBlockSize = u32Remaining - u16MaxChunk;
					if (nextBlockSize > 1u && nextBlockSize < 11u)
					{
						u16Chunk  = (VLT_U16)(u32Remaining/2u);
					}
				}
#endif
				Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = VLT_CLA_CHAINING;
				lastCmdClass = VLT_CLA_CHAINING;
			}
			else
			{
					u16Chunk = (VLT_U16) u32Remaining;

					Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = VLT_CLA_NO_CHANNEL; 
					lastCmdClass = VLT_CLA_NO_CHANNEL;
			}
			Command.pu8Data[ VLT_APDU_INS_OFFSET ] = u8Ins;
			Command.pu8Data[ VLT_APDU_P1_OFFSET ] = 0;
			Command.pu8Data[ VLT_APDU_P2_OFFSET ] = u8P2;
			Command.pu8Data[ VLT_APDU_P3_OFFSET ] = LIN(WRAPPED_BYTE(u16Chunk));

			if( 0u != u16Chunk )
			{
				/* Build Data In */

				/*
				* No need to check the return type as pointer has been validated
				*/
				if (pu8Src == NULL)
				{
					return EC4NULLPARA;
				}
				(void)host_memcpy( &Command.pu8Data[u16Idx], pu8Src, u16Chunk );
				u16Idx += u16Chunk;
				pu8Src = &pu8Src[u16Chunk];
			}
		}
        /* Send the command */

        status = VltCommand( &Command, &Response, u16Idx, 0, pSW );

        if (VLT_OK != status)
        {
            return status;
        }

        /* How big is the response? */
        Response.u16Len -= VLT_SW_SIZE;

        /* Copy */
        if( ( &pu8Out[Response.u16Len] ) > pu8OutEnd )
        {
            /* ran out of output buffer space */
            return( EC4NOROOM ); 
        }

        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_memcpy( pu8Out, Response.pu8Data, Response.u16Len );
        pu8Out = &pu8Out[Response.u16Len];
        u32ResponseLen += Response.u16Len;

        /* Check response code */
        switch( *pSW )
        {
            case VLT_STATUS_COMPLETED:
            case VLT_STATUS_RESPONDING:
            case VLT_STATUS_SUCCESS:
#ifdef VLT_STATUS_NEXT_TAG_PART_EXPECTED
            case VLT_STATUS_NEXT_TAG_PART_EXPECTED:
#endif
                break;
            case VLT_STATUS_NONE: 
                return( status );
				break; //For MISRA compliancy
            default:
                return VLT_OK; /* unexpected status word */
				break; //For MISRA compliancy
        }

        u32Remaining -= u16Chunk;
    }
    while (u32Remaining > 0u || *pSW == VLT_STATUS_RESPONDING);

    /* Report the final amount of data produced */
    //*pu32DstLen = (VLT_U32)(pu8Out - pu8Dst);
    *pu32DstLen =  u32ResponseLen;

    return status;
}
#else
VLT_STS VltCase4(VLT_U8 u8Ins,
    VLT_U8 u8P2,
    VLT_U32 u32SrcLen,
    const VLT_U8 *pu8Src,
    VLT_U32 *pu32DstLen,
    VLT_U32 u32DstCapacity,
    VLT_U8 *pu8Dst,
    VLT_SW *pSW)
{
    VLT_STS status;

    if(  0u == u32SrcLen ||
         NULL == pu8Src ||
         NULL == pu32DstLen ||
         0u == u32DstCapacity ||
         NULL == pu8Dst ||
         NULL == pSW)
    {
        return ENULLPARAM;
    }

    *pSW = VLT_STATUS_NONE;

    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = u8Ins;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = u8P2;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u32SrcLen));

    (void)host_memcpy(&Command.pu8Data[VLT_APDU_DATA_OFFSET], pu8Src, u32SrcLen);

    status = VltCommand(&Command, &Response, (VLT_U16) (VLT_APDU_DATA_OFFSET+ u32SrcLen), 0, pSW);

    if( (VLT_OK != status) || (VLT_STATUS_NONE == *pSW) )
    {
        return status;
    }

    if (*pSW != VLT_STATUS_SUCCESS)
    {
        return VLT_OK; /* unexpected status word */
    }

    Response.u16Len -= VLT_SW_SIZE;

    if (Response.u16Len > u32DstCapacity)
    {
        /* ran out of output buffer space */
        return(EC4NOROOM);
    }

    /* Copy response data received */
    (void)host_memcpy(pu8Dst, Response.pu8Data, Response.u16Len);

    /* Report the final amount of data produced */
    *pu32DstLen = Response.u16Len;

    return status;
}
#endif // #else (VLT_ENABLE_NO_CMD_CHAINING != VLT_ENABLE)
