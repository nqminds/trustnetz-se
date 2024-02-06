/**
* @file	   vaultic_comms.c
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
#include "vaultic_comms.h"
#include "vaultic_protocol.h"
#include "vaultic_apdu.h"

#if(VLT_ENABLE_SCP03 == VLT_ENABLE ) 
    #include <auth/vaultic_secure_channel.h>
#endif 

#include "vaultic_block_protocol.h"

#if( VLT_PLATFORM == VLT_WINDOWS ) && defined (TRACE_APDU)
static unsigned int GetTime()
{
    LONGLONG freq=0, count=0;
    QueryPerformanceCounter((LARGE_INTEGER*)&count);
    QueryPerformanceFrequency((LARGE_INTEGER*)&freq);
    return (unsigned int)(count * 1000 / freq);
}
#endif

/*
* Error Codes
*/
#define EINITNULLPARAM      VLT_ERROR( VLT_COMMS, 0u )
#define EDISPZEROLEN        VLT_ERROR( VLT_COMMS, 1u )
#define EDISPNULLIDATA      VLT_ERROR( VLT_COMMS, 2u )
#define EDISPNULLODATA      VLT_ERROR( VLT_COMMS, 3u )
#define EDISPNULLRSPDATA    VLT_ERROR( VLT_COMMS, 4u )

/*
* Defines
*/
#define MIN_CMD_SZ                (VLT_U8) 5
#define APDU_COMMAND_OFFSET       (VLT_U8) VLT_BLOCK_PROTOCOL_HDR_SZ
#define VLT_COMMS_CMD_BUFFER_SIZE (VLT_U16)(VLT_BLOCK_PROTOCOL_OH + VLT_MAX_APDU_SND_TRANS_SIZE)
#define VLT_COMMS_RSP_BUFFER_SIZE (VLT_U16)(VLT_BLOCK_PROTOCOL_OH + VLT_MAX_APDU_RCV_TRANS_SIZE) 

/*
* Private Data
*/
static VLT_U8 commsBuffer[VLT_COMMS_CMD_BUFFER_SIZE];

VLT_STS VltCommsInit(const VLT_INIT_COMMS_PARAMS *pInitCommsParams,
    VLT_MEM_BLOB *Command, 
    VLT_MEM_BLOB *Response )
{
    VLT_STS status;
    VLT_MEM_BLOB outData = { 0 };
    VLT_MEM_BLOB inData = { 0 };
    
    /*
    * Check input params
    */
    if( NULL == pInitCommsParams )
    {
        return EINITNULLPARAM;
    }

    /*
    * Setup the MEM_BLOBs passed for Command and Response to use the commsBuffer
    * Data should be added and removed from the APDU_COMMAND_OFFSET so that
    * any Block Protocol data is not seen at the API level
    */
    Command->pu8Data = &commsBuffer[APDU_COMMAND_OFFSET];
    Command->u16Capacity = VLT_MAX_APDU_SND_TRANS_SIZE;
    Command->u16Len = 0;

    Response->pu8Data = &commsBuffer[APDU_COMMAND_OFFSET];;
    Response->u16Capacity = VLT_MAX_APDU_RCV_TRANS_SIZE;
    Response->u16Len = 0;

    /*
    * The actual Comms Buffer has extra space in it.  The peripherals need 
    * to know about this
    */
    outData.pu8Data = &commsBuffer[0];
    outData.u16Len = 0;
    outData.u16Capacity = VLT_COMMS_CMD_BUFFER_SIZE;

    inData.pu8Data = &commsBuffer[0];
    inData.u16Len = 0;
    inData.u16Capacity = VLT_COMMS_RSP_BUFFER_SIZE;

    status = VltPtclInit( pInitCommsParams, &outData, &inData );

    return( status );
}

VLT_STS VltCommsClose( void )
{
    VLT_STS status = VltPtclClose();

    return( status );
}

VLT_STS VltCommsDispatchCommand( VLT_MEM_BLOB *Command, VLT_MEM_BLOB *Response )
{   
    VLT_STS status;

    /*
    * Ensure we a valid Command data pointer
    */
    if( NULL == Command->pu8Data )
    {
        return( EDISPNULLIDATA );
    }
    /*
    * Ensure we have a valid size command
    */
    if( MIN_CMD_SZ > Command->u16Len )
    {
        return( EDISPZEROLEN );
    }

    /*
    * Ensure we have a valid Response pointer
    */
    if( NULL == Response )
    {
        return( EDISPNULLRSPDATA );
    }

    /*
    * Ensure we have a valid Response data pointer
    */
    if( NULL == Response->pu8Data )
    {
        return( EDISPNULLODATA );
    }

    /*
    * The Status Word SW is always implied 
    */
    Response->u16Len += VLT_SW_SIZE;

#if ( VLT_ENABLE_SCP03 == VLT_ENABLE ) 
    /*
    * Call ScpWrap method to add appropriate security data
    */
#ifdef TRACE_APDU
    {
        int i;
        LOG_APDU("\n[APDU NOT WRAPPED]Sent:");
        for (i = 0; i < Command->u16Len; i++)
        {
            LOG_APDU_PARAM(" %2.2X", Command->pu8Data[i]);
        }
        LOG_APDU("\n");
    }
#endif

    status = VltScpWrap( Command );
#else
    status = VLT_OK;
#endif

    /*
    * Send the Data to the Peripheral and get the Response from it
    */
    if( VLT_OK == status )
    {
#ifdef TRACE_APDU
		{
			int i;
			LOG_APDU("[APDU]Sent:");
			for (i = 0; i < Command->u16Len; i++)
			{
				LOG_APDU_PARAM(" %2.2X", Command->pu8Data[i]);
			}
			LOG_APDU("\n");
		}

    #if( VLT_PLATFORM == VLT_WINDOWS ) 
        int start_time = GetTime();
    #endif
#endif

        status = VltPtclSendReceiveData( Command, Response );
#ifdef TRACE_APDU

    #if( VLT_PLATFORM == VLT_WINDOWS ) 
        int end_time = GetTime();
    #endif
		{
			if (status != VLT_OK)
			{
				LOG_APDU_PARAM("[APDU]Status: %x\n", status);
			}
			else {
				int i;
				LOG_APDU("[APDU]Recv:");
				for (i = 0; i<Response->u16Len; i++)
					LOG_APDU_PARAM(" %2.2X", Response->pu8Data[i]);
				LOG_APDU("\n");
			}
		}
    #if( VLT_PLATFORM == VLT_WINDOWS ) 
        printf("Time: %u ms\n\n", (end_time - start_time));
    #endif
#endif
    }

#if ( VLT_ENABLE_SCP03 == VLT_ENABLE ) 
    /*
    * Call Secure Channel Unwrap to remove any security data
    */
    if( VLT_OK == status )
    {
        status = VltScpUnwrap ( Response );
#ifdef TRACE_APDU
        if (status != VLT_OK)
        {
            LOG_APDU_PARAM("[APDU unwrapped]Status: %x\n", status);
        }
        else {
            int i;
            LOG_APDU("[APDU unwrapped]Recv:");
            for (i = 0; i<Response->u16Len; i++)
                LOG_APDU_PARAM(" %2.2X", Response->pu8Data[i]);
            LOG_APDU("\n");
        }
#endif
    }
#endif

    return( status );
}

VLT_U16 VltCommsGetMaxSendSize( void )
{
#if (VLT_ENABLE_SCP03 == VLT_ENABLE )
    VLT_U8 u8Overhead = 0;
    /*
    * The call to VltScpGetChannelOverhead will fail if the conditional compilation
    * switch for Secure Channel has not been enabled
    */
    (void)VltScpGetChannelOverhead( SECURE_CHANNEL_SEND, &u8Overhead );

    return VLT_MAX_APDU_SND_DATA_SZ - u8Overhead;
#else    
    return VLT_MAX_APDU_SND_DATA_SZ;
#endif 
}

VLT_U16 VltCommsGetMaxReceiveSize( void )
{
#if (VLT_ENABLE_SCP03 == VLT_ENABLE )

    VLT_U8 u8Overhead = 0;

    /*
    * The call to VltScpGetChannelOverhead will fail if the conditional compilation
    * switch for Secure Channel has not been enabled
    */
    (void)VltScpGetChannelOverhead( SECURE_CHANNEL_RECEIVE, &u8Overhead );
    
    return VLT_MAX_APDU_RCV_DATA_SZ - u8Overhead;

#else
    return VLT_MAX_APDU_RCV_DATA_SZ;
#endif /*#if ( VLT_ENABLE_SCP03 == VLT_ENABLE )  */
    
}

#if(VLT_ENABLE_ISO7816 == VLT_ENABLE )
VLT_STS VltCommsCardEvent(VLT_U8 *pu8ReaderName, DWORD dwTimeout,PDWORD pdwEventState)
{
    VLT_STS status = VLT_FAIL;

    status = VltPtclCardEvent(pu8ReaderName,dwTimeout,pdwEventState);

    return( status );
}

VLT_STS VltCommsSelectCard(SCARDHANDLE hScard, SCARDCONTEXT hCxt, DWORD dwProtocol)
{
	 VLT_STS status = VLT_FAIL;

	 status = VltPtclSelectCard(hScard,hCxt,dwProtocol);

    return( status );
}
#endif


#ifdef TRACE_APDU
#endif