/**
* @file	   vaultic_protocol.c
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
#include "vaultic_common.h"
#include "vaultic_protocol.h"
#if( VLT_ENABLE_ISO7816 == VLT_ENABLE )
    #include "vaultic_iso7816_protocol.h"
#endif

#if( VLT_ENABLE_BLOCK_PROTOCOL == VLT_ENABLE )
#include "vaultic_block_protocol.h"
#endif

#if(( VLT_ENABLE_OWI == VLT_ENABLE) && (VLT_ENABLE_WISEBOARD == VLT_ENABLE))   
#include "wiseboard_owi_peripheral.h"
#endif
/*
* Error Codes
*/
#define EPTCLINITNULLPARAMS       VLT_ERROR( VLT_PTCL, 0u )
#define EPTCLINVLDCOMMSTYPE       VLT_ERROR( VLT_PTCL, 1u )

/*
* Private Data
*/
static VltPtcl theVltPtcl = 
{
    0,
    0,
    0,
#if(VLT_ENABLE_ISO7816 == VLT_ENABLE )
	0,
    0,
#endif
};

/*
* Public Methods
*/
VLT_STS VltPtclInit(const VLT_INIT_COMMS_PARAMS *pInitCommsParams,
    VLT_MEM_BLOB *pOutData,
    const VLT_MEM_BLOB *pInData
 )
{
    VLT_STS status;

    /*
    * Check that the supplied pointer is valid
    */
    if( ( NULL == pInitCommsParams ) || 
        ( NULL == pOutData ) ||
        ( NULL == pInData ) )
    {
        return EPTCLINITNULLPARAMS;
    }

    /*
    * Setup routing of calls to the appropriate protocol
    */
	switch (pInitCommsParams->enCommsProtocol)
	{

#if( VLT_ENABLE_ISO7816 == VLT_ENABLE )    
		case VLT_ISO_T0_OR_T1_COMMS:
        case VLT_ISO_T0_COMMS:
        case VLT_ISO_T1_COMMS:
        case VLT_USB_COMMS:
            theVltPtcl.PtclInit = VltIso7816PtclInit;
            theVltPtcl.PtclClose = VltIso7816PtclClose;
            theVltPtcl.PtclSendReceiveData = VltIso7816PtclSendReceiveData;
            theVltPtcl.PtclCardEvent = VltIso7816PtclCardEvent;
			theVltPtcl.PtclSelectCard = VltIso7816SelectCard;
            status = VLT_OK;
            break;
#endif /*( VLT_ENABLE_ISO7816 == VLT_ENABLE ) */ 

#if( VLT_ENABLE_OWI == VLT_ENABLE )   
		case VLT_OWI_COMMS:
#if (VLT_ENABLE_WISEBOARD == VLT_ENABLE)
			theVltPtcl.PtclInit = VltWiseboardInit;
			theVltPtcl.PtclClose = VltWiseboardClose;
			theVltPtcl.PtclSendReceiveData = VltWiseboardSendReceiveData;
#else
			theVltPtcl.PtclInit = VltBlkPtclInit;
			theVltPtcl.PtclClose = VltBlkPtclClose;
			theVltPtcl.PtclSendReceiveData = VltBlkPtclSendReceiveData;
#endif
			status = VLT_OK;
			break;
#endif

#if( ( VLT_ENABLE_SPI == VLT_ENABLE ) || ( VLT_ENABLE_TWI == VLT_ENABLE ) )
            /*
            * Both SPI and TWI use the Block Protocol
            */
#if( VLT_ENABLE_SPI == VLT_ENABLE ) 
        case VLT_SPI_COMMS:
#endif
#if( VLT_ENABLE_TWI == VLT_ENABLE ) 
        case VLT_TWI_COMMS:
#endif
            theVltPtcl.PtclInit = VltBlkPtclInit;
            theVltPtcl.PtclClose = VltBlkPtclClose;
            theVltPtcl.PtclSendReceiveData = VltBlkPtclSendReceiveData;
            status = VLT_OK;
            break;
#endif

        default:
            /*
            * Invalid comms type
            */
            status = EPTCLINVLDCOMMSTYPE;
            break;
    }

    if( VLT_OK == status )
    {
        /*
        * Delegate the call to the appropriate protocol
        */
        status = theVltPtcl.PtclInit( pInitCommsParams, 
            pOutData, 
            pInData);
    }

    return( status );
}

VLT_STS VltPtclClose( void )
{
    /*
    * Delegate the call to the appropriate protocol
    */	
    if (theVltPtcl.PtclClose != NULL)
    {
        return theVltPtcl.PtclClose();
    }
    else
    {
        return VLT_OK;
    }
}

VLT_STS VltPtclSendReceiveData( VLT_MEM_BLOB *pSendData, VLT_MEM_BLOB *pReceiveData )
{   
    /*
    * Delegate the call to the appropriate protocol
    */
    return theVltPtcl.PtclSendReceiveData(pSendData, pReceiveData);
}

#if(VLT_ENABLE_ISO7816 == VLT_ENABLE )
VLT_STS VltPtclCardEvent(VLT_U8 *pu8ReaderName, DWORD dwTimeout,PDWORD pdwEventState)
{
    if (theVltPtcl.PtclCardEvent)
		return theVltPtcl.PtclCardEvent(pu8ReaderName,dwTimeout,pdwEventState);
    return VLT_OK;
}

VLT_STS VltPtclSelectCard( SCARDHANDLE hScard , SCARDCONTEXT hCxt, DWORD dwProtocol)
{
    if (theVltPtcl.PtclSelectCard)
		return theVltPtcl.PtclSelectCard(hScard,hCxt,dwProtocol);
    return VLT_OK;
}
#endif