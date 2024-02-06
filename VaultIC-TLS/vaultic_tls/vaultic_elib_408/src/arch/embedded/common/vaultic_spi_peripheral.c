/**
 * @file
 *
 * @note    THIS PRODUCT IS SUPPLIED FOR EVALUATION, TESTING AND/OR DEMONSTRATION PURPOSES ONLY.
 *
 * @note    <b>DISCLAIMER</b>
 *
 * @note    Copyright (C) 2016 Wisekey
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
 *
 *
 * @brief   VaultIC_API SPI tools
 *
 * @details This interface supports only one VaultIC at a time and is not thread safe
 *
 */

#include "vaultic_common.h"
#if( VLT_ENABLE_SPI == VLT_ENABLE ) && ( VLT_PLATFORM == VLT_EMBEDDED)

#include <vaultic_timer_delay.h>
#include "vaultic_mem.h"
#include <comms/vaultic_spi_peripheral.h>
#include <vaultic_spi_driver.h>
#include "vaultic_control_driver.h"

#ifdef VALID_HOOKS
#include "test_porting_layer.h"
#endif

#define ESPISNDNULLPARAMS       VLT_ERROR( VLT_SPI, 0 )         ///< ERROR in VltSpiPeripheralSendData    : Null parameters
#define ESPIRCVNULLPARAMS       VLT_ERROR( VLT_SPI, 1 )         ///< ERROR in VltSpiPeripheralReceiveData : Null parameters
#define ESPIINITCONFIG          VLT_ERROR( VLT_SPI, 2 )         ///< ERROR in VltSpiPeripheralInit        : Initialization fail
#define ESPISNDFAILED           VLT_ERROR( VLT_SPI, 13 )        ///< ERROR in VltSpiPeripheralSendData    : Send fail
#define ESPIRCVFAILED           VLT_ERROR( VLT_SPI, 15 )        ///< ERROR in VltSpiPeripheralReceiveData : Receive fail
#define ESPIUNSUPPIOCTLID       VLT_ERROR( VLT_SPI, 18 )        ///< ERROR in VltSpiPeripheralIoctl       : Command not supported
#define ESPIINITNULLPARAMS      VLT_ERROR( VLT_SPI, 19 )        ///< ERROR in VltSpiPeripheralInit        : Null parameters
#define ESPIRCVCAPTOOLOW		VLT_ERROR( VLT_SPI, 20 )        ///< ERROR in VltSpiPeripheralReceiveData : Buffer too small
#define ESPIRCVTIMEOUT			VLT_ERROR( VLT_SPI, 30 ) 		///< ERROR in VltSpiPeripheralReceiveData : timeout

#define SPI_POLLING_BYTE      	(VLT_U8)0xC0
#define ERROR_DELAY_MICRO_SEC 150000  // Delay in case of comm error
#define POLLBYTE_DELAY_MICRO_SEC 500  // Delay between poll byte in microseconds
#define SS_DELAY_MICRO_SEC 	100
#define SPI_BUS_TIMEOUT 300 	// Max time required to exchange 255 bytes on the SPI bus

static VLT_U32 u32ResponseTimeout;
static VLT_U8  bFirstReceive;


/**
 * @brief           Initialize the SPI driver
 *
 * @details         Wrapper between the VaultIC_API and the target platform
 *
 * @param[in]       pInitCommsParams    must have the following defined before calling this API:
 *                                          - u32msTimeout (in milliseconds)
 *                                          - u16BitRate (in kbits)
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          The status (expected VLT_OK).
 */
VLT_STS VltSpiPeripheralInit( const VLT_INIT_COMMS_PARAMS *pInitCommsParams )
{
    VLT_U16 u16SpiBitRate;
    
#ifdef VALID_HOOKS
    HOOK_PERIPH_INIT
#endif
    
    if (!pInitCommsParams) {
        return ESPIINITNULLPARAMS;
    }

	u16SpiBitRate = pInitCommsParams->VltSpiParams.u16BitRate;
	u32ResponseTimeout = pInitCommsParams->VltBlockProtocolParams.u32msTimeout;

#ifdef RST_CTRL_BY_GPIO
    /* Drive Reset to low */
    VltControlResetLow();

    /* Stabilize Rst */
    VltSleep(2*VLT_MICRO_SECS_IN_MSEC); /* wait 2 ms */
#endif

#ifdef SPI_SEL_CTRL_BY_GPIO
    /* Drive SDA/SPI_SEL to low (indicate to VaultIC to run in SPI mode)*/
    VltSpiSelect();
#endif

#ifdef VCC_CTRL_BY_GPIO
    /* Switch on VCC */
    VltControlPowerOn();

    /* Stabilize Vcc */
    VltSleep(2*VLT_MICRO_SECS_IN_MSEC); /* wait 2 ms */
#endif

#ifdef RST_CTRL_BY_GPIO
    /* Release Reset */
    VltControlResetHigh();
#endif

    /* Initialize SPI controller */
	if (VltSpiDriverInit(u16SpiBitRate) != SPI_OK)
    {
        return ( ESPIINITCONFIG);
    }

    return ( VLT_OK);
}

/**
 * @brief           Close the SPI driver
 *
 *
 * @param[in]       -
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          Always VLT_OK.
 */
VLT_STS VltSpiPeripheralClose( void )
{

#ifdef VALID_HOOKS
    HOOK_PERIPH_CLOSE
#endif

	VltSpiDriverDeInit();

#ifdef VCC_CTRL_BY_GPIO
    VltControlPowerOff();
#endif

#if defined(VCC_CTRL_BY_GPIO) || defined (RST_CTRL_BY_GPIO)
    VltControlUninit();
#endif

    VltSleep(100*VLT_MICRO_SECS_IN_MSEC); /* wait 100 ms */

	return ( VLT_OK);
}


/**
 * @brief           Send data over the SPI driver
 *
 * @pre             VltSpiPeripheralInit() must be called before
 * @details         Wrapper between the VaultIC_API and the target platform
 *
 * @param[in]       pOutData        Pointer on the data to send
 *
 * @return          The status (expected VLT_OK).
 */
VLT_STS VltSpiPeripheralSendData( const VLT_MEM_BLOB *pOutData )
{
	VLT_STS status = VLT_FAIL;
	uint16_t iRet = 0;
    
#ifdef VALID_HOOKS
    HOOK_PERIPH_SEND_DATA
#endif

	/*
	* Check the input parameter is valid
	*/
	if( NULL == pOutData )
	{
		return ESPISNDNULLPARAMS;
	}
    
    // 2ms turnaround time after a receive
    VltSleep( 2 * VLT_MICRO_SECS_IN_MSEC);

	/*
	* Send the Data
	*/
	VltSpiSlaveSelectLow();

	VltSleep(SS_DELAY_MICRO_SEC);

	iRet = VltSpiDriverSendBytes( pOutData->pu8Data, pOutData->u16Len, SPI_BUS_TIMEOUT );

	VltSpiSlaveSelectHigh();

	/*
	* Check that the send happened
	*/
	if( SPI_OK != iRet )  {
		status = ESPISNDFAILED;
	}
	else
	{
		/*
		* Activate polling
		*/
		bFirstReceive = TRUE;

		status = VLT_OK;
	}

	return( status );
}

/**
 * @brief           Receive data over SPI
 *
 * @pre             VltSpiPeripheralInit() must be called before
 * @details
 *
 * @param[in]       pInData         Pointer on where store the received data
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          The status (expected VLT_OK).
 */
VLT_STS VltSpiPeripheralReceiveData( VLT_MEM_BLOB *pInData )
{
	VLT_STS status = VLT_FAIL;
	uint16_t iRet = 0;
	VLT_U16 u16Len = pInData->u16Len;
	VLT_PU8 pu8DataPos = &(pInData->pu8Data[0]);
    
#ifdef VALID_HOOKS
    HOOK_PERIPH_RECEIVE_DATA
#endif

	/*
	* Check the input parameters are valid
	*/
	if( NULL == pInData )
	{
		return ESPIRCVNULLPARAMS;
	}

	if( 0 == u16Len )
	{
		/*
		* No need to attempt to get data as none is being requested
		*/
		status = VLT_OK;
	}
	else if( pInData->u16Len > pInData->u16Capacity )
	{
		status = ESPIRCVCAPTOOLOW;
	}
	else
	{
	    VltTimerStart(u32ResponseTimeout);

	    if( bFirstReceive )
		{
			/*
			* Poll the SPI until we stop getting 0xC0 or we have tried
			* too many times
			*/
			*pu8DataPos = SPI_POLLING_BYTE;

			do
			{
				VltSleep(POLLBYTE_DELAY_MICRO_SEC);

				VltSpiSlaveSelectLow();

				VltSleep(SS_DELAY_MICRO_SEC);

				iRet = VltSpiDriverReceiveBytes(pu8DataPos , 1 , SPI_BUS_TIMEOUT);

				VltSpiSlaveSelectHigh();

			} while( ( VltTimerIsExpired()== FALSE ) && ( SPI_POLLING_BYTE == *pu8DataPos ) );

			VltTimerStop();

			/*
			* Check if the read was successful
			*/
			if( VltTimerIsExpired() == TRUE)
			{
				status = ESPIRCVTIMEOUT;
			}
			else
			{
				/*
				* Successfully received the first byte of data.  Update the
				* position in the buffer where the remaining data should be
				* placed and reduce the length of the read by 1.  Also clear
				* the bFirstReceive flag so that further receives before
				* another send won't poll for the padding byte
				*/
				pu8DataPos++;
				u16Len--;
				bFirstReceive = FALSE;
				status = VLT_OK;
			}
		}
		else
		{
			status = VLT_OK;
		}

		if( VLT_OK == status )
		{
			/* Clean the buffer */
			host_memset(pu8DataPos , 0, u16Len);

			/*
			* Receive the data
			*/
			VltSpiSlaveSelectLow();

			VltSleep(SS_DELAY_MICRO_SEC);

			iRet = VltSpiDriverReceiveBytes(pu8DataPos , u16Len, SPI_BUS_TIMEOUT);

			VltSpiSlaveSelectHigh();

			if( SPI_OK != iRet )
			{
				/*
				* There was a problem receiving the data
				*/
				status = ESPIRCVFAILED;
			}

		}
	}

	if(status != VLT_OK)
    {
	    VltSleep(ERROR_DELAY_MICRO_SEC); // Wait in case of error
    }

	return( status );
}






/**
 * @brief           Driver options configuration
 *
 * @param[in]       u32Id         The option to configure
 * @param[in]       pConfigData   The data to use (if needed)
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          The status (expected VLT_OK).
 */
VLT_STS VltSpiPeripheralIoctl( VLT_U32 u32Id, const void* pConfigData )
{
    (void) pConfigData; // unused parameter
    
	VLT_STS status = VLT_FAIL;

#ifdef VALID_HOOKS
    HOOK_PERIPH_IOCTL
#endif

    switch (u32Id)
    {
    case VLT_UPDATE_BITRATE :
    case VLT_RESET_PROTOCOL :
        status = VLT_OK;
        break;

	case VLT_AWAIT_DATA :
		bFirstReceive = TRUE;   // Reactivate polling after receiving a More time request
		status = VLT_OK;
		break;

	default:
		status = ESPIUNSUPPIOCTLID;
		break;
	}

	return (status);
}

#endif
