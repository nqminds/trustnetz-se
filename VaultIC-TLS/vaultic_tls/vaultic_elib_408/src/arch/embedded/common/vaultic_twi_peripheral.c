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
 * @brief   VaultIC_API TWI tools
 *
 * @details This interface supports only one VaultIC at a time and is not thread safe
 *
 */

#include <vaultic_common.h>
#if( VLT_ENABLE_TWI == VLT_ENABLE ) && ( VLT_PLATFORM == VLT_EMBEDDED)

#include <vaultic_timer_delay.h>
#include <comms/vaultic_twi_peripheral.h>
#include <vaultic_twi_driver.h>
#include <vaultic_control_driver.h>

#ifdef VALID_HOOKS
#include "test_porting_layer.h"
#endif

#define ETWISNDNULLPARAMS       VLT_ERROR( VLT_TWI, 0 )         ///< ERROR in VltTwiPeripheralSendData    : Null parameters
#define ETWIRCVNULLPARAMS       VLT_ERROR( VLT_TWI, 1 )         ///< ERROR in VltTwiPeripheralReceiveData : Null parameters
#define ETWIINITCONFIG          VLT_ERROR( VLT_TWI, 5 )         ///< ERROR in VltTwiPeripheralInit        : Initialization fail
#define ETWISNDFAILED           VLT_ERROR( VLT_TWI, 13 )        ///< ERROR in VltTwiPeripheralSendData    : Send fail
#define ETWIRCVTRUNCATED        VLT_ERROR( VLT_TWI, 14 )        ///< ERROR in VltTwiPeripheralReceiveData : Receive truncated
#define ETWIRCVFAILED           VLT_ERROR( VLT_TWI, 15 )        ///< ERROR in VltTwiPeripheralReceiveData : Receive fail
#define ETWISNDTRUNCATED        VLT_ERROR( VLT_TWI, 17 )        ///< ERROR in VltTwiPeripheralSendData    : Send truncated
#define ETWIUNSUPPIOCTLID       VLT_ERROR( VLT_TWI, 18 )        ///< ERROR in VltTwiPeripheralIoctl       : Command not supported
#define ETWIINITNULLPARAMS      VLT_ERROR( VLT_TWI, 19 )        ///< ERROR in VltTwiPeripheralInit        : Null parameters

static uint8_t  u8I2cAddress;
static uint32_t u32ResponseTimeout;

#define I2C_BUS_TIMEOUT 300 // Max time required to exchange 255 bytes on the I2C bus


/**
 * @brief           Initialize the TWI driver
 *
 * @details         Wrapper between the VaultIC_API and the target platform
 *
 * @param[in]       pInitCommsParams    must have the following defined before calling this API:
 *                                          - u16BitRate (in kbits)
 *                                          - u8Address I2C address
 *                                          - u32msTimeout (in milliseconds)
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          The status (expected VLT_OK).
 */
VLT_STS VltTwiPeripheralInit( const VLT_INIT_COMMS_PARAMS *pInitCommsParams)
{
    VLT_U16 u16TwiBitRate;
    
#ifdef VALID_HOOKS
    HOOK_PERIPH_INIT
#endif
    
    if (!pInitCommsParams) {
        return ETWIINITNULLPARAMS;
    }

	u16TwiBitRate = pInitCommsParams->VltTwiParams.u16BitRate;
    u8I2cAddress = pInitCommsParams->VltTwiParams.u8Address;
    u32ResponseTimeout = pInitCommsParams->VltBlockProtocolParams.u32msTimeout;

#ifdef RST_CTRL_BY_GPIO
    /* Drive Reset to low */
    VltControlResetLow();

    /* Stabilize Rst */
    VltSleep(2*VLT_MICRO_SECS_IN_MSEC); /* wait 2 ms */
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

	if (VltTwiDriverInit(u8I2cAddress, u16TwiBitRate) != TWI_OK)
    {
        return ( ETWIINITCONFIG);
    }

    return ( VLT_OK);
}

/**
 * @brief           Close the TWI driver
 *
 *
 * @param[in]       -
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          Always VLT_OK.
 */
VLT_STS VltTwiPeripheralClose(void)
{

#ifdef VALID_HOOKS
    HOOK_PERIPH_CLOSE
#endif

	VltTwiDriverDeInit();

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
 * @brief           Send data over the TWI driver
 *
 * @pre             VltTwiPeripheralInit() must be called before
 * @details         Wrapper between the VaultIC_API and the target platform
 *
 * @param[in]       pOutData        Pointer on the data to send
 *
 * @return          The status (expected VLT_OK).
 */
VLT_STS VltTwiPeripheralSendData(const VLT_MEM_BLOB *pOutData)
{

	uint16_t u16Len;
    
#ifdef VALID_HOOKS
    HOOK_PERIPH_SEND_DATA
#endif


    if (!pOutData || !pOutData->pu8Data || (pOutData->u16Len < 1))
        return ETWISNDNULLPARAMS;

    // 2ms turnaround time after a receive
    VltSleep( 2 * VLT_MICRO_SECS_IN_MSEC);

#if (VAULT_IC_TARGET == VAULTIC4XX)
    // Wake Up VaultIC: read 0 bytes at address 0
    VltTwiDriverWakeUpVaultIc(I2C_BUS_TIMEOUT);
#endif
    // Transmit bytes
    u16Len = pOutData->u16Len;
    if (VltTwiDriverSendBytes( 	u8I2cAddress ,      // I2C address
                            	pOutData->pu8Data,  // Send Buffer
								u16Len,             // Nb of bytes to send
								I2C_BUS_TIMEOUT     // Timeout (in ms)
                          	 ) != TWI_OK)
    {
        return ( ETWISNDFAILED);
    }

    else if (u16Len != pOutData->u16Len)
        return ( ETWISNDTRUNCATED);

    return ( VLT_OK);
}

/**
 * @brief           Receive data over TWI
 *
 * @pre             VltTwiPeripheralInit() must be called before
 * @details
 *
 * @param[in]       pInData         Pointer on where store the received data
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          The status (expected VLT_OK).
 */
VLT_STS VltTwiPeripheralReceiveData(VLT_MEM_BLOB *pInData)
{
#ifdef VALID_HOOKS
    HOOK_PERIPH_RECEIVE_DATA
#endif

    if (!pInData || !pInData->pu8Data || (pInData->u16Capacity < 1))
        return ETWIRCVNULLPARAMS;

    VltSleep( 2 * VLT_MICRO_SECS_IN_MSEC);

    if( VltTwiDriverReceiveBytes(	u8I2cAddress ,		// I2C address
    								pInData->pu8Data ,	// Receive Buffer
									pInData->u16Len,    // Nb of bytes to receive
									I2C_BUS_TIMEOUT,    // I2C Bus Timeout (in ms)
    								u32ResponseTimeout)	// APDU Response Timeout (in ms)
        							!= TWI_OK)
    	return ETWIRCVFAILED;

    return ( VLT_OK);
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

VLT_STS VltTwiPeripheralIoctl(VLT_U32 u32Id, const void* pConfigData)
{
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
        status = VLT_OK;
        break;

    default:
        status = ETWIUNSUPPIOCTLID;
        break;
    }
    return (status);
}


#endif // ( VLT_ENABLE_TWI == VLT_ENABLE )
