/**
* @file	   vaultic_block_protocol.c
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
#if( VLT_ENABLE_BLOCK_PROTOCOL == VLT_ENABLE )
#include "vaultic_block_protocol.h"
#include "vaultic_peripheral.h"
#if ( VLT_ENABLE_SPI == VLT_ENABLE )
#include "vaultic_spi_peripheral.h"
#endif
#if ( VLT_ENABLE_TWI == VLT_ENABLE )
#include "vaultic_twi_peripheral.h"
#endif
#if ( VLT_ENABLE_OWI == VLT_ENABLE )
#include "vaultic_owi_peripheral.h"
#endif

#include "vaultic_mem.h"
#include "vaultic_apdu.h"
#include "vaultic_timer_delay.h"

#if defined(TRACE_BLOCK_PTCL)||defined(TRACE_BLOCK_PTCL_ERRORS)
#include "stdio.h"
#include "vaultic_utils.h"
#endif

#if (VLT_PLATFORM == VLT_WINDOWS)
    #define VLT_BLK_PTCL_CODE_SECTION                                                               /*!< @brief WIN32 Linker CODE section */
    #define VLT_BLK_PTCL_RAM_ZERO_SECTION                                                           /*!< @brief WIN32 Linker RAM zero-initialized variable section */
    #define VLT_BLK_PTCL_RAM_INIT_SECTION                                                           /*!< @brief WIN32 Linker RAM initialized variable section */
#elif defined (__APPLE__)
    #define VLT_BLK_PTCL_CODE_SECTION                                                               /*!< @brief APPLE Linker CODE section */
    #define VLT_BLK_PTCL_RAM_ZERO_SECTION                                                           /*!< @brief APPLE Linker RAM zero-initialized variable section */
    #define VLT_BLK_PTCL_RAM_INIT_SECTION                                                           /*!< @brief APPLE Linker RAM initialized variable section */
#elif defined (__GNUC__) && !defined (ESP_PLATFORM)
    #define VLT_BLK_PTCL_CODE_SECTION       __attribute__((section("VLT_BLK_PTCL_CODE")))           /*!< @brief GCC Linker CODE section */
    #define VLT_BLK_PTCL_RAM_ZERO_SECTION   __attribute__((section("VLT_BLK_PTCL_RAM_ZERO")))       /*!< @brief GCC Linker RAM zero-initialized variable section */
    #define VLT_BLK_PTCL_RAM_INIT_SECTION   __attribute__((section("VLT_BLK_PTCL_RAM_INIT")))       /*!< @brief GCC Linker RAM initialized variable section */
#elif defined (__ICCARM__)
    #define VLT_BLK_PTCL_CODE_SECTION       _Pragma("location=\"VLT_BLK_PTCL_CODE\"")               /*!< @brief IAR Linker CODE section */
    #define VLT_BLK_PTCL_RAM_ZERO_SECTION   _Pragma("location=\"VLT_BLK_PTCL_RAM_ZERO\"")           /*!< @brief IAR Linker RAM zero-initialized variable section */
    #define VLT_BLK_PTCL_RAM_INIT_SECTION   _Pragma("location=\"VLT_BLK_PTCL_RAM_INIT\"")           /*!< @brief IAR Linker RAM initialized variable section */
#elif defined (__CC_ARM)
    #define VLT_BLK_PTCL_CODE_SECTION       __attribute__((section("VLT_BLK_PTCL_CODE")))           /*!< @brief KEIL Linker CODE section */
    #define VLT_BLK_PTCL_RAM_ZERO_SECTION   __attribute__((section("VLT_BLK_PTCL_RAM_ZERO")))       /*!< @brief KEIL Linker RAM zero-initialized variable section */
    #define VLT_BLK_PTCL_RAM_INIT_SECTION   __attribute__((section("VLT_BLK_PTCL_RAM_INIT")))       /*!< @brief KEIL Linker RAM initialized variable section */
#else
    #define VLT_BLK_PTCL_CODE_SECTION                                                               /*!< @brief OTHER Linker CODE section */
    #define VLT_BLK_PTCL_RAM_ZERO_SECTION                                                           /*!< @brief OTHER Linker RAM zero-initialized variable section */
    #define VLT_BLK_PTCL_RAM_INIT_SECTION                                                           /*!< @brief OTHER Linker RAM initialized variable section */
#endif


/*
* Defines
*/
#define BLK_PTCL_BLOCK_TYPE_MASK     (VLT_U8)0xC0u
#define BLK_PTCL_IBLOCK_MASK         (VLT_U8)0x00
#define BLK_PTCL_SBLOCK_MASK         (VLT_U8)0x40
#define BLK_PTCL_RBLOCK_MASK         (VLT_U8)0x80

#define BLK_PTCL_TYPE_SLAVE_IBLOCK   (VLT_U8)0x01
#define BLK_PTCL_TYPE_SLAVE_RBLOCK   (VLT_U8)0x81
#define BLK_PTCL_TYPE_SLAVE_SRSYNC   (VLT_U8)0x47
#define BLK_PTCL_TYPE_SLAVE_STIME    (VLT_U8)0x49

#define BLK_PTCL_GET_PARAMS_MASK     (VLT_U8)0x00
#define BLK_PTCL_SET_PARAMS_MASK     (VLT_U8)0x02
#define BLK_PTCL_GET_IDENTITY_MASK   (VLT_U8)0x04
#define BLK_PTCL_RESYNCH_MASK        (VLT_U8)0x06
#define BLK_PTCL_MORE_TIME           (VLT_U8)0x08

#define BLCK_PTCL_MASTER_SEND_MASK   (VLT_U8)0x00
#define BLCK_PTCL_SLAVE_SEND_MASK    (VLT_U8)0x01u

#define VLT_BLK_PTCL_TEMP_BUFFER_SIZE       (VLT_U8)0x03u       /*!< @brief @ref VltBlkPtcl_u8CmdBackupBuf size */

/*
 * The Block protocol states
 */

typedef enum
{
    VLT_BLK_PTCL_STATE_NORMAL, 					/*!< @brief State = Normal */
    VLT_BLK_PTCL_STATE_RESEND_DATA, 			/*!< @brief State = Resends data request */
    VLT_BLK_PTCL_STATE_SEND_RBLOCK, 			/*!< @brief State = Bad data reception: send RBLOCK */
    VLT_BLK_PTCL_STATE_RESYNCH, 				/*!< @brief State = Resynchronizations request */
    VLT_BLK_PTCL_STATE_MORE_TIME, 				/*!< @brief State = More time request */
} VLT_BLK_PTCL_STATE;

#ifndef VLT_BLK_PTCL_MAX_RESYNC_ATTEMPTS
#define VLT_BLK_PTCL_MAX_RESYNC_ATTEMPTS    (VLT_U8)0x0Au       /*!< @brief Maximum allowed resynchronizations attempts */
#endif

#ifndef VLT_BLK_PTCL_MAX_ERR_CNT
#define VLT_BLK_PTCL_MAX_ERR_CNT            (VLT_U8)0x03u       /*!< @brief Maximum allowed error */
#endif

/*
* Private Data
*/

/**
 * @brief   Function pointers to the specified peripheral
 */
VLT_BLK_PTCL_RAM_ZERO_SECTION static VltPeripheral VltBlkPtcl_theVltPeripheral;

/**
 * @brief   MemBlob for store the command
 */
VLT_BLK_PTCL_RAM_ZERO_SECTION static VLT_MEM_BLOB VltBlkPtcl_Command;

/**
 * @brief   MemBlob for store the response
 */
VLT_BLK_PTCL_RAM_ZERO_SECTION static VLT_MEM_BLOB VltBlkPtcl_Response;

/**
 * @brief   Error counter for the number of R-Blocks received
 * @see     @ref VLT_BLK_PTCL_MAX_ERR_CNT
 */
VLT_BLK_PTCL_RAM_ZERO_SECTION static VLT_U8 VltBlkPtcl_u8ErrorCount;

/**
 * @brief   flag to say that an S-Block has been built in the command buffer
 */
VLT_BLK_PTCL_RAM_ZERO_SECTION static VLT_U8 VltBlkPtcl_u8SendSBlock;

/**
 * @brief   Store the BlockProtcol current state
 */
VLT_BLK_PTCL_RAM_ZERO_SECTION static VLT_BLK_PTCL_STATE VltBlkPtcl_enState;

/**
 * @brief   Temporary buffer used to backup command data that could be lost as a
 *          result of S-Blocks being sent/received between I-Blocks
 */
VLT_BLK_PTCL_RAM_ZERO_SECTION static VLT_U8 VltBlkPtcl_u8CmdBackupBuf[VLT_BLK_PTCL_TEMP_BUFFER_SIZE];

/**
 * @brief   Resynchronizations attempts counter
 * @see     @ref VLT_BLK_PTCL_MAX_RESYNC_ATTEMPTS
 */
VLT_BLK_PTCL_RAM_ZERO_SECTION static VLT_U8 VltBlkPtcl_u8ResynchSendCnt;

VLT_BLK_PTCL_RAM_ZERO_SECTION static VLT_BOOL VltBlkPtcl_InitDone;	// Initial Sync not completed yet
VLT_BLK_PTCL_RAM_ZERO_SECTION static VLT_BOOL VltBlkPtcl_RsyncInProgress; // Rsync in progress (following comm errors)
VLT_BLK_PTCL_RAM_ZERO_SECTION static VLT_BOOL VltBlkPtcl_ResendRequest;   // Frame resent required following comm error

void    VltBlkPtclAddIBlockHeader( VLT_MEM_BLOB *pOutData );
void    VltBlkPtclHandleResponse( VLT_MEM_BLOB *pInData );
void    VltBlkPtclHandleSBlockRsp( void );
VLT_U8  VltBlkPtclCalculateSum8Checksum( VLT_U8 *pu8Data, VLT_U16 u16Len );
void    VltBlkPtclAddCommandCheckSum( void );
void    VltBlkPtclConstructSBlockSend( VLT_U8 u8SBlockCmdMask, VLT_U8 u8Len, VLT_U8 *pu8Data );
void    VltBlkPtclConstructSendRBlock( void );
void 	VltBlkPtclResetProtocol( void);
VLT_BOOL VltBlkPtclCheckRBlockFormat( void);
VLT_BOOL VltBlkPtclCheckSBlockFormat( VLT_U8 u8Tag );


/**
 * @brief           Block protocol initialization method
 * @details         Initialize variables and call the device initialization method
 *
 *
 * @param[in]       pInitCommsParams    Protocol initialization parameters
 * @param[in]       pOutData            Pointer on output buffer
 * @param[in]       pInData             Pointer on input buffer
 * @note            When all is OK, the pInData is updated with the get parameters response
 *
 * @return          One of this status:
 *                      - @ref VLT_OK
 *                      - An error code
 *
 
 */
VLT_BLK_PTCL_CODE_SECTION VLT_STS VltBlkPtclInit(const VLT_INIT_COMMS_PARAMS *pInitCommsParams,
                                                  VLT_MEM_BLOB *pOutData,
                                                  const VLT_MEM_BLOB *pInData
 )
{
    VLT_STS status = VLT_FAIL;
    VLT_U16 u16BitRate=0;

    //==============================================================================
    // This is a public function ==> Sanity checks
    //==============================================================================

    // Check that the pointer to the Block Protocol Header Position Buffer is valid
    if( ( NULL == pInitCommsParams ) ||
        ( NULL == pOutData ) ||
        ( NULL == pInData )  )
    {
        return VLT_BLK_PTCL_ERROR_INIT_NULL_PARAM;
    }

    // Initialize peripheral functions pointers
    switch( pInitCommsParams->enCommsProtocol )
    {
#if( VLT_ENABLE_SPI == VLT_ENABLE )
    case VLT_SPI_COMMS:
        VltBlkPtcl_theVltPeripheral.PeripheralInit = VltSpiPeripheralInit;
        VltBlkPtcl_theVltPeripheral.PeripheralClose = VltSpiPeripheralClose;
        VltBlkPtcl_theVltPeripheral.PeripheralIoctl = VltSpiPeripheralIoctl;
        VltBlkPtcl_theVltPeripheral.PeripheralSendData = VltSpiPeripheralSendData;
        VltBlkPtcl_theVltPeripheral.PeripheralReceiveData = VltSpiPeripheralReceiveData;
        u16BitRate = pInitCommsParams->VltSpiParams.u16BitRate;
        break;
#endif

#if( VLT_ENABLE_TWI == VLT_ENABLE )
    case VLT_TWI_COMMS:
        VltBlkPtcl_theVltPeripheral.PeripheralInit = VltTwiPeripheralInit;
        VltBlkPtcl_theVltPeripheral.PeripheralClose = VltTwiPeripheralClose;
        VltBlkPtcl_theVltPeripheral.PeripheralIoctl = VltTwiPeripheralIoctl;
        VltBlkPtcl_theVltPeripheral.PeripheralSendData = VltTwiPeripheralSendData;
        VltBlkPtcl_theVltPeripheral.PeripheralReceiveData = VltTwiPeripheralReceiveData;
        u16BitRate = pInitCommsParams->VltTwiParams.u16BitRate;
        break;
#endif

#if( VLT_ENABLE_OWI == VLT_ENABLE )
    case VLT_OWI_COMMS:
        VltBlkPtcl_theVltPeripheral.PeripheralInit = VltOwiPeripheralInit;
        VltBlkPtcl_theVltPeripheral.PeripheralClose = VltOwiPeripheralClose;
        VltBlkPtcl_theVltPeripheral.PeripheralIoctl = VltOwiPeripheralIoctl;
        VltBlkPtcl_theVltPeripheral.PeripheralSendData = VltOwiPeripheralSendData;
        VltBlkPtcl_theVltPeripheral.PeripheralReceiveData = VltOwiPeripheralReceiveData;
        u16BitRate = pInitCommsParams->VltOwiParams.u8BitRate;
        break;
#endif


    default:
        return VLT_BLK_PTCL_ERROR_INVLD_COMMS_MD;
        break;
    }

    // Check input bit rate is not null
    if (u16BitRate ==0)
    {
        return VLT_BLK_PTCL_ERROR_INVLD_BIT_RATE;
    }

    //==============================================================================
    // Process
    //==============================================================================

    // Store the input MEM BLOBs that should be used to append the Block Protocol data
    VltBlkPtcl_Command.pu8Data = pOutData->pu8Data;
    VltBlkPtcl_Command.u16Capacity = pOutData->u16Capacity;
    VltBlkPtcl_Command.u16Len = pOutData->u16Len;
    VltBlkPtcl_Response.pu8Data = pInData->pu8Data;
    VltBlkPtcl_Response.u16Capacity = pInData->u16Capacity;
    VltBlkPtcl_Response.u16Len = pInData->u16Len;
    VltBlkPtcl_u8ErrorCount = 0;
    VltBlkPtcl_u8ResynchSendCnt = 0;
    VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_RESYNCH;
    VltBlkPtcl_u8SendSBlock = FALSE;
    VltBlkPtcl_ResendRequest = FALSE;
    VltBlkPtcl_RsyncInProgress = FALSE;

    // Call initialization on the Block Protocol Peripheral
    status = VltBlkPtcl_theVltPeripheral.PeripheralInit( pInitCommsParams );

    // SDVAULTICWRAP-58 - Introduce a delay from when bus power is applied
    //                    to sending first command to allow the self tests to complete
    VltSleep( pInitCommsParams->VltBlockProtocolParams.u16msSelfTestDelay * VLT_MICRO_SECS_IN_MSEC );

    // If all is OK : Force a resynchronization
    if( VLT_OK == status )
    {
        VltBlkPtcl_InitDone = FALSE;
        status = VltBlkPtclSendReceiveData( &VltBlkPtcl_Command, &VltBlkPtcl_Response );
    }

    return ( status );
}

/**
 * @brief           Block protocol closing method
 * @details         Call the device close method
 *
 * @pre             @ref VltBlkPtclInit must be called before
 *
 * @param[in]       -
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          One of this status:
 *                      - @ref VLT_BLK_PTCL_ERROR_INVLD_COMMS_MD if the device close method is NULL
 *                      - Status coming from the device close method
 */
VLT_BLK_PTCL_CODE_SECTION VLT_STS VltBlkPtclClose( void )
{
    //==============================================================================
    // This is a public function ==> Sanity checks
    //==============================================================================
    if (NULL == VltBlkPtcl_theVltPeripheral.PeripheralClose)
    {
        return VLT_BLK_PTCL_ERROR_INVLD_COMMS_MD;
    }

    //==============================================================================
    // Process
    //==============================================================================
    return VltBlkPtcl_theVltPeripheral.PeripheralClose( );
}

/**
 * @brief           Block protocol send and receive method
 * @details         This method add the block header description, and wait for the response.
 *
 * @pre             @ref VltBlkPtclInit must be called before
 *
 * @param[in]       -
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          One of this status:
 *                      - @ref VLT_OK
 *                      - An error code
 */
VLT_BLK_PTCL_CODE_SECTION VLT_STS VltBlkPtclSendReceiveData( VLT_MEM_BLOB *pOutData, VLT_MEM_BLOB *pInData )
{
    VLT_STS status=VLT_FAIL;
    VLT_MEM_BLOB TempBlob = {0};

    //==============================================================================
    // This is a public function ==> Sanity checks
    //==============================================================================
    if( ( NULL == pOutData ) || ( NULL == pInData ) )
    {
        return VLT_BLK_PTCL_ERROR_SND_RCV_NULL_IO;
    }

    //==============================================================================
    // Process
    //==============================================================================
    do
    {
        //
        // Add the appropriate header info
        //
        switch( VltBlkPtcl_enState )
        {
            case VLT_BLK_PTCL_STATE_NORMAL:
                // Normal case :
                //  - Add IBlock header
                VltBlkPtclAddIBlockHeader( pOutData );
                status = VLT_OK;
                break;

            case VLT_BLK_PTCL_STATE_RESEND_DATA:
                // Resends data request :
                //  - Restore the corrupted command data from the last command
                //  - Add IBlock header
                // Note :No need to check the return type as pointer has been validated
                (void)host_memcpy( &(VltBlkPtcl_Command.pu8Data[VLT_BLOCK_PROTOCOL_HDR_SZ]), &VltBlkPtcl_u8CmdBackupBuf[0], VLT_BLK_PTCL_TEMP_BUFFER_SIZE );
                VltBlkPtclAddIBlockHeader( pOutData );
                status = VLT_OK;
                break;

                case VLT_BLK_PTCL_STATE_SEND_RBLOCK:
                // Bad data received :
                //  - Send an RBlock to request a resend
                VltBlkPtclConstructSendRBlock( );
                status = VLT_OK;
                break;

            case VLT_BLK_PTCL_STATE_RESYNCH:
                // Resynchronization requested
                //  - Send resynchronization block
                VltBlkPtclConstructSBlockSend( BLK_PTCL_RESYNCH_MASK, 0, NULL );
                status = VLT_OK;
                break;

            case VLT_BLK_PTCL_STATE_MORE_TIME:
                // More time request
                // - Nothing to do
                status = VLT_OK;
                break;

            default:
#ifdef TRACE_BLOCK_PTCL_ERRORS
                printf("\nPeripheralSendData Error status: %4.4X\n ", status);
#endif
                return VLT_BLK_PTCL_ERROR_INVLD_STATE; // Fatal error exit block protocol (not supposed to happen)
        }

        //
        // Send the Block Protocol command and receive the response
        //
        if( VLT_OK == status )
        {
            // If more time has been requested don't send anything, just try to receive
            // else send the command.
            if( VLT_BLK_PTCL_STATE_MORE_TIME == VltBlkPtcl_enState )
            {
                VltBlkPtcl_theVltPeripheral.PeripheralIoctl( VLT_AWAIT_DATA, NULL );
            }
            else
            {
#ifdef TRACE_BLOCK_PTCL
                printf("\n[BLOCK_S] ");
                PrintHexBuffer(VltBlkPtcl_Command.pu8Data, VltBlkPtcl_Command.u16Len);
#endif
                status = VltBlkPtcl_theVltPeripheral.PeripheralSendData( &VltBlkPtcl_Command );
            }

            if(VLT_OK != status)
            {
#ifdef TRACE_BLOCK_PTCL_ERRORS
                printf("\nPeripheralSendData Error status: %4.4X\n ", status);
#endif
                if (VltBlkPtcl_enState == VLT_BLK_PTCL_STATE_NORMAL)
                {
                    VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_RESEND_DATA;
                }
                VltBlkPtcl_u8ErrorCount++;
                status = VLT_BLK_PTCL_ERROR_PERIPHERAL;
            }
            else
            {
                // Receive the header.
                // Setup the Temporary Mem Blob for this
                TempBlob.pu8Data = &VltBlkPtcl_Response.pu8Data[0];
                TempBlob.u16Len = VLT_BLOCK_PROTOCOL_HDR_SZ;
                TempBlob.u16Capacity = VLT_BLOCK_PROTOCOL_HDR_SZ;
                status = VltBlkPtcl_theVltPeripheral.PeripheralReceiveData ( &TempBlob);
                if( VLT_OK != status)
                {
#ifdef TRACE_BLOCK_PTCL_ERRORS
                    printf("\nPeripheralReceiveData Error status: %4.4X\n ", status);
#endif
                    VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_SEND_RBLOCK ;
                    VltBlkPtcl_u8ErrorCount++;
                    status = VLT_BLK_PTCL_ERROR_PERIPHERAL;
                }
                else
                {
                    // Receive the data.
                    // Setup the Temporary Mem Blob for this
                    TempBlob.pu8Data = &VltBlkPtcl_Response.pu8Data[VLT_BLOCK_PROTOCOL_HDR_SZ];
                    TempBlob.u16Len = (((VLT_U16)VltBlkPtcl_Response.pu8Data[BLK_PTCL_LEN_MSB_OFFSET]) << 8) + VltBlkPtcl_Response.pu8Data[BLK_PTCL_LEN_LSB_OFFSET];
                    TempBlob.u16Capacity = VltBlkPtcl_Response.u16Capacity - VLT_BLOCK_PROTOCOL_HDR_SZ;

                    // Adjust the requested length to include the checksum byte(s)
                    TempBlob.u16Len += sizeof(VLT_U8);

                    // Check the capacity before call the receive function
                    if (TempBlob.u16Len > TempBlob.u16Capacity)
                    {
                        VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_SEND_RBLOCK ;
                        VltBlkPtcl_u8ErrorCount++;
                        status = VLT_BLK_PTCL_ERROR_RCV_DATA_LEN;

#ifdef TRACE_BLOCK_PTCL_ERRORS
                        printf("\nBlock Protocol: ERROR (invalid block length) \n");
                        printf("[BLOCK_R] ");
                        PrintHexBuffer(VltBlkPtcl_Response.pu8Data, VLT_BLOCK_PROTOCOL_HDR_SZ);
#endif
                    }
                    else
                    {
                        status = VltBlkPtcl_theVltPeripheral.PeripheralReceiveData(&TempBlob);
                        if( VLT_OK != status)
                        {
#ifdef TRACE_BLOCK_PTCL_ERRORS
                            printf("\nPeripheralReceiveData Error status: %4.4X\n ", status);
#endif
                            VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_SEND_RBLOCK ;
                            VltBlkPtcl_u8ErrorCount++;
                            status = VLT_BLK_PTCL_ERROR_PERIPHERAL;
                        }
                        else
                        {
                            // Update the length of the Response Buffer
                            VltBlkPtcl_Response.u16Len = TempBlob.u16Len + VLT_BLOCK_PROTOCOL_HDR_SZ;

                        #ifdef TRACE_BLOCK_PTCL
                            printf("\n[BLOCK_R] ");
                            PrintHexBuffer(VltBlkPtcl_Response.pu8Data, VltBlkPtcl_Response.u16Len);
                        #endif

                            //
                            // Handle the response
                            VltBlkPtclHandleResponse( pInData );
                            if(VltBlkPtcl_u8ErrorCount !=0 )
                            {
                                // something bad happened
                                status = VLT_BLK_PTCL_ERROR_INVLD_RESP;
                            }
                        }
                    }
                }
            }
        }

        if (status != VLT_OK)
        {
            // Check that the maximum resync count is not reached
            if (VltBlkPtcl_u8ResynchSendCnt >= VLT_BLK_PTCL_MAX_RESYNC_ATTEMPTS)
            {
            #ifdef TRACE_BLOCK_PTCL_ERRORS
                printf("\nBlock Protocol: ERROR (too many rsync requests) \n");
            #endif
                return VLT_BLK_PTCL_ERROR_MAX_RSYNC; // abort
            }

            if(VltBlkPtcl_InitDone == FALSE)
            {
                // communication error during protocol init
                VltSleep(100 * VLT_MICRO_SECS_IN_MSEC);  // wait 100ms
                VltBlkPtclResetProtocol();
#ifdef TRACE_BLOCK_PTCL_ERRORS
                printf("\nresync request #%d \n", VltBlkPtcl_u8ResynchSendCnt);
#endif
            }
            else
            {
                // Check that the maximum error count is not reached
                if (VltBlkPtcl_u8ErrorCount >= VLT_BLK_PTCL_MAX_ERR_CNT )
                {
                    VltSleep(100 * VLT_MICRO_SECS_IN_MSEC);  // wait 100ms
                    VltBlkPtclResetProtocol();
                    VltBlkPtcl_RsyncInProgress = TRUE;
#ifdef TRACE_BLOCK_PTCL_ERRORS
                    printf("\nresync request #%d \n", VltBlkPtcl_u8ResynchSendCnt);
#endif
                }
                else
                {
#ifdef TRACE_BLOCK_PTCL_ERRORS
                    printf("\nBlock Protocol: WARNING (comm error #%d) \n", VltBlkPtcl_u8ErrorCount);
#endif
                }
            }

            status = VLT_OK; // clear status to stay in while loop
        }


#if defined(VAULT_IC_VLT_MORE_TIME_EXTERNAL)
    } while( (VLT_BLK_PTCL_ST_NORMAL != VltBlkPtcl_u8CurrentState) && ( VLT_OK == status ) && ( VLT_BLK_PTCL_ST_MORE_TIME != VltBlkPtcl_u8CurrentState ));
    if(( VLT_BLK_PTCL_ST_MORE_TIME == VltBlkPtcl_u8CurrentState ) && ( VLT_OK == status ))
    {
        status = VLT_MORE_TIME;
    }
#else
    } while( (VLT_BLK_PTCL_STATE_NORMAL != VltBlkPtcl_enState) && ( VLT_OK == status ) );
#endif

    return ( status );
}

VLT_BLK_PTCL_CODE_SECTION void VltBlkPtclResetProtocol( void)
{
    // Reset the protocol, update the state to show that we are
    // resynching at default parameters and set the status as VLT_OK
    // to allow an attempt to resync at default parameters
    VltBlkPtcl_theVltPeripheral.PeripheralIoctl(VLT_RESET_PROTOCOL, NULL);
    VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_RESYNCH;
    VltBlkPtcl_u8ErrorCount = 0;
    VltBlkPtcl_u8ResynchSendCnt++;
}




/**
 * @brief           Add the IBlock header to the block
 *
 * @warning         As it's a private function there is no parameters check
 *
 * @param[in]       pOutData    Pointer to the block
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          Nothing
 */
VLT_BLK_PTCL_CODE_SECTION void VltBlkPtclAddIBlockHeader( VLT_MEM_BLOB *pOutData )
{
    // If there is an SBlock to send, do nothing
    if( FALSE == VltBlkPtcl_u8SendSBlock )
    {
        // Set the Type Byte
        VltBlkPtcl_Command.pu8Data[BLK_PTCL_BLOCK_TYPE_OFFSET] = BLK_PTCL_IBLOCK_MASK | BLCK_PTCL_MASTER_SEND_MASK;

        // Set the Length to be the length of the command buffer which specifies the complete length of the APDU command
        VltBlkPtcl_Command.pu8Data[BLK_PTCL_LEN_MSB_OFFSET] = (VLT_U8)(pOutData->u16Len >> 8) & 0xFFu;
        VltBlkPtcl_Command.pu8Data[BLK_PTCL_LEN_LSB_OFFSET] = (VLT_U8)pOutData->u16Len & 0xFFu;
        VltBlkPtcl_Command.u16Len = pOutData->u16Len + VLT_BLOCK_PROTOCOL_HDR_SZ;

        // Add checksum
        VltBlkPtclAddCommandCheckSum( );

        // If any S or R-Block need to be sent they could corrupt some of the I-Block Data.
        // Back up the bytes that could be corrupted in case they are needed.
        (void)host_memcpy( &VltBlkPtcl_u8CmdBackupBuf[0], &(VltBlkPtcl_Command.pu8Data[VLT_BLOCK_PROTOCOL_HDR_SZ]), VLT_BLK_PTCL_TEMP_BUFFER_SIZE );
    }
}

/**
 * @brief           Manage the response
 *
 * @warning         As it's a private function there is no parameters check
 *
 * @param[in,out]       pInData    Pointer to the response to analyze
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          Nothing
 */
VLT_BLK_PTCL_CODE_SECTION void VltBlkPtclHandleResponse( VLT_MEM_BLOB* pInData )
{
    VLT_U8 u8BlockType;
    VLT_U16 u16Length;
    VLT_U16 u16RcvdCheckSum;
    VLT_U16 u16CalcCheckSum;

    // Check that the direction identifier within the Block Type is correct
    if( BLCK_PTCL_SLAVE_SEND_MASK != (VltBlkPtcl_Response.pu8Data[BLK_PTCL_BLOCK_TYPE_OFFSET] & BLCK_PTCL_SLAVE_SEND_MASK ) )
    {
#ifdef TRACE_BLOCK_PTCL_ERRORS
        printf("\n[BLK_PTCL_ST_RCVD_DATA_ERROR] Incorrect BLCK_PTCL_SLAVE_SEND_MASK %2.2X \n ", (unsigned) VltBlkPtcl_Response.pu8Data[BLK_PTCL_BLOCK_TYPE_OFFSET] & BLCK_PTCL_SLAVE_SEND_MASK);
#endif
        VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_SEND_RBLOCK ;
        VltBlkPtcl_u8ErrorCount++;
        return;
    }

    // Get the length
    u16Length = (((VLT_U16)VltBlkPtcl_Response.pu8Data[BLK_PTCL_LEN_MSB_OFFSET]) << 8) + VltBlkPtcl_Response.pu8Data[BLK_PTCL_LEN_LSB_OFFSET];

    // Check length is acceptable
    if(u16Length > VLT_MAX_APDU_RCV_TRANS_SIZE) // Max I-block size with 256 bytes of response data + 2 bytes of SW
    {
#ifdef TRACE_BLOCK_PTCL_ERRORS
        printf("\n[BLK_PTCL_ST_RCVD_DATA_ERROR] Incorrect Length received %2.2X\n ", u16Length);
#endif
        VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_SEND_RBLOCK;
        VltBlkPtcl_u8ErrorCount++;
        return;
    }

    // Validate the Checksum
    u16RcvdCheckSum = VltBlkPtcl_Response.pu8Data[VltBlkPtcl_Response.u16Len - sizeof(VLT_U8)];
    u16CalcCheckSum = VltBlkPtclCalculateSum8Checksum( VltBlkPtcl_Response.pu8Data, VltBlkPtcl_Response.u16Len - sizeof(VLT_U8) );

    // Check that the Checksums match
    if( u16CalcCheckSum != u16RcvdCheckSum )
    {
#ifdef TRACE_BLOCK_PTCL_ERRORS
        printf("\n[BLK_PTCL_ST_RCVD_DATA_ERROR] Incorrect Checksum received %2.2X expected %2.2X\n ", u16RcvdCheckSum, u16CalcCheckSum);
#endif
        VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_SEND_RBLOCK;
        VltBlkPtcl_u8ErrorCount++;
        return;
    }

    // Check the block type byte to determine the type of information received
    u8BlockType = VltBlkPtcl_Response.pu8Data[BLK_PTCL_BLOCK_TYPE_OFFSET] & BLK_PTCL_BLOCK_TYPE_MASK;
    switch( u8BlockType )
    {
        case BLK_PTCL_IBLOCK_MASK:
            if( (VltBlkPtcl_RsyncInProgress == TRUE) || (VltBlkPtcl_InitDone == FALSE) ||                     // reject if I-BLOCK during a R-SYNC
                 (VltBlkPtcl_Response.pu8Data[BLK_PTCL_BLOCK_TYPE_OFFSET] != BLK_PTCL_TYPE_SLAVE_IBLOCK) )
            {
                VltBlkPtcl_enState =  VLT_BLK_PTCL_STATE_SEND_RBLOCK ;
                VltBlkPtcl_u8ErrorCount++;
                break;
            }

            // Receive a IBlock :
            //  - Adjust the Response Buffer to remove the Block Protocol Info
            //      This requires that the data point back at the APDU command
            //      and that the length remove the Block Protocol Data length
            //  - Clear the error counter
            //  - Update the state
            pInData->pu8Data = &(VltBlkPtcl_Response.pu8Data[VLT_BLOCK_PROTOCOL_HDR_SZ]);
            pInData->u16Len = u16Length;
            VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_NORMAL ;
            VltBlkPtcl_u8ErrorCount = 0;
            break;

        case BLK_PTCL_SBLOCK_MASK:
            // Receive an SBlock
            //  - Manage the SBlock
            //  - The state and the error counter has been updated within VltBlkPtclHandleSBlockRsp()
            VltBlkPtclHandleSBlockRsp( );
            break;

        case BLK_PTCL_RBLOCK_MASK:
        default:
            // Receive an RBlock or unknown
            //  - Increment the error counter
            //  - Set the state to show that the last command didn't transmit correctly
            VltBlkPtcl_u8ErrorCount++;

            if (( VltBlkPtclCheckRBlockFormat() == TRUE) && ((VltBlkPtcl_enState == VLT_BLK_PTCL_STATE_NORMAL)||(VltBlkPtcl_enState == VLT_BLK_PTCL_STATE_RESEND_DATA)))
            {
                {
                    VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_RESEND_DATA;
                    VltBlkPtcl_ResendRequest = TRUE;
                }
            }
            else
            {
                VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_SEND_RBLOCK;
            }

            break;
    }
}


VLT_BLK_PTCL_CODE_SECTION VLT_BOOL VltBlkPtclCheckSBlockFormat( VLT_U8 u8Tag )
{
    // check S block format
    if( (VltBlkPtcl_Response.u16Len != 4) || // block size should be 4
        (VltBlkPtcl_Response.pu8Data[BLK_PTCL_BLOCK_TYPE_OFFSET] != u8Tag) ||
        (VltBlkPtcl_Response.pu8Data[BLK_PTCL_LEN_MSB_OFFSET] != 0x00) || // data length should be 00
        (VltBlkPtcl_Response.pu8Data[BLK_PTCL_LEN_LSB_OFFSET] != 0x00) )
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

VLT_BLK_PTCL_CODE_SECTION VLT_BOOL VltBlkPtclCheckRBlockFormat( void)
{
    // check R-block format
    if( (VltBlkPtcl_Response.u16Len != 4) || // block size should be 4
        (VltBlkPtcl_Response.pu8Data[BLK_PTCL_BLOCK_TYPE_OFFSET] != BLK_PTCL_TYPE_SLAVE_RBLOCK) ||
        (VltBlkPtcl_Response.pu8Data[BLK_PTCL_LEN_MSB_OFFSET] != 0x00) || // data length should be 00
        (VltBlkPtcl_Response.pu8Data[BLK_PTCL_LEN_LSB_OFFSET] != 0x00) )
    {
        return FALSE;
    }
    else
    {
        return TRUE;
    }
}

/**
 * @brief           Manage the SBlock response
 *
 * @param[in]       -
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          Nothing
 */
VLT_BLK_PTCL_CODE_SECTION void VltBlkPtclHandleSBlockRsp( void )
{
    VLT_U8 u8SBlkCmd;

    // Check the block type byte to determine the type of information received
    u8SBlkCmd = (VLT_U8)VltBlkPtcl_Response.pu8Data[BLK_PTCL_BLOCK_TYPE_OFFSET] & (VLT_U8)(~ (BLK_PTCL_BLOCK_TYPE_MASK | BLCK_PTCL_SLAVE_SEND_MASK ) );
    switch( u8SBlkCmd )
    {
        case BLK_PTCL_RESYNCH_MASK:
            // check block format
            if(VltBlkPtclCheckSBlockFormat(BLK_PTCL_TYPE_SLAVE_SRSYNC) != TRUE)
            {
                VltBlkPtcl_enState =  VLT_BLK_PTCL_STATE_SEND_RBLOCK ;
                VltBlkPtcl_u8ErrorCount++;
                break;
            }

            if( VltBlkPtcl_InitDone == FALSE)
            {
                // If here we are in the initial rsync
                VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_NORMAL;
                VltBlkPtcl_InitDone = TRUE;
                VltBlkPtcl_u8ResynchSendCnt = 0;
                VltBlkPtcl_u8ErrorCount=0;
            }
            else
            {
                if(VltBlkPtcl_RsyncInProgress == TRUE)
                {
                    // If here we are in a resynchro following several comm errors
                    if(VltBlkPtcl_ResendRequest == TRUE)
                    {
                        // If here the comm errors were detected by the slave
                        // so after the resynchro we need to resend the block
                        VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_RESEND_DATA;
                        VltBlkPtcl_ResendRequest = FALSE;
                    }
                    else
                    {
                        // If here the comm errors were detected by the master
                        // so after the resynchro we need to send a rblock to the slave
                        // to ask him to resend its block

                        // If here we got several comm errors leading to a rsync
                        VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_SEND_RBLOCK;
                    }

                    VltBlkPtcl_u8ErrorCount=0;
                    VltBlkPtcl_RsyncInProgress = FALSE;
                }
                else
                {
                    // S-Block Response received outside of a resynchro: something wrong!
                    VltBlkPtcl_enState =  VLT_BLK_PTCL_STATE_SEND_RBLOCK ;
                    VltBlkPtcl_u8ErrorCount++;
                }
            }
            break;

        case BLK_PTCL_MORE_TIME:
            // check block format
            if(VltBlkPtclCheckSBlockFormat(BLK_PTCL_TYPE_SLAVE_STIME) != TRUE)
            {
                VltBlkPtcl_enState =  VLT_BLK_PTCL_STATE_SEND_RBLOCK ;
                VltBlkPtcl_u8ErrorCount++;
                break;
            }

            // More time request :
            //  - Set the state to more time
            VltBlkPtcl_enState = VLT_BLK_PTCL_STATE_MORE_TIME ;
            VltBlkPtcl_u8ErrorCount = 0;
            break;

        default:
            // Unexpected S-Block Response received
            VltBlkPtcl_enState =  VLT_BLK_PTCL_STATE_SEND_RBLOCK ;
            VltBlkPtcl_u8ErrorCount++;
            break;
    }

    // Clear the flag to say that an S-Block has been built in the command buffer as S-Block has been dealt with
    VltBlkPtcl_u8SendSBlock = FALSE;
}

/**
 * @brief           Compute sum8 on data
 *
 * @warning         As it's a private function there is no parameters check
 *
 * @param[in]       pu8Data Pointer on the data
 * @param[in]       u16Len  The data length
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          The sum8
 */
VLT_BLK_PTCL_CODE_SECTION VLT_U8 VltBlkPtclCalculateSum8Checksum(VLT_U8 *pu8Data, VLT_U16 u16Len )
{
    VLT_U16 u16Pos;
    VLT_U8 u8Sum8 = 0;

    for( u16Pos = 0; u16Pos < u16Len; u16Pos++ )
    {
        u8Sum8 += pu8Data[u16Pos];
    }

    return ( u8Sum8 );
}

/**
 * @brief           Add the Block checksum
 *
 * @details         Calculate the specified checksum and add it after the APDU command data
 *
 * @param[in]       -
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          Nothing
 */
VLT_BLK_PTCL_CODE_SECTION void VltBlkPtclAddCommandCheckSum( void )
{
    VLT_U8 u8CalcCheckSum;
    u8CalcCheckSum = VltBlkPtclCalculateSum8Checksum (VltBlkPtcl_Command.pu8Data, VltBlkPtcl_Command.u16Len );
    VltBlkPtcl_Command.pu8Data[VltBlkPtcl_Command.u16Len] = u8CalcCheckSum;
    VltBlkPtcl_Command.u16Len += sizeof( VLT_U8 );
}

/**
 * @brief           Construct an RBlock for send
 *
 * @param[in]       -
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          Nothing
 */
VLT_BLK_PTCL_CODE_SECTION void VltBlkPtclConstructSendRBlock( void )
{
    // Set the Type Byte
    VltBlkPtcl_Command.pu8Data[BLK_PTCL_BLOCK_TYPE_OFFSET] = BLK_PTCL_RBLOCK_MASK | BLCK_PTCL_MASTER_SEND_MASK;

    // Set the Length
    VltBlkPtcl_Command.pu8Data[BLK_PTCL_LEN_MSB_OFFSET] = 0x00;
    VltBlkPtcl_Command.pu8Data[BLK_PTCL_LEN_LSB_OFFSET] = 0x00;

    // No data
    VltBlkPtcl_Command.u16Len = VLT_BLOCK_PROTOCOL_HDR_SZ;

    // Add checksum
    VltBlkPtclAddCommandCheckSum( );
}

/**
 * @brief           Construct an SBlock for send
 *
 * @note            The pointer to the data can be NULL as long as the length passed for the data is 0
 *
 * @warning         As it's a private function there is no parameters check
 *
 * @param[in]       u8SBlockCmdMask The SBlock type
 * @param[in]       u8Len           The Data length
 * @param[in]       pu8Data         Pointer on the data buffer
 * @param[out]      -
 * @param[in,out]   -
 *
 * @return          Nothing
 */
VLT_BLK_PTCL_CODE_SECTION void VltBlkPtclConstructSBlockSend( VLT_U8 u8SBlockCmdMask, VLT_U8 u8Len, VLT_U8 *pu8Data )
{
    // Set the Type Byte
    VltBlkPtcl_Command.pu8Data[BLK_PTCL_BLOCK_TYPE_OFFSET] = BLK_PTCL_SBLOCK_MASK | u8SBlockCmdMask | BLCK_PTCL_MASTER_SEND_MASK;

    // Set the Length.  No S-Block is bigger than a VLT_U8
    VltBlkPtcl_Command.pu8Data[BLK_PTCL_LEN_MSB_OFFSET] = 0x00;
    VltBlkPtcl_Command.pu8Data[BLK_PTCL_LEN_LSB_OFFSET] = u8Len;

    // Add the Data
    (void)host_memcpy(&VltBlkPtcl_Command.pu8Data[VLT_BLOCK_PROTOCOL_HDR_SZ], pu8Data, u8Len);
    VltBlkPtcl_Command.u16Len = ((VLT_U16)VLT_BLOCK_PROTOCOL_HDR_SZ) + u8Len;

    // Add checksum
    VltBlkPtclAddCommandCheckSum( );

    // Set the flag to say that an S-Block has been built in the command buffer
    VltBlkPtcl_u8SendSBlock = TRUE;
}

#endif /*( VLT_ENABLE_BLOCK_PROTOCOL == VLT_ENABLE ) */
