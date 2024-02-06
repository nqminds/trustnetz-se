/**
* @file	   vaultic_api.c
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
* @brief VaultIC API functions implementation
*
*/

#include "vaultic_common.h"
#include <comms/vaultic_comms.h>
#include "vaultic_utils.h"
#include "vaultic_mem.h"
#include "vaultic_cipher.h"
#include <tests/vaultic_cipher_tests.h>
#include "vaultic_apdu.h"
#include "vaultic_putkey_aux.h"
#include "vaultic_readkey_aux.h"
#if( VLT_ENABLE_API_DERIVE_KEY == VLT_ENABLE)
#include "vaultic_derivekey.h"
#endif
#include "vaultic_command.h"
#include "vaultic_api.h"
#include "vaultic_version.h"

/*
 * Local consts 
 */
#define VLT_PASS_MIN_LEN            (VLT_U8)0x04
#define VLT_PASS_MAX_LEN            (VLT_U8)0x20
#define VLT_SCRTKEY_HDR_LEN         (VLT_U8)0x04
#define VLT_FILENAME_MIN_LEN        (VLT_U8)0x02
#define VLT_FILENAME_MAX_LEN        (VLT_U8)0x09

#define VLT_STATE_SEND_MESSAGE      (VLT_U8)0x00
#define VLT_STATE_SEND_SIGNATURE    (VLT_U8)0x01
#define VLT_STATE_SEND_COMPLETE     (VLT_U8)0x02

#define STRINGER(x) #x
#define STRINGERIZE(x) STRINGER(x)

const VLT_U8 vltApiVersion[] = VAULTIC_API_VERSION " (for VaultIC" STRINGERIZE(VAULT_IC_VERSION) ")";



/*
 * Global variables
 */
#if(VLT_ENABLE_NO_WRAPKEY_CRC == VLT_ENABLE)
VLT_BOOL bSkipCRC = FALSE;
#endif

extern VLT_MEM_BLOB Command;
extern VLT_MEM_BLOB Response;
extern VLT_U16 idx;

VLT_MEM_BLOB Command;
VLT_MEM_BLOB Response;
VLT_U16 idx;
VLT_U8 VltApiInitDone=0;
VLT_U8 VltUpdateSignatureDone = 0;

VLT_STS VltApiInit(const VLT_INIT_COMMS_PARAMS *pInitCommsParams)
{    
    VLT_STS status;
    
/* Only perform the cipher tests if required. */
#if ( VLT_ENABLE_CIPHER_TESTS == VLT_ENABLE )
    status = DoCipherTests();
    if (VLT_OK != status) {
        return status;
    }
#endif

    if (VltApiInitDone == 1)
    {
        return VLT_FAIL;
    }

    status = VltCommsInit( pInitCommsParams, &Command, &Response );
    if(status == VLT_OK)
    {
    	VltApiInitDone = 1;
    }
    else
    {
    	VltApiInitDone = 0;
    	VltCommsClose();
    }
    return status;
}


VLT_STS VltApiClose( void )
{
	if (VltApiInitDone == 0) return VLT_OK;
	VltApiInitDone = 0;
	return( VltCommsClose( ) );
}


/* --------------------------------------------------------------------------
 * IDENTITY AUTHENTICATION COMMANDS
 * -------------------------------------------------------------------------- */

#if (VLT_ENABLE_API_SUBMIT_PASSWORD == VLT_ENABLE)
VLT_STS VltSubmitPassword(VLT_USER_ID enUserID, 
    VLT_ROLE_ID enRoleID,
    VLT_U8 u8PasswordLength,
    const VLT_U8 *pu8Password)
{ 
    VLT_STS status = VLT_FAIL;
    VLT_SW Sw = VLT_STATUS_NONE;    
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /*
     * Validate all input parameters.
     */                   
    if( NULL == pu8Password )
    {
        return( ESPNULLPARA );
    }

    /*
     * A password can only be between 0x04 and 0x20 bytes long
     */
    if( ( VLT_PASS_MAX_LEN < u8PasswordLength ) || 
        ( VLT_PASS_MIN_LEN > u8PasswordLength ) )
    {
        return( ESPPASSLENIVLD );
    }

    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_SUBMIT_PASSWORD;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = (VLT_U8)enUserID;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = (VLT_U8)enRoleID;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(u8PasswordLength);

    /* Build Data In */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( &Command.pu8Data[idx], pu8Password, u8PasswordLength);
    idx += u8PasswordLength;

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw);

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status ); 
}
#endif

#if (VLT_ENABLE_API_INITIALIZE_UPDATE == VLT_ENABLE)
VLT_STS VltInitializeUpdate(VLT_USER_ID enUserID, 
    VLT_ROLE_ID enRoleID,
    VLT_U8 u8HostChallengeLength,
    const VLT_U8 *pu8HostChallenge,
    VLT_INIT_UPDATE *pRespData )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;

    VLT_STS  status;
    VLT_BOOL bSCPMode; /* indicates SCP mode or MS mode */    
    VLT_U16  pu16Require=0;
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /*
    * Check the Repsonse Data parameter is not NULL
    */
    if( NULL == pRespData )
    {
        return( EIUNULLPARA ); 
    }

    /* If the host challenge is specified then the length must also be
     * specified, otherwise if the challenge is NULL then the length must be
     * zero. */

    if( ( ( 0u == u8HostChallengeLength ) && ( NULL != pu8HostChallenge ) )  ||
        ( ( 0u != u8HostChallengeLength ) && ( NULL == pu8HostChallenge ) ) )
    {
        return( EIUINVLDPARAM );
    }
    
    /* Are we in SCP mode, or MS mode?
     * Use the length of the host challenge to find out. */

    bSCPMode = (0u != u8HostChallengeLength);

    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_INITIALIZE_UPDATE;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = (VLT_U8) enUserID;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = (VLT_U8) enRoleID;
    if (bSCPMode)
    {
        /* This is a case #4 (case #3 + case #2) command: P3 is LIN. */
        Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(u8HostChallengeLength);

        /* Build Data In */
        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_memcpy( &Command.pu8Data[idx], pu8HostChallenge, u8HostChallengeLength);
        idx += u8HostChallengeLength;

        pu16Require = VLT_INITIALIZE_UPDATE_SCP_RSP_LENGTH;
    }

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, pu16Require, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    if(  VLT_OK != status )
    {
        return( status );
    }
    
    idx = 0;
    
    if( bSCPMode ) /* we're expecting an SCP03 response */
    {
        VLT_U8 u8ScpID = Response.pu8Data[VLT_SCP_IDENTIFIER_OFFSET];
        switch (u8ScpID)
        {

#if (VLT_ENABLE_SCP03 == VLT_ENABLE)
            case VLT_SCP_ID_SCP03:
                (void)host_memcpy(pRespData->data.Scp03.au8SerialNumber, &Response.pu8Data[idx], VLT_SCP_CHIP_SERIAL_LENGTH);
                idx += VLT_SCP_CHIP_SERIAL_LENGTH;
                idx += VLT_SCP_RFU_LENGTH;
                pRespData->data.Scp03.u8KeySetIndex = Response.pu8Data[idx++];
                pRespData->data.Scp03.u8ScpID = Response.pu8Data[idx++];

                pRespData->enLoginMethodID = VLT_AUTH_SCP03;

                /*
                * No need to check the return type as pointer has been validated
                */
                (void)host_memcpy(pRespData->data.Scp03.u8DeviceChallenge, &Response.pu8Data[idx],
                            VLT_SCP03_DEVICE_CHALLENGE_LENGTH);
                idx += VLT_SCP03_DEVICE_CHALLENGE_LENGTH;
                /*
                * No need to check the return type as pointer has been validated
                */
                (void)host_memcpy(pRespData->data.Scp03.u8Cryptogram, &Response.pu8Data[idx],
                            VLT_SCP_CRYPTOGRAM_LENGTH);
                idx += VLT_SCP_CRYPTOGRAM_LENGTH;
                break;
#endif

            default:
                return( EIUBADSCP ); /* unrecognised SCP identifier */
				break; //For MISRA compliancy
        }        
    }
    return( status );
}
#endif

#if (VLT_ENABLE_API_EXTERNAL_AUTHENTICATE == VLT_ENABLE)
VLT_STS VltExternalAuthenticate(VLT_AUTH_ID enAuthMethod,
    VLT_SEC_LEVEL_ID enChannelLevel,
    VLT_U8 u8CryptogramLength,
    const VLT_U8 *pu8Cryptogram )
{ 
    VLT_STS status;
    VLT_SW Sw = VLT_STATUS_NONE;
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* Is valid channel level? */
    if ( (VLT_NO_CHANNEL != enChannelLevel) &&
         (VLT_CMAC != enChannelLevel) &&
         (VLT_CMAC_CENC != enChannelLevel) &&
         (VLT_CMAC_RMAC != enChannelLevel) &&
         (VLT_CMAC_CENC_RMAC != enChannelLevel) &&
         (VLT_CMAC_CENC_RMAC_RENC != enChannelLevel)
       )
    {
        return(EEABADCHAN);
    }

    /*
     * Validate critical input parameters 
     */
    if( NULL == pu8Cryptogram )
    {
        return( EEANULLPARA );
    }

    if( 0u == u8CryptogramLength )
    {
        return( EEAIVLDCRPTLEN );
    }

    switch(enAuthMethod)
    {
        case VLT_AUTH_SCP03:
            Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_CHANNEL;
            Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_EXTERNAL_AUTHENTICATE_SCP;
            Command.pu8Data[VLT_APDU_P1_OFFSET] = (VLT_U8) enChannelLevel;
            break;

        default:
            return( EEABADCHAN );
			break; //For MISRA compliancy
    }
    
    /* Build APDU */
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(u8CryptogramLength);

    /* Build Data In */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( &Command.pu8Data[idx], pu8Cryptogram, u8CryptogramLength);
    idx += u8CryptogramLength;

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

/* Note: Manage Authentication Data is documented as permitting command
 * chaining but it never should need to use it as the P3 length field should
 * not exceed 0x4C. */

#if (VLT_ENABLE_API_MANAGE_AUTHENTICATION_DATA == VLT_ENABLE)
VLT_STS VltManageAuthenticationData( const VLT_MANAGE_AUTH_DATA *pAuthSetup )
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;    
    VLT_U16 u16Len;    
    VLT_U8 i;
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if( NULL == pAuthSetup )
    {
        return( EMADNULLPARA );
    }

    /* Build APDU */        
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_MANAGE_AUTHENTICATION_DATA;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = (VLT_U8) pAuthSetup->enUserID;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = (VLT_U8) pAuthSetup->enOperationID;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;


    /* Build Data In */
    /* The authentication data is sent only in the case of the create and
     * update operations. */
    if( ( pAuthSetup->enOperationID == VLT_CREATE_USER ) ||
        ( pAuthSetup->enOperationID == VLT_UPDATE_USER ) )
    {
        Command.pu8Data[idx++] = (VLT_U8) pAuthSetup->enMethod;
        Command.pu8Data[idx++] = (VLT_U8) pAuthSetup->enRoleID;
        Command.pu8Data[idx++] = (VLT_U8) pAuthSetup->enChannelLevel;
        Command.pu8Data[idx++] = (VLT_U8) pAuthSetup->enSecurityOption;
        Command.pu8Data[idx++] = pAuthSetup->u8TryCount;

        switch( pAuthSetup->enMethod )
        {
            case VLT_AUTH_PASSWORD:
                /*
                 * A password can only be between 0x04 and 0x20 bytes long
                 */
                if( ( VLT_PASS_MAX_LEN < pAuthSetup->data.password.u8PasswordLength ) || 
                    ( VLT_PASS_MIN_LEN > pAuthSetup->data.password.u8PasswordLength ) )
                {
                    return( EMADPASSLENIVLD );
                }
                u16Len = pAuthSetup->data.password.u8PasswordLength;

                Command.pu8Data[idx++] = (VLT_U8)((u16Len >> 8) & 0xFFu);
                Command.pu8Data[idx++] = (VLT_U8)((u16Len >> 0) & 0xFFu);

                /*
                * No need to check the return type as pointer has been validated
                */
                (void)host_memcpy( &Command.pu8Data[idx], 
                                pAuthSetup->data.password.u8Password,
                    pAuthSetup->data.password.u8PasswordLength );

                idx += pAuthSetup->data.password.u8PasswordLength;
                break;
#if (VLT_ENABLE_SEC_PWD == VLT_ENABLE)
            case VLT_AUTH_SECURE_PASSWORD:
            {
                u16Len = 5 + pAuthSetup->data.secPassword.u8PasswordLength + pAuthSetup->data.secPassword.aesKey.u16KeyLength;
                
                Command.pu8Data[idx++] = (VLT_U8)((u16Len >> 8) & 0xFFu);
                Command.pu8Data[idx++] = (VLT_U8)((u16Len >> 0) & 0xFFu);

                //Copy password length
                Command.pu8Data[idx++] = pAuthSetup->data.secPassword.u8PasswordLength;

                //Copy password value
                (void)host_memcpy(&Command.pu8Data[idx],
                    &pAuthSetup->data.secPassword.pu8Password[0],
                    pAuthSetup->data.secPassword.u8PasswordLength);

                idx += pAuthSetup->data.secPassword.u8PasswordLength;

                Command.pu8Data[idx++] = (VLT_U8)pAuthSetup->data.secPassword.aesKey.enKeyID;
                Command.pu8Data[idx++] = pAuthSetup->data.secPassword.aesKey.u8Mask;
                Command.pu8Data[idx++] = (VLT_U8)((pAuthSetup->data.secPassword.aesKey.u16KeyLength >> 8) & 0xFFu);
                Command.pu8Data[idx++] = (VLT_U8)((pAuthSetup->data.secPassword.aesKey.u16KeyLength >> 0) & 0xFFu);

                /*
                * No need to check the return type as pointer has been validated
                */
                (void)host_memcpyxor(&Command.pu8Data[idx],
                    pAuthSetup->data.secPassword.aesKey.pu8Key,
                    pAuthSetup->data.secPassword.aesKey.u16KeyLength,
                    pAuthSetup->data.secPassword.aesKey.u8Mask);

                idx += pAuthSetup->data.secPassword.aesKey.u16KeyLength;
                break;
            }
#endif

            case VLT_AUTH_SCP03:
                /*
                * SCP03 need an SMAC and SENC that is 2 keys.
                */
                if( 2u != pAuthSetup->data.secret.u8NumberOfKeys )
                {
                    return( EMADSCPKEYSINVLD );
                }   
                
                /*
                 * Calculate the key length 
                 */
                /* Add secret key header first */
                u16Len = ((VLT_U16)pAuthSetup->data.secret.u8NumberOfKeys) * VLT_SCRTKEY_HDR_LEN;
                for( i = 0; i < pAuthSetup->data.secret.u8NumberOfKeys; i++ )
                {
                    u16Len +=  pAuthSetup->data.secret.aKeys[i].u16KeyLength ;
                }

                Command.pu8Data[idx++] = (VLT_U8)((u16Len >> 8) & 0xFFu);
                Command.pu8Data[idx++] = (VLT_U8)((u16Len >> 0) & 0xFFu);

                /*
                 *  Set up the keys
                 */
                for( i = 0; i < pAuthSetup->data.secret.u8NumberOfKeys; i++ )
                {

                    Command.pu8Data[idx++] = (VLT_U8) pAuthSetup->data.secret.aKeys[i].enKeyID;
                    Command.pu8Data[idx++] = pAuthSetup->data.secret.aKeys[i].u8Mask;                   
                    Command.pu8Data[idx++] = (VLT_U8)( ( pAuthSetup->data.secret.aKeys[i].u16KeyLength >> 8 ) & 0xFFu );
                    Command.pu8Data[idx++] = (VLT_U8)( ( pAuthSetup->data.secret.aKeys[i].u16KeyLength >> 0 ) & 0xFFu );

                    /*
                    * No need to check the return type as pointer has been validated
                    */
                    (void)host_memcpyxor( &Command.pu8Data[idx],
                        pAuthSetup->data.secret.aKeys[i].pu8Key, 
                        pAuthSetup->data.secret.aKeys[i].u16KeyLength, 
                        pAuthSetup->data.secret.aKeys[i].u8Mask );

                    idx += pAuthSetup->data.secret.aKeys[i].u16KeyLength;
                }                   
                break;

            default:
                return( EMADBADOPER );
				break; //For MISRA compliancy
        }

        /* Update P3 now that we know the correct length. */
        Command.pu8Data[ VLT_APDU_P3_OFFSET ] = 
            LIN( WRAPPED_BYTE( idx - VLT_APDU_TYPICAL_HEADER_SZ ) );
    }

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return status;
}
#endif

#if (VLT_ENABLE_API_GET_AUTHENTICATION_INFO == VLT_ENABLE)
VLT_STS VltGetAuthenticationInfo( VLT_USER_ID enUserID, 
    VLT_AUTH_INFO *pRespData )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;
    idx = VLT_APDU_DATA_OFFSET;
    
    /*
     * Check VltApiInit done before
    */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if( NULL == pRespData )
    {
        return( EGAINULLPARA );
    }    

    if (enUserID < VLT_USER0 || enUserID > VLT_USER7)
    {
        return(EGAIINVDPARA);
    }

    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_GET_AUTHENTICATION_INFO;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = (VLT_U8) enUserID;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LEXP(VLT_GET_AUTH_INFO_P3);
    /* Send the command */
    status = VltCommand( &Command, &Response, idx, VLT_GET_AUTH_INFO_P3, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    if( VLT_OK != status )
    {
        return( status );
    }

    /* Unpack the response */
    idx = 0;    
    pRespData->enAuthMethod = (VLT_AUTH_ID)Response.pu8Data[idx++];
    pRespData->u8Roles = Response.pu8Data[idx++];
    pRespData->enMinSecurityLevel = (VLT_SEC_LEVEL_ID)Response.pu8Data[idx++];
    pRespData->u8RemainingTryCount = Response.pu8Data[idx++];
    pRespData->u8MaxTries = Response.pu8Data[idx++];
    pRespData->u16SequenceCount = VltEndianReadPU16( &Response.pu8Data[idx] );

    return( status );
}
#endif

#if (VLT_ENABLE_API_CANCEL_AUTHENTICATION == VLT_ENABLE)
VLT_STS VltCancelAuthentication( void )
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_CANCEL_AUTHENTICATION;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_GET_CHALLENGE == VLT_ENABLE)
VLT_STS VltGetChallenge(const VLT_GENERIC_AUTH_SETUP_DATA *pAuthParameters, 
    VLT_U8 *pu8DeviceChallenge )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;    
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /*
    * Check the input pointers
    */
    if( ( NULL == pAuthParameters ) || ( NULL == pu8DeviceChallenge ) )
    {
        return( EGCNULLPARA );
    }

    /* Pack the command data and the fixed initial part of the Generic Strong
     * Authentication parameters. */

    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_GET_CHALLENGE;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    /* P3 is filled out once the data has been built */

    /* Build Data In */

    Command.pu8Data[idx++] = pAuthParameters->u8ChallengeSize;
    Command.pu8Data[idx++] = pAuthParameters->u8Option;

    /* Append the variable sized identifiers portion of the GSA parameters only.
     * if it is required. */

    if( pAuthParameters->u8Option == VLT_GEN_AUTH_USE_IDENTIFIERS )
    {
        Command.pu8Data[idx++] = pAuthParameters->u8DeviceIdGroup;
        Command.pu8Data[idx++] = pAuthParameters->u8DeviceIdIndex;
        Command.pu8Data[idx++] = pAuthParameters->u8HostIdGroup;
        Command.pu8Data[idx++] = pAuthParameters->u8HostIdIndex;
    }

    /* Update P3 now that we know the correct length. */
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 
        LIN( WRAPPED_BYTE( idx - VLT_APDU_TYPICAL_HEADER_SZ ) );

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 
        pAuthParameters->u8ChallengeSize, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    if (VLT_OK != status)
    {
        return( status );
    }

    /* Unpack the response */
    idx = 0;    

    /* Unpack the challenge into the output buffer. */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( pu8DeviceChallenge, &Response.pu8Data[idx], 
        pAuthParameters->u8ChallengeSize );

    return( status );
}
#endif

#if (VLT_ENABLE_API_GENERIC_INTERNAL_AUTHENTICATE == VLT_ENABLE)
VLT_STS VltGenericInternalAuthenticate( 
    const VLT_GENERIC_AUTH_SETUP_DATA *pAuthParameters,
    const VLT_U8 *pu8HostChallenge,
    VLT_U8 *pu8DeviceChallenge,
    VLT_U16 *pu16SignatureLength,
    VLT_U16 u16SignatureCapacity,
    VLT_U8 *pu8Signature )
{ 
    VLT_STS status;
    VLT_SW Sw = VLT_STATUS_NONE; 
    VLT_U16 count = 0;   
    VLT_U8 bSgnRcvd;
    idx = VLT_APDU_DATA_OFFSET;
    VLT_U8 apduHeader[VLT_APDU_TYPICAL_HEADER_SZ];

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /*
     * Validate critical input parameters.
     */
    if( ( NULL == pAuthParameters ) ||
        ( NULL == pu8HostChallenge ) ||
        ( NULL == pu8DeviceChallenge ) ||
        ( NULL == pu16SignatureLength )  ||        
        ( NULL == pu8Signature ) )
    {
        return(EGIABADPARAM);
    }

    if( 0u == u16SignatureCapacity)
    {
        return( EGIAIVLDSIGLEN );
    }

    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_GEN_INTERNAL_AUTHENTICATE;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Cache the data in case we need to resend it */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( apduHeader, Command.pu8Data, VLT_APDU_TYPICAL_HEADER_SZ );

    /* Set up the bChallengeSize & bOption */
    Command.pu8Data[idx++] = pAuthParameters->u8ChallengeSize;
    Command.pu8Data[idx++] = pAuthParameters->u8Option;
    /*
     * If the bOption is set to use identifiers in the authentication protocol 
     * add them to the APDU, otherwise just add the Host Challenge
     */
    if (pAuthParameters->u8Option == VLT_GEN_AUTH_USE_IDENTIFIERS)
    {
        Command.pu8Data[idx++] = pAuthParameters->u8DeviceIdGroup;
        Command.pu8Data[idx++] = pAuthParameters->u8DeviceIdIndex;
        Command.pu8Data[idx++] = pAuthParameters->u8HostIdGroup;
        Command.pu8Data[idx++] = pAuthParameters->u8HostIdIndex;
    }

    /* Append the host challenge. */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( &Command.pu8Data[idx], 
        pu8HostChallenge, 
        pAuthParameters->u8ChallengeSize );

    idx += pAuthParameters->u8ChallengeSize;

    /* Update P3 now that we know the correct length. */
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN( 
        WRAPPED_BYTE( idx - VLT_APDU_TYPICAL_HEADER_SZ ) );

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    /* Check the status word */
    if( ( Sw != VLT_STATUS_NONE ) && 
        ( Sw != VLT_STATUS_SUCCESS ) && 
        ( Sw != VLT_STATUS_RESPONDING ) )
    {
        return( Sw );
    }
    /* Ensure the command didn't just failed */
    if( VLT_OK != status )
    {
        return( status );
    }

    /* Remove the status word size from the response length */
    Response.u16Len -= VLT_SW_SIZE ;

    /* Unpack the response */
    idx = 0;

    /* Unpack the device challenge */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( pu8DeviceChallenge, &Response.pu8Data[idx], pAuthParameters->u8ChallengeSize );
    idx += pAuthParameters->u8ChallengeSize;
    Response.u16Len -= pAuthParameters->u8ChallengeSize;

    /* Unpack the signature which may span more than one transaction */
    do
    {
        /* Check to see if we have received the whole signature */
        if( Sw == VLT_STATUS_RESPONDING )
        {
            bSgnRcvd = FALSE;
        }
        else
        {
            bSgnRcvd = TRUE;
        }

        /* Do we have enough space to copy the signature out to the caller? */
        if(u16SignatureCapacity < ( Response.u16Len + count ) )
        {
            return( EGIANOROOM );
        }
        else
        {
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy( &pu8Signature[ count ], 
                &Response.pu8Data[ idx ], 
                Response.u16Len );

            count += Response.u16Len;
        }

        if( FALSE == bSgnRcvd )
        {
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy( Command.pu8Data, apduHeader, VLT_APDU_TYPICAL_HEADER_SZ );

            /* Send the command */
            status = VltCommand( &Command, 
                &Response, 
                VLT_APDU_TYPICAL_HEADER_SZ,
                0, 
                &Sw );

            if( ( Sw != VLT_STATUS_NONE ) && 
                ( Sw != VLT_STATUS_SUCCESS ) && 
                ( Sw != VLT_STATUS_RESPONDING ) )
            {
                return( Sw );
            }

            if( VLT_OK != status )
            {
                return( status );
            } 

            /* Remove the status word size from the response length */
            Response.u16Len -= VLT_SW_SIZE ;
            /* Get the pointer to the response data */
            idx = 0;
        }
    }
    while( FALSE == bSgnRcvd );
    
    /* Let the caller know the size of the signature received */
    *pu16SignatureLength = count;

    return( status );
}
#endif

#if (VLT_ENABLE_API_GENERIC_EXTERNAL_AUTHENTICATE == VLT_ENABLE)
VLT_STS VltGenericExternalAuthenticate(VLT_U8 u8HostChallengeLength,
    const VLT_U8 *pu8HostChallenge,
    VLT_U16 u16HostSignatureLength,
    const VLT_U8 *pu8HostSignature )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;
    VLT_U16 size;
    VLT_U16 count = 0;
    VLT_U16 chunk;
    idx = 0;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if( ( NULL == pu8HostChallenge ) ||        
        ( NULL == pu8HostSignature ) )
    {
        return( EGEANULLPARA );
    }    

    if( 0u == u8HostChallengeLength )
    {
        return( EGEAINVLDHOSTCHLEN );
    }

    if( 0u == u16HostSignatureLength )
    {
        return( EGEAINVLDHOSTSIGLEN );
    }

    /* Total size of the payload */
    size = ( u16HostSignatureLength + u8HostChallengeLength );

    do 
    {
        /* Remaining data to send */
        chunk = (size - count);
        
        /*
         * If the remaining data to send is larger than our 
         * maximum buffer size chunk it down to the buffer size, 
         * otherwise just accept the size as is.
         */
        if( chunk > VltCommsGetMaxSendSize() )
        {
            chunk = VltCommsGetMaxSendSize();
            Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = VLT_CLA_CHAINING;
        }
        else
        {            
            Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = VLT_CLA_NO_CHANNEL; 
        }

        /* Set up the apdu */
        Command.pu8Data[ VLT_APDU_INS_OFFSET ] = VLT_INS_GEN_EXTERNAL_AUTHENTICATE;
        Command.pu8Data[ VLT_APDU_P1_OFFSET ] = 0;
        Command.pu8Data[ VLT_APDU_P2_OFFSET ] = 0;        
        Command.pu8Data[ VLT_APDU_P3_OFFSET ] = LIN(WRAPPED_BYTE(chunk));

        /*        
         * If this is the first time we transfer data then we need to 
         * account for the challenge part of the message. Otherwise
         * index in the right place of the signature and send the rest
         * of the data.
         */
        if( 0u == count )
        {
            /* Copy in the host challenge*/
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy( &Command.pu8Data[ VLT_APDU_DATA_OFFSET ], 
                pu8HostChallenge,             
                u8HostChallengeLength);            

            /* Update the index in the signature */
            idx = chunk - u8HostChallengeLength;

            /* Copy in part of the signature */
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy( &Command.pu8Data[ ( VLT_APDU_DATA_OFFSET + u8HostChallengeLength ) ], 
                pu8HostSignature, 
                idx);            
        }
        else
        {
            /* Copy in part of the signature */
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy( &Command.pu8Data[ VLT_APDU_DATA_OFFSET ], 
                &pu8HostSignature[idx], 
                chunk ); 

             /* Update the index in the signature */
            idx += chunk;
        }   

        /* Send the command */
        status = VltCommand( &Command, 
            &Response, 
            ( chunk + VLT_APDU_DATA_OFFSET ), 
            0, 
            &Sw );

        /* React to the status word */
        switch( Sw )
        {
            case VLT_STATUS_COMPLETED:
            case VLT_STATUS_SUCCESS:
                break;
            case VLT_STATUS_NONE:                
                return( status );
				break; //For MISRA compliancy
            default:
                return( Sw ); /* unexpected status word */
				break; //For MISRA compliancy
        }

        if (VLT_OK != status)
        {
            return status;
        }       
        
        /* Update the transfer progress */
        count += chunk;
    }
    while( count <  size );

    return( status );
}
#endif

#if (VLT_ENABLE_API_SUBMIT_SECURE_PASSWORD == VLT_ENABLE)
VLT_STS VltSubmitSecurePasswordInit(
    VLT_USER_ID enUserID,
    VLT_ROLE_ID enRoleID,
    VLT_U8 au8DeviceChallenge[VLT_SECURE_PWD_CHALLENGE_LENGTH])
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* Check User ID validity */
    if ((enUserID < VLT_USER0) || (enUserID > VLT_USER7))
    {
        return(ESSPINVLUSERID);
    }

    /* Check Role ID validity */
    if ((enRoleID != VLT_APPROVED_USER) &&
        (enRoleID != VLT_NON_APPROVED_USER) &&
        (enRoleID != VLT_MANUFACTURER) &&
        (enRoleID != VLT_ADMINISTRATOR) &&
        (enRoleID != VLT_NON_APPROVED_ADMINISTRATOR) &&
        (enRoleID != VLT_EVERYONE)
        )
    {
        return(ESSPINVLUSERID);
    }

    if (au8DeviceChallenge == NULL)
    {
        return ESSPNULLPARAM;
    }

    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_SUBMIT_SECURE_PASSWORD;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = enUserID;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = enRoleID;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LEXP(VLT_SECURE_PWD_CHALLENGE_LENGTH);

    /* Send the command */
    status = VltCommand(&Command, &Response, idx, 0, &Sw);

    if ((Sw != VLT_STATUS_NONE) && (Sw != VLT_STATUS_SUCCESS))
    {
        return(Sw);
    }

    if (VLT_OK != status)
    {
        return(status);
    }

    /* Unpack the challenge into the output buffer. */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy(au8DeviceChallenge, &Response.pu8Data[0],
        VLT_SECURE_PWD_CHALLENGE_LENGTH);

    return(status);
}

VLT_STS VltSubmitSecurePasswordFinal(
    VLT_USER_ID enUserID,
    VLT_ROLE_ID enRoleID,
    VLT_U8 u8EncPwdLen,
    const VLT_U8 *pu8EncPwd)
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* Check User ID validity */
    if ((enUserID < VLT_USER0) || (enUserID > VLT_USER7))
    {
        return(ESSPINVLUSERID);
    }

    /* Check Role ID validity */
    if ((enRoleID != VLT_APPROVED_USER) &&
        (enRoleID != VLT_NON_APPROVED_USER) &&
        (enRoleID != VLT_MANUFACTURER) &&
        (enRoleID != VLT_ADMINISTRATOR) &&
        (enRoleID != VLT_NON_APPROVED_ADMINISTRATOR) &&
        (enRoleID != VLT_EVERYONE)
       )
    {
        return(ESSPINVLUSERID);
    }

    if( (pu8EncPwd == NULL) || (u8EncPwdLen==0) )
    {
        return ESSPNULLPARAM;
    }

    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_SUBMIT_SECURE_PASSWORD;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = enUserID;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = enRoleID;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = u8EncPwdLen;

    /* Append the host challenge. */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy(&Command.pu8Data[idx],
        pu8EncPwd,
        u8EncPwdLen);

    idx += u8EncPwdLen;

 
    /* Send the command */
    status = VltCommand(&Command, &Response, idx, 0, &Sw);

    if ((Sw != VLT_STATUS_NONE) && (Sw != VLT_STATUS_SUCCESS))
    {
        return(Sw);
    }

    return(status);
}
#endif

/* --------------------------------------------------------------------------
 * CRYPTO SERVICES
 * -------------------------------------------------------------------------- */

#if (VLT_ENABLE_API_INITIALIZE_ALGORITHM == VLT_ENABLE)
VLT_STS VltInitializeAlgorithm(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_ALGO_MODE enMode,
    const VLT_ALGO_PARAMS *pAlgorithm )
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;    

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    VltUpdateSignatureDone = 0;

    idx = VLT_APDU_DATA_OFFSET;

    /* Check all pointers are valid pointer in the input arguments */
    if ( NULL == pAlgorithm )
    {
        return( EIANULLPARA );
    }

    /*
    * If the Algo ID specifies that a label is specified check that the length
    * of this can fit into the available buffer space
    */
	switch(pAlgorithm->u8AlgoID)
	{
#if( VLT_ENABLE_CIPHER_RSA == VLT_ENABLE)
	case VLT_ALG_CIP_RSAES_PKCS_OAEP:
	case VLT_ALG_KTS_RSA_OAEP_BASIC:
		{
		    VLT_U32 u32SendLen = (VLT_U32)pAlgorithm->data.RsaesOaep.u16LLen
                         + 1 /* Mode */ 
                         + 1 /* algo id*/;

			if( VltCommsGetMaxSendSize() < u32SendLen )
			{
				return( EIADATATOOLRG );
			}
			break;
		}
#endif

#if( VLT_ENABLE_CIPHER_AES_GCM == VLT_ENABLE )
    case VLT_ALG_CIP_GCM:
		{
			if (pAlgorithm->data.Gcm.pu8IvLen != NULL) //VaultIC 405
			{
				if (*pAlgorithm->data.Gcm.pu8IvLen != 0u && pAlgorithm->data.Gcm.pu8Iv == NULL) 
				{
					return( EIANULLPARA );
				}
			}
			else //Others VaultIC
			{
				if (pAlgorithm->data.Gcm.pu8Iv == NULL) 
				{
					return( EIANULLPARA );
				}
			}
			break;
		}
#endif
#if( VLT_ENABLE_SIGN_GMAC == VLT_ENABLE ) 
    case VLT_ALG_SIG_GMAC:
		{
			if (pAlgorithm->data.Gmac.pu8IvLen != NULL) //VaultIC 405
			{
				if (*pAlgorithm->data.Gmac.pu8IvLen != 0u && pAlgorithm->data.Gmac.pu8Iv == NULL) 
				{
					return( EIANULLPARA );
				}
			}
			else //Others VaultIC
			{
				if (pAlgorithm->data.Gmac.pu8Iv == NULL) 
				{
					return( EIANULLPARA );
				}
			}
			break;
		}
#endif
	default:
		break;
	}

    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_INITIALIZE_ALGORITHM;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
    /* P3 is filled out once the data has been built */

    /* Build Data In */

    Command.pu8Data[idx++] = (VLT_U8)enMode;
    Command.pu8Data[idx++] = pAlgorithm->u8AlgoID;

    switch( pAlgorithm->u8AlgoID )
    {
        case VLT_ALG_SIG_CMAC_AES:
            /* The Vault IC expects Padding method 2 and an all zero IV for
            * CMAC so no parameters are passed down 
            */
            break;
#if( VLT_ENABLE_SIGN_GMAC == VLT_ENABLE ) 
		case VLT_ALG_SIG_GMAC:
			 Command.pu8Data[idx++] = (VLT_U8) pAlgorithm->data.Gmac.enCipher;
			 Command.pu8Data[idx++] = pAlgorithm->data.Gmac.u8TagLen;
			 /*
            * No need to check the return type as pointer has been validated
            */
			if(pAlgorithm->data.Gmac.pu8IvLen != NULL) //Vaultic 405 case
			{
				Command.pu8Data[idx++] = *pAlgorithm->data.Gmac.pu8IvLen;
				(void)host_memcpy( &Command.pu8Data[idx], pAlgorithm->data.Gmac.pu8Iv, *pAlgorithm->data.Gmac.pu8IvLen);
				idx+= *pAlgorithm->data.Gmac.pu8IvLen;
			}
			else //Other VaultIC case
			{
				(void)host_memcpy( &Command.pu8Data[idx], pAlgorithm->data.Gmac.pu8Iv, VLT_GCM_IV_LENGTH);
				idx+= VLT_GCM_IV_LENGTH;
			}
			break;
#endif
#if( VLT_ENABLE_SIGN_HMAC == VLT_ENABLE )
        case VLT_ALG_SIG_HMAC:
            Command.pu8Data[idx++] = (VLT_U8) pAlgorithm->data.Hmac.enDigestId;
            Command.pu8Data[idx++] = pAlgorithm->data.Hmac.u8Output;
            break;
#endif

#if( VLT_ENABLE_KEY_HOTP == VLT_ENABLE)
        case VLT_ALG_SIG_HOTP:
            Command.pu8Data[idx++] = pAlgorithm->data.Otp.u8Output;
            break;
#endif

#if( VLT_ENABLE_KEY_TOTP == VLT_ENABLE)
        case VLT_ALG_SIG_TOTP:
            Command.pu8Data[idx++] = pAlgorithm->data.Otp.u8Output;
            break;
#endif

#if( VLT_ENABLE_SIGN_RSA == VLT_ENABLE)
        case VLT_ALG_SIG_RSASSA_PKCS_PSS:
            Command.pu8Data[idx++] = (VLT_U8)pAlgorithm->data.RsassaPss.enDigestIdPss;
            Command.pu8Data[idx++] = (VLT_U8)pAlgorithm->data.RsassaPss.enDigestIdMgf1;
            Command.pu8Data[idx++] = pAlgorithm->data.RsassaPss.u8SaltLength;
            break;

        case VLT_ALG_SIG_RSASSA_PKCS:
            Command.pu8Data[idx++] = (VLT_U8)pAlgorithm->data.RsassaPkcs.enDigestId;
            break;
#endif

#if (VLT_ENABLE_SIGN_xDSA == VLT_ENABLE)
#if((VAULT_IC_VERSION & VAULTIC_405_1_X_X) == VAULTIC_405_1_X_X)
		case VLT_ALG_SIG_ECDSA_GBCS:
#endif
        case VLT_ALG_SIG_ECDSA_GFP:
        case VLT_ALG_SIG_ECDSA_GF2M: 
            Command.pu8Data[idx++] = (VLT_U8)pAlgorithm->data.EcdsaDsa.enDigestId;
            break;
#endif

        case VLT_ALG_DIG_SHA1:
        case VLT_ALG_DIG_SHA224:
        case VLT_ALG_DIG_SHA256:
        case VLT_ALG_DIG_SHA384:
        case VLT_ALG_DIG_SHA512:
            /* no algorithm parameters */
            break;

        case VLT_ALG_CIP_AES:          
        case VLT_ALG_KTS_AES:       
            Command.pu8Data[idx++] = pAlgorithm->data.SymCipher.enMode;
            Command.pu8Data[idx++] = pAlgorithm->data.SymCipher.enPadding;
            
            (void)host_memcpy( &Command.pu8Data[idx], 
                pAlgorithm->data.SymCipher.u8Iv, 
                pAlgorithm->data.SymCipher.u8IvLength);

            idx += pAlgorithm->data.SymCipher.u8IvLength;
            break;
            
#if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE)
        case VLT_ALG_KTS_AES_P25:
            Command.pu8Data[idx++] = pAlgorithm->data.SymCipher.enPadding;
            break;
#endif

#if (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE)
        case VLT_ALG_KTS_AES_NIST_KWP:
            Command.pu8Data[idx++] = pAlgorithm->data.SymCipher.enPadding;
            break;
#endif

            
#if( VLT_ENABLE_CIPHER_RSA == VLT_ENABLE)
        case VLT_ALG_CIP_RSAES_PKCS_OAEP:
        case VLT_ALG_KTS_RSA_OAEP_BASIC:
            /* Check the pointers are valid before trying to use them */
            if ( ( NULL == pAlgorithm->data.RsaesOaep.pu8Label )&&
               ( 0u != pAlgorithm->data.RsaesOaep.u16LLen ) )
            {
                return ( EIAOAEPNULLPARA );
            }

            Command.pu8Data[idx++] = (VLT_U8)pAlgorithm->data.RsaesOaep.enDigestIdOaep;
            Command.pu8Data[idx++] = (VLT_U8)pAlgorithm->data.RsaesOaep.enDigestIdMgf1;
            Command.pu8Data[idx++] = (VLT_U8) ((pAlgorithm->data.RsaesOaep.u16LLen >> 8) & 0xFFu);
            Command.pu8Data[idx++] = (VLT_U8) ((pAlgorithm->data.RsaesOaep.u16LLen >> 0) & 0xFFu);
            /* FIXME: There's an assumption here that the label will be small enough
             *        to fit in the buffer. The label length is a U16 so could well
             *        need to span multiple chunks. */
            
            /* don't copy the label if the ptr is NULL. */            
            if ( NULL != pAlgorithm->data.RsaesOaep.pu8Label )
            {
                /*
                * No need to check the return type as pointer has been validated
                */
                (void)host_memcpy( &Command.pu8Data[idx], 
                    pAlgorithm->data.RsaesOaep.pu8Label,
                    pAlgorithm->data.RsaesOaep.u16LLen);
            }

            idx += pAlgorithm->data.RsaesOaep.u16LLen;
            break;

        case VLT_ALG_SIG_RSASSA_X509:/* "strongly discouraged" */
        case VLT_ALG_CIP_RSAES_PKCS:
        case VLT_ALG_CIP_RSAES_X509: /* "strongly discouraged" */
            /* no algorithm parameters */
            break;
#endif

#if( VLT_ENABLE_CIPHER_AES_GCM == VLT_ENABLE )
		case VLT_ALG_CIP_GCM:
			Command.pu8Data[idx++] = (VLT_U8) pAlgorithm->data.Gcm.enCipher;
			Command.pu8Data[idx++] = pAlgorithm->data.Gcm.u8TagLen;
			
			if(pAlgorithm->data.Gcm.pu8IvLen != NULL) //VaultIC 405 case
			{
				Command.pu8Data[idx++] = *pAlgorithm->data.Gcm.pu8IvLen;
				(void)host_memcpy( &Command.pu8Data[idx], pAlgorithm->data.Gcm.pu8Iv, *pAlgorithm->data.Gcm.pu8IvLen);
				idx += *pAlgorithm->data.Gcm.pu8IvLen;
			}
			else //Others VaultIC case
			{
				(void)host_memcpy( &Command.pu8Data[idx], pAlgorithm->data.Gcm.pu8Iv, VLT_GCM_IV_LENGTH);
				idx += VLT_GCM_IV_LENGTH;
			}

			Command.pu8Data[idx++] = (VLT_U8) ((pAlgorithm->data.Gcm.u16AddDataLen >> 8) & 0xFFu);
            Command.pu8Data[idx++] = (VLT_U8) ((pAlgorithm->data.Gcm.u16AddDataLen >> 0) & 0xFFu);
			(void)host_memcpy( &Command.pu8Data[idx], 
				pAlgorithm->data.Gcm.pu8AddData, 
				pAlgorithm->data.Gcm.u16AddDataLen);
			idx += pAlgorithm->data.Gcm.u16AddDataLen;
			break;
#endif
        default:
            return( EIABADALGO ); /* unrecognised algorithm */
			break; //For MISRA compliancy
    }

    /* Update P3 now that we know the correct length. */
    Command.pu8Data[VLT_APDU_P3_OFFSET] =
        LIN(WRAPPED_BYTE( idx - VLT_APDU_TYPICAL_HEADER_SZ ) );

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_UNINITIALIZE_ALGORITHM == VLT_ENABLE)
VLT_STS VltUnInitializeAlgorithm(void)
{
	VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;    

    /*
     * Check VltApiInit done before
    */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_INITIALIZE_ALGORITHM;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0x00;;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0x00;
    /* P3 is filled out once the data has been built */

    /* Build Data In */
    idx = VLT_APDU_DATA_OFFSET; // fix SDVAULTICAPI-145
    Command.pu8Data[idx++] = 0x00;

	  /* Update P3 now that we know the correct length. */
    Command.pu8Data[VLT_APDU_P3_OFFSET] =
        LIN(WRAPPED_BYTE( idx - VLT_APDU_TYPICAL_HEADER_SZ ) );

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_PUT_KEY == VLT_ENABLE)
VLT_STS VltPutKey(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
    const VLT_KEY_OBJECT *pKeyObj )
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;
    VLT_U8 u8KeyId;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if( ( NULL == pKeyFilePrivileges ) ||
        ( NULL == pKeyObj ) )
    {
        return( EPKNULLPARA );
    }

    u8KeyId = (VLT_U8)pKeyObj->enKeyID;

    switch(u8KeyId)
    {
#if(VLT_ENABLE_PUT_KEY_RAW == VLT_ENABLE)
    case VLT_KEY_RAW:
            status = VltPutKey_Raw(u8KeyGroup,
                u8KeyIndex,
                pKeyFilePrivileges,
                &(pKeyObj->data.RawKey),
                &Sw );
            break;
#endif

#if( VLT_ENABLE_PUT_KEY_SECRET == VLT_ENABLE )
            /* Secret key object */
        #if (VLT_ENABLE_CIPHER_AES == VLT_ENABLE)
        case VLT_KEY_AES_128:
        case VLT_KEY_AES_192:
        case VLT_KEY_AES_256:
        #endif
        case VLT_KEY_HMAC:
            status = VltPutKey_Secret( u8KeyGroup,
                u8KeyIndex,
                pKeyFilePrivileges,
                u8KeyId,
                &(pKeyObj->data.SecretKey),
                &Sw );
            break;
    #endif /* ( VLT_ENABLE_KEY_SECRET == VLT_ENABLE ) */

    #if( VLT_ENABLE_KEY_HOTP == VLT_ENABLE )
        case VLT_KEY_HOTP: /* HOTP key object */
            status = VltPutKey_Hotp( u8KeyGroup,
                u8KeyIndex,
                pKeyFilePrivileges,
                u8KeyId,
                &(pKeyObj->data.HotpKey),
                &Sw );
            break;
    #endif /* ( VLT_ENABLE_KEY_HOTP == VLT_ENABLE ) */

    #if( VLT_ENABLE_KEY_TOTP == VLT_ENABLE )
        case VLT_KEY_TOTP: /* TOTP key object */
            status = VltPutKey_Totp( u8KeyGroup,
                u8KeyIndex,
                pKeyFilePrivileges,
                u8KeyId,
                &(pKeyObj->data.TotpKey),
                &Sw );
            break;
    #endif /* ( VLT_ENABLE_KEY_TOTP == VLT_ENABLE ) */

    #if( VLT_ENABLE_KEY_RSA == VLT_ENABLE )
        case VLT_KEY_RSASSA_PUB: /* RSA public key object */
        case VLT_KEY_RSAES_PUB:
            status = VltPutKey_RsaPublic( u8KeyGroup,
                u8KeyIndex,
                pKeyFilePrivileges,
                u8KeyId,
                &(pKeyObj->data.RsaPubKey),
                &Sw );
            break;

        case VLT_KEY_RSASSA_PRIV: /* RSA private key object */
        case VLT_KEY_RSAES_PRIV:
            status = VltPutKey_RsaPrivate( u8KeyGroup,
                u8KeyIndex,
                pKeyFilePrivileges,
                u8KeyId,
                &(pKeyObj->data.RsaPrivKey),
                &Sw );
            break;

        case VLT_KEY_RSASSA_PRIV_CRT: /* RSA CRT private key object */
        case VLT_KEY_RSAES_PRIV_CRT:
            status = VltPutKey_RsaPrivateCrt( u8KeyGroup,
                u8KeyIndex,
                pKeyFilePrivileges,
                u8KeyId,
                &(pKeyObj->data.RsaPrivCrtKey),
                &Sw );
            break;
    #endif /* ( VLT_ENABLE_KEY_RSA == VLT_ENABLE ) */

#if( VLT_ENABLE_KEY_ECDSA == VLT_ENABLE )

#if( VLT_ENABLE_PUT_KEY_ECC_PUB == VLT_ENABLE )
		case VLT_KEY_ECC_PUB: /* ECC public key object */
			status = VltPutKey_EcdsaPublic( u8KeyGroup,
				u8KeyIndex,
				pKeyFilePrivileges,
                u8KeyId,
				&(pKeyObj->data.EcdsaPubKey),
				&Sw );
			break;
#endif

#if( VLT_ENABLE_PUT_KEY_ECC_PRIV == VLT_ENABLE )
		case VLT_KEY_ECC_PRIV: /* ECC private key object */
			status = VltPutKey_EcdsaPrivate( u8KeyGroup,
				u8KeyIndex,
				pKeyFilePrivileges,
                u8KeyId,
				&(pKeyObj->data.EcdsaPrivKey),
				&Sw );
			break;
#endif

#if( VLT_ENABLE_PUT_KEY_ECC_PARAMS == VLT_ENABLE )
		case VLT_KEY_ECC_PARAMS: /* ECC Domain key object */
            status = VltPutKey_EcdsaParams( u8KeyGroup,
                u8KeyIndex,
                pKeyFilePrivileges,
                u8KeyId,
                &(pKeyObj->data.EcdsaParamsKey),
                &Sw );
            break;
#endif

   #endif /* ( VLT_ENABLE_KEY_ECDSA == VLT_ENABLE ) */

#if( VLT_ENABLE_PUT_KEY_IDENTIFIER == VLT_ENABLE )

        case VLT_KEY_IDENTIFIER: /* Host/Device ID key object */
            status = VltPutKey_IdKey( u8KeyGroup,
                u8KeyIndex,
                pKeyFilePrivileges,
                u8KeyId,
                &(pKeyObj->data.IdentifierKey ),
                &Sw );
            break;

#endif /* ( VLT_ENABLE_KEY_IDENTIFIER == VLT_ENABLE ) */


        default:
            return( VLT_FAIL );
			break; //For MISRA compliancy
    }

    if( ( VLT_OK == status ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_READ_KEY == VLT_ENABLE)
VLT_STS VltReadKey( VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_KEY_OBJECT *pKeyObj )
{
    VLT_SW Sw = VLT_STATUS_NONE;    
    VLT_STS status;  
    
    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if (NULL == pKeyObj)
    {
        return(ERKNULLPARA);
    }

#if(VLT_ENABLE_NO_WRAPKEY_CRC == VLT_ENABLE)
    // Skip CRC if reading encrypted key (as not returned by VaultIC)
    bSkipCRC = (pKeyObj->enKeyID == VLT_KEY_RAW) && (pKeyObj->data.RawKey.isEncryptedKey == TRUE);

    if(bSkipCRC == FALSE)
#endif
    {
        /* initialise the crc for the read key */
        ReadKeyInitCrc();
    }

    /* read the first part of the key */
    status = VltReadKeyCommand( &Command, &Response, u8KeyGroup, u8KeyIndex, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && 
        ( Sw != VLT_STATUS_SUCCESS ) && 
        ( Sw != VLT_STATUS_RESPONDING ) )
    {
        return( Sw );
    }

    if( VLT_OK != status )
    {
        return( status );
    }

    /* We're going to rely on the client to expect the right sort of key, since
     * they have to allocate all of the data buffers required before we're
     * called. However, we need some level of safety so we require that the
     * client fill out the pKeyObj->u8KeyID with the type of key they're
     * expecting. If when we retrieve the key it's not the expected type then we
     * terminate early with an error. */

    if( VLT_KEY_RAW != pKeyObj->enKeyID )
    {
        if( Response.pu8Data[0] != (VLT_U8)pKeyObj->enKeyID )
        {
            return( ERKMISMATCH );
        }
    }
    
    switch( pKeyObj->enKeyID )
    {
#if(VLT_ENABLE_READ_KEY_RAW == VLT_ENABLE)
    case VLT_KEY_RAW:
            return( VltReadKey_Raw( u8KeyGroup, u8KeyIndex,
                &pKeyObj->data.RawKey, &Sw ) );
			break; //For MISRA compliancy
#endif

#if( VLT_ENABLE_KEY_SECRET == VLT_ENABLE )
#if(VLT_ENABLE_READ_KEY_SECRET == VLT_ENABLE)
    /* Secret key object */
        #if (VLT_ENABLE_CIPHER_AES == VLT_ENABLE)
        case VLT_KEY_AES_128:
        case VLT_KEY_AES_192:
        case VLT_KEY_AES_256:
        #endif
#if( VLT_ENABLE_ECDH == VLT_ENABLE )
        case VLT_KEY_SECRET_VALUE:
#endif
        case VLT_KEY_HMAC:            
            return( VltReadKey_Secret( &pKeyObj->data.SecretKey, &Sw ) );    
			break; //For MISRA compliancy
#endif //(VLT_ENABLE_READ_KEY_SECRET == VLT_ENABLE)
#endif /* ( VLT_ENABLE_KEY_SECRET == VLT_ENABLE ) */

    /* HOTP key object */
    #if( VLT_ENABLE_KEY_HOTP == VLT_ENABLE )
        case VLT_KEY_HOTP:             
            return( VltReadKey_Hotp( &pKeyObj->data.HotpKey, &Sw ) );  
			break; //For MISRA compliancy
    #endif /* ( VLT_ENABLE_KEY_HOTP == VLT_ENABLE ) */

    /* TOTP key object */
    #if( VLT_ENABLE_KEY_TOTP == VLT_ENABLE )
        case VLT_KEY_TOTP: 
            return( VltReadKey_Totp( &pKeyObj->data.TotpKey, &Sw ) );  
			break; //For MISRA compliancy
    #endif /* ( VLT_ENABLE_KEY_TOTP == VLT_ENABLE ) */

    #if( VLT_ENABLE_KEY_RSA == VLT_ENABLE )
        /* RSA public key object */
        case VLT_KEY_RSASSA_PUB: 
        case VLT_KEY_RSAES_PUB:            
            return( VltReadKey_RsaPublic( u8KeyGroup, u8KeyIndex,
                &pKeyObj->data.RsaPubKey, &Sw ) );  
			break; //For MISRA compliancy
        /* RSA private key object */
        case VLT_KEY_RSASSA_PRIV: 
        case VLT_KEY_RSAES_PRIV:            
            return( VltReadKey_RsaPrivate( u8KeyGroup, u8KeyIndex,
                &pKeyObj->data.RsaPrivKey, &Sw ) ); 
			break; //For MISRA compliancy
        /* RSA CRT private key object */
        case VLT_KEY_RSASSA_PRIV_CRT: 
        case VLT_KEY_RSAES_PRIV_CRT:
            return( VltReadKey_RsaPrivateCrt( u8KeyGroup, u8KeyIndex,
                &pKeyObj->data.RsaPrivCrtKey, &Sw ) );
			break; //For MISRA compliancy
    #endif /* ( VLT_ENABLE_KEY_RSA == VLT_ENABLE ) */

    #if( VLT_ENABLE_KEY_ECDSA == VLT_ENABLE )
#if(VLT_ENABLE_READ_KEY_ECC_PUB == VLT_ENABLE)
			/* ECC public key object */
        case VLT_KEY_ECC_PUB:             
            return( VltReadKey_EcdsaPublic( u8KeyGroup, u8KeyIndex,
                &pKeyObj->data.EcdsaPubKey, &Sw ) );
			break; //For MISRA compliancy
#endif //(VLT_ENABLE_READ_KEY_ECC_PUB == VLT_ENABLE)

#if(VLT_ENABLE_READ_KEY_ECC_PRIV == VLT_ENABLE)
        /* ECC private key object */
        case VLT_KEY_ECC_PRIV:             
            return( VltReadKey_EcdsaPrivate( u8KeyGroup, u8KeyIndex,
                &pKeyObj->data.EcdsaPrivKey, &Sw ) );
			break; //For MISRA compliancy        
        /* DSA Params key object */
#endif

#if(VLT_ENABLE_READ_KEY_ECC_PARAMS == VLT_ENABLE)
        case VLT_KEY_ECC_PARAMS:
            return( VltReadKey_EcdsaParams( u8KeyGroup, u8KeyIndex,
                &pKeyObj->data.EcdsaParamsKey, &Sw ) );
			break; //For MISRA compliancy 

    #endif /* ( VLT_ENABLE_KEY_ECDSA == VLT_ENABLE ) */
#endif //(VLT_ENABLE_READ_KEY_ECC_PARAMS == VLT_ENABLE)
			    
    #if( VLT_ENABLE_KEY_IDENTIFIER == VLT_ENABLE )
#if(VLT_ENABLE_READ_KEY_IDENTIFIER == VLT_ENABLE)
        /* Host/Device ID key object */
        case VLT_KEY_IDENTIFIER:
            return( VltReadKey_IdKey( u8KeyGroup, u8KeyIndex,
                &pKeyObj->data.IdentifierKey, &Sw ) );
			break; //For MISRA compliancy
    #endif /* ( VLT_ENABLE_KEY_IDENTIFIER == VLT_ENABLE ) */
#endif //(VLT_ENABLE_READ_KEY_IDENTIFIER == VLT_ENABLE)
        default:
            return( ERKUNSUPPKEY );
			break; //For MISRA compliancy
    }
}
#endif

#if (VLT_ENABLE_API_DELETE_KEY == VLT_ENABLE)
VLT_STS VltDeleteKey( VLT_U8 u8KeyGroup, VLT_U8 u8KeyIndex )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_DELETE_KEY;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_ENCRYPT == VLT_ENABLE)
VLT_STS VltEncrypt( VLT_U32 u32PlainTextLength,
    const VLT_U8 *pu8PlainText,
    VLT_U32 *pu32CipherTextLength,
    VLT_U32 u32CipherTextCapacity,
    VLT_U8 *pu8CipherText )
{
    /* Ensure that the input buffer is specified. The remainder of the parameter
     * checking happens inside VltCase4. */
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if( NULL == pu8PlainText )
    {
        return( EENULLPARA );
    }

    if ( 0u == u32PlainTextLength  )
    {
        return( EENINVLDPLTXTLEN );
    }

    status = VltCase4(VLT_INS_ENCRYPT_DECRYPT, 
        0,
        u32PlainTextLength, 
        pu8PlainText,
        pu32CipherTextLength, 
        u32CipherTextCapacity,
        pu8CipherText, 
        &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_DECRYPT == VLT_ENABLE)
VLT_STS VltDecrypt( VLT_U32 u32CipherTextLength,
    const VLT_U8 *pu8CipherText,
    VLT_U32 *pu32PlainTextLength,
    VLT_U32 u32PlainTextCapacity,
    VLT_U8 *pu8PlainText )
{ 
    /* Ensure that the input buffer is specified. The remainder of the parameter
     * checking happens inside VltCase4. */
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }


    if( NULL == pu8CipherText )
    {
        return( EDNULLPARA );
    }

    if( 0u == u32CipherTextLength )
    {
        return( EDCINVLDCHPTXTLEN );
    }

    status = VltCase4( VLT_INS_ENCRYPT_DECRYPT, 
        0,
        u32CipherTextLength, 
        pu8CipherText,
        pu32PlainTextLength, 
        u32PlainTextCapacity,
        pu8PlainText, 
        &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_GENERATE_ASSURANCE_MESSAGE == VLT_ENABLE)
VLT_STS VltGenerateAssuranceMessage( 
    VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    VLT_U8 *pu8SignerIdLength,
    const VLT_U8 *pu8SignerID,
    VLT_ASSURANCE_MESSAGE* pAssuranceMsg  )
{ 
    VLT_STS status = VLT_FAIL;
    VLT_SW Sw = VLT_STATUS_NONE;   
    VLT_U8 au8SignerID[VLT_GA_SIGNER_ID_LENGTH];

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }
    
    /* validate critical parameters */
    if( ( NULL == pAssuranceMsg ) || 
        ( NULL == pu8SignerID ) || 
        ( NULL == pu8SignerIdLength )||
        ( NULL == pAssuranceMsg->pu8AssuranceMessage ) ||
        ( NULL == pAssuranceMsg->pu8VerifierID ) )
    {
        return( EGASNULLPARA );
    }

    /** 
     * validate the signer ID, Verifier ID, and 
     * Assurance Message buffer lengths
     * match the required length 
     */
    if ( ( VLT_GA_SIGNER_ID_LENGTH != *pu8SignerIdLength ) ||
         ( pAssuranceMsg->u8VerifierIdLength < VLT_GA_VERIFIER_ID_LENGTH ) ||
         ( pAssuranceMsg->u8AssuranceMessageLength < VLT_GA_MESSAGE_LENGTH ))
    {
        return ( EGASINVLDLEN );
    }

    /* backup signer id for later check with response */
    host_memcpy(au8SignerID, pu8SignerID, VLT_GA_SIGNER_ID_LENGTH);

    /* set the index offset */
    idx = VLT_APDU_DATA_OFFSET;

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_GENERATE_ASSURANCE_MESSAGE;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LEXP( *pu8SignerIdLength );

    /* copy the Signer ID into the command buffer */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( &Command.pu8Data[idx], pu8SignerID, *pu8SignerIdLength );
    idx += *pu8SignerIdLength;

    /* send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    if (VLT_OK != status)
    {
        return status;
    }

    Response.u16Len -= VLT_SW_SIZE;

    /**
     * Check the length of the response is equal to the expected length
    */
    if ( VLT_GA_SIGNER_ID_LENGTH + 
         VLT_GA_VERIFIER_ID_LENGTH + 
         VLT_GA_MESSAGE_LENGTH != Response.u16Len )
    {
        return ( EGAINVLDRECLEN );
    }
    

    /* Unpack the response */    
    idx = 0;
    
    /* Check the signer ID is the same */
    if (host_memcmp(au8SignerID, &Response.pu8Data[idx], VLT_GA_SIGNER_ID_LENGTH) != 0)
    {
        return EGAINVLDSIGNERID;
    }
    *pu8SignerIdLength = VLT_GA_SIGNER_ID_LENGTH;
    idx += VLT_GA_SIGNER_ID_LENGTH;
    
    /* Copy out the Verifier ID byte stream. */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( pAssuranceMsg->pu8VerifierID, &Response.pu8Data[idx], VLT_GA_VERIFIER_ID_LENGTH );
    pAssuranceMsg->u8VerifierIdLength = VLT_GA_VERIFIER_ID_LENGTH;
    idx += VLT_GA_VERIFIER_ID_LENGTH;
    
    /* Copy out the assurance message byte stream. */
    (void)host_memcpy( pAssuranceMsg->pu8AssuranceMessage, &Response.pu8Data[idx], VLT_GA_MESSAGE_LENGTH );
    pAssuranceMsg->u8AssuranceMessageLength = VLT_GA_MESSAGE_LENGTH;
    idx += VLT_GA_MESSAGE_LENGTH;
 
    return( status );    
}
#endif

#if (VLT_ENABLE_API_GENERATE_SIGNATURE == VLT_ENABLE)
VLT_STS VltGenerateSignature(VLT_U32 u32MessageLength,
    const VLT_U8 *pu8Message,
    VLT_U16 *pu16SignatureLength,
    VLT_U16 u16SignatureCapacity,
    VLT_U8 *pu8Signature)
{ 
    VLT_STS status = VLT_FAIL;
    VLT_U32 u32SignatureLength;
    VLT_SW Sw = VLT_STATUS_NONE;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* Ensure that the signature length is specified as we use it here. The
     * remainder of the parameter checking happens inside VltCase4. */
    if (NULL == pu16SignatureLength)
    {
        return( EGSNULLPARA );
    }

    status = VltCase4( VLT_INS_GENERATE_VERIFY_SIGNATURE,
        0,
        u32MessageLength,
        pu8Message,
        &u32SignatureLength,
        u16SignatureCapacity,
        pu8Signature,
        &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    *pu16SignatureLength = (VLT_U16) u32SignatureLength; /*actual size of signature stored in the buffer*/

    return( status );
}
#endif

#if (VLT_ENABLE_API_UPDATE_SIGNATURE == VLT_ENABLE)
VLT_STS VltUpdateSignature(VLT_U32 u32MessagePartLength,
                           const VLT_U8 *pu8MessagePart)
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;

    VLT_U16 u16Idx; 
    VLT_U16 u16MaxChunk;
    VLT_U32 u32Remaining;
  
    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if (0 == u32MessagePartLength)
    {
        return(EGSINVLLENGTH);
    }
    if (pu8MessagePart == NULL)
    {
        return(EGSNULLPARA);
    }

    u16MaxChunk  = VltCommsGetMaxSendSize();
    u32Remaining = u32MessagePartLength;

    do
    {
        VLT_U16 u16Chunk;

        /* Build APDU. We have to do this on every iteration as the output of
         * the previous iteration will have overwritten it (assuming a shared
         * buffer). */
        u16Idx = VLT_APDU_DATA_OFFSET ;

        u16Chunk = (u32Remaining > u16MaxChunk) ? u16MaxChunk : (VLT_U16) u32Remaining;
        
        Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = VLT_CLA_CHAINING;
        Command.pu8Data[ VLT_APDU_INS_OFFSET ] = VLT_INS_GENERATE_VERIFY_SIGNATURE;
        Command.pu8Data[ VLT_APDU_P1_OFFSET ] = 0;
        Command.pu8Data[ VLT_APDU_P2_OFFSET ] = 0;
        Command.pu8Data[ VLT_APDU_P3_OFFSET ] = LIN(WRAPPED_BYTE(u16Chunk));

        if( 0 != u16Chunk )
        {
            /* Build Data In */

            host_memcpy( &Command.pu8Data[u16Idx], pu8MessagePart, u16Chunk );
            u16Idx += u16Chunk;
            pu8MessagePart += u16Chunk;
        }

        /* Send the command */

        status = VltCommand( &Command, &Response, u16Idx, 0, &Sw );

        if (VLT_OK != status)
        {
            return status;
        }

        u32Remaining -= u16Chunk;
    }
    while (u32Remaining > 0u && Sw == VLT_STATUS_NEXT_MESSAGE_PART_EXPECTED);

    if( ( Sw != VLT_STATUS_NONE ) && 
        ( Sw != VLT_STATUS_SUCCESS ) && 
        ( Sw != VLT_STATUS_COMPLETED  ) )
    {
        return( Sw );
    }

    VltUpdateSignatureDone = 1;

    return( status );
}
#endif

#if (VLT_ENABLE_API_COMPUTE_SIGNATURE_FINAL == VLT_ENABLE)
VLT_STS VltComputeSignatureFinal( VLT_U16 *pu16SignatureLength,
    VLT_U16 u16SignatureCapacity,
    VLT_U8 *pu8Signature )
{
    VLT_STS status = VLT_FAIL;
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_U32 u32SignatureLength;
    VLT_U16 u16Idx; 
    
    VLT_U8 *pu8Out;
    VLT_U8 *pu8OutEnd;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /*
    * Check VltUpdateSignature done before
    */
    if (VltUpdateSignatureDone == 0)
    {
        return VLT_FAIL;
    }
    
    VltUpdateSignatureDone = 0;

    if (NULL == pu16SignatureLength || NULL == pu8Signature)
    {
        return( EGSNULLPARA );
    }

    u32SignatureLength = u16SignatureCapacity;

    /* We need to split the data up into chunks, the size of which the comms
     * layer tells us. */
    pu8Out = pu8Signature;
    pu8OutEnd = pu8Signature + u32SignatureLength;

    do
    {
        /* Build APDU. We have to do this on every iteration as the output of
         * the previous iteration will have overwritten it (assuming a shared
         * buffer). */
        u16Idx = VLT_APDU_DATA_OFFSET ;

        Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = VLT_CLA_NO_CHANNEL; 
        Command.pu8Data[ VLT_APDU_INS_OFFSET ] = VLT_INS_GENERATE_VERIFY_SIGNATURE;
        Command.pu8Data[ VLT_APDU_P1_OFFSET ] = 0;
        Command.pu8Data[ VLT_APDU_P2_OFFSET ] = 0;
        Command.pu8Data[ VLT_APDU_P3_OFFSET ] = 0;

        /* Send the command */

        status = VltCommand( &Command, &Response, u16Idx, 0, &Sw );

        if (VLT_OK != status)
        {
            return status;
        }

        /* How big is the response? */
        Response.u16Len -= VLT_SW_SIZE;

        /* Copy */
        if( ( pu8Out + Response.u16Len ) > pu8OutEnd )
        {
            /* ran out of output buffer space */
            *pu16SignatureLength = Response.u16Len;
            return( EC4NOROOM ); 
        }

        host_memcpy( pu8Out, Response.pu8Data, Response.u16Len );
        pu8Out += Response.u16Len;

        /* Check response code */
        switch( Sw )
        {
            case VLT_STATUS_COMPLETED:
            case VLT_STATUS_RESPONDING:
            case VLT_STATUS_SUCCESS:
                break;
            case VLT_STATUS_NONE: 
                return( status );
				break; //For MISRA compliancy
            default:
                return Sw; /* unexpected status word */
				break; //For MISRA compliancy
        }
    }
    while (Sw == VLT_STATUS_RESPONDING);

    /* Report the final amount of data produced */
    u32SignatureLength = (VLT_U32)(pu8Out - pu8Signature);

	if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    *pu16SignatureLength = (VLT_U16) u32SignatureLength;

    return( status );
}
#endif

#if (VLT_ENABLE_API_VERIFY_SIGNATURE == VLT_ENABLE)
VLT_STS VltVerifySignature( VLT_U32 u32MessageLength,
    const VLT_U8 *pu8Message,
    VLT_U16 u16SignatureLength,
    const VLT_U8 *pu8Signature )
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;
    VLT_U8 state = VLT_STATE_SEND_MESSAGE;
    VLT_U16 u16Chunk = 0;
    VLT_U32 u32Remaining;
    const VLT_U8 *pu8In ;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* validate critical parameters */
    if( ( NULL == pu8Message ) ||
        ( NULL == pu8Signature ) )
    {
        return( EVSNULLPARA );
    }

    if( 0 == u32MessageLength )
    {
        return( EVSINVLDMSGLEN );
    }

    if( 0 == u16SignatureLength )
    {
        return( EVSINVLDSIGLEN );
    }

    /* 
     * Cycle through the send states:
     *  o - VLT_STATE_SEND_MESSAGE  
     *  o - VLT_STATE_SEND_SIGNATURE 
     */
    while( state < VLT_STATE_SEND_COMPLETE )
    {
        /*
         * set up state configuration data
         */
        switch( state )
        {
            case VLT_STATE_SEND_MESSAGE:
                u32Remaining = u32MessageLength;
                pu8In = pu8Message;
                break;
            case VLT_STATE_SEND_SIGNATURE:
                u32Remaining = u16SignatureLength;
                pu8In = pu8Signature;
                break;
            default:
                return( EVSINVLDSTATECFG );
				break; //For MISRA compliancy
        }

        /*
         * transfer data 
         */
        while( u32Remaining )
        {
            /* set the index offset */
            idx = VLT_APDU_DATA_OFFSET;

            /* determine the size of the transfer */
            if( VltCommsGetMaxSendSize() < u32Remaining )
            {
                u16Chunk = VltCommsGetMaxSendSize();
                    Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = 
                    VLT_CLA_CHAINING;
            }
            else
            {
                u16Chunk = (VLT_U16)u32Remaining;
                Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = 
                    VLT_CLA_NO_CHANNEL;
            }

            /* build apdu */
            Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_GENERATE_VERIFY_SIGNATURE;
            Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
            Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
            Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN( WRAPPED_BYTE( u16Chunk ) );
            /* copy the data */
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy( &Command.pu8Data[idx], pu8In, u16Chunk );
            idx += u16Chunk;
            pu8In += u16Chunk;
            /* send the command */
            status = VltCommand( &Command, &Response, idx, 0, &Sw );

            /*
             * validate the status word based on the current state
             */
            if( VLT_STATE_SEND_MESSAGE == state )
            {
               if( ( Sw != VLT_STATUS_NEXT_MESSAGE_PART_EXPECTED ) &&
                   ( Sw != VLT_STATUS_NEXT_SIGNATURE_PART_EXPECTED )&& 
                   ( Sw != VLT_STATUS_NONE ) )
               {
                   return( Sw );
               }
            }
            else if( VLT_STATE_SEND_SIGNATURE == state )
            {    
               if( ( Sw != VLT_STATUS_NEXT_SIGNATURE_PART_EXPECTED ) &&
                   ( Sw != VLT_STATUS_SUCCESS )&& 
                   ( Sw != VLT_STATUS_NONE ) )
               {
                   return( Sw );
               }
            }
            else
            {
                return( EVSINVLDSTATESND );
            }

            /* validate the transfer status */
            if( VLT_OK != status ) 
            {
                return( status );
            }
            
            /* update the transfer progress */
            u32Remaining -= u16Chunk;            
        }

        /* transition to the next state */
        ++state;
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_UPDATE_VERIFY == VLT_ENABLE)
VLT_STS VltUpdateVerify(VLT_U32 u32MessageLength,
                           const VLT_U8 *pu8Message)
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;
    
    VLT_U16 u16Idx; 
    VLT_U16 u16MaxChunk;
    VLT_U32 u32Remaining;
  
    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if (pu8Message == NULL)
    {
        return(EUVNULLPARA);
    }

    if (0 == u32MessageLength)
    {
        return( EGSNULLPARA );
    }

    u16MaxChunk  = VltCommsGetMaxSendSize();
    u32Remaining = u32MessageLength;
    
    do
    {
        VLT_U16 u16Chunk;
         if( u16MaxChunk < u32Remaining )
            {
                u16Chunk = u16MaxChunk;
                    Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = 
                    VLT_CLA_CHAINING;
            }
            else
            {
                u16Chunk = (VLT_U16)u32Remaining;
                Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = 
                    VLT_CLA_NO_CHANNEL;
            }
        /* Build APDU. We have to do this on every iteration as the output of
         * the previous iteration will have overwritten it (assuming a shared
         * buffer). */
        u16Idx = VLT_APDU_DATA_OFFSET ;
		
        Command.pu8Data[ VLT_APDU_INS_OFFSET ] = VLT_INS_GENERATE_VERIFY_SIGNATURE;
        Command.pu8Data[ VLT_APDU_P1_OFFSET ] = 0;
        Command.pu8Data[ VLT_APDU_P2_OFFSET ] = 0;
        Command.pu8Data[ VLT_APDU_P3_OFFSET ] = LIN(WRAPPED_BYTE(u16Chunk));

        if( 0 != u16Chunk )
        {
            /* Build Data In */

            host_memcpy( &Command.pu8Data[u16Idx], pu8Message, u16Chunk );
            u16Idx += u16Chunk;
            pu8Message += u16Chunk;
        }

        /* Send the command */

        status = VltCommand( &Command, &Response, u16Idx, 0, &Sw );

        if (VLT_OK != status)
        {
            return status;
        }

        u32Remaining -= u16Chunk;
    }
    while (u32Remaining > 0u && Sw == VLT_STATUS_NEXT_MESSAGE_PART_EXPECTED);

    if ( ( Sw != VLT_STATUS_SUCCESS )
        && ( Sw != VLT_STATUS_NONE ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_COMPUTE_VERIFY_FINAL == VLT_ENABLE)
VLT_STS VltComputeVerifyFinal(VLT_U32 u32SignatureLength,
                           const VLT_U8 *pu8Signature)
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;
    
    VLT_U16 u16Idx; 
    VLT_U16 u16MaxChunk;
    VLT_U32 u32Remaining;
  
    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if (0 == u32SignatureLength)
    {
        return( EGSNULLPARA );
    }

    u16MaxChunk  = VltCommsGetMaxSendSize();
    u32Remaining = u32SignatureLength;
    
    do
    {
        VLT_U16 u16Chunk;
        if( u16MaxChunk < u32Remaining )
        {
            u16Chunk = u16MaxChunk;
            Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = VLT_CLA_CHAINING;
        }
        else
        {
            u16Chunk = (VLT_U16)u32Remaining;
            Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = VLT_CLA_NO_CHANNEL;
        }
        /* Build APDU. We have to do this on every iteration as the output of
         * the previous iteration will have overwritten it (assuming a shared
         * buffer). */
        u16Idx = VLT_APDU_DATA_OFFSET ;

        Command.pu8Data[ VLT_APDU_INS_OFFSET ] = VLT_INS_GENERATE_VERIFY_SIGNATURE;
        Command.pu8Data[ VLT_APDU_P1_OFFSET ] = 0;
        Command.pu8Data[ VLT_APDU_P2_OFFSET ] = 0;
        Command.pu8Data[ VLT_APDU_P3_OFFSET ] = LIN(WRAPPED_BYTE(u16Chunk));

        if( 0 != u16Chunk )
        {
            /* Build Data In */
            host_memcpy( &Command.pu8Data[u16Idx], pu8Signature, u16Chunk );
            u16Idx += u16Chunk;
            pu8Signature += u16Chunk;
        }

        /* Send the command */
        status = VltCommand( &Command, &Response, u16Idx, 0, &Sw );

        if (VLT_OK != status)
        {
            return status;
        }

        u32Remaining -= u16Chunk;
    }
    while (u32Remaining && Sw == VLT_STATUS_NEXT_SIGNATURE_PART_EXPECTED);

    if ( ( Sw != VLT_STATUS_SUCCESS )
        && ( Sw != VLT_STATUS_NONE ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_COMPUTE_MESSAGE_DIGEST == VLT_ENABLE)
VLT_STS VltComputeMessageDigest( VLT_U32 u32MessageLength,
    const VLT_U8 *pu8Message,
    VLT_U8 *pu8DigestLength,
    VLT_U8 u8DigestCapacity,
    VLT_U8 *pu8Digest )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;
    VLT_U32 u32MsgIdx = 0;
    VLT_U16 u16Chunk = 0;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if( 
        ( u32MessageLength > 0 && NULL == pu8Message ) ||
        ( NULL == pu8DigestLength ) ||       
        ( NULL == pu8Digest ) )
    {
        return( EMDNULLPARA );
    }   

    if( 0u == u32MessageLength )
    {
        return( EMDINVLDMSGLEN );
    }

    if( 0 == u8DigestCapacity)
    {
        return( EMDINVLDSGSTLEN );
    }

    do
    {

        idx = VLT_APDU_DATA_OFFSET;

        /* determine the size of the transfer */
        if( VltCommsGetMaxSendSize() < ( u32MessageLength - u32MsgIdx ) )
        {            
            Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = 
            VLT_CLA_CHAINING;

            u16Chunk = VltCommsGetMaxSendSize();
        }
        else
        {         
            Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = 
                VLT_CLA_NO_CHANNEL;

            u16Chunk = (VLT_U16)( u32MessageLength - u32MsgIdx );
        }

        /* build apdu */
        Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_COMPUTE_MESSAGE_DIGEST;
        Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
        Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
        Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

        /* Build Data In */
        /*
        * No need to check the return type as pointer has been validated
        */
        if (u16Chunk > 0)
        {
            (void)host_memcpy( &Command.pu8Data[idx], &pu8Message[u32MsgIdx], u16Chunk );
            idx += u16Chunk;
            u32MsgIdx += u16Chunk;
        }

        /* Send the command */
        status = VltCommand( &Command, &Response, idx, 0, &Sw );

        /* adjust the length */
        Response.u16Len -= VLT_SW_SIZE;

        if( ( Sw != VLT_STATUS_NONE ) && 
            ( Sw != VLT_STATUS_SUCCESS ) && 
            ( Sw != VLT_STATUS_COMPLETED  ) )
        {
            return( Sw );
        }

        if (VLT_OK != status)
        {
            return status;
        }
    } while(  u32MsgIdx < u32MessageLength );

    /* ensure we have come out of the sending loop at the right time */
    if( ( 0 == Response.u16Len ) || 
        ( u32MsgIdx != u32MessageLength ) )
    {
        return( EMDIVLDSTATE );
    }
    /* ensure we have enough space to copy out the digest */
    if(u8DigestCapacity < Response.u16Len )
    {
        return( EMDNOROOM );
    }

    /* copy the digest */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( pu8Digest, Response.pu8Data, Response.u16Len );

    /* copy the digest size */
    *pu8DigestLength = (VLT_U8)Response.u16Len;

    return( status );
}
#endif

#if (VLT_ENABLE_API_UPDATE_MESSAGE_DIGEST == VLT_ENABLE)
VLT_STS VltUpdateMessageDigest( VLT_U32 u32MessageLength,
    const VLT_U8 *pu8Message)
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;
    VLT_U32 u32MsgIdx = 0;
    VLT_U16 u16Chunk = 0;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if ((u32MessageLength > 0) && (NULL == pu8Message))
    {
        return (EUMDNULLPARA);
    }

    if (u32MessageLength == 0 && pu8Message == NULL)
    {
        Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = VLT_CLA_CHAINING;
        Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_COMPUTE_MESSAGE_DIGEST;
        Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
        Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
        Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

        status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

         /* adjust the length */
        Response.u16Len -= VLT_SW_SIZE;

        if( ( Sw != VLT_STATUS_NONE ) && 
            ( Sw != VLT_STATUS_SUCCESS ) && 
            ( Sw != VLT_STATUS_COMPLETED  ) )
        {
            return( Sw );
        }

        if (VLT_OK != status)
        {
            return status;
        }
    }

    while (u32MsgIdx < u32MessageLength)
    {
        idx = VLT_APDU_DATA_OFFSET;

        Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = VLT_CLA_CHAINING;
        Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_COMPUTE_MESSAGE_DIGEST;
        Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
        Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;

        /* determine the size of the transfer */
        u16Chunk = ( VltCommsGetMaxSendSize() < ( u32MessageLength - u32MsgIdx ) ) ? VltCommsGetMaxSendSize() : (VLT_U16)( u32MessageLength - u32MsgIdx );

        /* build apdu */
        Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u16Chunk));

        /* Build Data In */
        host_memcpy( &Command.pu8Data[idx], &pu8Message[u32MsgIdx], u16Chunk );
        idx += u16Chunk;
        u32MsgIdx += u16Chunk;

        status = VltCommand( &Command, &Response, idx, 0, &Sw );

         /* adjust the length */
        Response.u16Len -= VLT_SW_SIZE;

        if( ( Sw != VLT_STATUS_NONE ) && 
            ( Sw != VLT_STATUS_SUCCESS ) && 
            ( Sw != VLT_STATUS_COMPLETED  ) )
        {
            return( Sw );
        }

        if (VLT_OK != status)
        {
            return status;
        }
    }

    return status;
}
#endif

#if (VLT_ENABLE_API_COMPUTE_MESSAGE_DIGEST_FINAL == VLT_ENABLE)
VLT_STS VltComputeMessageDigestFinal( 
    VLT_U8 *pu8DigestLength,
    VLT_U8 u8DigestCapacity,
    VLT_U8 *pu8Digest )
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if (NULL == pu8Digest) 
    {
        return( EMDNULLPARA );
    }   

    if (0 == pu8DigestLength)
    {
        return( EMDINVLDMSGLEN );
    }

    /* build apdu */
    Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_COMPUTE_MESSAGE_DIGEST;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    idx = VLT_APDU_DATA_OFFSET;

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    /* adjust the length */
    Response.u16Len -= VLT_SW_SIZE;

    if( ( Sw != VLT_STATUS_NONE ) && 
        ( Sw != VLT_STATUS_SUCCESS ) && 
        ( Sw != VLT_STATUS_COMPLETED  ) )
    {
        return( Sw );
    }

    if (VLT_OK != status)
    {
        return status;
    }

    /* ensure we have enough space to copy out the digest */
    if (u8DigestCapacity < Response.u16Len)
    {
        return(EMDNOROOM);
    }


    /* copy the digest */
    host_memcpy( pu8Digest, Response.pu8Data, Response.u16Len );

    /* copy the digest size */
    *pu8DigestLength = (VLT_U8)Response.u16Len;

    return( status );
}
#endif

#if( VLT_ENABLE_API_KEY_CONFIRMATION == VLT_ENABLE)
VLT_STS VltKeyConfirmation(VLT_U8 u8keyGroup, VLT_U8 u8keyIndex,VLT_MAC_TAG *pmacTagU)
{
	VLT_SW Sw = VLT_STATUS_NONE;
	VLT_STS status;
	idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* Check for a valid pointer in the input arguments */
	if ((NULL == pmacTagU) || (NULL == pmacTagU->pu8MacTagValue))
    {
        return( EPKNULLPARA );
    }

	/* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_KEY_CONFIRMATION;
	Command.pu8Data[VLT_APDU_P1_OFFSET] = u8keyGroup;
	Command.pu8Data[VLT_APDU_P2_OFFSET] = u8keyIndex;
    /* P3 is filled out once the data has been built */

	//Add Mac tag Length
	Command.pu8Data[idx++] = (VLT_U8) ((pmacTagU->u16wTLen >> 8) & 0xFFu);
	Command.pu8Data[idx++] = (VLT_U8) ((pmacTagU->u16wTLen >> 0) & 0xFFu);

	//Append Mac Tag value
	(void)host_memcpy( &Command.pu8Data[idx], 
		pmacTagU->pu8MacTagValue,
		pmacTagU->u16wTLen);
			idx+= pmacTagU->u16wTLen;

	 /* Update P3 now that we know the correct length. */
    Command.pu8Data[VLT_APDU_P3_OFFSET] =
        LIN(WRAPPED_BYTE( idx - VLT_APDU_TYPICAL_HEADER_SZ) );

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }
    else
    {
        return(status);
    }
}
#endif

#if( VLT_ENABLE_API_DERIVE_KEY == VLT_ENABLE)
VLT_STS VltDeriveKey(VLT_U8 u8keyGroup,
    VLT_U8 u8keyIndex,
	const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
	VLT_KEY_ID enDerivatedKeyType,
	VLT_U16 u16WDerivatedKeyLen,
	const VLT_KEY_DERIVATION *pKeyDerivation, 
    VLT_KEY_CONFIRM_POLICY enPolicy,
	VLT_KEY_DERIVATION_RESP *keyDerivationResp
	)
{
	VLT_SW Sw = VLT_STATUS_NONE;
	VLT_STS status ;
	
    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* Check for a valid pointer in the input arguments */
	if( ( NULL == pKeyFilePrivileges ) ||
        ( NULL == pKeyDerivation ) ||
        (NULL == keyDerivationResp))
    {
        return( EPKNULLPARA );
    }

	switch (pKeyDerivation->enAlgoID )
	{
	case VLT_ALG_KDF_HASH_MODE:
		status = VltDeriveKey_HashMode(u8keyGroup, u8keyIndex, pKeyFilePrivileges, enDerivatedKeyType, u16WDerivatedKeyLen, pKeyDerivation, enPolicy,&Sw);
		break;
	case VLT_ALG_KDF_CONCATENATION_NIST:
		status = VltDeriveKey_Concatenation_NIST(u8keyGroup, u8keyIndex, pKeyFilePrivileges, enDerivatedKeyType, u16WDerivatedKeyLen, pKeyDerivation, enPolicy, &Sw);
		break;
	case VLT_ALG_KDF_X963:
		status = VltDeriveKey_X963(u8keyGroup, u8keyIndex, pKeyFilePrivileges, enDerivatedKeyType, u16WDerivatedKeyLen, pKeyDerivation, enPolicy, &Sw);
		break;
	default:
		return( EIABADALGO ); /* unrecognized algorithm */
		break; //For MISRA compliancy
	}

    if (status != VLT_OK)
    {
        return status;
    }

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

	//Get the response if present ( case of key confirmation)
	if (Response.u16Len > 0)
	{
		/* Unpack the response */
		idx = 0;

		//Get nonce data
		keyDerivationResp->u16NonceVLen = (((VLT_U16)Response.pu8Data[idx]) << 8) + Response.pu8Data[idx+1];
		idx += 2;
		(void)host_memset(keyDerivationResp->pu8NonceV, 0x00, VLT_DERIVE_KEY_NONCE_MAX_LEN);
		(void)host_memcpy(keyDerivationResp->pu8NonceV, &Response.pu8Data[idx], keyDerivationResp->u16NonceVLen);
		idx += keyDerivationResp->u16NonceVLen;

		//Get Mactag data
		keyDerivationResp->u16MacTagLen = (((VLT_U16)Response.pu8Data[idx]) << 8) + Response.pu8Data[idx+1];
		idx += 2;
		(void)host_memset(keyDerivationResp->pu8MacTag, 0x00, VLT_DERIVE_KEY_MACTAG_MAX_LEN);
		(void)host_memcpy(keyDerivationResp->pu8MacTag, &Response.pu8Data[idx], keyDerivationResp->u16MacTagLen);
		idx += keyDerivationResp->u16MacTagLen;

		keyDerivationResp->u16MacKeyLen = (((VLT_U16)Response.pu8Data[idx]) << 8) + Response.pu8Data[idx+1];
	}
	return(status);
}
#endif

#if( VLT_ENABLE_API_CONSTRUCT_AGREEMENT == VLT_ENABLE)
VLT_STS VltConstructDHAgreement(
	VLT_U8 u8resultKeyGroup,
    VLT_U8 u8resultKeyIndex,
    const VLT_FILE_PRIVILEGES *pKeyFilePrivileges,
	const VLT_KEY_MATERIAL *pKeyMaterial )
{
	VLT_SW Sw = VLT_STATUS_NONE;
	VLT_STS status;
	idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* Check for a valid pointer in the input arguments */
	if( ( NULL == pKeyFilePrivileges ) ||
        ( NULL == pKeyMaterial ) )
    {
        return( EPKNULLPARA );
    }

	/* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_ESTABLISH_KEY_MATERIAL;
	Command.pu8Data[VLT_APDU_P1_OFFSET] = pKeyMaterial->u8StaticResponderPrivKeyGroup;
	Command.pu8Data[VLT_APDU_P2_OFFSET] = pKeyMaterial->u8StaticResponderPrivKeyIndex;
    /* P3 is filled out once the data has been built */

	/* Build Data In common data*/
	Command.pu8Data[idx++] = (VLT_U8)pKeyMaterial->enAlgoID;
	Command.pu8Data[idx++] = (VLT_U8)u8resultKeyGroup;
	Command.pu8Data[idx++] = (VLT_U8)u8resultKeyIndex;
	/* bmAccess */
    Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
    Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
    Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
    Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;
	
	/* Specific data */
	switch( pKeyMaterial->enAlgoID )
	{
	case VLT_ALG_KAS_ONE_PASS_ECKA_GFp:
	case VLT_ALG_KAS_ONE_PASS_ECKA_GF2m:
	case VLT_ALG_KAS_ONE_PASS_ECC_CDH_GFp:
	case VLT_ALG_KAS_ONE_PASS_ECC_CDH_GF2m:
	case VLT_ALG_KAS_ONE_PASS_ECC_DH_GFp:
	case VLT_ALG_KAS_ONE_PASS_ECC_DH_GF2m:
		{
#if (VAULT_IC_VERSION == VAULTIC_420_1_2_X)
			Command.pu8Data[idx++] = (VLT_U8) ((pKeyMaterial->data.onePass.u8KLen >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((pKeyMaterial->data.onePass.u8KLen >> 0) & 0xFFu);

			/* don't copy the key object if the ptr is NULL. */            
			if ( NULL != pKeyMaterial->data.onePass.pu8keyObject )
			{
				/*
				* No need to check the return type as pointer has been validated
				*/
				(void)host_memcpy( &Command.pu8Data[idx], 
					pKeyMaterial->data.onePass.pu8keyObject,
					pKeyMaterial->data.onePass.u8KLen);
			}

			idx += pKeyMaterial->data.onePass.u8KLen;
#else
        Command.pu8Data[idx++] = (VLT_U8)(pKeyMaterial->data.onePass.u8PubKeyGroup);
        Command.pu8Data[idx++] = (VLT_U8)(pKeyMaterial->data.onePass.u8PubKeyIndex);
#endif
		break;
		}
	case VLT_ALG_KAS_STATIC_UNIFIED_ECKA_GFp:
	case VLT_ALG_KAS_STATIC_UNIFIED_ECKA_GF2m:
	case VLT_ALG_KAS_STATIC_UNIFIED_ECC_CDH_GFp:
	case VLT_ALG_KAS_STATIC_UNIFIED_ECC_CDH_GF2m:
	case VLT_ALG_KAS_STATIC_UNIFIED_ECC_DH_GFp:
	case VLT_ALG_KAS_STATIC_UNIFIED_ECC_DH_GF2m:
		Command.pu8Data[idx++] = pKeyMaterial->data.staticUnified.u8InitiatorPubKeyGroup;
		Command.pu8Data[idx++] = pKeyMaterial->data.staticUnified.u8InitiatorPubKeyIndex;
		break;
	default:
		return( EIABADALGO ); /* unrecognised algorithm */
		break; //For MISRA compliancy
	}

	  /* Update P3 now that we know the correct length. */
    Command.pu8Data[VLT_APDU_P3_OFFSET] =
        LIN(WRAPPED_BYTE( idx - VLT_APDU_TYPICAL_HEADER_SZ) );

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

	return(status);
}
#endif

#if( VLT_ENABLE_API_GENERATE_RANDOM == VLT_ENABLE)
VLT_STS VltGenerateRandom(VLT_U8 u8NumberOfBytes, 
    VLT_U8 *pu8RandomBytes)
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* validate critical parameters */
    if( NULL == pu8RandomBytes)
    {
        return( EGRNULLPARAM );
    }

    if (0 == u8NumberOfBytes)
    {
        return( EGRZEROBYTES );
    }

    if(u8NumberOfBytes > VltCommsGetMaxReceiveSize() )
    {
        return( EGRNOROOM );
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_GENERATE_RANDOM;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = u8NumberOfBytes;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;
    /* send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );
    /* Adjust the size */
    Response.u16Len -= VLT_SW_SIZE;

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }
    
    if ( VLT_OK != status )
    {
        return status;
    }

    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy(pu8RandomBytes, Response.pu8Data, Response.u16Len );

    return( status );
}
#endif

#if (VLT_ENABLE_API_GENERATE_KEY_PAIR == VLT_ENABLE)
VLT_STS VltGenerateKeyPair(VLT_U8 u8PublicKeyGroup,
    VLT_U8 u8PublicKeyIndex,
    const VLT_FILE_PRIVILEGES *pPublicKeyFilePrivileges,
    VLT_U8 u8PrivateKeyGroup,
    VLT_U8 u8PrivateKeyIndex,
    const VLT_FILE_PRIVILEGES *pPrivateKeyFilePrivileges,
    const VLT_KEY_GEN_DATA *pKeyGenData )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if( ( NULL == pPublicKeyFilePrivileges ) ||
        ( NULL == pPrivateKeyFilePrivileges ) ||
        ( NULL == pKeyGenData ) )
    {
        return( EGKPNULLPARA );
    }    

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_GENERATE_KEY_PAIR;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;


    /* Build Data In */

    /* bAlgoID */
    Command.pu8Data[idx++] = (VLT_U8)pKeyGenData->enAlgoID;
    /* iPubGroup */
    Command.pu8Data[idx++] = u8PublicKeyGroup;
    /* iPub */
    Command.pu8Data[idx++] = u8PublicKeyIndex;
    /* bmPubAccess */
    Command.pu8Data[idx++] = pPublicKeyFilePrivileges->u8Read;
    Command.pu8Data[idx++] = pPublicKeyFilePrivileges->u8Write;
    Command.pu8Data[idx++] = pPublicKeyFilePrivileges->u8Delete;
    Command.pu8Data[idx++] = pPublicKeyFilePrivileges->u8Execute;
    /* iPrivGroup */
    Command.pu8Data[idx++] = u8PrivateKeyGroup;
    /* iPriv */
    Command.pu8Data[idx++] = u8PrivateKeyIndex;
    /* bmPubAccess */
    Command.pu8Data[idx++] = pPrivateKeyFilePrivileges->u8Read;
    Command.pu8Data[idx++] = pPrivateKeyFilePrivileges->u8Write;
    Command.pu8Data[idx++] = pPrivateKeyFilePrivileges->u8Delete;
    Command.pu8Data[idx++] = pPrivateKeyFilePrivileges->u8Execute;

    /* abParams */
	switch( pKeyGenData->enAlgoID )
	{
	case VLT_ALG_KPG_RSASSA:
	case VLT_ALG_KPG_RSAES:
		{
			const VLT_KEY_GEN_RSA_DATA *d = &pKeyGenData->data.RsaKeyGenObj;

            if (NULL == d->pu8e)
            {
                return(EGKPNULLPARA);
            }

			Command.pu8Data[idx++] = d->u8Option;
			Command.pu8Data[idx++] = (VLT_U8) ((d->u16Length >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((d->u16Length >> 0) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((d->u16ELen >> 8) & 0xFFu);
			Command.pu8Data[idx++] = (VLT_U8) ((d->u16ELen >> 0) & 0xFFu);
			/*
			* No need to check the return type as pointer has been validated
			*/
			(void)host_memcpy( &Command.pu8Data[idx], d->pu8e, d->u16ELen);
			idx += d->u16ELen; 
			break;
		}
	case VLT_ALG_KPG_DSA:
	case VLT_ALG_KPG_ECDSA_GFP:
	case VLT_ALG_KPG_ECDSA_GF2M:
		{
			const VLT_KEY_GEN_ECDSA_DSA_DATA *d = &pKeyGenData->data.EcdsaDsaKeyGenObj;

			Command.pu8Data[idx++] = d->u8DomainParamsGroup;
			Command.pu8Data[idx++] = d->u8DomainParamsIndex;

			break;
		}
	default:
		return EGKPBADKPG;
		break; //For MISRA compliancy
	}

    /* Update P3 now that we know the correct length. */

    Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE( idx - VLT_APDU_TYPICAL_HEADER_SZ ) );

    /* Send the command */

    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_GENERATE_SYMMETRIC_KEY == VLT_ENABLE)
VLT_STS VltGenerateSymmetricKey(VLT_U8 u8KeyGroup,
    VLT_U8 u8KeyIndex,
    const VLT_FILE_PRIVILEGES* pKeyFilePrivileges,
    VLT_AES_ID enAesKeyId)
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;
    idx = VLT_APDU_DATA_OFFSET;


    if (NULL == pKeyFilePrivileges)
    {
        return(EGKNULLPARA);
    }

    if (enAesKeyId != (VLT_AES_ID)VLT_KEY_AES_128
        && enAesKeyId != (VLT_AES_ID)VLT_KEY_AES_192
        && enAesKeyId != (VLT_AES_ID)VLT_KEY_AES_256)
    {
        return(EGKIVDKEYID);
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_GENERATE_SYM_KEY;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = u8KeyGroup;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = u8KeyIndex;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* bmAccess */
    Command.pu8Data[idx++] = pKeyFilePrivileges->u8Read;
    Command.pu8Data[idx++] = pKeyFilePrivileges->u8Write;
    Command.pu8Data[idx++] = pKeyFilePrivileges->u8Delete;
    Command.pu8Data[idx++] = pKeyFilePrivileges->u8Execute;

    /* bAlgoID */
    Command.pu8Data[idx++] = (VLT_U8)enAesKeyId;

    /* Update P3 now that we know the correct length. */

    Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(idx - VLT_APDU_TYPICAL_HEADER_SZ));

    /* Send the command */

    status = VltCommand(&Command, &Response, idx, 0, &Sw);

    if ((Sw != VLT_STATUS_NONE) && (Sw != VLT_STATUS_SUCCESS))
    {
        return(Sw);
    }

    return(status);
}
#endif
/* --------------------------------------------------------------------------
 * FILE SYSTEM SERVICES
 * -------------------------------------------------------------------------- */

#if (VLT_ENABLE_API_BEGIN_TRANSACTION == VLT_ENABLE)
VLT_STS VltBeginTransaction( void )
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_BEGIN_TRANSACTION;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_END_TRANSACTION == VLT_ENABLE)
VLT_STS VltEndTransaction( void )
{    
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_END_TRANSACTION;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_SELECT_FILE_OR_DIRECTORY == VLT_ENABLE)
VLT_STS VltSelectFileOrDirectory(const VLT_U8 *pu8Path, 
    VLT_U8 u8PathLength, 
    VLT_SELECT *pRespData )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if( ( NULL == pu8Path ) ||        
        ( NULL == pRespData ) )
    {
        return( ESFNULLPARA );
    }
    
    if( ( 0 == u8PathLength ) ||
        ( VltCommsGetMaxSendSize() < u8PathLength ) )
    {
        return( ESFDINVLDPATHLEN );
    }
    
    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_SELECT;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Build Data In */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( &Command.pu8Data[idx], pu8Path, u8PathLength );
    idx += u8PathLength;

    /* Check that a NULL terminator is there, if not add one */
    if( ( '\0' != Command.pu8Data[idx - 1] ) && 
        ( VltCommsGetMaxSendSize() != u8PathLength ) )
    {
        Command.pu8Data[idx++] = '\0';
    }

    /* Update P3 now that we know the correct length. */
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 
        LIN(WRAPPED_BYTE( idx - VLT_APDU_TYPICAL_HEADER_SZ ) );

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, VLT_SF_RESPONSE_LENGTH, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    if( VLT_OK != status )
    {
        return status;
    }

    /* Unpack the response */
    idx = 0;    

    pRespData->u32FileSize = VltEndianReadPU32( &Response.pu8Data[idx] );
    idx += 4;
    pRespData->FileAccess.u8Read    = Response.pu8Data[idx++];
    pRespData->FileAccess.u8Write   = Response.pu8Data[idx++];
    pRespData->FileAccess.u8Delete  = Response.pu8Data[idx++];
    pRespData->FileAccess.u8Execute = Response.pu8Data[idx++];
    pRespData->u8FileAttribute      = Response.pu8Data[idx++];

    return( status );
}
#endif

#if (VLT_ENABLE_API_LIST_FILES == VLT_ENABLE)
VLT_STS VltListFiles ( VLT_U16 *pu16ListRespLength, 
    VLT_U16 u16ListRespCapacity,
    VLT_U8 *pu8RespData)
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;
    idx = 0;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* validate critical parameters */
    if( ( NULL == pu16ListRespLength) ||
        ( NULL == pu8RespData ) )
    {
        return( ELFNULLPARAM );
    }
    
    if( 0u == u16ListRespCapacity)
    {
        return( ELFIVLDRESPLEN );
    }

    do
    {
        /* Set up the apdu */
        Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = VLT_CLA_NO_CHANNEL;
        Command.pu8Data[ VLT_APDU_INS_OFFSET ] = VLT_INS_LIST_FILES;
        Command.pu8Data[ VLT_APDU_P1_OFFSET ] = 0;
        Command.pu8Data[ VLT_APDU_P2_OFFSET ] = 0;        
        Command.pu8Data[ VLT_APDU_P3_OFFSET ] = 0;
        /* Fire in the command*/
        status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

        /* Check status and status word */
        if( VLT_OK != status )
        {
            return( status );
        }
        
        if( ( Sw != VLT_STATUS_NONE ) && 
            ( Sw != VLT_STATUS_SUCCESS ) && 
            ( Sw != VLT_STATUS_EOF ) )
        {
            return( Sw );
        }

        /* Adjust the response length */
        Response.u16Len -= VLT_SW_SIZE ; 

        /*
         * Copy the data if we have enough space in the buffer, 
         * otherwise keep accumulating the size of the listing so 
         * it can be reported back to the caller.
         */
        if( ( idx + Response.u16Len ) <= u16ListRespCapacity)
        {
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy( &pu8RespData[idx], Response.pu8Data, Response.u16Len );
            idx += Response.u16Len;
        }
        else
        {
            idx += Response.u16Len;
        }
    }
    while( Sw != VLT_STATUS_EOF );

    
    /*
     * The size of the listing is larger than the buffer
     * available, return an error code and let the caller
     * know the actual size of the listing.
     */
    if( idx > u16ListRespCapacity)
    {
        status = ELFNOROOM;
    }


    /* 
     * SDVAULTICWRAP-55:
     * Set the size regardless. 
     */
    *pu16ListRespLength = idx;

    return( status );    
}
#endif

#if (VLT_ENABLE_API_CREATE_FILE == VLT_ENABLE)
VLT_STS VltCreateFile(VLT_USER_ID enUserID,
    VLT_U32 u32FileSize, 
    const VLT_FILE_PRIVILEGES *pFilePriv,
    VLT_U8 u8FileAttribute,
    VLT_U16 u16FileNameLength,
    const VLT_U8 *pu8FileName )
{ 
    VLT_STS status;        
    VLT_SW Sw = VLT_STATUS_NONE;

    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }


    /* Check User ID validity */
    if ((enUserID < VLT_USER0) || (enUserID > VLT_USER7))
    {
        return(ECFLINVLUSERID);
    }

    /*
    * Check the input paramters for valid pointers
    */
    if( ( NULL == pFilePriv ) ||
        ( NULL == pu8FileName ) )
    {
        return( ECFNULLPARA );
    }

    if( ( VLT_FILENAME_MIN_LEN > u16FileNameLength ) || 
        ( VLT_FILENAME_MAX_LEN < u16FileNameLength ) )
    {
        return( ECFINVLDLEN );
    }

    /*
    * Check that the name passed will fit in the buffer
    */
    if( VltCommsGetMaxSendSize() < u16FileNameLength )
    {
        return( ECFILNMLENTOOBIG );
    }    

    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_CREATE_FILE;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = (VLT_U8) enUserID;
    /* P3 is filled out once the data has been built */

    /* dwSize */
    Command.pu8Data[idx++] = (VLT_U8) ((u32FileSize >> 24) & 0xFFu);
    Command.pu8Data[idx++] = (VLT_U8) ((u32FileSize >> 16) & 0xFFu);
    Command.pu8Data[idx++] = (VLT_U8) ((u32FileSize >>  8) & 0xFFu);
    Command.pu8Data[idx++] = (VLT_U8) ((u32FileSize >>  0) & 0xFFu);
    /* bmAccess */
    Command.pu8Data[idx++] = pFilePriv->u8Read;
    Command.pu8Data[idx++] = pFilePriv->u8Write;
    Command.pu8Data[idx++] = pFilePriv->u8Delete;
    Command.pu8Data[idx++] = pFilePriv->u8Execute;
    /* bmAttributes */
    Command.pu8Data[idx++] = u8FileAttribute;
    /* wNameLength */
    Command.pu8Data[idx++] = (VLT_U8)( ( ( u16FileNameLength ) >> 8 ) & 0xFFu );
    Command.pu8Data[idx++] = (VLT_U8)( ( ( u16FileNameLength ) >> 0 ) & 0xFFu );
    /* sName */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( &Command.pu8Data[idx], pu8FileName, u16FileNameLength );
    idx += u16FileNameLength;

    /* Update P3 now that we know the correct length. */
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 
        LIN(WRAPPED_BYTE( idx - VLT_APDU_TYPICAL_HEADER_SZ ) );

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_CREATE_FOLDER == VLT_ENABLE)
VLT_STS VltCreateFolder(VLT_USER_ID enUserID,
    const VLT_FILE_PRIVILEGES *pFilePriv,                                   
    VLT_U8 u8FolderAttribute,
    VLT_U16 u16FolderNameLength,
    const VLT_U8 *pu8FolderName)
{ 
    VLT_STS status;
    VLT_SW Sw = VLT_STATUS_NONE;

    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* Check User ID validity */
    if ((enUserID < VLT_USER0) || (enUserID > VLT_USER7))
    {
         return(ECFLINVLUSERID);
    }

    /*
    * Check the input paramters for valid pointers
    */
    if( ( NULL == pFilePriv ) ||
        ( NULL == pu8FolderName ) )
    {
        return( ECFLNULLPARA );
    }

    if( ( VLT_FILENAME_MIN_LEN > u16FolderNameLength ) || 
        ( VLT_FILENAME_MAX_LEN < u16FolderNameLength ) )
    {
        return( ECFLINVLDLEN );
    }
    
    /*
    * Check that the name passed will fit in the buffer
    */
    if( VltCommsGetMaxSendSize() < u16FolderNameLength )
    {
        return( ECFOLNMLENTOOBIG );
    }

    /* Build APDU */    
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_CREATE_FOLDER;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = (VLT_U8) enUserID;
    /* P3 is filled out once the data has been built */

    /* bmAccess */
    Command.pu8Data[idx++] = pFilePriv->u8Read;
    Command.pu8Data[idx++] = pFilePriv->u8Write;
    Command.pu8Data[idx++] = pFilePriv->u8Delete;
    Command.pu8Data[idx++] = pFilePriv->u8Execute;
    /* bmAttributes */
    Command.pu8Data[idx++] = u8FolderAttribute;
    /* wNameLength */
    Command.pu8Data[idx++] = (VLT_U8)( ( ( u16FolderNameLength ) >> 8 ) & 0xFFu );
    Command.pu8Data[idx++] = (VLT_U8)( ( ( u16FolderNameLength ) >> 0)  & 0xFFu );
    /* sName */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( &Command.pu8Data[idx], pu8FolderName, u16FolderNameLength);
    idx += u16FolderNameLength;

    /* Update P3 now that we know the correct length. */
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 
        LIN( WRAPPED_BYTE( idx - VLT_APDU_TYPICAL_HEADER_SZ ) );

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_DELETE_FILE == VLT_ENABLE)
VLT_STS VltDeleteFile( void )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_DELETE_FILE;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_DELETE_FOLDER == VLT_ENABLE)
VLT_STS VltDeleteFolder( VLT_BOOL bRecursion )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_DELETE_FOLDER;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = (VLT_U8) bRecursion;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_WRITE_FILE == VLT_ENABLE)
VLT_STS VltWriteFile( const VLT_U8 *pu8DataIn,
    VLT_U8 u8DataLength,
    VLT_BOOL bReclaimSpace )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if( NULL == pu8DataIn )
    {
        return( EWFNULLPARA );
    }    

    if( 0 == u8DataLength )
    {
        return( EWFIVLDLEN );
    }

    /* Reject the request if it's larger than the maximum chunk size. */
    if( u8DataLength > VltCommsGetMaxSendSize() )
    {
        return( EWFTOOBIG );
    }       

    if ((bReclaimSpace != FALSE) && (bReclaimSpace != TRUE))
    {
        status = EWFBADPARAM;
    }

    /* Build APDU */    
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_WRITE_FILE; 
    Command.pu8Data[VLT_APDU_P1_OFFSET] = (VLT_U8) bReclaimSpace;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(u8DataLength);

    /* Build Data In */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( &Command.pu8Data[idx], pu8DataIn, u8DataLength );
    idx += u8DataLength;

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_READ_FILE == VLT_ENABLE)
VLT_STS VltReadFile( VLT_U16 *pu16ReadLength,
    VLT_U8 *pu8RespData )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;
    VLT_U16 u16MemCopySize = 0;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    idx = 0;

    if( ( NULL == pu16ReadLength ) ||
        ( NULL == pu8RespData ) )
    {
        return( ERFNULLPARAM );
    }

    /*
    * SDVAULTICWRAP-44: Check for 0 bytes 
    */
    if( 0 == *pu16ReadLength )
    {
        return( ERFZEROBYTES );
    }

    if( ( 0 == *pu16ReadLength ) ||
        ( *pu16ReadLength > VLT_MAX_APDU_RCV_DATA_SZ ) )
    {
        return( ERFINVLDLEN );
    }

    do
    {
        /* Set up the apdu */
        Command.pu8Data[ VLT_APDU_CLASS_OFFSET ] = VLT_CLA_NO_CHANNEL;
        Command.pu8Data[ VLT_APDU_INS_OFFSET ] = VLT_INS_READ_FILE;
        Command.pu8Data[ VLT_APDU_P1_OFFSET ] = 0;
        Command.pu8Data[ VLT_APDU_P3_OFFSET ] = 0;        
        
        if ( VLT_STATUS_RESPONDING == Sw )
        {
            Command.pu8Data[ VLT_APDU_P2_OFFSET ] = 0;
        }
        else
        {
            /*
             * When the value is 256, the cast to a VLT_U8 will 
             * result in a P2 of 0. P2 = 0 will result in 256 bytes 
             * being received.
             */
            Command.pu8Data[ VLT_APDU_P2_OFFSET ] = (VLT_U8)*pu16ReadLength;
        }


        /* Send in the command*/
        status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );
        /* Adjust the length received */
        Response.u16Len -= VLT_SW_SIZE;

        /* Check status and status word */
        if( VLT_OK != status )
        {
            return( status );
        }
        

        /*
         * Check there is enough room in the read buffer.
         */
        if ( ( idx + Response.u16Len ) <= *pu16ReadLength )
        {
            /* The received size is less or equal the number requested. */
            u16MemCopySize = Response.u16Len;            
        }
        else if ( ( idx < *pu16ReadLength ) &&
                  ( Response.u16Len > ( *pu16ReadLength - idx ) ) )
        {
            /* The received size is greater than the number requested
             * only copy the bytes there is available space to store. */
            u16MemCopySize = *pu16ReadLength - idx;            
        }
        else
        {
            /* Run out of room, don't copy the rest. */
            u16MemCopySize = 0;
        }

        
        /*
         * Copy the data out if we have been given enough space.
         */
        if ( 0 != u16MemCopySize )
        {
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memcpy( &pu8RespData[idx], Response.pu8Data, u16MemCopySize );
            idx += u16MemCopySize;
        }
        
        
        /* Check response code */
        switch( Sw )
        {
            case VLT_STATUS_COMPLETED:
            case VLT_STATUS_RESPONDING:
            case VLT_STATUS_SUCCESS:
                break;
            case VLT_STATUS_NONE: 
                return( status );
				break; //For MISRA compliancy
            case VLT_STATUS_EOF:
                status = VLT_EOF;
                break;
            default:
                return Sw; /* unexpected status word */
				break; //For MISRA compliancy
        }

    } while ( Sw == VLT_STATUS_RESPONDING );

    
    *pu16ReadLength = idx;
    
    return( status );
}
#endif

#if (VLT_ENABLE_API_SEEK_FILE == VLT_ENABLE)
VLT_STS VltSeekFile( VLT_U32 u32SeekLength )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* Build APDU */ 
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_SEEK_FILE;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(4);


    /* Build Data In */
    Command.pu8Data[idx++] = (VLT_U8) ((u32SeekLength >> 24) & 0xFFu);
    Command.pu8Data[idx++] = (VLT_U8) ((u32SeekLength >> 16) & 0xFFu);
    Command.pu8Data[idx++] = (VLT_U8) ((u32SeekLength >>  8) & 0xFFu);
    Command.pu8Data[idx++] = (VLT_U8) ((u32SeekLength >>  0) & 0xFFu);

    /* Send the command */

    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && 
        ( Sw != VLT_STATUS_SUCCESS ) && 
        ( Sw != VLT_STATUS_EOF ) )
    {
        return( Sw );
    }

    if( VLT_STATUS_EOF == Sw )
    {
        return( VLT_EOF );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_SET_PRIVILEGES == VLT_ENABLE)
VLT_STS VltSetPrivileges( const VLT_FILE_PRIVILEGES *pFilePriv )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if( NULL == pFilePriv )
    {
        return( ESPVNULLPARA );
    }

    /* Build APDU */    
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL; 
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_SET_PRIVILEGES;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(4);


    /* Build Data In */

    Command.pu8Data[idx++] = pFilePriv->u8Read;
    Command.pu8Data[idx++] = pFilePriv->u8Write;
    Command.pu8Data[idx++] = pFilePriv->u8Delete;
    Command.pu8Data[idx++] = pFilePriv->u8Execute;

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_SET_ATTRIBUTES == VLT_ENABLE)
VLT_STS VltSetAttributes( VLT_U8 u8Attribute )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_SET_ATTRIBUTES;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(1);

    /* Build Data In */
    Command.pu8Data[idx++] = u8Attribute;

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

/* --------------------------------------------------------------------------
 * MANUFACTURING COMMANDS
 * -------------------------------------------------------------------------- */
#if (VLT_ENABLE_API_GET_INFO == VLT_ENABLE)
VLT_STS VltGetInfo(VLT_TARGET_INFO *pRespData )
{ 
    VLT_STS status = VLT_FAIL;
    VLT_SW Sw = VLT_STATUS_NONE;
#if (VLT_ENABLE_GETINFO_EXT == VLT_ENABLE)
    VLT_BOOL isExtendedGetInfo=FALSE;
#endif

    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if( NULL == pRespData )
    {
        return( EGINULLPARA );
    }

    /* Build APDU */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_GET_INFO;
#if (VLT_ENABLE_GETINFO_EXT == VLT_ENABLE)
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 1; // Extended mode
    Command.pu8Data[VLT_APDU_P3_OFFSET] = VLT_TARGET_INFO_LENGTH_EXT;
#else
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0; 
    Command.pu8Data[VLT_APDU_P3_OFFSET] = VLT_TARGET_INFO_LENGTH;
#endif
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;


    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    if( VLT_OK != status )
    {
        return ( status );
    }
   
    /* 
     * Remove the status word from the length of the 
     * data received.
     */
    Response.u16Len -= VLT_SW_SIZE;  

    /*
     * Check length returned  
     */
    switch (Response.u16Len)
    {   
        case VLT_TARGET_INFO_LENGTH:
#if (VLT_ENABLE_GETINFO_EXT == VLT_ENABLE)
            isExtendedGetInfo = FALSE; // Standard Get Info format (legacy)
        break;

        case VLT_TARGET_INFO_LENGTH_EXT:
            isExtendedGetInfo = TRUE; // Extended Get Info format
#endif
            break;

        default:
            return( EGTINFOIVLDRESPLEN ); // unknown format
    }

    /* Unpack the response */
    idx = 0;    

    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( pRespData->au8Firmware, &Response.pu8Data[idx], VLT_FIRMWARE_VERSION_LENGTH ); // sFirmware
    idx += VLT_FIRMWARE_VERSION_LENGTH;

    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy(pRespData->au8Serial, &Response.pu8Data[idx], VLT_CHIP_SERIAL_NUMBER_LENGTH); // abSerial
    idx += VLT_CHIP_SERIAL_NUMBER_LENGTH;

    pRespData->enState = (VLT_STATE) Response.pu8Data[idx++]; // bState
    pRespData->enSelfTests = (VLT_SELF_TESTS_STATUS)Response.pu8Data[idx++]; // bSelfTests
    pRespData->enRole = (VLT_ROLE_ID) Response.pu8Data[idx++]; // bRole
    pRespData->enMode = (VLT_MODE) Response.pu8Data[idx++]; // bMode
    pRespData->u32Space = VltEndianReadPU32(&Response.pu8Data[idx]); //dwSpace
    idx += 4u;    

#if (VLT_ENABLE_GETINFO_EXT == VLT_ENABLE)
    if (isExtendedGetInfo)
    {
        pRespData->enFipsLevel = (VLT_FIPS_LEVEL)Response.pu8Data[idx++]; //bFipsLevel
        pRespData->isLegacyMode = (VLT_BOOL)Response.pu8Data[idx++]; // bCompatibility
    }
    else
#endif
    {
        idx += 2u; // wRFU
    }

    pRespData->u8Attack = Response.pu8Data[idx++]; //bAttack
    pRespData->u16AttackCounter = VltEndianReadPU16(&Response.pu8Data[idx]); //wAttackCounter

#if (VLT_ENABLE_GETINFO_EXT == VLT_ENABLE)
    if (isExtendedGetInfo)
    {
        idx += 2u;
        pRespData->unFipsAlgos.val_u16 = VltEndianReadPU16(&Response.pu8Data[idx]); //wFipsAlgorithms
    }
#endif

    return( status );
}
#endif

#if (VLT_ENABLE_API_SELF_TEST == VLT_ENABLE)
VLT_STS VltSelfTest( void )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_SELF_TEST;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_SET_FIPS_LEVEL == VLT_ENABLE)
VLT_STS VltSetFipsLevel(VLT_FIPS_LEVEL enFipsLevel)
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_SET_FIPS_LEVEL;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = (VLT_U8)enFipsLevel;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Send the command */
    status = VltCommand(&Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw);

    if ((Sw != VLT_STATUS_NONE) && (Sw != VLT_STATUS_SUCCESS))
    {
        return(Sw);
    }

    return(status);
}
#endif

#if (VLT_ENABLE_API_SET_FIPS_ALGOS == VLT_ENABLE)
VLT_STS VltSetFipsAlgos(const VLT_FIPS_ALGOS *punFipsAlgos)
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_SET_FIPS_ALGOS;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(2);

    Command.pu8Data[VLT_APDU_DATA_OFFSET] = (VLT_U8) (punFipsAlgos->val_u16 >> 8);
    Command.pu8Data[VLT_APDU_DATA_OFFSET+1] = (VLT_U8) punFipsAlgos->val_u16;

    /* Send the command */
    status = VltCommand(&Command, &Response, VLT_APDU_DATA_OFFSET+2, 0, &Sw);

    if ((Sw != VLT_STATUS_NONE) && (Sw != VLT_STATUS_SUCCESS))
    {
        return(Sw);
    }

    return(status);
}
#endif

#if (VLT_ENABLE_API_SET_STATUS == VLT_ENABLE)
VLT_STS VltSetStatus(VLT_STATE enState )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_SET_STATUS;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = (VLT_U8) enState;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );    
}
#endif

#if (VLT_ENABLE_API_SET_CONFIG == VLT_ENABLE)
VLT_STS VltSetConfig(VLT_SET_CFG enConfigItemId, VLT_SET_CFG_SZ enConfigItemSize, const VLT_U8 *pu8ConfigData)
{ 
    VLT_STS status = VLT_FAIL;
    VLT_SW Sw = VLT_STATUS_NONE;
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* 
     * Ensure we have a non null data pointer
     */
    if( NULL == pu8ConfigData )
    {
        return( ESETCNFGNULLDATA );
    }
 
	  /*
     * Ensure we have been passed a supported config item.
     */
	if( VLT_SET_CFG_POWERON_SELFTESTS_MODE == enConfigItemId )
    {
        /*
         * Validate the length of the time and date config item
         * the size should also include the null string terminator. 
         */
        if( VLT_SET_CFG_POWERON_SELFTESTS_MODE_SZ != enConfigItemSize)
        {
            return( ESETCNFGIVLDDTLEN );
        }
    }
    else if( VLT_SET_CFG_I2C_ADDRESS == enConfigItemId )
    {
        /*
         * Validate the length of the I2C address
         */
        if( VLT_SET_CFG_I2C_ADDRESS_SZ != enConfigItemSize)
        {
            return( ESETCNFGIVLDI2CLEN );
        }
    }
    else if (VLT_SET_CFG_ATTACK_COUNTER_CONFIG == enConfigItemId)
    {
        /*
         * Validate the length of the Attack Counter Config parameter
         */
        if (VLT_SET_CFG_ATTACK_COUNTER_CONFIG_SZ != enConfigItemSize)
        {
            return(ESETCNFGIVLDDATALEN);
        }
    }
    else if( VLT_SET_CFG_SPI_POWER_SAVING_MODE == enConfigItemId )
    {
        /*
         * Validate the length of the Power Saving Mode parameter
         */
        if( VLT_SET_CFG_SPI_POWER_SAVING_MODE_SZ != enConfigItemSize)
        {
            return( ESETCNFGIVLDSPILEN );
        }
    }
	else if( VLT_SET_CFG_COMMUNICATION_CHANNEL == enConfigItemId )
    {
        /*
         * Validate the length of the communication channel parameter
         */
		if( VLT_SET_CFG_COMMUNICATION_CHANNEL_SZ != enConfigItemSize)
        {
            return( ESETCNFGIVLDCOMMLEN );
        }
    }
#if ((VAULT_IC_VERSION == VAULTIC_420_1_2_X)||(VAULT_IC_VERSION == VAULTIC_405_1_X_X))
    else if( VLT_SET_CFG_GPIO_ACCESS_MODE == enConfigItemId )
    {
        /*
         * Validate the length of the GPIO access Mode parameter
         */
        if( VLT_SET_CFG_GPIO_ACCESS_MODE_SZ != enConfigItemSize)
        {
            return( ESETCNFGIVLDGPIOLEN );
        }
    }
    else if (VLT_SET_CFG_LED_BLINKING == enConfigItemId)
    {
        /*
         * Validate the length of the Led Blinking parameter
         */
        if (VLT_SET_CFG_LED_BLINKING_SZ != enConfigItemSize)
        {
            return(ESETCNFGIVLDDATALEN);
        }
    }
    else if (VLT_SET_CFG_CHANGE_ATR == enConfigItemId)
    {
        /*
         * Validate the length of the USB CCID ATR parameter
         */
        if (VLT_SET_CFG_CHANGE_ATR_SZ != enConfigItemSize)
        {
            return(ESETCNFGIVLDDATALEN);
        }
    }
    else if (VLT_SET_CFG_USB_VENDORID_PRODUCTID_DEVICEID == enConfigItemId)
    {
        /*
        * Validate the length of the USB IDs parameter
        */
        if (VLT_SET_CFG_USB_VENDORID_PRODUCTID_DEVICEID_SZ!= enConfigItemSize)
        {
            return(ESETCNFGIVLDDATALEN);
        }
    }
    else if (VLT_SET_CFG_USB_ATTRIBUTES == enConfigItemId)
    {
        /*
        * Validate the length of the USB attributes parameter
        */
        if (VLT_SET_CFG_USB_ATTRIBUTES_SZ != enConfigItemSize)
        {
            return(ESETCNFGIVLDDATALEN);
        }
    }
    /*
    * Validate the length of the USB strings
    */
    else   if (VLT_SET_CFG_USB_MANUFACTURER_STRING == enConfigItemId)
    {
        if (enConfigItemSize > VLT_SET_CFG_USB_MANUFACTURER_STRING_SZ)
        {
            return ESETCNFGIVLDDATALEN;
        }
    }
    else   if (VLT_SET_CFG_USB_PRODUCT_STRING == enConfigItemId)
    {
        if (enConfigItemSize > VLT_SET_CFG_USB_PRODUCT_STRING_SZ)
        {
            return ESETCNFGIVLDDATALEN;
        }
    }
    else   if (VLT_SET_CFG_USB_CONFIG_STRING == enConfigItemId)
    {
        if (enConfigItemSize > VLT_SET_CFG_USB_CONFIG_STRING_SZ)
        {
            return ESETCNFGIVLDDATALEN;
        }
    }
    else   if (VLT_SET_CFG_USB_INTERFACE_STRING == enConfigItemId)
    {
        if (enConfigItemSize > VLT_SET_CFG_USB_INTERFACE_STRING_SZ)
        {
            return ESETCNFGIVLDDATALEN;
        }
    }
    else   if (VLT_SET_CFG_USB_SERIAL_NUMBER_STRING == enConfigItemId)
    {
        if (enConfigItemSize > VLT_SET_CFG_USB_SERIAL_NUMBER_STRING_SZ)
        {
            return ESETCNFGIVLDDATALEN;
        }
    }
    else  if (VLT_SET_CFG_USB_MAX_POWER == enConfigItemId)
    {
        /*
        * Validate the length of the USB max power parameter
        */
        if (VLT_SET_CFG_USB_MAX_POWER_SZ != enConfigItemSize)
        {
            return(ESETCNFGIVLDUSBMAXLEN);
        }
    }
#endif
    else if (VLT_SET_CFG_I2C_BUS_INACTIVITY_DETECTION_DURATION == enConfigItemId)
    {
        /* Validate the length of I2C timeout */
        if (VLT_SET_CFG_I2C_BUS_INACTIVITY_DETECTION_DURATION_SZ != enConfigItemSize)
        {
            return(ESETCNFGIVLDDATALEN);
        }
    }
    else  if (VLT_SET_CFG_ADMIN_SECURITY_POLICY == enConfigItemId)
    {
        /*
         * Validate the length of the admin security policy
         */
         if (VLT_SET_CFG_ADMIN_SECURITY_POLICY_SZ != enConfigItemSize)
         {
             return(ESETCNFGIVLDDATALEN);
         }

         if (pu8ConfigData[0] > VLT_SET_CFG_ADMIN_SECURITY_POLICY_USER_AUTHEN_DATA_DEF_DISABLE)
         {
             return(ESETCNFGIVLDADMINPOLICYVALUE);
         }
    }

#if ((VAULT_IC_VERSION == VAULTIC_407_1_0_X)||(VAULT_IC_VERSION == VAULTIC_408_1_X_X))
    else if (VLT_SET_CFG_BACK_TO_RX_TIMEOUT == enConfigItemId)
    {
        /* Validate the length of Rx timeout */
        if (VLT_SET_CFG_BACK_TO_RX_TIMEOUT_SZ != enConfigItemSize)
        {
            return(ESETCNFGIVLDDATALEN);
        }
    }
#endif

#if (VAULT_IC_VERSION == VAULTIC_408_1_X_X)
    else if (VLT_SET_CFG_LEGACY_MODE == enConfigItemId)
    {
        /* Validate the length of Legacy mode */
        if (VLT_SET_CFG_LEGACY_MODE_SZ != enConfigItemSize)
        {
            return(ESETCNFGIVLDDATALEN);
        }
    }
#endif

    else if (  (VLT_SET_CFG_ATTACK_COUNTER_CONFIG != enConfigItemId)
            && (VLT_SET_CFG_I2C_BUS_INACTIVITY_DETECTION_DURATION != enConfigItemId)


#if ((VAULT_IC_VERSION == VAULTIC_420_1_2_X)||(VAULT_IC_VERSION == VAULTIC_405_1_X_X))
            && (VLT_SET_CFG_USB_VENDORID_PRODUCTID_DEVICEID != enConfigItemId)
            && (VLT_SET_CFG_USB_ATTRIBUTES != enConfigItemId)
            && (VLT_SET_CFG_USB_MANUFACTURER_STRING != enConfigItemId)
            && (VLT_SET_CFG_USB_PRODUCT_STRING != enConfigItemId)
            && (VLT_SET_CFG_USB_CONFIG_STRING != enConfigItemId)
            && (VLT_SET_CFG_USB_INTERFACE_STRING != enConfigItemId)
            && (VLT_SET_CFG_USB_SERIAL_NUMBER_STRING != enConfigItemId)
            && (VLT_SET_CFG_CHANGE_ATR != enConfigItemId)
            && (VLT_SET_CFG_LED_BLINKING != enConfigItemId)
            && (VLT_SET_CFG_ADMIN_SECURITY_POLICY != enConfigItemId)
#endif

        )
    {
	    return( ESETCNFGIVLDITEM );
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_SET_CONFIG;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = (VLT_U8)enConfigItemId;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;

    VLT_U8 u8DataLength = (VLT_U8)enConfigItemSize;

	switch(enConfigItemId)
	{
#if ((VAULT_IC_VERSION == VAULTIC_420_1_2_X)||(VAULT_IC_VERSION == VAULTIC_405_1_X_X))
	case VLT_SET_CFG_USB_MANUFACTURER_STRING:
	case VLT_SET_CFG_USB_PRODUCT_STRING:
	case VLT_SET_CFG_USB_CONFIG_STRING:
	case VLT_SET_CFG_USB_INTERFACE_STRING:
	case VLT_SET_CFG_USB_SERIAL_NUMBER_STRING:
		Command.pu8Data[idx++] = u8DataLength+2u;
		Command.pu8Data[idx++] = 0x03;
			/*
		* No need to check the return type as pointer has been validated
		*/
		(void)host_memcpy( &Command.pu8Data[idx], pu8ConfigData, u8DataLength );
		idx += u8DataLength;
		u8DataLength+=2u;
		break;
#endif
	default:
		/*
		* No need to check the return type as pointer has been validated
		*/
		(void)host_memcpy( &Command.pu8Data[idx], pu8ConfigData, u8DataLength );
		idx += u8DataLength;
		break;
	}

    Command.pu8Data[VLT_APDU_P3_OFFSET] = u8DataLength;

	
  
    /* 
     * Send the command 
     */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    /*
     * Let the caller know that the command transport 
     * succeeded but the Vault IC responded with status word
     * other than 0x9000.
     */
    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status ); 
}
#endif

#if (VLT_ENABLE_API_SET_GPIO_DIRECTION == VLT_ENABLE)
VLT_STS VltSetGpioDirection( VLT_U8 u8GpioDirMask, VLT_U8 u8GpioMode )
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_SET_GPIO;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = u8GpioDirMask;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = u8GpioMode;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_WRITE_GPIO == VLT_ENABLE)
VLT_STS VltWriteGpio( VLT_U8 u8GpioValue )
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_WRITE_GPIO;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = u8GpioValue;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_READ_GPIO == VLT_ENABLE)
VLT_STS VltReadGpio( VLT_U8 au8GpioValue[1] )
{
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status;
     
    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* validate critical parameters*/
    if( NULL == au8GpioValue)
    {
        return( ERDGPIONULLPARAM );
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_READ_GPIO;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 1;

    /* Send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    if( VLT_OK != status )
    {
        return( status );
    }

    au8GpioValue[0] = Response.pu8Data[0];

    return( status );
}
#endif

#if (VLT_ENABLE_API_TEST_CASE1 == VLT_ENABLE)
VLT_STS VltTestCase1( void )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_TEST_CASE_1;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = 0;

    /* Send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_TEST_CASE2 == VLT_ENABLE)
VLT_STS VltTestCase2(VLT_U8 u8RequestedDataLength, VLT_U8 *pu8RespData )
{ 
    VLT_SW Sw = VLT_STATUS_NONE;
    VLT_STS status = VLT_FAIL;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    /* validate critical parameters */
    if( NULL == pu8RespData )
    {
        return( ETC2NULLPARAM );
    }

    /*
    * SDVAULTICWRAP-44: Check for 0 bytes 
    */
    if( 0 == u8RequestedDataLength )
    {
        return( ETC2ZEROBYTES );
    }

    if( u8RequestedDataLength > VltCommsGetMaxReceiveSize() )
    {
        return( ETC2NOROOM );
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_TEST_CASE_2;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = u8RequestedDataLength;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LEXP(u8RequestedDataLength);

    /* send the command */
    status = VltCommand( &Command, &Response, VLT_APDU_DATA_OFFSET, 0, &Sw );
    /* Adjust the size */
    Response.u16Len -= VLT_SW_SIZE;

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( pu8RespData, Response.pu8Data, Response.u16Len );

    return( status );       
}
#endif

#if (VLT_ENABLE_API_TEST_CASE3 == VLT_ENABLE)
VLT_STS VltTestCase3( VLT_U8 u8DataLength, const VLT_U8 *pu8DataIn )
{ 
    VLT_STS status = VLT_FAIL;
    VLT_SW Sw = VLT_STATUS_NONE;
    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    if( NULL == pu8DataIn )
    {
        return( ETC3NULLPARA );
    }

    /* Reject the request if it's larger than the maximum chunk size. */
    if( ( VltCommsGetMaxSendSize() < u8DataLength ) ||
        ( 0 == u8DataLength ) )
    {
        return( ETC3INVLDLEN );
    }

    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_TEST_CASE_3;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(u8DataLength);

    /* Build Data In */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( &Command.pu8Data[idx], pu8DataIn, u8DataLength );
    idx += u8DataLength;

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    return( status );
}
#endif

#if (VLT_ENABLE_API_TEST_CASE4 == VLT_ENABLE)
VLT_STS VltTestCase4( VLT_U8 u8DataLength,
    const VLT_U8 *pu8DataIn, 
    VLT_U8 u8RequestedDataLength,
    VLT_U8 *pu8RespData )
{
    VLT_STS status = VLT_FAIL;
    VLT_SW Sw = VLT_STATUS_NONE;

    idx = VLT_APDU_DATA_OFFSET;

    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }


    /* validate critical parameters */
    if( ( NULL == pu8DataIn ) ||
        ( NULL == pu8RespData ) )
    {
        return( ETC4NULLPARA );
    }

    if( ( VltCommsGetMaxSendSize() < u8DataLength ) ||
        ( 0 == u8DataLength ) )
    {
        return( ETC4IVLDSENDLEN );
    }

    if( ( VltCommsGetMaxReceiveSize() < u8RequestedDataLength ) ||
        ( 0 == u8RequestedDataLength ) )
    {
        return( ETC4IVLDRECVLEN );
    }
    
    /* build the apdu */
    Command.pu8Data[VLT_APDU_CLASS_OFFSET] = VLT_CLA_NO_CHANNEL;
    Command.pu8Data[VLT_APDU_INS_OFFSET] = VLT_INS_TEST_CASE_4;
    Command.pu8Data[VLT_APDU_P1_OFFSET] = 0;
    Command.pu8Data[VLT_APDU_P2_OFFSET] =  u8RequestedDataLength;
    Command.pu8Data[VLT_APDU_P3_OFFSET] = LIN(WRAPPED_BYTE(u8DataLength));

    /* Build Data In */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( &Command.pu8Data[idx], pu8DataIn, u8DataLength );
    idx += u8DataLength;

    /* Send the command */
    status = VltCommand( &Command, &Response, idx, 0, &Sw );

    if( ( Sw != VLT_STATUS_NONE ) && ( Sw != VLT_STATUS_SUCCESS ) )
    {
        return( Sw );
    }

    if (VLT_OK != status)
    {
        return status;
    }

    /* adjust the response size */
    Response.u16Len -= VLT_SW_SIZE;

    /* 
     * ensure that the received data don't exceed
     * the requested size 
     */
    if( u8RequestedDataLength < Response.u16Len )
    {
        return( ETC4NOROOM ); 
    }

    /* copy the data */
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( pu8RespData, Response.pu8Data, Response.u16Len );


    return( status );
}
#endif

#if(VLT_ENABLE_ISO7816 == VLT_ENABLE )
VLT_STS VltSelectCard( SCARDHANDLE hScard,  SCARDCONTEXT hCxt, DWORD dwProtocol)
{
    /*
     * Check VltApiInit done before
     */
    if (VltApiInitDone == 0)
    {
        return VLT_FAIL;
    }

    return( VltCommsSelectCard(hScard,hCxt,dwProtocol) );
}
#endif



