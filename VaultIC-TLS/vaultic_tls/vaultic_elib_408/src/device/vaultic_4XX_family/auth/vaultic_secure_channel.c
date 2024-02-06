/**
* @file	   vaultic_secure_channel.c
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
* @brief   Interface to secure channel.
*
* @details Interface to secure channel.
*
*/

#include "vaultic_common.h"
#if ( VLT_ENABLE_SCP03 == VLT_ENABLE)
#include "vaultic_secure_channel.h"
#include "vaultic_api.h"
#include "vaultic_scp03.h"
#include "vaultic_mem.h"
#include "vaultic_utils.h"

    /*
    * Function Pointer Defines
    */
    typedef VLT_STS (*pfnScpInit)( VLT_SEC_LEVEL_ID enChannelLevel, 
        const VLT_KEY_BLOB *pSMac, 
        const VLT_KEY_BLOB *pSEnc, 
        const VLT_U8 *pu8HostChal,
        VLT_U8 u8HostChalLen,
        const VLT_INIT_UPDATE* pInitUpRsp );

    typedef VLT_STS (*pfnScpClose)( void );

    typedef VLT_STS (*pfnScpWrap)( VLT_MEM_BLOB *pCmd );

    typedef VLT_STS (*pfnScpUnwrap)( VLT_MEM_BLOB *pRsp );

    typedef VLT_STS (*pfnScpGetChannelOverhead)( VLT_U8 u8Mode, VLT_U8 *pu8Overhead );

    typedef VLT_STS (*pfnScpGetAesIv)( VLT_U8 *pu8AesIv );

    typedef VLT_STS (*pfnScpSetAesIv)( const VLT_U8 *pu8AesIv );

    VLT_SEC_LEVEL_ID enSecureChannelLevel = VLT_NO_CHANNEL;
    VLT_AUTH_STATE enSecureChannelState = VLT_USER_NOT_AUTHENTICATED;

    extern VLT_U8 au8CMacKey[];
    extern VLT_U8 au8RMacKey[];
    extern VLT_U8 au8CEncKey[];
    extern VLT_U8 au8CMac[];
    extern VLT_U8 au8RMac[];

    VLT_U8 au8CMacKey[SCPXX_MAX_SESSION_KEY_LEN];
    VLT_U8 au8RMacKey[SCPXX_MAX_SESSION_KEY_LEN];
    VLT_U8 au8CEncKey[SCPXX_MAX_SESSION_KEY_LEN];

    VLT_U8 au8CMac[SCPXX_MAX_CMAC_LEN];
    VLT_U8 au8RMac[SCPXX_MAX_RMAC_LEN];

    /** \cond SHOW_INTERNAL */
    typedef struct 
    {
        pfnScpInit SecureChannelInit;
        pfnScpClose SecureChannelClose;
        pfnScpWrap SecureChannelWrap;
        pfnScpUnwrap SecureChannelUnwrap;
        pfnScpGetChannelOverhead SecureChannelGetChannelOverhead;
        pfnScpGetAesIv SecureChannelGetAesIv;
        pfnScpSetAesIv SecureChannelSetAesIv;
    } SecureChannel;
    /** \endcond */

    //initialisation
    static SecureChannel theSecureChannel =
    {
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
    };

/*
* Defines
*/

#define HOST_CHALLENGE_LEN    (VLT_U8)0x08

VLT_STS VltScpInit( VLT_USER_ID enUserID,
    VLT_ROLE_ID enRoleID, 
    VLT_SEC_LEVEL_ID enChannelLevel, 
    const VLT_KEY_BLOB *pSMac, 
    const VLT_KEY_BLOB *pSEnc )
{
#if ( VLT_ENABLE_SCP03 == VLT_ENABLE)
    VLT_STS status;
    VLT_U8 au8HostChallenge[HOST_CHALLENGE_LEN];
    VLT_INIT_UPDATE respData;
    
    /*
    * Check that the input parameters are valid
    */
    if( ( NULL == pSMac ) || 
        ( NULL == pSEnc ) || 
        ( NULL == pSMac->keyValue) || 
        ( NULL == pSEnc->keyValue) )
    {
        return ESCPINITNULLPARAM;
    }

    /*
    * Ensure the channel is closed
    */
    status = VltScpClose();
    
    if( VLT_OK != status )
    {
        return ( status );
    }

    /*
    * Generate a random on the host side
    */
    if (VLT_OK != GenerateRandomBytes(au8HostChallenge, HOST_CHALLENGE_LEN))
    {
        status = ESTRONGGENRANDFAIL;
    }
    
    /*
    * Check that the call to Generate Random was successful
    */
    if( VLT_OK != status )
    {
        return ( ESCPGENRANDFAIL );
    }

    
    /*
    * Initialise Update
    */
    status = VltInitializeUpdate( enUserID, 
        enRoleID,
        HOST_CHALLENGE_LEN,
        au8HostChallenge,
        &respData );
    
    
    /*
    * Check that the call to Initialize Update was successful
    */
    if( VLT_OK != status )
    {
        return ( ESCPINITUPDTFAIL );
    }

    /*
    * Check that the response has given SCP03 data
    */
    switch( respData.enLoginMethodID )
    {
#if( VLT_ENABLE_SCP03 == VLT_ENABLE )   
    case VLT_AUTH_SCP03:
        {
            theSecureChannel.SecureChannelInit = VltScp03Init;
            theSecureChannel.SecureChannelClose = VltScp03Close;
            theSecureChannel.SecureChannelWrap = VltScp03Wrap;
            theSecureChannel.SecureChannelUnwrap = VltScp03Unwrap;
            theSecureChannel.SecureChannelGetChannelOverhead = 
                VltScp03GetChannelOverhead;
            theSecureChannel.SecureChannelGetAesIv = VltScp03GetAesIv;
            theSecureChannel.SecureChannelSetAesIv = VltScp03SetAesIv;
            break;
        }
#endif /* ( VLT_ENABLE_SCP03 == VLT_ENABLE ) */
    default:
        {
            status = ESCPINITUPDTMODE;
            break;
        }
    }

    if ( VLT_OK == status ) 
    {
        status = theSecureChannel.SecureChannelInit(enChannelLevel, 
            pSMac, 
            pSEnc, 
            au8HostChallenge, 
            HOST_CHALLENGE_LEN,
            &respData );

        
        if ( VLT_OK != status )
        {
            /* Needed to ensure further attempts to start authentication,
               does not result in Initialise Update returning an error (6988h). */
            (void)VltCancelAuthentication( );
        }
    }
    
    return( status );
#else
    return( EMETHODNOTSUPPORTED );
#endif
}

VLT_STS VltScpClose(void)
{
    if (theSecureChannel.SecureChannelClose != NULL)
    {
        return theSecureChannel.SecureChannelClose();
    }
    else //NO secure channel initialized yet
    {
        return VltCancelAuthentication();
    }
}

VLT_STS VltScpGetState(VLT_AUTH_STATE *enState)
{
    /*
    * Check the validity of the input parameter
    */
    if( NULL == enState)
    {
        return SCPGETSTATENULLPARAM;
    }

    *enState = enSecureChannelState;

    return( VLT_OK );
}

VLT_STS VltScpWrap( VLT_MEM_BLOB *pCmd )
{    
    
    if (theSecureChannel.SecureChannelWrap != NULL)
    {
        return theSecureChannel.SecureChannelWrap(pCmd);
    }
    else
    {
        //NO secure channel initialized yet
        return(VLT_OK);
    }
}

VLT_STS VltScpUnwrap( VLT_MEM_BLOB *pRsp )
{    
    if (theSecureChannel.SecureChannelUnwrap != NULL)
    {
        return theSecureChannel.SecureChannelUnwrap(pRsp);
    }
    else
    {
        //NO secure channel initialized yet
        return(VLT_OK);
    }
}

VLT_STS VltScpGetChannelOverhead( VLT_U8 u8Mode, VLT_U8 *pu8Overhead )
{    
    if (theSecureChannel.SecureChannelGetChannelOverhead != NULL)
    {
        return theSecureChannel.SecureChannelGetChannelOverhead(u8Mode, pu8Overhead);
    }
    else
    {
        //NO secure channel initialized yet
        *pu8Overhead = 0;
        return VLT_OK;
    }
}

VLT_STS VltScpGetChannelSession( VLT_SECURE_SESSION_STATE *pState )
{
   if ( NULL == pState )
   {
       return ( EIDSTATENULLPARAM );
   }

   if (NULL == theSecureChannel.SecureChannelGetAesIv)
   {
       return (EIDINITSCPNOTDONE);
   }

   pState->enSecureChannelLevel = enSecureChannelLevel;
   pState->enSecureChannelState = enSecureChannelState;
   (void)host_memcpy(pState->au8CMacKey, au8CMacKey, sizeof(pState->au8CMacKey));
   (void)host_memcpy(pState->au8RMacKey, au8RMacKey, sizeof(pState->au8RMacKey));
   (void)host_memcpy(pState->au8CEncKey, au8CEncKey, sizeof(pState->au8CEncKey));
   (void)host_memcpy(pState->au8CMac, au8CMac, sizeof(pState->au8CMac));
   (void)host_memcpy(pState->au8RMac, au8RMac, sizeof(pState->au8RMac));
   return theSecureChannel.SecureChannelGetAesIv((VLT_U8 *)((void*)&pState->au8AesIV));
}

VLT_STS VltScpSetChannelSession( const VLT_SECURE_SESSION_STATE*pState )
{
   if ( NULL == pState )
   {
       return ( EIDSTATENULLPARAM );
   }

   if (NULL == theSecureChannel.SecureChannelSetAesIv)
   {
       return (EIDINITSCPNOTDONE);
   }

   enSecureChannelLevel = pState->enSecureChannelLevel;
   enSecureChannelState = pState->enSecureChannelState;
   (void)host_memcpy(au8CMacKey, pState->au8CMacKey, sizeof(au8CMacKey));
   (void)host_memcpy(au8RMacKey, pState->au8RMacKey, sizeof(au8RMacKey));
   (void)host_memcpy(au8CEncKey, pState->au8CEncKey, sizeof(au8CEncKey));
   (void)host_memcpy(au8CMac, pState->au8CMac, sizeof(au8CMac));
   (void)host_memcpy(au8RMac, pState->au8RMac, sizeof(au8RMac));
   return theSecureChannel.SecureChannelSetAesIv((VLT_U8 *)((void*)&pState->au8AesIV));
}
#endif/* VLT_ENABLE_SCP03 == VLT_ENABLE ) */
