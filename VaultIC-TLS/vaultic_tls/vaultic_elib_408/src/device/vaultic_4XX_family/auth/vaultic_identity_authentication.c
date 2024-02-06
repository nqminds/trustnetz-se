

/**
* @file	   vaultic_identity_authentication.c
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
* @brief   Interface to identity authentication.
*
* @par Description:
* Provides the host with the ability to authenticate users who have the
* following authentication methods:
* Secure Channel 02.
* Secure Channel 03.
* Secure Channel 11.
* Microsoft Card Minidriver.
* @date    10/01/2017
* @author  fmauraton
*/

#include "vaultic_common.h"
#if (VLT_ENABLE_SCP03 == VLT_ENABLE) 
#include "vaultic_identity_authentication.h"
#include "vaultic_secure_channel.h"
#include "vaultic_api.h"

/*
* Defines
*/
#define SMAC_STATIC_KEY_INDEX 0
#define SENC_STATIC_KEY_INDEX 1
#define UNDEFINED_AUTH_METHOD 255


#if( VLT_ENABLE_IDENTITY_AUTH == VLT_ENABLE )
/*
 * Private Variable Definitions
 */
static VLT_AUTH_ID enCurAuthMethod = (VLT_AUTH_ID) UNDEFINED_AUTH_METHOD;
#endif


#if (VLT_ENABLE_AT_AUTH_INIT == VLT_ENABLE)
VLT_STS VltAuthInit( VLT_AUTH_ID enAuthMethod,
    VLT_USER_ID enUserID, 
    VLT_ROLE_ID enRoleID, 
    VLT_SEC_LEVEL_ID enChannelLevel,
    VLT_KEY_BLOB_ARRAY keys)
{
#if( VLT_ENABLE_IDENTITY_AUTH == VLT_ENABLE )    
    VLT_STS status;
    VLT_U8 i;
        
    /*
    * Check the input parameters are valid.
    */    
    if( NULL == keys.pKeys )
    {
        return( EIDINITNULLPARAM );
    }

    /* Check the key size is within range, 1 key for MS and 2 for SCP. */
    if( ( keys.u8ArraySize <= 0u ) || ( keys.u8ArraySize > 3u ) )
    {
        return( EIDNUMKEYS );
    }

    /* Check the key blob pointer at index i is not null, 
     * and the key value in the key blob structure is not null.
     */
    for( i = 0; i < keys.u8ArraySize; i++ )
    {
        if( NULL == keys.pKeys[i] )
        {
            return( EIDNULLBLOBBASE + i );
        }
        if( NULL == keys.pKeys[i]->keyValue )
        {
            return( EIDNULLKEYBASE + i );
        }
    }

	/*
	 * Determine which type of channel the user has request.
	 */
	switch (enAuthMethod)
	{
#if ( VLT_ENABLE_SCP03 == VLT_ENABLE)
	    case VLT_AUTH_SCP03:

		/*
		 * Call the secure channel init method
		 */
		status = VltScpInit(enUserID,
			enRoleID,
			enChannelLevel,
			keys.pKeys[SMAC_STATIC_KEY_INDEX],
			keys.pKeys[SENC_STATIC_KEY_INDEX]);

		/* If the channel has been established, change the internal
		   state variable to equal the type of auth method. */
		if (VLT_OK == status)
		{
            enCurAuthMethod = enAuthMethod;
		}

		break;
#endif

	default:
		status = EIDINITNULLPARAM;
		break;
	}
    
    return( status );
#else
    return( EMETHODNOTSUPPORTED );
#endif
}
#endif

#if (VLT_ENABLE_AT_AUTH_CLOSE == VLT_ENABLE)
VLT_STS VltAuthClose( void )
{
#if( VLT_ENABLE_IDENTITY_AUTH == VLT_ENABLE )    
    VLT_STS status;

    /* Check the internal state variable to determine what 
     * type of authentication is established. */
    switch (enCurAuthMethod)
    {
#if ( VLT_ENABLE_SCP03 == VLT_ENABLE )    
        case VLT_AUTH_SCP03:
            /* Log out the secure channel authenticated user. */
            status = VltScpClose();
            break;
#endif
    default:
        /* Call cancel authentication, nothing else can be done. */
        status = VltCancelAuthentication( );
        break;
    }
    
    /* Clear the state tracking variable. */
    enCurAuthMethod = (VLT_AUTH_ID) UNDEFINED_AUTH_METHOD;

    return ( status );
#else
    return( EMETHODNOTSUPPORTED );
#endif
}
#endif

#if (VLT_ENABLE_AT_AUTH_GET_STATE == VLT_ENABLE)
VLT_STS VltAuthGetState(VLT_AUTH_STATE *enState )
{
#if( VLT_ENABLE_IDENTITY_AUTH == VLT_ENABLE )
    VLT_STS status;

    if ( NULL == enState)
    {
        return ( EIDSTATENULLPARAM );
    }

    /* Check the internal state variable to determine what 
     * type of authentication is established. */
    switch (enCurAuthMethod)
    {

#if ( VLT_ENABLE_SCP03 == VLT_ENABLE )
    case VLT_AUTH_SCP03:
        
        /* Get the state of the secure channel authenticated user. */
        status = VltScpGetState(enState);

        break;
#endif

    default:
        /* Not authenticated */
        *enState =  VLT_USER_NOT_AUTHENTICATED;
        status = VLT_OK;
        break;
    }

    return ( status ); 
#else
    return( EMETHODNOTSUPPORTED );
#endif
}
#endif

VLT_STS VltAuthGetSecureSession ( VLT_SECURE_SESSION_STATE *pSessionState )
{
#if( VLT_ENABLE_IDENTITY_AUTH == VLT_ENABLE )
    if ( NULL == pSessionState )
    {
        return ( EIDSTATENULLPARAM );
    }

    pSessionState->enAuthMethod = enCurAuthMethod;
    return VltScpGetChannelSession( pSessionState );
#else
    return( EMETHODNOTSUPPORTED );
#endif
}

VLT_STS VltAuthResumeSecureSession ( const VLT_SECURE_SESSION_STATE *pSessionState )
{
#if( VLT_ENABLE_IDENTITY_AUTH == VLT_ENABLE )
    if ( NULL == pSessionState )
    {
        return ( EIDSTATENULLPARAM );
    }

    enCurAuthMethod = pSessionState->enAuthMethod;
    return VltScpSetChannelSession( pSessionState );
#else
    return( EMETHODNOTSUPPORTED );
#endif
}
#endif
