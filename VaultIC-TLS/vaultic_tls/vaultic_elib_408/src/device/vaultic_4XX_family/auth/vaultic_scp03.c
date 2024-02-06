/**
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
 * @details
 */



#include "vaultic_common.h"
#if( VLT_ENABLE_SCP03 == VLT_ENABLE )
#include "vaultic_secure_channel.h"
#include "vaultic_api.h"
#include "vaultic_mem.h"
#include "vaultic_cipher.h"
#include "vaultic_symmetric_signer.h"
#include "vaultic_apdu.h"
#include "vaultic_scp03.h"

/*
* Defines
*/
#define SCP03_KDF_CONST_ZERO_LEN  (VLT_U8)0x0B
#define SCP03_KDF_INPUT_LEN       (VLT_U8)0x20
#define SCP03_CMAC_INIT_VAL       (VLT_U8)0x06
#define SCP03_RMAC_INIT_VAL       (VLT_U8)0x07
#define SCP03_CENC_INIT_VAL       (VLT_U8)0x04
#define SCP03_ACH_INIT_VAL        (VLT_U8)0x01
#define SCP03_ACD_INIT_VAL        (VLT_U8)0x00
#define SCP03_CRYP_LEN_VAL        (VLT_U16)0x0040

#define LEFT_SHIFTS_MULT_BY_8     (VLT_U8)0x03
#define BITS_PER_BYTE             (VLT_U8)0x08

#define SCP03_MAX_SESSION_KEY_LEN SCPXX_MAX_SESSION_KEY_LEN
#define AES_INIT_VECT_LEN         SCPXX_MAX_CMAC_LEN
#define SCP03_CMAC_RMAC_LEN       (VLT_U8)0x08
#define SCP03_CENC_LEN            (VLT_U8)0x10
#define AES_CMAC_LEN              (VLT_U8)0x10

#define CALC_CMAC                 (VLT_U8)0x00
#define CALC_RMAC                 (VLT_U8)0x01

#define SW_INVALID_MAC_HIGH       (VLT_U8)0x69
#define SW_INVALID_MAC_LOW        (VLT_U8)0x88


/*
* External Variables
*/
extern VLT_SEC_LEVEL_ID enSecureChannelLevel; /* Declared in vaultic_secure_channel.c */
extern VLT_AUTH_STATE enSecureChannelState; /* Declared in vaultic_secure_channel.c */

extern VLT_U8 au8CMacKey[SCPXX_MAX_SESSION_KEY_LEN]; /* Declared in vaultic_secure_channel.c */
extern VLT_U8 au8RMacKey[SCPXX_MAX_SESSION_KEY_LEN]; /* Declared in vaultic_secure_channel.c */
extern VLT_U8 au8CEncKey[SCPXX_MAX_SESSION_KEY_LEN]; /* Declared in vaultic_secure_channel.c */

extern VLT_U8 au8CMac[SCPXX_MAX_CMAC_LEN]; /* Declared in vaultic_secure_channel.c */
extern VLT_U8 au8RMac[SCPXX_MAX_RMAC_LEN]; /* Declared in vaultic_secure_channel.c */

/*
* Private Data
*/
static VLT_KEY_BLOB theCMacKey = { VLT_KEY_AES_128, AES_128_KEY_SIZE, au8CMacKey };
static VLT_KEY_BLOB theRMacKey = { VLT_KEY_AES_128, AES_128_KEY_SIZE, au8RMacKey };
static VLT_KEY_BLOB theCEncKey = { VLT_KEY_AES_128, AES_128_KEY_SIZE, au8CEncKey };

static VLT_U8 au8AesIV[AES_INIT_VECT_LEN];

/*
* Static methods
*/
static void ResetChannel( void );

static VLT_STS DeriveSessionKeys( const VLT_KEY_BLOB *pSMac,
								 const VLT_KEY_BLOB *pSEnc,
								 const VLT_U8 *pu8HostChal,
								 VLT_U8 u8HostChalLen,
								 const VLT_U8 *pu8DevChal,
								 VLT_U8 u8DevChalLen );

static VLT_STS KDF( const VLT_KEY_BLOB *pInputKey,
				   VLT_U8 u8InitVal,
				   const VLT_U8 *pu8HostChal,
				   VLT_U8 u8HostChalLen,
				   const VLT_U8 *pu8DevChal,
				   VLT_U8 u8DevChalLen,
				   VLT_U16 u16Length,
				   VLT_U8 *pu8Output );

static VLT_STS CalculateMac( VLT_MEM_BLOB *pCmd, VLT_U8 u8MacMode );

static VLT_STS EncryptCommandData( VLT_MEM_BLOB *pCmd);

static VLT_STS DecryptResponseData( VLT_MEM_BLOB *pRsp);


VLT_STS VltScp03Init( VLT_SEC_LEVEL_ID enChannelLevel,
					 const VLT_KEY_BLOB *pSMac,
					 const VLT_KEY_BLOB *pSEnc,
					 const VLT_U8 *pu8HostChal,
					 const VLT_U8 u8HostChalLen,
					 const VLT_INIT_UPDATE* pInitUpRsp )
{
	VLT_STS status;
	VLT_U8 au8Temp[SCP03_KDF_INPUT_LEN];
	VLT_U8 au8AuthCryptoDevice[VLT_SCPXX_CRYPTOGRAM_LENGTH];
	VLT_U8 au8AuthCryptoHost[VLT_SCPXX_CRYPTOGRAM_LENGTH];

	/*
	* Check that the input parameters are valid
	*/
	if( ( NULL == pSMac ) || 
		( NULL == pSEnc ) || 
		( NULL == pSMac->keyValue) || 
		( NULL == pSEnc->keyValue) ||
		( NULL == pu8HostChal ) ||
		( NULL == pInitUpRsp ) )
	{
		return ESCP03INITNULLPARAM;
	}

	/*
	* Check the validity of the SMAC Key
	*/
	if( ! ( ( ( VLT_KEY_AES_128 == pSMac->keyType ) &&
		( AES_128_KEY_SIZE == pSMac->keySize ) ) ||
		( ( VLT_KEY_AES_192 == pSMac->keyType ) &&
		( AES_192_KEY_SIZE == pSMac->keySize ) ) ||
		( ( VLT_KEY_AES_256 == pSMac->keyType ) && 
		( AES_256_KEY_SIZE == pSMac->keySize ) ) ) )
	{
		return ESCP03INITINVLDSMAC;
	}

	/*
	* Check the validity of the SENC Key
	*/
	if( ! ( ( ( VLT_KEY_AES_128 == pSEnc->keyType ) &&
		( AES_128_KEY_SIZE == pSEnc->keySize ) ) ||
		( ( VLT_KEY_AES_192 == pSEnc->keyType ) &&
		( AES_192_KEY_SIZE == pSEnc->keySize ) ) ||
		( ( VLT_KEY_AES_256 == pSEnc->keyType ) &&
		( AES_256_KEY_SIZE == pSEnc->keySize ) ) ) )
	{
		return ESCP03INITINVLDSENC;
	}

	/*
	* Reset the channel
	*/
	ResetChannel( );


	/*
	* Derive Session Keys
	*/
	status = DeriveSessionKeys( pSMac,
		pSEnc,
		pu8HostChal,
		u8HostChalLen,
		pInitUpRsp->data.Scp03.u8DeviceChallenge,
		(VLT_U8)sizeof( pInitUpRsp->data.Scp03.u8DeviceChallenge ) );

	if( VLT_OK == status )
	{
		/*
		* Calculate the relevant part for the Device Cryptogram
		*/
		status = KDF( &theCMacKey,
			SCP03_ACD_INIT_VAL,
			pu8HostChal,
			u8HostChalLen,
			pInitUpRsp->data.Scp03.u8DeviceChallenge,
			(VLT_U8)sizeof( pInitUpRsp->data.Scp03.u8DeviceChallenge ),
			SCP03_CRYP_LEN_VAL,
			&au8Temp[0] );
	}

	if( VLT_OK == status )
	{
		/*
		* Copy the device Cryptogram
		*/
		/*
		* No need to check the return type as pointer has been validated
		*/
		(void)host_memcpy( &au8AuthCryptoDevice[0],
			&au8Temp[0],
			VLT_SCPXX_CRYPTOGRAM_LENGTH );

		/*
		* Compare the computed and recieved values for Device Cryptogram
		*/
		if( 0u != host_memcmp(pInitUpRsp->data.Scp03.u8Cryptogram,
			&au8AuthCryptoDevice[0],
			VLT_SCPXX_CRYPTOGRAM_LENGTH ) )
		{
			/*
			* Invalid Device Authentication Cryptogram
			*/
			status = ESCP03INVLDDEVCRYPTO;
		}
	}

	if( VLT_OK == status )
	{
		/*
		* Calculate the Host Cryptogram
		*/
		status = KDF( &theCMacKey,
			SCP03_ACH_INIT_VAL,
			pu8HostChal,
			u8HostChalLen,
			pInitUpRsp->data.Scp03.u8DeviceChallenge,
			(VLT_U8)sizeof( pInitUpRsp->data.Scp03.u8DeviceChallenge ),
			SCP03_CRYP_LEN_VAL,
			&au8Temp[0] );
	}

	if( VLT_OK == status )
	{
		/*
		* Copy the relevant part for the host Cryptogram
		*/
		/*
		* No need to check the return type as pointer has been validated
		*/
		(void)host_memcpy( &au8AuthCryptoHost[0],
			&au8Temp[0],
			VLT_SCPXX_CRYPTOGRAM_LENGTH );

		/*
		* External Authenticate
		*/
		status = VltExternalAuthenticate(VLT_AUTH_SCP03,
			enChannelLevel,
			VLT_SCPXX_CRYPTOGRAM_LENGTH,
			&au8AuthCryptoHost[0] );

		/*
		* Check that the call to External Authenticate was successful
		*/
		if( VLT_OK != status )
		{
			status = ESCP03EXTAUTHFAIL;
		}
	}

	/*
	* If External Authenticate sent back status success update the channel
	* level as it has now been established
	*/
	if( VLT_OK == status )
	{
		enSecureChannelLevel = enChannelLevel;
		enSecureChannelState = VLT_USER_AUTHENTICATED;
	}

	return( status );
}

VLT_STS VltScp03Close( void  )
{
	VLT_STS status;

	status = VltCancelAuthentication();

	ResetChannel();

	return( status );
}

VLT_STS VltScp03Wrap( VLT_MEM_BLOB *pCmd )
{
	VLT_STS status = VLT_FAIL;

	/*
	* Check that we were passed a valid command buffer
	*/
	if( ( NULL == pCmd ) || ( NULL == pCmd->pu8Data ) )
	{
		return ESCP03WRAPNULLPARAM;
	}

	/*
	* If no channel is established don't add anything
	*/

	if( VLT_NO_CHANNEL == enSecureChannelLevel)
	{
		/*
		* The exception to this rule is if External Authenticate is being
		* sent to setup a Secure Channel.  If so it needs to have a C-Mac
		* appended
		*/
		if( VLT_INS_EXTERNAL_AUTHENTICATE_SCP !=
			pCmd->pu8Data[VLT_APDU_INS_OFFSET] )
		{
			/*
			* Any other command should be sent as is
			*/
			status = VLT_OK;
		}
	}
	else
	{
		/*
		* A secure channel has been established.  Check if the command is
		* Get Response.  If it is don't add any C-MAC or C-ENC
		*/
		if( VLT_INS_GET_RESPONSE == pCmd->pu8Data[VLT_APDU_INS_OFFSET])
		{
			status = VLT_OK;
		}
	}
	/*
	* If the status value still has the initial value of VLT_FAIL
	* add the appropriate secure channel data
	*/
	if ( VLT_FAIL == status )
	{
		/*
		* If Secure Channel is established with C-MAC or above change the class
		* byte
		*/
		pCmd->pu8Data[VLT_APDU_CLASS_OFFSET] |= VLT_CLA_SCP_BIT;

		/*
		* Check if the channel level requires the data to be encrypted
		*/
		if( ( VLT_CMAC_CENC == enSecureChannelLevel ) ||
			( VLT_CMAC_CENC_RMAC == enSecureChannelLevel) ||
			( VLT_CMAC_CENC_RMAC_RENC == enSecureChannelLevel) )
		{
			/*
			* Encrypt the data if there is data to encrypt
			*/
			if( VLT_HEADER_SIZE < pCmd->u16Len)
			{
				status = EncryptCommandData( pCmd );
			}
			else
			{
				/*
				* Set the status as VLT_OK so that the C-MAC can be added
				*/
				status = VLT_OK;
			}
		}
		else
		{
			/*
			* Set the status as VLT_OK so that the C-MAC can be added
			*/
			status = VLT_OK;
		}

		if( VLT_OK == status )
		{
			/*
			* All channel levels other than NO CHANNEL add a CMAC.
			* This is calculated on the encryped data
			*/
			status = CalculateMac( pCmd, CALC_CMAC );
		}

		if( VLT_OK == status)
		{
			/*
			* Add the C-Mac to the command buffer and update the P3 value
			*/
			/*
			* No need to check the return type as pointer has been validated
			*/
			(void)host_memcpy( &(pCmd->pu8Data[pCmd->u16Len]),
				&au8CMac[0],
				SCP03_CMAC_RMAC_LEN);

			/*
			* P3 value was already adjusted for the C-MAC calculation
			*/
			pCmd->u16Len += SCP03_CMAC_RMAC_LEN;
		}
	}

	return( status );
}

VLT_STS VltScp03Unwrap( VLT_MEM_BLOB *pRsp )
{
	VLT_STS status;
	VLT_U8 *pu8RMac;
	VLT_U8 *pu8SW = 0;
	VLT_U8 au8RMacRcvd[SCP03_CMAC_RMAC_LEN];

	/*
	* Check that we were passed a valid response buffer
	*/
	if( ( NULL == pRsp ) || ( NULL == pRsp->pu8Data ) )
	{
		return ESCP0UNWRAPNULLPARAM;
	}

	/*
	* If no channel is established don't remove anything
	*/
	if( VLT_NO_CHANNEL == enSecureChannelLevel)
	{
		status = VLT_OK;
	}
	else
	{
		if( VLT_SW_SIZE == pRsp->u16Len)
		{
			/*
			* Only a Status Word is present in the response data so don't
			* attempt to unwrap the data
			*/
			if( ( SW_INVALID_MAC_HIGH == pRsp->pu8Data[0] ) &&
				( SW_INVALID_MAC_LOW == pRsp->pu8Data[1] ) )
			{
				/*
				* Close the secure channel.
				*/
				(void)VltScp03Close();
				status = ESCP03INVLDCMAC;
			}
			else
			{
				status = VLT_OK;
			}
		}
		else
		{
			/*
			* Check if the channel level specifies if an R-MAC should be present
			*/
			if( ( VLT_CMAC_RMAC == enSecureChannelLevel) ||
				( VLT_CMAC_CENC_RMAC == enSecureChannelLevel) ||
				( VLT_CMAC_CENC_RMAC_RENC == enSecureChannelLevel) )
			{
				/*
				* A R-MAC will be present at the end of the data, but before
				* the status word.  Take a copy of it and move the status word
				* to the end of the data.  Also adjust the length of the buffer
				* to reflect this
				*/
				pu8SW = &(pRsp->pu8Data[pRsp->u16Len - VLT_SW_SIZE]);
				pu8RMac = &(pRsp->pu8Data[pRsp->u16Len - VLT_SW_SIZE - SCP03_CMAC_RMAC_LEN]);

				/*
				* No need to check the return type as pointer has been validated
				*/
				(void)host_memcpy( &au8RMacRcvd[0], pu8RMac, SCP03_CMAC_RMAC_LEN );
				(void)host_memcpy(pu8RMac, pu8SW, VLT_SW_SIZE );
				pRsp->u16Len -= SCP03_CMAC_RMAC_LEN;
			}
                        //useless code
                        //Set the status as VLT_OK so that the C-MAC can be removed
//			else
//			{
//				status = VLT_OK;
//			}


			if( ( VLT_CMAC_RMAC == enSecureChannelLevel) ||
				( VLT_CMAC_CENC_RMAC == enSecureChannelLevel) ||
				( VLT_CMAC_CENC_RMAC_RENC == enSecureChannelLevel) )
			{
				/*
				* Check that the R-MAC is valid
				*/
				status = CalculateMac( pRsp, CALC_RMAC );

				if(VLT_OK == status)
				{
					/*
					* Check that the R-MAC is as expected
					*/
					if( 0u !=
						host_memcmp( &au8RMac[0],
						&au8RMacRcvd[0],
						SCP03_CMAC_RMAC_LEN ))
					{
						status = ESCP03INVLDRMAC;

						/*
						* Close the channel as the R-MAC received doesn't
						* match that calculated
						*/
						(void)VltScp03Close();

						return( status );
					}
				}
			}

			/*
			* Check if the channel level requires the data to be decrypted
			*/
			if( VLT_CMAC_CENC_RMAC_RENC == enSecureChannelLevel)
			{
				/*
				* If only a status word is present there is no data to decrypt
				*/
				if(VLT_SW_SIZE < pRsp->u16Len)
				{
					status = DecryptResponseData( pRsp );

					if(VLT_OK == status)
					{
						/* Put the status word at the end of the decrypted
						* data and adjust the size to include it
						*/
						/*
						* No need to check the return type as pointer has been validated
						*/
						(void)host_memcpy( &(pRsp->pu8Data[pRsp->u16Len]),
							pu8SW,
							VLT_SW_SIZE);
						pRsp->u16Len += VLT_SW_SIZE;

					}
				}
				else
				{
					status = VLT_OK;
				}

				if( VLT_OK != status )
				{
					/*
					* Close the channel as decryption failed
					*/
					(void)VltScp03Close();
				}
			}
			else
			{
				status = VLT_OK;
			}
		}
	}

	return( status );
}

VLT_STS VltScp03GetChannelOverhead( VLT_U8 u8Mode, VLT_U8 *pu8Overhead )
{
	/*
	* Check the input paramters are valid
	*/
	if( NULL == pu8Overhead )
	{
		return ESCP03GETOVHDNULLPARAM;
	}

	if( ( SECURE_CHANNEL_SEND != u8Mode ) && 
		( SECURE_CHANNEL_RECEIVE != u8Mode ) )
	{
		return ESCP03GETOVHDINVLDMODE;
	}

	/*
	* The following values have been altered to match the current behaviour of
	* the firmware.  The commented values are what are believed to be the
	* correct values.  This is documented within JIRA issue SDAT98FW-277
	*/
	switch(enSecureChannelLevel)
	{
		/*
		* No channel means no extra overhead
		*/
	case VLT_NO_CHANNEL:
		*pu8Overhead = 0;
		break;

		/*
		* CMAC
		*/
	case VLT_CMAC:
		if( SECURE_CHANNEL_SEND == u8Mode)
		{
			*pu8Overhead = SCP03_CMAC_RMAC_LEN;
		}
		else
		{
			*pu8Overhead = 0;
		}
		break;

		/*
		* CMAC RMAC
		*/
	case VLT_CMAC_RMAC:
		*pu8Overhead = SCP03_CMAC_RMAC_LEN;
		break;

		/*
		* CMAC and CENC
		*/
	case VLT_CMAC_CENC:
		if( SECURE_CHANNEL_SEND == u8Mode)
		{
			/**pu8Overhead = SCP03_CENC_LEN + 1;*/
			*pu8Overhead = SCP03_CENC_LEN + SCP03_CMAC_RMAC_LEN;
		}
		else
		{
			*pu8Overhead = 0;
		}
		break;

		/*
		* CMAC CENC RMAC
		*/
	case VLT_CMAC_CENC_RMAC:
		if( SECURE_CHANNEL_SEND == u8Mode)
		{
			/**pu8Overhead = SCP03_CENC_LEN + 1;*/
			*pu8Overhead = SCP03_CENC_LEN + SCP03_CMAC_RMAC_LEN;
		}
		else
		{
			*pu8Overhead = SCP03_CMAC_RMAC_LEN;
		}
		break;

		/*
		* CMAC CENC RMAC RENC
		*/
	case VLT_CMAC_CENC_RMAC_RENC:
		/**pu8Overhead = SCP03_CENC_LEN + 1;*/
		*pu8Overhead = SCP03_CENC_LEN + SCP03_CMAC_RMAC_LEN;
		break;

		/*
		* Should never get here as the enSecureChannelLevel value is private
		* data and should only ever get one of the above values
		*/
	default:
		break;
	}

	return( VLT_OK );
}

VLT_STS VltScp03GetAesIv( VLT_U8 *pAesIv )
{
	/*
	* Check the input parameters are valid
	*/
	if( NULL == pAesIv )
	{
		return ESCP03GETOVHDNULLPARAM;
	}

	(void)host_memcpy(pAesIv, au8AesIV, sizeof(au8AesIV));
	return( VLT_OK );
}

VLT_STS VltScp03SetAesIv( const VLT_U8 *pAesIv )
{
	/*
	* Check the input parameters are valid
	*/
	if( NULL == pAesIv )
	{
		return ESCP03GETOVHDNULLPARAM;
	}

	(void)host_memcpy(au8AesIV, pAesIv, sizeof(au8AesIV));
	return( VLT_OK );
}

static void ResetChannel( void )
{
	/*
	* Clear the Session Keys
	*/
	(void)host_memset( &au8CMacKey[0], 0x00, SCP03_MAX_SESSION_KEY_LEN );
	(void)host_memset( &au8RMacKey[0], 0x00, SCP03_MAX_SESSION_KEY_LEN );
	(void)host_memset( &au8CEncKey[0], 0x00, SCP03_MAX_SESSION_KEY_LEN );

	/*
	* Reinitialise the MAC IV's
	*/
	(void)host_memset( &au8AesIV[0], 0x00, AES_INIT_VECT_LEN );

	/*
	* Clear the currently stored MAC
	*/
	(void)host_memset( &au8CMac[0], 0x00, AES_CMAC_LEN );

	/*
	* Reset the channel level to No Channel
	*/
	enSecureChannelLevel = VLT_NO_CHANNEL;

	/*
	* Reset the state of the channel to not established
	*/
	enSecureChannelState = VLT_USER_NOT_AUTHENTICATED;
}

static VLT_STS DeriveSessionKeys(const VLT_KEY_BLOB *pSMac,
								 const VLT_KEY_BLOB *pSEnc,
								 const VLT_U8 *pu8HostChal,
								 VLT_U8 u8HostChalLen,
								 const VLT_U8 *pu8DevChal,
								 VLT_U8 u8DevChalLen )
{
	VLT_STS status;
	VLT_U16 u16KeyLenInBits;

	/*
	* Check that the input parameters are valid
	*/
	if( ( NULL == pSMac ) ||
		( NULL == pSEnc ) ||
		( NULL == pu8HostChal ) ||
		( NULL == pu8DevChal ) )
	{
		return ESCP03DERSESSKEYNULLPARAM;
	}

	/*
	* Calculate the C-MAC Key
	*/

	u16KeyLenInBits = pSMac->keySize << LEFT_SHIFTS_MULT_BY_8;
	status = KDF( pSMac,
		SCP03_CMAC_INIT_VAL,
		pu8HostChal,
		u8HostChalLen,
		pu8DevChal,
		u8DevChalLen,
		u16KeyLenInBits,
		&au8CMacKey[0] );

	/*
	* Calculate the R-MAC Key
	*/
	if(VLT_OK == status)
	{
		status = KDF( pSMac,
			SCP03_RMAC_INIT_VAL,
			pu8HostChal,
			u8HostChalLen,
			pu8DevChal,
			u8DevChalLen,
			u16KeyLenInBits,
			&au8RMacKey[0] );
	}

	/*
	* Calculate the C-ENC Key
	*/
	if(VLT_OK == status)
	{
		u16KeyLenInBits = pSEnc->keySize << LEFT_SHIFTS_MULT_BY_8;
		status = KDF( pSEnc,
			SCP03_CENC_INIT_VAL,
			pu8HostChal,
			u8HostChalLen,
			pu8DevChal,
			u8DevChalLen,
			u16KeyLenInBits,
			&au8CEncKey[0] );
	}

	if( VLT_OK == status )
	{
		/*
		* Update the Session Key Key Blobs
		*/
		theCMacKey.keyType = pSMac->keyType;
		theCMacKey.keySize = pSMac->keySize;
		theCMacKey.keyValue = &au8CMacKey[0];

		theRMacKey.keyType = pSMac->keyType;
		theRMacKey.keySize = pSMac->keySize;
		theRMacKey.keyValue = &au8RMacKey[0];

		theCEncKey.keyType = pSEnc->keyType;
		theCEncKey.keySize = pSEnc->keySize;
		theCEncKey.keyValue = &au8CEncKey[0];
	}

	return( status );
}

static VLT_STS KDF( const VLT_KEY_BLOB *pInputKey,
				   VLT_U8 u8InitVal,
				   const VLT_U8 *pu8HostChal,
				   VLT_U8 u8HostChalLen,
				   const VLT_U8 *pu8DevChal,
				   VLT_U8 u8DevChalLen,
				   VLT_U16 u16Length,
				   VLT_U8 *pu8Output )
{
	VLT_STS status = VLT_FAIL;

	VLT_U8 u8Input[SCP03_KDF_INPUT_LEN];
	VLT_U8 *pu8InputDataPos = &u8Input[0];
	VLT_U8 u8NumIters;
	VLT_U8 i;
	SIGNER_PARAMS signerParams;
	VLT_U32 u32DataLen = 0;
	VLT_U8 *pu8OutputPos;
	VLT_U32 u32OutputCapacity;

    VLT_U8 u8IteratorIdx = 0;
    VLT_U8 idx = 0;

	/*
	* Setup the input to the AES CMAC in the form
	* Label || 00h || L || i || Context
	*/

	/*
	* Setup the constant value
	*/
	(void)host_memset( pu8InputDataPos, 0x00, SCP03_KDF_CONST_ZERO_LEN );
    idx += SCP03_KDF_CONST_ZERO_LEN;

    pu8InputDataPos[idx++] = u8InitVal;

	/*
	* Add the value of 00h
	*/
    pu8InputDataPos[idx++] = 0x00;

	/*
	* Copy the length.  This is has been passed in bits
	*/
    pu8InputDataPos[idx++] = ((VLT_U8)(u16Length >> BITS_PER_BYTE)) & 0xFFu;
    pu8InputDataPos[idx++] = ((VLT_U8)u16Length) & 0xFFu;

	/*
    * Store the position of the iterator
    */
    u8IteratorIdx = idx++;

	/*
	* Copy in the Host Challenge then the Device challenge.  Device Challenge
	*/
	/*
	* No need to check the return type as pointer has been validated
	*/
	(void)host_memcpy( &pu8InputDataPos[idx], pu8HostChal, u8HostChalLen );
    idx += u8HostChalLen;

	/*
	* No need to check the return type as pointer has been validated
	*/
    (void)host_memcpy(&pu8InputDataPos[idx], pu8DevChal, u8DevChalLen);

	/*
	* Calculate the number of iterations of the AES CMAC required
	*/
	if( AES_128_KEY_SIZE == pInputKey->keySize )
	{
		u8NumIters = 1;
	}
	else
	{
		u8NumIters = 2;
	}

	/*
	* Setup the Cipher Params
	*/
	signerParams.enAlgoID = VLT_ALG_SIG_CMAC_AES;
	signerParams.pIV = &au8AesIV[0];
	signerParams.enPaddingScheme = VLT_PADDING_ISO9797_METHOD2;
	signerParams.ivSize = AES_INIT_VECT_LEN;


	pu8OutputPos = pu8Output;
	u32OutputCapacity = SCP03_MAX_SESSION_KEY_LEN;

	for( i = 1; i <= u8NumIters; i++)
	{
		/*
        * Set the value of the iterator in the input data
        */
        pu8InputDataPos[u8IteratorIdx] = i;

		/*
		* Initialise the Signer with the correct key and parameters
		*/
		status = SymmetricSignerInit( VLT_SIGN_MODE, pInputKey, (VLT_U8 *)((void*)&signerParams) );

		if(VLT_OK == status)
		{
			/*
			* Sign the data
			*/
			status = SymmetricSignerDoFinal(&u8Input[0],
				SCP03_KDF_INPUT_LEN,
				SCP03_KDF_INPUT_LEN,
				pu8OutputPos,
				&u32DataLen,
				u32OutputCapacity);

			/*
			* Update the output pointer
			*/
			//Replace: pu8OutputPos += u32DataLen;
			//to be MISRA compliant
			pu8OutputPos = &pu8OutputPos[u32DataLen];

			u32OutputCapacity -= u32DataLen;
		}
	}

	return ( status );
}

static VLT_STS CalculateMac( VLT_MEM_BLOB *pCmd, VLT_U8 u8MacMode )
{
	VLT_STS status;
	VLT_KEY_BLOB *pKey;
	SIGNER_PARAMS signerParams;
	VLT_U32 u32SignedLen = 0;
	VLT_U8 *pu8Mac;

	/*
	* Check the input pointer is valid
	*/
	if( NULL == pCmd )
	{
		return ESCP03ADDMACNULLPARAM;
	}

	/*
	* Check that a valid mode has been selected
	*/
	if( CALC_RMAC < u8MacMode )
	{
		return ESCP03CALCMACINVLDMODE;
	}

	if( CALC_CMAC == u8MacMode)
	{
		pu8Mac = &au8CMac[0];
		pKey = &theCMacKey;
	}
	else
	{
		pu8Mac = &au8RMac[0];
		pKey = &theRMacKey;
	}

	/*
	* Setup the Signer Paramters
	*/
	signerParams.enAlgoID = VLT_ALG_SIG_CMAC_AES;
	signerParams.pIV = &au8AesIV[0];
	signerParams.ivSize = AES_INIT_VECT_LEN;
	signerParams.enPaddingScheme = VLT_PADDING_ISO9797_METHOD2;

	/*
	* Initialise the Signer
	*/
	status = SymmetricSignerInit( VLT_SIGN_MODE, pKey, (VLT_U8 *)((void*)&signerParams) );
	if(VLT_OK == status)
	{
		if(u8MacMode == CALC_CMAC)
		{
			/*
			* Update the P3 value to include the C-MAC length
			*/
			if( VLT_HEADER_SIZE == pCmd->u16Len )
			{
				/*
				* If only the header bytes are present make the P3 value
				* equal to the length of the CMAC
				*/
				pCmd->pu8Data[VLT_APDU_P3_OFFSET] = SCP03_CMAC_RMAC_LEN;
			}
			else
			{
				/*
				* Further data is present so adjust the P3 value to add
				* the length of the CMAC to the current P3 value
				*/
				pCmd->pu8Data[VLT_APDU_P3_OFFSET] += SCP03_CMAC_RMAC_LEN;
			}
		}
		/*
		* Use the previous CMAC as the chaining value.
		*/
		status = SymmetricSignerUpdate( &au8CMac[0],
			AES_CMAC_LEN,
			AES_CMAC_LEN );
	}

	if( VLT_OK == status)
	{
		/*
		* Calculate the MAC
		*/
		status = SymmetricSignerDoFinal( &(pCmd->pu8Data[0]),
			pCmd->u16Len,
			pCmd->u16Capacity,
			pu8Mac,
			&u32SignedLen,
			AES_CMAC_LEN);
	}

	return( status );
}

static VLT_STS EncryptCommandData( VLT_MEM_BLOB *pCmd)
{
	VLT_STS status;
	VLT_CIPHER_PARAMS cipherParams = {0};
	VLT_U32 u32DataLen = 0;
	VLT_U8 au8IV[AES_INIT_VECT_LEN];

	/*
	* Check that we have been passed a valid command
	*/
	if( NULL == pCmd )
	{
		return ESCP03ENCCMDDATANULLPARAM;
	}

	/*
	* Zero the Initialisation Vector
	*/
	(void)host_memset( &au8IV[0], 0x00, AES_INIT_VECT_LEN );

	/*
	* Setup the Cipher Parameters 
	*/
	cipherParams.enAlgoID = VLT_ALG_CIP_AES;
	cipherParams.enChainMode = VLT_BLOCK_MODE_CBC;
	cipherParams.pIV = &au8IV[0];
	cipherParams.enPaddingScheme = VLT_PADDING_ISO9797_METHOD2;

	/*
	* Initialise the cipher with the appropriate key and parameters
	*/
	status = CipherInit( VLT_ENCRYPT_MODE, &theCEncKey, &cipherParams);

	if(VLT_OK == status)
	{
		/*
		* Encrpyt the data portion of the command.  Data Length is the P3 value
		* is the length of  a C-Mac which has already been added
		*/
		status = CipherDoFinal( &(pCmd->pu8Data[VLT_APDU_DATA_OFFSET]),
			((VLT_U32)pCmd->u16Len) - VLT_HEADER_SIZE,
			VLT_MAX_APDU_SND_DATA_SZ,
			&(pCmd->pu8Data[VLT_APDU_DATA_OFFSET]),
			&u32DataLen,
			VLT_MAX_APDU_SND_DATA_SZ );

		if( VLT_OK == status )
		{
			/*
			* Update the P3 to include the length of the C-Enc
			* Need to cast as the return is a VLT_U32 and P3 is VLT_U8
			*/
			pCmd->pu8Data[VLT_APDU_P3_OFFSET] = (VLT_U8)u32DataLen;

			pCmd->u16Len = ((VLT_U16)pCmd->pu8Data[VLT_APDU_P3_OFFSET]) + VLT_HEADER_SIZE;
		}
	}

	/*
	* Close the Cipher
	*/
	if(VLT_OK != status)
	{
		(void)CipherClose();
	}
	else
	{
		status = CipherClose();
	}

	return ( status );
}

static VLT_STS DecryptResponseData( VLT_MEM_BLOB *pRsp)
{
	VLT_STS status;
	VLT_CIPHER_PARAMS cipherParams = {0};
	VLT_U32 u32DataLen = 0;
	VLT_U8 au8IV[AES_INIT_VECT_LEN];

	/*
	* Check that we have been passed a valid response
	*/
	if( NULL == pRsp )
	{
		return ESCP03DECCMDDATANULLPARAM;
	}

	/*
	* Zero the Initialisation Vector
	*/
	(void)host_memset( &au8IV[0], 0x00, AES_INIT_VECT_LEN );

	/*
	* Setup the Cipher Parameters
	*/
	cipherParams.enAlgoID = VLT_ALG_CIP_AES;
	cipherParams.enChainMode = VLT_BLOCK_MODE_CBC;
	cipherParams.pIV = &au8IV[0];
	cipherParams.enPaddingScheme = VLT_PADDING_ISO9797_METHOD2;

	/*
	* Initialise the cipher with the appropriate key and parameters
	*/
	status = CipherInit( VLT_DECRYPT_MODE, &theCEncKey, &cipherParams);

	if(VLT_OK == status)
	{
		/*
		* Decrpyt the data portion of the command.  If channel has encrypted
		* data there will be a R-MAC at the end of it so don't include that
		* in the decryption
		*/
		status = CipherDoFinal( &(pRsp->pu8Data[0]),
			((VLT_U32)pRsp->u16Len) - VLT_SW_SIZE,
			VLT_MAX_APDU_RCV_DATA_SZ,
			&(pRsp->pu8Data[0]),
			&u32DataLen,
			VLT_MAX_APDU_SND_DATA_SZ );

		if( VLT_OK == status )
		{
			/*
			* Update the length of the buffer to reflect the decryption
			* Need to cast as the return is a VLT_U32 and P3 is VLT_U8
			*/
			pRsp->u16Len = (VLT_U8)u32DataLen;
		}
	}

	/*
	* Close the Cipher
	*/
	if(VLT_OK != status)
	{
		(void)CipherClose();
	}
	else
	{
		status = CipherClose();
	}

	return ( status );
}

#endif /* ( VLT_ENABLE_SCP03 == VLT_ENABLE ) */
