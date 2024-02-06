/**
* @file	   vaultic_scp_utils.c
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
* @brief   Utils for SCP authentication.
*
* @details 
*
* @date    24/01/2017
* @author  fmauraton
*/

#include "vaultic_common.h"
#if ( VLT_ENABLE_SCP03 == VLT_ENABLE)
#include "vaultic_apdu.h"
#include "vaultic_cipher.h"
#include "vaultic_symmetric_signer.h"
#include "vaultic_secure_channel.h"
#include "vaultic_mem.h"
#include "vaultic_scp_utils.h"





VLT_STS CalculateMac( VLT_MEM_BLOB *pCmd, VLT_U8 u8MacMode )
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
				pCmd->pu8Data[VLT_APDU_P3_OFFSET] = SCPUTILS_CMAC_RMAC_LEN;
			}
			else
			{
				/*
				* Further data is present so adjust the P3 value to add
				* the length of the CMAC to the current P3 value
				*/
				pCmd->pu8Data[VLT_APDU_P3_OFFSET] += SCPUTILS_CMAC_RMAC_LEN;
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

VLT_STS EncryptCommandData( VLT_MEM_BLOB * pCmd)
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

VLT_STS DecryptResponseData( VLT_MEM_BLOB * pRsp)
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

#endif
