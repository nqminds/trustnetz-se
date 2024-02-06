/**
* @file	   vaultic_structs.h
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
 * @brief   VaultIC API structures definition
 */

/**
 * @defgroup Structures Commonly used API structures
 * @brief Structures used by the VaultIC API.
 *
 * @par Description:
 * A collection of structures used to specify values to the VaultIC API.
 */

 /** @{*/


#ifndef VAULTIC_STRUCTS_H
#define VAULTIC_STRUCTS_H

#include "vaultic_config.h"
#include "vaultic_typedefs.h"

#if(VLT_ENABLE_ISO7816 == VLT_ENABLE )
#if (VLT_PLATFORM != VLT_WINDOWS)
#include <PCSC/wintypes.h>
#include <PCSC/pcsclite.h>
#include <PCSC/winscard.h>
#endif
#endif

/* --------------------------------------------------------------------------
 * API COMM INITIALISATION STRUCTURES
 * -------------------------------------------------------------------------- */

#if(VLT_ENABLE_TWI == VLT_ENABLE )
/**
 *  \brief  Specific TWI Comms parameters
 */
typedef struct
{
    /** \brief The TWI bit rate in kbits */
    VLT_U16 u16BitRate;

    /** \brief The TWI address value */
    VLT_U8 u8Address;

    #if (VLT_ENABLE_WISEBOARD == VLT_ENABLE)
    /** \brief The name of the detected wiseboard */
    VLT_U8 *pu8WiseboardName;
    #endif

} VLT_TWI_PARAMS;
#endif

#if(VLT_ENABLE_SPI == VLT_ENABLE)
/**
*   \brief  Specific SPI Comms parameters,
*/
typedef struct
{
    /** \brief The SPI bit rate value specified in kbits.*/
    VLT_U16 u16BitRate;

    #if (VLT_ENABLE_WISEBOARD == VLT_ENABLE)
    /** \brief The name of the detected wiseboard */
    VLT_U8 *pu8WiseboardName;
    #endif

} VLT_SPI_PARAMS;
#endif

#if(VLT_ENABLE_ISO7816 == VLT_ENABLE )
/**
 *  \brief  Specific PCSC comms parameters,
 * particularly applicable to ISO7816 T0 and T1
 */
typedef struct
{
    /**
     * String descriptor of the ISO 7816 card reader
     * attached to the host.
     */
    VLT_U8 *pu8ReaderString;

    /* VaultIC smart card Handle */
    SCARDHANDLE hCard;

    /* PC/SC system handle */
    SCARDCONTEXT hContext;

    VLT_U32 u32Protocol;

} VLT_PCSC_PARAMS;
#endif

#if(VLT_ENABLE_BLOCK_PROTOCOL == VLT_ENABLE )
/**
*   \brief  Specific Block Protocol communication parameters
*/
typedef struct
{
    /** \brief The timeout for a response, in milliseconds */
    VLT_U32 u32msTimeout;

    /** \brief Self Test Delay.  The number of milliseconds to wait for
        * allowing communications with the VaultIC to allow the self tests
        * to complete.
        */
    VLT_U16 u16msSelfTestDelay;

} VLT_BLOCK_PTCL_PARAMS;
#endif

/**
 *  \brief  Comms layer parameters.
 */
typedef struct
{
    /** \brief Communication mode */
    VLT_COMM_MODE enCommsProtocol;

#if(VLT_ENABLE_BLOCK_PROTOCOL == VLT_ENABLE )
    /** \brief Block Protocol parameters */
    VLT_BLOCK_PTCL_PARAMS VltBlockProtocolParams;
#endif

#if(VLT_ENABLE_SPI == VLT_ENABLE)
    /** \brief SPI parameters */
    VLT_SPI_PARAMS VltSpiParams;
#endif

#if(VLT_ENABLE_TWI == VLT_ENABLE)
    /** \brief TWI parameters */
    VLT_TWI_PARAMS VltTwiParams;
#endif

#if (VLT_PLATFORM == VLT_WINDOWS)
    /** \brief Selected Communication Interface */
    COMM_INTERFACE_T VltInterface;
#endif

} VLT_INIT_COMMS_PARAMS;


/* --------------------------------------------------------------------------
 * INITIALIZE UPDATE STRUCTURES
 * -------------------------------------------------------------------------- */

#if (VLT_ENABLE_SCP03 == VLT_ENABLE)
/**
 *  \brief  SCP03 response data from VltInitializeUpdate.
 */
typedef struct
{
    /** \brief The Device Serial Number of length #VLT_CHIP_SERIAL_NUMBER_LENGTH */
    VLT_U8 au8SerialNumber[VLT_CHIP_SERIAL_NUMBER_LENGTH];

    /** \brief The Keyset index */
    VLT_U8 u8KeySetIndex;

    /** \brief The SCP identifier */
    VLT_U8 u8ScpID;

    /** \brief The Device challenge Cd, of length #VLT_SCP03_DEVICE_CHALLENGE_LENGTH */
    VLT_U8 u8DeviceChallenge[VLT_SCP03_DEVICE_CHALLENGE_LENGTH];

    /** \brief The Device authentication cryptogram ACd, of length #VLT_SCPXX_CRYPTOGRAM_LENGTH */
    VLT_U8 u8Cryptogram[VLT_SCPXX_CRYPTOGRAM_LENGTH];

} VLT_INIT_UPDATE_SCP03;
#endif


/**
 *  \brief  Response data from VltInitializeUpdate.
 */
#if ((VLT_ENABLE_API_INITIALIZE_UPDATE == VLT_ENABLE) && (VLT_ENABLE_SCP03== VLT_ENABLE))
typedef struct
{
    /** \brief Login method */
    VLT_AUTH_ID enLoginMethodID;

    union
    {
#if (VLT_ENABLE_SCP03 == VLT_ENABLE)
        /** \brief The Scp03 response specialisation */
        VLT_INIT_UPDATE_SCP03 Scp03;
#endif
    }
    data;

} VLT_INIT_UPDATE;
#endif

#if( VLT_ENABLE_SIGN_xDSA == VLT_ENABLE)
/**
*   \brief  An ECDSA public key object.
*/
typedef struct
{
    /** \brief length of EC prime in bytes. */
    VLT_U16 u16QLen;

    /** \brief public key X co-ordinate */
    VLT_U8 *pu8Qx;

    /** \brief public key Y co-ordinate */
    VLT_U8 *pu8Qy;

} VLT_ECDSA_PUBLIC_KEY;


/**
*   \brief  An ECDSA private key object.
*/
typedef struct
{
    /** \brief Length of EC prime in bytes. */
    VLT_U16 u16DLen;

    /** \brief  EC private key d. */
    VLT_U8 *pu8D;

} VLT_ECDSA_PRIVATE_KEY;
#endif

/* --------------------------------------------------------------------------
 * MANAGE AUTHENTICATION STRUCTURES
 * -------------------------------------------------------------------------- */

/**
 *  \brief  A key structure.
 */
typedef struct
{
    /** \brief Key ID */
    VLT_KEY_ID  enKeyID;

    /** \brief Masking byte */
    VLT_U8  u8Mask;

    /** \brief Length of the key, in bytes */
    VLT_U16 u16KeyLength;

    /** \brief The key itself */
    VLT_U8 *pu8Key;

} VLT_KEY;


/** \brief The specialised password based authentication data. */
typedef struct
{
    /** \brief Cleartext password length (4 to 32) */
    VLT_U8 u8PasswordLength;

    /** \brief Cleartext password */
    VLT_U8 u8Password[32];

} VLT_AUTH_DATA_PWD;


/** \brief The specialised secret key based authentication data. */
typedef struct
{
    /** \brief Number of secret keys specified (1 or 2) */
    VLT_U8  u8NumberOfKeys;

    /** \brief Secret keys */
    VLT_KEY aKeys[2];

} VLT_AUTH_DATA_SECRET;

/** \brief The specialised secret key based authentication data. */
typedef struct
{
    /** \brief Length of the password */
    VLT_U8  u8PasswordLength;

    /** \brief Password value*/
    VLT_U8 * pu8Password;

    /** \brief AES Secret key object*/
    VLT_KEY aesKey;

} VLT_AUTH_DATA_SECURE_PWD;

#if (VLT_ENABLE_API_MANAGE_AUTHENTICATION_DATA == VLT_ENABLE)
/**
 *
 * \brief Authentication data for VltManageAuthenticationData.
 *
 * This is specified when an operator is created or updated.
 */
typedef struct
{
    /** \brief Login method ID */
    VLT_AUTH_ID enMethod;

    /** \brief Operator ID */
    VLT_USER_ID enUserID;

    /** \brief Operator role ID */
    VLT_ROLE_ID enRoleID;

    /** \brief User operation ID */
    VLT_USER_OP_ID enOperationID;

    /** \brief  Minimum security level required for SCP secure channel */
    VLT_SEC_LEVEL_ID enChannelLevel;

    /** \brief Security option */
    VLT_SEC_OPTION enSecurityOption;

    /** \brief Maximum allowed consecutive authentication failures (1 to 127) */
    VLT_U8 u8TryCount;

    union
    {
        /** \brief Password based authentication data. */
        VLT_AUTH_DATA_PWD password;

        /** \brief Secret key based authentication data. */
        VLT_AUTH_DATA_SECRET secret;

        /** \brief Password based authentication data. */
        VLT_AUTH_DATA_SECURE_PWD secPassword;
    }
    data;

} VLT_MANAGE_AUTH_DATA;
#endif

/* --------------------------------------------------------------------------
 * GET AUTHENTICATION INFO STRUCTURES
 * -------------------------------------------------------------------------- */
#if (VLT_ENABLE_API_GET_AUTHENTICATION_INFO == VLT_ENABLE)
/**
 *  \brief  Authentication info response from VltGetInfo.
 */
 typedef struct
{
    /** \brief Authentication method identifier - 0xFF if the operator is not defined. */
    VLT_AUTH_ID  enAuthMethod;

    /** \brief Bit-field combination of #VLT_ROLE_ID roles assumed by the operator */
    VLT_U8  u8Roles;

    /** \brief Minimum security level required for SCP secure channel. Returns zero for non SCP authentication methods. */
    VLT_SEC_LEVEL_ID  enMinSecurityLevel;

    /** \brief Remaining allowed consecutive authentication failures */
    VLT_U8  u8RemainingTryCount;

    /** \brief Maximum allowed consecutive authentication failures */
    VLT_U8  u8MaxTries;

    /** \brief Sequence counter*/
    VLT_U16 u16SequenceCount;

} VLT_AUTH_INFO;
#endif
/* --------------------------------------------------------------------------
 * GENERIC STRONG AUTHENTICATION STRUCTURES
 * -------------------------------------------------------------------------- */

/**
 * \brief Generic Strong Authentication parameters
   (used by VltGenericInternalAuthenticate and VltGetChallenge)
 */
 typedef struct
{
    /** \brief Challenge size for authentication protocols.
     *  8 bytes recommended, 64 bytes maximum. */
    VLT_U8  u8ChallengeSize;

    /** \brief bOption field, possible values are:
     *  - #VLT_GEN_AUTH_DO_NOT_USE_IDENTIFIERS
     *  - #VLT_GEN_AUTH_USE_IDENTIFIERS
     */
    VLT_U8  u8Option;

    /** \brief Device identifier group */
    VLT_U8 u8DeviceIdGroup;

    /** \brief Device identifier index */
    VLT_U8 u8DeviceIdIndex;

    /** \brief Host identifier group */
    VLT_U8 u8HostIdGroup;

    /** \brief Host identifier index */
    VLT_U8 u8HostIdIndex;

} VLT_GENERIC_AUTH_SETUP_DATA;


/* --------------------------------------------------------------------------
 * INITIALIZE ALGORITHM PARAMETERS STRUCTURES
 * -------------------------------------------------------------------------- */
#if( VLT_ENABLE_CIPHER_AES == VLT_ENABLE )
/**
 *  \brief  Symmetric Cipher parameters.
 */
 typedef struct
{
    /** \brief Chaining mode identifier */
     VLT_BLOCK_MODE_ID enMode;

     /** \brief Padding mehod identifier */
     VLT_PADDING_ID enPadding;

    /** \brief Length of initial vector */
    VLT_U8 u8IvLength;

    /** \brief Initial vector, unused in ECB mode */
    VLT_U8 u8Iv[VLT_MAX_IV_LENGTH];

} VLT_ALG_OBJ_SYM_CIPHER;
#endif

#if (VLT_ENABLE_CIPHER_AES_GCM == VLT_ENABLE)
 /**
 *  \brief  GCM Cipher parameters.
 */
 typedef struct
{
    /** \brief Underlying Cipher engine (#VLT_ALG_CIP_AES) */
     VLT_ALG_CIP_ID enCipher;

    /** \brief Size of signature TAG (in nb of bytes), Min = 12, Max = 16 */
    VLT_U8 u8TagLen;

    /** \brief Initial vector Length (must be 0 or 12 bytes) for VAULTIC_405_1_X_X, NULL otherwise */
    VLT_U8 *pu8IvLen;

    /** \brief Initial vector value */
    VLT_U8 *pu8Iv;

    /** \brief Additional Data Length (in nb of bytes, Big Endian), Min = 0, Max = 512  */
    VLT_U16 u16AddDataLen;

    /** \brief AAD String, optional field  */
    VLT_U8 *pu8AddData;

} VLT_ALG_OBJ_GCM;
#endif

#if (VLT_ENABLE_SIGN_GMAC == VLT_ENABLE)
/**
 *  \brief  GMAC Signer parameters.
 */
 typedef struct
{
    /** \brief  Underlying Cipher engine (#VLT_ALG_CIP_AES) */
    VLT_ALG_CIP_ID enCipher;

    /** \brief  Size of signature TAG (in nb of bytes), Min = 12, Max = 16 */
    VLT_U8 u8TagLen;

    /** \brief  Initial vector Length (must be 0 or 12 bytes) for VAULTIC_405_1_X_X, NULL otherwise */
    VLT_U8 *pu8IvLen;

    /** \brief  Initial vector value */
    VLT_U8 *pu8Iv;

} VLT_ALG_OBJ_GMAC;
#endif

#if (VLT_ENABLE_SIGN_CMAC == VLT_ENABLE)
 /**
 *  \brief  CMAC Signer parameters.
 */
typedef struct
{
    /** \brief  Padding mode */
    VLT_PADDING_ID enPadding;

    /** \brief  Length of initial vector */
    VLT_U8 u8IvLength;

    /** \brief  Initial vector, unused by ECB mode */
    VLT_U8 u8Iv[VLT_MAX_IV_LENGTH];

} VLT_ALG_OBJ_CMAC;
#endif

#if (VLT_ENABLE_SIGN_HMAC == VLT_ENABLE)
/**
 *  \brief  HMAC Signer parameters.
 */
typedef struct
{
    /** \brief  Digest identifier */
    VLT_ALG_DIG_ID enDigestId;

    /** \brief  Truncated HMAC output size, in bytes  */
    VLT_U8 u8Output;

} VLT_ALG_OBJ_HMAC;
#endif

#if (VLT_ENABLE_KEY_HOTP == VLT_ENABLE) || (VLT_ENABLE_KEY_TOTP == VLT_ENABLE)
/**
 * \brief OTP parameters.
 */
typedef struct
{
    /** \brief  Required number of digits (6+)  */
    VLT_U8 u8Output;

} VLT_ALG_OBJ_OTP;
#endif

#if( VLT_ENABLE_CIPHER_RSA == VLT_ENABLE)
/**
 * \brief RSAES_PKCS_OAEP cipher parameters.
 */
typedef struct
{
    /** \brief  Digest identifier */
    VLT_ALG_DIG_ID enDigestIdOaep;

    /** \brief  Digest identifier applied during MGF1 masking.
     * We recommended keeping it the same as the OAEP digest. */
    VLT_ALG_DIG_ID enDigestIdMgf1;

    /** \brief  Label length. If zero, no label is used. */
    VLT_U16 u16LLen;

    /** \brief  Label */
    VLT_U8 *pu8Label;

} VLT_ALG_OBJ_RSAES_OAEP;
#endif

#if( VLT_ENABLE_SIGN_RSA == VLT_ENABLE)
/**
 * \brief RSASSA_PKCS_PSS signer parameters.
 */
typedef struct
{
    /** \brief  Digest algorithm applied to the input message and during PSS encoding */
    VLT_ALG_DIG_ID enDigestIdPss;

    /** \brief  Digest identifier applied during MGF1 masking.
     * We recommended keeping it the same as the PSS digest. */
    VLT_ALG_DIG_ID enDigestIdMgf1;

    /** \brief Salt length. Must be in the range 0 to u8DigestPss output length. */
    VLT_U8 u8SaltLength;

} VLT_ALG_OBJ_RSASSA_PSS;


/**
 * \brief RSASSA_PKCS signer parameters.
 */
typedef struct
{
    /** \brief  Digest algorithm applied to the input message */
    VLT_ALG_DIG_ID enDigestId;

} VLT_ALG_OBJ_RSASSA_PKCS;
#endif

#if( VLT_ENABLE_SIGN_xDSA == VLT_ENABLE)
/**
 *  \brief  DSA and ECDSA signer parameters.
 */
typedef struct
{
    /** \brief  Digest algorithm applied to the input message */
    VLT_ALG_DIG_ID enDigestId;

} VLT_ALG_OBJ_ECDSA_DSA;
#endif

#if( VLT_ENABLE_API_CONSTRUCT_AGREEMENT == VLT_ENABLE)

/**
 * \brief Key agreement parameters (Static Unified) .
 */
typedef struct
{
    /** \brief  Static initiator ECDH public key object group */
    VLT_U8 u8InitiatorPubKeyGroup;

    /** \brief  Static initiator ECDH public key object index */
    VLT_U8 u8InitiatorPubKeyIndex;

} VLT_ALG_OBJ_KAS_STATIC_UNIFIED;


#if (VAULT_IC_VERSION != VAULTIC_420_1_2_X)
/**
* \brief Key agreement parameters (One Pass) .
 */
typedef struct {
    /** \brief  Ephemeral initiator ECDH public key object group */
    VLT_U8 u8PubKeyGroup;

    /** \brief  Ephemeral initiator ECDH public key object index */
    VLT_U8 u8PubKeyIndex;

} VLT_ALG_OBJ_KAS_ONEPASS;
#else
/**
 * \brief  Establish Key material parameters.
 */
typedef struct
{
    /** \brief  Public Key object length, MSB first	*/
    VLT_U16 u8KLen;

    /** \brief  Ephemeral initiator ECDH public key object */
    VLT_U8 *pu8keyObject;

} VLT_ALG_OBJ_KAS_ONEPASS;
#endif
#endif

#if( VLT_ENABLE_API_INITIALIZE_ALGORITHM == VLT_ENABLE )
/**
 * \brief Algorithm parameters
 * (used by VltInitializeAlgorithm)
 */
typedef struct
{
    /** \brief Algorithm identifier
        \details  Depending on enAlgoMode , either:
     - Cipher identifier among #VLT_ALG_CIP_ID \n
     - Signer identifier among #VLT_ALG_SIG_ID \n
     - Digest identifier among #VLT_ALG_DIG_ID \n
     - Key Transport Scheme identifier among #VLT_ALG_KTS_ID

      Empty for enAlgoMode = #VLT_RESET_MODE*/
    VLT_U8 u8AlgoID;

    union
    {
#if( VLT_ENABLE_CIPHER_AES == VLT_ENABLE )
        /** \brief Symmetric Cipher parameters */
        VLT_ALG_OBJ_SYM_CIPHER  SymCipher;
#endif

#if( VLT_ENABLE_CIPHER_AES_GCM == VLT_ENABLE)
        /** \brief GCM parameters */
        VLT_ALG_OBJ_GCM         Gcm;
#endif

#if( VLT_ENABLE_SIGN_GMAC == VLT_ENABLE)
        /** \brief GMAC parameters */
        VLT_ALG_OBJ_GMAC        Gmac;
#endif

#if( VLT_ENABLE_SIGN_CMAC == VLT_ENABLE)
        /** \brief CMAC parameters */
        VLT_ALG_OBJ_CMAC        Cmac;
#endif

#if( VLT_ENABLE_SIGN_HMAC == VLT_ENABLE)
        /** \brief HMAC parameters */
        VLT_ALG_OBJ_HMAC        Hmac;
#endif

#if (VLT_ENABLE_KEY_HOTP == VLT_ENABLE) || (VLT_ENABLE_KEY_TOTP == VLT_ENABLE)
        /** \brief OTP parameters */
        VLT_ALG_OBJ_OTP         Otp;
#endif

#if( VLT_ENABLE_CIPHER_RSA == VLT_ENABLE)
        /** \brief RSAES OAEP parameters */
        VLT_ALG_OBJ_RSAES_OAEP  RsaesOaep;
#endif

#if( VLT_ENABLE_SIGN_RSA == VLT_ENABLE)
        /** \brief RSASSA PSS parameters */
        VLT_ALG_OBJ_RSASSA_PSS  RsassaPss;

        /** \brief RSASSA PKCS parameters */
        VLT_ALG_OBJ_RSASSA_PKCS RsassaPkcs;
#endif

#if( VLT_ENABLE_SIGN_xDSA == VLT_ENABLE)
        /** \brief ECDSA DSA parameters */
        VLT_ALG_OBJ_ECDSA_DSA   EcdsaDsa;
#endif

    }
    data;
} VLT_ALGO_PARAMS;
#endif

#if( VLT_ENABLE_API_CONSTRUCT_AGREEMENT == VLT_ENABLE)
/**
 * \brief Algorithm parameters
 * (used by VltConstructDHAgreement)
 */
typedef struct
{
    /** \brief Key agreement Scheme Algorithm identifier */
    VLT_ALG_KAS_ID enAlgoID;

    union
    {
        /** \brief Key agreement parameters (Static Unified) */
        VLT_ALG_OBJ_KAS_STATIC_UNIFIED staticUnified;

        /** \brief Key agreement parameters (One Pass) */
        VLT_ALG_OBJ_KAS_ONEPASS    onePass;
    }
    data;

    /** \brief Private key group */
    VLT_U8 u8StaticResponderPrivKeyGroup;

    /** \brief Private key index */
    VLT_U8 u8StaticResponderPrivKeyIndex;	/** \brief   Static key parameter file index. */

} VLT_KEY_MATERIAL;
#endif

#if( VLT_ENABLE_API_DERIVE_KEY == VLT_ENABLE)
/**
 * \brief Key derivation response
 * (used by VltDeriveKey)
 */
typedef struct
{
    /** \brief Nonce buffer */
    VLT_U8 pu8NonceV[VLT_DERIVE_KEY_NONCE_MAX_LEN];

    /** \brief Nonce length */
    VLT_U16 u16NonceVLen;

    /** \brief Mac Tag buffer */
    VLT_U8 pu8MacTag[VLT_DERIVE_KEY_MACTAG_MAX_LEN];

    /** \brief Mac Tag length */
    VLT_U16 u16MacTagLen;

    /** \brief Selected MacKey length */
    VLT_U16 u16MacKeyLen;

} VLT_KEY_DERIVATION_RESP;
#endif

#if( VLT_ENABLE_API_KEY_CONFIRMATION == VLT_ENABLE)
/**
 * \brief Mac Tag object
  * (used by VltKeyConfirmation)
 */
typedef struct
{
    /** \brief Mac Tag Object length, MSB first. Maximum size is 64 bytes */
    VLT_U16 u16wTLen;

    /** \brief Mac Tag Value */
    VLT_U8 *pu8MacTagValue;

} VLT_MAC_TAG;
#endif

#if( VLT_ENABLE_API_DERIVE_KEY == VLT_ENABLE)
/**
 * \brief  KDF Concatenate parameters.
 */
typedef struct
{
    /** \brief  Digest algorithm identifier applied during KDF */
    VLT_ALG_DIG_ID enDigestId;

    /** \brief  Length of AlgoId field */
    VLT_U16 u16algoIdLen;

    /** \brief  String that identifies the AlgoId */
    VLT_U8 *pu8algoId;

    /** \brief  Length of sUInfo field */
    VLT_U16 u16UInfoLen;

    /** \brief  String that identifies the initiator U */
    VLT_U8 *pu8UInfo;

    /** \brief  Length of sVInfo field */
    VLT_U16 u16VInfoLen;

    /** \brief  String that identifies the responder V */
    VLT_U8 *pu8VInfo;

    /** \brief  Length of SuppPubInfo field */
    VLT_U16 u16suppPubInfoLen;

    /** \brief  A bit string containing additional, mutually-known public information */
    VLT_U8 *pu8suppPubInfo;

    /** \brief  Length of sVInfo field */
    VLT_U16 u16suppPrivInfoLen;

    /** \brief  A bit string containing additional, mutually-known public information */
    VLT_U8 *pu8suppPrivInfo;

    /** \brief  Length of nonceU field */
    VLT_U16 u16nonceULen;

    /** \brief  A bit string containing nonceU */
    VLT_U8 *pu8nonceU;

} VLT_ALG_OBJ_KDF_CONCATENATION;

#ifdef VLT_ALG_KDF_COUNTER_MODE
/**
 * \brief  KDF Counter parameters.
 */
typedef struct
{
    /** \brief  Approved Pseudo Random Function PRF_ identifier applied during KDF */
    VLT_U8 u8PRF;

    /** \brief  Length of sInfo field */
    VLT_U16 u16wContextLen;

    /** \brief  String that identifies the initiator U */
    VLT_U8 *pu8sContext;

    /** \brief  Length of sLabel field */
    VLT_U16 u16wLabelLen;

    /** \brief  String that identifies the purpose for the derived keying material */
    VLT_U8 *pu8sLabel;

} VLT_ALG_OBJ_KDF_COUNTER_MODE;
#endif


/**
 * \brief  KDF Hash parameters.
 */
typedef struct
{
    /** \brief  Digest algorithm identifier applied during KDF */
    VLT_ALG_DIG_ID enDigestId;

    /** \brief  Prepend data length */
    VLT_U16 u16prependLen;

    /** \brief  Pointer to a value to add to the beginning of the message input to the hash function */
    VLT_U8 *pu8prependData;

    /** \brief  Append data length */
    VLT_U16 u16appendLen;

    /** \brief  Pointer to a value to add to the end of the message input to the hash function */
    VLT_U8 *pu8appendData;

} VLT_ALG_OBJ_KDF_HASH_MODE;


/**
 * \brief Key Derivation Algorithm parameters
 * (used by VltDeriveKey)
 */
typedef struct
{
    /** \brief Key Derivation Algorithm identifier */
     VLT_ALG_KDF_ID enAlgoID;

     union
     {
         /** \brief KDF Concatenate parameters */
         VLT_ALG_OBJ_KDF_CONCATENATION      concatenation_SP800_56A;

         #ifdef VLT_ALG_KDF_COUNTER_MODE
         /** \brief KDF Counter Mode parameters */
         VLT_ALG_OBJ_KDF_COUNTER_MODE       counterMode_SP800_108;
#endif
         /** \brief KDF Hash Mode parameters */
         VLT_ALG_OBJ_KDF_HASH_MODE          hashMode;
     }
     data;

     /** \brief Secret key group */
     VLT_U8 u8SecretKeyGroup;

     /** \brief Secret key index */
     VLT_U8 u8SecretKeyIndex;

} VLT_KEY_DERIVATION;
#endif

/* --------------------------------------------------------------------------
 * KEY OBJECT STRUCTURES
 * -------------------------------------------------------------------------- */
/**
 * \brief A raw key object format (e.g. all keys ).
 */
typedef struct
{
    /** \brief   Key object value. */
    VLT_U8 *pu8KeyObject;
    /** \brief   Key object value CRC. */
    VLT_U16 u16Crc;
    /** \brief   true if key object is encrypted. */
    VLT_BOOL isEncryptedKey;
    /** \brief   Clear key object length in bytes. */
    VLT_U16 *pu16ClearKeyObjectLen;
    /** \brief   Encrypted key object length in bytes. */
    VLT_U16 *pu16EncKeyObjectLen;
} VLT_KEY_OBJ_RAW;

#if( VLT_ENABLE_KEY_SECRET == VLT_ENABLE )
/**
 * \brief A secret key object (e.g. AES, HMAC).
 */
typedef struct
{
    /** \brief   Mask value. Zero if masking is not required. */
    VLT_U8  u8Mask;

    /** \brief  Secret key length in bytes. */
    VLT_U16 u16KeyLength;

    /** \brief  Secret key value. */
    VLT_U8 *pu8Key;

} VLT_KEY_OBJ_SECRET;
#endif

#if( VLT_ENABLE_KEY_HOTP == VLT_ENABLE )
/**
 * \brief An HOTP key object.
 */
typedef struct
{
    /** \brief  Mask value. Zero if masking is not required. */
    VLT_U8  u8Mask;

    /** \brief  Secret key length in bytes. */
    VLT_U16 u16KeyLength;

    /** \brief  HMAC-SHA-1 key value. */
    VLT_U8 *pu8Key;

    /** \brief  Moving factor - 8 byte counter value. */
    VLT_U8 *pu8MovingFactor;

} VLT_KEY_OBJ_HOTP;
#endif

#if( VLT_ENABLE_KEY_TOTP == VLT_ENABLE )
/**
 * \brief An TOTP key object.
 */
typedef struct
{
    /** \brief   Mask value. Zero if masking is not required. */
    VLT_U8  u8Mask;

    /** \brief   Secret key length in bytes. */
    VLT_U16 u16KeyLength;

    /** \brief   HMAC-SHA-1 key value. */
    VLT_U8 *pu8Key;

} VLT_KEY_OBJ_TOTP;
#endif

#if( VLT_ENABLE_KEY_RSA == VLT_ENABLE )
/**
 * \brief An RSA public key object.
 */
typedef struct
{
    /** \brief   Length of modulus n value in bytes. */
    VLT_U16 u16NLen;

    /** \brief   Modulus n value. */
    VLT_U8 *pu8N;

    /** \brief   Length of public exponent e in bytes. */
    VLT_U16 u16ELen;

    /** \brief   Public exponent e. */
    VLT_U8 *pu8E;

    /** \brief   Assurance method identifier for Public Key Validity. */
    VLT_PKV_ASSURANCE_ID enAssurance;

} VLT_KEY_OBJ_RSA_PUB;


/**
 * \brief An RSA private key object.
 */
typedef struct
{
    /** \brief   Mask value. Zero if masking is not required. */
    VLT_U8  u8Mask;

    /** \brief   Length of modulus n value in bytes. */
    VLT_U16 u16NLen;

    /** \brief   Modulus n value. */
    VLT_U8 *pu8N;

    /** \brief   Length of private exponent d in bytes. */
    VLT_U16 u16DLen;

    /** \brief   Private exponent d. */
    VLT_U8 *pu8D;

    /** \brief   Relevant RSA public key group. */
    VLT_U8 u8PublicKeyGroup;

    /** \brief   Relevant RSA public key file index. */
    VLT_U8 u8PublicKeyIndex;

} VLT_KEY_OBJ_RSA_PRIV;


/**
 * \brief An RSA CRT private key object.
 */
typedef struct
{
    /** \brief   Mask value. Zero if masking is not required. */
    VLT_U8  u8Mask;

    /** \brief   Prime p length in bytes. */
    VLT_U16 u16PLen;

    /** \brief   Prime factor p. */
    VLT_U8 *pu8P;

    /** \brief   Prime factor q. */
    VLT_U8 *pu8Q;

    /** \brief   dp value. */
    VLT_U8 *pu8Dp;

    /** \brief   dq value. */
    VLT_U8 *pu8Dq;

    /** \brief   ip value. */
    VLT_U8 *pu8Ip;

    /** \brief   Relevant RSA public key file group. */
    VLT_U8 u8PublicKeyGroup;

    /** \brief   Relevant RSA public key file index. */
    VLT_U8 u8PublicKeyIndex;

} VLT_KEY_OBJ_RSA_PRIV_CRT;
#endif

#if( VLT_ENABLE_KEY_ECDSA == VLT_ENABLE )
/**
 * \brief An ECDSA public key object.
 */
typedef struct
{
    /** \brief   Length of EC prime in bytes. */
    VLT_U16 u16QLen;

    /** \brief   EC public key Qx. */
    VLT_U8 *pu8Qx;

    /** \brief   EC public key Qy. */
    VLT_U8 *pu8Qy;

    /** \brief   ECC domain parameter file group. */
    VLT_U8 u8DomainParamsGroup;

    /** \brief   ECC domain parameter file index. */
    VLT_U8 u8DomainParamsIndex;

    /** \brief   Assurance method identifier for Public Key Validity. */
    VLT_PKV_ASSURANCE_ID enAssurance;

} VLT_KEY_OBJ_ECDSA_PUB;


/**
 * \brief An ECDSA private key object.
 */
typedef struct
{
    /** \brief   Mask value. Zero if masking is not required. */
    VLT_U8  u8Mask;

    /** \brief   Length of EC prime in bytes. */
    VLT_U16 u16DLen;

    /** \brief   EC private key d. */
    VLT_U8 *pu8D;

    /** \brief   ECC domain parameter file group. */
    VLT_U8 u8DomainParamsGroup;

    /** \brief   ECC domain parameter file index. */
    VLT_U8 u8DomainParamsIndex;

    /** \brief   Relevant ECDSA public key file group. */
    VLT_U8 u8PublicKeyGroup;

    /** \brief   Relevant ecDSA public key file index. */
    VLT_U8 u8PublicKeyIndex;

    /** \brief   Assurance method identifier for Private Key Validity. */
    VLT_PRKV_ASSURANCE_ID enAssurance;

} VLT_KEY_OBJ_ECDSA_PRIV;


/**
 * \brief An ECDSA domain parameters key object.
 */
typedef struct
{
    /** \brief q field size in bytes */
    VLT_U16 u16QLen;

    /** \brief  reduction polynomial (excluding MSB) */
    VLT_U8 *pu8Q;

    /** \brief  Gx - base generator point X co-ordinate*/
    VLT_U8 *pu8Gx;

    /** \brief  Gy - base generator point Y co-ordinate */
    VLT_U8 *pu8Gy;

    /** \brief  Gz - base generator point Z co-ordinate: must be 1 projective co-ordinates are not supported */
    VLT_U8 *pu8Gz;

    /** \brief  a co-efficient of defining curve equation  */
    VLT_U8 *pu8A;

    /** \brief  b co-efficient of defining curve equation */
    VLT_U8 *pu8B;

    /** \brief  base point order length */
    VLT_U16 u16NLen;

    /** \brief  n - base point order: number of points on curve that are multiples of G */
    VLT_U8 *pu8N;

    /** \brief  h co-factor (number of points in field = n * h) */
    VLT_U32 u32H;

    /** \brief Assurance method identifier for Domain Parameters Validity */
    VLT_DPV_ASSURANCE_ID  enAssurance;

} VLT_KEY_OBJ_ECDSA_PARAMS;
#endif

#if( VLT_ENABLE_KEY_IDENTIFIER == VLT_ENABLE )
/**
 * \brief A Host/Device ID key object.
 */
typedef struct
{
    /** \brief   The ID String length*/
    VLT_U16 u16StringLen;

    /** \brief   The ID String */
    VLT_U8 *pu8StringId;

} VLT_KEY_OBJ_ID;
#endif

/**
 * \brief A Generic key Object for use with VltPutKey() or VltReadKey().
 */
typedef struct
{
    /** \brief Key identifier.*/
    VLT_KEY_ID enKeyID;

    union
    {
        /** \brief  Raw Key Object , any type of key can be treated as a raw key */
        VLT_KEY_OBJ_RAW          RawKey;

#if( VLT_ENABLE_KEY_SECRET == VLT_ENABLE )
        /** \brief  Secret Key Object */
        VLT_KEY_OBJ_SECRET       SecretKey;
#endif

#if( VLT_ENABLE_KEY_HOTP == VLT_ENABLE )
        /** \brief  HOTP Key Object */
        VLT_KEY_OBJ_HOTP         HotpKey;
#endif

#if( VLT_ENABLE_KEY_TOTP == VLT_ENABLE )
        /** \brief  TOTP Key Object */
        VLT_KEY_OBJ_TOTP         TotpKey;
#endif

#if( VLT_ENABLE_KEY_RSA == VLT_ENABLE )
        /** \brief  Public RSA Key Object */
        VLT_KEY_OBJ_RSA_PUB      RsaPubKey;

        /** \brief  Private RSA Key Object  */
        VLT_KEY_OBJ_RSA_PRIV     RsaPrivKey;

        /** \brief  Private CRT RSA Key Object */
        VLT_KEY_OBJ_RSA_PRIV_CRT RsaPrivCrtKey;
#endif

#if( VLT_ENABLE_KEY_ECDSA == VLT_ENABLE )
        /** \brief  Public ECDSA Key Object  */
        VLT_KEY_OBJ_ECDSA_PUB    EcdsaPubKey;

        /** \brief  Private ECDSA Key Object */
        VLT_KEY_OBJ_ECDSA_PRIV   EcdsaPrivKey;

        /** \brief  ECDSA Domain Parameters Key Object  */
        VLT_KEY_OBJ_ECDSA_PARAMS EcdsaParamsKey;
#endif

#if( VLT_ENABLE_KEY_IDENTIFIER == VLT_ENABLE )
        /** \brief Host or Device Identifier Key Object */
        VLT_KEY_OBJ_ID IdentifierKey;
#endif
    }
    data;
} VLT_KEY_OBJECT;

#if (VLT_ENABLE_API_GENERATE_ASSURANCE_MESSAGE == VLT_ENABLE)
/* --------------------------------------------------------------------------
 * GENERATE ASSURANCE MESSAGE STRUCTURE
 * --------------------------------------------------------------------------
 */

 /**
  * \brief Assurance Message
    (used by VltGenerateAssuranceMessage)
 */
typedef struct
{
    /** \brief  Verifier ID buffer \n
      *  VLT_GA_VERIFIER_ID_LENGTH defines the required length.
      */
    VLT_U8 * pu8VerifierID;

    /** \brief  Verifier ID Length \n
     * [IN] The host Verifier ID buffer size \n
     * [OUT] The length of the received Verifier ID
     */
    VLT_U8 u8VerifierIdLength;

    /** \brief Assurance Message buffer - VLT_GA_MESSAGE_LENGTH defines the required length. */
    VLT_U8 * pu8AssuranceMessage;

    /** \brief Assurance Message Length \n
     * [IN] The host Assurance Message buffer size \n
     * [OUT] The length of the received Verifier ID
     */
    VLT_U8 u8AssuranceMessageLength;

} VLT_ASSURANCE_MESSAGE;
#endif

#if (VLT_ENABLE_API_GENERATE_KEY_PAIR == VLT_ENABLE)

/* --------------------------------------------------------------------------
 * GENERATE KEY PAIR STRUCTURES
 * --------------------------------------------------------------------------
 */

/**
 *
 * \brief RSA Key Generator parameters.
 */
typedef struct
{
    /** \brief  Key format - 0 for private exponent, or 1 for CRT */
    VLT_U8  u8Option;

    /** \brief  Modulus length, in bytes.
     * Shall be a multiple of 4 bytes. */
    VLT_U16 u16Length;

    /** \brief  Public exponent length, in bytes.
     * Shall be a multiple of 4 bytes. If not pad the exponent value with zero
     * bytes on the MSB side. */
    VLT_U16 u16ELen;

    /** \brief  Public exponent 'e'.
     * An odd positive integer such that 2**16 < e < * 2**256.
     */
    VLT_U8 *pu8e;

} VLT_KEY_GEN_RSA_DATA;


/**
 * \brief DSA or ECDSA Key Generator parameters.
 */
typedef struct
{
    /** \brief  Domain Parameters Group */
    VLT_U8 u8DomainParamsGroup;

    /** \brief  Domain Parameters Index */
    VLT_U8 u8DomainParamsIndex;
} VLT_KEY_GEN_ECDSA_DSA_DATA;


/**
 * \brief Abstract Generate Key Pair parameter structure.
 */
typedef struct
{
    /**\brief   Key pair generator identifier*/
    VLT_ALG_KPG_ID enAlgoID;

    union
    {
        /** \brief The RSA specific Generate Key Pair structure */
        VLT_KEY_GEN_RSA_DATA       RsaKeyGenObj;

        /** \brief The ECDSA/DSA specific Generate Key Pair structure */
        VLT_KEY_GEN_ECDSA_DSA_DATA EcdsaDsaKeyGenObj;
    }
    data;

} VLT_KEY_GEN_DATA;
#endif

/* --------------------------------------------------------------------------
 * FILE PRIVILEGES STRUCTURES
 * -------------------------------------------------------------------------- */

/**
 * \brief File and directory access conditions.
 *
 * At file or directory creation time, permission to perform an operation can be
 * granted to some combination of the defined operators. This structure
 * specifies that combination.
 *
 * Each element of the structure is a bit-field. In the bit-field, bit i, if
 * set, indicates that operator i has been granted that permission.
 */
typedef struct
{
    /** \brief      Read access for files, list access for directories.
        \details    Bitfield representing READ access condition for files or LIST access condition for directories:\n
                    [b7 .. b0]  : b(i) access condition for operator i (e.g. b7 = access condition for operator #7) \n
                    - bi=0 : Operation denied \n
                    - bi=1 : Operation granted */
    VLT_U8 u8Read;

    /** \brief      Write access for files, create access for directories.
        \details    Bitfield representing READ access condition for files or LIST access condition for directories:\n
                    [b7 .. b0]  : b(i) access condition for operator i (e.g. b7 = access condition for operator #7) \n
                    - bi=0 : Operation denied \n
                    - bi=1 : Operation granted */
    VLT_U8 u8Write;

    /** \brief  Delete access for both files and directories.
        \details    Bitfield representing READ access condition for files or LIST access condition for directories:\n
                    [b7 .. b0]  : b(i) access condition for operator i (e.g. b7 = access condition for operator #7) \n
                    - bi=0 : Operation denied \n
                    - bi=1 : Operation granted */
    VLT_U8 u8Delete;

    /** \brief  Execute access for files.
        \note       Shall be set to 00h for directories
        \details    Bitfield representing READ access condition for files or LIST access condition for directories:\n
                    [b7 .. b0]  : b(i) access condition for operator i (e.g. b7 = access condition for operator #7) \n
                    - bi=0 : Operation denied \n
                    - bi=1 : Operation granted */

    VLT_U8 u8Execute;

} VLT_FILE_PRIVILEGES;


/* --------------------------------------------------------------------------
 * SELECT FILE OR DIRECTORY STRUCTURES
 * -------------------------------------------------------------------------- */

/**
 *
 * \brief Response data from VltSelectFileOrDirectory.
 */
typedef struct
{
    /** \brief  File size.
     * This Reflects the length of data present in the file, and not the file
     * system space allocated to this file, which may be greater. */
    VLT_U32             u32FileSize;

    /** \brief Access conditions */
    VLT_FILE_PRIVILEGES FileAccess;

    /** \brief Attributes */
    VLT_U8              u8FileAttribute;

} VLT_SELECT;


/* --------------------------------------------------------------------------
 * GET INFO STRUCTURES
 * -------------------------------------------------------------------------- */

#if (VLT_ENABLE_FIPS_ALGOS == VLT_ENABLE)
 /**
   *
  * \brief List of algorithms used in Approved (FIPS mode)
    \details Bitfield of algorithms used in approved (FIPS) mode of operation, a bit is set to 1 if an
             algorithm is used , 0 otherwise
  */

typedef union
{
    /** \brief raw value on 16 bits */
    VLT_U16 val_u16;
    /** \brief bit encoded value */
    struct
    {   
        /** \brief D0: Message Digest*/
        VLT_UINT bMsgDigest : 1;

        /** \brief D1: AES*/
        VLT_UINT bAes : 1;

        /** \brief D2: ECDSA Signature over Gfp*/
        VLT_UINT bEcdsaSignatureGfp : 1;

        /** \brief D3: ECDSA Signature over Gf2m*/
        VLT_UINT bEcdsaSignatureGf2m : 1;

        /** \brief D4: RSA Signature */
        VLT_UINT bRsaSignature : 1;

        /** \brief D5: DSA Signature */
        VLT_UINT bDsaSignature : 1;

        /** \brief D6: Key Establishment over Gfp ECC*/
        VLT_UINT bKeyEstablishmentGfp : 1;

        /** \brief D7: Key Establishment over Gf2m ECC*/
        VLT_UINT bKeyEstablishmentGf2m : 1;

        /** \brief D8: Key Derivation Function */
        VLT_UINT bKeyDerivation : 1;

        /** \brief D9: Key Agreement Protocol over GFp ECC*/
        VLT_UINT bKeyAgreementGfp : 1;

        /** \brief D10: Key Agreement Protocol over GF2m ECC*/
        VLT_UINT bKeyAgreementGf2m : 1;

        /** \brief D11: Secure Channel Protocol SCP03 */
        VLT_UINT bScp03 : 1;

        /** \brief D12: Secure Password Authentication */
        VLT_UINT bSecurePassword : 1;

        /** \brief D15:D13: Reserved for future use */
        VLT_UINT bRfu : 3;
    } val_bits;
} VLT_FIPS_ALGOS;
#endif

/**
  *
 * \brief Response data from VltGetInfo.
 */
typedef struct
{
    /** \brief Firmware version */
    VLT_U8  au8Firmware[VLT_FIRMWARE_VERSION_LENGTH];

    /** \brief Device serial number */
    VLT_U8  au8Serial[VLT_CHIP_SERIAL_NUMBER_LENGTH];

    /** \brief Current Life Cycle state */
    VLT_STATE  enState;

    /** \brief Self-tests result */
    VLT_SELF_TESTS_STATUS enSelfTests;

    /** \brief Current authenticated Role ID */
    VLT_ROLE_ID  enRole;

    /** \brief Current mode of operation*/
    VLT_MODE  enMode;

    /** \brief Available bytes in the file system */
    VLT_U32 u32Space;

    /** \brief Tamper attack indicator */
    VLT_U8  u8Attack;

    /** \brief Tamper attack counter */
    VLT_U16 u16AttackCounter;
    
#if (VLT_ENABLE_GETINFO_EXT == VLT_ENABLE)
    /** \brief Current operating FIPS level; */
    VLT_FIPS_LEVEL enFipsLevel;

    /** \brief FIPS algorithm supported */
    VLT_FIPS_ALGOS unFipsAlgos;

    /** \brief Vic405 Legacy mode */
    VLT_BOOL isLegacyMode;

#endif
} VLT_TARGET_INFO;




/* --------------------------------------------------------------------------
 * INTERNAL STRUCTURES
 * -------------------------------------------------------------------------- */

 /** \cond INTERNAL_STRUCTS */

/**
 * \brief A buffer.
 */
typedef struct
{
    /** \brief   Length of the buffer, in bytes. */
    VLT_U16 u16Len;

    /** \brief   Capacity of the buffer, in bytes. */
    VLT_U16 u16Capacity;

    /** \brief   The buffer itself. */
    VLT_U8 *pu8Data;
} VLT_MEM_BLOB;

/** \endcond  */

/**
 * \brief A key object for use by vaultic_cipher and vaultic_signer, do not use
 * this for API functions.
 */
typedef struct
{
    /** \brief   key type */
    VLT_KEY_ID keyType;

    /** \brief   key size in bytes */
    VLT_U16 keySize;

    /** \brief   buffer containing the key value */
    VLT_U8 *keyValue;
} VLT_KEY_BLOB;

#define KEY_BLOB VLT_KEY_BLOB //backward compatibility

/**
* \brief The cipher parameters.
*
* \details
* The VLT_CIPHER_PARAMS structure is used to configure the cipher service.
*/

typedef struct
{
    /** \brief   Specifies which cipher will be used */
    VLT_ALG_CIP_ID enAlgoID;

    /** \brief Specifies which padding mode will be used */
    VLT_PADDING_ID enPaddingScheme;

      /** \brief Specifies which chain mode will be used */
    VLT_BLOCK_MODE_ID enChainMode;

    /** \brief An array of characters used as the Initialisation Vector */
    VLT_U8 *pIV;

} VLT_CIPHER_PARAMS;

#define CIPHER_PARAMS VLT_CIPHER_PARAMS //backward compatibility

/**
  * \brief The wrapping parameters.
  *
  * \details
  * The VLT_WRAP_PARAMS structure is used to configure the wrapping service.
  */
typedef struct
{
    /** \brief  Specifies which wrapping algorithm will be used */
    VLT_ALG_KTS_ID enAlgoID;

    /** \brief  Specifies which padding mode will be used  */
    VLT_PADDING_ID enPaddingScheme;

    /** \brief  Specifies which chain mode will be used  */
    VLT_BLOCK_MODE_ID enChainMode;

    /** \brief  An array of bytes used as the Initialisation Vector  */
    VLT_U8 *pIV;

} VLT_WRAP_PARAMS;

#define WRAP_PARAMS VLT_WRAP_PARAMS //backward compatibility

/**
 * \brief The Key Blob Array parameters.
 *
 * \details
 * The VLT_KEY_BLOB_ARRAY structure is used to configure the identity authentication service
 */
typedef struct  {
    /** \brief Specifies the number of keys being passed */
    VLT_U8 u8ArraySize;

    /** \brief pointer to an array of type VLT_KEY_BLOB */
    VLT_KEY_BLOB *pKeys[3];
} VLT_KEY_BLOB_ARRAY;

#define KEY_BLOB_ARRAY VLT_KEY_BLOB_ARRAY //backward compatibility

/**
 * \brief The attributes of the file system entry
 */
typedef struct
{
     /** \brief Specifies that file system entry cannot be written to :
                - 0 : file can be read and written
                - 1 : file can only be read */
    VLT_UINT readOnly : 1;

    /** \brief Specifies that file system entry is a system entry :
                - 0 : file is not a system file
                - 1 : file is a system file */
    VLT_UINT system : 1;

    /** \brief Specifies that file system entry is hidden :
                - 0 : file is not hidden
                - 1 : file is hidden */
    VLT_UINT hidden : 1;
} VLT_FS_ENTRY_ATTRIBS;


/**
 * \brief User access for the different users of the system
 *
 * \details
 * The VLT_USER_ACCESS structure holds information on file system entry acces
 * for different users
 */
typedef struct
{
    /** \brief Privilege for User 0:
    - 0 : denied
    - 1 : allowed */
    VLT_UINT user0 : 1;

    /** \brief Privilege for User 1:
    - 0 : denied
    - 1 : allowed */
    VLT_UINT user1 : 1;

    /** \brief Privilege for User 2:
    - 0 : denied
    - 1 : allowed */
    VLT_UINT user2 : 1;

    /** \brief Privilege for User 3:
    - 0 : denied
    - 1 : allowed */
    VLT_UINT user3 : 1;

    /** \brief Privilege for User 4:
    - 0 : denied
    - 1 : allowed */
    VLT_UINT user4 : 1;

    /** \brief Privilege for User 5:
    - 0 : denied
    - 1 : allowed */
    VLT_UINT user5 : 1;

    /** \brief Privilege for User 6:
    - 0 : denied
    - 1 : allowed */
    VLT_UINT user6 : 1;

    /** \brief Privilege for User 7:
    - 0 : denied
    - 1 : allowed */
    VLT_UINT user7 : 1;
} VLT_USER_ACCESS;


/**
 * \brief Privileges on a File System entry for Read, Write, Delete and Execute
 *
 * \par Description
 * The VLT_FS_ENTRY_PRIVILEGES structure holds information on file sytem entries regarding
 * the access privileges
 */
typedef struct
{
    /** \brief Bitmap defining Read Privilege for each user */
    VLT_USER_ACCESS readPrivilege;

    /** \brief Bitmap defining Write Privilege for each user */
    VLT_USER_ACCESS writePrivilege;

    /** \brief Bitmap defining Delete Privilege for each user */
    VLT_USER_ACCESS deletePrivilege;

    /** \brief Bitmap defining Execute Privilege for each user */
    VLT_USER_ACCESS executePrivilege;
} VLT_FS_ENTRY_PRIVILEGES;


/**
 *
 * \brief Parameters for entries within the fie system used by the File System
 * service
 *
 * \par Description
 * The VLT_FS_ENTRY_PARAMS structure holds information on file sytem entries for
 * the File System service
 */
typedef struct
{
    /** \brief The file system entry privileges */
    VLT_FS_ENTRY_PRIVILEGES filePriv;

    /** \brief Size of the entry in bytes.  Folders are zero bytes in size */
    VLT_U32 u32FileSize;

    /** \brief The type of entry either #VLT_FILE_ENTRY or #VLT_FOLDER_ENTRY */
    VLT_U8 u8EntryType;

    /** \brief The attributes for the file system entry */
    VLT_FS_ENTRY_ATTRIBS attribs;
} VLT_FS_ENTRY_PARAMS;


/**
 *
 * \brief Allows save and resume of secure channel session
 *
 * \par Description
 * The VLT_SECURE_SESSION_STATE holds information on the secure channel
 * state and can be used to resume a session.
 */
typedef struct
{
    /** \brief  The type of authentication method */
    VLT_AUTH_ID enAuthMethod;

    /** \brief  The security level of the secure channel */
    VLT_SEC_LEVEL_ID enSecureChannelLevel;

    /**\brief   The current state of the secure channel */
    VLT_AUTH_STATE enSecureChannelState;

    /** \brief  The CMAC session key */
   VLT_U8 au8CMacKey[SCPXX_MAX_SESSION_KEY_LEN];

   /** \brief   The RMAC session key */
   VLT_U8 au8RMacKey[SCPXX_MAX_SESSION_KEY_LEN];

   /** \brief   The CENC session key */
   VLT_U8 au8CEncKey[SCPXX_MAX_SESSION_KEY_LEN];

   /** \brief   Current CMAC */
   VLT_U8 au8CMac[SCPXX_MAX_CMAC_LEN];

   /** \brief   Current RMAC */
   VLT_U8 au8RMac[SCPXX_MAX_RMAC_LEN];

   /** \brief   The current AES IV/Counter */
   VLT_U8 au8AesIV[SCPXX_MAX_CMAC_LEN];
} VLT_SECURE_SESSION_STATE;

/** @}*/

#endif /* VAULTIC_STRUCTS_H */
