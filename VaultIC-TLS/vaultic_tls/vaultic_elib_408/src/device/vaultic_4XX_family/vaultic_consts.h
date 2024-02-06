/**
* @file	   vaultic_consts.h
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
* @brief   VaultIC API constants definition
*/

/**
* @defgroup Constants Commonly used API Constants
* @brief Constants used by VaultIC.
*
* @par Description:
* This file declares the constants used by VaultIC.
*/

/** @{ */
#ifndef VAULTIC_CONSTS_H
#define VAULTIC_CONSTS_H

#include "vaultic_config.h"

/** 
 *  \brief  User IDs 
 */
typedef enum {
    /** System User 0 */
    VLT_USER0                                               = 0x00 ,    

    /** System User 1 */
    VLT_USER1                                               = 0x01 ,    

    /** System User 2 */
    VLT_USER2                                               = 0x02 ,    

    /** System User 3 */
    VLT_USER3                                               = 0x03 ,    

    /** System User 4 */
    VLT_USER4                                               = 0x04 ,    

    /** System User 5 */
    VLT_USER5                                               = 0x05 ,    

    /** System User 6 */
    VLT_USER6                                               = 0x06 ,    

    /** System User 7 */
    VLT_USER7                                               = 0x07      
    
} VLT_USER_ID;


/** 
 *  \brief  Role IDs 
 */
typedef enum {
    /** (0x01) An approved  user is assumed to perform general security services and approved - only cryptographic operations. */
    VLT_APPROVED_USER                                       = 0x01 ,    

    /** (0x02) A non approved user is assumed to perform both approved and non approved cryptographic operations. */
    VLT_NON_APPROVED_USER                                   = 0x02 ,    

    /** (0x04) The Manufacturer can personalise and configure the chip and perform maintenance operations.*/
    VLT_MANUFACTURER                                        = 0x04 ,    

    /** (0x08) The Administrator can usually manage the approved users authentication data. */
    VLT_ADMINISTRATOR                                       = 0x08 ,    

    /** (0x10) The Non Approved Administrator can usually manage the non approved users authentication data. */
    VLT_NON_APPROVED_ADMINISTRATOR                          = 0x10 ,    

    /** (0x20) A role that is not authenticated.*/
    VLT_EVERYONE                                            = 0x20      
    
} VLT_ROLE_ID;


/** 
 *  \brief  Manage Authentication User Operation IDs 
 */
typedef enum {
    /** Defines and creates a new operator */
    VLT_CREATE_USER                                         = 0x01 ,    

    /** Removes an existing operator and associated authentication data */
    VLT_DELETE_USER                                         = 0x02 ,    

    /** Updates operator's authentication data */
    VLT_UPDATE_USER                                         = 0x04 ,    

    /** Lock operator (set authentication try counter to zero) */
    VLT_LOCK_USER                                           = 0x10 ,    

    /** Unlock operator (set authentication try counter to max tries counter) */
    VLT_UNLOCK_USER                                         = 0x20      
} VLT_USER_OP_ID;


/** 
 *  \brief  Secure Channel Level IDs 
 */
typedef enum {
    /** No protection (mutual authentication only) */
    VLT_NO_CHANNEL                                          = 0x00 ,    

    /** APDU command MAC */
    VLT_CMAC                                                = 0x01 ,    

    /** APDU command MAC + encrypted command data field */
    VLT_CMAC_CENC                                           = 0x03 ,    

    /** APDU command MAC + APDU response MAC */
    VLT_CMAC_RMAC                                           = 0x11 ,    

    /** APDU command MAC + encrypted command data field + APDU response MAC */
    VLT_CMAC_CENC_RMAC                                      = 0x13 ,    

    /** APDU command MAC + encrypted command data field + encrypted APDU response + APDU response MAC */
    VLT_CMAC_CENC_RMAC_RENC                                 = 0x33      
} VLT_SEC_LEVEL_ID;


/** 
 *  \brief  Manage Authentication Security Option IDs 
 */
typedef enum {
    /** Operator's data is persistent */
    VLT_NO_DELETE_ON_LOCK                                   = 0x00 ,    

    /** When operator is locked, authentication data, files and keys owned by this operator are wiped. 
               Folders owned by the operator are not deleted.*/
    VLT_DELETE_ON_LOCK                                      = 0x01      
} VLT_SEC_OPTION;


/** 
 *  \brief  Authentication methods IDs 
 */
typedef enum {
    /** Used to indicate that a password is required as an authentication access mechanism. */
    VLT_AUTH_PASSWORD                                      = 0x01 ,    

#if (VAULT_IC_VERSION == VAULTIC_408_1_X_X)
    /** Used to indicate that a secure password is required as an authentication access mechanism. */
    VLT_AUTH_SECURE_PASSWORD                               = 0x04,
#endif

#if (VLT_ENABLE_SCP03 == VLT_ENABLE)  
    /** Used to indicate that Secure Channel Protocol 3 is is required as an authentication access mechanism. */
    VLT_AUTH_SCP03                                         = 0x03 ,    
#endif

 } VLT_AUTH_ID;


/*******************************************************
 Manage Authentication Data Useful IDs: 
*******************************************************/ 
/** @cond SHOW_INTERNAL */
#define VLT_SMAC_KEY_INDEX                          (VLT_U8)  0x00
#define VLT_SENC_KEY_INDEX                          (VLT_U8)  0x01

#define VLT_PWD_KEY_INDEX                           (VLT_U8)  0x00
#define VLT_DEFAULT_TRY_COUNT                       (VLT_U8)  0x03
#define VLT_SCP_NUMBER_OF_KEYS                      (VLT_U8)  0x02

#define VLT_NUMBER_OF_PWDS                          (VLT_U8)  0x01
/** @endcond */

/** 
 *  \brief  Algorithm Mode IDs 
 */ 
typedef enum {

    /** Uninitialise algorithm, reset crypto engine */
    VLT_RESET_MODE                                          = 0x00 ,     

    /** Encrypt */
    VLT_ENCRYPT_MODE                                        = 0x01 ,     

    /** Decrypt */
    VLT_DECRYPT_MODE                                        = 0x02 ,     

    /** Compute Digest */
    VLT_DIGEST_MODE                                         = 0x08 ,     

    /** Wrap key */
    VLT_WRAP_KEY_MODE                                       = 0x10 ,     

    /** Unwrap key */
    VLT_UNWRAP_KEY_MODE                                     = 0x20 ,     

    /** Compute Signature */
    VLT_SIGN_MODE                                           = 0x40 ,     

    /** Verify Signature */
    VLT_VERIFY_MODE                                         = 0x80      
    
} VLT_ALGO_MODE;

/**
 *  \brief  Signer Mode IDs
 */
typedef enum {
    /** Compute Signature */
    VLT_SIGNER_MODE_SIGN = VLT_SIGN_MODE,

    /** Verify Signature */
    VLT_SIGNER_MODE_VERIFY = VLT_VERIFY_MODE

} VLT_SIGNER_MODE;


/** 
 *  \brief  Signing algorithm identifiers  
 */
typedef enum {
    
#if ((VAULT_IC_VERSION == VAULTIC_420_1_2_X)||(VAULT_IC_VERSION == VAULTIC_405_1_X_X))
    /** ISO/IEC 9797-1 Algorithm 1 CBC-MAC using 3DES-EDE */
    VLT_ALG_SIG_MAC_ISO9797_ALG1                            = 0x00 ,

    /** ISO/IEC 9797-1 Algorithm 3 CBC-MAC using DES */
    VLT_ALG_SIG_MAC_ISO9797_ALG3                            = 0x01 ,
#endif

    /** NIST SP 800-38B AES CMAC */
    VLT_ALG_SIG_CMAC_AES                                    = 0x11 ,

    /** FIPS 198 HMAC - Hash-based Message Authentication Code */
    VLT_ALG_SIG_HMAC                                        = 0x10 ,

    /** RFC4226 Hash-based OTP */
    VLT_ALG_SIG_HOTP                                        = 0x03 ,

#if (VAULT_IC_VERSION == VAULTIC_420_1_2_X)
    /** OATH Draft v5 Time-based OTP */
    VLT_ALG_SIG_TOTP                                        = 0x04 ,
#endif

#if( VLT_ENABLE_SIGN_RSA == VLT_ENABLE)
    /** PKCS#1 v2.1 RSASSA-PSS signer */
    VLT_ALG_SIG_RSASSA_PKCS_PSS                             = 0x16 ,

    /** PKCS#1 v2.1 RSASSA-PKCS1-v1_5 signer */
    VLT_ALG_SIG_RSASSA_PKCS                                 = 0x17 ,

    /** RSASSA-X509 raw RSA signer */
    VLT_ALG_SIG_RSASSA_X509                                 = 0x05 ,
#endif

#if( VLT_ENABLE_SIGN_xDSA == VLT_ENABLE)
    /** FIPS 186-3 signer over prime fields GF(p) ( P-xxx ) */
    VLT_ALG_SIG_ECDSA_GFP                                   = 0x19 ,

    /** FIPS 186-3 signer over binary fields GF2m ( B-xxx and K-xxx ) */
    VLT_ALG_SIG_ECDSA_GF2M                                  = 0x1A ,
#endif

#if (VAULT_IC_VERSION != VAULTIC_420_1_2_X)
#if( VLT_ENABLE_SIGN_xDSA == VLT_ENABLE)
    /** deterministic calculation of the 'per-message secret number' */
    VLT_ALG_SIG_ECDSA_GBCS                                  = 0x06 ,
#endif
    #if(VLT_ENABLE_SIGN_GMAC == VLT_ENABLE)
    /** GMAC signer */
    VLT_ALG_SIG_GMAC                                        = 0x1B
#endif
#endif
    
} VLT_ALG_SIG_ID;


/** 
 *  \brief  Digest algorithm identifiers 
 */
typedef enum {

    /** No digest (input message already predigested) */
    VLT_ALG_DIG_NONE                                        = 0x80,

    /** FIPS 186-3 SHA-1 digest */
    VLT_ALG_DIG_SHA1                                        = 0x30 ,  

    /** FIPS 186-3 SHA-224 digest */
    VLT_ALG_DIG_SHA224                                      = 0x31 ,   

    /** FIPS 186-3 SHA-256 digest*/
    VLT_ALG_DIG_SHA256                                      = 0x32 ,   

    /** FIPS 186-3 SHA-384 digest*/
    VLT_ALG_DIG_SHA384                                      = 0x33 ,   

    /** FIPS 186-3 SHA-512 digest*/
    VLT_ALG_DIG_SHA512                                      = 0x34 ,   
} VLT_ALG_DIG_ID;

#if (VLT_ENABLE_API_GENERATE_SYMMETRIC_KEY == VLT_ENABLE)
/**
 *  \brief  AES Key Types for Generic Assymetric Key command
 */
typedef enum {

    /** Aes 128 bits Id */
    VLT_AES_128 = 0x85,

    /** Aes 192 bits Id */
    VLT_AES_192 = 0x86,

    /** Aes 256 bits Id */
    VLT_AES_256 = 0x87,

} VLT_AES_ID;
#endif

/**
 *  \brief  Key Transport Scheme identifiers 
 */
typedef enum {
    /** NIST SP800-56B Key Transport Scheme based on RSAES-OAEP algorithm without key confirmation */
    VLT_ALG_KTS_RSA_OAEP_BASIC                              = 0x83 ,

#if (VAULT_IC_VERSION == VAULTIC_420_1_2_X)
        /** Generic Key Transport Scheme based on AES */
    VLT_ALG_KTS_AES                                         = 0x82 ,
#else
    /** Generic Key Transport Scheme based on AES */
    VLT_ALG_KTS_AES                                         = 0x92 ,

#if (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE)
    /** Generic Key Transport Scheme based on P25 (TIA-102.AACA) specifications */
    VLT_ALG_KTS_AES_P25                                     = 0x93,
#endif

#if (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE)
    /** Generic Key Transport Scheme based on NIST SP800-38F specifications */
    VLT_ALG_KTS_AES_NIST_KWP                                = 0x94,
#endif

#endif

} VLT_ALG_KTS_ID;


/**
 *  \brief  Cipher algorithm identifiers
 */
typedef enum {

    /** FIPS 197 AES Cipher */
    VLT_ALG_CIP_AES                                         = 0x52 ,

#if (VAULT_IC_VERSION != VAULTIC_420_1_2_X)
    /** NIST SP800-38D AES Cipher */
    VLT_ALG_CIP_GCM                                         = 0x53 ,
#endif

#if( VLT_ENABLE_CIPHER_RSA == VLT_ENABLE)
    /** PKCS#1 v2.1 RSAES-OAEP cipher */
    VLT_ALG_CIP_RSAES_PKCS_OAEP                             = 0x42 ,

    /** PKCS#1 v2.1 RSAES-PKCS1-v1_5 cipher */
    VLT_ALG_CIP_RSAES_PKCS                                  = 0x43 ,

    /** RSAES-X509 raw RSA cipher with no padding */
    VLT_ALG_CIP_RSAES_X509                                  = 0x44
#endif

} VLT_ALG_CIP_ID;

/**
 *  \brief  Padding Methods
 */
typedef enum {

    /** No Padding */
    VLT_PADDING_NONE = 0x00,

    /** ISO9797-1 Padding Method 1 */
    VLT_PADDING_ISO9797_METHOD1 = 0x01,

    /** ISO9797-1 Padding Method 2 */
    VLT_PADDING_ISO9797_METHOD2 = 0x02,

    /** PKCS5 Padding */
    VLT_PADDING_PKCS5 = 0x05,

    /** PKCS7 Padding */
    VLT_PADDING_PKCS7 = 0x07
} VLT_PADDING_ID;

// backward compatibility
#define PADDING_NONE VLT_PADDING_NONE
#define PADDING_ISO9797_METHOD1 VLT_PADDING_ISO9797_METHOD1
#define PADDING_ISO9797_METHOD2 VLT_PADDING_ISO9797_METHOD2
#define PADDING_PKCS5 VLT_PADDING_PKCS5 
#define PADDING_PKCS7 VLT_PADDING_PKCS7

#if (VLT_ENABLE_CIPHER_AES_NIST == VLT_ENABLE) || (VLT_ENABLE_CIPHER_AES_P25 == VLT_ENABLE) 
/**
 *  \brief  Padding Methods for Key Wrapping as defined in SP800-38F
 */
typedef enum {

    /** No SP800-38F padding */
    VLT_KTS_PADDING_MODE_KW = 0x00,

    /** SP800-38F padding*/
    VLT_KTS_PADDING_MODE_KWP = 0x01,

} VLT_KTS_PADDING_MODE;
//backward compatibility
#define KTS_PADDING_MODE_KW  VLT_KTS_PADDING_MODE_KW 
#define KTS_PADDING_MODE_KWP VLT_KTS_PADDING_MODE_KWP
#endif

/**
 *  \brief  Chaining mode identifiers
 */
typedef enum {
    /** Electronic Code Book Chaining Mode  */
    VLT_BLOCK_MODE_ECB = 0x00,

    /** Cipher Block Chaining Mode */
    VLT_BLOCK_MODE_CBC = 0x01,

    /** Output Feedback Register Chaining Mode */
    VLT_BLOCK_MODE_OFB = 0x02,

    /** Cipher Feedback Register Chaining Mode */
    VLT_BLOCK_MODE_CFB = 0x03,

    /** Cipher Feedback Register Chaining Mode */
    VLT_BLOCK_MODE_CTR = 0x04,

} VLT_BLOCK_MODE_ID;

// backward compatibility
#define BLOCK_MODE_ECB  VLT_BLOCK_MODE_ECB
#define BLOCK_MODE_CBC  VLT_BLOCK_MODE_CBC
#define BLOCK_MODE_OFB  VLT_BLOCK_MODE_OFB
#define BLOCK_MODE_CFB  VLT_BLOCK_MODE_CFB
#define BLOCK_MODE_CTR  VLT_BLOCK_MODE_CTR

#if (VLT_ENABLE_API_GENERATE_KEY_PAIR == VLT_ENABLE)
/**
 *  \brief  Key Pair Generator identifiers 
 */
typedef enum {
    /** RSA Key pair generation for signer engines */
    VLT_ALG_KPG_RSASSA                                      = 0x70 ,

    /** RSA Key pair generation for cipher engines */
    VLT_ALG_KPG_RSAES                                       = 0x73 ,

    /** DSA Key pair generation  */
    VLT_ALG_KPG_DSA                                         = 0x71 ,

    /** ECDSA key pair generation over prime fields GF(p) ( P-xxx ) */
    VLT_ALG_KPG_ECDSA_GFP                                   = 0x72 ,

    /** ECDSA key pair generation over binary fields GF(p) ( B-xxx  and K-xxx ) */
    VLT_ALG_KPG_ECDSA_GF2M                                  = 0x74
    
} VLT_ALG_KPG_ID;
#endif

#if (VAULT_IC_VERSION != VAULTIC_420_1_2_X)
#if(VLT_ENABLE_API_CONSTRUCT_AGREEMENT == VLT_ENABLE)
/**
 *  \brief  Key Agreement Scheme identifiers
 */
typedef enum {
    /** 
     *  STATIC_UNIFIED : Static Unified Model- C(0,2) \n
     * As defined by ANS X9.63 chapter 6.3 \n
     * As defined by FIPS SP800-56A, chapter 6.3.2 \n
     * ECKA: Elliptic Curve Key Agreement primitive \n
     * As defined by BSI-TR-03111 \n
     * Stricter version of Standard Diffie-Hellman primitive defined by ANSX9.63
     */
    VLT_ALG_KAS_STATIC_UNIFIED_ECKA_GFp                     = 0xA0 ,

    /** STATIC_UNIFIED : Static Unified Model - C(0,2) \n
     * As defined by ANS X9.63 chapter 6.3 \n
     * As defined by FIPS SP800-56A, chapter 6.3.2 \n
     * ECKA: Elliptic Curve Key Agreement primitive \n
     * As defined by BSI-TR-03111 \n
     * Stricter version of Standard Diffie-Hellman primitive defined by ANSX9.63
     */
    VLT_ALG_KAS_STATIC_UNIFIED_ECKA_GF2m                    = 0xA1 ,

    /**
     * STATIC_UNIFIED : Static Unified Model - C(0,2) \n
     * As defined by ANS X9.63 chapter 6.3 \n
     * As defined by FIPS SP800-56A, chapter 6.3.2 \n
     * ECC_DH : Standard Diffie-Hellman primitive \n
     * As defined by ANS X9.63, chapter 5.4.1
     */
    VLT_ALG_KAS_STATIC_UNIFIED_ECC_DH_GFp                   = 0xA4 ,

    /**
     * STATIC_UNIFIED : Static Unified Model - C(0,2) \n
     * As defined by ANS X9.63 chapter 6.3 \n
     * As defined by FIPS SP800-56A, chapter 6.3.2 v
     * ECC_DH : Standard Diffie-Hellman primitive \n
     * As defined by ANS X9.63, chapter 5.4.1
     */
    VLT_ALG_KAS_STATIC_UNIFIED_ECC_DH_GF2m                  = 0xA5 ,

    /**
     * STATIC_UNIFIED : Static Unified Model - C(0,2) \n
     * As defined by ANS X9.63 chapter 6.3 \n
     * As defined by FIPS SP800-56A, chapter 6.3.2 \n
     * ECC_CDH : Cofactor Diffie-Hellman primitive (ECC CDH) \n
     * As defined by FIPS SP800-56A, chapter 5.7.1.2 \n
     * As defined  by ANS 9.63, chapter 5.4.2
     */
    VLT_ALG_KAS_STATIC_UNIFIED_ECC_CDH_GFp                  = 0xB0 ,

    /**
     * STATIC_UNIFIED : Static Unified Model - C(0,2) \n
     * As defined by ANS X9.63 chapter 6.3 \n
     * As defined by FIPS SP800-56A, chapter 6.3.2 \n
     * ECC_CDH : Cofactor Diffie-Hellman primitive (ECC CDH)
     * As defined by FIPS SP800-56A, chapter 5.7.1.2 \n
     * As defined  by ANS 9.63, chapter 5.4.2
     */
    VLT_ALG_KAS_STATIC_UNIFIED_ECC_CDH_GF2m                 = 0xB1 ,

    /**
     * ONE_PASS : One-Pass Diffie-Hellman Model - C(1,1) \n
     * As defined by ANS X9.63 chapter 6.2 \n
     * As defined by FIPS SP800-56A, chapter 6.2.2.2 \n
     * ECC_CDH : Cofactor Diffie-Hellman primitive (ECC CDH) \n
     * As defined by FIPS SP800-56A, chapter 5.7.1.2 \n
     * As defined  by ANS 9.63, chapter 5.4.2
     */
    VLT_ALG_KAS_ONE_PASS_ECC_CDH_GFp                        = 0xB2 ,

    /**
     * ONE_PASS : One-Pass Diffie-Hellman Model - C(1,1) \n
     * As defined by ANS X9.63 chapter 6.2 \n
     * As defined by FIPS SP800-56A, chapter 6.2.2.2 \n
     * ECC_CDH : Cofactor Diffie-Hellman primitive (ECC CDH) \n
     * As defined by FIPS SP800-56A, chapter 5.7.1.2 \n
     * As defined  by ANS 9.63, chapter 5.4.2
     */
    VLT_ALG_KAS_ONE_PASS_ECC_CDH_GF2m                       = 0xB3 ,

    /**
     * ONE_PASS : One-Pass Diffie-Hellman Model - C(1,1) \n
     * As defined by ANS X9.63 chapter 6.2 \n
     * As defined by FIPS SP800-56A, chapter 6.2.2.2 \n
     * ECC_DH : Standard Diffie-Hellman primitive \n
     * As defined by ANS X9.63, chapter 5.4.1
     */
    VLT_ALG_KAS_ONE_PASS_ECC_DH_GFp                         = 0xA6 ,

    /**
     * ONE_PASS : One-Pass Diffie-Hellman Model - C(1,1) \n
     * As defined by ANS X9.63 chapter 6.2 \n
     * As defined by FIPS SP800-56A, chapter 6.2.2.2 \n
     * ECC_DH : Standard Diffie-Hellman primitive \n
     * As defined by ANS X9.63, chapter 5.4.1
     */
    VLT_ALG_KAS_ONE_PASS_ECC_DH_GF2m                        = 0xA7 ,

    /**
     * ONE_PASS : One-Pass Diffie-Hellman Model - C(1,1) \n
     * As defined by ANS X9.63 chapter 6.2 \n
     * As defined by FIPS SP800-56A, chapter 6.2.2.2 \n
     * ECKA: Elliptic Curve Key Agreement primitive \n
     * As defined by BSI-TR-03111 \n
     * Stricter version of Standard Diffie-Hellman primitive defined by ANSX9.63
     */
    VLT_ALG_KAS_ONE_PASS_ECKA_GFp                           = 0xA2 ,

    /**
     * ONE_PASS : One-Pass Diffie-Hellman Model - C(1,1) \n
     * ECKA: Elliptic Curve Key Agreement primitive \n
     * As defined by BSI-TR-03111 \n
     * Stricter version of Standard Diffie-Hellman primitive defined by ANSX9.63
     */
    VLT_ALG_KAS_ONE_PASS_ECKA_GF2m                          = 0xA3 ,
} VLT_ALG_KAS_ID;
#endif
#endif

#if (VAULT_IC_VERSION != VAULTIC_420_1_2_X)
#if (VLT_ENABLE_API_DERIVE_KEY == VLT_ENABLE)
/**
 *  \brief  Key Derivation Algorithm identifiers
 */
typedef enum {
    /** NIST SP800-56A Concatenation KDF */
    VLT_ALG_KDF_CONCATENATION_NIST                          = 0xD0 ,

    /** Hash KDF defined by Microsoft Card Minidriver specification */
    VLT_ALG_KDF_HASH_MODE                                   = 0xC1 ,

    /** KDF defined by ANS X9.63 */
    VLT_ALG_KDF_X963                                        = 0xC0 ,

} VLT_ALG_KDF_ID;
#endif
#endif

/**
 *  \brief  Key identifiers
 */
typedef enum {

    /** AES key - 128 bits */
    VLT_KEY_AES_128                                         = 0x85 ,

    /** AES key - 192 bits */
    VLT_KEY_AES_192                                         = 0x86 ,

    /** AES key - 256 bits */
    VLT_KEY_AES_256                                         = 0x87 ,
    
    /** HMAC key */
    VLT_KEY_HMAC                                            = 0x89 ,
    
    /** HOTP key */
    VLT_KEY_HOTP                                            = 0x8A ,

#if (VAULT_IC_VERSION == VAULTIC_420_1_2_X)
    /** TOTP key */
    VLT_KEY_TOTP                                            = 0x8B ,
#endif    

#if (VLT_ENABLE_KEY_RSA == VLT_ENABLE)
    /** RSA public key for signer engine */
    VLT_KEY_RSASSA_PUB                                      = 0x02 ,
    
    /** RSA private key for signer engine */
    VLT_KEY_RSASSA_PRIV                                     = 0x90 ,

    /** RSA private key for signer engine in CRT format*/
    VLT_KEY_RSASSA_PRIV_CRT                                 = 0x91 ,

    /** RSA public key for cipher engine */
    VLT_KEY_RSAES_PUB                                       = 0x03 ,

    /** RSA private key for cipher engine */
    VLT_KEY_RSAES_PRIV                                      = 0x92 ,

    /** RSA private key for cipher engine in CRT format */
    VLT_KEY_RSAES_PRIV_CRT                                  = 0x93 ,
#endif

#if (VAULT_IC_VERSION != VAULTIC_420_1_2_X)
    #if (VLT_ENABLE_API_CONSTRUCT_AGREEMENT == VLT_ENABLE)
    /** Secret value material, output of Key Material Establishment Scheme and used as input of Key Derivation Function. */
    VLT_KEY_SECRET_VALUE                                    = 0xB0 ,
    #endif
#endif
    
    #if (VLT_ENABLE_KEY_ECDSA == VLT_ENABLE)
    /** ECC public key */
    VLT_KEY_ECC_PUB                                         = 0x0A ,

    /** ECC private key */
    VLT_KEY_ECC_PRIV                                        = 0x9B ,

    /** ECC domain parameters */
    VLT_KEY_ECC_PARAMS                                      = 0x70 ,
#endif

    #if( VLT_ENABLE_KEY_IDENTIFIER == VLT_ENABLE )
    /** Host or Device identifier */
    VLT_KEY_IDENTIFIER                                      = 0x60 ,
#endif

    /** Key in RAW format */
    VLT_KEY_RAW                                             = 0xFF ,
    
} VLT_KEY_ID;

/** @cond SHOW_INTERNAL */
#define VLT_SECRET_KEY_STATIC_PART_LENGTH           (VLT_U8)  0x04
#define VLT_HOTP_KEY_STATIC_PART_LENGTH             (VLT_U8)  0x0C
#define VLT_TOTP_KEY_STATIC_PART_LENGTH             (VLT_U8)  0x18


#define VLT_ECDSA_PRIVATE_STATIC_PART_LENGTH        (VLT_U8)  0x09

#define VLT_DSA_PUBLIC_STATIC_PART_LENGTH           (VLT_U8)  0x06
#define VLT_DSA_PRIVATE_STATIC_PART_LENGTH          (VLT_U8)  0x08
#define VLT_ECDSA_PUBLIC_STATIC_PART_LENGTH         (VLT_U8)  0x06
#define VLT_RSA_PRIVATE_STATIC_PART_LENGTH          (VLT_U8)  0x08
#define VLT_RSA_PUBLIC_STATIC_PART_LENGTH           (VLT_U8)  0x06
#define VLT_RSA_CRT_PRIVATE_STATIC_PART_LENGTH      (VLT_U8)  0x06
#define VLT_DSA_PARAMS_STATIC_PART_LENGTH           (VLT_U8)  0x0B
#define VLT_ECDSA_PARAMS_STATIC_PART_LENGTH         (VLT_U8)  0x0A
#define VLT_IDENTIFIER_STATIC_PART_LENGTH           (VLT_U8)  0x03
#define VLT_ECDH_PUBLIC_STATIC_PART_LENGTH          (VLT_U8)  0x05
#define VLT_ECDH_PRIVATE_STATIC_PART_LENGTH         (VLT_U8)  0x08 

#define VLT_PUTKEY_FIXED_DATA_LENGTH                (VLT_U8)  0x08

/* XOTP in this case means HOTP or TOTP */
#define VLT_KEY_XOTP_KEY_LENGTH                     (VLT_U8)  0x14
#define VLT_KEY_HOTP_MOVINGFACTOR_LENGTH            (VLT_U8)  0x08

/** @endcond */

/*******************************************************
 Put Key Assurance Values:
*******************************************************/
#if (VLT_ENABLE_API_GENERATE_ASSURANCE_MESSAGE == VLT_ENABLE)
/**
 *  \brief Assurance method identifier for Domain Parameters Validity  
 */
typedef enum {
    /** Domain Parameters have not been validated and assurance of Domain Parameters Validity should be internally obtained by the device using approved method.*/
    VLT_DPV_NON_UNASSURED                                   = 0x00 ,

    /** The Trusted Third Party has performed an explicit Domain Parameters Validation and obtained an indication of validity */
    VLT_DPV_ASSURED_EXPLICIT_VALIDATION                     = 0x03 ,

    /** Domain Parameters have been generated by a Trusted Third Party in accordance with FIPS186-4 */
    VLT_DPV_ASSURED_COMPLIANT_GENERATION                    = 0x04 ,

    /** Domain Parameters have been selected from a set of domain parameters published by an entity that the TTP trusts */
    VLT_DPV_ASSURED_SELECTION_FROM_TRUSTED_SET              = 0x05,

    /** The Trusted Third Party has performed an explicit Domain Parameters Validation but founded to be faulty.*/
    VLT_DPV_FAILED_EXPLICIT_VALIDATION                      = 0x83,
    
    /** Domain Parameters have been generated by a Trusted Third Party in accordance with FIPS186 - 4 but founded to be faulty. */
    VLT_DPV_FAILED_COMPLIANT_GENERATION                     = 0x84, 
    
    /** Domain Parameters have been selected from a set of domain parameters  published by an entity that the TTP trusts but founded to be faulty. */
    VLT_DPV_FAILED_SELECTION_FROM_TRUSTED_SET               = 0x85 
    
 } VLT_DPV_ASSURANCE_ID;

/**
 *  \brief Assurance method identifier for Public Key Validity 
 */
typedef enum {
    /** Public Key has not been validated and assurance of Public Key Validity - PKV should be internally obtained by the device using approved method */
    VLT_PKV_NON_UNASSURED                                   = 0x00 ,
    
    /** The Trusted Third Party has performed an explicit Public Key Validation and obtained an indication of validity */
    VLT_PKV_ASSURED_EXPLICIT_VALIDATION                     = 0x23 ,

    /** The key pair has been generated by the Trusted Third Party using approved methods and has been provided to the owner */
    VLT_PKV_ASSURED_COMPLIANT_GENERATION                    = 0x24 ,

    /** The key pair has been generated in cooperation between the Trusted Third Party and the owner */
    VLT_PKV_ASSURED_COOPERATIVE_GENERATION                  = 0x25 ,

    /** The Trusted Third Party has performed key generation/regeneration and pairwise test */
    VLT_PKV_ASSURED_KEY_REGENERATION                        = 0x26 ,

    /** The Trusted Third Party has performed an explicit Public Key Validation but founded to be faulty. */
    VLT_PKV_FAILED_EXPLICIT_VALIDATION                      = 0xA3 ,
    
    /** The key pair has been generated by the Trusted Third Party using approved methods but founded to be faulty. */
    VLT_PKV_FAILED_COMPLIANT_GENERATION                     = 0xA4 ,
    
    /** The key pair has been generated in cooperation between the Trusted Third Party and the owner but founded to be faulty. */
    VLT_PKV_FAILED_COOPERATIVE_GENERATION                   = 0xA5 ,
    
    /** The Trusted Third Party has performed key generation / regeneration and pairwise test but founded to be faulty. */
    VLT_PKV_FAILED_KEY_REGENERATION                         = 0xA6 

} VLT_PKV_ASSURANCE_ID;


/**
 *  \brief Assurance method identifier for Private Key Validity 
 */
typedef enum {
    /** Private Key has not been validated and assurance of Privare Key Validity - PKV should be internally obtained by the device using approved method */
    VLT_PRKV_NON_UNASSURED                                  = 0x00 ,
    
    /** The private key has been generated by the Trusted Third Party using approved methods and has been provided to the owner */
    VLT_PRKV_ASSURED_COMPLIANT_GENERATION                   = 0x44 ,

} VLT_PRKV_ASSURANCE_ID;
#endif

#if (VAULT_IC_VERSION != VAULTIC_420_1_2_X)
#if (VLT_ENABLE_API_KEY_CONFIRMATION == VLT_ENABLE)
/**
 *  \brief Key Confirmation Policy for Key Derivation
 */
typedef enum {
    /** Key Confirmation command is not required */
    VLT_KEY_CONFIRM_NOT_REQUIRED                            = 0x00,

    /** Key Confirmation command is optional, and derived key not locked*/
    VLT_KEY_CONFIRM_OPTIONAL                                = 0x01,

    /** Key Confirmation command is required to unlock the derived key(only possible in Static Unified scheme) */
    VLT_KEY_CONFIRM_REQUIRED                                = 0x02
} VLT_KEY_CONFIRM_POLICY;
#endif
#endif

/*******************************************************
 VaultIC Life Cycle State IDs: 
*******************************************************/
/**
 *  \brief  VaultIC Life Cycle State , please consult the Vault IC Generic Datasheet for a detailed description. 
 */
typedef enum {
    /** (0x01) Creation state  */
    VLT_STATE_CREATION                                      = 0x01 , 
    
    /** (0x07) Activated state  */
    VLT_STATE_ACTIVATED                                     = 0x07 , 
    
    /** (0x87) Deactivated state */
    VLT_STATE_DEACTIVATED                                   = 0x87 ,
    
    /** (0xFF) Terminated state */
     VLT_STATE_TERMINATED                                   = 0xFF
     
} VLT_STATE;


/**
 *  \brief  Product mode returned by VltGetInfo
 */
typedef enum {
    /** Idle mode: the device is in ACTIVATED state and is waiting for an operator authentication */
    VLT_MODE_IDLE                                  = 0x00 ,

    /** Approved mode: the device is in ACTIVATED state and an approved operator is authenticated */
    VLT_MODE_APPROVED                              = 0x01 ,

    /** Non-approved mode: the device is in ACTIVATED state and a non-approved operator is authenticated */
    VLT_MODE_NON_APPROVED                          = 0x02 ,
    
    /** Personalization mode: the device is in CREATION */
    VLT_MODE_CREATION                              = 0x03 ,

    /** Maintenance mode: the device is either in DEACTIVATED state or TERMINATED state. */
    VLT_MODE_MAINTENANCE                           = 0x04 
    
} VLT_MODE;


/**
 *  \brief  Self tests result returned by VltGetInfo
 */
typedef enum {
    /** Self Tests succeed */
    VLT_SELF_TESTS_OK                                       = 0x00 ,

    /** Self Tests failed */
    VLT_SELF_TESTS_FAILURE                                  = 0xFF  

} VLT_SELF_TESTS_STATUS;


#if (VAULT_IC_VERSION == VAULTIC_408_1_X_X)
/**
 *  \brief  FIPS level returned by VltGetInfo
 */
typedef enum {

    /** FIPS level 2 */
    VLT_FIPS_LEVEL_2 = 0x02,

    /** FIPS level 3 */
    VLT_FIPS_LEVEL_3 = 0x03,

} VLT_FIPS_LEVEL;

#endif



/**
 * \brief Elliptics curve identifiers.
 */
typedef enum {
    /** NIST B-163 binary curve. */
    VLT_ECC_ID_B163,
  
    /** NIST B-233 binary curve. */
    VLT_ECC_ID_B233,

    /** NIST B-283 binary curve. */
    VLT_ECC_ID_B283,

    /** NIST B-409 binary curve. */
    VLT_ECC_ID_B409,

    /** NIST B-571 binary curve. */
    VLT_ECC_ID_B571,

    /** NIST K-163 Koblitz curve. */
    VLT_ECC_ID_K163,

    /** NIST K-233 Koblitz curve. */
    VLT_ECC_ID_K233,

    /** NIST K-283 Koblitz curve. */
    VLT_ECC_ID_K283,

    /** NIST K-409 Koblitz curve. */
    VLT_ECC_ID_K409,

    /** NIST K-571 Koblitz curve. */
    VLT_ECC_ID_K571,

    /** NIST P-192 prime curve. */
    VLT_ECC_ID_P192,

    /** NIST P-224 prime curve. */
    VLT_ECC_ID_P224,

    /** NIST P-256 prime curve. */
    VLT_ECC_ID_P256,

    /** NIST P-384 prime curve. */
    VLT_ECC_ID_P384,

    /** NIST P-521 prime curve. */
    VLT_ECC_ID_P521
} VLT_ECC_ID;

#if (VLT_ENABLE_ECDSA_K571 == VLT_ENABLE) || (VLT_ENABLE_ECDSA_B571 == VLT_ENABLE)
#define MAX_ECC_KEY_BYTES_SIZE	72
#elif (VLT_ENABLE_ECDSA_P521 == VLT_ENABLE) 
#define MAX_ECC_KEY_BYTES_SIZE	68
#elif (VLT_ENABLE_ECDSA_K409 == VLT_ENABLE) || (VLT_ENABLE_ECDSA_B409 == VLT_ENABLE)
#define MAX_ECC_KEY_BYTES_SIZE	52
#elif (VLT_ENABLE_ECDSA_P384 == VLT_ENABLE) 
#define MAX_ECC_KEY_BYTES_SIZE	48
#elif (VLT_ENABLE_ECDSA_K283 == VLT_ENABLE) || (VLT_ENABLE_ECDSA_B283 == VLT_ENABLE)
#define MAX_ECC_KEY_BYTES_SIZE	36
#elif (VLT_ENABLE_ECDSA_P256 == VLT_ENABLE) || (VLT_ENABLE_ECDSA_K233 == VLT_ENABLE) || (VLT_ENABLE_ECDSA_B233 == VLT_ENABLE)
#define MAX_ECC_KEY_BYTES_SIZE	32
#elif (VLT_ENABLE_ECDSA_P224 == VLT_ENABLE) 
#define MAX_ECC_KEY_BYTES_SIZE	28
#elif (VLT_ENABLE_ECDSA_P192 == VLT_ENABLE) || (VLT_ENABLE_ECDSA_K163 == VLT_ENABLE) || (VLT_ENABLE_ECDSA_B163 == VLT_ENABLE)
#define MAX_ECC_KEY_BYTES_SIZE	24
#else
#define MAX_ECC_KEY_BYTES_SIZE	0
#endif
/*******************************************************
 Generic Authentication Defines IDs: 
*******************************************************/
/**
 * \brief Generic Strong Authentication parameter field 
 * bOption, Do not use Identifiers.
 */
#define VLT_GEN_AUTH_DO_NOT_USE_IDENTIFIERS         (VLT_U8)  0x00
/**
 * \brief Generic Strong Authentication parameter field 
 * bOption, Use identifiers in authentication protocol.
 */
#define VLT_GEN_AUTH_USE_IDENTIFIERS                (VLT_U8)  0x01

/*******************************************************
 Returned Data Structures Lengths 
*******************************************************/
#define VLT_FIRMWARE_VERSION_LENGTH                 (VLT_U8)  0x20
#define VLT_FIRMWARE_DATE_LENGTH                    (VLT_U8)  0x14

/** \brief The length in bytes of the serial number */
#define VLT_CHIP_SERIAL_NUMBER_LENGTH               (VLT_U8)  0x08

/** \brief The length in bytes of the SCP03 device challenge. */
#define VLT_SCP03_DEVICE_CHALLENGE_LENGTH           (VLT_U8)  0x08

/** \brief The length in bytes of the SCP cryptogram. */
#define VLT_SCPXX_CRYPTOGRAM_LENGTH                 (VLT_U8)  0x08

/** @cond SHOW_INTERNAL */

#define VLT_INIT_UPDATE_HOST_CHALLENGE_LENGTH       (VLT_U8)  0x08
#define VLT_MAX_CHALLENGE_LENGTH                    (VLT_U8)  0x40
#define VLT_MAX_SIGNATURE_LENGTH                    (VLT_U16)0x200
#define VLT_MAX_IV_LENGTH                           (VLT_U8)  0x10
#define VLT_AES_CMAC_LENGTH                         (VLT_U8)  0x08
#define VLT_KEY_LENGTH_ATTRIBUTE_SIZE               (VLT_U8)  0x02
#define VLT_GCM_IV_LENGTH                           (VLT_U8)  0x0C

#define VLT_TARGET_INFO_LENGTH                      (VLT_U8)  0x35
#if (VLT_ENABLE_GETINFO_EXT == VLT_ENABLE)
#define VLT_TARGET_INFO_LENGTH_EXT                  (VLT_U8)  0x37
#endif


/*******************************************************
 Command Class Byte Defines
*******************************************************/
#define VLT_CLA_NO_CHANNEL                          (VLT_U8)  0x80
#define VLT_CLA_CHANNEL                             (VLT_U8)  0x84
#define VLT_CLA_CHAINING                            (VLT_U8)  0x90
#define VLT_CLA_SCP_BIT                             (VLT_U8)(1u<<2)
#define VLT_CLA_CHAINING_BIT                        (VLT_U8)(1<<4)
                                         
/*******************************************************
 Command Instruction Byte Defines        
*******************************************************/
#define VLT_INS_SUBMIT_PASSWORD                     (VLT_U8)  0x20
#define VLT_INS_INITIALIZE_UPDATE                   (VLT_U8)  0x88
#define VLT_INS_EXTERNAL_AUTHENTICATE_SCP           (VLT_U8)  0x82
#define VLT_INS_EXTERNAL_AUTHENTICATE_MS            (VLT_U8)  0x83
#define VLT_INS_MANAGE_AUTHENTICATION_DATA          (VLT_U8)  0x24
#define VLT_INS_GET_AUTHENTICATION_INFO             (VLT_U8)  0x25
#define VLT_INS_CANCEL_AUTHENTICATION               (VLT_U8)  0x28
#define VLT_INS_GET_CHALLENGE                       (VLT_U8)  0x84
#define VLT_INS_GEN_INTERNAL_AUTHENTICATE           (VLT_U8)  0x89
#if (VLT_ENABLE_API_SUBMIT_SECURE_PASSWORD == VLT_ENABLE)
#define VLT_INS_SUBMIT_SECURE_PASSWORD              (VLT_U8)  0x21
#endif
#define VLT_INS_INITIALIZE_ALGORITHM                (VLT_U8)  0x23
#define VLT_INS_PUT_KEY                             (VLT_U8)  0x47
#define VLT_INS_READ_KEY                            (VLT_U8)  0x48
#define VLT_INS_DELETE_KEY                          (VLT_U8)  0x49
#define VLT_INS_ENCRYPT_DECRYPT                     (VLT_U8)  0x2A
#define VLT_INS_GENERATE_VERIFY_SIGNATURE           (VLT_U8)  0x2C
#define VLT_INS_GENERATE_ASSURANCE_MESSAGE          (VLT_U8)  0x2F
#define VLT_INS_COMPUTE_MESSAGE_DIGEST              (VLT_U8)  0x2B
#define VLT_INS_GENERATE_RANDOM                     (VLT_U8)  0x2D
#define VLT_INS_GENERATE_KEY_PAIR                   (VLT_U8)  0x46
#if (VLT_ENABLE_API_GENERATE_SYMMETRIC_KEY == VLT_ENABLE)
#define VLT_INS_GENERATE_SYM_KEY                    (VLT_U8)  0x4B
#endif
#define VLT_INS_BEGIN_TRANSACTION                   (VLT_U8)  0xFD
#define VLT_INS_END_TRANSACTION                     (VLT_U8)  0xFE
#define VLT_INS_SELECT                              (VLT_U8)  0xA4
#define VLT_INS_LIST_FILES                          (VLT_U8)  0xA5
#define VLT_INS_GET_RESPONSE                        (VLT_U8)  0xC0
#define VLT_INS_CREATE_FILE                         (VLT_U8)  0xCF
#define VLT_INS_CREATE_FOLDER                       (VLT_U8)  0xCD
#define VLT_INS_DELETE_FILE                         (VLT_U8)  0xDF
#define VLT_INS_DELETE_FOLDER                       (VLT_U8)  0xDD
#define VLT_INS_WRITE_FILE                          (VLT_U8)  0xF1
#define VLT_INS_READ_FILE                           (VLT_U8)  0xF0
#define VLT_INS_SEEK_FILE                           (VLT_U8)  0xFC
#define VLT_INS_SET_PRIVILEGES                      (VLT_U8)  0xCB
#define VLT_INS_SET_ATTRIBUTES                      (VLT_U8)  0xCA
#define VLT_INS_GET_INFO                            (VLT_U8)  0x01
#define VLT_INS_SELF_TEST                           (VLT_U8)  0x02
#if (VLT_ENABLE_API_SET_FIPS_LEVEL == VLT_ENABLE)
#define VLT_INS_SET_FIPS_LEVEL	                    (VLT_U8)  0x03
#endif
#if (VLT_ENABLE_API_SET_FIPS_ALGOS == VLT_ENABLE)
#define VLT_INS_SET_FIPS_ALGOS	                    (VLT_U8)  0x04
#endif
#define VLT_INS_SET_STATUS                          (VLT_U8)  0xAA
#if (VLT_ENABLE_API_SET_GPIO_DIRECTION == VLT_ENABLE)
#define VLT_INS_SET_GPIO                            (VLT_U8)  0x32
#endif
#if (VLT_ENABLE_API_READ_GPIO == VLT_ENABLE)
#define VLT_INS_READ_GPIO                           (VLT_U8)  0x34
#endif
#if (VLT_ENABLE_API_WRITE_GPIO == VLT_ENABLE)
#define VLT_INS_WRITE_GPIO                          (VLT_U8)  0x36
#endif
#define VLT_INS_SET_CONFIG                          (VLT_U8)  0xCE
#define VLT_INS_GEN_EXTERNAL_AUTHENTICATE           (VLT_U8)  0x8A
#define VLT_INS_TEST_CASE_1                         (VLT_U8)  0x11
#define VLT_INS_TEST_CASE_2                         (VLT_U8)  0x12
#define VLT_INS_TEST_CASE_3                         (VLT_U8)  0x13
#define VLT_INS_TEST_CASE_4                         (VLT_U8)  0x14

#define VLT_INS_ESTABLISH_KEY_MATERIAL              (VLT_U8)  0x45
#define VLT_INS_DERIVE_KEY                          (VLT_U8)  0x44

#define VLT_DERIVE_KEY_NONCE_MAX_LEN                (VLT_U8)  0x40
#define VLT_DERIVE_KEY_MACTAG_MAX_LEN               (VLT_U8)  0x40

#define VLT_INS_KEY_CONFIRMATION                    (VLT_U8)  0x4A


/*******************************************************
 Initialise Update Defines:
*******************************************************/
#define VLT_INITIALIZE_UPDATE_SCP_RSP_LENGTH        (VLT_U8)  0x1C

#define VLT_SCP_CHIP_SERIAL_OFFSET                  (VLT_U8)  0x00
#define VLT_SCP_CHIP_SERIAL_LENGTH                  (VLT_U8)  0x08
#define VLT_SCP_RFU_OFFSET                          (VLT_U8)  0x08
#define VLT_SCP_RFU_LENGTH                          (VLT_U8)  0x02

#define VLT_SCP_SEQUENCE_CTR_FIELD_LENGTH           (VLT_U8)  0x02
#define VLT_SCP_KEYSET_FIELD_OFFSET                 (VLT_U8)  0x0A
#define VLT_SCP_IDENTIFIER_OFFSET                   (VLT_U8)  0x0B

#define VLT_SCP_CRYPTOGRAM_OFFSET                   (VLT_U8)  0x14
#define VLT_SCP_CRYPTOGRAM_LENGTH                   (VLT_U8)  0x08

#if (VLT_ENABLE_SCP03 == VLT_ENABLE)
#define VLT_SCP_ID_SCP03                            (VLT_U8)  0x03
#define VLT_SCP03_DEVICE_CHALLENGE_OFFSET           (VLT_U8)  0x0C
#endif

/*******************************************************
 External Authenticate Defines:
*******************************************************/
#define VLT_EXTERNAL_AUTH_SCP_LENGTH                (VLT_U8)  0x10

/*******************************************************
 External Authenticate Defines:
*******************************************************/
#define VLT_SECURE_PWD_CHALLENGE_LENGTH             (VLT_U8)  0x08

/*******************************************************
 Manage Authentication Data Defines:
*******************************************************/
#define VLT_AUTH_DATA_HEADER_LENGTH                 (VLT_U8)  0x07
#define VLT_SECRET_KEY_HEADER_LENGTH                (VLT_U8)  0x04

/*******************************************************
 Select File or Directory Data Defines:
*******************************************************/
#define VLT_SF_RESPONSE_LENGTH                      (VLT_U8)  0x09

/*******************************************************
 File System Defines:
*******************************************************/
#define VLT_SEEK_FILE_LENGTH_SIZE                   (VLT_U8)  0x04
#define VLT_FILE_PATH_LENGTH_SIZE                   (VLT_U8)  0x02
#define VLT_FILE_PRIVILEGES_LENGTH                  (VLT_U8)  0x04
#define VLT_FILE_ATTRIBUTES_LENGTH                  (VLT_U8)  0x01

#define VLT_FILE_MAXIMUM_SIZE                       (VLT_U32)0xFFFF

/*******************************************************
 Get Authentication Info Defines:
*******************************************************/
#define VLT_GET_AUTH_INFO_P3                        (VLT_U8)  0x07
#define VLT_GET_AUTH_INFO_METHOD_OFFSET             (VLT_U8)  0x00
#define VLT_GET_AUTH_INFO_ROLE_OFFSET               (VLT_U8)  0x01
#define VLT_GET_AUTH_INFO_SEC_LEVEL_OFFSET          (VLT_U8)  0x02
#define VLT_GET_AUTH_INFO_REM_TRY_CNT_OFFSET        (VLT_U8)  0x03
#define VLT_GET_AUTH_INFO_MAX_TRY_CNT_OFFSET        (VLT_U8)  0x04
#define VLT_GET_AUTH_INFO_SEQUENCE_CNT_OFFSET       (VLT_U8)  0x05
#define VLT_GET_AUTH_INFO_SEQUENCE_CNT_LENGTH       (VLT_U8)  0x02


/*******************************************************
 Generate Assurance Message Defines:
*******************************************************/
#define VLT_GA_SIGNER_ID_LENGTH                     (VLT_U8)  0x08
#define VLT_GA_VERIFIER_ID_LENGTH                   (VLT_U8)  0x08
#define VLT_GA_MESSAGE_LENGTH                       (VLT_U8)  0x50

#define AES_128_KEY_SIZE                            (VLT_U16)16u
#define AES_192_KEY_SIZE                            (VLT_U16)24u
#define AES_256_KEY_SIZE                            (VLT_U16)32u
#define AES_BLOCK_SIZE                              (VLT_U8) 16u
                                     
/*********************************************************
 Status Codes                        
*********************************************************/
#define VLT_STATUS_NONE                             (VLT_SW) 0x0000u
#define VLT_STATUS_GET_RESPONSE                     (VLT_SW) 0x6100u
#define VLT_STATUS_COMPLETED                        (VLT_SW) 0x6200u
#define VLT_STATUS_ABORTED                          (VLT_SW) 0x6300u
#define VLT_STATUS_RESPONDING                       (VLT_SW) 0x6301u
#define VLT_STATUS_REISSUE                          (VLT_SW) 0x6C00u
#define VLT_STATUS_SUCCESS                          (VLT_SW) 0x9000u
#define VLT_STATUS_EOF                              (VLT_SW) 0x9001u

#define VLT_STATUS_NEXT_MESSAGE_PART_EXPECTED       (VLT_SW) 0x6200u
#define VLT_STATUS_NEXT_SIGNATURE_PART_EXPECTED     (VLT_SW) 0x6201u
#define VLT_STATUS_NEXT_TAG_PART_EXPECTED           (VLT_SW) 0x6201u

#define VLT_STATUS_TRANSACTION_MEM_FAILURE          (VLT_SW) 0x6581u

/** \brief Used to initialise the CRC16 CCITT calculation with 0xFFFF */
#define VLT_CRC16_CCITT_INIT_Fs                     (VLT_U16) 0xFFFFu

/** \brief Used to initialise the CRC16 CCITT calculation with 0x0000 */
#define VLT_CRC16_CCITT_INIT_0s                     (VLT_U16) 0x0000u

/** @endcond  */
/**
 *  \brief  Communication mode identifiers
 */
typedef enum {
#ifdef USE_SPI
    /** SPI communication */
    VLT_SPI_COMMS,  
#endif

#ifdef USE_TWI
    /** TWI/I2C communication */
    VLT_TWI_COMMS,  
#endif

#ifdef USE_OWI
    /** OWI communication */
    VLT_OWI_COMMS,  
#endif

#ifdef USE_ISO7816
    /** ISO7816 T=0 communication */
    VLT_ISO_T0_COMMS, 

    /** ISO7816 T=1 communication */
    VLT_ISO_T1_COMMS, 

    /** ISO7816 T=0 or T=1 communication */
    VLT_ISO_T0_OR_T1_COMMS, 

    /** USB communication */
    VLT_USB_COMMS     
#endif

} VLT_COMM_MODE;

#if (VLT_PLATFORM == VLT_WINDOWS)
typedef enum enInterfaceTypes
{
#if(VLT_ENABLE_ISO7816 == VLT_ENABLE )  
    INTERFACE_PCSC = 10,
#endif

#if(VLT_ENABLE_WISEBOARD == VLT_ENABLE )  
#if(VLT_ENABLE_SPI == VLT_ENABLE )  
    INTERFACE_WISEBOARD_SPI = 40,
#endif
#if(VLT_ENABLE_TWI == VLT_ENABLE )  
    INTERFACE_WISEBOARD_I2C = 50,
#endif
#endif
} COMM_INTERFACE_T;
#endif

/** 
 * \brief User authentication states 
 */
typedef enum {
    /** User has not successfully logged in */
    VLT_USER_NOT_AUTHENTICATED                              = 0x00 ,   
    
    /* \User has successfully logged in */
    VLT_USER_AUTHENTICATED                                  = 0x01     
} VLT_AUTH_STATE;


/**
  * \brief Set Config parameters
  */
typedef enum {
#if (VAULT_IC_VERSION == VAULTIC_408_1_X_X)
    VLT_SET_CFG_LEGACY_MODE                                 = 0x10,
#endif

#if ((VAULT_IC_VERSION == VAULTIC_407_1_0_X)||(VAULT_IC_VERSION == VAULTIC_408_1_X_X))
    VLT_SET_CFG_BACK_TO_RX_TIMEOUT                          = 0x93,
#endif
#if ((VAULT_IC_VERSION == VAULTIC_420_1_2_X)||(VAULT_IC_VERSION == VAULTIC_405_1_X_X))
    /** USB Vendor ID, Product ID and Device ID - 6 bytes */
    VLT_SET_CFG_USB_VENDORID_PRODUCTID_DEVICEID             = 0x81 ,

    /** USB Attributes - 1 byte */
    VLT_SET_CFG_USB_ATTRIBUTES                              = 0x82 ,
    
    /** USB String Manufacturer - max 132 bytes (65 unicode chars) */
    VLT_SET_CFG_USB_MANUFACTURER_STRING                     = 0x83 ,

    /** USB String Product - max 68 bytes (33 unicode chars) */
    VLT_SET_CFG_USB_PRODUCT_STRING                          = 0x84 ,

    /** USB String Configuration - max 132 bytes (65 unicode chars) */
    VLT_SET_CFG_USB_CONFIG_STRING                           = 0x85 ,

    /** USB String Interface - max 254 bytes (126 unicode chars) */
    VLT_SET_CFG_USB_INTERFACE_STRING                        = 0x86 ,

    /**USB String Serial Number - max 68 bytes (33 unicode chars) */
    VLT_SET_CFG_USB_SERIAL_NUMBER_STRING                    = 0x87 ,

    /** USB Max Power - 1 byte */
    VLT_SET_CFG_USB_MAX_POWER                               = 0x89 ,

   /** LED blinking configuration - 1 byte */
    VLT_SET_CFG_LED_BLINKING                                = 0x8D,

    /** USB CCID ATR - max 15 bytes as historical bytes of the ATR */
    VLT_SET_CFG_CHANGE_ATR                                  = 0x90 ,

    /** GPIOs access mode - 1 byte */
    VLT_SET_CFG_GPIO_ACCESS_MODE                            = 0xCC ,
#endif

    /** Communication Channel - 1 byte */
    VLT_SET_CFG_COMMUNICATION_CHANNEL	                    = 0x88 ,

    /** Shorter I2C timeout (200ms) - 1 byte */
    VLT_SET_CFG_USE_SHORT_TWI_TIMEOUT                       = 0x8A ,

    /** I2C Timeout duration configuration - 2 bytes (Unit is 1ms) */
    VLT_SET_CFG_I2C_BUS_INACTIVITY_DETECTION_DURATION       = 0x8E ,

    /** Attack Counter Configuration - 2 bytes */
    VLT_SET_CFG_ATTACK_COUNTER_CONFIG                       = 0xAC ,

    /** SPI Sleep Mode - 1 byte */
    VLT_SET_CFG_SPI_POWER_SAVING_MODE                       = 0xCA ,

    /** I2C Address - 1 byte */
    VLT_SET_CFG_I2C_ADDRESS                                 = 0xCB ,

    /** Administrator Security Policy - 1 byte */
    VLT_SET_CFG_ADMIN_SECURITY_POLICY                       = 0x01 ,

    /** Power-on self-tests mode - 1 byte */
    VLT_SET_CFG_POWERON_SELFTESTS_MODE                      = 0x02 ,

} VLT_SET_CFG;

/* Security policy */
typedef enum
{
    VLT_SET_CFG_ADMIN_SECURITY_POLICY_USER_AUTHEN_DATA_DEF_ENABLE = 0x00,  /* Administrators can redefine users authentication data (default) */
    VLT_SET_CFG_ADMIN_SECURITY_POLICY_USER_AUTHEN_DATA_DEF_DISABLE = 0x01, /* Administrators cannot redefine users authentication data */
} VLT_SET_CFG_ADMIN_SECURITY_POLICY_VALUES;

/**
  * \brief Size of Set Config parameters
  */
typedef enum {
#if (VAULT_IC_VERSION == VAULTIC_408_1_X_X)
    VLT_SET_CFG_LEGACY_MODE_SZ                              = 0x01,
#endif

#if ((VAULT_IC_VERSION == VAULTIC_407_1_0_X)||(VAULT_IC_VERSION == VAULTIC_408_1_X_X))
    VLT_SET_CFG_BACK_TO_RX_TIMEOUT_SZ                       = 0x02,
#endif

#if ((VAULT_IC_VERSION == VAULTIC_420_1_2_X)||(VAULT_IC_VERSION == VAULTIC_405_1_X_X))
    VLT_SET_CFG_USB_VENDORID_PRODUCTID_DEVICEID_SZ          = 0x06,
    VLT_SET_CFG_USB_ATTRIBUTES_SZ                           = 0x01,
    VLT_SET_CFG_USB_MAX_POWER_SZ                            = 0x01 ,
    VLT_SET_CFG_GPIO_ACCESS_MODE_SZ                         = 0x01 ,
    VLT_SET_CFG_LED_BLINKING_SZ                             = 3,
    VLT_SET_CFG_USB_MANUFACTURER_STRING_SZ                  = 132,
    VLT_SET_CFG_USB_PRODUCT_STRING_SZ                       = 68,
    VLT_SET_CFG_USB_CONFIG_STRING_SZ                        = 132,
    VLT_SET_CFG_USB_INTERFACE_STRING_SZ                     = 254,
    VLT_SET_CFG_USB_SERIAL_NUMBER_STRING_SZ                 = 68,
    VLT_SET_CFG_CHANGE_ATR_SZ                               = 15,

#endif
    VLT_SET_CFG_COMMUNICATION_CHANNEL_SZ                    = 0x01 ,
    VLT_SET_CFG_I2C_ADDRESS_SZ                              = 0x01 ,
    VLT_SET_CFG_USE_SHORT_TWI_TIMEOUT_SZ                    = 0x01 ,
    VLT_SET_CFG_SPI_POWER_SAVING_MODE_SZ                    = 0x01 ,
    VLT_SET_CFG_ATTACK_COUNTER_CONFIG_SZ                    = 0x02,
    VLT_SET_CFG_POWERON_SELFTESTS_MODE_SZ                   = 0x01,
    VLT_SET_CFG_I2C_BUS_INACTIVITY_DETECTION_DURATION_SZ    = 0x02 ,
    VLT_SET_CFG_ADMIN_SECURITY_POLICY_SZ                    = 0x01
} VLT_SET_CFG_SZ;

/** @cond SHOW_INTERNAL */
#define VLT_PRIVATE_EXPONENT                        (VLT_U8)  0x00
#define VLT_CRT                                     (VLT_U8)  0x01
/** @endcond  */

/*******************************************************
File System Service definitions
*******************************************************/
/** \brief Create a file within the file system */
#define VLT_FILE_ENTRY                              (VLT_U8)  0x00

/** \brief Create a folder within the file system */
#define VLT_FOLDER_ENTRY                            (VLT_U8)  0x01

/** \brief Seek from the start of the file */
#define VLT_SEEK_FROM_START                         (VLT_U8)  0x00

/** \brief Seek to the end of the file */
#define VLT_SEEK_TO_END                             (VLT_U32)0xFFFFFFFFu

/**
* \brief Number of microseconds in a millisecond
*/
#define VLT_MICRO_SECS_IN_MSEC                      (VLT_U32)1000


/******************************************************
 Secure Channel definitions
 ******************************************************/
 /** @cond SHOW_INTERNAL */
#define SCPXX_MAX_SESSION_KEY_LEN                   (VLT_U8)  0x20
#define SCPXX_MAX_CMAC_LEN                          (VLT_U8)  0x10
#define SCPXX_MAX_RMAC_LEN                          (VLT_U8)  0x10

/** @endcond  */
#endif /* VAULTIC_CONSTS_H */

/**@}*/
