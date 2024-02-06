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
 *
 * @brief   VaultIC API Product Definition file
 *
 * @details
 */

#ifndef VAULTIC_API_PRODUCT_DEFINITION_H_
#define VAULTIC_API_PRODUCT_DEFINITION_H_

//////////////////////////////////////////////////////////////////
//                DO NOT EDIT FOLLOWING CODE                    //
//////////////////////////////////////////////////////////////////

#define VLT_ENABLE_PUT_KEY_RAW                          VLT_ENABLE
#define VLT_ENABLE_PUT_KEY_SECRET                       VLT_ENABLE
#define VLT_ENABLE_PUT_KEY_ECC_PUB                      VLT_ENABLE
#define VLT_ENABLE_PUT_KEY_ECC_PRIV                     VLT_ENABLE
#define VLT_ENABLE_PUT_KEY_ECC_PARAMS                   VLT_ENABLE
#define VLT_ENABLE_PUT_KEY_IDENTIFIER                   VLT_ENABLE

#define VLT_ENABLE_READ_KEY_RAW                         VLT_ENABLE
#define VLT_ENABLE_READ_KEY_SECRET                      VLT_ENABLE
#define VLT_ENABLE_READ_KEY_ECC_PUB                     VLT_ENABLE
#define VLT_ENABLE_READ_KEY_ECC_PRIV                    VLT_ENABLE
#define VLT_ENABLE_READ_KEY_ECC_PARAMS                  VLT_ENABLE
#define VLT_ENABLE_READ_KEY_IDENTIFIER                  VLT_ENABLE

#define VLT_ENABLE_GETINFO_EXT                          VLT_ENABLE

#define VLT_ENABLE_KEY_SECRET                           VLT_ENABLE
#define VLT_ENABLE_KEY_HOTP                             VLT_ENABLE
#define VLT_ENABLE_KEY_RSA                              VLT_ENABLE
#define VLT_ENABLE_KEY_ECDSA                            VLT_ENABLE
#define VLT_ENABLE_KEY_IDENTIFIER                       VLT_ENABLE
#define VLT_ENABLE_CIPHER_AES                           VLT_ENABLE
#define VLT_ENABLE_CIPHER_AES_GCM                       VLT_ENABLE
#define VLT_ENABLE_CIPHER_AES_NIST                      VLT_ENABLE
#define VLT_ENABLE_CIPHER_AES_P25                       VLT_ENABLE
#define VLT_ENABLE_CIPHER_RSA                           VLT_ENABLE
#define VLT_ENABLE_SIGN_xDSA                            VLT_ENABLE
#define VLT_ENABLE_SIGN_GMAC                            VLT_ENABLE
#define VLT_ENABLE_SIGN_RSA                             VLT_ENABLE
#define VLT_ENABLE_SIGN_CMAC                            VLT_ENABLE
#define VLT_ENABLE_SIGN_HMAC                            VLT_ENABLE
#define VLT_ENABLE_ECDH                                 VLT_ENABLE
#define VLT_ENABLE_SCP03                                VLT_ENABLE
#define VLT_ENABLE_VAULTIC_CRC16                        VLT_ENABLE
#define VLT_ENABLE_API_GET_LIB_INFO                     VLT_ENABLE
#define VLT_ENABLE_API_SUBMIT_PASSWORD                  VLT_ENABLE
#define VLT_ENABLE_API_INITIALIZE_UPDATE                VLT_ENABLE
#define VLT_ENABLE_API_EXTERNAL_AUTHENTICATE            VLT_ENABLE
#define VLT_ENABLE_API_MANAGE_AUTHENTICATION_DATA       VLT_ENABLE
#define VLT_ENABLE_API_GET_AUTHENTICATION_INFO          VLT_ENABLE
#define VLT_ENABLE_API_CANCEL_AUTHENTICATION            VLT_ENABLE
#define VLT_ENABLE_API_GET_CHALLENGE                    VLT_ENABLE
#define VLT_ENABLE_API_GENERIC_INTERNAL_AUTHENTICATE    VLT_ENABLE
#define VLT_ENABLE_API_GENERIC_EXTERNAL_AUTHENTICATE    VLT_ENABLE
#define VLT_ENABLE_API_INITIALIZE_ALGORITHM             VLT_ENABLE
#define VLT_ENABLE_API_UNINITIALIZE_ALGORITHM           VLT_ENABLE
#define VLT_ENABLE_API_PUT_KEY                          VLT_ENABLE
#define VLT_ENABLE_API_READ_KEY                         VLT_ENABLE
#define VLT_ENABLE_API_DELETE_KEY                       VLT_ENABLE
#define VLT_ENABLE_API_ENCRYPT                          VLT_ENABLE
#define VLT_ENABLE_API_DECRYPT                          VLT_ENABLE
#define VLT_ENABLE_API_GENERATE_ASSURANCE_MESSAGE       VLT_ENABLE
#define VLT_ENABLE_API_GENERATE_SIGNATURE               VLT_ENABLE
#define VLT_ENABLE_API_VERIFY_SIGNATURE                 VLT_ENABLE
#define VLT_ENABLE_API_COMPUTE_MESSAGE_DIGEST           VLT_ENABLE
#define VLT_ENABLE_API_GENERATE_RANDOM                  VLT_ENABLE
#define VLT_ENABLE_API_GENERATE_KEY_PAIR                VLT_ENABLE
#define VLT_ENABLE_API_BEGIN_TRANSACTION                VLT_ENABLE
#define VLT_ENABLE_API_END_TRANSACTION                  VLT_ENABLE
#define VLT_ENABLE_API_SELECT_FILE_OR_DIRECTORY         VLT_ENABLE
#define VLT_ENABLE_API_LIST_FILES                       VLT_ENABLE
#define VLT_ENABLE_API_CREATE_FILE                      VLT_ENABLE
#define VLT_ENABLE_API_CREATE_FOLDER                    VLT_ENABLE
#define VLT_ENABLE_API_DELETE_FILE                      VLT_ENABLE
#define VLT_ENABLE_API_DELETE_FOLDER                    VLT_ENABLE
#define VLT_ENABLE_API_WRITE_FILE                       VLT_ENABLE
#define VLT_ENABLE_API_READ_FILE                        VLT_ENABLE
#define VLT_ENABLE_API_SEEK_FILE                        VLT_ENABLE
#define VLT_ENABLE_API_SET_PRIVILEGES                   VLT_ENABLE
#define VLT_ENABLE_API_SET_ATTRIBUTES                   VLT_ENABLE
#define VLT_ENABLE_API_GET_INFO                         VLT_ENABLE
#define VLT_ENABLE_API_SELF_TEST                        VLT_ENABLE
#define VLT_ENABLE_API_SET_STATUS                       VLT_ENABLE
#define VLT_ENABLE_API_SET_CONFIG                       VLT_ENABLE
#define VLT_ENABLE_API_TEST_CASE1                       VLT_ENABLE
#define VLT_ENABLE_API_TEST_CASE2                       VLT_ENABLE
#define VLT_ENABLE_API_TEST_CASE3                       VLT_ENABLE
#define VLT_ENABLE_API_TEST_CASE4                       VLT_ENABLE
#define VLT_ENABLE_API_UPDATE_SIGNATURE                 VLT_ENABLE
#define VLT_ENABLE_API_COMPUTE_SIGNATURE_FINAL          VLT_ENABLE
#define VLT_ENABLE_API_UPDATE_VERIFY                    VLT_ENABLE
#define VLT_ENABLE_API_COMPUTE_VERIFY_FINAL             VLT_ENABLE
#define VLT_ENABLE_API_UPDATE_MESSAGE_DIGEST            VLT_ENABLE
#define VLT_ENABLE_API_COMPUTE_MESSAGE_DIGEST_FINAL     VLT_ENABLE
#define VLT_ENABLE_API_DERIVE_KEY                       VLT_ENABLE
#define VLT_ENABLE_API_CONSTRUCT_AGREEMENT              VLT_ENABLE
#define VLT_ENABLE_API_KEY_CONFIRMATION                 VLT_ENABLE
#define VLT_ENABLE_API_SUBMIT_SECURE_PASSWORD           VLT_ENABLE
#define VLT_ENABLE_API_SET_FIPS_LEVEL                   VLT_ENABLE
#define VLT_ENABLE_API_SET_FIPS_ALGOS                   VLT_ENABLE
#define VLT_ENABLE_API_GENERATE_SYMMETRIC_KEY           VLT_ENABLE
#define VLT_ENABLE_AT_AUTH_INIT                         VLT_ENABLE
#define VLT_ENABLE_AT_AUTH_CLOSE                        VLT_ENABLE
#define VLT_ENABLE_AT_AUTH_GET_STATE                    VLT_ENABLE
#define VLT_ENABLE_KEY_WRAPPING                         VLT_ENABLE
#define VLT_ENABLE_KW_WRAPPING_INIT                     VLT_ENABLE
#define VLT_ENABLE_KW_WRAPPING_CLOSE                    VLT_ENABLE
#define VLT_ENABLE_KW_WRAP_KEY                          VLT_ENABLE
#define VLT_ENABLE_KW_UNWRAP_KEY                        VLT_ENABLE
#define VLT_ENABLE_IDENTITY_AUTH                        VLT_ENABLE
#define VLT_ENABLE_FILE_SYSTEM                          VLT_ENABLE
#define VLT_ENABLE_FS_CLOSE_FILE                        VLT_ENABLE
#define VLT_ENABLE_FS_CREATE                            VLT_ENABLE
#define VLT_ENABLE_FS_DELETE                            VLT_ENABLE
#define VLT_ENABLE_FS_LIST_FILES                        VLT_ENABLE
#define VLT_ENABLE_FS_OPEN_FILE                         VLT_ENABLE
#define VLT_ENABLE_FS_READ_FILE                         VLT_ENABLE
#define VLT_ENABLE_FS_SET_ATTRIBUTES                    VLT_ENABLE
#define VLT_ENABLE_FS_SET_PRIVILEGES                    VLT_ENABLE
#define VLT_ENABLE_FS_WRITE_FILE                        VLT_ENABLE
#define VLT_ENABLE_BLOCK_PROTOCOL                       VLT_ENABLE
#define VLT_ENABLE_SEC_PWD                              VLT_ENABLE
#define VLT_ENABLE_FIPS_ALGOS                           VLT_ENABLE
#define VLT_ENABLE_NO_WRAPKEY_CRC                       VLT_ENABLE
#define VLT_ENABLE_NO_SELF_TESTS_DELAY                  VLT_ENABLE


#if defined USE_OPENSSL_CRYPTO
// Delegate all crypto operations to openssl
#define HOST_CRYPTO                                     HOST_CRYPTO_OPENSSL

#elif defined  USE_FAST_ARM_CRYPTO
// Delegate all ECDSA crypto operations to provided ARM crypto library
#define HOST_CRYPTO                                     HOST_CRYPTO_ARM_CRYPTO_LIB

#else
// No Host Cryptography required
#define HOST_CRYPTO                                     HOST_CRYPTO_NONE
#endif

#ifdef USE_FAST_ARM_CRYPTO
/* Provided ARM crypto library only supports B163 curve           */
#define VLT_ENABLE_ECDSA_B233                           VLT_DISABLE
#define VLT_ENABLE_ECDSA_B283                           VLT_DISABLE
#define VLT_ENABLE_ECDSA_B409                           VLT_DISABLE
#define VLT_ENABLE_ECDSA_B571                           VLT_DISABLE
#define VLT_ENABLE_ECDSA_K163                           VLT_DISABLE
#define VLT_ENABLE_ECDSA_K233                           VLT_DISABLE
#define VLT_ENABLE_ECDSA_K283                           VLT_DISABLE
#define VLT_ENABLE_ECDSA_K409                           VLT_DISABLE
#define VLT_ENABLE_ECDSA_K571                           VLT_DISABLE
#define VLT_ENABLE_ECDSA_P192                           VLT_DISABLE
#define VLT_ENABLE_ECDSA_P224                           VLT_DISABLE
#define VLT_ENABLE_ECDSA_P256                           VLT_DISABLE
#define VLT_ENABLE_ECDSA_P384                           VLT_DISABLE
#define VLT_ENABLE_ECDSA_P521                           VLT_DISABLE
#endif

/* VLT_ENABLE_ECDSA must be disabled if all VLT_ENABLE_ECDSA_* are disabled */
#define VLT_ENABLE_ECDSA                               (VLT_ENABLE_ECDSA_B163||\
														VLT_ENABLE_ECDSA_B233||\
                                                        VLT_ENABLE_ECDSA_B283||\
                                                        VLT_ENABLE_ECDSA_B409||\
                                                        VLT_ENABLE_ECDSA_B571||\
                                                        VLT_ENABLE_ECDSA_K163||\
                                                        VLT_ENABLE_ECDSA_K233||\
                                                        VLT_ENABLE_ECDSA_K283||\
                                                        VLT_ENABLE_ECDSA_K409||\
                                                        VLT_ENABLE_ECDSA_K571||\
                                                        VLT_ENABLE_ECDSA_P192||\
                                                        VLT_ENABLE_ECDSA_P224||\
                                                        VLT_ENABLE_ECDSA_P256||\
                                                        VLT_ENABLE_ECDSA_P384||\
                                                        VLT_ENABLE_ECDSA_P521)


/* VLT_ENABLE_SHA must be disabled if all VLT_ENABLE_SHA_* are disabled */
#define VLT_ENABLE_SHA  (VLT_ENABLE_SHA224 || VLT_ENABLE_SHA256 || VLT_ENABLE_SHA384 || VLT_ENABLE_SHA512)

#ifdef USE_WISEBOARD
#define VLT_ENABLE_WISEBOARD                            VLT_ENABLE  
#else
#define VLT_ENABLE_WISEBOARD                            VLT_DISABLE 
#endif

#ifdef USE_SPI
#define VLT_ENABLE_SPI                                  VLT_ENABLE
#else
#define VLT_ENABLE_SPI                                  VLT_DISABLE
#endif

#ifdef USE_TWI
#define VLT_ENABLE_TWI                                  VLT_ENABLE
#else
#define VLT_ENABLE_TWI                                  VLT_DISABLE
#endif

#define VAULT_IC_TARGET                                 VAULTIC4XX

// Select platform automatically
#ifdef _WIN32
#define VLT_PLATFORM                                    VLT_WINDOWS
#else
#define VLT_PLATFORM                                	VLT_EMBEDDED
#endif

#endif // VAULTIC_API_PRODUCT_DEFINITION_H_


