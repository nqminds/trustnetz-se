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
 * @brief   VaultIC API Configuration file
 *
 * @details
 */
 
/////////////////////////////////////////////////////////////////////////////////////////////
//     WARNING: This configuration applies only for VAULTIC 408                            //
/////////////////////////////////////////////////////////////////////////////////////////////


#ifndef VAULTIC_API_CONFIG_H_
#define VAULTIC_API_CONFIG_H_

///////////////////////////////////////////////////////////////////////////
//                   SET YOUR  CUSTOM CONFIGURATION HERE                 //
///////////////////////////////////////////////////////////////////////////

/**
*   Uncomment the platform you want to use
*/
//#define VLT_PLATFORM        VLT_WINDOWS
//#define VLT_PLATFORM        VLT_EMBEDDED

/**
*   Uncomment the protocol you want to use (it also could be defined by PREPROCESSOR variable)
*/
//#define USE_SPI
//#define USE_TWI

/**
*   Uncomment the crypto library you want to use for host crypto operations (if required) (it also could be defined by PREPROCESSOR variable)
*/
//#define USE_OPENSSL_CRYPTO        /* Open SSL crypto library */
//#define USE_FAST_ARM_CRYPTO       /* Crypto library optimized for ARM cortex processors */

/**
*   Uncomment the required hardware control options
*/
//#define VCC_CTRL_BY_GPIO          /* control VaultIC VCC with a GPIO pin */
//#define RST_CTRL_BY_GPIO	        /* control VaultIC RST with a GPIO pin */

/**
*   SET YOUR CRYPTOGRAPHIC FEATURES HERE
*   Edit following parameters by setting each parameters to 
*     - VLT_ENABLE : To embed the source code related to the feature in the lib
*     - VLT_DISABLE : To discard the source code related to the feature in the lib
*/
#ifndef USE_FAST_ARM_CRYPTO
#define VLT_ENABLE_ECDSA_B163                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_B233                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_B283                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_B409                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_B571                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_K163                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_K233                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_K283                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_K409                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_K571                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_P192                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_P224                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_P256                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_P384                           VLT_ENABLE
#define VLT_ENABLE_ECDSA_P521                           VLT_ENABLE
#else
/* Provided ARM crypto library only supports B163 curve           */
#define VLT_ENABLE_ECDSA_B163                           VLT_ENABLE
#endif

#define VLT_ENABLE_SHA224                               VLT_ENABLE
#define VLT_ENABLE_SHA256                               VLT_ENABLE
#define VLT_ENABLE_SHA384                               VLT_ENABLE
#define VLT_ENABLE_SHA512                               VLT_ENABLE

#define VLT_ENABLE_FAST_CRC16CCIT                       VLT_ENABLE

//////////////////////////////////////////////////////////////////
//                  END OF YOUR CUSTOM CONFIGURATION            //
//////////////////////////////////////////////////////////////////

#endif // VAULTIC_API_CONFIG_H_


