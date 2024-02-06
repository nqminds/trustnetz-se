/**
* @file	   vaultic_options.h
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
* @brief Customer configuration options for the VaultIC API.
*
* @par Description:
* This file presents the options which are available to the client when
* configuring the VaultIC API.
*/

#ifndef VAULTIC_OPTIONS_H
#define VAULTIC_OPTIONS_H

/*
 * ------------------
 * Platform Options
 * ------------------
 *
 * Please set the VLT_PLATFORM macro in vaultic_config.h.
 */
#define VLT_WINDOWS                 0
#define VLT_EMBEDDED                1

/**
 * Vault IC products definition
 */

///////////////////////////////////////////////////////////////////
// VaultIC 1XX family
///////////////////////////////////////////////////////////////////
#define VAULTIC_155                 155
#define VAULTIC_183                 183
#define VAULTIC_186                 186
#define VAULTIC_187                 187


///////////////////////////////////////////////////////////////////
// VaultIC 2XX family
///////////////////////////////////////////////////////////////////
#define VAULTIC_292                 292


///////////////////////////////////////////////////////////////////
// VaultIC 4XX family
///////////////////////////////////////////////////////////////////
#define VAULTIC_420_1_2_X           420
#define VAULTIC_405_1_X_X           405
#define VAULTIC_407_1_0_X           407
#define VAULTIC_408_1_X_X           408

/** 
 * Conditional Compilation Options
 */
#define VLT_ENABLE                  1   
#define VLT_DISABLE                 0   

/**
 * Vault IC target macros
 */
#define VAULTIC4XX					1
#define VAULTIC1XX					2
#define VAULTIC2XX                  3

/*
 * Host crypto macros
*/
#define HOST_CRYPTO_NONE            0 // No Host Crypto operation required
#define HOST_CRYPTO_OPENSSL         1 // Delegate all host crypto operations to openssl 
#define HOST_CRYPTO_ARM_CRYPTO_LIB  2 // Delegate all ECDSA crypto operations to ARM Crypto library

#endif /*VAULTIC_OPTIONS_H*/

