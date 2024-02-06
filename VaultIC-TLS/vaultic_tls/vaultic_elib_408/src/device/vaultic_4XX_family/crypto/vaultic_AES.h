/**
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
*/

/**
 * 
 * \brief Implementation of the AES Cipher based on the common cipher interface. 
 * 
 * \par Description
 * This file declares the specific AES cipher methods that Implement the AES 
 * cipher based on the common cipher interface. \see vaultic_cipher
 */
#ifndef VAULTIC_AES_H
#define VAULTIC_AES_H

#ifdef __cplusplus
    extern "C"
    {
#endif

    /**
     * \fn AesInit( VLT_U8 opMode, const VLT_KEY_BLOB *pKey, VLT_U8 *pParams )
     *
     * \brief Initialises the AES cipher.
     *
     * \par Description
     * This method is the AES concrete implementation of the CipherInit method of the
     * common cipher interface. \see CipherInit.
     *
     * \return Status
     */
    VLT_STS AesInit(VLT_ALGO_MODE opMode, const VLT_KEY_BLOB *pKey, VLT_U8 *pParams );

    /**
     * \fn AesClose( void )
     *
     * \brief Releases resources used by the AES Cipher.
     *
     * \par Description
     * This method is the AES concrete implementation of the CipherClose method of the
     * common cipher interface. \see CipherClose.
     *
     * \return Status
     */
    VLT_STS AesClose( void );

    /**
     *
     * \brief Performs the last step of the encryption/decryption process for the AES cipher.
     *
     * \par Description
     * This method is the AES concrete implementation of the CipherDoFinal method of the
     * common cipher interface. \see CipherDoFinal.
     *
     * \return Status
     */
    VLT_STS AesDoFinal(const VLT_U8 *pDataIn, VLT_U32 DataInLen, VLT_U8 *pDataOut, VLT_U32 *pDataOutLen );

    /**
     * \brief Performs part of the encryption/decryption process for the AES cipher.
     *
     * \par Description
     * This method is the AES concrete implementation of the CipherUpdate method of the
     * common cipher interface. \see CipherUpdate.
     *
     * \return Status
     */
    VLT_STS AesUpdate(const VLT_U8 *pDataIn, VLT_U32 DataInLen, VLT_U8 *pDataOut, VLT_U32 *pDataOutLen );

    /**
     * \fn AesGetBlockSize
     *
     * \brief Returns the AES cipher block size.
     *
     * \par Description
     * This method is the AES concrete implementation of the CipherGetBlockSize method of the
     * common cipher interface. \see CipherGetBlockSize.
     *
     * \return Status
     */
    VLT_U16 AesGetBlockSize( void );
    VLT_STS AesTest( void );

#if( VLT_ENABLE_CIPHER_TESTS == VLT_ENABLE )
	VLT_STS Aes128Key( void );
	VLT_STS Aes192Key( void );
	VLT_STS Aes256Key( void );
#endif

#ifdef __cplusplus
    };
#endif


#endif//VAULTIC_AES_H
