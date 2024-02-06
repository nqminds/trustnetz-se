/**
* @file	   vaultic_cipher.h
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

#ifndef VAULTIC_CIPHER_H
#define VAULTIC_CIPHER_H
/**
 * 
 * \brief The common cipher interface. 
 * 
 * \par Description
 * This file declares the common cipher interface, all ciphers supported by 
 * the Vault IC adhere to this interface. It allows further ciphers to be added
 * without affecting existing code.
 */





#ifdef __cplusplus
    extern "C"
    {
#endif

    /**

     * \brief Initialises the underlying cipher.
     *
     * \par Description
     * This method initialises the underlying cipher for use in the mode specified by
     * the opMode parameter, using the secret key specified by the pKey parameter and 
     * configured by the pParams parameter.
     * Once a cipher has been initialised in can only be used in the mode specified, 
     * e.g. if the cipher was initialised for encryption then only encrypt operations 
     * can be carried out. To use the cipher for decryption the CipherInit method with
     * the appropriate parameters should be called before decryption operations can 
     * take place.
     *
     * \param[in]  opMode   The Operational mode VLT_CIPHER_ENCRYPT for encryption  
     *                      otherwise VLT_CIPHER_DECRYPT for decryption.
     * 
     * \param[in]  pKey     The key used to initialise the cipher see VLT_KEY_BLOB 
     *                      structure for further information.
     * 
     * \param[in]  pParams  This parameter configures the cipher to operate in a 
     *                      required mode. 
     *
     * \return Status
     */
    VLT_STS CipherInit(VLT_ALGO_MODE opMode, const VLT_KEY_BLOB *pKey, const VLT_CIPHER_PARAMS *pParams );

    /**
     * \brief Releases resources used.
     *
     * \par Description
     * This method clears any residual data used by the underlying cipher. 
     * It must be called at the end of an encrypt or decrypt sequence.
     *
     * \return Status
     */
    VLT_STS CipherClose( void );

    /**
     *
     * \brief Performs the last step of the encryption/decryption process.
     *
     * \par Description
     * This method performs the last step of the encryption or decryption depending
     * on the mode of operation specified during a call to the CipherInit method. 
     * Once the call to the CipherDoFinal has completed no more encryption/decryption
     * operations can take place until a further call to the CipherInit method has 
     * been issued.
     * Depending on how the cipher was configured during the call to the CipherInit
     * method, if a the padding method selected was VLT_PADDING_NONE and the block of 
     * data passed in was not multiple of the block size of the underlying cipher the
     * the call will fail with the appropriate error code.
     *
     * \param[in]  pDataIn         The array of data to be encrypted/decrypted.
     * 
     * \param[in]  DataInLen       The length of the array of data to be encrypted/decrypted.
     * 
     * \param[in]  dataInCapacity  The capacity of the array of data to be encrypted/decrypted.
     *
     * \param[out] pDataOut        The array of data that will hold the result of the 
     *                             encryption/decryption.
     * 
     * \param[out] pDataOutLen     The length of the array of data that holds the result of the 
     *                             encryption/decryption.
     *
     * \param[in]  dataOutCapacity The capacity of the array of data that holds the result of the 
     *                             encryption/decryption.
     *
     * \return Status
     */ 
    VLT_STS CipherDoFinal( 
        VLT_U8 *pDataIn,
        VLT_U32 DataInLen, 
        VLT_U32 dataInCapacity, 
        VLT_U8 *pDataOut, 
        VLT_U32 *pDataOutLen, 
        VLT_U32 dataOutCapacity );

    /**
     *
     * \brief Performs part of the encryption/decryption process.
     *
     * \par Description
     * This method performs part of the encryption/decryption process, this method is provided
     * in aid of the scenario where the data to be processed are not contiguous but need 
     * to be processed in smaller chunks due to target memory storage constraints. This method
     * can only be called once a call to the CipherInit method has completed successfully.
     * This method can be called multiple times.
     * Please note, this method only process data of length equal or multiple of the underlying 
     * cipher block size. The block size can be determined by making a call to the CipherGetBlockSize
     * method. If a the DataInLen specified isn't equal or multiple of the block size then the 
     * method will return the appropriate error code.
     *
     * \param[in]  pDataIn         The array of data to be encrypted/decrypted.
     * 
     * \param[in]  DataInLen       The length of the array of data to be encrypted/decrypted.
     * 
     * \param[out] pDataOut        The array of data that will hold the result of the 
     *                             encryption/decryption.
     * 
     * \param[out] pDataOutLen     The length of the array of data that holds the result of the 
     *                             encryption/decryption.
     *
     * \param[in]  dataOutCapacity The capacity of the array of data that holds the result of the 
     *                             encryption/decryption.
     *
     * \return Status
     */ 
    VLT_STS CipherUpdate( 
        VLT_U8 *pDataIn,
        VLT_U32 DataInLen, 
        VLT_U8 *pDataOut, 
        VLT_U32 *pDataOutLen, 
        VLT_U32 dataOutCapacity );

    /**
     * \fn CipherGetBlockSize
     *
     * \brief Returns the underlying cipher block size.
     *   
     * \return The underlying cipher block size.
     */
    VLT_U16 CipherGetBlockSize( void );

#ifdef __cplusplus
    };
#endif


#endif//VAULTIC_CIPHER_H
