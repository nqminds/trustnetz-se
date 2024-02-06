/**
* @file
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
* @brief   X509 Certificate parser module
*
*/

#include "vaultic_common.h"
#include "certificate_typedef.h"


/**
* @brief X509_CERT_Get_Certificate
* @param[in]  in_x509_certificate buffer containing the X509 certificate
* @param[out] out_x509_certificate 
                - offset (in in_x509_certificate buffer) of the value field of the X509 certificate sequence
                - length of the value field of the of the X509 certificate sequence
* @return VLT_OK    success
* @return VLT_FAIL  parsing error
*/
VLT_STS X509_CERT_Get_Certificate(const VLT_U8 *in_x509_certificate, CertField *out_x509_certificate);

/**
* @brief X509_CERT_Get_Size
* @param[in]  in_x509_certificate buffer containing the X509 certificate
* @param[out] out_x509_certificate_size total size of the certificate
* @return VLT_OK    success
* @return VLT_FAIL  parsing error
*/
VLT_STS X509_CERT_Get_Size(const VLT_U8 *in_x509_certificate, VLT_U16 *out_x509certificate_size);

/**
* @brief X509_CERT_Get_TbsData
* @param[in]  in_x509_certificate buffer containing the X509 certificate
* @param[out] out_tbs_certificate 
                - offset (in in_x509_certificate buffer) of the value field of the TBS sequence 
                - length of the value field of the TBS sequence 
* @return VLT_OK    success
* @return VLT_FAIL  parsing error
*/
VLT_STS X509_CERT_Get_TbsData(const VLT_U8 *in_x509_certificate, CertField *out_tbs_certificate);

/**
* @brief X509_CERT_Get_PublicKey
* @param[in]  in_x509_certificate buffer containing the X509 certificate
* @param[out] out_pubkey
                - offset (in in_tbs_certificate buffer) of Qx and Qy
                - length of Qx and Qy
                - algorithm id
* @return VLT_OK    success
* @return VLT_FAIL  parsing error
*/

VLT_STS X509_CERT_Get_PublicKey(const VLT_U8 *in_x509_certificate,  CertPubKey *out_pubkey);


/**
* @brief X509_CERT_Get_Signature
* @param[in]  in_x509_certificate buffer containing the X509 certificate
* @param[out] out_signature
                - offset (in in_x509_certificate buffer) of R and S
                - length of R and S
* @return VLT_OK    success
* @return VLT_FAIL  parsing error
*/
VLT_STS X509_CERT_Get_Signature(const VLT_U8 *in_x509_certificate, CertSignature *out_signature);

/**
* @brief Check the Tag of a TLV object
* @param[in] tag The T(ag) to check
* @param[in] idx Index of the T(ag) field of the TLV object in the data buffer
* @param[in] data The data buffer in which to check the tag
* @param[out] idx Index of the L(ength) field of the TLV object in the data buffer
* @return VLT_OK if successful, an @ref Error otherwise
*/
VLT_STS checkTag(VLT_U8 tag, VLT_U16 *idx, const VLT_U8 *data);

/**
* @brief Get the length of a TLV object
* @param[in] idx Index of the L(ength) field of the TLV object in the data buffer
* @param[out] idx Index of the V(alue) field of the TLV object in the data buffer
* @param[out] The (L)ength field value of the TLV object
* @return VLT_OK if successful, an @ref Error otherwise
*/
VLT_STS getLength(VLT_U16 *idx, const VLT_U8 *data, VLT_U16 *length);

/**
* @brief getTlv
* @param[in] tag The expected Tag
* @param[in] idx Index of the TLV object in the data buffer
* @param[in] data The data buffer in which to get the TLV
* @param[out] idx Index of the value field of the TLV
* @param[out] len The (L) length field of the TLV

* @return VLT_OK if successful, an @ref Error otherwise
*/
VLT_STS getTlv(VLT_U16 *idx, const VLT_U8 *data, VLT_U16 *len, VLT_U8 tag);

/**
* @brief parseSubjectPubKeyInfo
* @details \verbatim
* SubjectPublicKeyInfo  ::=  SEQUENCE  {
*                                       algorithm            AlgorithmIdentifier,
*                                       subjectPublicKey     BIT STRING
*                                      }
* \endverbatim
* @param idx Index of the current position in the data buffer
* @param data The buffer to parse
* @param pubKeyinfo The WiseSubjectPubKeyInfo to be filled
* @return VLT_OK if successful, an @ref Error otherwise
*/
VLT_STS parseSubjectPubKeyInfo(VLT_U16 *idx, const VLT_U8 *certificate, WiseSubjectPubKeyInfo* pubKeyinfo);

/**
* @brief skipTagValue: ignore the value field of a TLV object
* @param[in] idx  Index of the value field of the TLV in the data buffer
* @param[in] data The data buffer 
* @param[in] tag  The expected tag value
* @param[out] idx  Index of the following TLV in the data buffer
* \return VLT_OK if successful, an @ref Error otherwise
*/
VLT_STS skipTlv(VLT_U16 *idx, const VLT_U8 *data, VLT_U8 tag);

/**
* @brief	Extract the algorithm identifier from the following DER endoding sequence.
* @details	\verbatim
AlgorithmIdentifier  ::=  SEQUENCE  {
									algorithm OBJECT IDENTIFIER,
									parameters ANY DEFINED BY algorithm OPTIONAL
									}
Contains a value of the type registered for use with the algorithm object identifier value.
 \endverbatim
* @param idx Index of the current position in the data buffer
* @param data The data buffer in which to get the Algorithm Identifier
* @param algId The WiseAlgoIdentifier structure to be filled
* @return VLT_OK if successful, an @ref Error otherwise
*/
VLT_STS getAlgorithmIdentifier(VLT_U16 *idx, const VLT_U8 *data, WiseAlgoIdentifier* algId);

/**
* @brief This function extract a BITSTRING value from the buffer
* @param idx Index of the current position in the data buffer
* @param data The data buffer in which to get the BITSTRING
* @param bitstring The buffer in which the extracted BITSTRING value will be stored
* @param offset The offset where are the data in the certificate
* @return VLT_OK if successful, an @ref Error otherwise
*/
VLT_STS getBitString(VLT_U16 *idx, const VLT_U8 *data, WiseByteArray* bitstring, VLT_U16 *offset);




