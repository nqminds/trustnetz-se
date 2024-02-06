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

#include "x509parser.h"
#include "vaultic_mem.h"

VLT_STS getLength(VLT_U16 *idx, const VLT_U8 *data,VLT_U16 *puLength)
{
    if ((data == NULL) || (puLength == NULL))
        return VLT_FAIL;

    if (CHECK_BIT(data[*idx], 7))
    {
        int i;
        VLT_U16 length = 0;
        //get number of bytes used for data length
        VLT_U16 numberOfbyteForLength = data[(*idx)++] & 0x7F; //remove leading byte

        for (i = numberOfbyteForLength - 1; i >= 0; i--)
        {
            length |= (VLT_U16) (data[(*idx)++] << (i * 8));
        }
        *puLength = length;
    }
    else
    {
    	VLT_U16 length = data[(*idx)];
        (*idx)++;
        *puLength = length;
    }

    return VLT_OK;
}

VLT_STS getTlv(VLT_U16 *idx, const VLT_U8 *data, VLT_U16 *len, VLT_U8 tag)
{
    if (data == NULL)
        return VLT_FAIL;

    //Check tag value
    if (data[(*idx)++] != tag)
        return VLT_FAIL;

    if (getLength(idx, data, len) != VLT_OK)
        return VLT_FAIL;

    return VLT_OK;
}

VLT_STS checkTag(VLT_U8 tag, VLT_U16 *idx, const VLT_U8 *data)
{
    if (data == NULL)
        return VLT_FAIL;

    return (data[(*idx)++] == tag) ? VLT_OK : VLT_FAIL;
}


VLT_STS skipTlv(VLT_U16 *idx, const VLT_U8 *data, VLT_U8 tag)
{
    VLT_U16 length;

    if (data == NULL)
        return VLT_FAIL;

    if (getTlv(idx, data, &length, tag) != VLT_OK)
        return VLT_FAIL;

    *idx = (VLT_U16) (*idx + length);

    return VLT_OK;
}

/**
* \brief getObjectID
* \param idx Index of the current position in the data buffer
* \param data The data buffer in which to get the OBJECT ID
* \param oid The buffer in which the extracted OBJECT ID value will be stored
* \return WIS_OK if successful, an @ref Error otherwise
*/
VLT_STS getObjectID(VLT_U16 *idx, const VLT_U8 *data, WiseObjectIdentifier* oid)
{
    // Check input parameters
    if ((data == NULL) || (oid==NULL))
        return VLT_FAIL;

    //Check this is an object identifier
    if (checkTag(OBJECT_IDENTIFIER_TAG, idx, data) != VLT_OK)
        return OBJECT_IDENTIFIER_TAG_ERROR;

    if(getLength(idx, data, &oid->length) != VLT_OK)
        return VLT_FAIL;

    host_memset(&oid->buffer[0], 0x00, sizeof(oid->buffer));
    host_memcpy(&oid->buffer[0], &data[*idx], oid->length);
    *idx = (VLT_U16) (*idx + oid->length);

    return VLT_OK;
}


VLT_STS getBitString(VLT_U16 *idx, const VLT_U8 *data, WiseByteArray* bitstring, VLT_U16 *offset)
{
    // Check input parameters
    if ((data == NULL) || (bitstring==NULL))
        return VLT_FAIL;

    //Check this is an object identifier
    if (checkTag(BIT_STRING_TAG, idx, data) != VLT_OK)
        return BITSTRING_IDENTIFIER_TAG_ERROR;

    if (getLength(idx, data, &bitstring->length) != VLT_OK)
        return VLT_FAIL;

    *offset = *idx;
    host_memset(&bitstring->buffer[0], 0x00, sizeof(bitstring->buffer));
    host_memcpy(&bitstring->buffer[0], &data[*idx], bitstring->length);
    *idx = (VLT_U16) (*idx + bitstring->length);

    return VLT_OK;
}

VLT_STS parseSubjectPubKeyInfo(VLT_U16 *idx, const VLT_U8 *data, WiseSubjectPubKeyInfo* pubKeyinfo)
{
    USHORT length;

    // Check input parameters
    if ((data == NULL) || (pubKeyinfo==NULL))
        return VLT_FAIL;

    //Sequence subjectPublicKeyInfo
    if (getTlv(idx, data, &length, SEQUENCE_TAG) != VLT_OK)
        return SUBPUBKEYINFO_SEQ_ERROR;

    if (getAlgorithmIdentifier(idx, data, &pubKeyinfo->algId) != VLT_OK)
        return SUBPUBKEYINFO_ALG_ERROR;

    if (getBitString(idx, data, &pubKeyinfo->subjectPublicKey,&pubKeyinfo->pubKeyOffset) != VLT_OK)
        return SUBPUBKEYINFO_BITSTRING_ERROR;

    return VLT_OK;
}

VLT_STS getAlgorithmIdentifier(VLT_U16 *idx, const VLT_U8 *data, WiseAlgoIdentifier* algId)
{
    VLT_STS res;
    USHORT length;

    // Check input parameters
    if ((data == NULL) || (algId==NULL))
        return VLT_FAIL;

    //Sequence Algorithm identifier
    USHORT backupidx;
    res = getTlv(idx, data, &length, SEQUENCE_TAG);
    backupidx = *idx;

    if (res == VLT_OK)
    {
        res = getObjectID(idx, data, &algId->oid);
    }

    if (res == VLT_OK)
    {
        *idx = (VLT_U16) (backupidx + length);
    }
    return res;
}


VLT_STS X509_CERT_Get_Size(const VLT_U8 *in_x509_certificate, VLT_U16 *out_x509certificate_size)
{
    CertField x509certificate_info;

    // Get Certificate info
    if (X509_CERT_Get_Certificate(in_x509_certificate, &x509certificate_info) != VLT_OK)
        return VLT_FAIL;

    // Add sequence header size
    *out_x509certificate_size = (VLT_U16) (x509certificate_info.len + 4);

    return VLT_OK;
}

VLT_STS X509_CERT_Get_Certificate(const VLT_U8 *in_x509_certificate, CertField *out_x509certificate_info)
{
    /* Cursor in the X509 certificate  */
    VLT_U16 idx = 0;
    VLT_U16 length = 0;

    // Check input parameters
    if ((in_x509_certificate == NULL) || (out_x509certificate_info==NULL))
        return VLT_FAIL;

    //Get X509 certificate sequence
    if (getTlv(&idx, in_x509_certificate, &length, SEQUENCE_TAG) != VLT_OK)
        return VLT_FAIL;

    // Return offset and length of X509 certificate
    out_x509certificate_info->offset = idx; // offset of value field of X509 certificate sequence (ie TBS certificate)
    out_x509certificate_info->len = length; // total size of value field of X509 certificate sequence

    return VLT_OK;
}

VLT_STS X509_CERT_Get_TbsData(const VLT_U8 *in_x509_certificate, CertField *out_tbs_certificate_info)
{
    CertField x509certificate_info;
    VLT_U16 idx = 0;
    VLT_U16 length = 0;

    // Get Certificate info
    if (X509_CERT_Get_Certificate(in_x509_certificate, &x509certificate_info) != VLT_OK)
        return VLT_FAIL;

    idx = x509certificate_info.offset;
    length = x509certificate_info.len;

    //Get TBS certificate sequence
    if (getTlv(&idx, in_x509_certificate, &length, SEQUENCE_TAG) != VLT_OK)
        return VLT_FAIL;

    // Return offset and length of TBS certificate
    out_tbs_certificate_info->offset = idx;
    out_tbs_certificate_info->len = length;

    return VLT_OK;
}


VLT_STS X509_CERT_Get_Signature(const VLT_U8 *in_x509_certificate, CertSignature *out_signature_info)
{
    CertField x509certificate_info;
    VLT_U16 idx = 0;
    VLT_U16 length = 0;

    // Get Certificate info
    if (X509_CERT_Get_Certificate(in_x509_certificate, &x509certificate_info) != VLT_OK)
        return VLT_FAIL;

    idx = x509certificate_info.offset;
    length = x509certificate_info.len;

    //Skip TBS certificate Sequence
    if (skipTlv(&idx, in_x509_certificate, SEQUENCE_TAG) != VLT_OK)
        return VLT_FAIL;

    //Skip Signature Algorithm Sequence
    if (skipTlv(&idx, in_x509_certificate, SEQUENCE_TAG) != VLT_OK)
        return VLT_FAIL;

    //Get Signature Bit String
    if (getTlv(&idx, in_x509_certificate, &length, BIT_STRING_TAG) != VLT_OK)
        return VLT_FAIL;

    //Skip number of unused bits
    idx++; 

    //Get Signature Sequence
    if (getTlv(&idx, in_x509_certificate, &length, SEQUENCE_TAG) != VLT_OK)
        return VLT_FAIL;

    // Get R Integer component
    if (getTlv(&idx, in_x509_certificate, &length, INTEGER_TAG) != VLT_OK)
        return VLT_FAIL;

    out_signature_info->r.offset = idx;
    out_signature_info->r.len = length;


    // Get S Integer component
    idx = (VLT_U16) (idx + length);
    if (getTlv(&idx, in_x509_certificate, &length, INTEGER_TAG) != VLT_OK)
        return VLT_FAIL;

    out_signature_info->s.offset = idx;
    out_signature_info->s.len = length;

    return VLT_OK;
}


VLT_STS X509_CERT_Get_PublicKey(const VLT_U8 *in_x509_certificate, CertPubKey *out_pubkey)
{
    CertField tbsCertificate;
    
    /* Cursor in the X509 certificate */
    VLT_U16 idx = 0;
    VLT_U16 length = 0;

    // Get TBS certificate
    if (X509_CERT_Get_TbsData(in_x509_certificate, &tbsCertificate) != VLT_OK)
        return VLT_FAIL;
    idx = tbsCertificate.offset;

    //Skip (optional) Certificate Version 
    if (in_x509_certificate[idx] == VERSION_TAG)
    {
        if (skipTlv(&idx, in_x509_certificate, VERSION_TAG) != VLT_OK)
            return VLT_FAIL;
    }

    //Skip Serial number
    if (skipTlv(&idx, in_x509_certificate, INTEGER_TAG) != VLT_OK)
        return VLT_FAIL;

    //Skip Signature Algorithm Sequence
    if (skipTlv(&idx, in_x509_certificate, SEQUENCE_TAG) != VLT_OK)
        return VLT_FAIL;

    //Skip Issuer Sequence
    if (skipTlv(&idx, in_x509_certificate, SEQUENCE_TAG) != VLT_OK)
        return VLT_FAIL;

    //Skip Validity Sequence
    if (skipTlv(&idx, in_x509_certificate, SEQUENCE_TAG) != VLT_OK)
        return VLT_FAIL;

    //Skip Subject Sequence
    if (skipTlv(&idx, in_x509_certificate, SEQUENCE_TAG) != VLT_OK)
        return VLT_FAIL;

    //Get Subject Public Key Info sequence
    if (getTlv(&idx, in_x509_certificate, &length, SEQUENCE_TAG) != VLT_OK)
        return VLT_FAIL;

    //Skip Algo Identifier sequence
    if (skipTlv(&idx, in_x509_certificate, SEQUENCE_TAG) != VLT_OK)
        return VLT_FAIL;
    
    // Get Public Key bit string
    if (getTlv(&idx, in_x509_certificate, &length, BIT_STRING_TAG) != VLT_OK)
        return VLT_FAIL;

    // bit string is formatted as follows:
    // zz 04 [Qx] [Qy] 
    // zz number of unused bits

    //Skip number of unused bits
    idx++;
    length--;

    //Skip 04 trailer
    idx++;
    length--;

    out_pubkey->qx.offset = idx;
    out_pubkey->qx.len = length/2;

    out_pubkey->qy.offset = (VLT_U16) (out_pubkey->qx.offset + length / 2);
    out_pubkey->qy.len = length / 2;
    
    return VLT_OK;
}
