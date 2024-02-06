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
* @brief   Certificate parser module
*
*/

#pragma once


#ifdef _DEBUG
#define PRINT_RESULT
#define TRACE(a)            //printf("%s\n",a); //!< Logging Macro that display the provided message in debug mode
#else
#define TRACE(a)     //!< Logging Macro that display the provided message in debug mode
#endif

#define MAX_ENTENSIONS  20 //!< Maximum number of extensions that the program supports

#define CHECK_BIT(var,pos) ((var) & (1<<(pos)))     //!< Check on var that the bit at the 'pos' position is set to 1  


/** @defgroup Tag Tags
*  List of ASN.1 Tags 
*/
/** @{ */
#define ENUMERATED_TAG              0x0A //!< ASN.1 ENUMERATED tag value
#define BIT_STRING_TAG              0x03 //!< ASN.1 BIT STRING tag value
#define INTEGER_TAG                 0x02 //!< ASN.1 INTEGER tag value
#define BOOLEAN_TAG                 0x01 //!< ASN.1 BOOLEAN tag value
#define OCTET_STRING_TAG            0x04 //!< ASN.1 OCTET STRING tag value
#define OBJECT_IDENTIFIER_TAG       0x06 //!< ASN.1 OBJECT IDENTIFIER tag value
#define UTCTIME_TAG                 0x17 //!< ASN.1 UTC TIME tag value
#define VERSION_TAG                 0xA0 //!< ASN.1 VERSION tag value
#define GENERALIZED_TIME            0x18 //!< ASN.1 GENERALIZED TIME tag value
#define UTF8STRING_TAG              0x0C //!< ASN.1 UTF8 STRING tag value
#define PRINTABLE_STRING_TAG        0x13 //!< ASN.1 PRINTABLE STRING tag value
#define IA5STRING_TAG               0x16 //!< ASN.1 IA5 STRING tag value
#define SEQUENCE_TAG                0x30 //!< ASN.1 SEQUENCE tag value
#define SEQUENCE_OF_TAG             0x31 //!< ASN.1 SEQUENCE OF tag value
/** @} */

/** @defgroup Error Errors
*  List of possible errors.
*/
/** @{ */
#define BOOLEAN_VALUE_ERROR                     0x02 //!< The Boolean value is invalid
#define BOOLEAN_LENGTH_ERROR                    0x03 //!< The Boolean length value is invalid
#define BITSTRING_IDENTIFIER_TAG_ERROR          0x04 //!< Expected BITSTRING tag not found
#define OBJECT_IDENTIFIER_TAG_ERROR             0x05 //!< Expected OBJECT ID tag not found
#define OCTET_TAG_NOT_FOUND                     0x06 //!< Expected OCTET tag not found
#define VERSION_TAG_ERROR                       0x10 //!< Expected VERSION tag not found
#define VERSION_LEN_ERROR                       0x11 //!< The version length value is invalid
#define VERSION_FORMAT_ERROR                    0x12 //!< The format of version value is invalid
#define SERIAL_FORMAT_ERROR                     0x13 //!< Serial number format is invalid
#define SIGNATURE_TAG_ERROR                     0x14 //!< Expected SIGNATURE tag not found
#define START_UTCTIME_TAG_ERROR                 0x16 //!< Expected START UTC TIME tag not found
#define END_UTCTIME_TAG_ERROR                   0x17 //!< Expected END UTC TIME tag not found
#define ALGORITHMIDENTIFIER_FORMAT_ERROR        0x18 //!< The format of algorithm identifier value is invalid
#define SUBPUBKEYINFO_SEQ_ERROR                 0x19 //!< Error while getting the subject public key sequence
#define SUBPUBKEYINFO_ALG_ERROR                 0x1A //!< Error while getting the subject public key algorithm value
#define SUBPUBKEYINFO_BITSTRING_ERROR           0x1B //!< Error while getting the subject public key value
#define SIGNATURE_BITSTRING_ERROR               0x1C //!< Error while getting the signature bitstring value
#define HOST_MEMORY_ERROR                       0x1D //!< Error while trying to allocate memory
#define MAX_EXTENSIONS_ERROR                    0x20 //!< Maximum number of extensions exceeded 
/** @} */

////////////////////////////////////////////////////////////////////////////////////////
///
///                                OID definitions
///
////////////////////////////////////////////////////////////////////////////////////////

/** @defgroup OID OIDs
*  List of OID
*/
/** @{ */
#define ISO_MEMBERBODY              0x2A //!< Refer to rfc2459
#define US_0                        0x86 //!< Refer to rfc2459
#define US_1                        0x48 //!< Refer to rfc2459
#define RSADSI_0                    0x86 //!< Refer to rfc2459
#define RSADSI_1                    0xF7 //!< Refer to rfc2459
#define RSADSI_2                    0x0D //!< Refer to rfc2459
#define PKCS                        0x01 //!< Refer to rfc2459
#define PKCS_9                      0x09 //!< Refer to rfc2459
#define PKCS_9_EMAIL                0x01 //!< Refer to rfc2459
#define ID_AT_0                     0x55 //!< Refer to rfc2459
#define ID_AT_1                     0x04 //!< Refer to rfc2459
#define ID_AT_COUNTRY_NAME          0x06 //!< Refer to rfc2459
#define ID_AT_NAME                  0x29 //!< Refer to rfc2459
#define ID_AT_SURNAME               0x04 //!< Refer to rfc2459
#define ID_AT_GIVENNAME             0x2A //!< Refer to rfc2459
#define ID_AT_INITIALS              0x2B //!< Refer to rfc2459
#define ID_AT_COMMONNAME            0x03 //!< Refer to rfc2459
#define ID_AT_LOCALITYNAME          0x07 //!< Refer to rfc2459
#define ID_AT_STATEORPROVINCENAME   0x08 //!< Refer to rfc2459
#define ID_AT_ORGANIZATIONNAME      0x0A //!< Refer to rfc2459
#define ID_AT_ORGANIZATIONALUNITNAME  0x0B //!< Refer to rfc2459

#ifdef __cplusplus  
extern "C" {  // only need to export C interface if  
    // used by C++ source code  
#endif  


/*! Type that defines a BYTE (unsigned char) */
typedef unsigned char WISEBYTE; 
/*! Type that defines an unsigned short */
typedef unsigned short USHORT; 
/*! Type that defines a string */
typedef unsigned char* WISESTRING; 

/*!  Structure that represent a byte array by providing the data buffer and length. */
typedef struct 
{ 
    USHORT length; //!< Length of the byte array
	WISEBYTE buffer[512]; //!< The byte array
	
    
}WiseByteArray; 

/*! X509 Object Identifier definition */
typedef WiseByteArray WiseObjectIdentifier;

/*! X509 Certificate algorithm values */
typedef struct
{
	WiseObjectIdentifier oid; //!< Algorithm OID
    unsigned char description[128]; //!< Description of the algorithm

}WiseAlgoIdentifier;

/*! X509 Certificate attribute values */
typedef struct
{
	WiseByteArray value; //!< Value of the attribute
	WISEBYTE type; //!< Type of the attribute

}WiseAttributeValue;

/*! X509 Object Identifier definition */
typedef struct
{
	WiseObjectIdentifier oidType; //!< Attribute OID
	WiseAttributeValue attributeValue; //!< Attribute value
}WiseAttributeObject;

#if (WIS_SUBJECTPUBKEYINFO_DATA == WIS_ENABLE)
/*! X509 Certificate Subject Public Key informations */
typedef struct
{
	WiseAlgoIdentifier algId; //!< Subject public key algorithm OID
	WiseByteArray subjectPublicKey;  //!< Subject public key value
	USHORT pubKeyOffset;
}WiseSubjectPubKeyInfo;
#endif

#if ( (WIS_ISSUER_DATA == WIS_ENABLE) || (WIS_SUBJECT_DATA == WIS_ENABLE) )
/*! X509 Certificate name value data */
typedef struct
{
    WiseByteArray derEncoding; //!< Der endoding of the value
    WiseAttributeObject attributes[10]; //!< Predefined list of WiseAttributeObject
	USHORT attributeCount;  //!< Number of attributes
}WiseName;
#endif

#if (WIS_VALIDITY_DATA == WIS_ENABLE)
/*! X509 Certificate Validity data */
typedef struct
{
	WiseByteArray startDate; //!< Start validity date
	WiseByteArray endDate; //!< End validity date
}WiseValidity;
#endif

#if (WIS_EXTENSIONS_DATA == WIS_ENABLE)
/*! Certificate Extension definition */
typedef struct
{
	WiseObjectIdentifier oid; //!< Object identifier of the extension
	WISEBYTE critical; //!< Extension criticity : TRUE (critical) or FALSE (not critical)
	WiseByteArray value; //!< Byte array that represent the value of the extension
}WiseExtension;

/*! Represents a list of WiseExtension */
typedef struct
{
	WiseExtension extensions[MAX_ENTENSIONS]; //!< Predefined extension list
	USHORT count; //!< Number of attributes

}WiseExtensions;
#endif

/*! TBS certificate structure */
typedef struct{
	WISEBYTE version; //!< Certificate version
#if (WIS_SERIAL_NUMBER_DATA == WIS_ENABLE)
	WiseByteArray serialNumber; //!< Certificate serial number
#endif
	WiseAlgoIdentifier signature; //!< Certificate signature
#if (WIS_ISSUER_DATA == WIS_ENABLE)
	WiseName issuer; //!< Certificate issuer
#endif
#if (WIS_VALIDITY_DATA == WIS_ENABLE)
	WiseValidity validity; //!< Certificate validity
#endif
#if (WIS_SUBJECT_DATA == WIS_ENABLE)
	WiseName subject; //!< Certificate subject  
#endif
#if (WIS_SUBJECTPUBKEYINFO_DATA == WIS_ENABLE)
	WiseSubjectPubKeyInfo subjectPubKeyInfo; //!<Certificate subject public key info
#endif
#if (WIS_EXTENSIONS_DATA == WIS_ENABLE)
	WiseExtensions extensions; //!< List of extensions
#endif
}WiseTBSCertificate;

/*! Structure that defines a X509 certificate */
typedef struct{
	WiseTBSCertificate TBSCertificate; //!< TBS value of the certificate
#if (WIS_SIG_ALGORITHM_DATA == WIS_ENABLE)
	WiseAlgoIdentifier signatureAlgorithm; //!< Signature algorithm of the certificate
#endif
#if (WIS_SIGNATURE_DATA == WIS_ENABLE)
	WiseByteArray signature; //!< Signature of the certificate
	USHORT signatureOffset;
#endif
}WiseX509Certificate;

typedef struct {
    VLT_U16 offset;
    VLT_U16 len;
} CertField;

typedef struct {
    CertField qx;
    CertField qy;
} CertPubKey;

typedef struct {
    CertField r;
    CertField s;
} CertSignature;

#ifdef __cplusplus  
}
#endif 