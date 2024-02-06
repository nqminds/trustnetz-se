/**
* @file	   vaultic_padding.c
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

#include "vaultic_common.h"
#if( VAULT_IC_TARGET ==  VAULTIC4XX)
#include "vaultic_padding.h"
#include "vaultic_mem.h"

/**
 * Error Codes
 */
#define EPDDADDPADUNKNOWN       VLT_ERROR( VLT_PADDING, 0u )
#define EPDDRMVPADUNKNOWN       VLT_ERROR( VLT_PADDING, 1u )
#define EPDDADDBFTOOSMALL       VLT_ERROR( VLT_PADDING, 2u )
#define EPDDADDINVLDPARAMS      VLT_ERROR( VLT_PADDING, 3u )
#define EPDDRMVINVLDPARAMS      VLT_ERROR( VLT_PADDING, 4u )
#define EPDDRMVFRMTISO9797      VLT_ERROR( VLT_PADDING, 5u )
#define EPDDRMVIVLDISO9797      VLT_ERROR( VLT_PADDING, 6u )
#define EPDDRMVIVLDPKCS5        VLT_ERROR( VLT_PADDING, 7u )
#define EPDDRMVIVLDPKCS7        VLT_ERROR( VLT_PADDING, 8u )
#define EPDDADDINVLDBLKSZ       VLT_ERROR( VLT_PADDING, 9u )
#define EPDDADDINVLDCASE        VLT_ERROR( VLT_PADDING, 10u )
#define EPDDRMVZEROLEN          VLT_ERROR( VLT_PADDING, 11u )
#define EPDDRMVINVLDBLKSIZE     VLT_ERROR( VLT_PADDING, 12u )
#define EPDDRMVNOTBLKSIZE       VLT_ERROR( VLT_PADDING, 13u )


VLT_STS PaddingAdd( VLT_U8 paddingMode, VLT_U16 blockSize, VLT_U8 *pData, VLT_U32 *pDataLen,
    VLT_U32 bufferCapacity )
{
    VLT_U8 paddingSize;

    /**
     * Ensure we haven't been passed any null pointers.
     */
    if( ( NULL == pData ) ||
        ( NULL == pDataLen ) )
    {
        return( EPDDADDINVLDPARAMS );
    }

    /**
     * The block size can't be zero
     */
    if( 0u == blockSize )
    {
        return( EPDDADDINVLDBLKSZ );
    }

    /**
     * Determine how much padding we need.
     */
    paddingSize = (VLT_U8)( blockSize - (*pDataLen % blockSize ) );

    /**
     * Make sure we have enough space to add the padding.
     */
    if( (paddingSize + *pDataLen) > bufferCapacity )
    {
        return( EPDDADDBFTOOSMALL );
    }

    switch( paddingMode )
    {   
        case VLT_PADDING_ISO9797_METHOD2:
            /**
             * If the padding size is zero then the padding required is
             * equal to the block size.
             */
            if( 0u == paddingSize )
            {
                paddingSize = (VLT_U8)blockSize;
            }
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memset( &pData[*pDataLen], 0x00, paddingSize );
            pData[*pDataLen] = VLT_PADDING_METHOD2_MARK;            
            break;
        case VLT_PADDING_NONE:
            /**
             * We have been asked not to pad something that
             * doesn't alging to the block size specified.
             * Data blocks passed to a cipher should match
             * the block size.
             */
            if( 0u != paddingSize )
            {
                return( EPDDADDINVLDCASE );
            }
            paddingSize = 0u;
            break;
        case VLT_PADDING_PKCS5:
        case VLT_PADDING_PKCS7:
            /*
            * No need to check the return type as pointer has been validated
            */
            (void)host_memset( &pData[*pDataLen], paddingSize, paddingSize );         
            break;
        default:
            return(EPDDADDPADUNKNOWN);
			break; //For MISRA compliancy
    }           

    /**
     * Update the length
     */
    *pDataLen += paddingSize;

    return( VLT_OK );
}

VLT_STS PaddingRemove( VLT_U8 paddingMode, VLT_U16 blockSize, VLT_U8 *pData, VLT_U32 *pDataLen )
{

    VLT_U16 paddingSize = 0;
    VLT_U8 paddingValue;    

    /**
     * Ensure we haven't been passed any null pointers.
     */
    if( ( NULL == pData ) ||
        ( NULL == pDataLen ) )
    {
        return( EPDDRMVINVLDPARAMS );
    }

    /**
     * The data length passed can't be zero or less
     * that the block size.
     */
    if( ( 0u == *pDataLen ) ||
        ( blockSize > *pDataLen ) )
    {
        return( EPDDRMVZEROLEN );
    }

    /**
     * The blockSize can't be zero!
     */
    if( 0u == blockSize )
    {
        return( EPDDRMVINVLDBLKSIZE );
    }

    /**
     * The data Length passed must be multiple of
     * the block size.
     */
    if( 0u != ( *pDataLen % blockSize ) )
    {
        return( EPDDRMVNOTBLKSIZE );
    }

	switch( paddingMode )
	{   
	case VLT_PADDING_NONE:
		break;
	case VLT_PADDING_ISO9797_METHOD2:

		paddingValue = pData[ ( *pDataLen - 1u ) ];

		if( VLT_PADDING_METHOD2_MARK == paddingValue )
		{
			paddingSize = 1;
		}
		else if( 0u == paddingValue )
		{

			/**
			* Keep looking backwards until you find
			* the 0x80 marker or until we have looked at
			* enough bytes to cover a block size length.
			*/
			while( ++paddingSize <= blockSize )
			{
				/**
				* The only values expected are 0s and 0x80 if anything
				* else if found we need to return an error.
				*/
				paddingValue = pData[ (*pDataLen - paddingSize) ];

				if( VLT_PADDING_METHOD2_MARK == paddingValue )
				{
					break;
				}
				else if ( 0u == paddingValue )
				{                       
					continue;
				}
				else
				{
					return( EPDDRMVFRMTISO9797 );
				}
			}
		}
		else
		{
			return( EPDDRMVIVLDISO9797 );
		}

		break;

	case VLT_PADDING_PKCS5:
		paddingSize = pData[ ( *pDataLen - 1u) ];
		/**
		* PKCS5 always pads and llegedly the padding value
		* shouldn't be more than 8.
		*/
		if( ( MAX_PKCS5_PAD_SZ < paddingSize  ) || ( 0u == paddingSize ) )
		{
			return( EPDDRMVIVLDPKCS5 );
		}

		break;
	case VLT_PADDING_PKCS7:
		paddingSize = pData[ ( *pDataLen - 1u) ];
		/**
		* PKCS7 always pads
		*/
		if( 0u == paddingSize )
		{
			return( EPDDRMVIVLDPKCS7 );
		}
		break;
	default:
		return(EPDDRMVPADUNKNOWN);
		break; //For MISRA compliancy
	}

    /**
     * Update the length to reflect the removal
     * of the padding.
     */
    *pDataLen -= paddingSize;

    return( VLT_OK );
}

#if( VLT_ENABLE_CIPHER_TESTS == VLT_ENABLE )

VLT_STS PaddingTests( void )
{
    /**
    * "The Brown Fox has Jumped the Fence!"
    */
    VLT_U8 vector1[] =
    {
        0x54, 0x68, 0x65, 0x20, 0x42, 0x72, 0x6f, 0x77,
        0x6e, 0x20, 0x46, 0x6f, 0x78, 0x20, 0x68, 0x61,
        0x73, 0x20, 0x4a, 0x75, 0x6d, 0x70, 0x65, 0x64,
        0x20, 0x74, 0x68, 0x65, 0x20, 0x46, 0x65, 0x6e,
        0x63, 0x65, 0x21
    };

    VLT_U32 vector1Size = 35;

    VLT_U8 vector1Method2[] =
    {
        0x54, 0x68, 0x65, 0x20, 0x42, 0x72, 0x6f, 0x77,
        0x6e, 0x20, 0x46, 0x6f, 0x78, 0x20, 0x68, 0x61,
        0x73, 0x20, 0x4a, 0x75, 0x6d, 0x70, 0x65, 0x64,
        0x20, 0x74, 0x68, 0x65, 0x20, 0x46, 0x65, 0x6e,
        0x63, 0x65, 0x21, 0x80, 0x00, 0x00, 0x00, 0x00
    };
    VLT_U32 vector1Method2Size = 40;
    
    VLT_U8 vector1PKCS7[] =
    {
        0x54, 0x68, 0x65, 0x20, 0x42, 0x72, 0x6f, 0x77,
        0x6e, 0x20, 0x46, 0x6f, 0x78, 0x20, 0x68, 0x61,
        0x73, 0x20, 0x4a, 0x75, 0x6d, 0x70, 0x65, 0x64,
        0x20, 0x74, 0x68, 0x65, 0x20, 0x46, 0x65, 0x6e,
        0x63, 0x65, 0x21, 0x05, 0x05, 0x05, 0x05, 0x05
    };
    VLT_U8 vector1PKCS7Size = 40;

    VLT_U8 text[40];
    VLT_U32 textSize = vector1Size;

    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memset( text, 0x00,  textSize );
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( text, vector1, textSize );
    
    /**
     * The buffer doesn't have enough capacity.
     */
    if( VLT_OK == PaddingAdd( VLT_PADDING_ISO9797_METHOD2, 8, text, &textSize, textSize ) )
    {
        return( VLT_FAIL );
    }

    /**
     * The padding method shouldn't be recognised.
     */
    if( VLT_OK == PaddingAdd( 20, 8, text, &textSize, sizeof(text)/sizeof(VLT_U8 ) ) )
    {
        return( VLT_FAIL );
    }

    /**
     * The text pointer is null
     */
    if( VLT_OK == PaddingAdd( VLT_PADDING_NONE, 8, 0, &textSize, textSize ) )
    {
        return( VLT_FAIL );
    }

    /**
     * The text length pointer is null
     */
    if( VLT_OK == PaddingAdd( VLT_PADDING_NONE, 8, text, 0, textSize ) )
    {
        return( VLT_FAIL );
    }

    /**
     * All ok the padding method 2 vector should match
     */
    if( VLT_OK != PaddingAdd( VLT_PADDING_ISO9797_METHOD2, 8, text,
        &textSize, sizeof(text)/sizeof(VLT_U8 ) ) )
    {
        return( VLT_FAIL );
    }
    if( textSize != vector1Method2Size )
    {
        return( VLT_FAIL );
    }
    if( 0u != host_memcmp( text, vector1Method2, vector1Method2Size ) )
    {
        return( VLT_FAIL );
    }
    if( VLT_OK != PaddingRemove( VLT_PADDING_ISO9797_METHOD2, 8, text, &textSize ) )
    {
        return( VLT_FAIL );
    }
    if( textSize != vector1Size )
    {
        return( VLT_FAIL );
    }
    if( 0u != host_memcmp( text, vector1, vector1Size ) )
    {
        return( VLT_FAIL );
    }

    /**
     * All ok the PKCS7 vector should match
     */
    if( VLT_OK != PaddingAdd( VLT_PADDING_PKCS7, 8, text,
        &textSize, sizeof(text)/sizeof(VLT_U8 ) ) )
    {
        return( VLT_FAIL );
    }
    if( textSize != vector1PKCS7Size )
    {
        return( VLT_FAIL );
    }
    if( 0u != host_memcmp( text, vector1PKCS7, vector1PKCS7Size ) )
    {
        return( VLT_FAIL );
    }
    if( VLT_OK != PaddingRemove( VLT_PADDING_PKCS7, 8, text, &textSize ) )
    {
        return( VLT_FAIL );
    }
    if( textSize != vector1Size )
    {
        return( VLT_FAIL );
    }
    if( 0u != host_memcmp( text, vector1, vector1Size ) )
    {
        return( VLT_FAIL );
    }

    return( VLT_OK );
}

#endif /* ( VLT_ENABLE_CIPHER_TESTS == VLT_ENABLE ) */
#endif