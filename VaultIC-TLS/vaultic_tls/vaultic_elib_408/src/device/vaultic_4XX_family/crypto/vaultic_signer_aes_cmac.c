/**
* @file	   vaultic_signer_aes_cmac.c
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
#if (VLT_ENABLE_SIGN_CMAC == VLT_ENABLE)
#include "vaultic_symmetric_signer.h"
#include "vaultic_cipher.h"
#include "vaultic_padding.h"
#include "vaultic_mem.h"
#include "vaultic_utils.h"
#include "vaultic_signer_aes_cmac.h"


/**
 * Error Codes
 */
#define EAESCMACIIVLDPARAM           VLT_ERROR( VLT_AES_CMAC, 0u )
#define EAESCMACIIVLDKEY             VLT_ERROR( VLT_AES_CMAC, 1u )
#define EAESCMACDFIVLDMSG            VLT_ERROR( VLT_AES_CMAC, 2u )   
#define EAESCMACDFIVLDMAC            VLT_ERROR( VLT_AES_CMAC, 3u )
#define EAESCMACDFIVLDMACLEN         VLT_ERROR( VLT_AES_CMAC, 4u )
#define EAESCMACDFIVLDMACCAP         VLT_ERROR( VLT_AES_CMAC, 5u )
#define EAESCMACDFIVLDMSGCAP         VLT_ERROR( VLT_AES_CMAC, 6u )
#define EAESCMACUPIVLDMSG            VLT_ERROR( VLT_AES_CMAC, 7u )
#define EAESCMACUPIVLDMSGLEN         VLT_ERROR( VLT_AES_CMAC, 8u )
#define EAESCMACUPIVLDMSGCAP         VLT_ERROR( VLT_AES_CMAC, 9u )
#define EINVALIDOPMODE               VLT_ERROR( VLT_AES_CMAC, 10u )
#define EAESCMACHOSTNOMEMORY         VLT_ERROR( VLT_AES_CMAC, 0x84 )


VLT_STS AES_CMAC_Sign(const VLT_KEY_BLOB *kbKey, const VLT_U8 *pu8Message,VLT_U32 u32Messagelen,VLT_U8 *pu8Mac, VLT_U32 *pu32MacLen)
{
    VLT_STS status;
    VLT_U8 *msg_buffer;

    // as SignerAesCmacDoFinal appends padding bytes directly to the message we need to use an intermediate buffer
    msg_buffer=malloc(u32Messagelen+AES_BLOCK_SIZE);
	if (msg_buffer == NULL)
	{
		return EAESCMACHOSTNOMEMORY;
	}

    if( VLT_OK != ( status = SignerAesCmacInit( VLT_SIGN_MODE, kbKey, 0 ) ) )
    {
        FREE(msg_buffer);
        return( status );
    }

    if( VLT_OK != ( status = SignerAesCmacDoFinal( pu8Message,
        u32Messagelen,
        u32Messagelen+AES_BLOCK_SIZE,
        pu8Mac,
        pu32MacLen,
        *pu32MacLen ) ) )
    {
        FREE(msg_buffer);
        return( status );
    }

    (void)SignerAesCmacClose();

    FREE(msg_buffer);

    return( VLT_OK );
}



#if( VLT_ENABLE_CIPHER_AES == VLT_ENABLE )

/**
 * Private Methods
 */
VLT_STS generateSubKeys( const VLT_KEY_BLOB *pKey, VLT_U8 *K1, VLT_U8 *K2 );

/**
 * The Sub Keys K1 and K2.
 */
static VLT_U8 K1[AES_BLOCK_SIZE];
static VLT_U8 K2[AES_BLOCK_SIZE];
static VLT_U8 mac[AES_BLOCK_SIZE];

/**
 * Private Data
 */
static VLT_CIPHER_PARAMS cipherParams = {0};

static VLT_KEY_BLOB theKey = {0};


VLT_STS SignerAesCmacInit( VLT_U8 opMode, const VLT_KEY_BLOB *pKey, const VLT_U8 *pParams )
{   
    UNREFERENCED_PARAM(pParams);

    VLT_STS status;

    /**
     * NOTE: Extensive validation of all the parameters should happen at
     * the interface level since they are common to all the Signers.    
     */
    if( NULL == pKey )
    {
        return( EAESCMACIIVLDKEY );
    }

    /**
     * Before we initialise the signer ensure that we are purging
     * any residual data from previous calls.
     * We are not checking the return value by design.
     */
    (void)SignerAesCmacClose();

    /**
     * Cache the key Blob
     */
    /*
    * No need to check the return type as pointer has been validated
    */
    //theKey.keySize = pKey->keySize;
    //theKey.keyType = pKey->keyType;
    //(void)host_memcpy(theKey.keyValue, pKey->keyValue, pKey->keySize);
    (void)host_memcpy((VLT_U8 *)((void*)&theKey), (VLT_U8 *)((void*)pKey), sizeof(VLT_KEY_BLOB));

    /**
     * Carry out the subkey generation.
     */
    if( VLT_OK != ( status = generateSubKeys( &theKey, K1, K2 ) ) )
    {
        return( status );
    }

    /*
     * Check the op mode
     */
    if ( VLT_SIGN_MODE != opMode )
    {
        return ( EINVALIDOPMODE );
    }

    /**
     * Now Initialise the underlying cipher for the mac generation.
     */
    cipherParams.enAlgoID = VLT_ALG_CIP_AES;
    cipherParams.enChainMode = VLT_BLOCK_MODE_ECB;
    cipherParams.enPaddingScheme = VLT_PADDING_NONE;
    cipherParams.pIV = 0; /*N/A for ECB*/
    if( VLT_OK != ( status = CipherInit(
        VLT_ENCRYPT_MODE,
        &theKey,
        &cipherParams) ) )
    {
        return( status );
    }

    return( VLT_OK );
}

VLT_STS SignerAesCmacClose( void )
{
    /**
     * Clear every piece of residual data used by the AES CMAC
     * signer.
     */ 
    (void)host_memset( (VLT_U8 *)((void*)&cipherParams), 0x00, sizeof(VLT_CIPHER_PARAMS) );
    (void)host_memset( (VLT_U8 *)((void*)&theKey), 0x00, sizeof(VLT_KEY_BLOB) );
    (void)host_memset( (VLT_U8 *)((void*)K1), 0x00, AES_BLOCK_SIZE );
    (void)host_memset( (VLT_U8 *)((void*)K2), 0x00, AES_BLOCK_SIZE );   
    (void)host_memset( (VLT_U8 *)((void*)mac), 0x00, AES_BLOCK_SIZE );
    
    return( CipherClose() );
}

/**
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   +                   Algorithm AES-CMAC                              +
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   +                                                                   +
   +   Input    : K    ( 128-bit key )                                 +
   +            : M    ( message to be authenticated )                 +
   +            : len  ( length of the message in octets )             +
   +   Output   : T    ( message authentication code )                 +
   +                                                                   +
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   +   Constants: const_Zero is 0x00000000000000000000000000000000     +
   +              const_Bsize is 16                                    +
   +                                                                   +
   +   Variables: K1, K2 for 128-bit subkeys                           +
   +              M_i is the i-th block (i=1..ceil(len/const_Bsize))   +
   +              M_last is the last block xor-ed with K1 or K2        +
   +              n      for number of blocks to be processed          +
   +              r      for number of octets of last block            +
   +              flag   for denoting if last block is complete or not +
   +                                                                   +
   +   Step 1.  (K1,K2) := Generate_Subkey(K);                         +
   +   Step 2.  n := ceil(len/const_Bsize);                            +
   +   Step 3.  if n = 0                                               +
   +            then                                                   +
   +                 n := 1;                                           +
   +                 flag := false;                                    +
   +            else                                                   +
   +                 if len mod const_Bsize is 0                       +
   +                 then flag := true;                                +
   +                 else flag := false;                               +
   +                                                                   +
   +   Step 4.  if flag is true                                        +
   +            then M_last := M_n XOR K1;                             +
   +            else M_last := padding(M_n) XOR K2;                    +
   +   Step 5.  X := const_Zero;                                       +
   +   Step 6.  for i := 1 to n-1 do                                   +
   +                begin                                              +
   +                  Y := X XOR M_i;                                  +
   +                  X := AES-128(K,Y);                               +
   +                end                                                +
   +            Y := M_last XOR X;                                     +
   +            T := AES-128(K,Y);                                     +
   +   Step 7.  return T;                                              +
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

VLT_STS SignerAesCmacDoFinal(
    const VLT_U8 *pMessage,
    VLT_U32 messageLen,
    VLT_U32 messageCapacity,
    VLT_U8 *pMac,
    VLT_U32 *pMacLen,
    VLT_U32 macCapacity )
{
    VLT_STS status;
    VLT_U8 bNoPaddingRequired;
    VLT_U32 blockCount;
    VLT_U32 padSize;
    VLT_U8 M_last[AES_BLOCK_SIZE];

    /**
     * Rudimentary input parameter validation
     */
    if( NULL == pMessage )
    {
        return( EAESCMACDFIVLDMSG );
    }

    if( NULL == pMac )
    {
        return( EAESCMACDFIVLDMAC );
    }

    if( NULL == pMacLen )
    {
        return( EAESCMACDFIVLDMACLEN );
    }

    if( macCapacity < AES_BLOCK_SIZE )
    {
        return( EAESCMACDFIVLDMACCAP );
    }

    /**
     * Step 1.  (K1,K2) := Generate_Subkey(K);
     * has already taken place during the SignerAesCmacInit method call.
     */

    /**
     *   Step 2.  n := ceil(len/const_Bsize);
     *   Step 3.  if n = 0
     *            then
     *                 n := 1;
     *                 flag := false;
     *            else
     *                 if len mod const_Bsize is 0
     *                 then flag := true;
     *                 else flag := false;
     */
    if( AES_BLOCK_SIZE > messageLen )
    {
        blockCount = 1;
        bNoPaddingRequired = FALSE;
    }
    else
    {
        blockCount = ( messageLen / AES_BLOCK_SIZE );

        if( 0u == ( messageLen % AES_BLOCK_SIZE ) )
        {
            bNoPaddingRequired = TRUE;
        }
        else
        {
            bNoPaddingRequired = FALSE;         
        }
    }

    /**
      *   Step 4.  if flag is true
      *            then M_last := M_n XOR K1;
      *            else M_last := padding(M_n) XOR K2;
     */
    if( TRUE == bNoPaddingRequired )
    {
        /**
         * Cache the last block
         */
        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_memcpy( M_last, &pMessage[ ( ( blockCount - 1u ) * AES_BLOCK_SIZE ) ],
            AES_BLOCK_SIZE );

        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_memxor( M_last, K1, AES_BLOCK_SIZE );
    }
    else
    {   
        VLT_U8 paddingRequired = (VLT_U8)( AES_BLOCK_SIZE - ( messageLen % AES_BLOCK_SIZE ) );

        /**
         * Ensure the calling method has got enough buffer to
         * add any padding.
         */
        if( messageCapacity < ( messageLen + paddingRequired ) )
        {
            return( EAESCMACDFIVLDMSGCAP );
        }

        blockCount = ( ( messageLen + paddingRequired ) / AES_BLOCK_SIZE );

        /**
         * Cache the last block
         */
        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_memcpy( M_last, &pMessage[ ( ( blockCount - 1u ) * AES_BLOCK_SIZE ) ],
            AES_BLOCK_SIZE );

        padSize = ( messageLen % AES_BLOCK_SIZE );

        if( VLT_OK != ( status = PaddingAdd( VLT_PADDING_ISO9797_METHOD2, AES_BLOCK_SIZE,
            M_last, &padSize, ( messageCapacity - ( messageLen - padSize ) ) ) ) )
        {
            return( status );
        }
        
        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_memxor( M_last, K2, AES_BLOCK_SIZE );
    }

    /**
     *   Step 5.  X := const_Zero;
     *   Step 6.  for i := 1 to n-1 do
     *                begin
     *                  Y := X XOR M_i;
     *                  X := AES-128(K,Y);
     *                end
     *            Y := M_last XOR X;
     *            T := AES-128(K,Y);
     */
    if( 1u == blockCount )
    {
        if( VLT_OK != ( status = SignerAesCmacUpdate( M_last,
            AES_BLOCK_SIZE,
            AES_BLOCK_SIZE ) ) )
        {
            return( status );
        }
    }
    else
    {
        if( VLT_OK != ( status = SignerAesCmacUpdate( pMessage,
            ( ( blockCount - 1u ) * AES_BLOCK_SIZE ),
            messageCapacity ) ) )
        {
            return( status );
        }

        /**
         * Do the last block
         */
        if( VLT_OK != ( status = SignerAesCmacUpdate( M_last,
            AES_BLOCK_SIZE,
            AES_BLOCK_SIZE ) ) )
        {
            return( status );
        }
    }


    /**
     * Return the MAC back to the caller.
     */
    *pMacLen = AES_BLOCK_SIZE;
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( pMac, mac, AES_BLOCK_SIZE );
    
    return ( VLT_OK );
}

VLT_STS SignerAesCmacUpdate( const VLT_U8 *pMessage, VLT_U32 messageLen, VLT_U32 messageCapacity )
{
    VLT_STS status;

    /**
     * The Update only deals with multiples blocks of AES_BLOCK_SIZE
     */
    VLT_U32 blockCount = ( messageLen / AES_BLOCK_SIZE );
    VLT_U32 i;
    VLT_U32 outCount = 0;
    VLT_U8 block[AES_BLOCK_SIZE];

    /**
     * Rudimentary input parameter validation
     */
    if( NULL == pMessage )
    {
        return( EAESCMACUPIVLDMSG );
    }

    if( 0u == messageLen )
    {
        return( EAESCMACUPIVLDMSGLEN );
    }

    if( ( 0u == messageCapacity ) ||
        ( messageLen > messageCapacity ) )
    {
        return( EAESCMACUPIVLDMSGCAP );
    }

    /**
     * clear the working block.
     */
    (void)host_memset( block, 0x00, AES_BLOCK_SIZE );

    for( i = 0; i < blockCount; i++ )
    {
        /**
         * Do not modify the original text, cache the block.
         */
        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_memcpy( block, &pMessage[ ( AES_BLOCK_SIZE * i ) ], AES_BLOCK_SIZE );
        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_memxor( block, mac, AES_BLOCK_SIZE );

        if( VLT_OK != ( status = CipherUpdate( block,
            AES_BLOCK_SIZE,
            mac,
            &outCount,
            AES_BLOCK_SIZE ) ) )
        {
            return( status );
        }
    }

    return ( VLT_OK );
}

VLT_U16 SignerAesCmacGetBlockSize( void )
{
    return ( CipherGetBlockSize() );
}


/**

RFC 4493                 The AES-CMAC Algorithm                June 2006


   Figure 2.2 specifies the subkey generation algorithm.

   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   +                    Algorithm Generate_Subkey                      +
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
   +                                                                   +
   +   Input    : K (128-bit key)                                      +
   +   Output   : Key1 (128-bit first subkey)                            +
   +              Key2 (128-bit second subkey)                           +
   +-------------------------------------------------------------------+
   +                                                                   +
   +   Constants: const_Zero is 0x00000000000000000000000000000000     +
   +              const_Rb   is 0x00000000000000000000000000000087     +
   +   Variables: L          for output of AES-128 applied to 0^128    +
   +                                                                   +
   +   Step 1.  L := AES-128(K, const_Zero);                           +
   +   Step 2.  if MSB(L) is equal to 0                                +
   +            then    Key1 := L << 1;                                  +
   +            else    Key1 := (L << 1) XOR const_Rb;                   +
   +   Step 3.  if MSB(K1) is equal to 0                               +
   +            then    Key2 := Key1 << 1;                                 +
   +            else    Key2 := (Key1 << 1) XOR const_Rb;                  +
   +   Step 4.  return Key1, K2;                                         +
   +                                                                   +
   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/
VLT_STS generateSubKeys( const VLT_KEY_BLOB *pKey, VLT_U8 *Key1, VLT_U8 *Key2 )
{   
    VLT_CIPHER_PARAMS theParams = {0};
    VLT_STS status;
    VLT_U32 outLen = 0;
    VLT_U8 L[AES_BLOCK_SIZE] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    VLT_U8 Zero[AES_BLOCK_SIZE] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    VLT_U8 Rb[AES_BLOCK_SIZE] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
    };  

    /**
     *
     * Step 1.  L := AES-128(K, const_Zero);
     *
     */ 

    /**
     * Algorithm AES
     * Padding None
     * Block Mode ECB
     */
    theParams.enAlgoID = VLT_ALG_CIP_AES;
    theParams.enPaddingScheme = VLT_PADDING_NONE;
    theParams.enChainMode = VLT_BLOCK_MODE_ECB;
    theParams.pIV = 0;  

    /**
     * Initialise the Cipher
     */
    if( VLT_OK != ( status = CipherInit( VLT_ENCRYPT_MODE , pKey, &theParams ) ) )
    {
        return( status );
    }   

    /**
     * Encrypt the text
     */
    if( VLT_OK != ( status = CipherDoFinal( Zero,
        AES_BLOCK_SIZE,
        AES_BLOCK_SIZE,
        L,
        &outLen,
        AES_BLOCK_SIZE ) ) )
    {
        return( status );
    }

    /**
     * Release the Cipher.
     */
    if( VLT_OK != ( status = CipherClose() ) )
    {
        return( status );
    }

    /**
     *
     * Step 2.  if MSB(L) is equal to 0
     *          then    Key1 := L << 1;
     *          else    Key1 := (L << 1) XOR const_Rb;
     *
     */ 
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( Key1, L, AES_BLOCK_SIZE );
    if( 0u == ( Key1[0] & 0x80u ) )
    {
        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_lshift( Key1, 16, 1 );
    }
    else
    {
        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_lshift( Key1, 16, 1 );
        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_memxor( Key1, Rb, 16 );
    }

    /**
     *
     * Step 3.  if MSB(K1) is equal to 0
     *          then    Key2 := Key1 << 1;
     *          else    Key2 := (Key1 << 1) XOR const_Rb;
     *
     */ 
    /*
    * No need to check the return type as pointer has been validated
    */
    (void)host_memcpy( Key2, Key1, AES_BLOCK_SIZE );
    if( 0u == ( K2[0] & 0x80u ) )
    {
        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_lshift( Key2, 16, 1 );
    }
    else
    {
        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_lshift( Key2, 16, 1 );
        /*
        * No need to check the return type as pointer has been validated
        */
        (void)host_memxor( Key2, Rb, 16 );
    }

    return( VLT_OK );
}

#endif /*( VLT_ENABLE_CIPHER_AES == VLT_ENABLE )*/

#if( VLT_ENABLE_CIPHER_TESTS == VLT_ENABLE )

VLT_STS AesCMacExample2(void)
{
    VLT_STS status;

    VLT_U8 K[] =
    {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    VLT_U8 Msg[] =
    {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };

    VLT_U8 ExpectedMac[] =
    {
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44,
        0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c
    };

    VLT_U8 CalculatedMac[] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    VLT_U32 macLen = AES_BLOCK_SIZE;

    VLT_KEY_BLOB keyBlob = {0};
    keyBlob.keyType = VLT_KEY_AES_128 ;
    keyBlob.keySize = AES_128_KEY_SIZE;
    keyBlob.keyValue = K;
    
    if( VLT_OK != ( status = SignerAesCmacInit( VLT_SIGN_MODE,
        &keyBlob, 0 ) ) )
    {
        return( status );
    }

    if( VLT_OK != ( status = SignerAesCmacDoFinal( Msg,
        NELEMS(Msg),
        NELEMS(Msg),
        CalculatedMac,
        &macLen,
        NELEMS(CalculatedMac) ) ) )
    {
        return( status );
    }

    (void)SignerAesCmacClose();

    if( host_memcmp( CalculatedMac, ExpectedMac, NELEMS(ExpectedMac) ) != 0u )
    {
        return( VLT_FAIL );
    }

    return( VLT_OK );
}

VLT_STS AesCMacExample3(void)
{
    VLT_STS status;

    VLT_U8 K[] =
    {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    VLT_U8 Msg[] =
    {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    VLT_U8 ExpectedMac[] =
    {
        0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30,
        0x30, 0xca, 0x32, 0x61, 0x14, 0x97, 0xc8, 0x27
    };

    VLT_U8 CalculatedMac[] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    VLT_U32 macLen = AES_BLOCK_SIZE;

    VLT_KEY_BLOB keyBlob = {0};
    keyBlob.keyType = VLT_KEY_AES_128;
    keyBlob.keySize = AES_128_KEY_SIZE;
    keyBlob.keyValue = K;
    
    if( VLT_OK != ( status = SignerAesCmacInit( VLT_SIGN_MODE,
        &keyBlob, 0 ) ) )
    {
        return( status );
    }

    if( VLT_OK != ( status = SignerAesCmacDoFinal( Msg,
        40,
        NELEMS(Msg),
        CalculatedMac,
        &macLen,
        NELEMS(CalculatedMac) ) ) )
    {
        return( status );
    }

    (void)SignerAesCmacClose();

    if( host_memcmp( CalculatedMac, ExpectedMac, NELEMS(ExpectedMac) ) != 0u)
    {
        return( VLT_FAIL );
    }

    return( VLT_OK );
}


VLT_STS AesCMacExample4(void)
{
    VLT_STS status;

    VLT_U8 K[] =
    {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };

    VLT_U8 Msg[] =
    {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
        0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
        0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
    };

    VLT_U8 ExpectedMac[] =
    {
        0x51, 0xf0, 0xbe, 0xbf, 0x7e, 0x3b, 0x9d, 0x92,
        0xfc, 0x49, 0x74, 0x17, 0x79, 0x36, 0x3c, 0xfe
    };

    VLT_U8 CalculatedMac[] =
    {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    VLT_U32 macLen = AES_BLOCK_SIZE;

    VLT_KEY_BLOB keyBlob = {0};
    keyBlob.keyType = VLT_KEY_AES_128;
    keyBlob.keySize = AES_128_KEY_SIZE;
    keyBlob.keyValue = K;
    
    if( VLT_OK != ( status = SignerAesCmacInit( VLT_SIGN_MODE,
        &keyBlob, 0 ) ) )
    {
        return( status );
    }

    if( VLT_OK != ( status = SignerAesCmacDoFinal( Msg,
        NELEMS(Msg),
        NELEMS(Msg),
        CalculatedMac,
        &macLen,
        NELEMS(CalculatedMac) ) ) )
    {
        return( status );
    }

    (void)SignerAesCmacClose();

    if( host_memcmp( CalculatedMac, ExpectedMac, NELEMS(ExpectedMac) ) != 0u)
    {
        return( VLT_FAIL );
    }

    return( VLT_OK );
}
#endif/*( VLT_ENABLE_CIPHER_TESTS == VLT_ENABLE )*/

/**
 *
 * The following test vectors are the same as those of [NIST-CMAC].  The
 * following vectors are also the output of the test program in Appendix
 * A.
 *
 */
VLT_STS AesCMacTest(void)
{
#if( VLT_ENABLE_CIPHER_TESTS == VLT_ENABLE ) 
	VLT_STS status = VLT_OK;

    if( VLT_OK != ( status = AesCMacExample2() ) )
    {
        return( status );
    }

    if( VLT_OK != ( status = AesCMacExample3() ) )
    {
        return( status );
    }
    
    if( VLT_OK != ( status = AesCMacExample4() ) )
    {
        return( status );
    }
#endif /*( VLT_ENABLE_CIPHER_TESTS == VLT_ENABLE )*/

    return( VLT_OK );
}
#endif