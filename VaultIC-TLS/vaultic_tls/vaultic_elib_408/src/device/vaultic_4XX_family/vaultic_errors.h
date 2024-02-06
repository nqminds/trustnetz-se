/**
* @file    vaultic_errors.h
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
* @brief Errors returned by the VaultIC API.
*
* @par Description:
* This file enumerates all errors returned by the VaultIC API. Unique error
* codes are provided for every possible failure case.
*/

#ifndef VAULTIC_ERR_H
#define VAULTIC_ERR_H

#define VLT_ERROR( module, errorcode ) ((VLT_U16)((module) + (errorcode)))

/*
* Module Error codes
*/
#define VLT_GLOBAL                                      0xC000u
#define VLT_COMMS                                       0xC100u
#define VLT_API                                         0xC200u
#define VLT_API2                                        0xC300u
#define VLT_DES                                         0xC400u
#define VLT_TDES                                        0xC500u
#define VLT_CIPHER                                      0xC600u
#define VLT_PADDING                                     0xC700u
#define VLT_ISO7816                                     0xC800u
#define VLT_SIGNER                                      0xC900u
#define VLT_SECCHAN                                     0xCA00u
#define VLT_SCP02                                       0xCB00u
#define VLT_BLKPTCL                                     0xCC00u
#define VLT_PTCL                                        0xCD00u
#define VLT_SPI                                         0xCE00u
#define VLT_TWI                                         0xCF00u
#define VLT_AES                                         0xD000u
#define VLT_SCP03                                       0xD100u
#define VLT_AES_CMAC                                    0xD200u
#define VLT_ISO9797_MAC                                 0xD300u
#define VLT_KEY_WRAP                                    0xD400u
#define VLT_MS_AUTH                                     0xD500u

#define VLT_DERIVE                                      0xD700u
#define VLT_ID_AUTH                                     0xD800u
#define VLT_FILE_SYS                                    0xD900u
#define VLT_MEM                                         0xDA00u
#define VLT_CRC16                                       0xDB00u
#define VLT_ID_AUTH2                                    0xDC00u
#define VLT_STRONG_AUTH                                 0xDD00u
#define VLT_CRYPTO                                      0xDE00u
#define VLT_ECDSA                                       0xDF00u
#define VLT_HMAC                                        0xE000u
#define VLT_API3                                        0xE100u
#define VLT_SCP11                                       0xE200u
#define VLT_ECC                                         0xE300u
#define VLT_ECDH                                        0xE400u
#define VLT_AES_KW                                      0xE500u
#define VLT_OWI                                         0xE600u
#define VLT_WBOARD                                      0xE700u
#define VLT_CERT                                        0xE800u
#define VLT_DIGEST                                      0xE900u
#define VLT_FAST_AUTH                                   0xEA00u

/*
* Global Error Codes
*/
/**
  * \addtogroup Constants
  */
#define VLT_OK                                          VLT_ERROR( VLT_GLOBAL, 0u ) /*!< Denotes successful completion of an API call */
/**
 * \addtogroup Constants
 */
#define VLT_FAIL                                        VLT_ERROR( VLT_GLOBAL, 1u ) /*!< Denotes generic failure of an API call */
/**
 * \addtogroup Constants
 */
#define VLT_EOF                                         VLT_ERROR( VLT_GLOBAL, 2u ) /*!< Denotes the end of a file being reached. */
/**
 * \addtogroup Constants
 */
#define EMETHODNOTSUPPORTED                             VLT_ERROR( VLT_GLOBAL, 3u ) /*!<Denotes the API method call is not supported. */
/**
 * \addtogroup Constants
 */
#define VLT_MORE_TIME                                   VLT_ERROR( VLT_GLOBAL, 4u ) /*!< Denotes more timer requested for completion of an API call.*/


/*
 * API Error Codes
 */
#define ESPNULLPARA                                     VLT_ERROR( VLT_API, 0u )
#define EMADPASSLENIVLD                                 VLT_ERROR( VLT_API, 1u )
#define EMADMSPKEYSINVLD                                VLT_ERROR( VLT_API, 2u )
#define EMADSCPKEYSINVLD                                VLT_ERROR( VLT_API, 3u )
#define ESPPASSLENIVLD                                  VLT_ERROR( VLT_API, 4u )
#define EEAIVLDCRPTLEN                                  VLT_ERROR( VLT_API, 5u )
#define EGIAIVLDSIGLEN                                  VLT_ERROR( VLT_API, 6u )
#define EIUNULLPARA                                     VLT_ERROR( VLT_API, 10u )
#define EIUBADSCP                                       VLT_ERROR( VLT_API, 11u )
#define ESETCNFGNULLDATA                                VLT_ERROR( VLT_API, 12u )
#define ESETCNFGIVLDAARLEN                              VLT_ERROR( VLT_API, 13u )
#define ESETCNFGIVLDDTLEN                               VLT_ERROR( VLT_API, 14u )
#define ESETCNFGIVLDI2CLEN                              VLT_ERROR( VLT_API, 15u )
#define ESETCNFGIVLDITEM                                VLT_ERROR( VLT_API, 16u )
#define EGEAINVLDHOSTCHLEN                              VLT_ERROR( VLT_API, 17u )
#define EGEAINVLDHOSTSIGLEN                             VLT_ERROR( VLT_API, 18u )
#define ELFNOROOM                                       VLT_ERROR( VLT_API, 19u )
#define EEANULLPARA                                     VLT_ERROR( VLT_API, 20u )
#define EEABADCHAN                                      VLT_ERROR( VLT_API, 21u )
#define ELFNULLPARAM                                    VLT_ERROR( VLT_API, 22u )
#define ELFIVLDRESPLEN                                  VLT_ERROR( VLT_API, 23u )
#define ERFNULLPARAM                                    VLT_ERROR( VLT_API, 24u )
#define ERFINVLDLEN                                     VLT_ERROR( VLT_API, 25u )
#define ERFLENEXDMAXSZ                                  VLT_ERROR( VLT_API, 26u )
#define ESETCNFGIVLDSPILEN                              VLT_ERROR( VLT_API, 27u )
#define EWFIVLDLEN                                      VLT_ERROR( VLT_API, 28u )
#define EGRNULLPARAM                                    VLT_ERROR( VLT_API, 29u )
#define EMADNULLPARA                                    VLT_ERROR( VLT_API, 30u )
#define EMADBADOPER                                     VLT_ERROR( VLT_API, 31u )
#define EGRNOROOM                                       VLT_ERROR( VLT_API, 32u )
#define ETC2NULLPARAM                                   VLT_ERROR( VLT_API, 33u )
#define ETC2NOROOM                                      VLT_ERROR( VLT_API, 34u )
#define ESFDINVLDPATHLEN                                VLT_ERROR( VLT_API, 35u )
#define EENINVLDPLTXTLEN                                VLT_ERROR( VLT_API, 36u )
#define EDCINVLDCHPTXTLEN                               VLT_ERROR( VLT_API, 37u )
#define ETC3INVLDLEN                                    VLT_ERROR( VLT_API, 38u )
#define ETC4IVLDSENDLEN                                 VLT_ERROR( VLT_API, 39u )
#define ETC4IVLDRECVLEN                                 VLT_ERROR( VLT_API, 40u )
#define EGAINULLPARA                                    VLT_ERROR( VLT_API, 41u )
#define EVSINVLDMSGLEN                                  VLT_ERROR( VLT_API, 42u )
#define EVSINVLDSIGLEN                                  VLT_ERROR( VLT_API, 43u )
#define EVSINVLDSTATECFG                                VLT_ERROR( VLT_API, 44u )
#define EVSINVLDSTATESND                                VLT_ERROR( VLT_API, 45u )
#define EGTLBINFIVLDPTR                                 VLT_ERROR( VLT_API, 46u )
#define EGASIVLDLEN                                     VLT_ERROR( VLT_API, 47u )
#define EMDINVLDMSGLEN                                  VLT_ERROR( VLT_API, 48u )
#define EMDINVLDSGSTLEN                                 VLT_ERROR( VLT_API, 49u )
#define EMDIVLDSTATE                                    VLT_ERROR( VLT_API, 50u )
#define ERDGPIONULLPARAM                                VLT_ERROR( VLT_API, 51u )
#define ERKSCIVLDCRC                                    VLT_ERROR( VLT_API, 52u )
#define ERKHOTPIVLDCRC                                  VLT_ERROR( VLT_API, 53u )
#define ERKTOTPIVLDCRC                                  VLT_ERROR( VLT_API, 54u )
#define ERKRSAPBIVLDCRC                                 VLT_ERROR( VLT_API, 55u )
#define ERKRSAPRIVLDCRC                                 VLT_ERROR( VLT_API, 56u )
#define ERKRSACRIVLDCRC                                 VLT_ERROR( VLT_API, 57u )
#define ERKDSAPBIVLDCRC                                 VLT_ERROR( VLT_API, 58u )
#define ERKDSAPRIVLDCRC                                 VLT_ERROR( VLT_API, 59u )
#define ERKECDSAPBIVLDCRC                               VLT_ERROR( VLT_API, 60u )
#define ERKECDSAPRIVLDCRC                               VLT_ERROR( VLT_API, 61u )
#define EGCNULLPARA                                     VLT_ERROR( VLT_API, 62u )
#define ERKRAWNOROOM                                    VLT_ERROR( VLT_API, 63u )
#define EGTDEVSIVLDPARAM                                VLT_ERROR( VLT_API, 64u )
#define EGTDEVSIVLDSTR                                  VLT_ERROR( VLT_API, 65u )
#define EGTDEVSINSFLEN                                  VLT_ERROR( VLT_API, 66u )
#define ERKIDNULLPARA                                   VLT_ERROR( VLT_API, 67u )
#define ERKIDBADFIELD                                   VLT_ERROR( VLT_API, 68u )
#define ERKIDNOROOM                                     VLT_ERROR( VLT_API, 69u )
#define ERKIDIVLDCRC                                    VLT_ERROR( VLT_API, 70u )
#define EGIABADPARAM                                    VLT_ERROR( VLT_API, 71u )
#define EGIANOROOM                                      VLT_ERROR( VLT_API, 72u )
#define ERKDSAPARAMSNULLPARA                            VLT_ERROR( VLT_API, 73u )
#define ERKDSAPARAMSBADFIELD                            VLT_ERROR( VLT_API, 74u )
#define ERKDSAPARAMSIVLDCRC                             VLT_ERROR( VLT_API, 75u )
#define ERKECDSAPARAMSNULLPARA                          VLT_ERROR( VLT_API, 76u )
#define ERKECDSAPARAMSBADFIELD                          VLT_ERROR( VLT_API, 77u )
#define ERKECDSAPARAMSNOROOM                            VLT_ERROR( VLT_API, 78u )
#define ERKECDSAPARAMSIVLDCRC                           VLT_ERROR( VLT_API, 79u )
#define EGEANULLPARA                                    VLT_ERROR( VLT_API, 80u )
#define ERKKEYGENNULLPARA                               VLT_ERROR( VLT_API, 81u )
#define ERKKEYGENNODATA                                 VLT_ERROR( VLT_API, 82u )
#define ERKKEYGENIVLDCRC                                VLT_ERROR( VLT_API, 83u )
#define EGRZEROBYTES                                    VLT_ERROR( VLT_API, 84u )
#define ETC2ZEROBYTES                                   VLT_ERROR( VLT_API, 85u )
#define ERFZEROBYTES                                    VLT_ERROR( VLT_API, 86u )
#define ERFNOROOM                                       VLT_ERROR( VLT_API, 87u )
#define EGAIINVDPARA                                    VLT_ERROR( VLT_API, 88u )


#define EIANULLPARA                                     VLT_ERROR( VLT_API, 90u )
#define EIABADALGO                                      VLT_ERROR( VLT_API, 91u )
#define EPKNULLPARA                                     VLT_ERROR( VLT_API, 100u )
#define ERKNULLPARA                                     VLT_ERROR( VLT_API, 110u )
#define ERKMISMATCH                                     VLT_ERROR( VLT_API, 112u )
#define ERKNOROOM                                       VLT_ERROR( VLT_API, 113u )
#define ERKUNSUPPKEY                                    VLT_ERROR( VLT_API, 114u )
#define EGSNULLPARA                                     VLT_ERROR( VLT_API, 150u )
#define EGSINVLLENGTH                                   VLT_ERROR( VLT_API, 151u )
#define EUMDNULLPARA                                    VLT_ERROR( VLT_API, 152u )
#define EUVNULLPARA                                     VLT_ERROR( VLT_API, 153u )

#define EVSNULLPARA                                     VLT_ERROR( VLT_API, 160u )
#define EGASNULLPARA                                    VLT_ERROR( VLT_API, 170u )
#define EGASNOROOM                                      VLT_ERROR( VLT_API, 171u )
#define EMDNULLPARA                                     VLT_ERROR( VLT_API, 180u )
#define EMDNOROOM                                       VLT_ERROR( VLT_API, 181u )
#define EGKPNULLPARA                                    VLT_ERROR( VLT_API, 200u )
#define EGKPBADKPG                                      VLT_ERROR( VLT_API, 201u )
#define ESFNULLPARA                                     VLT_ERROR( VLT_API, 230u )
#define ESFEXPSUC                                       VLT_ERROR( VLT_API, 231u )
#define EC4NULLPARA                                     VLT_ERROR( VLT_API, 130u )
#define EC4NOROOM                                       VLT_ERROR( VLT_API, 131u )
#define EC1NULLPARA                                     VLT_ERROR( VLT_API, 140u )
#define EPKBADFIELDRSACRT                               VLT_ERROR( VLT_API, 101u )
#define ERKINVLDRSP                                     VLT_ERROR( VLT_API, 111u )
#define ERKBADFIELD                                     VLT_ERROR( VLT_API, 115u )
#define EPKBADFLDECDSAPUB                               VLT_ERROR( VLT_API, 116u )
#define EIAOAEPNULLPARA                                 VLT_ERROR( VLT_API, 117u )

#define ENFCFORUMSELECT                                 VLT_ERROR( VLT_API, 118u )
#define ENFCFORUMREADPARAMNULL                          VLT_ERROR( VLT_API, 119u )
#define ENFCFORUMUPTPARAMNULL                           VLT_ERROR( VLT_API, 120u )

#define ENFCREADPARAMNULL                               VLT_ERROR( VLT_API, 130u )
#define ENFCUPTBINPARAMNULL                             VLT_ERROR( VLT_API, 131u )

#define ERKRAWNULLPARA                                  VLT_ERROR( VLT_API, 240u )
#define ERKSECNULLPARA                                  VLT_ERROR( VLT_API, 241u )
#define ERKHPNULLPARA                                   VLT_ERROR( VLT_API, 242u )
#define ERKTPNULLPARA                                   VLT_ERROR( VLT_API, 243u )
#define ERKRPUBNULLPARA                                 VLT_ERROR( VLT_API, 244u )
#define ERKRPRIVNULLPARA                                VLT_ERROR( VLT_API, 245u )
#define ERKRCRTNULLPARA                                 VLT_ERROR( VLT_API, 246u )
#define ERKDPUBNULLPARA                                 VLT_ERROR( VLT_API, 247u )
#define ERKDPRIVNULLPARA                                VLT_ERROR( VLT_API, 248u )
#define ERKEPUBNULLPARA                                 VLT_ERROR( VLT_API, 249u )
#define ERKEPRIVNULLPARA                                VLT_ERROR( VLT_API, 250u )
#define ERKSECNOROOM                                    VLT_ERROR( VLT_API, 251u )
#define ERKHPNOROOM                                     VLT_ERROR( VLT_API, 252u )
#define ERKTPNOROOM                                     VLT_ERROR( VLT_API, 253u )
#define ERKRPUBNOROOM                                   VLT_ERROR( VLT_API, 254u )
#define ERKRPRIVNOROOM                                  VLT_ERROR( VLT_API, 255u )



/*
 * API 2 Error Codes
 */
#define ESRANULLPARA                                    VLT_ERROR( VLT_API2, 9u )
#define ECFNULLPARA                                     VLT_ERROR( VLT_API2, 10u )
#define EIUINVLDPARAM                                   VLT_ERROR( VLT_API2, 11u )
#define EGCINVLDDEVIDPTH                                VLT_ERROR( VLT_API2, 12u )
#define EGCINVLDHSTIDPTH                                VLT_ERROR( VLT_API2, 13u )
#define EGCDATATOOLRG                                   VLT_ERROR( VLT_API2, 14u )
#define EIADATATOOLRG                                   VLT_ERROR( VLT_API2, 15u )
#define ECFILNMLENTOOBIG                                VLT_ERROR( VLT_API2, 16u )
#define ECFOLNMLENTOOBIG                                VLT_ERROR( VLT_API2, 17u )
#define ECFLINVLDLEN                                    VLT_ERROR( VLT_API2, 18u )
#define ECFINVLDLEN                                     VLT_ERROR( VLT_API2, 19u )
#define ECFLNULLPARA                                    VLT_ERROR( VLT_API2, 20u )
#define ECFLINVLUSERID                                  VLT_ERROR( VLT_API2, 21u ) /* Invalid file creation parameter User ID */
#if ((VAULT_IC_VERSION == VAULTIC_183) ||(VAULT_IC_VERSION ==  VAULTIC_186))
#define ESHCNULLPARAM                                   VLT_ERROR( VLT_API2, 30u )
#define ESHCINVLENGTH                                   VLT_ERROR( VLT_API2, 31u )
#define EDCINVLDAUTHMTHD                                VLT_ERROR( VLT_API2, 32u )
#define EVSINVLDPUBKEYLEN                               VLT_ERROR( VLT_API2, 33u )
#endif
#define EWFNULLPARA                                     VLT_ERROR( VLT_API2, 40u )
#define EWFTOOBIG                                       VLT_ERROR( VLT_API2, 41u )
#define EWFBADPARAM                                     VLT_ERROR( VLT_API2, 42u )
#define ESANULLPARA                                     VLT_ERROR( VLT_API2, 90u )
#define ESPVNULLPARA                                    VLT_ERROR( VLT_API2, 91u )
#define EGINULLPARA                                     VLT_ERROR( VLT_API2, 100u )
#define ESTNULLPARA                                     VLT_ERROR( VLT_API2, 110u )
#define EGTINFOIVLDRESPLEN                              VLT_ERROR( VLT_API2, 111u )
#define ESCNULLPARA                                     VLT_ERROR( VLT_API2, 130u )
#define EENULLPARA                                      VLT_ERROR( VLT_API2, 140u )
#define EDNULLPARA                                      VLT_ERROR( VLT_API2, 150u )
#define ETC3NULLPARA                                    VLT_ERROR( VLT_API2, 160u )
#define ETC3TOOBIG                                      VLT_ERROR( VLT_API2, 161u )
#define ETC4NULLPARA                                    VLT_ERROR( VLT_API2, 170u )
#define ETC4TOOBIG                                      VLT_ERROR( VLT_API2, 171u )
#define ETC4NOROOM                                      VLT_ERROR( VLT_API2, 172u )
#define EGPDNULLPARA                                    VLT_ERROR( VLT_API2, 180u )
#define EGPWNULLPARA                                    VLT_ERROR( VLT_API2, 190u )
#define EGPRNULLPARA                                    VLT_ERROR( VLT_API2, 200u )
#define EC2NULLPARA                                     VLT_ERROR( VLT_API2, 30u )
#define EC2TOOBIG                                       VLT_ERROR( VLT_API2, 31u )
#define EC2ANULLPARA                                    VLT_ERROR( VLT_API2, 60u )
#define EC2ANOROOM                                      VLT_ERROR( VLT_API2, 61u )
#define EC2AINVLDRSP                                    VLT_ERROR( VLT_API2, 62u )
#define EGTBADSW                                        VLT_ERROR( VLT_API2, 211u )
#define EGTINVLDSWSZ                                    VLT_ERROR( VLT_API2, 210u )
#define ECINVLDSWSZ                                     VLT_ERROR( VLT_API2, 217u )
#define ECINVLDRSP                                      VLT_ERROR( VLT_API2, 218u )
#define EICIVLDRESPLEN                                  VLT_ERROR( VLT_API2, 219u )
#define EDCNULLPARAM                                    VLT_ERROR( VLT_API2, 220u )
#define EDCINVLDLEN                                     VLT_ERROR( VLT_API2, 221u )
#define EDCINVLDVAL                                     VLT_ERROR( VLT_API2, 222u )
#define ERKRCRTNOROOM                                   VLT_ERROR( VLT_API2, 223u )
#define ERKDPUBNOROOM                                   VLT_ERROR( VLT_API2, 224u )
#define ERKDPRIVNOROOM                                  VLT_ERROR( VLT_API2, 225u )
#define ERKEPUBNOROOM                                   VLT_ERROR( VLT_API2, 226u )
#define ERKEPRIVNOROOM                                  VLT_ERROR( VLT_API2, 227u )
#define ERKCMDNULLPARA                                  VLT_ERROR( VLT_API2, 228u )
#define EPKEPRIVNULLPARA                                VLT_ERROR( VLT_API2, 229u )
#define EPKEPUBNULLPARA                                 VLT_ERROR( VLT_API2, 230u )
#define EPKDPRIVNULLPARA                                VLT_ERROR( VLT_API2, 231u )
#define EPKDPUBNULLPARA                                 VLT_ERROR( VLT_API2, 232u )
#define EPKRCRTNULLPARA                                 VLT_ERROR( VLT_API2, 233u )
#define EPKRPUBBADPARAM                                 VLT_ERROR( VLT_API2, 234u )
#define EPKTPNULLPARA                                   VLT_ERROR( VLT_API2, 235u )
#define EPKRAWNULLPARA                                  VLT_ERROR( VLT_API2, 236u )
#define EPKHPNULLPARA                                   VLT_ERROR( VLT_API2, 237u )
#define EPKDSAPARAMNULLPARA                             VLT_ERROR( VLT_API2, 238u )
#define EPKECDSAPRMNULLPARA                             VLT_ERROR( VLT_API2, 239u )
#define EPKIDNULLPARA                                   VLT_ERROR( VLT_API2, 240u )
#define EGASINVLDLEN                                    VLT_ERROR( VLT_API2, 241u )
#define EGAINVLDRECLEN                                  VLT_ERROR( VLT_API2, 242u )
#define EGAINVLDSIGNERID                                VLT_ERROR( VLT_API2, 242u )
#define ESETCNFGIVLDCOMMLEN                             VLT_ERROR( VLT_API2, 243u )
#define ESETCNFGIVLDGPIOLEN                             VLT_ERROR( VLT_API2, 244u )
#define ESETCNFGIVLDUSBMAXLEN                           VLT_ERROR( VLT_API2, 245u )
#define EGETCHALLENGENULLDATA                           VLT_ERROR( VLT_API2, 246u )
#define EGETCHALLENGEINVLENGTH                          VLT_ERROR( VLT_API2, 247u )
#define EDEACTIVATENULLDATA                             VLT_ERROR( VLT_API2, 248u )
#define EDEACTIVATEINVLENGTH                            VLT_ERROR( VLT_API2, 249u )
#define EICNULLPARAM                                    VLT_ERROR( VLT_API2, 250u )
#define EICINVLDLEN                                     VLT_ERROR( VLT_API2, 251u )
#define EICINVLDVAL                                     VLT_ERROR( VLT_API2, 252u )
#define ESETCNTNULLDATA                                 VLT_ERROR( VLT_API2, 253u )
#define ESETCNTINVLDLEN                                 VLT_ERROR( VLT_API2, 254u )
#define ESETCNTINVLDVAL                                 VLT_ERROR( VLT_API2, 255u )
#define EFMANULLPARAM                                   VLT_ERROR( VLT_API, 229u )
#define EGDNULLPARAM                                    VLT_ERROR( VLT_API, 230u )
#define EGDINVLDLEN                                     VLT_ERROR( VLT_API, 231u )
#define EGDNOROOM                                       VLT_ERROR( VLT_API, 232u )
#define EPCSONULLPARAM                                  VLT_ERROR( VLT_API, 233u )
#define EPCSONOCERT                                     VLT_ERROR( VLT_API, 234u )
#define EMANULLPARAM                                    VLT_ERROR( VLT_API, 235u )
#define EMAHOSTNOROOM                                   VLT_ERROR( VLT_API, 236u )
#define EMARSPDATAMALFORMATED                           VLT_ERROR( VLT_API, 237u )
#define EMARSPDATARCPLENINVL                            VLT_ERROR( VLT_API, 238u )
#define EMAPARAMINVL                                    VLT_ERROR( VLT_API, 239u )
#define EMADATABUFFERNULL                               VLT_ERROR( VLT_API, 240u )
#define EFASTAUTHNULLPARAM                              VLT_ERROR( VLT_API, 241u )
#define EFASTAUTHINVALIDPARAM                           VLT_ERROR( VLT_API, 242u )
#define ESETCNFGIVLDADMINPOLICYVALUE                    VLT_ERROR( VLT_API, 243u )
#define ESETCNFGIVLDDATALEN                             VLT_ERROR( VLT_API, 244u )

/*
 * API 3 Error Codes
 */
#define EGKNULLPARA                                     VLT_ERROR( VLT_API3, 1u )
#define EGKIVDKEYID                                     VLT_ERROR( VLT_API3, 2u )

/*  Submit Secure Password */
#define ESSPNULLPARAM                                   VLT_ERROR( VLT_API3, 3u )
#define ESSPNOROOM                                      VLT_ERROR( VLT_API3, 4u )
#define ESSPINVLUSERID                                  VLT_ERROR( VLT_API3, 5u ) /* Invalid User ID */
#define ESSPINVLROLEID                                  VLT_ERROR( VLT_API3, 6u ) /* Invalid Role ID */



/*
 * Secure Channel Generic (SCP)
 */
#define ESCPINITNULLPARAM                               VLT_ERROR( VLT_SECCHAN, 0u )
#define ESCPINITUPDTMODE                                VLT_ERROR( VLT_SECCHAN, 1u )
#define ESCPGENRANDFAIL                                 VLT_ERROR( VLT_SECCHAN, 2u )
#define ESCPINITUPDTFAIL                                VLT_ERROR( VLT_SECCHAN, 3u )
#define SCPGETSTATENULLPARAM                            VLT_ERROR( VLT_SECCHAN, 4u )
#define ESCP11INITNULLPARAM                             VLT_ERROR( VLT_SECCHAN, 5u )

/*
* Secure Channel SCP02 specific
*/
#define ESCP02INITNULLPARAM                             VLT_ERROR( VLT_SCP02, 0u )
#define ESCP02INVLDDEVCRYPTO                            VLT_ERROR( VLT_SCP02, 1u )
#define ESCP02WRAPNULLPARAM                             VLT_ERROR( VLT_SCP02, 2u )
#define ESCP02UNWRAPNULLPARAM                           VLT_ERROR( VLT_SCP02, 3u )
#define ESCP02ADDMACNULLPARAM                           VLT_ERROR( VLT_SCP02, 4u )
#define ESCP02DERSESSKEYNULLPARAM                       VLT_ERROR( VLT_SCP02, 5u )
#define ESCP02TDESEDECBCNP                              VLT_ERROR( VLT_SCP02, 6u )
#define ESCP02ISO9797MACALGO1                           VLT_ERROR( VLT_SCP02, 7u )
#define ESCP02UPDTCMACIV                                VLT_ERROR( VLT_SCP02, 8u )
#define ESCP02ENCCMDDATANULLPARAM                       VLT_ERROR( VLT_SCP02, 9u )
#define ESCP02CALCMACINVLDMODE                          VLT_ERROR( VLT_SCP02, 10u )
#define ESCP02DECCMDDATANULLPARAM                       VLT_ERROR( VLT_SCP02, 11u )
#define ESCP02INVLDRMAC                                 VLT_ERROR( VLT_SCP02, 12u )
#define ESCP02INVLDCMAC                                 VLT_ERROR( VLT_SCP02, 13u )
#define ESCP02EXTAUTHFAIL                               VLT_ERROR( VLT_SCP02, 14u )
#define ESCP02GETOVHDNULLPARAM                          VLT_ERROR( VLT_SCP02, 15u )
#define ESCP02GETOVHDINVLDMODE                          VLT_ERROR( VLT_SCP02, 16u )
#define ESCP02INITINVLDSMAC                             VLT_ERROR( VLT_SCP02, 17u )
#define ESCP02INITINVLDSENC                             VLT_ERROR( VLT_SCP02, 18u )

/*
* Secure Channel SCP03 specific
*/
#define ESCP03DERSESSKEYNULLPARAM                       VLT_ERROR( VLT_SCP03, 0u )
#define ESCP03INVLDDEVCRYPTO                            VLT_ERROR( VLT_SCP03, 1u )
#define ESCP03EXTAUTHFAIL                               VLT_ERROR( VLT_SCP03, 2u )
#define ESCP03ADDMACNULLPARAM                           VLT_ERROR( VLT_SCP03, 3u )
#define ESCP03CALCMACINVLDMODE                          VLT_ERROR( VLT_SCP03, 4u )
#define ESCP03INITNULLPARAM                             VLT_ERROR( VLT_SCP03, 5u )
#define ESCP0UNWRAPNULLPARAM                            VLT_ERROR( VLT_SCP03, 6u )
#define ESCP03INVLDCMAC                                 VLT_ERROR( VLT_SCP03, 7u )
#define ESCP03INVLDRMAC                                 VLT_ERROR( VLT_SCP03, 8u )
#define ESCP03ENCCMDDATANULLPARAM                       VLT_ERROR( VLT_SCP03, 9u )
#define ESCP03DECCMDDATANULLPARAM                       VLT_ERROR( VLT_SCP03, 10u )
#define ESCP03WRAPNULLPARAM                             VLT_ERROR( VLT_SCP03, 11u )
#define ESCP03GETOVHDNULLPARAM                          VLT_ERROR( VLT_SCP03, 12u )
#define ESCP03GETOVHDINVLDMODE                          VLT_ERROR( VLT_SCP03, 13u )
#define ESCP03INITINVLDSMAC                             VLT_ERROR( VLT_SCP03, 14u )
#define ESCP03INITINVLDSENC                             VLT_ERROR( VLT_SCP03, 15u )

/*
* Secure Channel SCP11 specific
*/
#define ESCP11NOMEMORY                                  VLT_ERROR( VLT_SCP11, 1u )
#define ESCP11SHAREDSECRETNULL                          VLT_ERROR( VLT_SCP11, 2u )
#define ESCP11SHAREDINFONULL                            VLT_ERROR( VLT_SCP11, 3u )
#define ESCP11MUTUALCMDDATANULL                         VLT_ERROR( VLT_SCP11, 4u )
#define ESCP11DOMAININVLD                               VLT_ERROR( VLT_SCP11, 5u )
#define ESCP11SECLEVELINVLD                             VLT_ERROR( VLT_SCP11, 6u )
#define ESCP11DERIVEDKEYNULL                            VLT_ERROR( VLT_SCP11, 7u )
#define ESCP11UNWRAPINVLDCMAC                           VLT_ERROR( VLT_SCP11, 8u )
#define ESCP11UNWRAPINVLDRMAC                           VLT_ERROR( VLT_SCP11, 9u )
#define ESCP11WRAPNULLPARAM                             VLT_ERROR( VLT_SCP11, 10u )
#define ESCP11GETOVHDINVLDMODE                          VLT_ERROR( VLT_SCP11, 11u )
#define ESCP11GETOVHDNULLPARAM                          VLT_ERROR( VLT_SCP11, 12u )
#define ESCP11SETAESNULLPARAM                           VLT_ERROR( VLT_SCP11, 13u )
#define ESCP11GETAESNULLPARAM                           VLT_ERROR( VLT_SCP11, 14u )
#define ESCP11VERIFYRECPTNULLPARAM                      VLT_ERROR(VLT_SCP11, 15u)
#define ESCP11VERIFYRECPTFAILED                         VLT_ERROR(VLT_SCP11, 16u)
#define ESCP11VERIFYNOROOM                              VLT_ERROR(VLT_SCP11, 17u )
#define ESCP11CALCULATERECEIPTNOMEMORY                  VLT_ERROR(VLT_SCP11, 18u )
#define ESCP11BUILDKEYNOROOM                            VLT_ERROR(VLT_SCP11, 19u )
#define ESCP11DERIVEDKEYNULLBUFFER                      VLT_ERROR(VLT_SCP11, 20u )
#define ESCP11SHAREDSECRETNOROOM                        VLT_ERROR( VLT_SCP11, 21u )
#define ESCP11KEYDERIVATIONNOROOM                       VLT_ERROR( VLT_SCP11, 22u )
#define ESCP11INVLDSIGNLEN                              VLT_ERROR( VLT_SCP11, 23u )

/*
* Key Wrapping specific error codes
*/
#define EKWINITNULLPARAM                                VLT_ERROR( VLT_KEY_WRAP, 0u )
#define EKWINITINVLDKTSKEY                              VLT_ERROR( VLT_KEY_WRAP, 1u )
#define EKWWKNULLPARAM                                  VLT_ERROR( VLT_KEY_WRAP, 2u )
#define EKWUKNULLPARAM                                  VLT_ERROR( VLT_KEY_WRAP, 4u )
#define EKWRKINVLDRSP                                   VLT_ERROR( VLT_KEY_WRAP, 6u )
#define EKWUKSCIVLDCRC                                  VLT_ERROR( VLT_KEY_WRAP, 7u )
#define EKWUKWNOROOM                                    VLT_ERROR( VLT_KEY_WRAP, 8u )
#define EKWWKUNINIT                                     VLT_ERROR( VLT_KEY_WRAP, 10u )
#define EKWUKUNINIT                                     VLT_ERROR( VLT_KEY_WRAP, 11u )
#define EKWINITINVLDALGOID                              VLT_ERROR( VLT_KEY_WRAP, 12u )
#define EKWRKINVLDALGOID                                VLT_ERROR( VLT_KEY_WRAP, 13u )
#define EKUWKINVLDALGOID                                VLT_ERROR( VLT_KEY_WRAP, 14u )
#define EKWKINVLIVSIZE                                  VLT_ERROR( VLT_KEY_WRAP, 15u )
#define EKUWKINVLIVSIZE                                 VLT_ERROR( VLT_KEY_WRAP, 15u )
#define EKUWKINVLKEYSIZE                                VLT_ERROR( VLT_KEY_WRAP, 16u )
#define EKWINITINVLDCHAINID                             VLT_ERROR( VLT_KEY_WRAP, 17u )

/*
 * MS Authentication specific error codes
 */
#define EMSINITNULLPARAM                                VLT_ERROR( VLT_MS_AUTH, 0u )
#define EMSINITUPDTFAIL                                 VLT_ERROR( VLT_MS_AUTH, 1u )
#define EMSUSERNOTMS                                    VLT_ERROR( VLT_MS_AUTH, 2u )
#define EMSCGRAMNULLPARAM                               VLT_ERROR( VLT_MS_AUTH, 3u )
#define EMSINITINVDPARAM                                VLT_ERROR( VLT_MS_AUTH, 4u )
#define EMSEXTAUTHFAIL                                  VLT_ERROR( VLT_MS_AUTH, 5u )

/*
* Identity Authentication specific error codes
*/
#define EIDINITNULLPARAM                                VLT_ERROR( VLT_ID_AUTH, 0u )
#define EIDINITSCPNULLPARAM                             VLT_ERROR( VLT_ID_AUTH, 1u )
#define EIDSTATENULLPARAM                               VLT_ERROR( VLT_ID_AUTH, 2u )
#define EIDINITSCPNOTDONE                               VLT_ERROR( VLT_ID_AUTH, 3u )
#define EIDNULLBLOBBASE                                 VLT_ERROR( VLT_ID_AUTH, 10u )
/* ALL VALUES BETWEEN 10 -> 19 are reserved for NULL
 * VLT_KEY_BLOB pointer errors, 10 being the first element
 * of the array and 11 being element 1 ....
 */
#define EIDNULLKEYBASE                                  VLT_ERROR( VLT_ID_AUTH, 20u )
/* ALL VALUES BETWEEN 20 -> 29 are reserved for NULL
 * VLT_KEY_BLOB key pointer errors, 20 being the first element
 * of the array and 11 being element 1 ....
 */
#define EIDNUMKEYS                                      VLT_ERROR( VLT_ID_AUTH, 21u )


/*
 * Identity Authentication version 2 specific error codes
 */
#define EID2INITNULLPARAM                               VLT_ERROR( VLT_ID_AUTH2, 1u )
#define EID2NULLBLOBBASE                                VLT_ERROR( VLT_ID_AUTH2, 2u )
#define EID2NULLKEYBASE                                 VLT_ERROR( VLT_ID_AUTH2, 3u )
#define EID2SCPNOSUPPORT                                VLT_ERROR( VLT_ID_AUTH2, 4u )
#define EID2MSNOSUPPORT                                 VLT_ERROR( VLT_ID_AUTH2, 5u )
#define EID2STRONGNOSUPPORT                             VLT_ERROR( VLT_ID_AUTH2, 6u )
#define EID2AUTHMETHODNS                                VLT_ERROR( VLT_ID_AUTH2, 7u )


/*
* File System specific error codes
*/
#define EFSOPNNULLPARAM                                 VLT_ERROR( VLT_FILE_SYS, 0u )
#define EFSOPNINVLDTRNMD                                VLT_ERROR( VLT_FILE_SYS, 1u )
#define EFSCRTNULLPARAMS                                VLT_ERROR( VLT_FILE_SYS, 2u )
#define EFSCRTINVLDENTRYTYP                             VLT_ERROR( VLT_FILE_SYS, 3u )
#define FSDLTNULLPARAMS                                 VLT_ERROR( VLT_FILE_SYS, 4u )
#define EFSDLTFILERECSV                                 VLT_ERROR( VLT_FILE_SYS, 5u )
#define EFSDLTFOLRECSV                                  VLT_ERROR( VLT_FILE_SYS, 6u )
#define EFSRDNULLPARAMS                                 VLT_ERROR( VLT_FILE_SYS, 7u )
#define EFSWRTNULLPARAMS                                VLT_ERROR( VLT_FILE_SYS, 8u )
#define EFSWRTINVLDRCLMMD                               VLT_ERROR( VLT_FILE_SYS, 9u )
#define EFSSKINVLDORGN                                  VLT_ERROR( VLT_FILE_SYS, 10u )
#define EFSSKEOFSEEK                                    VLT_ERROR( VLT_FILE_SYS, 11u )
#define EFSOPNNOTFILE                                   VLT_ERROR( VLT_FILE_SYS, 12u )
#define EFSOPNALRDYOPN                                  VLT_ERROR( VLT_FILE_SYS, 13u )
#define EFSRDNOFILEOPN                                  VLT_ERROR( VLT_FILE_SYS, 14u )
#define EFSWRTNOFILEOPN                                 VLT_ERROR( VLT_FILE_SYS, 15u )
#define EFSSKNOFILEOPN                                  VLT_ERROR( VLT_FILE_SYS, 16u )
#define EFSCLSNOFILEOPN                                 VLT_ERROR( VLT_FILE_SYS, 17u )
#define EFSOPNINVLDNMLEN                                VLT_ERROR( VLT_FILE_SYS, 18u )
#define EFSCRTINVLDNMLEN                                VLT_ERROR( VLT_FILE_SYS, 19u )
#define EFSDLTINVLDNMLEN                                VLT_ERROR( VLT_FILE_SYS, 20u )
#define EFSDLTINVLDENTRYTYP                             VLT_ERROR( VLT_FILE_SYS, 21u )
#define EFSOPNSLCTFLD                                   VLT_ERROR( VLT_FILE_SYS, 22u )
#define EFSSWDINVLDPTH                                  VLT_ERROR( VLT_FILE_SYS, 23u )
#define EFSSWDINVLDPTHLEN                               VLT_ERROR( VLT_FILE_SYS, 24u )
#define EFSSWDENTRYTOOLONG                              VLT_ERROR( VLT_FILE_SYS, 25u )
#define EFSSWDNULLPARAMS                                VLT_ERROR( VLT_FILE_SYS, 26u )
#define EFSCRTFILEALRDYOPN                              VLT_ERROR( VLT_FILE_SYS, 27u )
#define EFSDLTFILEALRDYOPN                              VLT_ERROR( VLT_FILE_SYS, 28u )
#define EFSLSTNULLPARAMS                                VLT_ERROR( VLT_FILE_SYS, 29u )
#define EFSLSTINVLDRESPLEN                              VLT_ERROR( VLT_FILE_SYS, 30u )
#define EFSLSTALRDYOPN                                  VLT_ERROR( VLT_FILE_SYS, 31u )
#define EFSCFPBYTBTNULLPARAM                            VLT_ERROR( VLT_FILE_SYS, 32u )
#define EFSCFPBTBYTNULLPARAM                            VLT_ERROR( VLT_FILE_SYS, 33u )
#define EFSCONVPRVACC                                   VLT_ERROR( VLT_FILE_SYS, 34u )
#define EFSCONVACCPRV                                   VLT_ERROR( VLT_FILE_SYS, 35u )
#define EFSSTPRIVNULLPARAM                              VLT_ERROR( VLT_FILE_SYS, 36u )
#define EFSSTPRIVINVLDLEN                               VLT_ERROR( VLT_FILE_SYS, 37u )
#define EFSSTATTRBINVLDLEN                              VLT_ERROR( VLT_FILE_SYS, 38u )
#define EFSLSTINVLDLEN                                  VLT_ERROR( VLT_FILE_SYS, 39u )
#define EFSSTATTRNULLPARAM                              VLT_ERROR( VLT_FILE_SYS, 40u )
#define EFSLSTENTRYNOTFLDR                              VLT_ERROR( VLT_FILE_SYS, 41u )
#define EFSSETPRIVALRDYOPN                              VLT_ERROR( VLT_FILE_SYS, 42u )
#define EFSSETATTRALRDYOPN                              VLT_ERROR( VLT_FILE_SYS, 43u )
#define EFSRDSEEKFAILED                                 VLT_ERROR( VLT_FILE_SYS, 44u )
#define EFSRDINVDLEN                                    VLT_ERROR( VLT_FILE_SYS, 45u )
#define EFSWRINVDLEN                                    VLT_ERROR( VLT_FILE_SYS, 46u )
#define EFSWRSEEKFAILED                                 VLT_ERROR( VLT_FILE_SYS, 47u )

/*
 * CRC16 CCITT Specific Error Codes.
 */
#define ECRC16NULLCRCVAL                                VLT_ERROR( VLT_CRC16, 0u )
#define ECRC16NULLBLOCK                                 VLT_ERROR( VLT_CRC16, 1u )

/*
 * Strong Authentication Specific Error Codes
 */
#define ESTRONGINITNULLPARAM                            VLT_ERROR( VLT_STRONG_AUTH, 0u )
#define ESTRONGGENRANDFAIL                              VLT_ERROR( VLT_STRONG_AUTH, 1u )
#define ESTRONGINTAUTHFAIL                              VLT_ERROR( VLT_STRONG_AUTH, 2u )
#define ESTRONGGENSIGNIDFAIL                            VLT_ERROR( VLT_STRONG_AUTH, 3u )
#define ESTRONGGENASSURANCEFAIL                         VLT_ERROR( VLT_STRONG_AUTH, 4u )
#define ESTRONGVERASSMSGFAIL                            VLT_ERROR( VLT_STRONG_AUTH, 5u )
#define ESTRONGAUTHFAIL                                 VLT_ERROR( VLT_STRONG_AUTH, 6u )
#define EINTERNALAUTHVERFAILED                          VLT_ERROR( VLT_STRONG_AUTH, 7u )
#define EASSURANCEMSGSIGNFAILED                         VLT_ERROR( VLT_STRONG_AUTH, 8u )
#define EEXTERNALAUTHSIGNFAILED                         VLT_ERROR( VLT_STRONG_AUTH, 9u )
#define EREADPUBLICKEYFAILED                            VLT_ERROR( VLT_STRONG_AUTH, 10u )
#define ESTRONGNOTSUPPORTED                             VLT_ERROR( VLT_STRONG_AUTH, 11u )

/*
 * Crypto Service Provider Specific Error Codes
 */
#define ECRYPTOINITNULLPARAM                            VLT_ERROR( VLT_CRYPTO, 0u )
#define ECRYPTOCLSNOTSUPPORTED                          VLT_ERROR( VLT_CRYPTO, 1u )
#define ECRYPTODFNOTSUPPORTED                           VLT_ERROR( VLT_CRYPTO, 2u )
#define ECRYPTOUPDNOTSUPPORTED                          VLT_ERROR( VLT_CRYPTO, 3u )
#define ECRYPTOALGNOTSUP                                VLT_ERROR( VLT_CRYPTO, 4u )
#define ECRYPTODFNULLPARAM                              VLT_ERROR( VLT_CRYPTO, 5u )
#define ECRYPTOUNULLPARAM                               VLT_ERROR( VLT_CRYPTO, 6u )


/*
 * ECDSA Signer Service Provider Error Codes
 */
#define EECDSAINITNULLPARAM                             VLT_ERROR( VLT_ECDSA, 0u )
#define EECDSAINUPNULLPARAM                             VLT_ERROR( VLT_ECDSA, 1u )
#define EECDSAINDFINNULLPARAM                           VLT_ERROR( VLT_ECDSA, 2u )
#define EECDSAOPMODENOTSUPP                             VLT_ERROR( VLT_ECDSA, 3u )
#define EECDSAINVALIDPARAM                              VLT_ERROR( VLT_ECDSA, 4u )
#define EECDSAEXECUTIONERROR                            VLT_ERROR( VLT_ECDSA, 5u )
#define EECDSAINVALIDCOMPILSETTINGS                     VLT_ERROR( VLT_ECDSA, 6u )

 /*
 * ECC Utils Error Codes
 */
#define EECCGENERATIONERROR                             VLT_ERROR( VLT_ECC, 0u )
#define EECCQHOSTNOMEMORY                               VLT_ERROR( VLT_ECC, 1u )
#define EECCDHOSTNOMEMORY                               VLT_ERROR( VLT_ECC, 2u )
#define EECCDOMAINSELERROR                              VLT_ERROR( VLT_ECC, 3u )
#define EECLIBERROR                                     VLT_ERROR( VLT_ECC, 4u )
#define EECCCURVEIDINVLD                                VLT_ERROR( VLT_ECC, 5u )
#define EECCVESHOSTNOMEMORY                             VLT_ERROR( VLT_ECC, 6u )
#define EECCVESINVLDDIGEST                              VLT_ERROR( VLT_ECC, 7u )
 /*
 * ECC Utils Error Codes
 */
#define EECDHECKAGETORDERFAILED                         VLT_ERROR( VLT_ECDH, 0u )
#define EECDHECKAGETCOFACTORFAILED                      VLT_ERROR( VLT_ECDH, 1u )
#define EECDHECKAINVALIDPARAMS                          VLT_ERROR( VLT_ECDH, 2u )
#define EECDHECKAGETPRIVKEYFAILED                       VLT_ERROR( VLT_ECDH, 3u )
#define EECDHECKAMULFAILED                              VLT_ERROR( VLT_ECDH, 4u )
#define EECDHECKAMODFAILED                              VLT_ERROR( VLT_ECDH, 5u )
#define EECDHECKASABNULL                                VLT_ERROR( VLT_ECDH, 6u )
#define EECDHECKASTEPTHREEFAILED                        VLT_ERROR( VLT_ECDH, 7u )
#define EECDHKAECKASTEPTWOFAILED                        VLT_ERROR( VLT_ECDH, 8u )
#define EECDHKAECKANOMEMORY                             VLT_ERROR( VLT_ECDH, 9u )
#define EECDHKAECKASETPFAILED                           VLT_ERROR( VLT_ECDH, 10u)
#define EECDHKDFBADDIGEST                               VLT_ERROR( VLT_ECDH, 11u)
#define EECDHKDFHOST_MEMORY                             VLT_ERROR( VLT_ECDH, 12u)
#define EECDHINVALIDCOMPILSETTINGS                      VLT_ERROR( VLT_ECDH, 13u)

 /*
  * Derive Key Error Codes
  */
#define ERR_DRV_HASH_HOST_MEMORY                        VLT_ERROR( VLT_DERIVE, 0u )
#define ERR_DRV_HASH_PREPEND_NULL                       VLT_ERROR( VLT_DERIVE, 1u )
#define ERR_DRV_HASH_APPEND_NULL                        VLT_ERROR( VLT_DERIVE, 2u )
#define ERR_DRV_X963_SUPPPUB_NULL                       VLT_ERROR( VLT_DERIVE, 3u )
#define ERR_DRV_X963_SUPPPRIV_NULL                      VLT_ERROR( VLT_DERIVE, 4u )
#define ERR_DRV_X963_NONCEU_LENGTH_NOT_NULL             VLT_ERROR( VLT_DERIVE, 5u )
#define ERR_DRV_X963_PARTYU_NULL                        VLT_ERROR( VLT_DERIVE, 6u )
#define ERR_DRV_X963_PARTYV_NULL                        VLT_ERROR( VLT_DERIVE, 7u )
#define ERR_DRV_X963_ALGOID_NULL                        VLT_ERROR( VLT_DERIVE, 8u )
#define ERR_DRV_X963_HOST_MEMORY                        VLT_ERROR( VLT_DERIVE, 9u )
#define ERR_DRV_CONCAT_NIST_SUPPPUB_NULL                VLT_ERROR( VLT_DERIVE, 10u )
#define ERR_DRV_CONCAT_NIST_SUPPPRIV_NULL               VLT_ERROR( VLT_DERIVE, 11u )
#define ERR_DRV_CONCAT_NIST_NONCEU_NULL                 VLT_ERROR( VLT_DERIVE, 12u )
#define ERR_DRV_CONCAT_NIST_PARTYU_NULL                 VLT_ERROR( VLT_DERIVE, 13u )
#define ERR_DRV_CONCAT_NIST_PARTYV_NULL                 VLT_ERROR( VLT_DERIVE, 14u )
#define ERR_DRV_CONCAT_NIST_ALGOID_NULL                 VLT_ERROR( VLT_DERIVE, 15u )
#define ERR_DRV_CONCAT_NIST_HOST_MEMORY                 VLT_ERROR( VLT_DERIVE, 16u )

/*
* Digest service Error Codes
*/
#define EEDIGESTSEQERROR                                VLT_ERROR( VLT_DIGEST, 0u )
#define EEDIGESTOVERFLOW                          		VLT_ERROR( VLT_DIGEST, 1u )
#define EEDIGESTINVALIDPARAM                            VLT_ERROR( VLT_DIGEST, 2u )
#define EEDIGESTEXECUTIONERROR                          VLT_ERROR( VLT_DIGEST, 3u )

/*
* Fast authentication service Error Codes
*/
#define EEFAST_AUTH_SYMMETRIC_KEY_SW                    VLT_ERROR( VLT_FAST_AUTH, 0u )
#define EEFAST_AUTH_SYMMETRIC_KEY_RESPONSE              VLT_ERROR( VLT_FAST_AUTH, 1u )
#define EEFAST_AUTH_PAIRING_ERROR                       VLT_ERROR( VLT_FAST_AUTH, 2u )
#define EEFAST_AUTH_ERROR                               VLT_ERROR( VLT_FAST_AUTH, 3u )
#define EEFAST_AUTH_UNKNOWN_UID                         VLT_ERROR( VLT_FAST_AUTH, 4u ) /* Unknown UID */
#define EEFAST_AUTH_CNT_MAX_REACHED                     VLT_ERROR( VLT_FAST_AUTH, 5u ) /* Max fast authentication counter reached */

#endif /*VAULTIC_ERR_H*/
