/**
* @file	   vaultic_file_system.h
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
* @defgroup FileSystem  File System service 
* @brief   Interface functions to VaultIC File System Service.
* @details The file system service is intended to provide a straightforward means of accessing the file system of the VaultIC Security Module.\n
 *          \note The Base API methods can be used as an alternative, but this is not recommended.
 *   \see filesystem_ll 
 */

#ifndef VAULTIC_FILE_SYSTEM_H
#define VAULTIC_FILE_SYSTEM_H

 /** @{ */

/**
 * \brief Used to open a file ready for reading or writing
 *
 * This method is used to 'open' a file to allow it to be read from or wriiten
 * to.  If operations on the file are to be carried out within a transaction,
 * the \a bTransactionMode parameter should be set to #TRUE.
 *
 * \param[in] u16FileNameLength     The length of the file name.
 * \param[in] pu8FileName           The file name to open, optionally including any
*                                   modifications to the path
 * \param[in] bTransactionMode     Specifies whether further operations should be
 *                                  carried out within a transaction to protect
 *                                  against power loss.  \n
 *                                  Possible values are :
 *                                  - #FALSE: Do not operate within a transaction
 *                                  - #TRUE: Operate within a transaction
 * \param[out] pFsFileParams        The File Entry parameters for the file opened
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the Vault IC.
 *
 */
VLT_STS VltFsOpenFile( VLT_U16 u16FileNameLength,
    const VLT_U8 *pu8FileName, 
    VLT_BOOL bTransactionMode,
    VLT_FS_ENTRY_PARAMS *pFsFileParams );

/**
 *
 * \brief Used to close a file once it has been operated on.  
 *
 * This method must be called if VltFsOpenFile() was called with the \a bTransactionMode argument
 * set as #TRUE to ensure that the transaction is ended and
 * that the updates to the file are commited to the file system.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the Vault IC.
 *
 */
VLT_STS VltFsCloseFile( void );

/**
 * \brief Used to create files or folders within the file system
 *
 * \param[in]   u16EntryNameLen     The length of the file/folder path being passed in
 * \param[in]   pu8EntryName        The full name of the file/folder to be created
 * \param[in]   pFsEntryParams      The parameters needed to create the file/folder
 * \param[in]   enUserId            The user id of the owner of the file system entry
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the Vault IC.
 *
 */
VLT_STS VltFsCreate( VLT_U16 u16EntryNameLen,
    const VLT_U8 *pu8EntryName,
    const VLT_FS_ENTRY_PARAMS *pFsEntryParams,
    VLT_USER_ID enUserId );

/**
 *
 * \brief Used to delete files or folders within the file system
 *
 * \param u16EntryNameLen       The length of the file/folder path being passed in
 * \param pu8EntryName          The full name of the file/folder to be deleted
 * \param bRecursion            If the entry to be deleted is a folder, specifies
 *                              whether a recursive delete of files and folders
 *                              should take place. Possibles values are:
*                               - #FALSE Delete the folder non recursively 
*                               - #TRUE  Delete the folder and any contained files and folders 
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the Vault IC.
 *
 */
VLT_STS VltFsDelete( VLT_U16 u16EntryNameLen,
    const VLT_U8 *pu8EntryName,
    VLT_BOOL bRecursion);

/**
 * \brief Used to read data from an opened file
 *
 * \note This method is used to read data from a file previously opened with
 * VltFsOpenFile()
 *
 * \note If the requested length goes beyond the End of File, only the available data
 * are returned and a specific status (#VLT_EOF) is returned.
 *
 * \param[in]   u32Offset           The position from 0 within in the file to start 
 *                                  reading from. Don't use #VLT_SEEK_TO_END, an 
 *                                  error #EFSRDSEEKFAILED will be returned.
 * \param[out]  pu8DataOut          The buffer to place the data read from the VaultIC
 *
 * \param[in]   pu32DataLength     The length of the data to be read.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the Vault IC.
 *
 */
VLT_STS VltFsReadFile( VLT_U32 u32Offset, 
    VLT_U8 *pu8DataOut, 
    VLT_U32 *pu32DataLength );

/**
 *
 * \brief Used to write data to an opened file
 *
 * \note This method is used to write data from a file previously opened with
 * VltFsOpenFile()
 *
 * \param[in]   u32Offset      The position from 0 within in the file to start 
 *                             writing from.  Use constants #VLT_SEEK_FROM_START,
 *                             #VLT_SEEK_TO_END, or any value less than or equal
 *                             to the open file size.
 * \param[in]   pu8DataIn      The buffer contaning the data to be written 
 *                             to the Vault IC
 * \param[in]   u32DataLength  The length of the data to be written.
 * \param[in]   bReclaimSpace  Specifies whether any existing data proceeding the written data should be deleted or not.
 *                              - #FALSE : data after the new end of file should not be reclaimed
 *                              - #TRUE  : data after the new end of file should be reclaimed
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the Vault IC.
 *
 */
VLT_STS VltFsWriteFile(VLT_U32 u32Offset,
    const VLT_U8 *pu8DataIn, 
    VLT_U32 u32DataLength,
    VLT_BOOL bReclaimSpace );


/**
 * \brief Used to list the files and folders within the specified folder
 *
 * Returns a multi-string containing the names of files and directories located
 * in the currently selected directory.
 *
 * Files or directories with the hidden attribute are skipped out the listing.
 *
 * \note A multi-string is a sequence of NULL-terminated strings. The sequence is
 * terminated by a NULL byte, therefore the multi-string ends up by two
 * consecutive bytes.
 *
 * \note The order in which files are reported may be different before and after
 * a secure transaction performed on the selected directory.
 *
 * \note The logged-in operator must have the List privilege on the selected
 * directory.
 *
 * \note A single NULL byte is returned if the current directory does not contain any
 * files or sub-directories.
 *
 * \note An error code is returned if the buffer passed in is not large enough to 
 * accomodate all of the data returned by the Vault IC.  The \a pu16ListRespLength
 * parameter is updated to the size of the buffer required to return the full 
 * directory listing.  A partial directory listing will be contained within the
 * buffer, but this should be ignored.  A buffer of the size reported  back by 
 * the updated \a pu16ListRespLength should be constructed and passed as the input
 * parameters to #VltFsListFiles.
 *
 * \param[in]   u16FolderNameLength     The length of the folder name
 * \param[in]   pu8FolderName           The folder name to perform the listing on
 * \param[out]  pu16ListRespLength      Size of the file list response
 * \param[in]   u16ListRespCapacity     Size of allocated buffer to receive the file list
 * \param[out]  pu8RespData             Buffer to receive the file list
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the Vault IC.
 *
 */
VLT_STS VltFsListFiles(VLT_U16 u16FolderNameLength,
    const VLT_U8 *pu8FolderName,
    VLT_U16 *pu16ListRespLength,
    VLT_U16 u16ListRespCapacity,
    VLT_U8 *pu8RespData );

/**
 * \brief Used to change the privileges on a file system entry
 *
 * \param[in]   u16EntryNameLength  The length of the file/folder path being passed in
 * \param[in]   pu8EntryName        The full name of the file/folder to be deleted
 * \param[in]   pFsEntryPrivileges  The new access privileges to set on the file
 *                                  system entry.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the Vault IC.
 *
 */
VLT_STS VltFsSetPrivileges( VLT_U16 u16EntryNameLength,
    const VLT_U8 *pu8EntryName, 
    const VLT_FS_ENTRY_PRIVILEGES* pFsEntryPrivileges );

/**
 * \brief Used to change the attributes on a file system entry
 *
 * This method is used to change the attributes on a file or folder
 *
 * \param[in]   u16EntryNameLength  The length of the file/folder path being passed in
 * \param[in]   pu8EntryName        The full name of the file/folder to be deleted
 * \param[in]   pFsEntryAttributes  The updated attributes to set on the file system entry.
 *
 * \return Upon successful completion a #VLT_OK status will be returned otherwise
 * the appropriate error code will be returned.\n Please note, status values 
 * larger than #VLT_OK are errors that have originated in the API library while 
 * status values smaller than #VLT_OK are the APDU status words that are returned 
 * by the Vault IC.
 *
 */
VLT_STS VltFsSetAttributes( VLT_U16 u16EntryNameLength,
    const VLT_U8 *pu8EntryName, 
    const VLT_FS_ENTRY_ATTRIBS* pFsEntryAttributes );

#endif /*VAULTIC_FILE_SYSTEM_H*/
/**@}*/

