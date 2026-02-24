//****************************************************************************//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  Microsoft Corporation - Confidential & Proprietary
//
//  Use of this file is restricted to internal testing by recipients authorized
//	by Microsoft Corporation.
//
//  This file is provided without warranty, express or implied, of any kind.
//
//  @File: sqlcrypt.h
//  @Owner: ruslano
//  @Test: stevengo
//
//  Purpose:
//
//      SQL Server Cryptographic Interface v1
//
//
// @EndHeader@
//****************************************************************************//

// Version of this SQL Crypto header
//
#define x_scp_SqlCpVerMajor 1
#define x_scp_SqlCpVerMinor 1

#define __IN
#define __OUT
#define __INOUT

// Maximum length of provider friendly name in bytes
//
#define x_cbFriendlyNameMaxLen 2048

// Maximum length of provider key name
//
#define x_cbKeyNameMaxLen 512

// Maximum length of provider algorithm
//
#define x_cbAlgorithmTagMaxLen 120

// Maximum length of provider IV Length
//
#define x_cbAlgorithmIVMaxLength 512

// Maximum length of provider Bit Length
//
#define x_cbAlgorithmBitLenMaxLength 4096

// Maximum length of key thumbprint
//
#define x_cbKeyThumbprintMaxLen 32

// Invalid AlgId
//
#define x_scp_AlgIdBad 0

// Maximum length of key blob
//
#define x_cbKeyBlobMaxLen 2048

// Maximum length of key blob
//
#define x_cbKeyBlobMaxLen 2048

// Invalid KeyId
//
#define x_scp_KeyIdBad 0

// Error
typedef enum
{
    scp_err_Success = 0,
    scp_err_Failure = 1,
    scp_err_InsufficientBuffer = 2,
    scp_err_NotSupported = 3,
    scp_err_NotFound = 4,
    scp_err_AuthFailure = 5,
    scp_err_InvalidArgument = 6,
    scp_err_ProviderError = 7, // Error in provider caught by SQL (Call Traits)

    // ISV specific error codes must be larger that this number
    //
    scp_err_MaxReserved = 2048,
} SqlCpError;

// Authentication type
typedef enum
{
    // Provider specific that doesn't require support in SQL
    //
    scp_auth_Other = 0,

    // Basic (username/password) authentication
    //
    scp_auth_Basic = 1,

    // Add new entries above this, as this is used internally to keep track
    // of all supported authentication types
    //
    scp_auth_Last,
} SqlCpAuthType;

// Key type
typedef enum
{
    scp_kt_Symmetric = 0,
    scp_kt_Asymmetric = 1,
} SqlCpKeyType;

// Key blob type
typedef enum
{
    scp_kb_SimpleBlob = 0,
    scp_kb_PublicKeyBlob = 1,
} SqlCpKeyBlobType;

// Key flag bitmask
typedef enum
{
    scp_kf_Supported = 0x01,
    scp_kf_Volatile = 0x02, // key is not persisted
    scp_kf_Exportable = 0x04,
    scp_kf_Importable = 0x08,
} SqlCpKeyFlagsBm;

// Encryption flags
typedef enum
{
    scp_ep_IV = 0,
} SqlCpEncParamType;

// Common types
typedef struct _SqlCpData
{
    ULONG cb; // Length of data bytes
    BYTE *pb; // Data bytes
} SqlCpData;

typedef struct _SqlCpStr
{
    ULONG cb;  // Count in bytes
    WCHAR *ws; // Pointer to Unicode string
} SqlCpStr;

// Guid
typedef GUID SqlCpGuid;

// Version
typedef struct _SqlCpVersion
{
    BYTE major;
    BYTE minor;
    USHORT build;
    BYTE revision;
} SqlCpVersion;

// Algorithm identifier
typedef ULONG SqlCpAlgId;

// Key options
typedef ULONG SqlCpKeyFlags;

// Key identifier
typedef ULONG SqlCpKeyId;

// EKM session object
typedef void *SqlCpSession;

// Credentials to authenticate with EKM provider using Basic Auth
typedef struct _SqlCpCredential
{
    SqlCpStr name;     // Username
    SqlCpStr password; // Password
} SqlCpCredential;

// Key thumbprint
typedef SqlCpData SqlCpKeyThumbprint;

// Key info
typedef struct _SqlCpKeyInfo
{
    SqlCpStr name;            // Friendly key name
    SqlCpKeyThumbprint thumb; // Unique key thumbprint
    SqlCpAlgId algId;         // Algorithm id
    SqlCpKeyFlags flags;      // Flags
} SqlCpKeyInfo;

// Provider info
typedef struct _SqlCpProviderInfo
{
    SqlCpStr name;                 // Provider friendly name
    SqlCpGuid guid;                // Unique provider guid
    SqlCpVersion version;          // Provider DLL version
    SqlCpVersion scpVersion;       // SQL Crypto API version
    SqlCpAuthType authType;        // Supported authentication
    SqlCpKeyFlags symmKeySupport;  // Symmetric key support bitmask
    SqlCpKeyFlags asymmKeySupport; // Asymmetric key support bitmask
    ULONG cbKeyThumbLen;           // Max length of a key thumbprint in bytes
    BOOLEAN fAcceptsKeyName;       // if accepts external key name in CreateKey
} SqlCpProviderInfo;

// Algorithm info
typedef struct _SqlCpAlgorithmInfo
{
    SqlCpAlgId algId;  // Algorithm id
    SqlCpStr algTag;   // Algorithm tag, i.e. "RSA_1024"
    SqlCpKeyType type; // Key type, i.e. symmetric, asymmetric
    ULONG bitLen;      // Key bitlength in bits
    ULONG ivLen;       // IV bitlength in bits
} SqlCpAlgorithmInfo;

// Key blob to export/import keys
typedef SqlCpData SqlCpKeyBlob;

typedef struct _SqlCpEncryptionParam
{
    SqlCpEncParamType type; // Param type
    ULONG cb;               // Length of data bytes
    BYTE *pb;               // Data bytes
} SqlCpEncryptionParam;

//
// SQL Crypto interface
//
// Provider initialization
//
extern "C"
{
    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptInitializeProvider();

    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptFreeProvider();

    // Session
    //
    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptOpenSession(__IN const SqlCpCredential *pAuth,
                        __OUT SqlCpSession *pSess);

    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptCloseSession(__IN SqlCpSession *pSess,
                         __IN BOOLEAN fAbort);

    // Provider Info
    //
    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptGetProviderInfo(__OUT SqlCpProviderInfo *pProviderInfo);

    // Provider Algorithms
    //
    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptGetNextAlgorithmId(__INOUT SqlCpAlgId *pAlgId);

    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptGetAlgorithmInfo(__IN SqlCpAlgId algId,
                             __OUT SqlCpAlgorithmInfo *pAlgorithmInfo);

    // Key management
    //
    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptCreateKey(__IN const SqlCpSession *pSess,
                      __IN const SqlCpStr *pKeyName,
                      __IN SqlCpAlgId algid,
                      __IN SqlCpKeyFlags keyFlags,
                      __OUT SqlCpKeyThumbprint *pKeyThumb);

    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptDropKey(__IN const SqlCpSession *pSess,
                    __IN const SqlCpKeyThumbprint *pKeyThumb);

    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptGetNextKeyId(__IN const SqlCpSession *pSess,
                         __INOUT SqlCpKeyId *pKeyId);

    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptGetKeyInfoByKeyId(__IN const SqlCpSession *pSess,
                              __IN SqlCpKeyId keyId,
                              __OUT SqlCpKeyInfo *pKeyInfo);

    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptGetKeyInfoByThumb(__IN const SqlCpSession *pSess,
                              __IN const SqlCpKeyThumbprint *pKeyThumb,
                              __OUT SqlCpKeyInfo *pKeyInfo);

    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptGetKeyInfoByName(__IN const SqlCpSession *pSess,
                             __IN const SqlCpStr *pKeyName,
                             __OUT SqlCpKeyInfo *pKeyInfo);

    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptExportKey(__IN const SqlCpSession *pSess,
                      __IN const SqlCpKeyThumbprint *pKeyThumb,
                      __IN const SqlCpKeyThumbprint *keyEncryptorThumb,
                      __IN SqlCpKeyBlobType blobType,
                      __OUT SqlCpKeyBlob *pKeyBlob);

    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptImportKey(__IN const SqlCpSession *pSess,
                      __IN const SqlCpStr *pKeyName,
                      __IN const SqlCpKeyThumbprint *keyDecryptorThumb,
                      __IN SqlCpKeyBlobType blobType,
                      __IN SqlCpKeyFlags keyFlags,
                      __IN const SqlCpKeyBlob *pKeyBlob);

    // Encryption/Decyption
    //
    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptEncrypt(__IN const SqlCpSession *pSess,
                    __IN const SqlCpKeyThumbprint *pKeyThumb,
                    __IN BOOLEAN fFinal,
                    __IN const SqlCpEncryptionParam *pEncryptParams,
                    __IN ULONG cEncryptParams,
                    __IN const SqlCpData *pDataPlainText,
                    __OUT SqlCpData *pDataCiphertext);

    __declspec(dllexport) SqlCpError __cdecl
    SqlCryptDecrypt(__IN const SqlCpSession *pSess,
                    __IN const SqlCpKeyThumbprint *pKeyThumb,
                    __IN BOOLEAN fFinal,
                    __IN const SqlCpEncryptionParam *pEncryptParams,
                    __IN ULONG cEncryptParams,
                    __IN const SqlCpData *pDataCiphertext,
                    __OUT SqlCpData *pDataPlainText);
}
