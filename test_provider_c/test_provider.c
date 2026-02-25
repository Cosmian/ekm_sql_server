// ==========================================================================
// Minimal EKM Provider for SQL Server — Pure C reference implementation
//
// This is a stripped-down EKM provider DLL that implements only the bare
// minimum required by the SQL Crypto API v1 (sqlcrypt.h), as documented
// in the "SQL Server 2008 EKM Development Guide".
//
// All 17 SqlCrypt* entry points are exported with __cdecl calling
// convention.  The provider reports:
//
//   - scpVersion  = {1, 1, 0, 0}   (SQL Crypto API v1.1)
//   - version     = {1, 0, 0, 0}   (provider DLL version)
//   - authType    = scp_auth_Basic
//   - symmKeySupport  = scp_kf_Supported
//   - asymmKeySupport = scp_kf_Supported
//   - cbKeyThumbLen   = sizeof(GUID) = 16
//   - fAcceptsKeyName = TRUE
//
// Every function returns scp_err_Success except:
//   - SqlCryptGetNextAlgorithmId → scp_err_NotFound  (empty algorithm list)
//   - SqlCryptGetNextKeyId       → scp_err_NotFound  (empty key list)
//   - all other unimplemented ops → scp_err_NotSupported
//
// PURPOSE: Demonstrate that CREATE CRYPTOGRAPHIC PROVIDER fails with
//          Msg 33029 / error code 0 ("Success") on SQL Server 2025
//          (17.0.1050.2, Enterprise Developer Edition, 64-bit) even
//          when the DLL is correctly structured and Authenticode-signed
//          with a certificate whose root is in Trusted Root CA.
// ==========================================================================

#include <windows.h>

// ---------------------------------------------------------------------------
// Types from sqlcrypt.h  (SQL Crypto API v1, x_scp_SqlCpVerMajor=1,
//                         x_scp_SqlCpVerMinor=1)
// ---------------------------------------------------------------------------

typedef unsigned long ULONG;

typedef enum
{
    scp_err_Success = 0,
    scp_err_Failure = 1,
    scp_err_InsufficientBuffer = 2,
    scp_err_NotSupported = 3,
    scp_err_NotFound = 4,
    scp_err_AuthFailure = 5,
    scp_err_InvalidArgument = 6,
    scp_err_ProviderError = 7,
    scp_err_MaxReserved = 2048,
} SqlCpError;

typedef enum
{
    scp_auth_Other = 0,
    scp_auth_Basic = 1,
    scp_auth_Last,
} SqlCpAuthType;

typedef enum
{
    scp_kf_Supported = 0x01,
    scp_kf_Volatile = 0x02,
    scp_kf_Exportable = 0x04,
    scp_kf_Importable = 0x08,
} SqlCpKeyFlagsBm;

typedef struct _SqlCpData
{
    ULONG cb;
    BYTE *pb;
} SqlCpData;

typedef struct _SqlCpStr
{
    ULONG cb;
    WCHAR *ws;
} SqlCpStr;

typedef GUID SqlCpGuid;

typedef struct _SqlCpVersion
{
    BYTE major;
    BYTE minor;
    USHORT build;
    BYTE revision;
} SqlCpVersion;

typedef ULONG SqlCpAlgId;
typedef ULONG SqlCpKeyFlags;
typedef ULONG SqlCpKeyId;
typedef void *SqlCpSession;

typedef struct _SqlCpCredential
{
    SqlCpStr name;
    SqlCpStr password;
} SqlCpCredential;

typedef SqlCpData SqlCpKeyThumbprint;

typedef struct _SqlCpKeyInfo
{
    SqlCpStr name;
    SqlCpKeyThumbprint thumb;
    SqlCpAlgId algId;
    SqlCpKeyFlags flags;
} SqlCpKeyInfo;

typedef struct _SqlCpProviderInfo
{
    SqlCpStr name;
    SqlCpGuid guid;
    SqlCpVersion version;
    SqlCpVersion scpVersion;
    SqlCpAuthType authType;
    SqlCpKeyFlags symmKeySupport;
    SqlCpKeyFlags asymmKeySupport;
    ULONG cbKeyThumbLen;
    BOOLEAN fAcceptsKeyName;
} SqlCpProviderInfo;

typedef struct _SqlCpAlgorithmInfo
{
    SqlCpAlgId algId;
    SqlCpStr algTag;
    int type;
    ULONG bitLen;
    ULONG ivLen;
} SqlCpAlgorithmInfo;

typedef SqlCpData SqlCpKeyBlob;

typedef enum
{
    scp_ep_IV = 0
} SqlCpEncParamType;

typedef struct _SqlCpEncryptionParam
{
    SqlCpEncParamType type;
    ULONG cb;
    BYTE *pb;
} SqlCpEncryptionParam;

typedef enum
{
    scp_kb_SimpleBlob = 0,
    scp_kb_PublicKeyBlob = 1,
} SqlCpKeyBlobType;

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

static WCHAR *wsProviderName = L"Test C EKM Provider";

// -- Provider lifecycle ----------------------------------------------------

__declspec(dllexport) SqlCpError __cdecl
SqlCryptInitializeProvider(void)
{
    return scp_err_Success;
}

__declspec(dllexport) SqlCpError __cdecl
SqlCryptFreeProvider(void)
{
    return scp_err_Success;
}

// -- Session management ----------------------------------------------------

__declspec(dllexport) SqlCpError __cdecl
SqlCryptOpenSession(const SqlCpCredential *pAuth, SqlCpSession *pSess)
{
    (void)pAuth;
    if (!pSess)
        return scp_err_InvalidArgument;
    *pSess = (SqlCpSession)1; // sentinel
    return scp_err_Success;
}

__declspec(dllexport) SqlCpError __cdecl
SqlCryptCloseSession(SqlCpSession *pSess, BOOLEAN fAbort)
{
    (void)pSess;
    (void)fAbort;
    return scp_err_Success;
}

// -- Provider info ---------------------------------------------------------

// Global const provider info, following the Microsoft USBCryptoProvider pattern
static const SqlCpProviderInfo x_providerInfo = {
    {(ULONG)(19 * sizeof(WCHAR)), NULL},                                            // name: cb=38, ws set at runtime
    {0xC05A1A00, 0x1001, 0x4001, {0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}}, // guid
    {1, 0, 0, 0},                                                                   // version
    {1, 1, 0, 0},                                                                   // scpVersion
    scp_auth_Basic,                                                                 // authType
    (SqlCpKeyFlags)(scp_kf_Supported),                                              // symmKeySupport
    (SqlCpKeyFlags)(scp_kf_Supported),                                              // asymmKeySupport
    sizeof(GUID),                                                                   // cbKeyThumbLen = 16
    TRUE                                                                            // fAcceptsKeyName
};

__declspec(dllexport) SqlCpError __cdecl
SqlCryptGetProviderInfo(SqlCpProviderInfo *pProviderInfo)
{
    ULONG cbNameRequired;
    WCHAR *pwsCallerBuf;

    if (!pProviderInfo)
        return scp_err_InvalidArgument;

    // The name byte-count for "Test C EKM Provider" (19 chars, no null)
    cbNameRequired = (ULONG)(wcslen(wsProviderName) * sizeof(WCHAR));

    // Two-call buffer-negotiation protocol (matches Microsoft USBCryptoProvider):
    //   Call 1: SQL Server passes name.ws = NULL / name.cb = 0.
    //           Provider sets name.cb = required size and returns InsufficientBuffer.
    //   Call 2: SQL Server passes name.ws = allocated buffer, name.cb = buffer size.
    //           Provider copies data into the caller's buffer.
    if (pProviderInfo->name.cb < cbNameRequired || pProviderInfo->name.ws == NULL)
    {
        pProviderInfo->name.cb = cbNameRequired;
        return scp_err_InsufficientBuffer;
    }

    // Save the caller's name buffer pointer before overwriting the struct
    pwsCallerBuf = pProviderInfo->name.ws;

    // Copy the entire struct (overwrites name.ws with x_providerInfo's value)
    memcpy(pProviderInfo, &x_providerInfo, sizeof(SqlCpProviderInfo));

    // Restore the caller's buffer pointer and copy the name string into it
    pProviderInfo->name.ws = pwsCallerBuf;
    pProviderInfo->name.cb = cbNameRequired;
    if (cbNameRequired)
    {
        memcpy(pProviderInfo->name.ws, wsProviderName, cbNameRequired);
    }

    return scp_err_Success;
}

// -- Algorithm enumeration -------------------------------------------------

__declspec(dllexport) SqlCpError __cdecl
SqlCryptGetNextAlgorithmId(SqlCpAlgId *pAlgId)
{
    (void)pAlgId;
    return scp_err_NotFound; // no built-in algorithms
}

__declspec(dllexport) SqlCpError __cdecl
SqlCryptGetAlgorithmInfo(SqlCpAlgId algId, SqlCpAlgorithmInfo *pAlgorithmInfo)
{
    (void)algId;
    (void)pAlgorithmInfo;
    return scp_err_NotSupported;
}

// -- Key management --------------------------------------------------------

__declspec(dllexport) SqlCpError __cdecl
SqlCryptCreateKey(const SqlCpSession *pSess, const SqlCpStr *pKeyName,
                  SqlCpAlgId algid, SqlCpKeyFlags keyFlags,
                  SqlCpKeyThumbprint *pKeyThumb)
{
    (void)pSess;
    (void)pKeyName;
    (void)algid;
    (void)keyFlags;
    (void)pKeyThumb;
    return scp_err_NotSupported;
}

__declspec(dllexport) SqlCpError __cdecl
SqlCryptDropKey(const SqlCpSession *pSess, const SqlCpKeyThumbprint *pKeyThumb)
{
    (void)pSess;
    (void)pKeyThumb;
    return scp_err_NotSupported;
}

__declspec(dllexport) SqlCpError __cdecl
SqlCryptGetNextKeyId(const SqlCpSession *pSess, SqlCpKeyId *pKeyId)
{
    (void)pSess;
    (void)pKeyId;
    return scp_err_NotFound; // no keys
}

__declspec(dllexport) SqlCpError __cdecl
SqlCryptGetKeyInfoByKeyId(const SqlCpSession *pSess, SqlCpKeyId keyId,
                          SqlCpKeyInfo *pKeyInfo)
{
    (void)pSess;
    (void)keyId;
    (void)pKeyInfo;
    return scp_err_NotSupported;
}

__declspec(dllexport) SqlCpError __cdecl
SqlCryptGetKeyInfoByThumb(const SqlCpSession *pSess,
                          const SqlCpKeyThumbprint *pKeyThumb,
                          SqlCpKeyInfo *pKeyInfo)
{
    (void)pSess;
    (void)pKeyThumb;
    (void)pKeyInfo;
    return scp_err_NotSupported;
}

__declspec(dllexport) SqlCpError __cdecl
SqlCryptGetKeyInfoByName(const SqlCpSession *pSess, const SqlCpStr *pKeyName,
                         SqlCpKeyInfo *pKeyInfo)
{
    (void)pSess;
    (void)pKeyName;
    (void)pKeyInfo;
    return scp_err_NotSupported;
}

__declspec(dllexport) SqlCpError __cdecl
SqlCryptExportKey(const SqlCpSession *pSess,
                  const SqlCpKeyThumbprint *pKeyThumb,
                  const SqlCpKeyThumbprint *keyEncryptorThumb,
                  SqlCpKeyBlobType blobType, SqlCpKeyBlob *pKeyBlob)
{
    (void)pSess;
    (void)pKeyThumb;
    (void)keyEncryptorThumb;
    (void)blobType;
    (void)pKeyBlob;
    return scp_err_NotSupported;
}

__declspec(dllexport) SqlCpError __cdecl
SqlCryptImportKey(const SqlCpSession *pSess, const SqlCpStr *pKeyName,
                  const SqlCpKeyThumbprint *keyDecryptorThumb,
                  SqlCpKeyBlobType blobType, SqlCpKeyFlags keyFlags,
                  const SqlCpKeyBlob *pKeyBlob)
{
    (void)pSess;
    (void)pKeyName;
    (void)keyDecryptorThumb;
    (void)blobType;
    (void)keyFlags;
    (void)pKeyBlob;
    return scp_err_NotSupported;
}

// -- Encrypt / Decrypt -----------------------------------------------------

__declspec(dllexport) SqlCpError __cdecl
SqlCryptEncrypt(const SqlCpSession *pSess,
                const SqlCpKeyThumbprint *pKeyThumb,
                BOOLEAN fFinal,
                const SqlCpEncryptionParam *pEncryptParams,
                ULONG cEncryptParams,
                const SqlCpData *pDataPlainText,
                SqlCpData *pDataCiphertext)
{
    (void)pSess;
    (void)pKeyThumb;
    (void)fFinal;
    (void)pEncryptParams;
    (void)cEncryptParams;
    (void)pDataPlainText;
    (void)pDataCiphertext;
    return scp_err_NotSupported;
}

__declspec(dllexport) SqlCpError __cdecl
SqlCryptDecrypt(const SqlCpSession *pSess,
                const SqlCpKeyThumbprint *pKeyThumb,
                BOOLEAN fFinal,
                const SqlCpEncryptionParam *pEncryptParams,
                ULONG cEncryptParams,
                const SqlCpData *pDataCiphertext,
                SqlCpData *pDataPlainText)
{
    (void)pSess;
    (void)pKeyThumb;
    (void)fFinal;
    (void)pEncryptParams;
    (void)cEncryptParams;
    (void)pDataCiphertext;
    (void)pDataPlainText;
    return scp_err_NotSupported;
}

// -- DllMain ---------------------------------------------------------------

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved)
{
    (void)hModule;
    (void)ul_reason_for_call;
    (void)lpReserved;
    return TRUE;
}
