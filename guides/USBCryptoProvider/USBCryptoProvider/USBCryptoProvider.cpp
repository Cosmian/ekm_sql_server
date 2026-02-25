/*****************************************************************************
  Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

 Notes: 
    See USBCryptoProvider.h for details. 
    This file implements the interfaces defined in SqlCrypt.h. It also implements
    the DLL entry point.

****************************************************************************/


#include "stdafx.h"

#include <stdio.h> 
#include <wincrypt.h>
#include <crtdbg.h>

#include "util.h"
#include "USBCryptoProvider.h"
#include "SessionManager.h"
#include "KeyManager.h"


// Entry point for the DLL. http://msdn.microsoft.com/en-us/library/ms682583.aspx
// This can be used to initialize and cleanyp any global structures
//
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  fdwReason,
                       LPVOID lpReserved
					 )
{
    // Perform actions based on the reason for calling.
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:

			// Key manager init 
			CKeyManager::Initialize();

			// Session manager init 
			CSessManager::Initialize();

			break;

        case DLL_PROCESS_DETACH:

			// Session manager cleanup 
			CSessManager::Cleanup();


			// Key manager cleanup 
			CKeyManager::Cleanup();
	
			break;
    }

    return TRUE;
}

///////////////////////////////////////////////////////////
//
//	SqlCryptInitializeProvider
//
SqlCpError __cdecl
SqlCryptInitializeProvider ()
{
    // Check OS version if it is earlier than Vista then we cannot initialize since
    // this provider uses CNG which is only available in Vista and beyond.
    //
    OSVERSIONINFO OSVersion;
    ZeroMemory(&OSVersion, sizeof(OSVERSIONINFO));
    OSVersion.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    if (!GetVersionEx(&OSVersion))
    {
        dprintf("Cannot get OS version info. Error: %d", GetLastError());
        return scp_err_Failure;
    }

    if (OSVersion.dwMajorVersion < 6)
    {
        dprintf("Cannot initialize provider on this machine as the minimum OS requirement is Windows Vista");
        return scp_err_NotSupported;
    }

	return CKeyManager::Get()->LoadFromXmlFile();    
}

///////////////////////////////////////////////////////////
//
//	SqlCryptFreeProvider
//
SqlCpError __cdecl
SqlCryptFreeProvider ()
{
	return scp_err_Success;
}


///////////////////////////////////////////////////////////
//
//	SqlCryptGetProviderInfo
//
SqlCpError __cdecl
SqlCryptGetProviderInfo(__OUT SqlCpProviderInfo* pProviderInfo)
{
    if (!pProviderInfo)
        return scp_err_InvalidArgument;

	if (pProviderInfo->name.cb < x_providerInfo.name.cb || pProviderInfo->name.ws == NULL)
	{
		pProviderInfo->name.cb = x_providerInfo.name.cb;
		return scp_err_InsufficientBuffer;
	}

	WCHAR* pwsName = pProviderInfo->name.ws;
	memcpy(pProviderInfo, &x_providerInfo, sizeof(SqlCpProviderInfo));
	pProviderInfo->name.ws = pwsName;
	if (x_providerInfo.name.cb)
	{
		memcpy(pProviderInfo->name.ws, x_providerInfo.name.ws, x_providerInfo.name.cb);
	}
	return scp_err_Success;
}

// Provider Algorithms
//

///////////////////////////////////////////////////////////
//
//	SqlCryptGetNextAlgorithmId
//
SqlCpError  __cdecl
SqlCryptGetNextAlgorithmId (__INOUT SqlCpAlgId* algId)  
{
	if (!algId)
		return scp_err_InvalidArgument;

	int algCount = sizeof(x_AlgInfos)/sizeof(x_AlgInfos[0]);
	int i = 0;
	for (i = 0; i < algCount && *algId >= x_AlgInfos[i]._algInfo.algId; i++)
	{}

	if (i >= algCount)
		return scp_err_NotFound;

	*algId = x_AlgInfos[i]._algInfo.algId;
	return scp_err_Success;
}

///////////////////////////////////////////////////////////
//
//	SqlCryptGetAlgorithmInfo
//
SqlCpError  __cdecl
SqlCryptGetAlgorithmInfo (__IN SqlCpAlgId algId,
                          __OUT SqlCpAlgorithmInfo* pAlgorithmInfo)
   {
	if (!pAlgorithmInfo)
		return scp_err_InvalidArgument;
	
	int algCount = sizeof(x_AlgInfos)/sizeof(x_AlgInfos[0]);
	int i = 0;
	for (i = 0; i < algCount && algId != x_AlgInfos[i]._algInfo.algId; i++)
		{}

	if (i >= algCount)
		return scp_err_NotFound;

    // Check if the buffer provider for AlgTag is big enough
    //
	if (pAlgorithmInfo->algTag.cb < x_AlgInfos[i]._algInfo.algTag.cb ||
		pAlgorithmInfo->algTag.ws == NULL)
	{
		pAlgorithmInfo->algTag.cb = x_AlgInfos[i]._algInfo.algTag.cb;
		return scp_err_InsufficientBuffer;
	}

	WCHAR* wsTag = pAlgorithmInfo->algTag.ws;
	memcpy(pAlgorithmInfo, &(x_AlgInfos[i]), sizeof(*pAlgorithmInfo));
	pAlgorithmInfo->algTag.ws = wsTag;
	if (x_AlgInfos[i]._algInfo.algTag.cb)
	{
		memcpy(pAlgorithmInfo->algTag.ws, x_AlgInfos[i]._algInfo.algTag.ws, x_AlgInfos[i]._algInfo.algTag.cb);
	}
	return scp_err_Success;
   }


///////////////////////////////////////////////////////////
//
//	SqlCryptOpenSession
//
SqlCpError __cdecl 
SqlCryptOpenSession (__IN const SqlCpCredential* pAuth, 
                                __OUT SqlCpSession* pSess)
{
    // Check arguments
    if (!pSess || !pAuth)
        return scp_err_InvalidArgument;

    // Open a session only if the user was authenticated
    //
	SessionId idSess = CSessManager::Get()->OpenSession(pAuth);
	if (idSess != x_SessionIdBad)
	{
		memcpy(pSess, &idSess, sizeof(idSess));
		return scp_err_Success;
	}

    return scp_err_AuthFailure; 
}

///////////////////////////////////////////////////////////
//
//	SqlCryptCloseSession
//
SqlCpError __cdecl 
SqlCryptCloseSession (__IN SqlCpSession* pSess, 
								 __IN BOOLEAN fAbort)
{
    // Check arguments
    if (!pSess )
        return scp_err_InvalidArgument;

	SessionId idSess = x_SessionIdBad;
	memcpy(&idSess, pSess, sizeof(idSess));
	CSessManager::Get()->CloseSession(idSess);
    return scp_err_Success;
}

///////////////////////////////////////////////////////////
//
//	SqlCryptCreateKey
//
SqlCpError __cdecl 
SqlCryptCreateKey (__IN const SqlCpSession* pSess,        
                                           __IN const SqlCpStr* pKeyName,      
                                           __IN SqlCpAlgId algid,
                                           __IN SqlCpKeyFlags keyFlags,
                                           __OUT SqlCpKeyThumbprint* pKeyThumb)
{


	// Check arguments
    if (!pSess || !pKeyThumb || !pKeyThumb->pb || pKeyThumb->cb < x_providerInfo.cbKeyThumbLen)
        return scp_err_InvalidArgument;

	SessionId idSess = x_SessionIdBad;
	memcpy(&idSess, pSess, sizeof(idSess));

	CUser* pUser = NULL;
	if ((pUser = CSessManager::Get()->GetUserFromSessionId(idSess)) == NULL)
	{
        return scp_err_AuthFailure;
	}

    // Create a key for this user
    // 
	SqlCpError err = pUser->CreateKey(pKeyName, algid, keyFlags, pKeyThumb);

	if (err != scp_err_Success)
	{
		return err;
	}

    // Save the new key information to XML file
    //
	return CKeyManager::Get()->SaveToXmlFile();

}

///////////////////////////////////////////////////////////
//
//	SqlCryptDropKey
//
SqlCpError __cdecl 
SqlCryptDropKey (__IN const SqlCpSession* pSess,        
                 __IN const SqlCpKeyThumbprint* pKeyThumb)
{
	// Check arguments
    if (!pSess || !pKeyThumb || !pKeyThumb->pb || pKeyThumb->cb < x_providerInfo.cbKeyThumbLen)
        return scp_err_InvalidArgument;

	SessionId idSess = x_SessionIdBad;
	memcpy(&idSess, pSess, sizeof(idSess));

	CUser* pUser = NULL;
	if ((pUser = CSessManager::Get()->GetUserFromSessionId(idSess)) == NULL)
	{
        return scp_err_AuthFailure;
	}

    // Delete the key for this user
    //
	SqlCpError err = pUser->DeleteKey(pKeyThumb);
	if (err != scp_err_Success)
	{
		return err;
	}

    // Save the user state to XML file 
    //
	return CKeyManager::Get()->SaveToXmlFile();
}

///////////////////////////////////////////////////////////
//
//	SqlCryptGetKeyInfoByName
//
SqlCpError __cdecl 
SqlCryptGetKeyInfoByName (__IN const SqlCpSession* pSess,    
                                   __IN  const SqlCpStr* pKeyName, 
                                   __OUT  SqlCpKeyInfo* pKeyInfo)
{
	// Check arguments
    if (!pSess || !pKeyInfo || !pKeyName)
        return scp_err_InvalidArgument;

	SessionId idSess = x_SessionIdBad;
	memcpy(&idSess, pSess, sizeof(idSess));

	CUser* pUser = NULL;
	if ((pUser = CSessManager::Get()->GetUserFromSessionId(idSess)) == NULL)
	{
        return scp_err_AuthFailure;
	}

	return pUser->GetKeyInfoByName(pKeyName, pKeyInfo);
}

///////////////////////////////////////////////////////////
//
//	SqlCryptGetKeyInfoByThumb
//
SqlCpError __cdecl 
SqlCryptGetKeyInfoByThumb (__IN const SqlCpSession* pSess,    
                                   __IN  const SqlCpKeyThumbprint* pKeyThumb, 
                                   __OUT  SqlCpKeyInfo* pKeyInfo)
{
	// Check arguments
    if (!pSess || !pKeyInfo || !pKeyThumb || !pKeyThumb->pb || 
		pKeyThumb->cb < x_providerInfo.cbKeyThumbLen)
        return scp_err_InvalidArgument;

	SessionId idSess = x_SessionIdBad;
	memcpy(&idSess, pSess, sizeof(idSess));

	CUser* pUser = NULL;
	if ((pUser = CSessManager::Get()->GetUserFromSessionId(idSess)) == NULL)
	{
        return scp_err_AuthFailure;
	}

	return pUser->GetKeyInfoByThumb(pKeyThumb, pKeyInfo);
}

///////////////////////////////////////////////////////////
//
//	SqlCryptGetNextKeyInfo
//
SqlCpError  __cdecl 
SqlCryptGetNextKeyId (__IN const SqlCpSession* pSess,         
                       __INOUT SqlCpKeyId* pKeyId)
{
	// Check arguments
    if (!pSess || !pKeyId)
        return scp_err_InvalidArgument;

	// Get user session
	SessionId idSess = x_SessionIdBad;
	memcpy(&idSess, pSess, sizeof(idSess));

	CUser* pUser = NULL;
	if ((pUser = CSessManager::Get()->GetUserFromSessionId(idSess)) == NULL)
	{
        return scp_err_AuthFailure;
	}

    CAutoRefc<CCryptoKey> a_pKey = pUser->GetNextKey(*pKeyId);
	if (a_pKey)
	{
		*pKeyId = a_pKey->GetKeyId();
		return scp_err_Success;
	}
	return scp_err_NotFound;
}
  

SqlCpError  __cdecl 
SqlCryptGetKeyInfoByKeyId (__IN const SqlCpSession* pSess,    
                           __IN  SqlCpKeyId keyId,  
                           __OUT SqlCpKeyInfo* pKeyInfo)
{
	// Check arguments
    if (!pSess || !pKeyInfo)
        return scp_err_InvalidArgument;

	if (keyId == x_scp_KeyIdBad)
	{
		return scp_err_NotFound;
	}

	// Get user 
	SessionId idSess = x_SessionIdBad;
	memcpy(&idSess, pSess, sizeof(idSess));

	CUser* pUser = NULL;
	if ((pUser = CSessManager::Get()->GetUserFromSessionId(idSess)) == NULL)
	{
        return scp_err_AuthFailure;
	}

    CAutoRefc<CCryptoKey> a_pKey = pUser->GetKeyById(keyId);
	if (!a_pKey)
	{
		return scp_err_NotFound;
	}
	return a_pKey->GetKeyInfo(pKeyInfo);
}


///////////////////////////////////////////////////////////
//
//	SqlCryptExportKey
//
SqlCpError __cdecl 
SqlCryptExportKey(__IN const SqlCpSession* pSess,            
								__IN   const SqlCpKeyThumbprint* pKeyThumb,  
								__IN   const SqlCpKeyThumbprint* keyEncryptorThumb,  
								__IN   SqlCpKeyBlobType blobType,                 
								__OUT  SqlCpKeyBlob* pKeyBlob)
{
	// Check arguments
    if (!pSess || !pKeyThumb || !pKeyThumb->pb || 
		pKeyThumb->cb < x_providerInfo.cbKeyThumbLen ||
		!pKeyBlob)
        return scp_err_InvalidArgument;

	// Public key is the only key which can be requested 
	// for export by SQL server 2008
	_ASSERT(blobType == scp_kb_PublicKeyBlob);

	// Get the session
	SessionId idSess = x_SessionIdBad;
	memcpy(&idSess, pSess, sizeof(idSess));

	CUser* pUser = NULL;
	if ((pUser = CSessManager::Get()->GetUserFromSessionId(idSess)) == NULL)
	{
        return scp_err_AuthFailure;
	}

	// Get the key
	CAutoRefc<CCryptoKey> a_pKey = pUser->GetKeyByThumb(pKeyThumb);
	if (!a_pKey)
	{
        return scp_err_NotFound;
	}

	// Return key material here
    //
    return a_pKey->Export(blobType, pKeyBlob);
}

///////////////////////////////////////////////////////////
//
//	SqlCryptImportKey
//
SqlCpError __cdecl 
SqlCryptImportKey (__IN const SqlCpSession* pSess,        
								__IN  const SqlCpStr* keyName,          
								__IN   const SqlCpKeyThumbprint* keyDecryptorThumb,  
								__IN  SqlCpKeyBlobType blobType,             
								__IN  SqlCpKeyFlags keyFlags,            
								__IN const SqlCpKeyBlob* pKeyBlob)  
{
    // This is currently not supported 
    //
    return scp_err_NotSupported;
}

///////////////////////////////////////////////////////////
//
//	SqlCryptEncrypt
//
SqlCpError __cdecl 
SqlCryptEncrypt( __IN const SqlCpSession* pSess,        
							   __IN const SqlCpKeyThumbprint* pKeyThumb,    
							   __IN   BOOLEAN fFinal,
							   __IN const SqlCpEncryptionParam* pEncryptParams,
							   __IN   ULONG cEncryptParams,
							   __IN const SqlCpData* pPlaintext,
							   __OUT SqlCpData* pCiphertext)
{
    // Check arguments
    if (!pSess || !pKeyThumb || !pKeyThumb->pb || !pKeyThumb->cb || !pPlaintext || 
            !pPlaintext->cb || !pCiphertext || (cEncryptParams && !pEncryptParams))
        return scp_err_InvalidArgument;

	// Get user 
	SessionId idSess = x_SessionIdBad;
	memcpy(&idSess, pSess, sizeof(idSess));

	CUser* pUser = NULL;
	if ((pUser = CSessManager::Get()->GetUserFromSessionId(idSess)) == NULL)
	{
        return scp_err_AuthFailure;
	}

    CAutoRefc<CCryptoKey> a_pKey = pUser->GetKeyByThumb(pKeyThumb);

	if (!a_pKey)
	{
		return scp_err_NotFound;
	}

    return a_pKey->Encrypt(fFinal, pEncryptParams, cEncryptParams, pPlaintext, pCiphertext);
}

///////////////////////////////////////////////////////////
//
//	SqlCryptDecrypt
//
SqlCpError __cdecl 
SqlCryptDecrypt (__IN const SqlCpSession* pSess,    
                           __IN const SqlCpKeyThumbprint* pKeyThumb,  
                           __IN   BOOLEAN fFinal,    
                           __IN const SqlCpEncryptionParam* pEncryptParams,
                           __IN ULONG cEncryptParams,    
                           __IN const SqlCpData* pCiphertext,
                           __OUT SqlCpData* pPlaintext)
{

    if (!pSess || !pKeyThumb || !pKeyThumb->cb || !pPlaintext || !pCiphertext->pb || (cEncryptParams && !pEncryptParams))
        return scp_err_InvalidArgument;

	// Get user 
	SessionId idSess = x_SessionIdBad;
	memcpy(&idSess, pSess, sizeof(idSess));

	CUser* pUser = NULL;
	if ((pUser = CSessManager::Get()->GetUserFromSessionId(idSess)) == NULL)
	{
        return scp_err_AuthFailure;
	}

    CAutoRefc<CCryptoKey> a_pKey = pUser->GetKeyByThumb(pKeyThumb);

	if (!a_pKey)
	{
		return scp_err_NotFound;
	}

    return a_pKey->Decrypt(fFinal, pEncryptParams, cEncryptParams, pCiphertext, pPlaintext); 
}


#ifdef _MANAGED
#pragma managed(pop)
#endif

