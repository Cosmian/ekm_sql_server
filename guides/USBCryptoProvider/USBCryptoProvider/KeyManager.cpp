/*****************************************************************************
  Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

Notes:
    See the header file KeyManager.h for more details about this file.

****************************************************************************/

#include "stdafx.h"
#include <crtdbg.h>
#include "Util.h"
#include "XmlLite.h"
#include "Rpc.h"
#include <fstream>
#include "KeyManager.h"
#include <winreg.h>


using namespace std;

CKeyManager* CKeyManager::m_pKeyManager = NULL;

// Initialize users and add them to user store and Initialize keys and add them to 
// user's key store. This method provides high level parsing functionality.
// Note that the access to XML file is serialized and the CS is held for the lifetime
// of this method which is not very performance efficient. This sample just highlights 
// some important synchronization points which should be kept in mind while implementing 
// a provider.
//
SqlCpError CKeyManager::LoadFromXmlFile()
{
	_ASSERT(m_awsFile);
	if (m_fLoadedFromXml)
	{
		return scp_err_Success;
	}

	// Synchronize with other threads, which do Load/Save Xml
    // As noted above, in an actual provider this could be much more efficient. In this sample it is just used to highlight
    // that access to persisted user/key information should be serialized as their could be multiple sessions active simultaneously
    // and there could be multiple sessions by the same user as well.
    //
	CAutoCriticalSection acs(&m_csXmlLoadSave);
	acs.Enter();

	if (m_fLoadedFromXml)
	{
		return scp_err_Success;
	}

    // If Filepath has not been loaded from registry then load it
    //
    if (!m_awsFile)
    {
        LoadFilePathFromRegistry();
    }
    
    // XMLLite Auto Pointers
    //
    CComPtr<IStream> pFileStream;
    CComPtr<IXmlReader> pReader;
    XmlNodeType nodeType;
    const WCHAR * pwszLocalName;
    const WCHAR * pwszValue;
    HRESULT hr = S_OK;

    //Load XML File using XML Lite
    //
    HRCALL(SHCreateStreamOnFile(m_awsFile, STGM_READ, &pFileStream), scp_err_CantLoadXml);

    // Create Reader from the input file stream
    HRCALL(CreateXmlReader(__uuidof(IXmlReader), (void**) &pReader, NULL), scp_err_CantLoadXml);
    HRCALL(pReader->SetProperty(XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit), scp_err_CantLoadXml);
    HRCALL(pReader->SetInput(pFileStream), scp_err_CantLoadXml);

    // Auto pointer for user
    //
	CAutoP<CUser> a_pUser = NULL;
	CUser * pUserCopy = NULL;

    // Read each node one-by-one
    //
    while (S_OK == (hr = pReader->Read(&nodeType)))
    {

        // Auto Pointers for key
        //        
        CAutoRefc<CCryptoKey> a_pKey;
    
        switch (nodeType)
        {
            // We are only interested in elements and end elements
            case XmlNodeType_Element:
                //Get the Name of the element
                HRCALL(pReader->GetLocalName(&pwszLocalName, NULL), scp_err_KeyContainerParseError);

                // If it is a user Tag then create a pUser object based on it
                //                
                if (FEqStringIgnoreCase(pwszLocalName, wcslen(pwszLocalName), TAG_USER, CE_TAG_USER))
                {

                    // Get username and password from attributes
                    //
                    CAutoP<WCHAR> a_pUserName = NULL;
                    CAutoP<WCHAR> a_pUserPwd  = NULL;
					pUserCopy = NULL;

                    // Read all attributes from this node
                    //
                    while (TRUE)
                    {
                        if (!pReader->IsDefault())
                        {
                            const WCHAR * pwszAttrib;
                            const WCHAR * pwszValue;

                            // Fetch attribute name and value     
                            HRCALL(pReader->GetLocalName(&pwszAttrib, NULL), scp_err_KeyContainerParseError);
                            HRCALL(pReader->GetValue(&pwszValue, NULL), scp_err_KeyContainerParseError);

                            // Populate User Name
                            if (FEqStringIgnoreCase(pwszAttrib, wcslen(pwszAttrib), ATTRIB_USER_NAME, CE_ATTRIB_USER_NAME))
                            {
                                DWORD strLength = wcslen(pwszValue);
                                a_pUserName = new WCHAR[strLength+1];
                                memcpy(a_pUserName, pwszValue, (strLength+1)*sizeof(WCHAR));
                            }
                            // Populate user password
                            else if (FEqStringIgnoreCase(pwszAttrib, wcslen(pwszAttrib), ATTRIB_USER_PWD, CE_ATTRIB_USER_PWD))
                            {
                                DWORD strLength = wcslen(pwszValue);
                                a_pUserPwd = new WCHAR[strLength+1];
                                memcpy(a_pUserPwd, pwszValue, (strLength+1)*sizeof(WCHAR));
                            }

                            if (S_OK != pReader->MoveToNextAttribute())
                            {
                                break;
                            }

                        }
                        
                    } //while - read all attributes

                    if (!a_pUserName || !a_pUserPwd)
                    {
                        return scp_err_KeyContainerParseError;
                    }

                    // Create a use object and initialize it with the attributes we just read
                    //
                    a_pUser = new CUser(
                                    GenerateUserId(),                                     
                                     a_pUserName,                                    
                                     a_pUserPwd);
					// Add current user to KeyManager's Store
					//
					pUserCopy = a_pUser.PvReturn();
					m_userStore.Add(pUserCopy);                    
                    

                 }//if - User TAG
                //if it is a key tag then add it to current user's store
    	    	else if (FEqStringIgnoreCase(pwszLocalName, wcslen(pwszLocalName), TAG_KEY, CE_TAG_KEY)) 
	    	    {
                    CAutoP<WCHAR> a_pthumb, a_pname, a_pflags, a_palgid, a_ppvtkey;
                    
                    // Read the attributes of the key tag and generate a key object
                    // 
                    while (TRUE)
                    {
                        const WCHAR * pwszAttrib;
                        const WCHAR * pwszValue;
                        DWORD strlen = 0;

                        HRCALL(pReader->GetLocalName(&pwszAttrib, NULL), scp_err_KeyContainerParseError);
                        HRCALL(pReader->GetValue(&pwszValue, NULL), scp_err_KeyContainerParseError);
                        strlen = wcslen(pwszValue);

                        // Thumbprint
                        if (FEqStringIgnoreCase(pwszAttrib, wcslen(pwszAttrib), ATTRIB_KEY_THUMB, CE_ATTRIB_KEY_THUMB))
                        {
                            a_pthumb = new WCHAR[strlen+1];
                            memcpy(a_pthumb, pwszValue, (strlen+1) * sizeof(WCHAR));
                        }
                        // Key Name
                        else if (FEqStringIgnoreCase(pwszAttrib, wcslen(pwszAttrib), ATTRIB_KEY_NAME, CE_ATTRIB_KEY_NAME))
                        {
                            a_pname = new WCHAR[strlen+1];
                            memcpy(a_pname, pwszValue, (strlen+1) * sizeof(WCHAR));				
                        }
                        // Flags
                        else if (FEqStringIgnoreCase(pwszAttrib, wcslen(pwszAttrib), ATTRIB_KEY_FLAGS, CE_ATTRIB_KEY_FLAGS))
                        {
                            a_pflags = new WCHAR[strlen+1];
                            memcpy(a_pflags, pwszValue, (strlen+1) * sizeof(WCHAR));
                        }
                        // AlgId
                        else if (FEqStringIgnoreCase(pwszAttrib, wcslen(pwszAttrib), ATTRIB_KEY_ALGID, CE_ATTRIB_KEY_ALGID))
                        {
                            a_palgid = new WCHAR[strlen+1];
                            memcpy(a_palgid, pwszValue, (strlen+1) * sizeof(WCHAR));
                        }		
                        // Private key file path    
                        else if (FEqStringIgnoreCase(pwszAttrib, wcslen(pwszAttrib), ATTRIB_KEY_PVTKEY, CE_ATTRIB_KEY_PVTKEY))
                        {
                            a_ppvtkey = new WCHAR[strlen+1];
                            memcpy(a_ppvtkey, pwszValue, (strlen+1) * sizeof(WCHAR));
                        }

                        if (S_OK != pReader->MoveToNextAttribute())
                        {
                            break;
                        }
                    
                    }// Read all attributes

                    // Convert Thumbprint to UUID
                    // 
                    RPC_STATUS retStatus = RPC_S_OK;
                    UUID thumbGUID;
                    RPC_WSTR temp;

                    retStatus = UuidFromStringW( const_cast<WCHAR*>(*(&a_pthumb)), &thumbGUID);
                    if (retStatus != RPC_S_OK)
                    {
                        dprintf("Unable to convert thumbprint: %s to UUID", a_pthumb);
                        goto cleanup;
                    }

                    // Convert AlgId & flags to integer
                    //
                    int algID = _wtoi(a_palgid);
                    int keyFlags = _wtoi(a_pflags);

                    // Create a Crypto Key object and Add to User's key store
                    //
                    a_pKey = new CCryptoKey(
                                        GenerateKeyId(), 
                                        a_pname, 
                                        thumbGUID, 
                                        algID, 
                                        GetAlgInfoByAlgId(algID),
                                        keyFlags, 
                                        a_ppvtkey);

                    // Initialize key material from file
                    //
                    if (a_pKey->InitFromFile() != scp_err_Success)
                    {
                        dprintf("Unable to read key file");
                        goto cleanup;
                    }

                    // Add the key to user store
                    //
                    pUserCopy->AddKeyToStore(a_pKey.PvReturn());

		        }//if - Key Tag
                 
			break; // XmlNodeType_Element:
		
            }//switch
             
        }
        
    
cleanup:
	m_fLoadedFromXml = TRUE;
	return scp_err_Success;
};

// This method serializes the current provider state to XML file. All users and 
// their respective key store are serialized into XML. Each user and key object
// performs its own serialization. As in LoadFromXML method, this method also 
// synchronizes access to the XML file. Look at the comments above for more details.
//
SqlCpError CKeyManager::SaveToXmlFile()
{
	_ASSERT(m_awsFile && m_fLoadedFromXml);

	// Synchronize with other threads, which do Load/Save Xml
	CAutoCriticalSection acs(&m_csXmlLoadSave);
	acs.Enter();

    // If Filepath has not been loaded from registry then load it
    //
    if (!m_awsFile)
    {
        LoadFilePathFromRegistry();
    }
	
    // Save XML to File
	//	
	HRESULT hr;
	CComPtr<IStream> pOutFileStream;
	CComPtr<IXmlWriter> pWriter;

    // Create file stream for writing
    //
	HRCALL(SHCreateStreamOnFile(m_awsFile, STGM_CREATE | STGM_WRITE, &pOutFileStream), scp_err_CantLoadXml);

    // Create writer and set properties
    //
    HRCALL(CreateXmlWriter(__uuidof(IXmlWriter), (void**) &pWriter, NULL), scp_err_CantLoadXml);
    HRCALL(pWriter->SetProperty(XmlWriterProperty_Indent, TRUE), scp_err_CantLoadXml);
    HRCALL(pWriter->SetOutput(pOutFileStream), scp_err_CantLoadXml);

    // Write XML Header
    //
    HRCALL(pWriter->WriteStartDocument(XmlStandalone_Omit), scp_err_CantLoadXml);

    // Write <USBCryptoProviders>
    HRCALL(pWriter->WriteStartElement(NULL, TAG_USBCRYPTOPROVIDERS, NULL), scp_err_CantLoadXml);    
    // Write <Users>
    HRCALL(pWriter->WriteStartElement(NULL, TAG_USERS, NULL), scp_err_CantLoadXml);

    // Writer user data
    //
    for (ULONG i = 0; i < m_userStore.GetCount(); i++)
    {
        // Write <USER>
        HRCALL(pWriter->WriteStartElement(NULL, TAG_USER, NULL), scp_err_CantLoadXml);
        
        // Serialize User
        CUser * pUser = m_userStore.GetAt(i);        
        _ASSERT(pUser);
        pUser->ToXml(pWriter);

        // Write </USER>
        HRCALL(pWriter->WriteEndElement(), scp_err_CantLoadXml);
    }



    // Write </Users>
    HRCALL(pWriter->WriteEndElement(), scp_err_CantLoadXml);
    // Write </USBCryptoProviders> and flush it to XML file
    HRCALL(pWriter->WriteEndElement(), scp_err_CantLoadXml);
	HRCALL(pWriter->WriteEndDocument(), scp_err_CantLoadXml);
	HRCALL(pWriter->Flush(), scp_err_CantLoadXml);
	return scp_err_Success;
}


// Locate a user in the user list based on its name
// This sample doesn't allow dynamic creation/deletion of users
// so there is no need to synchronize over this list. However an
// actual provider which allows such facility should implement proper
// synchronization scheme
//
CUser* CKeyManager::GetUserByName(CWStr& name)
{
	if (name.Cb() == 0 || name.Ws() == NULL)
	{
		return NULL;
	}

	for (ULONG i = 0; i < m_userStore.GetCount(); i++)
	{
		CUser* pUser = m_userStore.GetAt(i);
		_ASSERT(pUser);
		if (pUser->GetName().Cb() == name.Cb() &&
			_wcsnicmp(pUser->GetName().Ws(), name.Ws(), pUser->GetName().Cb()/sizeof(WCHAR)) == 0)
		{
			return pUser;
		}
	}
	return NULL;
}

// Locate a user in the user store based on its ID
// In this example, user information is only loaded/deleted by load/save 
// to XML methods, therefore there is no need to synchronize here. However
// an actual provider might need to serialize this access as well based on its
// own requirements
//
CUser* CKeyManager::GetUserById(UserId idUser)
{
	if (idUser == x_UserIdBad)
	{
		return NULL;
	}

	for (ULONG i = 0; i < m_userStore.GetCount(); i++)
	{
		CUser* pUser = m_userStore.GetAt(i);
		_ASSERT(pUser);
		if (idUser == pUser->GetUserId())
		{
			return pUser;
		}
	}
	return NULL;
}

// Get the Algorithm Info structure for a given algID
//
const SqlCpAlgorithmInfoUSB* CKeyManager::GetAlgInfoByAlgId(SqlCpAlgId algId)
{
	for (ULONG i = 0; i< x_cAlgInfos; i++)
	{
		if (x_AlgInfos[i]._algInfo.algId == algId)
		{
			return &x_AlgInfos[i];
		}
	}
	return NULL;
}

// Load configuration information from the registry
// It looks up the registy keys from: HKLM\Software\USBCryptoProvider
// KeyFolderPath (REG_SZ): Path to a directory where key files are stored
// XMLFilePath   (REG_SZ): Path to XML configuration file
// If any of these values could not loaded from the registry then the default paths
// specified in USBCryptoProvider.h are used
//
void CKeyManager::LoadFilePathFromRegistry()
{
    LONG err = ERROR_SUCCESS;
    HKEY hKey = NULL;
    DWORD cbSize = 0;
    DWORD dwType = 0;

    // Open Regkey
    err = RegOpenKey(HKEY_LOCAL_MACHINE, x_wszRegKeyPath, &hKey);
    if (err != ERROR_SUCCESS)
    {
        dprintf ("Failed to open regkey. Error code: %d", err);
        goto cleanup;
    }

    // Read Key directory path
    //
    err = RegGetValue(hKey, NULL, x_wszRegValueName, RRF_RT_REG_SZ, &dwType, NULL, &cbSize);
    if (err != ERROR_SUCCESS && err != ERROR_MORE_DATA)
    {
        dprintf ("Failed to get key value Size. Error code: %d", err);
        goto cleanup;
    }
	
    // Allocate memory
    m_awsDirectoryPath = (WCHAR *) new BYTE[cbSize];

    err = RegGetValue(hKey, NULL, x_wszRegValueName, RRF_RT_REG_SZ, &dwType, m_awsDirectoryPath, &cbSize);
    if (err != ERROR_SUCCESS)
    {
        dprintf ("Failed to get key value. Error code: %d", err);
        goto cleanup;
    }

    // Read XML File Path
    //
    err = RegGetValue(hKey, NULL, x_wszRegXmlValueName, RRF_RT_REG_SZ, &dwType, NULL, &cbSize);
    if (err != ERROR_SUCCESS && err != ERROR_MORE_DATA)
    {
        dprintf ("Failed to get XML File key value size. Error code: %d", err);
        goto cleanup;
    }

    // allocate memory    
    m_awsFile = (WCHAR *) new BYTE[cbSize];

    err = RegGetValue(hKey, NULL, x_wszRegXmlValueName, RRF_RT_REG_SZ, &dwType, m_awsFile, &cbSize);
    if (err != ERROR_SUCCESS)
    {
        dprintf ("Failed to get XML File key value. Error code: %d", err);
        goto cleanup;
    }


cleanup:
    // Use Default Paths
    //
    if (err != ERROR_SUCCESS)
    {
        if (!m_awsFile)
        {
            dprintf("Using default path for Key Directory");
            m_awsFile = new WCHAR[wcslen(x_wszXMLDefaultFileName) + 1];
            memcpy(m_awsFile, x_wszXMLDefaultFileName, (wcslen(x_wszXMLDefaultFileName) + 1) * sizeof(WCHAR));
        }

        if (!m_awsDirectoryPath)
        {
            dprintf("Using default path for XML file");
            m_awsDirectoryPath = new WCHAR[wcslen(x_wszKeyDirectoryPath)];
            memcpy(m_awsDirectoryPath, x_wszKeyDirectoryPath, (wcslen(x_wszKeyDirectoryPath) + 1) * sizeof(WCHAR));
        }

    }    

    if (hKey)
        RegCloseKey(hKey);

}

// Cleanup all keys in dtor
//
CUser::~CUser()
{
	for (ULONG i = 0; i< m_keyStore.GetCount();i++)
	{
		_ASSERT(m_keyStore.GetAt(i));
		m_keyStore.GetAt(i)->Release();
	}
	m_keyStore.RemoveAll();

	DeleteCriticalSection(&m_csKeyStore);
}


// Authenticate a user with EKM provider. 
// This method does a simple match on password
//
BOOLEAN CUser::FAuthenticate(CWStr& pwd)
{
	if (m_cbPwdHash == pwd.Cb() &&
		_wcsnicmp(m_awsPwdHash, pwd.Ws(), m_cbPwdHash/sizeof(WCHAR)) == 0)
	{
		return TRUE;
	}
	return FALSE;
}

// Create a key with the provided name in the user. If no 
// name is given then a GUID is generated for name.
// Access to key store is synchronized. Once again the simple 
// synchronization scheme is only for illustration and an actual 
// provider should use its own scheme.
//
SqlCpError CUser::CreateKey (const SqlCpStr* pKeyName,      
							   SqlCpAlgId algid,
							   SqlCpKeyFlags keyFlags,
							   __OUT SqlCpKeyThumbprint* pKeyThumb)
{
	_ASSERT(pKeyThumb && pKeyThumb->pb && pKeyThumb->cb >= sizeof(GUID));

    // Synchronize with other threads, which need to read/write to key store
	CAutoCriticalSection acs(&m_csKeyStore);
	acs.Enter();

	// Check that the key with this name doesn't exist already
	CAutoRefc<CCryptoKey> a_key;
	if (pKeyName && pKeyName->cb && pKeyName->ws)
	{
		a_key = GetKeyByName(pKeyName);
		if (a_key)
		{
			return scp_err_KeyWithNameExists;
		}
	}

    // If a key by this name doesn't exist then create a new key object
	a_key = new CCryptoKey(); 

    // Initialize/Generate the key
	SqlCpError err = scp_err_Success;
	if ((err = a_key->InitKey(pKeyName, algid, keyFlags)) != scp_err_Success)
	{
		return err;
	}
    // Copy the thumbprint to the out pointer
	memcpy(pKeyThumb->pb, &a_key->GetThumb(), sizeof(GUID));
	pKeyThumb->cb = sizeof(GUID);

    // Add the key to key store
	m_keyStore.Add(a_key.PvReturn());	
	return scp_err_Success;
}

// Delete a key from the EKM provider, This method does not delete the key file or the 
// actual persisted key from the machine. It uses the same synchronization scheme as 
// CreateKey for key store.
//
SqlCpError CUser::DeleteKey (const SqlCpKeyThumbprint* pKeyThumb)
{
	_ASSERT(pKeyThumb && pKeyThumb->pb && pKeyThumb->cb >= sizeof(GUID));
	if (pKeyThumb->cb != sizeof(GUID))
	{
		return scp_err_NotFound;
	}

	// Synchronize with other threads, which need to read/write to key store
	CAutoCriticalSection acs(&m_csKeyStore);
	acs.Enter();
	for (ULONG i = 0; i< m_keyStore.GetCount(); i++)
	{
		CCryptoKey* pKey = m_keyStore.GetAt(i);
		_ASSERT(pKey);
		if (memcmp(&pKey->GetThumb(), pKeyThumb->pb, sizeof(GUID)) == 0)
		{
			pKey->Release();
			m_keyStore.RemoveAt(i);
			return scp_err_Success;
		}
	}
	
	return scp_err_NotFound;
}

// Add a key to store - synchronize access to key store
//
SqlCpError CUser::AddKeyToStore(CCryptoKey * pKey)
{
  	// Synchronize with other threads, which need to read/write to key store
	CAutoCriticalSection acs(&m_csKeyStore);
	acs.Enter();

    m_keyStore.Add(pKey);
	return scp_err_Success;
}

// Iterator to get the next key - synchronize access to key store
//
CCryptoKey* CUser::GetNextKey (SqlCpKeyId idKey)
{
	// Synchronize with other threads, which need to read/write to key store
	CAutoCriticalSection acs(&m_csKeyStore);
	acs.Enter();
	for (ULONG i = 0; i< m_keyStore.GetCount(); i++)
	{
		CCryptoKey* pKey = m_keyStore.GetAt(i);
		_ASSERT(pKey);
		if (pKey->GetKeyId() > idKey)
		{
			pKey->AddRef();
			return pKey;
		}
	}
	return NULL;
}

// Get the key object based on its key id  - synchronize access to key store
//
CCryptoKey* CUser::GetKeyById (SqlCpKeyId idKey)
{
	if (idKey == x_scp_KeyIdBad)
	{
		return NULL;
	}

	// Synchronize with other threads, which need to read/write to key store
	CAutoCriticalSection acs(&m_csKeyStore);
	acs.Enter();
	for (ULONG i = 0; i< m_keyStore.GetCount(); i++)
	{
		CCryptoKey* pKey = m_keyStore.GetAt(i);
		_ASSERT(pKey);
		if (pKey->GetKeyId() == idKey)
		{
			pKey->AddRef();
			return pKey;
		}
	}
	return NULL;
}

// Get the key object based on its name - synchronize access to key store
//
CCryptoKey* CUser::GetKeyByName (const SqlCpStr* pKeyName, BOOLEAN fNoLock)
{
	_ASSERT(pKeyName);
	if ( !pKeyName->ws || !pKeyName->cb)
	{
		return NULL;
	}

	// Synchronize with other threads, which need to read/write to key store
	CAutoCriticalSection acs(&m_csKeyStore);
	if (!fNoLock)
	{
		acs.Enter();
	}
	for (ULONG i = 0; i< m_keyStore.GetCount(); i++)
	{
		CCryptoKey* pKey = m_keyStore.GetAt(i);
		_ASSERT(pKey);
		if (pKey->GetName().Cb() == pKeyName->cb && 
			(_wcsnicmp(pKey->GetName().Ws(), pKeyName->ws, pKey->GetName().Cb()/sizeof(WCHAR)) == 0))
		{
			pKey->AddRef();
			return pKey;
		}
	}
	return NULL;
}

// Get the key object based on its thumbprint - synchronize access to key store
//
CCryptoKey* CUser::GetKeyByThumb (const SqlCpKeyThumbprint* pKeyThumb)
{
	_ASSERT(pKeyThumb);
	if (!pKeyThumb->pb || pKeyThumb->cb != sizeof(GUID))
	{
		return NULL;
	}

	// Synchronize with other threads, which need to read/write to key store
	CAutoCriticalSection acs(&m_csKeyStore);
	acs.Enter();
	for (ULONG i = 0; i< m_keyStore.GetCount(); i++)
	{
		CCryptoKey* pKey = m_keyStore.GetAt(i);
		_ASSERT(pKey);
		if (memcmp(&pKey->GetThumb(), pKeyThumb->pb, sizeof(GUID)) == 0)
		{
			pKey->AddRef();
			return pKey;
		}
	}
	
	return NULL;
}

// Get key info based on its name
//
SqlCpError CUser::GetKeyInfoByName (const SqlCpStr* pKeyName, __OUT SqlCpKeyInfo* pKeyInfo)
{
	_ASSERT(pKeyInfo);
	CAutoRefc<CCryptoKey> a_key = GetKeyByName(pKeyName);
	if ( !a_key)
	{
		return scp_err_NotFound;
	}

	return a_key->GetKeyInfo(pKeyInfo);
}

// Get key info based on its thumbprint
//
SqlCpError CUser::GetKeyInfoByThumb (const SqlCpKeyThumbprint* pKeyThumb, __OUT SqlCpKeyInfo* pKeyInfo)
{
	_ASSERT(pKeyInfo);
	CAutoRefc<CCryptoKey> a_key = GetKeyByThumb(pKeyThumb);
	if ( !a_key)
	{
		return scp_err_NotFound;
	}

	return a_key->GetKeyInfo(pKeyInfo);
}

// Serialize the current User to XML - synchronize access to key store
//
SqlCpError CUser::ToXml(CComPtr<IXmlWriter> &pWriter)
{


	// Synchronize with other threads, which need to read/write to key store
	CAutoCriticalSection acs(&m_csKeyStore);
	acs.Enter();

    //Serialize Attributes
    //
    WCHAR ** autoStrPtr = NULL;
	HRESULT hr = S_OK;

    autoStrPtr = &m_awsName;
    HRCALL(pWriter->WriteAttributeString(NULL, ATTRIB_USER_NAME, NULL, *autoStrPtr), scp_err_CantLoadXml);

    autoStrPtr = &m_awsPwdHash;
    HRCALL(pWriter->WriteAttributeString(NULL, ATTRIB_USER_PWD, NULL, *autoStrPtr), scp_err_CantLoadXml);


    // Serialize Keys to XML
	for (ULONG i = 0; i< m_keyStore.GetCount(); i++)
	{
        // Write <Key>
        HRCALL(pWriter->WriteStartElement(NULL,TAG_KEY, NULL), scp_err_CantLoadXml);    

		CCryptoKey* pKey = m_keyStore.GetAt(i);
		_ASSERT(pKey);
		pKey->ToXml(pWriter);

        // Write </Key>
        HRCALL(pWriter->WriteEndElement(), scp_err_CantLoadXml);
	}

    return scp_err_Success;
}


// ctor to initialize the key object based on properties read from XML file
//
CCryptoKey::CCryptoKey(
                    SqlCpKeyId keyid, 
                    const WCHAR * wsName, 
                    GUID Thumb, 
                    SqlCpAlgId algId, 
					const SqlCpAlgorithmInfoUSB * pAlgInfo,
                    SqlCpKeyFlags keyFlags, 
					const WCHAR * pvtKeyPath) : m_pAlgInfo(NULL),
												m_keyFlags(0),  
												m_hCryptoProvider(0), m_hKey(0), 
												m_fInitialized(FALSE)
												
{
    m_idKey = keyid;
    m_thumb = Thumb;
    m_algid = algId;
    m_keyFlags = keyFlags;
    m_pKeyMaterial = NULL;
    m_cbKeyMaterial = 0;

    // Allocate memory for strings and copy them over
    //
	m_cbName = wcslen(wsName) * sizeof(WCHAR);
    m_awsName = (WCHAR *) new BYTE[m_cbName + sizeof(WCHAR)];
    memcpy(m_awsName, wsName, m_cbName + sizeof(WCHAR));
    
    m_awsPvtKeyPath = new WCHAR[wcslen(pvtKeyPath)+1];
    memcpy(m_awsPvtKeyPath, pvtKeyPath, (wcslen(pvtKeyPath) +1) * sizeof(WCHAR));

	//Initialize AlgInfo
	//
	m_pAlgInfo = pAlgInfo;

}

// dtor
//
CCryptoKey::~CCryptoKey()
{
	if (m_hKey)
	{
		BCryptDestroyKey(m_hKey);
	}

	if (m_hCryptoProvider)
	{
		BCryptCloseAlgorithmProvider (m_hCryptoProvider, 0);
	}

    if (m_pKeyMaterial)
    {
        delete[] m_pKeyMaterial;
    }

}

// Verify all the properties and generate the key
// This method verifies all the properties and flags and calls Generate key which actually generates
// key material.
//
SqlCpError CCryptoKey::InitKey(const SqlCpStr* pKeyName, SqlCpAlgId algid, SqlCpKeyFlags keyFlags)
{
	_ASSERT(!m_fInitialized);

	// Check that algId is supported by the provider
	m_pAlgInfo = CKeyManager::GetAlgInfoByAlgId(algid);
	if (!m_pAlgInfo)
	{
		return scp_err_NotSupported;
	}

	// Check if key flags are supported by the provider
	SqlCpKeyFlags provFlags = m_pAlgInfo->_algInfo.type == scp_kt_Symmetric ? 
						x_providerInfo.symmKeySupport : x_providerInfo.asymmKeySupport;

	// Exclude "supported" bit from the comparison
	keyFlags &= ~scp_kf_Supported;
	provFlags &= ~scp_kf_Supported;

	// Even if a single key feature (bit) is not suported by the provider, we fail
	if ((provFlags & keyFlags) != keyFlags)
	{
		return scp_err_NotSupported;
	}


	// Generate key id here
	m_idKey = CKeyManager::Get()->GenerateKeyId();

	// Generate thumbprint here
    RPC_STATUS rpcStatus = UuidCreate(&m_thumb);
	_ASSERT(rpcStatus == RPC_S_OK);

	// If SqlCpProviderInfo.fAcceptKeyName = FALSE, then need to fail here
	// since the flag dictates that the user can't secify key name - it will be generated
	// by the provider instead
	// For this implementation we allow user specified name, i.e.
	// SqlCpProviderInfo.fAcceptKeyName = TRUE
	if (pKeyName->cb && pKeyName->ws)
	{
		m_awsName = (WCHAR*)new BYTE[pKeyName->cb + sizeof(WCHAR)];
		memcpy(m_awsName, pKeyName->ws, pKeyName->cb);
		m_cbName = pKeyName->cb;
		// We maintain all strings internally as NULL terminated strings
		// 
		m_awsName[m_cbName/sizeof(WCHAR)] = L'\0';
	}
	else
	{
		// If name is not provided, then generate one
		m_cbName = 0;
		FBytesToString((BYTE*)&m_thumb, sizeof(GUID), NULL, m_cbName);
		m_awsName = (WCHAR*)new BYTE[m_cbName];
		BOOL f = FBytesToString((BYTE*)&m_thumb, sizeof(GUID), (BYTE*)((WCHAR*)m_awsName), m_cbName);
		_ASSERT(f);
	}
	
    m_keyFlags = keyFlags;
    m_algid = algid;

	SqlCpError err = scp_err_Failure;
	if ((err = GenerateKey()) != scp_err_Success)
	{
		return err;
	}

	m_fInitialized = TRUE;
	return scp_err_Success;
}

// Get the key info - return insufficientBuffer in case the provided
// buffers are not big enough.
//
SqlCpError CCryptoKey::GetKeyInfo(__OUT SqlCpKeyInfo* pKeyInfo)
{
	_ASSERT(m_fInitialized && pKeyInfo);

	// Check if buffer is sufficient
	BOOLEAN fInsufficientBuf = FALSE;
	if (pKeyInfo->name.cb < GetName().Cb() || !pKeyInfo->name.ws)
	{
		pKeyInfo->name.cb = GetName().Cb();
		fInsufficientBuf = TRUE;
	}

	if (pKeyInfo->thumb.cb < sizeof(GUID) || !pKeyInfo->thumb.pb)
	{
		pKeyInfo->thumb.cb = sizeof(GUID);
		fInsufficientBuf = TRUE;
	}

	if (fInsufficientBuf)
	{
		return scp_err_InsufficientBuffer;
	}

	// Otherwise copy the info
	memcpy(pKeyInfo->name.ws, GetName().Ws(), GetName().Cb());
	pKeyInfo->name.cb = GetName().Cb();

	memcpy(pKeyInfo->thumb.pb, &m_thumb, sizeof(GUID));
	pKeyInfo->thumb.cb = sizeof(GUID);

	pKeyInfo->algId = m_algid;
    pKeyInfo->flags = m_keyFlags;  

	return scp_err_Success;
}

// Serialize the key to XML - Also serialize the key material to file
//
SqlCpError CCryptoKey::ToXml(CComPtr<IXmlWriter> &pWriter)
{
	_ASSERT(m_fInitialized);

    // Serialize attributes
    //
    WCHAR ** autoStrPtr = NULL;
	HRESULT hr = S_OK;
    
    WCHAR * ThumbStr;    
    RPC_STATUS rpcStatus = RPC_S_OK;
    WCHAR integerString[MAX_PATH];

    rpcStatus = UuidToStringW(&m_thumb, &ThumbStr);
    if (rpcStatus != RPC_S_OK)
    {
        dprintf("Unable to Serialize GUID to String");
        return scp_err_CantLoadXml;
    }

    hr = pWriter->WriteAttributeString(NULL, ATTRIB_KEY_THUMB, NULL, ThumbStr);
    if (S_OK != hr)
    {
        RpcStringFree(&ThumbStr);
        return scp_err_CantLoadXml;        
    }

    autoStrPtr = &m_awsName;
    HRCALL(pWriter->WriteAttributeString(NULL, ATTRIB_KEY_NAME, NULL, *autoStrPtr), scp_err_CantLoadXml);    

    wsprintf(integerString, L"%d", m_algid);
    HRCALL(pWriter->WriteAttributeString(NULL, ATTRIB_KEY_ALGID,NULL, integerString), scp_err_CantLoadXml);    

    wsprintf(integerString, L"%d", m_keyFlags);
    HRCALL(pWriter->WriteAttributeString(NULL, ATTRIB_KEY_FLAGS,NULL, integerString), scp_err_CantLoadXml);    

    // Serialize the key - we don't check for any serialization errors
    //
    SerializeKey();

	// Serialize Private key path
	//
	autoStrPtr = &m_awsPvtKeyPath;
    HRCALL(pWriter->WriteAttributeString(NULL, ATTRIB_KEY_PVTKEY,NULL, *autoStrPtr), scp_err_CantLoadXml);  

    
    return scp_err_Success;
}

// Initialize the key materia from a file (i.e. open an existing key)
//
SqlCpError CCryptoKey::InitFromFile()
{
	_ASSERT(!m_fInitialized);
    _ASSERT(!m_hCryptoProvider);
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	
    // Create Stream for Key File
    //
    ifstream keyFile(m_awsPvtKeyPath, ios::in | ios::binary | ios::ate);

    if (keyFile.fail() || !keyFile.is_open())
    {
        dprintf("Unable to open key file %ws", m_awsPvtKeyPath);
        return scp_err_CantLoadXml;
    }

    // Read data from File
    //
    ifstream::pos_type ifStream_size = keyFile.tellg();
    ULONG size = (ULONG)ifStream_size;

    CAutoP<BYTE> a_pKeyData;
    a_pKeyData = new BYTE[size];

    // Move to start of file and read
    //
    keyFile.seekg(0, ios::beg);
    keyFile.read((CHAR *)(*(&a_pKeyData)), ifStream_size);

    keyFile.close();    

    // Create Algorithm Provider Handle
    //

    NTCALL(BCryptOpenAlgorithmProvider(&m_hCryptoProvider, m_pAlgInfo->_cngAlgId, NULL, 0), scp_err_CantGenerateCryptoKey);

    // Read Blob depending on Key Type
    //
    if (m_pAlgInfo->_algInfo.type == scp_kt_Symmetric)
    {
        ULONG cbData = 0;

        NTCALL(BCryptGetProperty(
                                   m_hCryptoProvider, 
                                   BCRYPT_OBJECT_LENGTH, 
                                   (PBYTE)&m_cbKeyMaterial, 
                                   sizeof(DWORD), 
                                   &cbData, 
                                   0), scp_err_CantGenerateCryptoKey);
        
        m_pKeyMaterial = new UCHAR[m_cbKeyMaterial];

        NTCALL(BCryptImportKey(
                        m_hCryptoProvider, 
                        NULL,
                        BCRYPT_OPAQUE_KEY_BLOB,
                        &m_hKey,
                        m_pKeyMaterial,
                        m_cbKeyMaterial,
                        a_pKeyData,
                        size,
                        0), scp_err_CantGenerateCryptoKey);
        
    }
    else
    {
        NTCALL(BCryptImportKeyPair(
                        m_hCryptoProvider,
                        NULL,
                        BCRYPT_PRIVATE_KEY_BLOB,
                        &m_hKey,
                        a_pKeyData,
                        size,
                        0), scp_err_CantGenerateCryptoKey);
    }
	
	m_fInitialized = TRUE;
	return scp_err_Success;
}

// Generate a key based on specified properties
//
SqlCpError CCryptoKey::GenerateKey()
{
	_ASSERT(!m_hCryptoProvider);
	_ASSERT (m_algid != x_scp_AlgIdBad);


	_ASSERT(m_pAlgInfo);
    LPCWSTR cngAlgId = m_pAlgInfo->_cngAlgId;
	ULONG ulKeyLen = m_pAlgInfo->_algInfo.bitLen;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // Acquire handle for CNG Crypto Provider
    //
    NTCALL(BCryptOpenAlgorithmProvider(&m_hCryptoProvider, cngAlgId, NULL, 0), scp_err_CantGenerateCryptoKey);

    // Generate Key (different code for symmetric vs asymmetric)
    //
    if (m_pAlgInfo->_algInfo.type == scp_kt_Symmetric)
    {
        ULONG cbData = 0;
       
        // Set chaining mode to CBC (CAPI Default)
        //
        NTCALL(BCryptSetProperty(
                                m_hCryptoProvider,
                                BCRYPT_CHAINING_MODE, 
                                (PBYTE)BCRYPT_CHAIN_MODE_CBC, 
                                sizeof(BCRYPT_CHAIN_MODE_CBC), 
                                0), scp_err_CantGenerateCryptoKey);
                                

        // Get Key Material size
        //
        NTCALL(BCryptGetProperty(
                                   m_hCryptoProvider, 
                                   BCRYPT_OBJECT_LENGTH, 
                                   (PBYTE)&m_cbKeyMaterial, 
                                   sizeof(DWORD), 
                                   &cbData, 
                                   0), scp_err_CantGenerateCryptoKey);
        
        m_pKeyMaterial = new UCHAR[m_cbKeyMaterial];

        NTCALL (BCryptGenerateSymmetricKey(
                                    m_hCryptoProvider,
                                    &m_hKey,
                                    m_pKeyMaterial,
                                    m_cbKeyMaterial,
                                    (PUCHAR)&x_pbKeySecret[0],
                                    x_cbKeySecret,
                                    0),scp_err_CantGenerateCryptoKey);
    
    }// if symmetric key
    else if (m_pAlgInfo->_algInfo.type == scp_kt_Asymmetric)
    {
		NTCALL(BCryptGenerateKeyPair(m_hCryptoProvider, &m_hKey, ulKeyLen, 0), scp_err_CantGenerateCryptoKey);        
        // Persisit the key so that it can be used
        //
        NTCALL(BCryptFinalizeKeyPair(m_hKey, 0), scp_err_CantGenerateCryptoKey);
    
    }// if asymmetric key
    else
    {
        return scp_err_NotSupported;
    }

	_ASSERT(m_hKey);

	return scp_err_Success;
}

// Serialize the key material into a file
//
SqlCpError CCryptoKey::SerializeKey()
{
	_ASSERT(m_hKey);
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    
    // Create File Name for the private key file
    //
    const WCHAR * pDirPath = CKeyManager::Get()->GetDirectoryPath();
    ULONG ceFileDirPath = wcslen(pDirPath);
    ULONG ceFilePath = ceFileDirPath;    
    ceFilePath += wcslen(m_awsName) + 1;

    m_awsPvtKeyPath = new WCHAR[ceFilePath];
    memcpy(m_awsPvtKeyPath, pDirPath, wcslen(pDirPath) * sizeof(WCHAR));
    memcpy(m_awsPvtKeyPath + ceFileDirPath, m_awsName, wcslen(m_awsName) * sizeof(WCHAR));
    m_awsPvtKeyPath[ceFilePath-1] = L'\0';

    // Create a FileStream with a blank file
    //
    ofstream keyFile(m_awsPvtKeyPath, ios_base::binary | ios_base::trunc);
    
    ULONG cbOut = 0;
    ULONG pcbResult = 0;
    CAutoP<BYTE> pbOut;
    LPWSTR pwszBlobType = BCRYPT_PRIVATE_KEY_BLOB;

    if (m_pAlgInfo->_algInfo.type == scp_kt_Symmetric)
    {
        pwszBlobType = BCRYPT_OPAQUE_KEY_BLOB;
    }

    // Export the key into a blob
    //
    
    //Query the size
    status = BCryptExportKey(
                            m_hKey, 
                            NULL,
                            pwszBlobType,
                            NULL, //pbout
                            0,
                            &pcbResult, 
                            0);
   if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }

    // Allocate memory
    _ASSERT(pcbResult);
    pbOut = new BYTE[pcbResult];
    cbOut = pcbResult;
        
    // Make the call
    status = BCryptExportKey(
                            m_hKey, 
                            NULL,
                            pwszBlobType,
                            pbOut,
                            cbOut,
                            &pcbResult, 
                            0);        
    if (!NT_SUCCESS(status))
    {
        goto cleanup;
    }
    
    // Serialize the key into the file
    //
    keyFile.write((CHAR *)*(&pbOut), cbOut);
    keyFile.flush();
	
cleanup:
    if (keyFile.is_open())
    {
        keyFile.close();
    }   
    return scp_err_Success;
}

// Encrypt Data. Check the size of pCiphertext buffer and return Insufficient buffer if it is not big enough
// otherwise encrypt data and copy it over to pCiphertext. Certain key providers like CAPI have problems if the
// same key handle is used simultaneously for crypto operations. This implementation doesn't care about that but
// and actual provider should consider this issue.
//
SqlCpError CCryptoKey::Encrypt(
    					   __IN   BOOLEAN fFinal,
						   __IN const SqlCpEncryptionParam* pEncryptParams,
						   __IN   ULONG cEncryptParams,
						   __IN const SqlCpData* pPlaintext,
						   __OUT SqlCpData* pCiphertext)
{

    if (!m_hCryptoProvider || !m_hKey || !m_fInitialized)
    {
        return scp_err_Failure;
    }
    
    // For Asymmetric keys pad data using PKCS1. This will pad random data
    // upto one block length
    //
    DWORD dwPaddingFlags = BCRYPT_PAD_PKCS1; 
    DWORD pcbResult = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    CAutoP<BYTE> pbIVCopy;
    DWORD        cbIV  = 0;
    DWORD        cbOut = 0;

    // Set padding info and IV for symmetric key
    //
    if (m_pAlgInfo->_algInfo.type == scp_kt_Symmetric)
    {
        if (fFinal == FALSE)
        {
            return scp_err_NotSupported;
        }

        // Find IV in parameters array
        //
        SqlCpEncryptionParam * pIVParam = NULL;
        for (DWORD i=0; i<cEncryptParams; i++)
        {
            if (pEncryptParams[i].type == scp_ep_IV)
            {
                pIVParam = (SqlCpEncryptionParam *)&pEncryptParams[i];
                break;
            }
        }

        // If an IV is provided then make a copy since CNG APIs alter the IV buffer during Encryption/Decryption
        //
        if (pIVParam)
        {
            cbIV = pIVParam->cb;
            // Make sure the IV provided is atleast as long as the required IV
            //
            if (m_pAlgInfo->_algInfo.ivLen > cbIV)
            {
                return scp_err_CantEncryptData;
            }

            pbIVCopy = new BYTE[cbIV];
            memcpy(pbIVCopy, pIVParam->pb, cbIV);
        }

        // Set Padding Mode
        //
        dwPaddingFlags = BCRYPT_BLOCK_PADDING;
    }

    // Query required size for Ciphertext
    //
    NTCALL(BCryptEncrypt(
                    m_hKey,
                    pPlaintext->pb,
                    pPlaintext->cb,
                    NULL,
                    (PUCHAR)pbIVCopy,
                    cbIV,
                    NULL, // pbOutput
                    cbOut,
                    &pcbResult,
                    dwPaddingFlags), scp_err_CantEncryptData);

    // Populate buffer size and return insufficient buffer
    //
    if (pCiphertext->pb == NULL || pCiphertext->cb < pcbResult)
    {
        pCiphertext->cb = pcbResult;
        return scp_err_InsufficientBuffer;
    }

    // Encrypt Data
    //
    NTCALL(BCryptEncrypt(
                    m_hKey,
                    pPlaintext->pb,
                    pPlaintext->cb,
                    NULL,
                    (PUCHAR)pbIVCopy,
                    cbIV,
                    pCiphertext->pb,
                    pCiphertext->cb,
                    &pcbResult,
                    dwPaddingFlags), scp_err_CantEncryptData);      

    // Copy the number of bytes copied into output buffer
    //  
    pCiphertext->cb = pcbResult;


    return scp_err_Success;
}



// Decrypt Data
// Certain key providers like CAPI have problems if the
// same key handle is used simultaneously for crypto operations. This implementation doesn't care about that but
// and actual provider should consider this issue.
//
SqlCpError CCryptoKey::Decrypt (
                            __IN BOOLEAN fFinal,    
                            __IN const SqlCpEncryptionParam* pEncryptParams,
                            __IN ULONG cEncryptParams,    
                            __IN const SqlCpData* pCiphertext,
                            __OUT SqlCpData* pPlaintext)
{

    if (!m_hCryptoProvider || !m_hKey || !m_fInitialized)
    {
        return scp_err_Failure;
    }
    
    // For Asymmetric keys pad data using PKCS1. This will pad random data
    // upto one block length
    //
    DWORD dwPaddingFlags = BCRYPT_PAD_PKCS1;
    DWORD pcbResult = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    CAutoP<BYTE> pbIVCopy;
    DWORD        cbIV  = 0;
    DWORD        cbOut = 0;

    // Set parameters for Symmetric key
    //
    if (m_pAlgInfo->_algInfo.type == scp_kt_Symmetric)
    {
        if (fFinal == FALSE)
        {
            return scp_err_NotSupported;
        }

        // Find IV in parameters array
        //
        SqlCpEncryptionParam * pIVParam = NULL;
        for (DWORD i=0; i<cEncryptParams; i++)
        {
            if (pEncryptParams[i].type == scp_ep_IV)
            {
                pIVParam = (SqlCpEncryptionParam *)&pEncryptParams[i];
                break;
            }
        }

        // If an IV is provided then make a copy since CNG APIs alter the IV buffer during Encryption/Decryption
        //
        if (pIVParam)
        {
            cbIV = pIVParam->cb;
            pbIVCopy = new BYTE[cbIV];
            memcpy(pbIVCopy, pIVParam->pb, cbIV);
        }

        // Set Padding Mode
        //
        dwPaddingFlags = BCRYPT_BLOCK_PADDING;
    
    }

    // Query required size for Ciphertext
    //
    NTCALL(BCryptDecrypt(
                    m_hKey,
                    pCiphertext->pb,
                    pCiphertext->cb,
                    NULL,
                    (PUCHAR)pbIVCopy,
                    cbIV,
                    NULL, // pbOutput
                    cbOut,
                    &pcbResult,
                    dwPaddingFlags), scp_err_CantEncryptData);

    // Populate buffer size and return insufficient buffer
    //
    if (pPlaintext->pb == NULL || pPlaintext->cb < pcbResult)
    {
        pPlaintext->cb = pcbResult;
        return scp_err_InsufficientBuffer;
    }

    // Encrypt Data
    //
    NTCALL(BCryptDecrypt(
                    m_hKey,
                    pCiphertext->pb,
                    pCiphertext->cb,
                    NULL,
                    (PUCHAR)pbIVCopy,
                    cbIV,
                    pPlaintext->pb, // pbOutput
                    pPlaintext->cb,
                    &pcbResult,
                    dwPaddingFlags), scp_err_CantEncryptData);
    // Copy the number of bytes copied into output buffer
    //  
    pPlaintext->cb = pcbResult;

    return scp_err_Success;

}

// Export the public key material of asymmetric key. This method should not be called
// for symmetric keys in v1. For asymmetric keys it should only be called for public_key_blob
//
SqlCpError CCryptoKey::Export(__IN SqlCpKeyBlobType blobType, __IN SqlCpData * pKeyBlob)
{
    _ASSERT(pKeyBlob);
    _ASSERT(m_fInitialized);
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    // Cannot do this for Symmetric keys or private key blobs
    //
    if (m_pAlgInfo->_algInfo.type == scp_kt_Symmetric )
    {
        return scp_err_NotSupported;
    }

    // Currently only public key is allowed to be exported. We do not have to check for scp_kf_exportable
    // since that represents private key material and is not required right now.
    if (blobType != scp_kb_PublicKeyBlob) 
	{
		return scp_err_NotSupported;
	}

    // Get the buffer size for public key blob
    //
    DWORD pcbResult = 0;
    NTCALL(BCryptExportKey(
                            m_hKey, 
                            NULL, 
                            BCRYPT_RSAPUBLIC_BLOB, 
                            NULL, 
                            0 /* cbOut */, 
                            &pcbResult,
                            0), scp_err_CantExportKey);

    if (pKeyBlob->cb < pcbResult || pKeyBlob->pb == NULL)
    {
        pKeyBlob->cb = pcbResult;
        return scp_err_InsufficientBuffer;
    }
    
    // Export the key and copy it over to a buffer
    //
    CAutoP<BYTE> pubKey;
    DWORD cbOut = pcbResult;

    _ASSERT(cbOut);
    pubKey = new BYTE[cbOut];

    NTCALL(BCryptExportKey(
                            m_hKey, 
                            NULL, 
                            BCRYPT_RSAPUBLIC_BLOB, 
                            pubKey, 
                            cbOut,
                            &pcbResult,
                            0), scp_err_CantExportKey);    

    memcpy(pKeyBlob->pb, pubKey, cbOut);
    return scp_err_Success;

}
