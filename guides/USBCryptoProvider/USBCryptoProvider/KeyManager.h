/*****************************************************************************
  Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

Notes:
   This class defines the following:
 1. XML tag strings which are used during parsing the XML configuration file

 2. CCryptoKey Class:
    This class represents a cryptographic key in the EKM provider. Since this
    implementation is based on CNG so it maintains a BCRYPT handle for key and 
    algorithm. It also contains other properties of the keys like flags, name,
    thumbprint and algorithm ID inside EKM. It provides methods for: key creation
    either from XML file or generating a new key and getters for key properties.
    This class is also responsible for serialization and de-serialization of the
    key material in files.

 3. CUser Class:
    This class abstracts a user inside EKM provider. There is no way to automatically
    add users in this EKM provider, add entries to XML file for to add users. It also 
    authenticates users against credentials configured in the XML file. It provides 
    interfaces (which are used by CKeyManager) for key creation, deleteion and enumeration.
    All keys are maintained in a synchronized list inside this class. It is upto the EKM to
    decide the synchronization scheme. This sample only highlights important synchronization 
    points without any consideration to performance. An actual implementation should handle 
    such situations more efficiently and according to their own requirements.

 4. CKeyManager Class:
    This class does bulk of the work in EKM provider from key management to parsing the XML file.
    XML file and directory paths are loaded from registry and then the file is parsed to get a list
    of users and keys. This class also maintains the XML configuration file and provides a serialized
    access to load and save changes. This sample implementation only shows some, but necessary not all,
    areas where the access to internal key and user store should be serialized. Implementation of an 
    actual EKM provider should base its synchronization scheme on its own specific requirements.


****************************************************************************/


#ifdef __KEYMANAGER_H
#else
#define __KEYMANAGER_H

#include <atlcoll.h>
#include "USBCryptoProvider.h"
#include "XmlLite.h"
#include "bcrypt.h"

// XML Tags used during parsing of XML file
//
#define TAG_USBCRYPTOPROVIDERS L"USBCRYPTOPROVIDER"
#define TAG_USERS			   L"USERS"

#define TAG_USER            L"USER"
#define CE_TAG_USER         4
#define ATTRIB_USER_NAME    L"NAME"
#define CE_ATTRIB_USER_NAME 4
#define ATTRIB_USER_PWD     L"PASSWORD"
#define CE_ATTRIB_USER_PWD  8

#define TAG_KEY             L"KEY"
#define CE_TAG_KEY          3
#define ATTRIB_KEY_THUMB	L"THUMB"
#define CE_ATTRIB_KEY_THUMB 5
#define ATTRIB_KEY_NAME		L"NAME"
#define CE_ATTRIB_KEY_NAME	4
#define ATTRIB_KEY_FLAGS	L"FLAGS"
#define CE_ATTRIB_KEY_FLAGS	5
#define ATTRIB_KEY_ALGID	L"ALGID"
#define CE_ATTRIB_KEY_ALGID 5
#define ATTRIB_KEY_PUBKEY	L"PUBKEY"
#define CE_ATTRIB_KEY_PUBKEY 6
#define ATTRIB_KEY_PVTKEY	L"PVTKEY"
#define CE_ATTRIB_KEY_PVTKEY 6

static const UUID UUID_NULL = {0, 0, 0, {0, 0, 0, 0, 0, 0, 0, 0 }};

typedef ULONG UserId;
static const ULONG x_UserIdBad = (UserId)-1;

// This class represents a cryptographic key and its properties
//
class CCryptoKey : public CRefManager
{
private:

	SqlCpKeyId				m_idKey;                // KeyID inside the provider
	CAutoP<WCHAR>			m_awsName;              // Key Name
	ULONG					m_cbName;               // byte count of name
	SqlCpAlgId				m_algid;                // Algorithm ID in EKM
	const SqlCpAlgorithmInfoUSB* m_pAlgInfo;        // Pointer to AlgInfo structure
	SqlCpKeyFlags			m_keyFlags;             // Flags set on the key
	GUID					m_thumb;                // Key thumbprint
	BOOLEAN					m_fInitialized:1;       // Initialization flag
    CAutoP<WCHAR>           m_awsPvtKeyPath;        // Path to key file
    UCHAR *                 m_pKeyMaterial;         // Pointer to key material (for symmetric keys)
    ULONG                   m_cbKeyMaterial;        // byte count of key material


	// CNG Crypto provider to perfrom key operation
	BCRYPT_ALG_HANDLE m_hCryptoProvider;

	// CNG Crypto key handle
	BCRYPT_KEY_HANDLE m_hKey;

	// Generate a new key
	SqlCpError GenerateKey();

	// Serialize the key into file
	SqlCpError SerializeKey();

public:
    // This constructor is called when a new key is generated from scratch
    //
	CCryptoKey() : m_idKey(x_scp_KeyIdBad), m_cbName(0), m_algid(x_scp_AlgIdBad), m_pAlgInfo(NULL),
					m_keyFlags(0), m_thumb(UUID_NULL), m_fInitialized(FALSE), 					
                    m_pKeyMaterial(NULL), m_cbKeyMaterial(0),
                    m_hCryptoProvider(0), m_hKey(0)
	{	}

    // This constuctor is called to initialize a key object from XML file
    //
    CCryptoKey(
                SqlCpKeyId keyid, 
                const WCHAR * wsName, 
                GUID  Thumb,
                SqlCpAlgId algId,
				const SqlCpAlgorithmInfoUSB * pAlgInfo,
                SqlCpKeyFlags keyFlags,                
                const WCHAR * pvtKeyPath);
                
                

	~CCryptoKey();

    // Property getters
    //
	inline SqlCpKeyId GetKeyId() 
	{
		return m_idKey;
	}
	inline GUID& GetThumb() 
	{
		return m_thumb;
	}
	inline CWStr GetName()
	{
		return CWStr(m_awsName, m_cbName);
	}
	inline SqlCpAlgId GetAlgId()
	{
		return m_algid;
	}
	inline SqlCpKeyFlags GetFlags()
	{
		return m_keyFlags;
	}

    // Populates a KeyInfo object with the properties of this key
	SqlCpError GetKeyInfo(__OUT SqlCpKeyInfo* pKeyInfo);

    // Initializes a key object by a creating a key with the given properties
	SqlCpError InitKey(const SqlCpStr* pKeyName, SqlCpAlgId algid, SqlCpKeyFlags keyFlags);

    // Initialize key from a file (when an existing key is opened)
	SqlCpError InitFromFile();

    // Serializes the key properties into XML file
	SqlCpError ToXml(CComPtr<IXmlWriter> &);

    // Encryption and Decryption methods
    //
    SqlCpError Encrypt (
						   __IN   BOOLEAN fFinal,
						   __IN const SqlCpEncryptionParam* pEncryptParams,
						   __IN   ULONG cEncryptParams,
						   __IN const SqlCpData* pPlaintext,
						   __OUT SqlCpData* pCiphertext);
    SqlCpError Decrypt (
                            __IN BOOLEAN fFinal,    
                            __IN const SqlCpEncryptionParam* pEncryptParams,
                            __IN ULONG cEncryptParams,    
                            __IN const SqlCpData* pDataCiphertext,
                            __OUT SqlCpData* pDataPlainText);

    // Export the public key blob of asymmetric key
    //
    SqlCpError Export ( 
                            __IN SqlCpKeyBlobType blobType,
                            __IN SqlCpData * pKeyBlob );

            

};

// Represents a User on the provider. User list is initialized by KeyManager from the XML file
// Add a user entry to create a new user on the EKM provider.
//
class CUser
{
	UserId m_idUser;            // UserID in EKM provider

	CAutoP<WCHAR> m_awsName;    // User Name
	ULONG m_cbName;             // byte count of user name

	CAutoP<WCHAR> m_awsPwdHash; // Password
	ULONG m_cbPwdHash;          // byte count of password

	// Used to synchronize access to the key store 
	CRITICAL_SECTION m_csKeyStore;

	// A list to store keys belonging to this user
	CAtlArray<CCryptoKey*> m_keyStore;

    // Get a key object by its name
	CCryptoKey* GetKeyByName (const SqlCpStr* pKeyName, BOOLEAN fNoLock = FALSE);

public:
	CUser() : m_idUser(x_UserIdBad), m_cbName(0), m_cbPwdHash(0)
	{
		InitializeCriticalSection(&m_csKeyStore);
	}
    
    // Ctor used to init a user object from XML file properties
    //
    CUser(UserId id, WCHAR * wsName, WCHAR * wsPwd)
    {
        // Note that the m_cb* members do not store the NULL character
        // This is because SQL does not send NULL terminated strings.
        //
        m_idUser = id;
        m_cbName = wcslen(wsName) * sizeof (WCHAR);
        m_cbPwdHash = wcslen(wsPwd) * sizeof (WCHAR);

        m_awsName = (WCHAR *)new BYTE[m_cbName + sizeof(WCHAR)];
        m_awsPwdHash = (WCHAR *)new BYTE[m_cbPwdHash + sizeof(WCHAR)];

        memcpy(m_awsName, wsName, m_cbName + sizeof(WCHAR));
        memcpy(m_awsPwdHash, wsPwd, m_cbPwdHash + sizeof (WCHAR));

        InitializeCriticalSection(&m_csKeyStore);
    }

	~CUser();

    // Property getters
    //
	inline CWStr GetName()
	{
		return CWStr(m_awsName, m_cbName);
	}
	inline CWStr GetPwd()
	{
		return CWStr(m_awsPwdHash, m_cbPwdHash);
	}

	inline UserId GetUserId()
	{
		_ASSERT(m_idUser != x_UserIdBad);
		return m_idUser;
	}

    // Authenticate a user based on its password from XML file
	BOOLEAN FAuthenticate(CWStr& pwd);

    // Create a key for this user and it to its store
	SqlCpError CreateKey (const SqlCpStr* pKeyName,      
						   SqlCpAlgId algid,
						   SqlCpKeyFlags keyFlags,
						   __OUT SqlCpKeyThumbprint* pKeyThumb);

    // Remove a key from this user's store
	SqlCpError DeleteKey (const SqlCpKeyThumbprint* pKeyThumb);

    // Add a key to user store
    SqlCpError AddKeyToStore(CCryptoKey * pKey);

    // Key enumerator - for enumerating all keys of this user
	CCryptoKey* GetNextKey (SqlCpKeyId idKey);

    // Key lookup methods based on different properties
	CCryptoKey* GetKeyById (SqlCpKeyId idKey);
	CCryptoKey* GetKeyByThumb (const SqlCpKeyThumbprint* pKeyThumb);
	SqlCpError GetKeyInfoByName (const SqlCpStr* pKeyName, __OUT SqlCpKeyInfo* pKeyInfo);
	SqlCpError GetKeyInfoByThumb (const SqlCpKeyThumbprint* pKeyThumb, __OUT SqlCpKeyInfo* pKeyInfo);

    // Serialize this users's attributes to XML
	SqlCpError  ToXml(CComPtr<IXmlWriter> &);
};

typedef CAtlArray<CUser*> Users;

// Manages the users present on the EKM provider and also provides manageability functions
// to serialize and de-serialize provider state into XML file.
//
class CKeyManager
{
	static CKeyManager* m_pKeyManager;  // Singleton pointer

	// Used to synchronize reads and writes to XML file
	CRITICAL_SECTION m_csXmlLoadSave;

	// User store - list of users present on the EKM provider (read from XML file)
	Users m_userStore; 

    // XML File path
	CAutoP<WCHAR>  m_awsFile;

    // Key directory path
    CAutoP<WCHAR>  m_awsDirectoryPath;

    // Flag signaling that the file has been loaded or not
	BOOLEAN m_fLoadedFromXml;

    // Current key and user ids. Next IDs are generated by incrementing them
	SqlCpKeyId	m_idKeyCurr;
	ULONG	m_idUserCurr;

	CKeyManager() : 
            m_fLoadedFromXml(FALSE), 
			m_idKeyCurr(x_scp_AlgIdBad), m_idUserCurr(0)
	{
		InitializeCriticalSection(&m_csXmlLoadSave);		
	}

    // Dtor - destroys all users and finally the list 
    // Also destroys the critical section
	~CKeyManager()
	{
		for (ULONG i = 0; i< m_userStore.GetCount();i++)
		{
			delete m_userStore.GetAt(i);
		}
		m_userStore.RemoveAll();

		DeleteCriticalSection(&m_csXmlLoadSave);
	}	
	CWStr* ToXml();

    // Initialize file paths from registry
    void LoadFilePathFromRegistry();
		
public: 
	// not thread safe
	static void Initialize()
	{
		_ASSERT(!m_pKeyManager);
		m_pKeyManager = new CKeyManager();
	}

	// not thread safe
	static void Cleanup()
	{
		_ASSERT(m_pKeyManager);
		delete m_pKeyManager;
		m_pKeyManager = NULL;
	}

    // Accessor to key manager singleton object
	static CKeyManager* Get() 
	{
		_ASSERT(m_pKeyManager);
		return m_pKeyManager;
	}

    // Loads users and keys from XML file
	SqlCpError LoadFromXmlFile();

    // Save users and keys to XML file
	SqlCpError SaveToXmlFile();

    // User lookup methods
	CUser* GetUserByName(CWStr& name);
	CUser* GetUserById(UserId idUser);

    // returns Alg Info based for an algid
	static const SqlCpAlgorithmInfoUSB* GetAlgInfoByAlgId(SqlCpAlgId algId);

    // Key and User ID generation methods.
	inline SqlCpKeyId GenerateKeyId()
	{
		return (SqlCpKeyId)InterlockedIncrement((LONG*)&m_idKeyCurr);
	}
	inline UserId GenerateUserId()
	{
		return (UserId)InterlockedIncrement((LONG*)&m_idUserCurr);
	}

    // returns the directory path configured for this user.
    inline const WCHAR * GetDirectoryPath()
    {
        _ASSERT(m_awsDirectoryPath);
        return m_awsDirectoryPath;
    }
};
#endif // __KEYMANAGER_H
