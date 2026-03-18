Extensible Key Management Development Guide

Author: Zubair Mughal

Version: 1.1

Last Updated: 2/24/2026


Microsoft Confidential. © 2011 Microsoft Corporation. All rights reserved. These materials are confidential to and maintained as a trade secret by Microsoft Corporation. Information in these materials is restricted to Microsoft authorized recipients only. Any use, distribution or public discussion of, and any feedback to, these materials is subject to the terms of the attached license. By providing any feedback on these materials to Microsoft, you agree to the terms of that license.




Microsoft Corporation Technical Documentation License Agreement (Standard)
READ THIS! THIS IS A LEGAL AGREEMENT BETWEEN MICROSOFT CORPORATION ("MICROSOFT") AND THE RECIPIENT OF THESE MATERIALS, WHETHER AN INDIVIDUAL OR AN ENTITY ("YOU"). IF YOU HAVE ACCESSED THIS AGREEMENT IN THE PROCESS OF DOWNLOADING MATERIALS ("MATERIALS") FROM A MICROSOFT WEB SITE, BY CLICKING "I ACCEPT", DOWNLOADING, USING OR PROVIDING FEEDBACK ON THE MATERIALS, YOU AGREE TO THESE TERMS. IF THIS AGREEMENT IS ATTACHED TO MATERIALS, BY ACCESSING, USING OR PROVIDING FEEDBACK ON THE ATTACHED MATERIALS, YOU AGREE TO THESE TERMS.

1. For good and valuable consideration, the receipt and sufficiency of which are acknowledged, You and Microsoft agree as follows:

(a) If You are an authorized representative of the corporation or other entity designated below ("Company"), and such Company has executed a Microsoft Corporation Non-Disclosure Agreement that is not limited to a specific subject matter or event ("Microsoft NDA"), You represent that You have authority to act on behalf of Company and agree that the Confidential Information, as defined in the Microsoft NDA, is subject to the terms and conditions of the Microsoft NDA and that Company will treat the Confidential Information accordingly;

(b) If You are an individual, and have executed a Microsoft NDA, You agree that the Confidential Information, as defined in the Microsoft NDA, is subject to the terms and conditions of the Microsoft NDA and that You will treat the Confidential Information accordingly; or

(c)If a Microsoft NDA has not been executed, You (if You are an individual), or Company (if You are an authorized representative of Company), as applicable, agrees: (a) to refrain from disclosing or distributing the Confidential Information to any third party for five (5) years from the date of disclosure of the Confidential Information by Microsoft to Company/You; (b) to refrain from reproducing or summarizing the Confidential Information; and (c) to take reasonable security precautions, at least as great as the precautions it takes to protect its own confidential information, but no less than reasonable care, to keep confidential the Confidential Information. You/Company, however, may disclose Confidential Information in accordance with a judicial or other governmental order, provided You/Company either (i) gives Microsoft reasonable notice prior to such disclosure and to allow Microsoft a reasonable opportunity to seek a protective order or equivalent, or (ii) obtains written assurance from the applicable judicial or governmental entity that it will afford the Confidential Information the highest level of protection afforded under applicable law or regulation. Confidential Information shall not include any information, however designated, that: (i) is or subsequently becomes publicly available without Your/Company’s breach of any obligation owed to Microsoft; (ii) became known to You/Company prior to Microsoft’s disclosure of such information to You/Company pursuant to the terms of this Agreement; (iii) became known to You/Company from a source other than Microsoft other than by the breach of an obligation of confidentiality owed to Microsoft; or (iv) is independently developed by You/Company. For purposes of this paragraph, "Confidential Information" means nonpublic information that Microsoft designates as being confidential or which, under the circumstances surrounding disclosure ought to be treated as confidential by Recipient. "Confidential Information" includes, without limitation, information in tangible or intangible form relating to and/or including released or unreleased Microsoft software or hardware products, the marketing or promotion of any Microsoft product, Microsoft's business policies or practices, and information received from others that Microsoft is obligated to treat as confidential. 

2. You may review these Materials only (a) as a reference to assist You in planning and designing Your product, service or technology ("Product") to interface with a Microsoft Product as described in these Materials; and (b) to provide feedback on these Materials to Microsoft. All other rights are retained by Microsoft; this agreement does not give You rights under any Microsoft patents. You may not (i) duplicate any part of these Materials, (ii) remove this agreement or any notices from these Materials, or (iii) give any part of these Materials, or assign or otherwise provide Your rights under this agreement, to anyone else.

3. These Materials may contain preliminary information or inaccuracies, and may not correctly represent any associated Microsoft Product as commercially released. All Materials are provided entirely "AS IS." To the extent permitted by law, MICROSOFT MAKES NO WARRANTY OF ANY KIND, DISCLAIMS ALL EXPRESS, IMPLIED AND STATUTORY WARRANTIES, AND ASSUMES NO LIABILITY TO YOU FOR ANY DAMAGES OF ANY TYPE IN CONNECTION WITH THESE MATERIALS OR ANY INTELLECTUAL PROPERTY IN THEM.

4. If You are an entity and (a) merge into another entity or (b) a controlling ownership interest in You changes, Your right to use these Materials automatically terminates and You must destroy them.

5. You have no obligation to give Microsoft any suggestions, comments or other feedback ("Feedback") relating to these Materials. However, any Feedback you voluntarily provide may be used in Microsoft Products and related specifications or other documentation (collectively, "Microsoft Offerings") which in turn may be relied upon by other third parties to develop their own Products. Accordingly, if You do give Microsoft Feedback on any version of these Materials or the Microsoft Offerings to which they apply, You agree: (a) Microsoft may freely use, reproduce, license, distribute, and otherwise commercialize Your Feedback in any Microsoft Offering; (b) You also grant third parties, without charge, only those patent rights necessary to enable other Products to use or interface with any specific parts of a Microsoft Product that incorporate Your Feedback; and (c) You will not give Microsoft any Feedback (i) that You have reason to believe is subject to any patent, copyright or other intellectual property claim or right of any third party; or (ii) subject to license terms which seek to require any Microsoft Offering incorporating or derived from such Feedback, or other Microsoft intellectual property, to be licensed to or otherwise shared with any third party.

6. Microsoft has no obligation to maintain confidentiality of any Microsoft Offering, but otherwise the confidentiality of Your Feedback, including Your identity as the source of such Feedback, is governed by Your NDA.

7. This agreement is governed by the laws of the State of Washington. Any dispute involving it must be brought in the federal or state superior courts located in King County, Washington, and You waive any defenses allowing the dispute to be litigated elsewhere. If there is litigation, the losing party must pay the other party’s reasonable attorneys’ fees, costs and other expenses. If any part of this agreement is unenforceable, it will be considered modified to the extent necessary to make it enforceable, and the remainder shall continue in effect. This agreement is the entire agreement between You and Microsoft concerning these Materials; it may be changed only by a written document signed by both You and Microsoft.




# Summary:

SQL Server provides cryptographic features like encryption, module signing etc. to offer data protection and privacy. However meeting the database compliance requirements are sometimes not possible by only using database encryption management tools. Hardware vendors provide products that address enterprise key management by using Hardware Security Modules (HSM). HSM devices store encryption keys on hardware or software modules offering a more secure solution because the encryption keys do not reside with encryption data.

The SQL Server 2008 Extensible Key Management enables third-party EKM/HSM vendors to register their modules in SQL Server. When registered, SQL Server can communicate with the module using a pre-defined interface to access the encryption keys stored on EKM modules. This enables SQL Server to access the advanced encryption features these modules support such as bulk encryption and decryption, and key management functions such as key aging and key rotation.

This document will explain the standard interface in version 1 of the API which has to be implemented to write an EKM provider. For details about using and configuring EKM provider refer to: http://msdn.microsoft.com/en-us/library/bb895340(SQL.100).aspx

# Introduction:

SQL Server 2008 will allow third party EKM/HSM vendors to register their modules in SQL Server so that SQL users can create or open keys using the module. This will allow enterprises to use sophisticated key management solutions which meet their compliance or security requirements. Moreover, this provides a way to add crypto agility to SQL Server since the actual management and implementation of cryptographic algorithms can be done externally on the EKM module. EKM modules can also chose to enforce management policies like key rotation, aging etc. which are not present in SQL Server.

Extensible Key Management also provides the following benefits:

- Additional authorization check (enabling separation of duties).

- Higher performance for hardware-based encryption/decryption.

- External encryption key generation.

- External encryption key storage (physical separation of data and keys).

- Encryption key retrieval.

- External encryption key retention (enables encryption key rotation).

- Easier encryption key recovery.

- Manageable encryption key distribution.

- Secure encryption key disposal.


This document will walk through how SQL Server interacts with EKM modules, explaining the Authentication and Session models. This will be followed by a brief explanation of the APIs that define the interface which is used by SQL Server to communicate with EKM modules. A sample provider is also available with this document which shows a very basic and crude implementation of the APIs, it will be used as an example throughout this document.

# Configuring a provider:

Extensible Key Management is available only on the Enterprise, Developer, and Evaluation editions of SQL Server.

The provider module has to be compiled into a dynamically linked library (DLL) which is loaded inside SQL Server's process. This allows faster communication between the provider and SQL Server. Note that this module must be digitally signed by a signer which is trusted on the server, otherwise SQL Server will not load the provider.  By default EKM is off, following TSQL turns it on:

    sp_configure 'show advanced', 1

    GO

    RECONFIGURE

    GO

    sp_configure 'EKM provider enabled', 1

    GO

    RECONFIGURE

    GO


After enabling EKM the provider has to be created on Server:


    CREATE CRYPTOGRAPHIC PROVIDER USBProv

    FROM FILE = 'F:\USBProvider\USBCryptoProvider.dll'


This will check the digital signature on the provider and also see if all the required interfaces are exported by the provider and create a cryptographic provider object in metadata.

Once a Cryptographic provider is created in metadata the DLL is loaded and unloaded from memory by SQL Server as required. Each time it is loaded the aforementioned checks are done in addition to the supported version (explained later) of the provider.

# Authentication Model:

EKMs usually have their own authentication mechanisms to connect to their hardware or key management solutions, e.g. Smartcards use pins to control access. When a SQL Server user tries to connect to an EKM module there must be a way for SQL Server to authenticate this user on EKM. SQL Server supports two methods of authentication to handle this scenario, EKM module can chose to support any one model but not both.

## Basic Auth:

This is simple username and password authentication. A credential is created in SQL Server with a username and password and associated with a login. When a user tries to access a key on EKM which supports basic authentication then credentials associated with the user for that provider is queried and the username and password pair is sent to the EKM for authentication. If authentication fails at EKM then the user operation is denied.









## Other Auth:

In case the EKM has its own authentication model and doesn't require any support in SQL Server then this authentication model should be used. In this case SQL Server will not send any information to the provider and would try to establish a session. It will be up to the EKM provider to enforce any kind of authentication policies whatsoever. Currently there is no way for the provider to get the user's security token so it can use SQL Server's service account token to perform authentication.

# Session Model:

SQL Server uses sessions to communicate with the EKM provider. When a user tries to connect to EKM provider for the first time, SQL Server authenticates the user on the EKM provider based on the authentication model and in return the EKM provider returns a session object which is stored in SQL Server for the lifetime of user's operation. This session object is passed as a parameter to any subsequent calls to EKM provider which requires user context, e.g. key creation, encryption, key properties etc. EKM providers should internally manage these sessions and associate them with authenticated users.





# EKM Provider API (SqlCryptAPI version 1.0)


This section will walk through the semantics of each of the APIs that have to be implemented by an EKM provider.

All the interfaces and structures required are listed in the header file SqlCrypt.h, this must be included as is, without any modifications in the provider DLL. Before diving into the API it is worthwhile to look at some important structures and semantics.

## Error Codes:

Error codes are enumerated in SqlCpError, where first seven error codes are generic errors which can be used by the provider; error codes till 2048 are reserved by SQL Server and the provider should not use them, however values above 2048 can be used. It is highly recommended that providers should define granular error codes and document them for all their internal operations, so in case of any error the customers can look at the error codes returned by the provider and infer the root cause.

## SqlCpStr:

All strings used by the API are referenced by this structure.

typedef struct _SqlCpStr

{

ULONG   cb;        // Count in bytes

WCHAR*  ws;        // Pointer to Unicode string

} SqlCpStr;


The "ws" member is a pointer to Unicode string and does not have to be NULL-terminated. The "cb" member is count in 'bytes' of the string.


## Memory Management:

Any API that returns a variable length member like querying the name of a key should check if the supplied buffer is large enough to store the output value, if it isn't or it is NULL then it should return scp_err_InsufficientBuffer and populate the "cb" member with the required size in bytes. It should not try to allocate memory on behalf of the caller. Provider can use any suitable method for its own memory management.

Also note that it is not necessary that the provider DLL will be loaded once for the lifetime of SQL Server process. SQL Server can chose to load and unload the DLL on its own discretion.

## SqlCpProviderInfo:


typedef struct _SqlCpProviderInfo

{

SqlCpStr       name;               // Provider friendly name

SqlCpGuid      guid;               // Unique provider guid

SqlCpVersion   version;            // Provider DLL version

SqlCpVersion   scpVersion;        // SQL Crypto API version

SqlCpAuthType  authType;           // Supported authentication

SqlCpKeyFlags  symmKeySupport;     // Symmetric key support bitmask

SqlCpKeyFlags  asymmKeySupport;    // Asymmetric key support bitmask

ULONG          cbKeyThumbLen;  // Max length of a key thumbprint in bytes

BOOLEAN      fAcceptsKeyName;// if accepts external key name in CreateKey

} SqlCpProviderInfo;


This structure defines the provider properties and should not change for a specific provider version.  This structure is defined in the sample provider like this:

// Provider properties

//

const SqlCpProviderInfo x_providerInfo =

{

STR_AND_CBLEN(x_wszProvName),

{0x66871e70, 0x473a, 0x4da2, {0x9c, 0xe2, 0x4d, 0xb3, 0xf4, 0xbf, 0x84, 0x99}},		{1,0,0,0},				// USB Crypto Provider Version

{1,1,0,0},				// SqlCrypt Version

scp_auth_Basic,			// Authentication

(SqlCpKeyFlags)(scp_kf_Supported),	// Symmetric key support

(SqlCpKeyFlags)(scp_kf_Supported), 	// Asymmetric key support

sizeof(GUID),					// Thumbprint length in bytes

TRUE						// fAcceptKeyName

};



This provider supports V1 of Sql Crypt API and its own version is 1.1. It supports both symmetric and asymmetric key generation and the size of key thumbprint is 16 bytes as it uses GUIDs to uniquely identify keys.

Note that the SQL Crypto API version(SqlCpProviderInfo.scpVersion) should always be defined exactly like this for V1. Once the provider is created in SQL Server its version (provider DLL version  SqlCpProviderInfo.version) is checked each time it is loaded. If the version doesn't match the one that is stored in SQL Server then the DLL fails to load.

## SqlCpAlgorithmInfo:


// Algorithm info

typedef struct _SqlCpAlgorithmInfo

{

SqlCpAlgId          algId;           // Algorithm id

SqlCpStr            algTag;          // Algorithm tag, i.e. "RSA_1024"

SqlCpKeyType        type;            // Key type, i.e. symmetric, asymmetric

ULONG               bitLen;          // Key bitlength in bits

ULONG               ivLen;           // IV bitlength in bits

} SqlCpAlgorithmInfo;


This structure defines a supported algorithm by the provider. Internally provider can represent the algorithms by numeric algId, but the important thing to note here is algTag. This is a string value which is used by SQL Server to identify an algorithm. SQLCryptAPI uses string based algorithm tags to avoid any dependency on CAPI like integer algorithm IDs. In v1 of the API an EKM provider can implement only those algorithms which are supported by SQL Server, any key created with an unsupported algorithm on the EKM provider will not be available in SQL Server. SQL Server currently supports following algorithm tags:


For every supported algorithm the bit length should match the values in the above table and IV (Initialization Vector) length should be less than or equal to the above values.

Sample provider supports only two of the above listed algorithms:

// Supported algorithms

//

struct SqlCpAlgorithmInfoUSB

{

SqlCpAlgorithmInfo  _algInfo;

LPCWSTR             _cngAlgId;      // CNG algid

};


// Table of supported algorithms

//

const SqlCpAlgorithmInfoUSB x_AlgInfos[] =

{

{{1,	STR_AND_CBLEN(L"RSA_1024"),scp_kt_Asymmetric,	1024,	0}, BCRYPT_RSA_ALGORITHM},

{{2,	STR_AND_CBLEN(L"AES_128") , scp_kt_Symmetric,	128,	16},BCRYPT_AES_ALGORITHM},

};



## SqlCryptInitializeProvider

SqlCpError SqlCryptInitializeProvider ();


After the DLL is loaded into memory this method is called to Initialize the provider. This can be used to initialize any internal structures by the provider. Note that this method can be called multiple times in the lifetime of SQL Server process as it loads and unloads provider DLL on its own discretion.

Sample USB provider uses this method to check the OS to ensure it is at least Vista and also loads the key and user information from XML file. Other internal structures are initialized in DllMain() method.

## SqlCryptFreeProvider

    SqlCpError  SqlCryptFreeProvider ();

This method is called before the DLL is unloaded to provide an opportunity to EKM provider to cleanup its resources.

## SqlCryptOpenSession

SqlCpError	SqlCryptOpenSession(__IN const SqlCpCredential * pAuth,

__OUT SqlCpSession * pSess);


    Each time a user tries to connect to the provider for the first time SQL Server calls this method to open a session with the provider. Based on SqlCpProviderInfo.authType pAuth parameter would either represent a username and password pair or it would be NULL. SqlCpSession is defined as a void pointer so EKM provider can chose its own internal representation for the Session object. On return Session parameter is populated with a pointer a Session object created by the provider.

Sample provider uses a single integer for Session Id which uniquely identifies a session inside the provider.

## SqlCryptCloseSession

SqlCpError 	SqlCryptCloseSession (__IN SqlCpSession* pSess,

__IN BOOLEAN fAbort);


When SQL Server needs to close a session with the provider this method is called. EKM provider can free the Session object in this method.

## SqlCryptGetProviderInfo

SqlCpError 	SqlCryptGetProviderInfo (__OUT SqlCpProviderInfo* pProviderInfo);


Whenever SQL Server has to query provider information it calls this method. EKM provider receives a pointer to SqlCpProviderInfo structure and it should populate all fields accordingly. Follow the semantics described in 'Memory Management' section for variable sized members.

## SqlCryptGetNextAlgorithmId

SqlCpError SqlCryptGetNextAlgorithmId(__INOUT SqlCpAlgId* pAlgId);


This method is used to enumerate all the algorithms supported by the provider. The first call to this method will usually have contents of pAlgId set to x_scp_AlgIdBad and on return the provider will populate it with the first algorithm Id that it supports. This new value can be used in the next call to get the following algorithm Id and so on as long as the method returns scp_err_Success.

## SqlCryptGetAlgorithmInfo

SqlCpError 	SqlCryptGetAlgorithmInfo (__IN SqlCpAlgId algId,
                                       __OUT SqlCpAlgorithmInfo* pAlgorithmInfo);


For a given algorithm Id this method should populate the algorithm info structure. Follow the semantics described in 'Memory Management' section for variable sized members.

## SqlCryptCreateKey

SqlCpError SqlCryptCreateKey	(__IN const SqlCpSession* pSess,

__IN const SqlCpStr* pKeyName,

__IN SqlCpAlgId algid,

__IN SqlCpKeyFlags keyFlags,

__OUT SqlCpKeyThumbprint* pKeyThumb);


As mentioned earlier, once a session is established it is passed to the APIs which need an authenticated user context. EKM provider should infer the user and its properties based on the pSess parameter and perform any necessary policy or authorization checks. This method is used to create a new key on the provider with a given name; this should not be confused with the name of the key on SQL Server. Inside SQL Server the key will have a object name with which it can be referenced, while pKeyName is the name which the provider uses to identify a key internally. Key flags represent any optional parameters that SQL Server wants to set on the key, all of them are defined under SqlCpKeyFlags enumeration. On success this method should populate the pKeyThumb structure with the thumbprint of the newly generated key.

Currently v1 does not support generating key names on the provider, however this support is present in T-SQL where the user can chose not to specify a key name to refer the key on a provider.

Sample USB provider creates the key based on the specified algorithm using CNG and then persists the key material and its attributes in the key directory and the XML file respectively.

Note that there are two ways that a user can create a key in SQL Server which refers to a key in EKM provider.

1. Create new key

Following T-SQL statement can be used to create a new key:


create symmetric key myEKM_Key

from provider USBProv

with

algorithm = AES_128,

PROVIDER_KEY_NAME = 'New EKM Key2',

CREATION_DISPOSITION = CREATE_NEW

Go


This statement will result in a call to SqlCryptCreateKey method with key name as 'New EKM key2' and algorithm Id set corresponding to algorithm tag of 'AES_128'. Similarly an asymmetric key can be created on the provider.

2. Open existing key:

If a key already exists on an EKM and the user wants to create a key in SQL Server corresponding to that key then it can do so using the following T-SQL

create symmetric key myEKM_Key

from provider USBProv

with

PROVIDER_KEY_NAME = 'New EKM Key2',

CREATION_DISPOSITION = OPEN_EXISTING

Go


In this case SqlCryptCreateKey will not be called instead SQL Server will query key properties to ensure that such a key exists with supported values and then create the key inside SQL Server.

## SqlCryptDropKey

SqlCpError 	SqlCryptDropKey (__IN const SqlCpSession* pSess,

__IN const SqlCpKeyThumbprint* pKeyThumb);


This method is called when a user executes a 'DROP KEY' statement. The session object can be used to identify an authenticated user session and the thumbprint uniquely identifies the key that should be dropped.

## SqlCryptGetNextKeyId

SqlCpError 	SqlCryptGetNextKeyId (__IN const SqlCpSession* pSess,

__INOUT SqlCpKeyId* pKeyId);


This enumerator is very similar to GetNextAlgorithmId, however a session is object is also passed to the provider so that it can verify an authenticated session and user and return only the keys associated to that user.

## SqlCryptGetKeyInfoByKeyId, SqlCryptGetKeyInfoByThumb & SqlCryptGetKeyInfoByName

SqlCpError	SqlCryptGetKeyInfoByKeyId (__IN const SqlCpSession* pSess,

__IN  SqlCpKeyId keyId,

__OUT SqlCpKeyInfo* pKeyInfo);


SqlCpError 	SqlCryptGetKeyInfoByThumb (__IN const SqlCpSession* pSess,

__IN const SqlCpKeyThumbprint* pKeyThumb,

__OUT SqlCpKeyInfo* pKeyInfo);


SqlCpError 	SqlCryptGetKeyInfoByName (__IN const SqlCpSession* pSess,

__IN  const SqlCpStr* pKeyName,

__OUT SqlCpKeyInfo* pKeyInfo);


The above three methods are used to query KeyInfo based on the keyId, thumbprint and name respectively. If a matching key is found on the provider, it should populate the pKeyInfo structure with appropriate values. Follow the semantics described in 'Memory Management' section for variable sized members.

## SqlCryptExportKey

SqlCpError SqlCryptExportKey (__IN const SqlCpSession* pSess,

__IN const SqlCpKeyThumbprint* pKeyThumb,

__IN const SqlCpKeyThumbprint* keyEncryptorThumb,

__IN SqlCpKeyBlobType blobType,

__OUT SqlCpKeyBlob* pKeyBlob);


SQL Server calls this method to export the key inside SQL Server. Currently this method is only called to export public key portions of asymmetric keys; it is not called for symmetric keys. Note that the scp_kf_exportable flag specifies if the private key material of asymmetric key and key material for symmetric key is exportable. So even if the asymmetric key is not marked as exportable the public key portion should always be exportable. Follow the semantics described in 'Memory Management' section for variable sized members.

Look at the implementation of this method in USB provider for exact details.

## SqlCryptImportKey

SqlCpError SqlCryptImportKey (__IN const SqlCpSession* pSess,

__IN const SqlCpStr* pKeyName,

__IN const SqlCpKeyThumbprint* keyDecryptorThumb,

__IN SqlCpKeyBlobType blobType,

__IN SqlCpKeyFlags keyFlags,

__IN const SqlCpKeyBlob* pKeyBlob);


This method is not currently used and it should return an error.

## SqlCryptEncrypt

SqlCpError SqlCryptEncrypt  ( __IN const SqlCpSession* pSess,

__IN const SqlCpKeyThumbprint* pKeyThumb,

__IN BOOLEAN fFinal,

__IN const SqlCpEncryptionParam* pEncryptParams,

__IN ULONG cEncryptParams,

__IN const SqlCpData* pDataPlainText,

__OUT SqlCpData* pDataCiphertext);


This method is used to encrypt data on the EKM provider. Session and thumbprint can be used to infer the user and they key that is used for encryption. fFinal parameter specifies whether it is the final block or not and is currently always true. There is only one encryption parameter defined currently and it is Initialization vector. Plain text blob contains plain text and Cipher text blob should be populated with the encrypted data on success. Follow the semantics described in 'Memory Management' section for variable sized members.

## SqlCryptDecrypt

SqlCpError 	SqlCryptDecrypt (__IN const SqlCpSession* pSess,

__IN const SqlCpKeyThumbprint* pKeyThumb,

__IN BOOLEAN fFinal,

__IN const SqlCpEncryptionParam* pEncryptParams,

__IN ULONG cEncryptParams,

__IN const SqlCpData* pDataCiphertext,

__OUT SqlCpData* pDataPlainText);


This method is the inverse of SqlCryptEncrypt and has similar semantics.


# Appendix A: Sample USB Provider


THIS SAMPLE CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.

To better illustrate different concepts mentioned in this document there is a sample provider available for download. This provider, called USBCryptoProvider (or USBProvider) offers a very basic implementation of the required interfaces. It supports basic_auth and performs basic key creation, deletion, encryption and decryption mechanisms. It uses CNG for its cryptographic operations and therefore it only works on Vista and beyond.

All the keys that are created are persisted in files, the path to this directory can be configured via registry. User and key information is persisted in a XML file which is read at startup and written to disk whenever a state change happens. In order to create a new user create a XML node like this:

<USER NAME="user1" PASSWORD="p@$$word">

Path of the key directory and XML file can be configured via the following registry entries:




Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\USBCryptoProvider]

"KeyFolderPath"="C:\USBProviderKeys\"

"XMLFilePath"="C:\USBProviderKeys\USBProvider.xml"


Note that this provider is not production quality and it should just be used as a reference to understand the semantics of the APIs and session and authentication models. This should not be used for as a baseline for development or performance analysis.

# Appendix B: Useful tests to run against EKM provider


EKM provider is loaded inside SQL Server so it should be thoroughly tested before handing over to customers. Following is a list of some basic scenarios that should be tested (preferably stress tested):

- Key creation

- Key deletion

- Symmetric and asymmetric key encryption decryption

- Cryptographic provider views

- sys.cryptographic_providers

- sys.dm_cryptographic_provider_properties

- sys.dm_cryptographic_provider_sessions

- sys.dm_cryptographic_provider_algorithms

- sys.dm_cryptographic_provider_keys



- Transparent Database Encryption (TDE) with EKM

- Synchronization issues:

- Multiple sessions opened by same user

- Same key referenced in multiple sessions

- Same key used for cryptographic operations simultaneously

- Application verifier testing.


There is no baseline provided by Microsoft as baseline for performance testing of EKM devices. However EKM operations should not be significantly slower than SQL Server encryption/decryption.


# Appendix C: Transparent Database Encryption


EKM can be used with TDE for additional security of data at rest. When TDE is enabled a Database encryption key (DEK) is created inside SQL Server which is protected by an asymmetric key or certificate. This DEK is used to encrypt and decrypt database pages as the written to and read from the disk. An asymmetric key residing on EKM provider can be used to encrypt the DEK, this add more comprehensive key management to database encryption. It is important to understand that EKM provider will not be used to encrypt and decrypt the data pages, instead it will only be used to encrypt and decrypt the DEK.

Securing a DEK with a key on EKM provides better key management as both the keys are residing separately. Moreover, the database cannot be restored without the encryptor; i.e. if the DEK is encrypted by a certificate then to restore the database on another server which does not have that certificate is not possible, this is why certificates protecting DEKs should always be backed up to avoid loss of data in case the certificate is not available on the server. This adds management overhead and a need to secure the certificate's backup as it also contains the private key. EKM can be used to mitigate this problem since the key will always be present outside SQL Server in a secure environment (provider by EKM). In order to restore the database on another machine the same key can be created (using OPEN_EXISTING disposition) inside SQL Server on this machine; when the database will be restored the encrypting key will be identified based on its thumbprint and used to decrypt the DEK and thus restore the database.

# Appendix D: Using Events to trace calls to EKM APIs

SQL Server 2008 offers an event tracing mechanism. To provide better debugging and diagnosis support every time an EKM API is called it is logged using this tracing infrastructure. For Each call the event will have the following information:

- SqlCpError value which was returned by the API.

- EKM provider name or DLL path (in case the provider name is not available)

- Name of the API that was called

The event name is: sqlserver.sec_ekm_provider_called
The following script will create and start an event session and post the events to ring buffer:

create event session testsession1 on server

add event sqlserver.sec_ekm_provider_called

add target package0.ring_buffer ( set max_memory=1, occurrence_number=1)

with (MAX_DISPATCH_LATENCY=1 seconds)

go


alter event session testsession1 on server state=start


View the contents of event data by querying the last column of sysdm_xe_session_targets. There is a default ring buffer always present so you can query this view before starting the event session and after it and note the event_session_address of the new ring buffer. Just copy past the XML from the last column of the ring buffer into a text file to view the contents. This is a sample event data where a call to SqlCryptGetKeyInfoByName to "SQL Server USB Cryptographic Provider" returned "4":

    <RingBufferTarget eventsPerSec="0" processingTime="0" totalEventsProcessed="1" eventCount="1" droppedCount="0" memoryUsed="248">


    <event name="sec_ekm_provider_called" package="sqlserver" id="115" version="1" timestamp="2008-	07-02T20:22:01.984Z">

    <data name="cred_prov_result">

    <type name="int32" package="package0"></type>

    <value>4</value>

    <text></text>

    </data>

    <data name="cred_prov_name">

    <type name="unicode_string" package="package0"></type>

    <value><![CDATA[SQL Server USB Cryptographic Provider]]></value>

    <text></text>

    </data>

    <data name="cred_prov_api">

    <type name="unicode_string" package="package0"></type>

    <value><![CDATA[SqlCryptGetKeyInfoByName]]></value>

    <text></text>

    </data>

    </event>

    </RingBufferTarget>


Refer to MSDN documentation regarding events on how to configure and use events

| DATE | MODIFIED BY | CHANGE DESCRIPTION |
| --- | --- | --- |
| 11/8/2008 | Ilsung | Initial drop with legal notices |
| 04/08/2009 | Ilsung | Corrected AES algorithm tag names in table. |
| 04/13/2011 | Ilsung | Updated Technical Document Agreement verbage |
|  |  |  |
|  |  |  |
|  |  |  |
|  |  |  |

| Algorithm Tag (AlgTag) | Bit Length | IV length | Description |
| --- | --- | --- | --- |
| RC2 | 128 | 64 | RC2 Symmetric key algorithm |
| RC4 | 40 | 64 | RC4 Symmetric key algorithm |
| RC4_128 | 128 | 64 | RC4 128 bit Symmetric key algorithm |
| DES | 64 | 64 | DES Symmetric key algorithm |
| TRIPLE_DES | 128 | 64 | Triple DES Symmetric key algorithm |
| DESX | 192 | 64 | DESX Symmetric key algorithm |
| TRIPLE_DES_3KEY | 192 | 64 | Triple DES 3 key Symmetric key algorithm |
| AES_128 | 128 | 128 | AES 128 bit Symmetric key algorithm |
| AES_192 | 192 | 128 | AES 192 bit Symmetric key algorithm |
| AES_256 | 256 | 128 | AES 256 bit Symmetric key algorithm |
| RSA_512 | 512 | N/A | RSA 512 bit Asymmetric key algorithm |
| RSA_1024 | 1024 | N/A | RSA 1024 bit Asymmetric key algorithm |
| RSA_2048 | 2048 | N/A | RSA 2048 bit Asymmetric key algorithm |
