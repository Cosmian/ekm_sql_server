/*****************************************************************************
  Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

Notes:
    This file declares global constants used by crypto provider. e.g:
    - Provider Name
    - EKM Provider specific error codes 
    - Provider Info structure
    - Algorithm Info and its mapping to CNG algorithms
    - Secret used to generate symmetric keys
    - Registry key path which points to configuration information


****************************************************************************/


#ifdef __USBCRYPTOPROVIDER_H
#else
#define __USBCRYPTOPROVIDER_H

#include <wincrypt.h>
#include "sqlcrypt.h"

// Provider name used in the provider descriptor
//
const WCHAR x_wszProvName[] = L"SQL Server USB Cryptographic Provider";

#define STR_AND_CBLEN(x) {(ULONG)wcslen(x)*sizeof(WCHAR), (WCHAR*)(x)}

// Provider specific errors
//
class SqlCpErrorUSB
{
	int m_err;
	const WCHAR* m_wsz;
public:
	SqlCpErrorUSB(int err, const WCHAR* wsz = NULL) : 
			m_err(err), m_wsz(wsz){}
	inline operator SqlCpError() const
	{
		return (SqlCpError)m_err;
	}
	inline operator WCHAR*() const
	{
		return (WCHAR*)m_wsz;
	}
};

// ISV specific error codes must be larger than 2048
//
static const SqlCpErrorUSB scp_err_CantAcquireDOMCOM					(2050, L"Cannot acquire DOM COM");
static const SqlCpErrorUSB scp_err_CantLoadDOMCOM						(2051, L"Cannot load DOM COM");
static const SqlCpErrorUSB scp_err_KeyContainerParseError				(2052, L"Key container parse error");
static const SqlCpErrorUSB scp_err_KeyContainerGetXmlError				(2053, L"Key container get_xml error");
static const SqlCpErrorUSB scp_err_KeyContainerCantFindUsers			(2054, L"Invalid users in key container");
static const SqlCpErrorUSB scp_err_KeyContainerBadUserAttrs				(2055, L"Invalid user attributes");
static const SqlCpErrorUSB scp_err_KeyContainerBadUserName				(2056, L"Invalid user name");
static const SqlCpErrorUSB scp_err_KeyContainerBadUserPwd				(2057, L"Invalid user pwd");
static const SqlCpErrorUSB scp_err_KeyWithNameExists					(2058, L"Key with this name already exists");
static const SqlCpErrorUSB scp_err_CantLoadXml							(2059, L"Cannot load Xml string");
static const SqlCpErrorUSB scp_err_KeyContainerBadKeyAttrs				(2060, L"Invalid key attributes");
static const SqlCpErrorUSB scp_err_KeyContainerBadKeyName				(2061, L"Invalid key name");
static const SqlCpErrorUSB scp_err_KeyContainerInvalidThumbLen			(2062, L"Invalid thumb length");
static const SqlCpErrorUSB scp_err_CantAcquireCAPIProvider				(2063, L"Cannot acquire MSCAPI  provider");
static const SqlCpErrorUSB scp_err_CantGenerateCryptoKey				(2064, L"Cannot generate cryptographic key");
static const SqlCpErrorUSB scp_err_CantExportKey						(2065, L"Cannot export key");
static const SqlCpErrorUSB scp_err_CantEncryptData                      (2066, L"Cannot encrypt data");

// Provider Info structure definition
// NOTE: For SQL Server 2008 the last member (fAcceptKeyName) should always be true. 
//
const SqlCpProviderInfo x_providerInfo =
    {
    STR_AND_CBLEN(x_wszProvName),													// name
	{0x66871e70, 0x473a, 0x4da2, {0x9c, 0xe2, 0x4d, 0xb3, 0xf4, 0xbf, 0x84, 0x99}},	// guid
	{1,0,0,0},																	// USB Crypto Provider Version    
	{1,1,0,0},																	// SqlCrypt Version
	scp_auth_Basic,																// Authentication
	(SqlCpKeyFlags)(scp_kf_Supported),											// Symmetric key support    
	(SqlCpKeyFlags)(scp_kf_Supported),                                          // Asymmetric key support    
    sizeof(GUID),																// Thumbprint length in bytes
    TRUE																		// fAcceptKeyName - should always be TRUED for SQL Server 2008
   };

// Supported algorithms
//
struct SqlCpAlgorithmInfoUSB
{
	SqlCpAlgorithmInfo _algInfo;
    LPCWSTR             _cngAlgId;      // CNG algid
};

// Table of supported algorithms:
//
// NOTE: Internally the provider can use any ALG_ID it wants to represent different algorithms. Each ALG_ID is associated with an ALG_TAG and other algorithm
// properties. In SQl Server 2008 there is a restriction over ALG_TAG; EKM Providers cannot use any other ALG_TAG besides the ones supported by SQL Server 2008. 
// Any key created or opened on EKM provider with an unsupported ALG_TAG will not be accepted by SQL Server and the user operation will fail.
//
const SqlCpAlgorithmInfoUSB x_AlgInfos[] =
	{
		{{1,		STR_AND_CBLEN(L"RSA_1024"),	    scp_kt_Asymmetric,	1024,	0},  BCRYPT_RSA_ALGORITHM},
		{{2,		STR_AND_CBLEN(L"AES_128"),		scp_kt_Symmetric,	128,	16}, BCRYPT_AES_ALGORITHM},
	};

const ULONG x_cAlgInfos = sizeof(x_AlgInfos)/sizeof(x_AlgInfos[0]);

// Secret used to generate symmetric keys
//
const UCHAR x_pbKeySecret[] =	{
									0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
									0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
								};
const ULONG x_cbKeySecret   = sizeof(x_pbKeySecret);


// Default paths for XML file and key directory
//
const WCHAR x_wszXMLDefaultFileName[] = L"F:\\scratch\\USBProviderKeys\\USBProvider.xml";
const WCHAR x_wszKeyDirectoryPath[] = L"F:\\scratch\\USBProviderKeys\\";

// Location of Registry keys and values pointing to configuration information
//
const WCHAR x_wszXMLFileName[]  = L"USBProvider.xml";
const WCHAR x_wszRegKeyPath[] = L"Software\\USBCryptoProvider";
const WCHAR x_wszRegValueName[] = L"KeyFolderPath";
const WCHAR x_wszRegXmlValueName[] = L"XMLFilePath";


#endif // __USBCRYPTOPROVIDER_H
