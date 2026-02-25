/*****************************************************************************
  Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
    ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
    THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.

Notes:
    This class defines utility classes like autopointers which are used by
    the EKM provider.


****************************************************************************/

#include "stdafx.h"
#include <crtdbg.h>
#include "Util.h"

// Helper function that put output in stdout and debug window
// in Visual Studio:
void dprintf( char * format, ...)
{
    static char buf[1024];
    va_list args;
    va_start( args, format );
    vsprintf_s( buf, format, args );
    va_end( args);
    OutputDebugStringA( buf);
    printf("%s", buf);
}

#define HEXBYTETOASCII(x) ((x) >= 0xA ? 'A' + (x) - 0xA : '0' + (x))

BYTE CharToByte(char c)
{
	if (c >= 'a' && c <= 'f')
	{
	    return c - 'a' + 0xA;
	}
	else if (c >= 'A' && c <= 'F')
	{
	   return c - 'A' + 0xA;
	}
	else if (c >= '0' && c <= '9')
	{
	    return c - '0';
	}
	else
	{
	    return 0;
	}
}

// Convert token to ASCII (non-Unicode String)
//
BOOL
FBytesToString(
	const BYTE* pbIn, 
    ULONG cbIn, 
    BYTE* pbOut, 
    ULONG& cbOut)
{
	// Allocate 2 chars for every byte to convert (e.g. 0xFF = 'F''F')
	// Account for '0x' and null terminator
	//
    ULONG cb = (cbIn * 2 + 3);
    cb *= sizeof(WCHAR);
    BYTE bInc = sizeof(WCHAR);


    if (pbOut == NULL)
    {
        cbOut = cb;
        return TRUE;
    }
    else if (cbOut < cb)
    {
        return FALSE;
    }

    ULONG i = 0;
    memset(pbOut, 0, cb);

    *(WCHAR *)(pbOut + i) = L'0'; i += bInc; 
    *(WCHAR *)(pbOut + i) = L'x'; i += bInc;

	// Check boundary conditions:
	// 1. We have not reached the end of the input byte stream
	// 2. Output byte stream has space (account for the null terminator, hence
	// 	the check for 2*bInc)
	//
    for (ULONG j = 0; i + (2*bInc) < cb && j < cbIn; i += 2 * bInc, j++)
    {
        *(WCHAR *)(pbOut + i) = (WCHAR)(HEXBYTETOASCII(pbIn[j] >> 4));
        *(WCHAR *)(pbOut + i + bInc) = (WCHAR)(HEXBYTETOASCII(pbIn[j] & 0xF));
    }

    *(WCHAR *)(pbOut + i) = 0;

    cbOut = cb - bInc;
    return TRUE;
}

#define ASCIITOHEXBYTE(x) ((x) >= 'a' ? (x) - 'a' + 0xA : (x) >= 'A' ? (x) - 'A' + 0xA : (x) - '0')

// Convert Unicode string to bytes
//
BOOL
FWStringToBytes(const WCHAR* wsIn, 
    ULONG cbIn, 
    __out_bcount(cbOut) BYTE* pbOut, 
    __inout ULONG& cbOut)
{
    if (cbIn < 2 * sizeof(WCHAR) || cbIn % (2 * sizeof(WCHAR)) != 0)
    {
        return FALSE;
    }

    ULONG cb = (cbIn  - 2 * sizeof(WCHAR)) / (2 * sizeof(WCHAR));

    if (pbOut == NULL)
    {
        cbOut = cb;
        return TRUE;
    }
    else if (cbOut < cb)
    {
        return FALSE;
    }

    ULONG i = 0;
    ULONG j = 0;
	for (i = 2, j = 0; i + 1 < cbIn/sizeof(WCHAR) && j < cb; i += 2, j++)
    {
        pbOut[j] = (ASCIITOHEXBYTE(wsIn[i]) << 4) | ASCIITOHEXBYTE(wsIn[i + 1]);
    }

    _ASSERT(j == cb);
    cbOut = cb;
    return TRUE;
}


BOOL
FEqStringIgnoreCase(const WCHAR * ws1,
    ULONG ce1,
    const WCHAR * ws2,
    ULONG ce2)
{
    return ((ce1 == ce2) && (_wcsnicmp(ws1, ws2, ce1) == 0));

}
