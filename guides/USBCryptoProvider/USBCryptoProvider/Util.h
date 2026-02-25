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
#ifdef __UTIL_H
#else
#define __UTIL_H
#include <stdio.h> 
#include <atlbase.h>
#include <atlcoll.h>

// This file contains utility classes and methods which are used by other pieces for code
// 

class CWStr
{
	WCHAR* m_ws;
	ULONG m_cb;
	BOOLEAN m_fOwn;
public:
	inline CWStr(WCHAR* ws = NULL, ULONG cb = 0, BOOLEAN fOwn = FALSE) : 
					m_ws(ws), m_cb(cb), m_fOwn(fOwn) {}
	inline ~CWStr() 
	{
		if (m_fOwn)
		{
			delete m_ws;
		}
	}
	inline WCHAR* Ws() const
	{
		return m_ws;
	}

	inline ULONG Cb() const
	{
		return m_cb;
	}
};

class CAutoCriticalSection 
{
public:
	CAutoCriticalSection(CRITICAL_SECTION* pSection) : m_fTaken(FALSE), m_pSection(pSection)
	{
		_ASSERT(m_pSection);
	}
	~CAutoCriticalSection()
	{
		Leave();
	}
	void Enter()
	{
		_ASSERT(!m_fTaken);
		EnterCriticalSection(m_pSection);
		m_fTaken = TRUE;
	}

	void Leave()
	{
		if (m_fTaken)
		{
			LeaveCriticalSection(m_pSection);
			m_pSection = NULL;
			m_fTaken = FALSE;
		}
	}
private:
	CRITICAL_SECTION* m_pSection;
	BOOL m_fTaken;
};

template <class T>class CAutoP
{
	T* m_p;

public:
	CAutoP(T* p = NULL) : m_p(p) {}
	~CAutoP()
	{
		if (m_p)
		{
			delete m_p;
		}
	}
	void operator=(T* p)
	{
		if (m_p)
		{
			delete m_p;
		}
		m_p = p;
	}
	inline operator T* (void) const
	{
		return m_p;
	}
	inline T** operator & (void) 
	{
		_ASSERT(m_p);
		return &m_p;
	}
	inline T* operator->(void)
	{
		_ASSERT(m_p);
		return m_p;
	}
	inline T* PvReturn(void)
	{
		T*p = m_p;
		m_p = NULL;
		return p;
	}
};


template <class T>
class CAutoRefc
{
	T* m_p;
    LONG m_lRef;

public:
	CAutoRefc(T* p = NULL) : m_p(p), m_lRef(1) {}
	~CAutoRefc()
	{
		if (m_p)
		{
			m_p->Release();
		}
	}
	void operator=(T* p)
	{
		if (m_p)
		{
			m_p->Release();
		}
		m_p = p;
	}
	inline operator T* (void) const
	{
		return m_p;
	}
	inline  T** operator & (void) 
	{
		_ASSERT(m_p);
		return &m_p;
	}
	inline T* operator->(void)
	{
		_ASSERT(m_p);
		return m_p;
	}
	inline T* PvReturn(void)
	{
		T*p = m_p;
		m_p = NULL;
		return p;
	}

    
};


template <class T>
class CAutoAtlArray
{
	CAtlArray<T*> m_a;

public:
	CAutoAtlArray(){}
	~CAutoAtlArray()
	{
		for (ULONG i = 0; i< m_a.GetCount(); i++)
		{
			T* p = m_a.GetAt(i);
			delete p;
		}
	}

	inline CAtlArray<T*>* operator ->() 
	{
		return &m_a;
	}

	inline operator CAtlArray<T*>* () 
	{
		return &m_a;
	}
};


// Macro that calls a method returning HRESULT value:
#define HRCALL(a, err) \
do { \
    hr = (a); \
    if (FAILED(hr)) { \
        dprintf( "%s:%d  HRCALL Failed: %s\n  0x%.8x = %s\n", \
                __FILE__, __LINE__, (WCHAR*)err, hr, #a ); \
        return err; \
    } \
} while (0)

#define HRCALL1(a, errmsg, err) \
do { \
    hr = (a); \
    if (FAILED(hr)) { \
        dprintf( "%s:%d  HRCALL Failed: %s\n  0x%.8x = %s\n", \
                __FILE__, __LINE__, errmsg, hr, #a ); \
        return err; \
    } \
} while (0)

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)


#define NTCALL(a, err) \
do { \
    status = (a); \
    if (!NT_SUCCESS(status)) { \
        dprintf( "%s:%d  HRCALL Failed: %s\n  0x%.8x = %s\n", \
                __FILE__, __LINE__, (WCHAR*)err, status, #a ); \
        return err; \
    } \
} while (0)

// Helper function that put output in stdout and debug window
// in Visual Studio:
void dprintf( char * format, ...);


class CRefManager
{
	LONG m_lRef;
public:
	CRefManager() : m_lRef(1) {}
	LONG AddRef()
	{
		_ASSERT(m_lRef);
		return static_cast<ULONG>(InterlockedIncrement(&m_lRef));
	}

	LONG Release()
	{
		_ASSERT(m_lRef);
        ULONG refval = static_cast<ULONG>(InterlockedDecrement(&m_lRef));
        if (refval == 0)
        {
            delete this;
        }

        return refval;
	}

    virtual ~CRefManager()
    {
        _ASSERT(m_lRef == 0);
    }
};

BOOL
FBytesToString( 
	const BYTE* pbIn, 
    ULONG 		cbIn, 
    BYTE* 		pbOut, 
    ULONG& 		cbOut);

BOOL
FWStringToBytes(const WCHAR* wsIn, 
    ULONG cbIn, 
    __out_bcount(cbOut) BYTE* pbOut, 
    __inout ULONG& cbOut);

BOOL
FEqStringIgnoreCase(const WCHAR * ws1,
    ULONG ce1,
    const WCHAR * ws2,
    ULONG ce2);

#endif // __UTIL_H
