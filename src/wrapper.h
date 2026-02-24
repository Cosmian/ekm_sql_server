// Wrapper header for bindgen
// Provides Windows type definitions and neutralizes MSVC-specific attributes

// Windows base types
typedef unsigned long ULONG;
typedef unsigned char BYTE;
typedef unsigned short USHORT;
typedef unsigned char BOOLEAN;
typedef unsigned short WCHAR;

typedef struct _GUID
{
    unsigned long Data1;
    unsigned short Data2;
    unsigned short Data3;
    unsigned char Data4[8];
} GUID;

// Neutralize MSVC-specific attributes for clang/bindgen parsing
#define __declspec(x)
#define __cdecl

#include "sqlcrypt.h"
