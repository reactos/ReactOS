#ifndef _ADVAPI32_WINETEST_PRECOMP_H_
#define _ADVAPI32_WINETEST_PRECOMP_H_

#include <stdio.h>
#include <ntstatus.h>
#define WIN32_NO_STATUS
#define WIN32_LEAN_AND_MEAN
#define _INC_WINDOWS
#define COM_NO_WINDOWS_H
#include <wine/test.h>
#include <winreg.h>
#include <wine/winternl.h>
#include <ntsecapi.h>
#include <sddl.h>
#include <lmcons.h>
#include <aclapi.h>

static BOOL (WINAPI *pConvertStringSidToSidA)( LPCSTR str, PSID pSid );

#endif /* !_ADVAPI32_WINETEST_PRECOMP_H_ */