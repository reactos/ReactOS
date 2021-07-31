/*
 * IMM32 library
 *
 * Copyright 1998 Patrik Stridvall
 * Copyright 2002, 2003, 2007 CodeWeavers, Aric Stewart
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdarg.h>
#include <stdio.h>

#define WIN32_NO_STATUS
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
#include <winerror.h>
#include <wine/debug.h>
#include <imm.h>
#include <ddk/imm.h>
#include <winnls.h>
#include <winreg.h>
#include <wine/list.h>
#include <stdlib.h>
#include <ndk/umtypes.h>
#include <ndk/pstypes.h>
#include <ndk/exfuncs.h>
#include <ndk/rtlfuncs.h>
#include "../../../win32ss/include/ntuser.h"
#include "../../../win32ss/include/ntwin32.h"
#include <imm32_undoc.h>
#include <strsafe.h>

WINE_DEFAULT_DEBUG_CHANNEL(imm);

#define IMM_INIT_MAGIC 0x19650412
#define IMM_INVALID_CANDFORM ULONG_MAX

#define LANGID_CHINESE_SIMPLIFIED MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED)
#define LANGID_CHINESE_TRADITIONAL MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_TRADITIONAL)
#define LANGID_JAPANESE MAKELANGID(LANG_JAPANESE, SUBLANG_DEFAULT)

#define REGKEY_KEYBOARD_LAYOUTS \
    L"System\\CurrentControlSet\\Control\\Keyboard Layouts"
#define REGKEY_IMM \
    L"Software\\Microsoft\\Windows NT\\CurrentVersion\\IMM"

#define ROUNDUP4(n) (((n) + 3) & ~3)  /* DWORD alignment */

/* flags for g_dwImm32Flags */
#define IMM32_FLAG_UNKNOWN 0x4
#define IMM32_FLAG_CICERO_ENABLED 0x20

HMODULE g_hImm32Inst = NULL;
RTL_CRITICAL_SECTION g_csImeDpi;
PIMEDPI g_pImeDpiList = NULL;
PSERVERINFO g_psi = NULL;
BYTE g_bClientRegd = FALSE;
ULONG g_MaximumUserModeAddress = 0;
HANDLE g_hImm32Heap = NULL;
DWORD g_dwImm32Flags = 0;

LPVOID APIENTRY Imm32HeapAlloc(DWORD dwFlags, DWORD dwBytes)
{
    if (!g_hImm32Heap)
    {
        g_hImm32Heap = RtlGetProcessHeap();
        if (g_hImm32Heap == NULL)
            return NULL;
    }
    return HeapAlloc(g_hImm32Heap, dwFlags, dwBytes);
}

static DWORD_PTR APIENTRY Imm32QueryWindow(HWND hWnd, DWORD Index)
{
    return NtUserQueryWindow(hWnd, Index);
}

static DWORD APIENTRY
Imm32UpdateInputContext(HIMC hIMC, DWORD Unknown1, PCLIENTIMC pClientImc)
{
    return NtUserUpdateInputContext(hIMC, Unknown1, pClientImc);
}

static DWORD APIENTRY Imm32QueryInputContext(HIMC hIMC, DWORD dwUnknown2)
{
    return NtUserQueryInputContext(hIMC, dwUnknown2);
}

static DWORD APIENTRY Imm32NotifyIMEStatus(HWND hwnd, HIMC hIMC, DWORD dwConversion)
{
    return NtUserNotifyIMEStatus(hwnd, hIMC, dwConversion);
}

static HIMC APIENTRY Imm32CreateInputContext(PCLIENTIMC pClientImc)
{
    return NtUserCreateInputContext(pClientImc);
}

static BOOL APIENTRY Imm32DestroyInputContext(HIMC hIMC)
{
    return NtUserDestroyInputContext(hIMC);
}

DWORD_PTR APIENTRY Imm32GetThreadState(DWORD Routine)
{
    return NtUserGetThreadState(Routine);
}

static VOID APIENTRY Imm32FreeImeDpi(PIMEDPI pImeDpi, BOOL bDestroy)
{
    if (pImeDpi->hInst == NULL)
        return;
    if (bDestroy)
        pImeDpi->ImeDestroy(0);
    FreeLibrary(pImeDpi->hInst);
    pImeDpi->hInst = NULL;
}

static BOOL APIENTRY
Imm32NotifyAction(HIMC hIMC, HWND hwnd, DWORD dwAction, DWORD_PTR dwIndex, DWORD_PTR dwValue,
                  DWORD_PTR dwCommand, DWORD_PTR dwData)
{
    DWORD dwLayout;
    HKL hKL;
    PIMEDPI pImeDpi;

    if (dwAction)
    {
        dwLayout = Imm32QueryInputContext(hIMC, 1);
        if (dwLayout)
        {
            /* find keyboard layout and lock it */
            hKL = GetKeyboardLayout(dwLayout);
            pImeDpi = ImmLockImeDpi(hKL);
            if (pImeDpi)
            {
                /* do notify */
                pImeDpi->NotifyIME(hIMC, dwAction, dwIndex, dwValue);

                ImmUnlockImeDpi(pImeDpi); /* unlock */
            }
        }
    }

    if (hwnd && dwCommand)
        SendMessageW(hwnd, WM_IME_NOTIFY, dwCommand, dwData);

    return TRUE;
}

static PIMEDPI APIENTRY Imm32FindImeDpi(HKL hKL)
{
    RtlEnterCriticalSection(&g_csImeDpi);
    PIMEDPI pImeDpi = g_pImeDpiList;
    while (pImeDpi != 0)
    {
        if (pImeDpi->hKL == hKL)
            break;
        pImeDpi = pImeDpi->pNext;
    }
    RtlLeaveCriticalSection(&g_csImeDpi);
    return pImeDpi;
}

static VOID Imm32GetSystemLibraryPath(LPWSTR pszPath, DWORD cchPath, LPCWSTR pszFileName)
{
    GetSystemDirectoryW(pszPath, cchPath);
    StringCchCatW(pszPath, cchPath, L"\\");
    StringCchCatW(pszPath, cchPath, pszFileName);
}

DWORD APIENTRY Imm32SetImeOwnerWindow(PIMEINFOEX pImeInfoEx, BOOL fFlag)
{
    return NtUserSetImeOwnerWindow(pImeInfoEx, fFlag);
}

static BOOL APIENTRY Imm32LoadImeTable(PIMEINFOEX pImeInfoEx, PIMEDPI pImeDpi)
{
    WCHAR szPath[MAX_PATH];
    HINSTANCE hIME;
    FARPROC fn;

    Imm32GetSystemLibraryPath(szPath, _countof(szPath), pImeInfoEx->wszImeFile);
    hIME = GetModuleHandleW(szPath);
    if (hIME == NULL)
    {
        hIME = LoadLibraryW(szPath);
        if (hIME == NULL)
        {
            pImeDpi->hInst = NULL;
            return FALSE;
        }
    }
    pImeDpi->hInst = hIME;

#define DEFINE_IME_ENTRY(type, name, params, extended) \
    do { \
        fn = GetProcAddress(hIME, #name); \
        if (fn) pImeDpi->name = (FN_##name)fn; \
        else if (!extended) goto Failed; \
    } while (0);
#include "../../../win32ss/include/imetable.h"
#undef DEFINE_IME_ENTRY

    FIXME("We have to do something here\n");

    if (pImeInfoEx->fLoadFlag)
        return TRUE;

    Imm32SetImeOwnerWindow(pImeInfoEx, TRUE);
    return TRUE;

Failed:
    FreeLibrary(pImeDpi->hInst);
    pImeDpi->hInst = NULL;
    return FALSE;
}

static PIMEDPI APIENTRY Ime32LoadImeDpi(HKL hKL, BOOL bLock)
{
    IMEINFOEX imeinfo;
    CHARSETINFO ci;
    PIMEDPI pImeDpiNew, pImeDpiFound;
    UINT uCodePage;

    if (!ImmGetImeInfoEx(&imeinfo, ImeInfoExKeyboardLayout, &hKL) ||
        imeinfo.fLoadFlag == 1)
    {
        return NULL;
    }

    pImeDpiNew = Imm32HeapAlloc(HEAP_ZERO_MEMORY, sizeof(IMEDPI));
    if (pImeDpiNew == 0)
        return NULL;

    pImeDpiNew->hKL = hKL;
    if (TranslateCharsetInfo((LPDWORD)(DWORD_PTR)LOWORD(hKL), &ci, TCI_SRCLOCALE))
        uCodePage = ci.ciACP;
    else
        uCodePage = 0;

    pImeDpiNew->dwUnknown2[5] = uCodePage;

    if (!Imm32LoadImeTable(&imeinfo, pImeDpiNew))
    {
        HeapFree(g_hImm32Heap, 0, pImeDpiNew);
        return FALSE;
    }

    RtlEnterCriticalSection(&g_csImeDpi);

    pImeDpiFound = Imm32FindImeDpi(hKL);
    if (pImeDpiFound)
    {
        if (!bLock)
            pImeDpiFound->dwFlags &= 0xfffffffd;

        RtlLeaveCriticalSection(&g_csImeDpi);
        Imm32FreeImeDpi(pImeDpiNew, FALSE);
        HeapFree(g_hImm32Heap, 0, pImeDpiNew);

        return pImeDpiFound;
    }
    else
    {
        if (bLock)
        {
            pImeDpiNew->dwFlags |= IMEDPI_FLAG_UNKNOWN2;
            pImeDpiNew->cLockObj = 1;
        }

        pImeDpiNew->pNext = g_pImeDpiList;
        g_pImeDpiList = pImeDpiNew;

        RtlLeaveCriticalSection(&g_csImeDpi);
        return pImeDpiNew;
    }
}

BOOL WINAPI ImmLoadIME(HKL hKL)
{
    PW32CLIENTINFO pInfo;
    PIMEDPI pImeDpi;

    if (!IS_IME_HKL(hKL))
    {
        if (g_psi == NULL || (g_psi->dwSRVIFlags & SRVINFO_METRICS) == 0)
            return FALSE;

        pInfo = (PW32CLIENTINFO)(NtCurrentTeb()->Win32ClientInfo);
        if ((pInfo->W32ClientInfo[0] & 2))
            return FALSE;
    }

    pImeDpi = Imm32FindImeDpi(hKL);
    if (pImeDpi == NULL)
        pImeDpi = Ime32LoadImeDpi(hKL, 0);
    return (pImeDpi != NULL);
}

HKL WINAPI ImmLoadLayout(HKL hKL, PIMEINFOEX pImeInfoEx)
{
    DWORD cbData;
    UNICODE_STRING UnicodeString;
    HKEY hLayoutKey = NULL, hLayoutsKey = NULL;
    LONG error;
    NTSTATUS Status;
    WCHAR szLayout[MAX_PATH];

    TRACE("ImmLoadLayout(%p, %p)\n", hKL, pImeInfoEx);

    if (IS_IME_HKL(hKL) ||
        !g_psi || (g_psi->dwSRVIFlags & SRVINFO_METRICS) == 0 ||
        ((PW32CLIENTINFO)NtCurrentTeb()->Win32ClientInfo)->W32ClientInfo[0] & 2)
    {
        UnicodeString.Buffer = szLayout;
        UnicodeString.MaximumLength = sizeof(szLayout);
        Status = RtlIntegerToUnicodeString((DWORD_PTR)hKL, 16, &UnicodeString);
        if (!NT_SUCCESS(Status))
            return NULL;

        error = RegOpenKeyW(HKEY_LOCAL_MACHINE, REGKEY_KEYBOARD_LAYOUTS, &hLayoutsKey);
        if (error)
            return NULL;

        error = RegOpenKeyW(hLayoutsKey, szLayout, &hLayoutKey);
    }
    else
    {
        error = RegOpenKeyW(HKEY_LOCAL_MACHINE, REGKEY_IMM, &hLayoutKey);
    }

    if (error)
    {
        ERR("RegOpenKeyW error: 0x%08lX\n", error);
        hKL = NULL;
    }
    else
    {
        cbData = sizeof(pImeInfoEx->wszImeFile);
        error = RegQueryValueExW(hLayoutKey, L"Ime File", 0, 0,
                                 (LPBYTE)pImeInfoEx->wszImeFile, &cbData);
        if (error)
            hKL = NULL;
    }

    RegCloseKey(hLayoutKey);
    if (hLayoutsKey)
        RegCloseKey(hLayoutsKey);
    return hKL;
}

typedef struct _tagImmHkl{
    struct list entry;
    HKL         hkl;
    HMODULE     hIME;
    IMEINFO     imeInfo;
    WCHAR       imeClassName[17]; /* 16 character max */
    ULONG       uSelected;
    HWND        UIWnd;

    /* Function Pointers */
    BOOL (WINAPI *pImeInquire)(IMEINFO *, WCHAR *, const WCHAR *);
    BOOL (WINAPI *pImeConfigure)(HKL, HWND, DWORD, void *);
    BOOL (WINAPI *pImeDestroy)(UINT);
    LRESULT (WINAPI *pImeEscape)(HIMC, UINT, void *);
    BOOL (WINAPI *pImeSelect)(HIMC, BOOL);
    BOOL (WINAPI *pImeSetActiveContext)(HIMC, BOOL);
    UINT (WINAPI *pImeToAsciiEx)(UINT, UINT, const BYTE *, DWORD *, UINT, HIMC);
    BOOL (WINAPI *pNotifyIME)(HIMC, DWORD, DWORD, DWORD);
    BOOL (WINAPI *pImeRegisterWord)(const WCHAR *, DWORD, const WCHAR *);
    BOOL (WINAPI *pImeUnregisterWord)(const WCHAR *, DWORD, const WCHAR *);
    UINT (WINAPI *pImeEnumRegisterWord)(REGISTERWORDENUMPROCW, const WCHAR *, DWORD, const WCHAR *, void *);
    BOOL (WINAPI *pImeSetCompositionString)(HIMC, DWORD, const void *, DWORD, const void *, DWORD);
    DWORD (WINAPI *pImeConversionList)(HIMC, const WCHAR *, CANDIDATELIST *, DWORD, UINT);
    BOOL (WINAPI *pImeProcessKey)(HIMC, UINT, LPARAM, const BYTE *);
    UINT (WINAPI *pImeGetRegisterWordStyle)(UINT, STYLEBUFW *);
    DWORD (WINAPI *pImeGetImeMenuItems)(HIMC, DWORD, DWORD, IMEMENUITEMINFOW *, IMEMENUITEMINFOW *, DWORD);
} ImmHkl;

typedef struct tagInputContextData
{
        DWORD           dwLock;
        INPUTCONTEXT    IMC;
        DWORD           threadID;

        ImmHkl          *immKbd;
        UINT            lastVK;
        BOOL            threadDefault;
        DWORD           magic;
} InputContextData;

#define WINE_IMC_VALID_MAGIC 0x56434D49

typedef struct _tagTRANSMSG {
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
} TRANSMSG, *LPTRANSMSG;

typedef struct _tagIMMThreadData {
    struct list entry;
    DWORD threadID;
    HIMC defaultContext;
    HWND hwndDefault;
    BOOL disableIME;
    DWORD windowRefs;
} IMMThreadData;

static struct list ImmHklList = LIST_INIT(ImmHklList);
static struct list ImmThreadDataList = LIST_INIT(ImmThreadDataList);

static const WCHAR szwWineIMCProperty[] = {'W','i','n','e','I','m','m','H','I','M','C','P','r','o','p','e','r','t','y',0};

static const WCHAR szImeFileW[] = {'I','m','e',' ','F','i','l','e',0};
static const WCHAR szLayoutTextW[] = {'L','a','y','o','u','t',' ','T','e','x','t',0};
static const WCHAR szImeRegFmt[] = {'S','y','s','t','e','m','\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\','C','o','n','t','r','o','l','\\','K','e','y','b','o','a','r','d',' ','L','a','y','o','u','t','s','\\','%','0','8','l','x',0};

static const WCHAR szwIME[] = {'I','M','E',0};
static const WCHAR szwDefaultIME[] = {'D','e','f','a','u','l','t',' ','I','M','E',0};

static CRITICAL_SECTION threaddata_cs;
static CRITICAL_SECTION_DEBUG critsect_debug =
{
    0, 0, &threaddata_cs,
    { &critsect_debug.ProcessLocksList, &critsect_debug.ProcessLocksList },
      0, 0, { (DWORD_PTR)(__FILE__ ": threaddata_cs") }
};
static CRITICAL_SECTION threaddata_cs = { &critsect_debug, -1, 0, 0, 0, 0 };
static BOOL disable_ime;

static inline BOOL is_himc_ime_unicode(const InputContextData *data)
{
    return !!(data->immKbd->imeInfo.fdwProperty & IME_PROP_UNICODE);
}

static inline BOOL is_kbd_ime_unicode(const ImmHkl *hkl)
{
    return !!(hkl->imeInfo.fdwProperty & IME_PROP_UNICODE);
}

static InputContextData* get_imc_data(HIMC hIMC);

static inline WCHAR *strdupAtoW( const char *str )
{
    WCHAR *ret = NULL;
    if (str)
    {
        DWORD len = MultiByteToWideChar( CP_ACP, 0, str, -1, NULL, 0 );
        if ((ret = HeapAlloc( GetProcessHeap(), 0, len * sizeof(WCHAR) )))
            MultiByteToWideChar( CP_ACP, 0, str, -1, ret, len );
    }
    return ret;
}

static inline CHAR *strdupWtoA( const WCHAR *str )
{
    CHAR *ret = NULL;
    if (str)
    {
        DWORD len = WideCharToMultiByte( CP_ACP, 0, str, -1, NULL, 0, NULL, NULL );
        if ((ret = HeapAlloc( GetProcessHeap(), 0, len )))
            WideCharToMultiByte( CP_ACP, 0, str, -1, ret, len, NULL, NULL );
    }
    return ret;
}

static DWORD convert_candidatelist_WtoA(
        LPCANDIDATELIST lpSrc, LPCANDIDATELIST lpDst, DWORD dwBufLen)
{
    DWORD ret, i, len;

    ret = FIELD_OFFSET( CANDIDATELIST, dwOffset[lpSrc->dwCount] );
    if ( lpDst && dwBufLen > 0 )
    {
        *lpDst = *lpSrc;
        lpDst->dwOffset[0] = ret;
    }

    for ( i = 0; i < lpSrc->dwCount; i++)
    {
        LPBYTE src = (LPBYTE)lpSrc + lpSrc->dwOffset[i];

        if ( lpDst && dwBufLen > 0 )
        {
            LPBYTE dest = (LPBYTE)lpDst + lpDst->dwOffset[i];

            len = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)src, -1,
                                      (LPSTR)dest, dwBufLen, NULL, NULL);

            if ( i + 1 < lpSrc->dwCount )
                lpDst->dwOffset[i+1] = lpDst->dwOffset[i] + len * sizeof(char);
            dwBufLen -= len * sizeof(char);
        }
        else
            len = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)src, -1, NULL, 0, NULL, NULL);

        ret += len * sizeof(char);
    }

    if ( lpDst )
        lpDst->dwSize = ret;

    return ret;
}

static DWORD convert_candidatelist_AtoW(
        LPCANDIDATELIST lpSrc, LPCANDIDATELIST lpDst, DWORD dwBufLen)
{
    DWORD ret, i, len;

    ret = FIELD_OFFSET( CANDIDATELIST, dwOffset[lpSrc->dwCount] );
    if ( lpDst && dwBufLen > 0 )
    {
        *lpDst = *lpSrc;
        lpDst->dwOffset[0] = ret;
    }

    for ( i = 0; i < lpSrc->dwCount; i++)
    {
        LPBYTE src = (LPBYTE)lpSrc + lpSrc->dwOffset[i];

        if ( lpDst && dwBufLen > 0 )
        {
            LPBYTE dest = (LPBYTE)lpDst + lpDst->dwOffset[i];

            len = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)src, -1,
                                      (LPWSTR)dest, dwBufLen);

            if ( i + 1 < lpSrc->dwCount )
                lpDst->dwOffset[i+1] = lpDst->dwOffset[i] + len * sizeof(WCHAR);
            dwBufLen -= len * sizeof(WCHAR);
        }
        else
            len = MultiByteToWideChar(CP_ACP, 0, (LPCSTR)src, -1, NULL, 0);

        ret += len * sizeof(WCHAR);
    }

    if ( lpDst )
        lpDst->dwSize = ret;

    return ret;
}

static IMMThreadData *IMM_GetThreadData(HWND hwnd, DWORD thread)
{
    IMMThreadData *data;
    DWORD process;

    if (hwnd)
    {
        if (!(thread = GetWindowThreadProcessId(hwnd, &process))) return NULL;
        if (process != GetCurrentProcessId()) return NULL;
    }
    else if (thread)
    {
        HANDLE h = OpenThread(THREAD_QUERY_INFORMATION, FALSE, thread);
        if (!h) return NULL;
        process = GetProcessIdOfThread(h);
        CloseHandle(h);
        if (process != GetCurrentProcessId()) return NULL;
    }
    else
        thread = GetCurrentThreadId();

    EnterCriticalSection(&threaddata_cs);
    LIST_FOR_EACH_ENTRY(data, &ImmThreadDataList, IMMThreadData, entry)
        if (data->threadID == thread) return data;

    data = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*data));
    data->threadID = thread;
    list_add_head(&ImmThreadDataList,&data->entry);
    TRACE("Thread Data Created (%x)\n",thread);
    return data;
}

static HMODULE load_graphics_driver(void)
{
    static const WCHAR display_device_guid_propW[] = {
        '_','_','w','i','n','e','_','d','i','s','p','l','a','y','_',
        'd','e','v','i','c','e','_','g','u','i','d',0 };
    static const WCHAR key_pathW[] = {
        'S','y','s','t','e','m','\\',
        'C','u','r','r','e','n','t','C','o','n','t','r','o','l','S','e','t','\\',
        'C','o','n','t','r','o','l','\\',
        'V','i','d','e','o','\\','{',0};
    static const WCHAR displayW[] = {'}','\\','0','0','0','0',0};
    static const WCHAR driverW[] = {'G','r','a','p','h','i','c','s','D','r','i','v','e','r',0};

    HMODULE ret = 0;
    HKEY hkey;
    DWORD size;
    WCHAR path[MAX_PATH];
    WCHAR key[ARRAY_SIZE( key_pathW ) + ARRAY_SIZE( displayW ) + 40];
    UINT guid_atom = HandleToULong( GetPropW( GetDesktopWindow(), display_device_guid_propW ));

    if (!guid_atom) return 0;
    memcpy( key, key_pathW, sizeof(key_pathW) );
    if (!GlobalGetAtomNameW( guid_atom, key + lstrlenW(key), 40 )) return 0;
    lstrcatW( key, displayW );
    if (RegOpenKeyW( HKEY_LOCAL_MACHINE, key, &hkey )) return 0;
    size = sizeof(path);
    if (!RegQueryValueExW( hkey, driverW, NULL, NULL, (BYTE *)path, &size )) ret = LoadLibraryW( path );
    RegCloseKey( hkey );
    TRACE( "%s %p\n", debugstr_w(path), ret );
    return ret;
}

/* ImmHkl loading and freeing */
#define LOAD_FUNCPTR(f) if((ptr->p##f = (LPVOID)GetProcAddress(ptr->hIME, #f)) == NULL){WARN("Can't find function %s in ime\n", #f);}
static ImmHkl *IMM_GetImmHkl(HKL hkl)
{
    ImmHkl *ptr;
    WCHAR filename[MAX_PATH];

    TRACE("Seeking ime for keyboard %p\n",hkl);

    LIST_FOR_EACH_ENTRY(ptr, &ImmHklList, ImmHkl, entry)
    {
        if (ptr->hkl == hkl)
            return ptr;
    }
    /* not found... create it */

    ptr = HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sizeof(ImmHkl));

    ptr->hkl = hkl;
    if (ImmGetIMEFileNameW(hkl, filename, MAX_PATH)) ptr->hIME = LoadLibraryW(filename);
    if (!ptr->hIME) ptr->hIME = load_graphics_driver();
    if (ptr->hIME)
    {
        LOAD_FUNCPTR(ImeInquire);
        if (!ptr->pImeInquire || !ptr->pImeInquire(&ptr->imeInfo, ptr->imeClassName, NULL))
        {
            FreeLibrary(ptr->hIME);
            ptr->hIME = NULL;
        }
        else
        {
            LOAD_FUNCPTR(ImeDestroy);
            LOAD_FUNCPTR(ImeSelect);
            if (!ptr->pImeSelect || !ptr->pImeDestroy)
            {
                FreeLibrary(ptr->hIME);
                ptr->hIME = NULL;
            }
            else
            {
                LOAD_FUNCPTR(ImeConfigure);
                LOAD_FUNCPTR(ImeEscape);
                LOAD_FUNCPTR(ImeSetActiveContext);
                LOAD_FUNCPTR(ImeToAsciiEx);
                LOAD_FUNCPTR(NotifyIME);
                LOAD_FUNCPTR(ImeRegisterWord);
                LOAD_FUNCPTR(ImeUnregisterWord);
                LOAD_FUNCPTR(ImeEnumRegisterWord);
                LOAD_FUNCPTR(ImeSetCompositionString);
                LOAD_FUNCPTR(ImeConversionList);
                LOAD_FUNCPTR(ImeProcessKey);
                LOAD_FUNCPTR(ImeGetRegisterWordStyle);
                LOAD_FUNCPTR(ImeGetImeMenuItems);
                /* make sure our classname is WCHAR */
                if (!is_kbd_ime_unicode(ptr))
                {
                    WCHAR bufW[17];
                    MultiByteToWideChar(CP_ACP, 0, (LPSTR)ptr->imeClassName,
                                        -1, bufW, 17);
                    lstrcpyW(ptr->imeClassName, bufW);
                }
            }
        }
    }
    list_add_head(&ImmHklList,&ptr->entry);

    return ptr;
}
#undef LOAD_FUNCPTR

HWND WINAPI __wine_get_ui_window(HKL hkl)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hkl);
    return immHkl->UIWnd;
}

/* for posting messages as the IME */
static void ImmInternalPostIMEMessage(InputContextData *data, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HWND target = GetFocus();
    if (!target)
       PostMessageW(data->IMC.hWnd,msg,wParam,lParam);
    else
       PostMessageW(target, msg, wParam, lParam);
}

/* for sending messages as the IME */
static void ImmInternalSendIMEMessage(InputContextData *data, UINT msg, WPARAM wParam, LPARAM lParam)
{
    HWND target = GetFocus();
    if (!target)
       SendMessageW(data->IMC.hWnd,msg,wParam,lParam);
    else
       SendMessageW(target, msg, wParam, lParam);
}

static LRESULT ImmInternalSendIMENotify(InputContextData *data, WPARAM notify, LPARAM lParam)
{
    HWND target;

    target = data->IMC.hWnd;
    if (!target) target = GetFocus();

    if (target)
       return SendMessageW(target, WM_IME_NOTIFY, notify, lParam);

    return 0;
}

static InputContextData* get_imc_data(HIMC hIMC)
{
    InputContextData *data = hIMC;

    if (hIMC == NULL)
        return NULL;

    if(IsBadReadPtr(data, sizeof(InputContextData)) || data->magic != WINE_IMC_VALID_MAGIC)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return NULL;
    }
    return data;
}

static HIMC get_default_context( HWND hwnd )
{
    FIXME("Don't use this function\n");
    return FALSE;
}

static BOOL IMM_IsCrossThreadAccess(HWND hWnd,  HIMC hIMC)
{
    InputContextData *data;

    if (hWnd)
    {
        DWORD thread = GetWindowThreadProcessId(hWnd, NULL);
        if (thread != GetCurrentThreadId()) return TRUE;
    }
    data = get_imc_data(hIMC);
    if (data && data->threadID != GetCurrentThreadId())
        return TRUE;

    return FALSE;
}

/***********************************************************************
 *		ImmAssociateContext (IMM32.@)
 */
HIMC WINAPI ImmAssociateContext(HWND hWnd, HIMC hIMC)
{
    HIMC old = NULL;
    InputContextData *data = get_imc_data(hIMC);

    TRACE("(%p, %p):\n", hWnd, hIMC);

    if(hIMC && !data)
        return NULL;

    /*
     * If already associated just return
     */
    if (hIMC && data->IMC.hWnd == hWnd)
        return hIMC;

    if (hIMC && IMM_IsCrossThreadAccess(hWnd, hIMC))
        return NULL;

    if (hWnd)
    {
        HIMC defaultContext = get_default_context( hWnd );
        old = RemovePropW(hWnd,szwWineIMCProperty);

        if (old == NULL)
            old = defaultContext;
        else if (old == (HIMC)-1)
            old = NULL;

        if (hIMC != defaultContext)
        {
            if (hIMC == NULL) /* Meaning disable imm for that window*/
                SetPropW(hWnd,szwWineIMCProperty,(HANDLE)-1);
            else
                SetPropW(hWnd,szwWineIMCProperty,hIMC);
        }

        if (old)
        {
            InputContextData *old_data = old;
            if (old_data->IMC.hWnd == hWnd)
                old_data->IMC.hWnd = NULL;
        }
    }

    if (!hIMC)
        return old;

    if(GetActiveWindow() == data->IMC.hWnd)
    {
        SendMessageW(data->IMC.hWnd, WM_IME_SETCONTEXT, FALSE, ISC_SHOWUIALL);
        data->IMC.hWnd = hWnd;
        SendMessageW(data->IMC.hWnd, WM_IME_SETCONTEXT, TRUE, ISC_SHOWUIALL);
    }

    return old;
}


/*
 * Helper function for ImmAssociateContextEx
 */
static BOOL CALLBACK _ImmAssociateContextExEnumProc(HWND hwnd, LPARAM lParam)
{
    HIMC hImc = (HIMC)lParam;
    ImmAssociateContext(hwnd,hImc);
    return TRUE;
}

/***********************************************************************
 *              ImmAssociateContextEx (IMM32.@)
 */
BOOL WINAPI ImmAssociateContextEx(HWND hWnd, HIMC hIMC, DWORD dwFlags)
{
    TRACE("(%p, %p, 0x%x):\n", hWnd, hIMC, dwFlags);

    if (!hWnd)
        return FALSE;

    switch (dwFlags)
    {
    case 0:
        ImmAssociateContext(hWnd,hIMC);
        return TRUE;
    case IACE_DEFAULT:
    {
        HIMC defaultContext = get_default_context( hWnd );
        if (!defaultContext) return FALSE;
        ImmAssociateContext(hWnd,defaultContext);
        return TRUE;
    }
    case IACE_IGNORENOCONTEXT:
        if (GetPropW(hWnd,szwWineIMCProperty))
            ImmAssociateContext(hWnd,hIMC);
        return TRUE;
    case IACE_CHILDREN:
        EnumChildWindows(hWnd,_ImmAssociateContextExEnumProc,(LPARAM)hIMC);
        return TRUE;
    default:
        FIXME("Unknown dwFlags 0x%x\n",dwFlags);
        return FALSE;
    }
}

/***********************************************************************
 *		ImmConfigureIMEA (IMM32.@)
 */
BOOL WINAPI ImmConfigureIMEA(
  HKL hKL, HWND hWnd, DWORD dwMode, LPVOID lpData)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);

    TRACE("(%p, %p, %d, %p):\n", hKL, hWnd, dwMode, lpData);

    if (dwMode == IME_CONFIG_REGISTERWORD && !lpData)
        return FALSE;

    if (immHkl->hIME && immHkl->pImeConfigure)
    {
        if (dwMode != IME_CONFIG_REGISTERWORD || !is_kbd_ime_unicode(immHkl))
            return immHkl->pImeConfigure(hKL,hWnd,dwMode,lpData);
        else
        {
            REGISTERWORDW rww;
            REGISTERWORDA *rwa = lpData;
            BOOL rc;

            rww.lpReading = strdupAtoW(rwa->lpReading);
            rww.lpWord = strdupAtoW(rwa->lpWord);
            rc = immHkl->pImeConfigure(hKL,hWnd,dwMode,&rww);
            HeapFree(GetProcessHeap(),0,rww.lpReading);
            HeapFree(GetProcessHeap(),0,rww.lpWord);
            return rc;
        }
    }
    else
        return FALSE;
}

/***********************************************************************
 *		ImmConfigureIMEW (IMM32.@)
 */
BOOL WINAPI ImmConfigureIMEW(
  HKL hKL, HWND hWnd, DWORD dwMode, LPVOID lpData)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);

    TRACE("(%p, %p, %d, %p):\n", hKL, hWnd, dwMode, lpData);

    if (dwMode == IME_CONFIG_REGISTERWORD && !lpData)
        return FALSE;

    if (immHkl->hIME && immHkl->pImeConfigure)
    {
        if (dwMode != IME_CONFIG_REGISTERWORD || is_kbd_ime_unicode(immHkl))
            return immHkl->pImeConfigure(hKL,hWnd,dwMode,lpData);
        else
        {
            REGISTERWORDW *rww = lpData;
            REGISTERWORDA rwa;
            BOOL rc;

            rwa.lpReading = strdupWtoA(rww->lpReading);
            rwa.lpWord = strdupWtoA(rww->lpWord);
            rc = immHkl->pImeConfigure(hKL,hWnd,dwMode,&rwa);
            HeapFree(GetProcessHeap(),0,rwa.lpReading);
            HeapFree(GetProcessHeap(),0,rwa.lpWord);
            return rc;
        }
    }
    else
        return FALSE;
}

/***********************************************************************
 *		ImmCreateContext (IMM32.@)
 */
HIMC WINAPI ImmCreateContext(void)
{
    PCLIENTIMC pClientImc;
    HIMC hIMC;

    TRACE("ImmCreateContext()\n");

    if (g_psi == NULL || !(g_psi->dwSRVIFlags & SRVINFO_IMM32))
        return NULL;

    pClientImc = Imm32HeapAlloc(HEAP_ZERO_MEMORY, sizeof(CLIENTIMC));
    if (pClientImc == NULL)
        return NULL;

    hIMC = Imm32CreateInputContext(pClientImc);
    if (hIMC == NULL)
    {
        HeapFree(g_hImm32Heap, 0, pClientImc);
        return NULL;
    }

    RtlInitializeCriticalSection(&pClientImc->cs);
    pClientImc->unknown = Imm32GetThreadState(THREADSTATE_UNKNOWN13);
    return hIMC;
}

static VOID APIENTRY Imm32CleanupContextExtra(LPINPUTCONTEXT pIC)
{
    FIXME("We have to do something do here");
}

static PCLIENTIMC APIENTRY Imm32FindClientImc(HIMC hIMC)
{
    // FIXME
    return NULL;
}

BOOL APIENTRY Imm32CleanupContext(HIMC hIMC, HKL hKL, BOOL bKeep)
{
    PIMEDPI pImeDpi;
    LPINPUTCONTEXT pIC;
    PCLIENTIMC pClientImc;

    if (g_psi == NULL || !(g_psi->dwSRVIFlags & SRVINFO_IMM32) || hIMC == NULL)
        return FALSE;

    FIXME("We have do something to do here\n");
    pClientImc = Imm32FindClientImc(hIMC);
    if (!pClientImc)
        return FALSE;

    if (pClientImc->hImc == NULL)
    {
        pClientImc->dwFlags |= CLIENTIMC_UNKNOWN1;
        ImmUnlockClientImc(pClientImc);
        if (!bKeep)
            return Imm32DestroyInputContext(hIMC);
        return TRUE;
    }

    pIC = ImmLockIMC(hIMC);
    if (pIC == NULL)
    {
        ImmUnlockClientImc(pClientImc);
        return FALSE;
    }

    FIXME("We have do something to do here\n");

    if (pClientImc->hKL == hKL)
    {
        pImeDpi = ImmLockImeDpi(hKL);
        if (pImeDpi != NULL)
        {
            if (IS_IME_HKL(hKL))
            {
                pImeDpi->ImeSelect(hIMC, FALSE);
            }
            else if (g_psi && (g_psi->dwSRVIFlags & SRVINFO_METRICS))
            {
                FIXME("We have do something to do here\n");
            }
            ImmUnlockImeDpi(pImeDpi);
        }
        pClientImc->hKL = NULL;
    }

    ImmDestroyIMCC(pIC->hPrivate);
    ImmDestroyIMCC(pIC->hMsgBuf);
    ImmDestroyIMCC(pIC->hGuideLine);
    ImmDestroyIMCC(pIC->hCandInfo);
    ImmDestroyIMCC(pIC->hCompStr);

    Imm32CleanupContextExtra(pIC);

    ImmUnlockIMC(hIMC);

    pClientImc->dwFlags |= CLIENTIMC_UNKNOWN1;
    ImmUnlockClientImc(pClientImc);

    if (!bKeep)
        return Imm32DestroyInputContext(hIMC);

    return TRUE;
}

/***********************************************************************
 *		ImmDestroyContext (IMM32.@)
 */
BOOL WINAPI ImmDestroyContext(HIMC hIMC)
{
    DWORD dwImeThreadId, dwThreadId;
    HKL hKL;

    TRACE("ImmDestroyContext(%p)\n", hIMC);

    if (g_psi == NULL || !(g_psi->dwSRVIFlags & SRVINFO_IMM32))
        return FALSE;

    dwImeThreadId = Imm32QueryInputContext(hIMC, 1);
    dwThreadId = GetCurrentThreadId();
    if (dwImeThreadId != dwThreadId)
        return FALSE;

    hKL = GetKeyboardLayout(0);
    return Imm32CleanupContext(hIMC, hKL, FALSE);
}

/***********************************************************************
 *		ImmDisableIME (IMM32.@)
 */
BOOL WINAPI ImmDisableIME(DWORD dwThreadId)
{
    return NtUserDisableThreadIme(dwThreadId);
}

/***********************************************************************
 *		ImmEnumRegisterWordA (IMM32.@)
 */
UINT WINAPI ImmEnumRegisterWordA(
  HKL hKL, REGISTERWORDENUMPROCA lpfnEnumProc,
  LPCSTR lpszReading, DWORD dwStyle,
  LPCSTR lpszRegister, LPVOID lpData)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);
    TRACE("(%p, %p, %s, %d, %s, %p):\n", hKL, lpfnEnumProc,
        debugstr_a(lpszReading), dwStyle, debugstr_a(lpszRegister), lpData);
    if (immHkl->hIME && immHkl->pImeEnumRegisterWord)
    {
        if (!is_kbd_ime_unicode(immHkl))
            return immHkl->pImeEnumRegisterWord((REGISTERWORDENUMPROCW)lpfnEnumProc,
                (LPCWSTR)lpszReading, dwStyle, (LPCWSTR)lpszRegister, lpData);
        else
        {
            LPWSTR lpszwReading = strdupAtoW(lpszReading);
            LPWSTR lpszwRegister = strdupAtoW(lpszRegister);
            BOOL rc;

            rc = immHkl->pImeEnumRegisterWord((REGISTERWORDENUMPROCW)lpfnEnumProc,
                                              lpszwReading, dwStyle, lpszwRegister,
                                              lpData);

            HeapFree(GetProcessHeap(),0,lpszwReading);
            HeapFree(GetProcessHeap(),0,lpszwRegister);
            return rc;
        }
    }
    else
        return 0;
}

/***********************************************************************
 *		ImmEnumRegisterWordW (IMM32.@)
 */
UINT WINAPI ImmEnumRegisterWordW(
  HKL hKL, REGISTERWORDENUMPROCW lpfnEnumProc,
  LPCWSTR lpszReading, DWORD dwStyle,
  LPCWSTR lpszRegister, LPVOID lpData)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);
    TRACE("(%p, %p, %s, %d, %s, %p):\n", hKL, lpfnEnumProc,
        debugstr_w(lpszReading), dwStyle, debugstr_w(lpszRegister), lpData);
    if (immHkl->hIME && immHkl->pImeEnumRegisterWord)
    {
        if (is_kbd_ime_unicode(immHkl))
            return immHkl->pImeEnumRegisterWord(lpfnEnumProc, lpszReading, dwStyle,
                                            lpszRegister, lpData);
        else
        {
            LPSTR lpszaReading = strdupWtoA(lpszReading);
            LPSTR lpszaRegister = strdupWtoA(lpszRegister);
            BOOL rc;

            rc = immHkl->pImeEnumRegisterWord(lpfnEnumProc, (LPCWSTR)lpszaReading,
                                              dwStyle, (LPCWSTR)lpszaRegister, lpData);

            HeapFree(GetProcessHeap(),0,lpszaReading);
            HeapFree(GetProcessHeap(),0,lpszaRegister);
            return rc;
        }
    }
    else
        return 0;
}

static inline BOOL EscapeRequiresWA(UINT uEscape)
{
        if (uEscape == IME_ESC_GET_EUDC_DICTIONARY ||
            uEscape == IME_ESC_SET_EUDC_DICTIONARY ||
            uEscape == IME_ESC_IME_NAME ||
            uEscape == IME_ESC_GETHELPFILENAME)
        return TRUE;
    return FALSE;
}

/***********************************************************************
 *		ImmEscapeA (IMM32.@)
 */
LRESULT WINAPI ImmEscapeA(
  HKL hKL, HIMC hIMC,
  UINT uEscape, LPVOID lpData)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);
    TRACE("(%p, %p, %d, %p):\n", hKL, hIMC, uEscape, lpData);

    if (immHkl->hIME && immHkl->pImeEscape)
    {
        if (!EscapeRequiresWA(uEscape) || !is_kbd_ime_unicode(immHkl))
            return immHkl->pImeEscape(hIMC,uEscape,lpData);
        else
        {
            WCHAR buffer[81]; /* largest required buffer should be 80 */
            LRESULT rc;
            if (uEscape == IME_ESC_SET_EUDC_DICTIONARY)
            {
                MultiByteToWideChar(CP_ACP,0,lpData,-1,buffer,81);
                rc = immHkl->pImeEscape(hIMC,uEscape,buffer);
            }
            else
            {
                rc = immHkl->pImeEscape(hIMC,uEscape,buffer);
                WideCharToMultiByte(CP_ACP,0,buffer,-1,lpData,80, NULL, NULL);
            }
            return rc;
        }
    }
    else
        return 0;
}

/***********************************************************************
 *		ImmEscapeW (IMM32.@)
 */
LRESULT WINAPI ImmEscapeW(
  HKL hKL, HIMC hIMC,
  UINT uEscape, LPVOID lpData)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);
    TRACE("(%p, %p, %d, %p):\n", hKL, hIMC, uEscape, lpData);

    if (immHkl->hIME && immHkl->pImeEscape)
    {
        if (!EscapeRequiresWA(uEscape) || is_kbd_ime_unicode(immHkl))
            return immHkl->pImeEscape(hIMC,uEscape,lpData);
        else
        {
            CHAR buffer[81]; /* largest required buffer should be 80 */
            LRESULT rc;
            if (uEscape == IME_ESC_SET_EUDC_DICTIONARY)
            {
                WideCharToMultiByte(CP_ACP,0,lpData,-1,buffer,81, NULL, NULL);
                rc = immHkl->pImeEscape(hIMC,uEscape,buffer);
            }
            else
            {
                rc = immHkl->pImeEscape(hIMC,uEscape,buffer);
                MultiByteToWideChar(CP_ACP,0,buffer,-1,lpData,80);
            }
            return rc;
        }
    }
    else
        return 0;
}

static PCLIENTIMC APIENTRY Imm32GetClientImcCache(void)
{
    // FIXME: Do something properly here
    return NULL;
}

static NTSTATUS APIENTRY
Imm32BuildHimcList(DWORD dwThreadId, DWORD dwCount, HIMC *phList, LPDWORD pdwCount)
{
    return NtUserBuildHimcList(dwThreadId, dwCount, phList, pdwCount);
}

static DWORD APIENTRY Imm32AllocAndBuildHimcList(DWORD dwThreadId, HIMC **pphList)
{
#define INITIAL_COUNT 0x40
#define MAX_RETRY 10
    NTSTATUS Status;
    DWORD dwCount = INITIAL_COUNT, cRetry = 0;
    HIMC *phNewList;

    phNewList = Imm32HeapAlloc(0, dwCount * sizeof(HIMC));
    if (phNewList == NULL)
        return 0;

    Status = Imm32BuildHimcList(dwThreadId, dwCount, phNewList, &dwCount);
    while (Status == STATUS_BUFFER_TOO_SMALL)
    {
        HeapFree(g_hImm32Heap, 0, phNewList);
        if (cRetry++ >= MAX_RETRY)
            return 0;

        phNewList = Imm32HeapAlloc(0, dwCount * sizeof(HIMC));
        if (phNewList == NULL)
            return 0;

        Status = Imm32BuildHimcList(dwThreadId, dwCount, phNewList, &dwCount);
    }

    if (NT_ERROR(Status) || !dwCount)
    {
        HeapFree(g_hImm32Heap, 0, phNewList);
        return 0;
    }

    *pphList = phNewList;
    return dwCount;
#undef INITIAL_COUNT
#undef MAX_RETRY
}

static BOOL APIENTRY Imm32ImeNonImeToggle(HIMC hIMC, HKL hKL, HWND hWnd, LANGID LangID)
{
    LPINPUTCONTEXT pIC;
    BOOL fOpen;

    if (hWnd != NULL)
        return FALSE;

    if (!IS_IME_HKL(hKL) || LOWORD(hKL) != LangID)
    {
        FIXME("We have to do something here\n");
        return TRUE;
    }

    pIC = ImmLockIMC(hIMC);
    if (pIC == NULL)
        return TRUE;

    fOpen = pIC->fOpen;
    ImmUnlockIMC(hIMC);

    if (!fOpen)
    {
        ImmSetOpenStatus(hIMC, TRUE);
        return TRUE;
    }

    FIXME("We have to do something here\n");
    return TRUE;
}

static BOOL APIENTRY Imm32CShapeToggle(HIMC hIMC, HKL hKL, HWND hWnd)
{
    LPINPUTCONTEXT pIC;
    BOOL fOpen;
    DWORD dwConversion, dwSentence;

    if (hWnd == NULL || !IS_IME_HKL(hKL))
        return FALSE;

    pIC = ImmLockIMC(hIMC);
    if (pIC == NULL)
        return TRUE;

    fOpen = pIC->fOpen;
    if (fOpen)
    {
        dwConversion = (pIC->fdwConversion ^ IME_CMODE_FULLSHAPE);
        dwSentence = pIC->fdwSentence;
    }

    ImmUnlockIMC(hIMC);

    if (fOpen)
        ImmSetConversionStatus(hIMC, dwConversion, dwSentence);
    else
        ImmSetOpenStatus(hIMC, TRUE);

    return TRUE;
}

static BOOL APIENTRY Imm32CSymbolToggle(HIMC hIMC, HKL hKL, HWND hWnd)
{
    LPINPUTCONTEXT pIC;
    BOOL fOpen;
    DWORD dwConversion, dwSentence;

    if (hWnd == NULL || !IS_IME_HKL(hKL))
        return FALSE;

    pIC = ImmLockIMC(hIMC);
    if (pIC == NULL)
        return TRUE;

    fOpen = pIC->fOpen;
    if (fOpen)
    {
        dwConversion = (pIC->fdwConversion ^ IME_CMODE_SYMBOL);
        dwSentence = pIC->fdwSentence;
    }

    ImmUnlockIMC(hIMC);

    if (fOpen)
        ImmSetConversionStatus(hIMC, dwConversion, dwSentence);
    else
        ImmSetOpenStatus(hIMC, TRUE);

    return TRUE;
}

static BOOL APIENTRY Imm32JCloseOpen(HIMC hIMC, HKL hKL, HWND hWnd)
{
    BOOL fOpen;

    if (ImmIsIME(hKL) && LOWORD(hKL) == LANGID_JAPANESE)
    {
        fOpen = ImmGetOpenStatus(hIMC);
        ImmSetOpenStatus(hIMC, !fOpen);
        return TRUE;
    }

    FIXME("We have to do something here\n");
    return TRUE;
}

static BOOL APIENTRY Imm32KShapeToggle(HIMC hIMC)
{
    LPINPUTCONTEXT pIC;
    DWORD dwConversion, dwSentence;

    pIC = ImmLockIMC(hIMC);
    if (pIC == NULL)
        return FALSE;

    dwConversion = (pIC->fdwConversion ^ IME_CMODE_FULLSHAPE);
    dwSentence = pIC->fdwSentence;
    ImmSetConversionStatus(hIMC, dwConversion, dwSentence);

    if (pIC->fdwConversion & (IME_CMODE_FULLSHAPE | IME_CMODE_NATIVE))
        ImmSetOpenStatus(hIMC, TRUE);
    else
        ImmSetOpenStatus(hIMC, FALSE);

    ImmUnlockIMC(hIMC);
    return TRUE;
}

static BOOL APIENTRY Imm32KHanjaConvert(HIMC hIMC)
{
    LPINPUTCONTEXT pIC;
    DWORD dwConversion, dwSentence;

    pIC = ImmLockIMC(hIMC);
    if (!pIC)
        return FALSE;

    dwConversion = (pIC->fdwConversion ^ IME_CMODE_HANJACONVERT);
    dwSentence = pIC->fdwSentence;
    ImmUnlockIMC(hIMC);

    ImmSetConversionStatus(hIMC, dwConversion, dwSentence);
    return TRUE;
}

static BOOL APIENTRY Imm32KEnglish(HIMC hIMC)
{
    LPINPUTCONTEXT pIC;
    DWORD dwConversion, dwSentence;
    BOOL fOpen;

    pIC = ImmLockIMC(hIMC);
    if (pIC == NULL)
        return FALSE;

    dwConversion = (pIC->fdwConversion ^ IME_CMODE_NATIVE);
    dwSentence = pIC->fdwSentence;
    ImmSetConversionStatus(hIMC, dwConversion, dwSentence);

    fOpen = ((pIC->fdwConversion & (IME_CMODE_FULLSHAPE | IME_CMODE_NATIVE)) != 0);
    ImmSetOpenStatus(hIMC, fOpen);

    ImmUnlockIMC(hIMC);
    return TRUE;
}

static BOOL APIENTRY Imm32ProcessHotKey(HWND hWnd, HIMC hIMC, HKL hKL, DWORD dwHotKeyID)
{
    DWORD dwImeThreadId, dwThreadId;
    PIMEDPI pImeDpi;
    BOOL ret;

    if (hIMC)
    {
        dwImeThreadId = Imm32QueryInputContext(hIMC, 1);
        dwThreadId = GetCurrentThreadId();
        if (dwImeThreadId != dwThreadId)
            return FALSE;
    }

    switch (dwHotKeyID)
    {
        case IME_CHOTKEY_IME_NONIME_TOGGLE:
            return Imm32ImeNonImeToggle(hIMC, hKL, hWnd, LANGID_CHINESE_SIMPLIFIED);

        case IME_CHOTKEY_SHAPE_TOGGLE:
            return Imm32CShapeToggle(hIMC, hKL, hWnd);

        case IME_CHOTKEY_SYMBOL_TOGGLE:
            return Imm32CSymbolToggle(hIMC, hKL, hWnd);

        case IME_JHOTKEY_CLOSE_OPEN:
            return Imm32JCloseOpen(hIMC, hKL, hWnd);

        case IME_KHOTKEY_SHAPE_TOGGLE:
            return Imm32KShapeToggle(hIMC);

        case IME_KHOTKEY_HANJACONVERT:
            return Imm32KHanjaConvert(hIMC);

        case IME_KHOTKEY_ENGLISH:
            return Imm32KEnglish(hIMC);

        case IME_THOTKEY_IME_NONIME_TOGGLE:
            return Imm32ImeNonImeToggle(hIMC, hKL, hWnd, LANGID_CHINESE_TRADITIONAL);

        case IME_THOTKEY_SHAPE_TOGGLE:
            return Imm32CShapeToggle(hIMC, hKL, hWnd);

        case IME_THOTKEY_SYMBOL_TOGGLE:
            return Imm32CSymbolToggle(hIMC, hKL, hWnd);

        default:
            break;
    }

    if (dwHotKeyID < IME_HOTKEY_PRIVATE_FIRST || IME_HOTKEY_PRIVATE_LAST < dwHotKeyID)
        return FALSE;

    pImeDpi = ImmLockImeDpi(hKL);
    if (pImeDpi == NULL)
        return FALSE;

    ret = (BOOL)pImeDpi->ImeEscape(hIMC, IME_ESC_PRIVATE_HOTKEY, &dwHotKeyID);
    ImmUnlockImeDpi(pImeDpi);
    return ret;
}

PCLIENTIMC WINAPI ImmLockClientImc(HIMC hImc)
{
    PCLIENTIMC pClientImc;

    TRACE("ImmLockClientImc(%p)\n", hImc);

    if (hImc == NULL)
        return NULL;

    pClientImc = Imm32GetClientImcCache();
    if (!pClientImc)
    {
        pClientImc = Imm32HeapAlloc(HEAP_ZERO_MEMORY, sizeof(CLIENTIMC));
        if (!pClientImc)
            return NULL;

        RtlInitializeCriticalSection(&pClientImc->cs);
        pClientImc->unknown = Imm32GetThreadState(THREADSTATE_UNKNOWN13);

        if (!Imm32UpdateInputContext(hImc, 0, pClientImc))
        {
            HeapFree(g_hImm32Heap, 0, pClientImc);
            return NULL;
        }

        pClientImc->dwFlags |= CLIENTIMC_UNKNOWN2;
    }
    else
    {
        if (pClientImc->dwFlags & CLIENTIMC_UNKNOWN1)
            return NULL;
    }

    InterlockedIncrement(&pClientImc->cLockObj);
    return pClientImc;
}

VOID WINAPI ImmUnlockClientImc(PCLIENTIMC pClientImc)
{
    LONG cLocks;
    HIMC hImc;

    TRACE("ImmUnlockClientImc(%p)\n", pClientImc);

    cLocks = InterlockedDecrement(&pClientImc->cLockObj);
    if (cLocks != 0 || !(pClientImc->dwFlags & CLIENTIMC_UNKNOWN1))
        return;

    hImc = pClientImc->hImc;
    if (hImc)
        LocalFree(hImc);

    RtlDeleteCriticalSection(&pClientImc->cs);
    HeapFree(g_hImm32Heap, 0, pClientImc);
}

static DWORD APIENTRY
CandidateListWideToAnsi(const CANDIDATELIST *pWideCL, LPCANDIDATELIST pAnsiCL, DWORD dwBufLen,
                        UINT uCodePage)
{
    BOOL bUsedDefault;
    DWORD dwSize, dwIndex, cbGot, cbLeft;
    const BYTE *pbWide;
    LPBYTE pbAnsi;
    LPDWORD pibOffsets;

    /* calculate total ansi size */
    if (pWideCL->dwCount > 0)
    {
        dwSize = sizeof(CANDIDATELIST) + ((pWideCL->dwCount - 1) * sizeof(DWORD));
        for (dwIndex = 0; dwIndex < pWideCL->dwCount; ++dwIndex)
        {
            pbWide = (const BYTE *)pWideCL + pWideCL->dwOffset[dwIndex];
            cbGot = WideCharToMultiByte(uCodePage, 0, (LPCWSTR)pbWide, -1, NULL, 0,
                                        NULL, &bUsedDefault);
            dwSize += cbGot;
        }
    }
    else
    {
        dwSize = sizeof(CANDIDATELIST);
    }

    dwSize = ROUNDUP4(dwSize);
    if (dwBufLen == 0)
        return dwSize;
    if (dwBufLen < dwSize)
        return 0;

    /* store to ansi */
    pAnsiCL->dwSize = dwBufLen;
    pAnsiCL->dwStyle = pWideCL->dwStyle;
    pAnsiCL->dwCount = pWideCL->dwCount;
    pAnsiCL->dwSelection = pWideCL->dwSelection;
    pAnsiCL->dwPageStart = pWideCL->dwPageStart;
    pAnsiCL->dwPageSize = pWideCL->dwPageSize;

    pibOffsets = pAnsiCL->dwOffset;
    if (pWideCL->dwCount > 0)
    {
        pibOffsets[0] = sizeof(CANDIDATELIST) + ((pWideCL->dwCount - 1) * sizeof(DWORD));
        cbLeft = dwBufLen - pibOffsets[0];

        for (dwIndex = 0; dwIndex < pWideCL->dwCount; ++dwIndex)
        {
            pbWide = (const BYTE *)pWideCL + pWideCL->dwOffset[dwIndex];
            pbAnsi = (LPBYTE)pAnsiCL + pibOffsets[dwIndex];

            /* convert to ansi */
            cbGot = WideCharToMultiByte(uCodePage, 0, (LPCWSTR)pbWide, -1,
                                        (LPSTR)pbAnsi, cbLeft, NULL, &bUsedDefault);
            cbLeft -= cbGot;

            if (dwIndex < pWideCL->dwCount - 1)
                pibOffsets[dwIndex + 1] = pibOffsets[dwIndex] + cbGot;
        }
    }
    else
    {
        pibOffsets[0] = sizeof(CANDIDATELIST);
    }

    return dwBufLen;
}

static DWORD APIENTRY
CandidateListAnsiToWide(const CANDIDATELIST *pAnsiCL, LPCANDIDATELIST pWideCL, DWORD dwBufLen,
                        UINT uCodePage)
{
    DWORD dwSize, dwIndex, cchGot, cbGot, cbLeft;
    const BYTE *pbAnsi;
    LPBYTE pbWide;
    LPDWORD pibOffsets;

    /* calculate total wide size */
    if (pAnsiCL->dwCount > 0)
    {
        dwSize = sizeof(CANDIDATELIST) + ((pAnsiCL->dwCount - 1) * sizeof(DWORD));
        for (dwIndex = 0; dwIndex < pAnsiCL->dwCount; ++dwIndex)
        {
            pbAnsi = (const BYTE *)pAnsiCL + pAnsiCL->dwOffset[dwIndex];
            cchGot = MultiByteToWideChar(uCodePage, MB_PRECOMPOSED, (LPCSTR)pbAnsi, -1, NULL, 0);
            dwSize += cchGot * sizeof(WCHAR);
        }
    }
    else
    {
        dwSize = sizeof(CANDIDATELIST);
    }

    dwSize = ROUNDUP4(dwSize);
    if (dwBufLen == 0)
        return dwSize;
    if (dwBufLen < dwSize)
        return 0;

    /* store to wide */
    pWideCL->dwSize = dwBufLen;
    pWideCL->dwStyle = pAnsiCL->dwStyle;
    pWideCL->dwCount = pAnsiCL->dwCount;
    pWideCL->dwSelection = pAnsiCL->dwSelection;
    pWideCL->dwPageStart = pAnsiCL->dwPageStart;
    pWideCL->dwPageSize = pAnsiCL->dwPageSize;

    pibOffsets = pWideCL->dwOffset;
    if (pAnsiCL->dwCount > 0)
    {
        pibOffsets[0] = sizeof(CANDIDATELIST) + ((pWideCL->dwCount - 1) * sizeof(DWORD));
        cbLeft = dwBufLen - pibOffsets[0];

        for (dwIndex = 0; dwIndex < pAnsiCL->dwCount; ++dwIndex)
        {
            pbAnsi = (const BYTE *)pAnsiCL + pAnsiCL->dwOffset[dwIndex];
            pbWide = (LPBYTE)pWideCL + pibOffsets[dwIndex];

            /* convert to wide */
            cchGot = MultiByteToWideChar(uCodePage, MB_PRECOMPOSED, (LPCSTR)pbAnsi, -1,
                                         (LPWSTR)pbWide, cbLeft / sizeof(WCHAR));
            cbGot = cchGot * sizeof(WCHAR);
            cbLeft -= cbGot;

            if (dwIndex + 1 < pAnsiCL->dwCount)
                pibOffsets[dwIndex + 1] = pibOffsets[dwIndex] + cbGot;
        }
    }
    else
    {
        pibOffsets[0] = sizeof(CANDIDATELIST);
    }

    return dwBufLen;
}

static DWORD APIENTRY
ImmGetCandidateListAW(HIMC hIMC, DWORD dwIndex, LPCANDIDATELIST lpCandList, DWORD dwBufLen,
                      BOOL bAnsi)
{
    DWORD ret = 0;
    LPINPUTCONTEXT pIC;
    PCLIENTIMC pClientImc;
    LPCANDIDATEINFO pCI;
    LPCANDIDATELIST pCL;
    DWORD dwSize;

    pClientImc = ImmLockClientImc(hIMC);
    if (!pClientImc)
        return 0;

    pIC = ImmLockIMC(hIMC);
    if (pIC == NULL)
    {
        ImmUnlockClientImc(pClientImc);
        return 0;
    }

    pCI = ImmLockIMCC(pIC->hCandInfo);
    if (pCI == NULL)
    {
        ImmUnlockIMC(hIMC);
        ImmUnlockClientImc(pClientImc);
        return 0;
    }

    if (pCI->dwSize < sizeof(CANDIDATEINFO) || pCI->dwCount <= dwIndex)
        goto Quit;

    /* get required size */
    pCL = (LPCANDIDATELIST)((LPBYTE)pCI + pCI->dwOffset[dwIndex]);
    if (bAnsi)
    {
        if (pClientImc->dwFlags & CLIENTIMC_WIDE)
            dwSize = CandidateListAnsiToWide(pCL, NULL, 0, CP_ACP);
        else
            dwSize = pCL->dwSize;
    }
    else
    {
        if (pClientImc->dwFlags & CLIENTIMC_WIDE)
            dwSize = pCL->dwSize;
        else
            dwSize = CandidateListWideToAnsi(pCL, NULL, 0, CP_ACP);
    }

    if (dwBufLen != 0 && dwSize != 0)
    {
        if (lpCandList == NULL || dwBufLen < dwSize)
            goto Quit;

        /* store */
        if (bAnsi)
        {
            if (pClientImc->dwFlags & CLIENTIMC_WIDE)
                CandidateListAnsiToWide(pCL, lpCandList, dwSize, CP_ACP);
            else
                RtlCopyMemory(lpCandList, pCL, dwSize);
        }
        else
        {
            if (pClientImc->dwFlags & CLIENTIMC_WIDE)
                RtlCopyMemory(lpCandList, pCL, dwSize);
            else
                CandidateListWideToAnsi(pCL, lpCandList, dwSize, CP_ACP);
        }
    }

    ret = dwSize;

Quit:
    ImmUnlockIMCC(pIC->hCandInfo);
    ImmUnlockIMC(hIMC);
    ImmUnlockClientImc(pClientImc);
    return ret;
}

DWORD APIENTRY ImmGetCandidateListCountAW(HIMC hIMC, LPDWORD lpdwListCount, BOOL bAnsi)
{
    DWORD ret = 0, cbGot, dwIndex;
    PCLIENTIMC pClientImc;
    LPINPUTCONTEXT pIC;
    const CANDIDATEINFO *pCI;
    const BYTE *pb;
    const CANDIDATELIST *pCL;
    const DWORD *pdwOffsets;

    if (lpdwListCount == NULL)
        return 0;

    *lpdwListCount = 0;

    pClientImc = ImmLockClientImc(hIMC);
    if (pClientImc == NULL)
        return 0;

    pIC = ImmLockIMC(hIMC);
    if (pIC == NULL)
    {
        ImmUnlockClientImc(pClientImc);
        return 0;
    }

    pCI = ImmLockIMCC(pIC->hCandInfo);
    if (pCI == NULL)
    {
        ImmUnlockIMC(hIMC);
        ImmUnlockClientImc(pClientImc);
        return 0;
    }

    if (pCI->dwSize < sizeof(CANDIDATEINFO))
        goto Quit;

    *lpdwListCount = pCI->dwCount; /* the number of candidate lists */

    /* calculate total size of candidate lists */
    if (bAnsi)
    {
        if (pClientImc->dwFlags & CLIENTIMC_WIDE)
        {
            ret = ROUNDUP4(pCI->dwPrivateSize);
            pdwOffsets = pCI->dwOffset;
            for (dwIndex = 0; dwIndex < pCI->dwCount; ++dwIndex)
            {
                pb = (const BYTE *)pCI + pdwOffsets[dwIndex];
                pCL = (const CANDIDATELIST *)pb;
                cbGot = CandidateListWideToAnsi(pCL, NULL, 0, CP_ACP);
                ret += cbGot;
            }
        }
        else
        {
            ret = pCI->dwSize;
        }
    }
    else
    {
        if (pClientImc->dwFlags & CLIENTIMC_WIDE)
        {
            ret = pCI->dwSize;
        }
        else
        {
            ret = ROUNDUP4(pCI->dwPrivateSize);
            pdwOffsets = pCI->dwOffset;
            for (dwIndex = 0; dwIndex < pCI->dwCount; ++dwIndex)
            {
                pb = (const BYTE *)pCI + pdwOffsets[dwIndex];
                pCL = (const CANDIDATELIST *)pb;
                cbGot = CandidateListAnsiToWide(pCL, NULL, 0, CP_ACP);
                ret += cbGot;
            }
        }
    }

Quit:
    ImmUnlockIMCC(pIC->hCandInfo);
    ImmUnlockIMC(hIMC);
    ImmUnlockClientImc(pClientImc);
    return ret;
}

/***********************************************************************
 *		ImmGetCandidateListA (IMM32.@)
 */
DWORD WINAPI ImmGetCandidateListA(
  HIMC hIMC, DWORD dwIndex,
  LPCANDIDATELIST lpCandList, DWORD dwBufLen)
{
    return ImmGetCandidateListAW(hIMC, dwIndex, lpCandList, dwBufLen, TRUE);
}

/***********************************************************************
 *		ImmGetCandidateListCountA (IMM32.@)
 */
DWORD WINAPI ImmGetCandidateListCountA(
  HIMC hIMC, LPDWORD lpdwListCount)
{
    return ImmGetCandidateListCountAW(hIMC, lpdwListCount, TRUE);
}

/***********************************************************************
 *		ImmGetCandidateListCountW (IMM32.@)
 */
DWORD WINAPI ImmGetCandidateListCountW(
  HIMC hIMC, LPDWORD lpdwListCount)
{
    return ImmGetCandidateListCountAW(hIMC, lpdwListCount, FALSE);
}

/***********************************************************************
 *		ImmGetCandidateListW (IMM32.@)
 */
DWORD WINAPI ImmGetCandidateListW(
  HIMC hIMC, DWORD dwIndex,
  LPCANDIDATELIST lpCandList, DWORD dwBufLen)
{
    return ImmGetCandidateListAW(hIMC, dwIndex, lpCandList, dwBufLen, FALSE);
}

/***********************************************************************
 *		ImmGetCandidateWindow (IMM32.@)
 */
BOOL WINAPI ImmGetCandidateWindow(
  HIMC hIMC, DWORD dwIndex, LPCANDIDATEFORM lpCandidate)
{
    BOOL ret = FALSE;
    LPINPUTCONTEXT pIC;
    LPCANDIDATEFORM pCF;

    TRACE("ImmGetCandidateWindow(%p, %lu, %p)\n", hIMC, dwIndex, lpCandidate);

    pIC = ImmLockIMC(hIMC);
    if (pIC  == NULL)
        return FALSE;

    pCF = &pIC->cfCandForm[dwIndex];
    if (pCF->dwIndex != IMM_INVALID_CANDFORM)
    {
        *lpCandidate = *pCF;
        ret = TRUE;
    }

    ImmUnlockIMC(hIMC);
    return ret;
}

static VOID APIENTRY LogFontAnsiToWide(const LOGFONTA *plfA, LPLOGFONTW plfW)
{
    size_t cch;
    RtlCopyMemory(plfW, plfA, offsetof(LOGFONTA, lfFaceName));
    StringCchLengthA(plfA->lfFaceName, _countof(plfA->lfFaceName), &cch);
    cch = MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, plfA->lfFaceName, (INT)cch,
                              plfW->lfFaceName, _countof(plfW->lfFaceName));
    if (cch > _countof(plfW->lfFaceName) - 1)
        cch = _countof(plfW->lfFaceName) - 1;
    plfW->lfFaceName[cch] = 0;
}

static VOID APIENTRY LogFontWideToAnsi(const LOGFONTW *plfW, LPLOGFONTA plfA)
{
    size_t cch;
    RtlCopyMemory(plfA, plfW, offsetof(LOGFONTW, lfFaceName));
    StringCchLengthW(plfW->lfFaceName, _countof(plfW->lfFaceName), &cch);
    cch = WideCharToMultiByte(CP_ACP, 0, plfW->lfFaceName, (INT)cch,
                              plfA->lfFaceName, _countof(plfA->lfFaceName), NULL, NULL);
    if (cch > _countof(plfA->lfFaceName) - 1)
        cch = _countof(plfA->lfFaceName) - 1;
    plfA->lfFaceName[cch] = 0;
}

/***********************************************************************
 *		ImmGetCompositionFontA (IMM32.@)
 */
BOOL WINAPI ImmGetCompositionFontA(HIMC hIMC, LPLOGFONTA lplf)
{
    PCLIENTIMC pClientImc;
    BOOL ret = FALSE, bWide;
    LPINPUTCONTEXT pIC;

    TRACE("ImmGetCompositionFontA(%p, %p)\n", hIMC, lplf);

    pClientImc = ImmLockClientImc(hIMC);
    if (pClientImc == NULL)
        return FALSE;

    bWide = (pClientImc->dwFlags & CLIENTIMC_WIDE);
    ImmUnlockClientImc(pClientImc);

    pIC = ImmLockIMC(hIMC);
    if (pIC == NULL)
        return FALSE;

    if (pIC->fdwInit & INIT_LOGFONT)
    {
        if (bWide)
            LogFontWideToAnsi(&pIC->lfFont.W, lplf);
        else
            *lplf = pIC->lfFont.A;

        ret = TRUE;
    }

    ImmUnlockIMC(hIMC);
    return ret;
}

/***********************************************************************
 *		ImmGetCompositionFontW (IMM32.@)
 */
BOOL WINAPI ImmGetCompositionFontW(HIMC hIMC, LPLOGFONTW lplf)
{
    PCLIENTIMC pClientImc;
    BOOL bWide;
    LPINPUTCONTEXT pIC;
    BOOL ret = FALSE;

    TRACE("ImmGetCompositionFontW(%p, %p)\n", hIMC, lplf);

    pClientImc = ImmLockClientImc(hIMC);
    if (pClientImc == NULL)
        return FALSE;

    bWide = (pClientImc->dwFlags & CLIENTIMC_WIDE);
    ImmUnlockClientImc(pClientImc);

    pIC = ImmLockIMC(hIMC);
    if (pIC == NULL)
        return FALSE;

    if (pIC->fdwInit & INIT_LOGFONT)
    {
        if (bWide)
            *lplf = pIC->lfFont.W;
        else
            LogFontAnsiToWide(&pIC->lfFont.A, lplf);

        ret = TRUE;
    }

    ImmUnlockIMC(hIMC);
    return ret;
}


/* Helpers for the GetCompositionString functions */

/* Source encoding is defined by context, source length is always given in respective characters. Destination buffer
   length is always in bytes. */
static INT CopyCompStringIMEtoClient(const InputContextData *data, const void *src, INT src_len, void *dst,
        INT dst_len, BOOL unicode)
{
    int char_size = unicode ? sizeof(WCHAR) : sizeof(char);
    INT ret;

    if (is_himc_ime_unicode(data) ^ unicode)
    {
        if (unicode)
            ret = MultiByteToWideChar(CP_ACP, 0, src, src_len, dst, dst_len / sizeof(WCHAR));
        else
            ret = WideCharToMultiByte(CP_ACP, 0, src, src_len, dst, dst_len, NULL, NULL);
        ret *= char_size;
    }
    else
    {
        if (dst_len)
        {
            ret = min(src_len * char_size, dst_len);
            memcpy(dst, src, ret);
        }
        else
            ret = src_len * char_size;
    }

    return ret;
}

/* Composition string encoding is defined by context, returned attributes correspond to string, converted according to
   passed mode. String length is in characters, attributes are in byte arrays. */
static INT CopyCompAttrIMEtoClient(const InputContextData *data, const BYTE *src, INT src_len, const void *comp_string,
        INT str_len, BYTE *dst, INT dst_len, BOOL unicode)
{
    union
    {
        const void *str;
        const WCHAR *strW;
        const char *strA;
    } string;
    INT rc;

    string.str = comp_string;

    if (is_himc_ime_unicode(data) && !unicode)
    {
        rc = WideCharToMultiByte(CP_ACP, 0, string.strW, str_len, NULL, 0, NULL, NULL);
        if (dst_len)
        {
            int i, j = 0, k = 0;

            if (rc < dst_len)
                dst_len = rc;
            for (i = 0; i < str_len; ++i)
            {
                int len;

                len = WideCharToMultiByte(CP_ACP, 0, string.strW + i, 1, NULL, 0, NULL, NULL);
                for (; len > 0; --len)
                {
                    dst[j++] = src[k];

                    if (j >= dst_len)
                        goto end;
                }
                ++k;
            }
        end:
            rc = j;
        }
    }
    else if (!is_himc_ime_unicode(data) && unicode)
    {
        rc = MultiByteToWideChar(CP_ACP, 0, string.strA, str_len, NULL, 0);
        if (dst_len)
        {
            int i, j = 0;

            if (rc < dst_len)
                dst_len = rc;
            for (i = 0; i < str_len; ++i)
            {
                if (IsDBCSLeadByte(string.strA[i]))
                    continue;

                dst[j++] = src[i];

                if (j >= dst_len)
                    break;
            }
            rc = j;
        }
    }
    else
    {
        memcpy(dst, src, min(src_len, dst_len));
        rc = src_len;
    }

    return rc;
}

static INT CopyCompClauseIMEtoClient(InputContextData *data, LPBYTE source, INT slen, LPBYTE ssource,
                                     LPBYTE target, INT tlen, BOOL unicode )
{
    INT rc;

    if (is_himc_ime_unicode(data) && !unicode)
    {
        if (tlen)
        {
            int i;

            if (slen < tlen)
                tlen = slen;
            tlen /= sizeof (DWORD);
            for (i = 0; i < tlen; ++i)
            {
                ((DWORD *)target)[i] = WideCharToMultiByte(CP_ACP, 0, (LPWSTR)ssource,
                                                          ((DWORD *)source)[i],
                                                          NULL, 0,
                                                          NULL, NULL);
            }
            rc = sizeof (DWORD) * i;
        }
        else
            rc = slen;
    }
    else if (!is_himc_ime_unicode(data) && unicode)
    {
        if (tlen)
        {
            int i;

            if (slen < tlen)
                tlen = slen;
            tlen /= sizeof (DWORD);
            for (i = 0; i < tlen; ++i)
            {
                ((DWORD *)target)[i] = MultiByteToWideChar(CP_ACP, 0, (LPSTR)ssource,
                                                          ((DWORD *)source)[i],
                                                          NULL, 0);
            }
            rc = sizeof (DWORD) * i;
        }
        else
            rc = slen;
    }
    else
    {
        memcpy( target, source, min(slen,tlen));
        rc = slen;
    }

    return rc;
}

static INT CopyCompOffsetIMEtoClient(InputContextData *data, DWORD offset, LPBYTE ssource, BOOL unicode)
{
    int rc;

    if (is_himc_ime_unicode(data) && !unicode)
    {
        rc = WideCharToMultiByte(CP_ACP, 0, (LPWSTR)ssource, offset, NULL, 0, NULL, NULL);
    }
    else if (!is_himc_ime_unicode(data) && unicode)
    {
        rc = MultiByteToWideChar(CP_ACP, 0, (LPSTR)ssource, offset, NULL, 0);
    }
    else
        rc = offset;

    return rc;
}

static LONG ImmGetCompositionStringT( HIMC hIMC, DWORD dwIndex, LPVOID lpBuf,
                                      DWORD dwBufLen, BOOL unicode)
{
    LONG rc = 0;
    InputContextData *data = get_imc_data(hIMC);
    LPCOMPOSITIONSTRING compstr;
    LPBYTE compdata;

    TRACE("(%p, 0x%x, %p, %d)\n", hIMC, dwIndex, lpBuf, dwBufLen);

    if (!data)
       return FALSE;

    if (!data->IMC.hCompStr)
       return FALSE;

    compdata = ImmLockIMCC(data->IMC.hCompStr);
    compstr = (LPCOMPOSITIONSTRING)compdata;

    switch (dwIndex)
    {
    case GCS_RESULTSTR:
        TRACE("GCS_RESULTSTR\n");
        rc = CopyCompStringIMEtoClient(data, compdata + compstr->dwResultStrOffset, compstr->dwResultStrLen, lpBuf, dwBufLen, unicode);
        break;
    case GCS_COMPSTR:
        TRACE("GCS_COMPSTR\n");
        rc = CopyCompStringIMEtoClient(data, compdata + compstr->dwCompStrOffset, compstr->dwCompStrLen, lpBuf, dwBufLen, unicode);
        break;
    case GCS_COMPATTR:
        TRACE("GCS_COMPATTR\n");
        rc = CopyCompAttrIMEtoClient(data, compdata + compstr->dwCompAttrOffset, compstr->dwCompAttrLen,
                                     compdata + compstr->dwCompStrOffset, compstr->dwCompStrLen,
                                     lpBuf, dwBufLen, unicode);
        break;
    case GCS_COMPCLAUSE:
        TRACE("GCS_COMPCLAUSE\n");
        rc = CopyCompClauseIMEtoClient(data, compdata + compstr->dwCompClauseOffset,compstr->dwCompClauseLen,
                                       compdata + compstr->dwCompStrOffset,
                                       lpBuf, dwBufLen, unicode);
        break;
    case GCS_RESULTCLAUSE:
        TRACE("GCS_RESULTCLAUSE\n");
        rc = CopyCompClauseIMEtoClient(data, compdata + compstr->dwResultClauseOffset,compstr->dwResultClauseLen,
                                       compdata + compstr->dwResultStrOffset,
                                       lpBuf, dwBufLen, unicode);
        break;
    case GCS_RESULTREADSTR:
        TRACE("GCS_RESULTREADSTR\n");
        rc = CopyCompStringIMEtoClient(data, compdata + compstr->dwResultReadStrOffset, compstr->dwResultReadStrLen, lpBuf, dwBufLen, unicode);
        break;
    case GCS_RESULTREADCLAUSE:
        TRACE("GCS_RESULTREADCLAUSE\n");
        rc = CopyCompClauseIMEtoClient(data, compdata + compstr->dwResultReadClauseOffset,compstr->dwResultReadClauseLen,
                                       compdata + compstr->dwResultStrOffset,
                                       lpBuf, dwBufLen, unicode);
        break;
    case GCS_COMPREADSTR:
        TRACE("GCS_COMPREADSTR\n");
        rc = CopyCompStringIMEtoClient(data, compdata + compstr->dwCompReadStrOffset, compstr->dwCompReadStrLen, lpBuf, dwBufLen, unicode);
        break;
    case GCS_COMPREADATTR:
        TRACE("GCS_COMPREADATTR\n");
        rc = CopyCompAttrIMEtoClient(data, compdata + compstr->dwCompReadAttrOffset, compstr->dwCompReadAttrLen,
                                     compdata + compstr->dwCompReadStrOffset, compstr->dwCompReadStrLen,
                                     lpBuf, dwBufLen, unicode);
        break;
    case GCS_COMPREADCLAUSE:
        TRACE("GCS_COMPREADCLAUSE\n");
        rc = CopyCompClauseIMEtoClient(data, compdata + compstr->dwCompReadClauseOffset,compstr->dwCompReadClauseLen,
                                       compdata + compstr->dwCompStrOffset,
                                       lpBuf, dwBufLen, unicode);
        break;
    case GCS_CURSORPOS:
        TRACE("GCS_CURSORPOS\n");
        rc = CopyCompOffsetIMEtoClient(data, compstr->dwCursorPos, compdata + compstr->dwCompStrOffset, unicode);
        break;
    case GCS_DELTASTART:
        TRACE("GCS_DELTASTART\n");
        rc = CopyCompOffsetIMEtoClient(data, compstr->dwDeltaStart, compdata + compstr->dwCompStrOffset, unicode);
        break;
    default:
        FIXME("Unhandled index 0x%x\n",dwIndex);
        break;
    }

    ImmUnlockIMCC(data->IMC.hCompStr);

    return rc;
}

/***********************************************************************
 *		ImmGetCompositionStringA (IMM32.@)
 */
LONG WINAPI ImmGetCompositionStringA(
  HIMC hIMC, DWORD dwIndex, LPVOID lpBuf, DWORD dwBufLen)
{
    return ImmGetCompositionStringT(hIMC, dwIndex, lpBuf, dwBufLen, FALSE);
}


/***********************************************************************
 *		ImmGetCompositionStringW (IMM32.@)
 */
LONG WINAPI ImmGetCompositionStringW(
  HIMC hIMC, DWORD dwIndex,
  LPVOID lpBuf, DWORD dwBufLen)
{
    return ImmGetCompositionStringT(hIMC, dwIndex, lpBuf, dwBufLen, TRUE);
}

/***********************************************************************
 *		ImmGetCompositionWindow (IMM32.@)
 */
BOOL WINAPI ImmGetCompositionWindow(HIMC hIMC, LPCOMPOSITIONFORM lpCompForm)
{
    LPINPUTCONTEXT pIC;
    BOOL ret = FALSE;

    TRACE("ImmGetCompositionWindow(%p, %p)\n", hIMC, lpCompForm);

    pIC = ImmLockIMC(hIMC);
    if (!pIC)
        return FALSE;

    if (pIC->fdwInit & INIT_COMPFORM)
    {
        *lpCompForm = pIC->cfCompForm;
        ret = TRUE;
    }

    ImmUnlockIMC(hIMC);
    return ret;
}

/***********************************************************************
 *		ImmGetContext (IMM32.@)
 *
 */
HIMC WINAPI ImmGetContext(HWND hWnd)
{
    HIMC rc;

    TRACE("%p\n", hWnd);

    if (!IsWindow(hWnd))
    {
        SetLastError(ERROR_INVALID_WINDOW_HANDLE);
        return NULL;
    }

    rc = GetPropW(hWnd,szwWineIMCProperty);
    if (rc == (HIMC)-1)
        rc = NULL;
    else if (rc == NULL)
        rc = get_default_context( hWnd );

    if (rc)
    {
        InputContextData *data = rc;
        data->IMC.hWnd = hWnd;
    }

    TRACE("returning %p\n", rc);

    return rc;
}

/***********************************************************************
 *		ImmGetConversionListA (IMM32.@)
 */
DWORD WINAPI ImmGetConversionListA(
  HKL hKL, HIMC hIMC,
  LPCSTR pSrc, LPCANDIDATELIST lpDst,
  DWORD dwBufLen, UINT uFlag)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);
    TRACE("(%p, %p, %s, %p, %d, %d):\n", hKL, hIMC, debugstr_a(pSrc), lpDst,
                dwBufLen, uFlag);
    if (immHkl->hIME && immHkl->pImeConversionList)
    {
        if (!is_kbd_ime_unicode(immHkl))
            return immHkl->pImeConversionList(hIMC,(LPCWSTR)pSrc,lpDst,dwBufLen,uFlag);
        else
        {
            LPCANDIDATELIST lpwDst;
            DWORD ret = 0, len;
            LPWSTR pwSrc = strdupAtoW(pSrc);

            len = immHkl->pImeConversionList(hIMC, pwSrc, NULL, 0, uFlag);
            lpwDst = HeapAlloc(GetProcessHeap(), 0, len);
            if ( lpwDst )
            {
                immHkl->pImeConversionList(hIMC, pwSrc, lpwDst, len, uFlag);
                ret = convert_candidatelist_WtoA( lpwDst, lpDst, dwBufLen);
                HeapFree(GetProcessHeap(), 0, lpwDst);
            }
            HeapFree(GetProcessHeap(), 0, pwSrc);

            return ret;
        }
    }
    else
        return 0;
}

/***********************************************************************
 *		ImmGetConversionListW (IMM32.@)
 */
DWORD WINAPI ImmGetConversionListW(
  HKL hKL, HIMC hIMC,
  LPCWSTR pSrc, LPCANDIDATELIST lpDst,
  DWORD dwBufLen, UINT uFlag)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);
    TRACE("(%p, %p, %s, %p, %d, %d):\n", hKL, hIMC, debugstr_w(pSrc), lpDst,
                dwBufLen, uFlag);
    if (immHkl->hIME && immHkl->pImeConversionList)
    {
        if (is_kbd_ime_unicode(immHkl))
            return immHkl->pImeConversionList(hIMC,pSrc,lpDst,dwBufLen,uFlag);
        else
        {
            LPCANDIDATELIST lpaDst;
            DWORD ret = 0, len;
            LPSTR paSrc = strdupWtoA(pSrc);

            len = immHkl->pImeConversionList(hIMC, (LPCWSTR)paSrc, NULL, 0, uFlag);
            lpaDst = HeapAlloc(GetProcessHeap(), 0, len);
            if ( lpaDst )
            {
                immHkl->pImeConversionList(hIMC, (LPCWSTR)paSrc, lpaDst, len, uFlag);
                ret = convert_candidatelist_AtoW( lpaDst, lpDst, dwBufLen);
                HeapFree(GetProcessHeap(), 0, lpaDst);
            }
            HeapFree(GetProcessHeap(), 0, paSrc);

            return ret;
        }
    }
    else
        return 0;
}

/***********************************************************************
 *		ImmGetConversionStatus (IMM32.@)
 */
BOOL WINAPI ImmGetConversionStatus(
  HIMC hIMC, LPDWORD lpfdwConversion, LPDWORD lpfdwSentence)
{
    LPINPUTCONTEXT pIC;

    TRACE("ImmGetConversionStatus(%p %p %p)\n", hIMC, lpfdwConversion, lpfdwSentence);

    pIC = ImmLockIMC(hIMC);
    if (!pIC)
        return FALSE;

    if (lpfdwConversion)
        *lpfdwConversion = pIC->fdwConversion;
    if (lpfdwSentence)
        *lpfdwSentence = pIC->fdwSentence;

    ImmUnlockIMC(hIMC);
    return TRUE;
}

static BOOL needs_ime_window(HWND hwnd)
{
    WCHAR classW[8];

    if (GetClassNameW(hwnd, classW, ARRAY_SIZE(classW)) && !lstrcmpW(classW, szwIME))
        return FALSE;
    if (GetClassLongPtrW(hwnd, GCL_STYLE) & CS_IME) return FALSE;

    return TRUE;
}

/***********************************************************************
 *		__wine_register_window (IMM32.@)
 */
BOOL WINAPI __wine_register_window(HWND hwnd)
{
    HWND new = NULL;
    IMMThreadData *thread_data;
    TRACE("(%p)\n", hwnd);

    if (!needs_ime_window(hwnd))
        return FALSE;

    thread_data = IMM_GetThreadData(hwnd, 0);
    if (!thread_data)
        return FALSE;

    if (thread_data->disableIME || disable_ime)
    {
        TRACE("IME for this thread is disabled\n");
        LeaveCriticalSection(&threaddata_cs);
        return FALSE;
    }
    thread_data->windowRefs++;
    TRACE("windowRefs=%u, hwndDefault=%p\n",
          thread_data->windowRefs, thread_data->hwndDefault);

    /* Create default IME window */
    if (thread_data->windowRefs == 1)
    {
        /* Do not create the window inside of a critical section */
        LeaveCriticalSection(&threaddata_cs);
        new = CreateWindowExW( 0, szwIME, szwDefaultIME,
                               WS_POPUP | WS_DISABLED | WS_CLIPSIBLINGS,
                               0, 0, 1, 1, 0, 0, 0, 0);
        /* thread_data is in the current thread so we can assume it's still valid */
        EnterCriticalSection(&threaddata_cs);
        /* See if anyone beat us */
        if (thread_data->hwndDefault == NULL)
        {
            thread_data->hwndDefault = new;
            new = NULL;
            TRACE("Default is %p\n", thread_data->hwndDefault);
        }
    }

    LeaveCriticalSection(&threaddata_cs);

    /* Clean up an unused new window outside of the critical section */
    if (new != NULL)
        DestroyWindow(new);
    return TRUE;
}

/***********************************************************************
 *		__wine_unregister_window (IMM32.@)
 */
void WINAPI __wine_unregister_window(HWND hwnd)
{
    HWND to_destroy = 0;
    IMMThreadData *thread_data;
    TRACE("(%p)\n", hwnd);

    thread_data = IMM_GetThreadData(hwnd, 0);
    if (!thread_data) return;

    thread_data->windowRefs--;
    TRACE("windowRefs=%u, hwndDefault=%p\n",
          thread_data->windowRefs, thread_data->hwndDefault);

    /* Destroy default IME window */
    if (thread_data->windowRefs == 0 && thread_data->hwndDefault)
    {
        to_destroy = thread_data->hwndDefault;
        thread_data->hwndDefault = NULL;
    }
    LeaveCriticalSection(&threaddata_cs);

    if (to_destroy) DestroyWindow( to_destroy );
}

/***********************************************************************
 *		ImmGetDefaultIMEWnd (IMM32.@)
 */
HWND WINAPI ImmGetDefaultIMEWnd(HWND hWnd)
{
    if (!(g_dwImm32Flags & IMM32_FLAG_UNKNOWN))
        return NULL;

    if (hWnd == NULL)
        return (HWND)Imm32GetThreadState(THREADSTATE_ACTIVEWINDOW);

    return (HWND)Imm32QueryWindow(hWnd, QUERY_WINDOW_DEFAULT_IME);
}

/***********************************************************************
 *		CtfImmIsCiceroEnabled (IMM32.@)
 */
BOOL WINAPI CtfImmIsCiceroEnabled(VOID)
{
    return !!(g_dwImm32Flags & IMM32_FLAG_CICERO_ENABLED);
}

/***********************************************************************
 *		ImmGetDescriptionA (IMM32.@)
 */
UINT WINAPI ImmGetDescriptionA(
  HKL hKL, LPSTR lpszDescription, UINT uBufLen)
{
    IMEINFOEX info;
    size_t cch;

    TRACE("ImmGetDescriptionA(%p,%p,%d)\n", hKL, lpszDescription, uBufLen);

    if (!ImmGetImeInfoEx(&info, ImeInfoExKeyboardLayout, &hKL) || !IS_IME_HKL(hKL))
        return 0;

    StringCchLengthW(info.wszImeDescription, _countof(info.wszImeDescription), &cch);
    cch = WideCharToMultiByte(CP_ACP, 0, info.wszImeDescription, (INT)cch,
                              lpszDescription, uBufLen, NULL, NULL);
    if (uBufLen)
        lpszDescription[cch] = 0;
    return cch;
}

/***********************************************************************
 *		ImmGetDescriptionW (IMM32.@)
 */
UINT WINAPI ImmGetDescriptionW(HKL hKL, LPWSTR lpszDescription, UINT uBufLen)
{
    IMEINFOEX info;
    size_t cch;

    TRACE("ImmGetDescriptionW(%p, %p, %d)\n", hKL, lpszDescription, uBufLen);

    if (!ImmGetImeInfoEx(&info, ImeInfoExKeyboardLayout, &hKL) || !IS_IME_HKL(hKL))
        return 0;

    if (uBufLen != 0)
        StringCchCopyW(lpszDescription, uBufLen, info.wszImeDescription);

    StringCchLengthW(info.wszImeDescription, _countof(info.wszImeDescription), &cch);
    return (UINT)cch;
}

/***********************************************************************
 *		ImmGetGuideLineA (IMM32.@)
 */
DWORD WINAPI ImmGetGuideLineA(
  HIMC hIMC, DWORD dwIndex, LPSTR lpBuf, DWORD dwBufLen)
{
  FIXME("(%p, %d, %s, %d): stub\n",
    hIMC, dwIndex, debugstr_a(lpBuf), dwBufLen
  );
  SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
  return 0;
}

/***********************************************************************
 *		ImmGetGuideLineW (IMM32.@)
 */
DWORD WINAPI ImmGetGuideLineW(HIMC hIMC, DWORD dwIndex, LPWSTR lpBuf, DWORD dwBufLen)
{
  FIXME("(%p, %d, %s, %d): stub\n",
    hIMC, dwIndex, debugstr_w(lpBuf), dwBufLen
  );
  SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
  return 0;
}

/***********************************************************************
 *		ImmGetIMEFileNameA (IMM32.@)
 */
UINT WINAPI ImmGetIMEFileNameA( HKL hKL, LPSTR lpszFileName, UINT uBufLen)
{
    BOOL bDefUsed;
    IMEINFOEX info;
    size_t cch;

    TRACE("ImmGetIMEFileNameA(%p, %p, %u)\n", hKL, lpszFileName, uBufLen);

    if (!ImmGetImeInfoEx(&info, ImeInfoExKeyboardLayout, &hKL) || !IS_IME_HKL(hKL))
    {
        if (uBufLen > 0)
            lpszFileName[0] = 0;
        return 0;
    }

    StringCchLengthW(info.wszImeFile, _countof(info.wszImeFile), &cch);

    cch = WideCharToMultiByte(CP_ACP, 0, info.wszImeFile, (INT)cch,
                              lpszFileName, uBufLen, NULL, &bDefUsed);
    if (uBufLen == 0)
        return (UINT)cch;

    if (cch > uBufLen - 1)
        cch = uBufLen - 1;

    lpszFileName[cch] = 0;
    return (UINT)cch;
}

/***********************************************************************
 *		ImmGetIMEFileNameW (IMM32.@)
 */
UINT WINAPI ImmGetIMEFileNameW(HKL hKL, LPWSTR lpszFileName, UINT uBufLen)
{
    IMEINFOEX info;
    size_t cch;

    TRACE("ImmGetIMEFileNameW(%p, %p, %u)\n", hKL, lpszFileName, uBufLen);

    if (!ImmGetImeInfoEx(&info, ImeInfoExKeyboardLayout, &hKL) || !IS_IME_HKL(hKL))
    {
        if (uBufLen > 0)
            lpszFileName[0] = 0;
        return 0;
    }

    StringCchLengthW(info.wszImeFile, _countof(info.wszImeFile), &cch);
    if (uBufLen == 0)
        return (UINT)cch;

    StringCchCopyNW(lpszFileName, uBufLen, info.wszImeFile, cch);

    if (cch > uBufLen - 1)
        cch = uBufLen - 1;

    lpszFileName[cch] = 0;
    return (UINT)cch;
}

/***********************************************************************
 *		ImmGetOpenStatus (IMM32.@)
 */
BOOL WINAPI ImmGetOpenStatus(HIMC hIMC)
{
    BOOL ret;
    LPINPUTCONTEXT pIC;

    TRACE("ImmGetOpenStatus(%p)\n", hIMC);

    if (!hIMC)
        return FALSE;

    pIC = ImmLockIMC(hIMC);
    if (!pIC)
        return FALSE;

    ret = pIC->fOpen;

    ImmUnlockIMC(hIMC);
    return ret;
}

/***********************************************************************
 *		ImmGetProperty (IMM32.@)
 */
DWORD WINAPI ImmGetProperty(HKL hKL, DWORD fdwIndex)
{
    DWORD rc = 0;
    ImmHkl *kbd;

    TRACE("(%p, %d)\n", hKL, fdwIndex);
    kbd = IMM_GetImmHkl(hKL);

    if (kbd && kbd->hIME)
    {
        switch (fdwIndex)
        {
            case IGP_PROPERTY: rc = kbd->imeInfo.fdwProperty; break;
            case IGP_CONVERSION: rc = kbd->imeInfo.fdwConversionCaps; break;
            case IGP_SENTENCE: rc = kbd->imeInfo.fdwSentenceCaps; break;
            case IGP_SETCOMPSTR: rc = kbd->imeInfo.fdwSCSCaps; break;
            case IGP_SELECT: rc = kbd->imeInfo.fdwSelectCaps; break;
            case IGP_GETIMEVERSION: rc = IMEVER_0400; break;
            case IGP_UI: rc = 0; break;
            default: rc = 0;
        }
    }
    return rc;
}

/***********************************************************************
 *		ImmGetRegisterWordStyleA (IMM32.@)
 */
UINT WINAPI ImmGetRegisterWordStyleA(
  HKL hKL, UINT nItem, LPSTYLEBUFA lpStyleBuf)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);
    TRACE("(%p, %d, %p):\n", hKL, nItem, lpStyleBuf);
    if (immHkl->hIME && immHkl->pImeGetRegisterWordStyle)
    {
        if (!is_kbd_ime_unicode(immHkl))
            return immHkl->pImeGetRegisterWordStyle(nItem,(LPSTYLEBUFW)lpStyleBuf);
        else
        {
            STYLEBUFW sbw;
            UINT rc;

            rc = immHkl->pImeGetRegisterWordStyle(nItem,&sbw);
            WideCharToMultiByte(CP_ACP, 0, sbw.szDescription, -1,
                lpStyleBuf->szDescription, 32, NULL, NULL);
            lpStyleBuf->dwStyle = sbw.dwStyle;
            return rc;
        }
    }
    else
        return 0;
}

/***********************************************************************
 *		ImmGetRegisterWordStyleW (IMM32.@)
 */
UINT WINAPI ImmGetRegisterWordStyleW(
  HKL hKL, UINT nItem, LPSTYLEBUFW lpStyleBuf)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);
    TRACE("(%p, %d, %p):\n", hKL, nItem, lpStyleBuf);
    if (immHkl->hIME && immHkl->pImeGetRegisterWordStyle)
    {
        if (is_kbd_ime_unicode(immHkl))
            return immHkl->pImeGetRegisterWordStyle(nItem,lpStyleBuf);
        else
        {
            STYLEBUFA sba;
            UINT rc;

            rc = immHkl->pImeGetRegisterWordStyle(nItem,(LPSTYLEBUFW)&sba);
            MultiByteToWideChar(CP_ACP, 0, sba.szDescription, -1,
                lpStyleBuf->szDescription, 32);
            lpStyleBuf->dwStyle = sba.dwStyle;
            return rc;
        }
    }
    else
        return 0;
}

/***********************************************************************
 *		ImmGetStatusWindowPos (IMM32.@)
 */
BOOL WINAPI ImmGetStatusWindowPos(HIMC hIMC, LPPOINT lpptPos)
{
    LPINPUTCONTEXT pIC;
    BOOL ret;

    TRACE("ImmGetStatusWindowPos(%p, %p)\n", hIMC, lpptPos);

    pIC = ImmLockIMC(hIMC);
    if (pIC == NULL)
        return FALSE;

    ret = !!(pIC->fdwInit & INIT_STATUSWNDPOS);
    if (ret)
        *lpptPos = pIC->ptStatusWndPos;

    ImmUnlockIMC(hIMC);
    return ret;
}

/***********************************************************************
 *		ImmGetVirtualKey (IMM32.@)
 */
UINT WINAPI ImmGetVirtualKey(HWND hWnd)
{
  OSVERSIONINFOA version;
  InputContextData *data = ImmGetContext( hWnd );
  TRACE("%p\n", hWnd);

  if ( data )
      return data->lastVK;

  version.dwOSVersionInfoSize = sizeof(OSVERSIONINFOA);
  GetVersionExA( &version );
  switch(version.dwPlatformId)
  {
  case VER_PLATFORM_WIN32_WINDOWS:
      return VK_PROCESSKEY;
  case VER_PLATFORM_WIN32_NT:
      return 0;
  default:
      FIXME("%d not supported\n",version.dwPlatformId);
      return VK_PROCESSKEY;
  }
}

/***********************************************************************
 *		ImmInstallIMEA (IMM32.@)
 */
HKL WINAPI ImmInstallIMEA(
  LPCSTR lpszIMEFileName, LPCSTR lpszLayoutText)
{
    LPWSTR lpszwIMEFileName;
    LPWSTR lpszwLayoutText;
    HKL hkl;

    TRACE ("(%s, %s)\n", debugstr_a(lpszIMEFileName),
                         debugstr_a(lpszLayoutText));

    lpszwIMEFileName = strdupAtoW(lpszIMEFileName);
    lpszwLayoutText = strdupAtoW(lpszLayoutText);

    hkl = ImmInstallIMEW(lpszwIMEFileName, lpszwLayoutText);

    HeapFree(GetProcessHeap(),0,lpszwIMEFileName);
    HeapFree(GetProcessHeap(),0,lpszwLayoutText);
    return hkl;
}

/***********************************************************************
 *		ImmInstallIMEW (IMM32.@)
 */
HKL WINAPI ImmInstallIMEW(
  LPCWSTR lpszIMEFileName, LPCWSTR lpszLayoutText)
{
    INT lcid = GetUserDefaultLCID();
    INT count;
    HKL hkl;
    DWORD rc;
    HKEY hkey;
    WCHAR regKey[ARRAY_SIZE(szImeRegFmt)+8];

    TRACE ("(%s, %s):\n", debugstr_w(lpszIMEFileName),
                          debugstr_w(lpszLayoutText));

    /* Start with 2.  e001 will be blank and so default to the wine internal IME */
    count = 2;

    while (count < 0xfff)
    {
        DWORD disposition = 0;

        hkl = (HKL)MAKELPARAM( lcid, 0xe000 | count );
        wsprintfW( regKey, szImeRegFmt, (ULONG_PTR)hkl);

        rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, regKey, 0, NULL, 0, KEY_WRITE, NULL, &hkey, &disposition);
        if (rc == ERROR_SUCCESS && disposition == REG_CREATED_NEW_KEY)
            break;
        else if (rc == ERROR_SUCCESS)
            RegCloseKey(hkey);

        count++;
    }

    if (count == 0xfff)
    {
        WARN("Unable to find slot to install IME\n");
        return 0;
    }

    if (rc == ERROR_SUCCESS)
    {
        rc = RegSetValueExW(hkey, szImeFileW, 0, REG_SZ, (const BYTE*)lpszIMEFileName,
                            (lstrlenW(lpszIMEFileName) + 1) * sizeof(WCHAR));
        if (rc == ERROR_SUCCESS)
            rc = RegSetValueExW(hkey, szLayoutTextW, 0, REG_SZ, (const BYTE*)lpszLayoutText,
                                (lstrlenW(lpszLayoutText) + 1) * sizeof(WCHAR));
        RegCloseKey(hkey);
        return hkl;
    }
    else
    {
        WARN("Unable to set IME registry values\n");
        return 0;
    }
}

/***********************************************************************
 *		ImmIsIME (IMM32.@)
 */
BOOL WINAPI ImmIsIME(HKL hKL)
{
    IMEINFOEX info;
    TRACE("ImmIsIME(%p)\n", hKL);
    return !!ImmGetImeInfoEx(&info, ImeInfoExImeWindow, &hKL);
}

/***********************************************************************
 *		ImmIsUIMessageA (IMM32.@)
 */
BOOL WINAPI ImmIsUIMessageA(
  HWND hWndIME, UINT msg, WPARAM wParam, LPARAM lParam)
{
    TRACE("(%p, %x, %ld, %ld)\n", hWndIME, msg, wParam, lParam);
    if ((msg >= WM_IME_STARTCOMPOSITION && msg <= WM_IME_KEYLAST) ||
            (msg == WM_IME_SETCONTEXT) ||
            (msg == WM_IME_NOTIFY) ||
            (msg == WM_IME_COMPOSITIONFULL) ||
            (msg == WM_IME_SELECT) ||
            (msg == 0x287 /* FIXME: WM_IME_SYSTEM */))
    {
        if (hWndIME)
            SendMessageA(hWndIME, msg, wParam, lParam);

        return TRUE;
    }
    return FALSE;
}

/***********************************************************************
 *		ImmIsUIMessageW (IMM32.@)
 */
BOOL WINAPI ImmIsUIMessageW(
  HWND hWndIME, UINT msg, WPARAM wParam, LPARAM lParam)
{
    TRACE("(%p, %x, %ld, %ld)\n", hWndIME, msg, wParam, lParam);
    if ((msg >= WM_IME_STARTCOMPOSITION && msg <= WM_IME_KEYLAST) ||
            (msg == WM_IME_SETCONTEXT) ||
            (msg == WM_IME_NOTIFY) ||
            (msg == WM_IME_COMPOSITIONFULL) ||
            (msg == WM_IME_SELECT) ||
            (msg == 0x287 /* FIXME: WM_IME_SYSTEM */))
    {
        if (hWndIME)
            SendMessageW(hWndIME, msg, wParam, lParam);

        return TRUE;
    }
    return FALSE;
}

/***********************************************************************
 *		ImmNotifyIME (IMM32.@)
 */
BOOL WINAPI ImmNotifyIME(
  HIMC hIMC, DWORD dwAction, DWORD dwIndex, DWORD dwValue)
{
    DWORD dwImeThreadId, dwThreadId;
    HKL hKL;
    PIMEDPI pImeDpi;
    BOOL ret;

    TRACE("ImmNotifyIME(%p, %lu, %lu, %lu)\n", hIMC, dwAction, dwIndex, dwValue);

    if (hIMC)
    {
        dwImeThreadId = Imm32QueryWindow(hIMC, QUERY_WINDOW_UNIQUE_THREAD_ID);
        dwThreadId = GetCurrentThreadId();
        if (dwImeThreadId != dwThreadId)
            return FALSE;
    }

    hKL = GetKeyboardLayout(0);
    pImeDpi = ImmLockImeDpi(hKL);
    if (pImeDpi == NULL)
        return FALSE;

    ret = pImeDpi->NotifyIME(hIMC, dwAction, dwIndex, dwValue);
    ImmUnlockImeDpi(pImeDpi);
    return ret;
}

/***********************************************************************
 *		ImmRegisterWordA (IMM32.@)
 */
BOOL WINAPI ImmRegisterWordA(
  HKL hKL, LPCSTR lpszReading, DWORD dwStyle, LPCSTR lpszRegister)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);
    TRACE("(%p, %s, %d, %s):\n", hKL, debugstr_a(lpszReading), dwStyle,
                    debugstr_a(lpszRegister));
    if (immHkl->hIME && immHkl->pImeRegisterWord)
    {
        if (!is_kbd_ime_unicode(immHkl))
            return immHkl->pImeRegisterWord((LPCWSTR)lpszReading,dwStyle,
                                            (LPCWSTR)lpszRegister);
        else
        {
            LPWSTR lpszwReading = strdupAtoW(lpszReading);
            LPWSTR lpszwRegister = strdupAtoW(lpszRegister);
            BOOL rc;

            rc = immHkl->pImeRegisterWord(lpszwReading,dwStyle,lpszwRegister);
            HeapFree(GetProcessHeap(),0,lpszwReading);
            HeapFree(GetProcessHeap(),0,lpszwRegister);
            return rc;
        }
    }
    else
        return FALSE;
}

/***********************************************************************
 *		ImmRegisterWordW (IMM32.@)
 */
BOOL WINAPI ImmRegisterWordW(
  HKL hKL, LPCWSTR lpszReading, DWORD dwStyle, LPCWSTR lpszRegister)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);
    TRACE("(%p, %s, %d, %s):\n", hKL, debugstr_w(lpszReading), dwStyle,
                    debugstr_w(lpszRegister));
    if (immHkl->hIME && immHkl->pImeRegisterWord)
    {
        if (is_kbd_ime_unicode(immHkl))
            return immHkl->pImeRegisterWord(lpszReading,dwStyle,lpszRegister);
        else
        {
            LPSTR lpszaReading = strdupWtoA(lpszReading);
            LPSTR lpszaRegister = strdupWtoA(lpszRegister);
            BOOL rc;

            rc = immHkl->pImeRegisterWord((LPCWSTR)lpszaReading,dwStyle,
                                          (LPCWSTR)lpszaRegister);
            HeapFree(GetProcessHeap(),0,lpszaReading);
            HeapFree(GetProcessHeap(),0,lpszaRegister);
            return rc;
        }
    }
    else
        return FALSE;
}

/***********************************************************************
 *		ImmReleaseContext (IMM32.@)
 */
BOOL WINAPI ImmReleaseContext(HWND hWnd, HIMC hIMC)
{
  static BOOL shown = FALSE;

  if (!shown) {
     FIXME("(%p, %p): stub\n", hWnd, hIMC);
     shown = TRUE;
  }
  return TRUE;
}

/***********************************************************************
*              ImmRequestMessageA(IMM32.@)
*/
LRESULT WINAPI ImmRequestMessageA(HIMC hIMC, WPARAM wParam, LPARAM lParam)
{
    InputContextData *data = get_imc_data(hIMC);

    TRACE("%p %ld %ld\n", hIMC, wParam, wParam);

    if (data) return SendMessageA(data->IMC.hWnd, WM_IME_REQUEST, wParam, lParam);

    SetLastError(ERROR_INVALID_HANDLE);
    return 0;
}

/***********************************************************************
*              ImmRequestMessageW(IMM32.@)
*/
LRESULT WINAPI ImmRequestMessageW(HIMC hIMC, WPARAM wParam, LPARAM lParam)
{
    InputContextData *data = get_imc_data(hIMC);

    TRACE("%p %ld %ld\n", hIMC, wParam, wParam);

    if (data) return SendMessageW(data->IMC.hWnd, WM_IME_REQUEST, wParam, lParam);

    SetLastError(ERROR_INVALID_HANDLE);
    return 0;
}

/***********************************************************************
 *		ImmSetCandidateWindow (IMM32.@)
 */
BOOL WINAPI ImmSetCandidateWindow(
  HIMC hIMC, LPCANDIDATEFORM lpCandidate)
{
    InputContextData *data = get_imc_data(hIMC);

    TRACE("(%p, %p)\n", hIMC, lpCandidate);

    if (!data || !lpCandidate)
        return FALSE;

    if (IMM_IsCrossThreadAccess(NULL, hIMC))
        return FALSE;

    TRACE("\t%x, %x, %s, %s\n",
          lpCandidate->dwIndex, lpCandidate->dwStyle,
          wine_dbgstr_point(&lpCandidate->ptCurrentPos),
          wine_dbgstr_rect(&lpCandidate->rcArea));

    if (lpCandidate->dwIndex >= ARRAY_SIZE(data->IMC.cfCandForm))
        return FALSE;

    data->IMC.cfCandForm[lpCandidate->dwIndex] = *lpCandidate;
    ImmNotifyIME(hIMC, NI_CONTEXTUPDATED, 0, IMC_SETCANDIDATEPOS);
    ImmInternalSendIMENotify(data, IMN_SETCANDIDATEPOS, 1 << lpCandidate->dwIndex);

    return TRUE;
}

/***********************************************************************
 *		ImmSetCompositionFontA (IMM32.@)
 */
BOOL WINAPI ImmSetCompositionFontA(HIMC hIMC, LPLOGFONTA lplf)
{
    InputContextData *data = get_imc_data(hIMC);
    TRACE("(%p, %p)\n", hIMC, lplf);

    if (!data || !lplf)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (IMM_IsCrossThreadAccess(NULL, hIMC))
        return FALSE;

    memcpy(&data->IMC.lfFont.W,lplf,sizeof(LOGFONTA));
    MultiByteToWideChar(CP_ACP, 0, lplf->lfFaceName, -1, data->IMC.lfFont.W.lfFaceName,
                        LF_FACESIZE);
    ImmNotifyIME(hIMC, NI_CONTEXTUPDATED, 0, IMC_SETCOMPOSITIONFONT);
    ImmInternalSendIMENotify(data, IMN_SETCOMPOSITIONFONT, 0);

    return TRUE;
}

/***********************************************************************
 *		ImmSetCompositionFontW (IMM32.@)
 */
BOOL WINAPI ImmSetCompositionFontW(HIMC hIMC, LPLOGFONTW lplf)
{
    InputContextData *data = get_imc_data(hIMC);
    TRACE("(%p, %p)\n", hIMC, lplf);

    if (!data || !lplf)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (IMM_IsCrossThreadAccess(NULL, hIMC))
        return FALSE;

    data->IMC.lfFont.W = *lplf;
    ImmNotifyIME(hIMC, NI_CONTEXTUPDATED, 0, IMC_SETCOMPOSITIONFONT);
    ImmInternalSendIMENotify(data, IMN_SETCOMPOSITIONFONT, 0);

    return TRUE;
}

/***********************************************************************
 *		ImmSetCompositionStringA (IMM32.@)
 */
BOOL WINAPI ImmSetCompositionStringA(
  HIMC hIMC, DWORD dwIndex,
  LPCVOID lpComp, DWORD dwCompLen,
  LPCVOID lpRead, DWORD dwReadLen)
{
    DWORD comp_len;
    DWORD read_len;
    WCHAR *CompBuffer = NULL;
    WCHAR *ReadBuffer = NULL;
    BOOL rc;
    InputContextData *data = get_imc_data(hIMC);

    TRACE("(%p, %d, %p, %d, %p, %d):\n",
            hIMC, dwIndex, lpComp, dwCompLen, lpRead, dwReadLen);

    if (!data)
        return FALSE;

    if (!(dwIndex == SCS_SETSTR ||
          dwIndex == SCS_CHANGEATTR ||
          dwIndex == SCS_CHANGECLAUSE ||
          dwIndex == SCS_SETRECONVERTSTRING ||
          dwIndex == SCS_QUERYRECONVERTSTRING))
        return FALSE;

    if (!is_himc_ime_unicode(data))
        return data->immKbd->pImeSetCompositionString(hIMC, dwIndex, lpComp,
                        dwCompLen, lpRead, dwReadLen);

    comp_len = MultiByteToWideChar(CP_ACP, 0, lpComp, dwCompLen, NULL, 0);
    if (comp_len)
    {
        CompBuffer = HeapAlloc(GetProcessHeap(),0,comp_len * sizeof(WCHAR));
        MultiByteToWideChar(CP_ACP, 0, lpComp, dwCompLen, CompBuffer, comp_len);
    }

    read_len = MultiByteToWideChar(CP_ACP, 0, lpRead, dwReadLen, NULL, 0);
    if (read_len)
    {
        ReadBuffer = HeapAlloc(GetProcessHeap(),0,read_len * sizeof(WCHAR));
        MultiByteToWideChar(CP_ACP, 0, lpRead, dwReadLen, ReadBuffer, read_len);
    }

    rc =  ImmSetCompositionStringW(hIMC, dwIndex, CompBuffer, comp_len,
                                   ReadBuffer, read_len);

    HeapFree(GetProcessHeap(), 0, CompBuffer);
    HeapFree(GetProcessHeap(), 0, ReadBuffer);

    return rc;
}

/***********************************************************************
 *		ImmSetCompositionStringW (IMM32.@)
 */
BOOL WINAPI ImmSetCompositionStringW(
	HIMC hIMC, DWORD dwIndex,
	LPCVOID lpComp, DWORD dwCompLen,
	LPCVOID lpRead, DWORD dwReadLen)
{
    DWORD comp_len;
    DWORD read_len;
    CHAR *CompBuffer = NULL;
    CHAR *ReadBuffer = NULL;
    BOOL rc;
    InputContextData *data = get_imc_data(hIMC);

    TRACE("(%p, %d, %p, %d, %p, %d):\n",
            hIMC, dwIndex, lpComp, dwCompLen, lpRead, dwReadLen);

    if (!data)
        return FALSE;

    if (!(dwIndex == SCS_SETSTR ||
          dwIndex == SCS_CHANGEATTR ||
          dwIndex == SCS_CHANGECLAUSE ||
          dwIndex == SCS_SETRECONVERTSTRING ||
          dwIndex == SCS_QUERYRECONVERTSTRING))
        return FALSE;

    if (is_himc_ime_unicode(data))
        return data->immKbd->pImeSetCompositionString(hIMC, dwIndex, lpComp,
                        dwCompLen, lpRead, dwReadLen);

    comp_len = WideCharToMultiByte(CP_ACP, 0, lpComp, dwCompLen, NULL, 0, NULL,
                                   NULL);
    if (comp_len)
    {
        CompBuffer = HeapAlloc(GetProcessHeap(),0,comp_len);
        WideCharToMultiByte(CP_ACP, 0, lpComp, dwCompLen, CompBuffer, comp_len,
                            NULL, NULL);
    }

    read_len = WideCharToMultiByte(CP_ACP, 0, lpRead, dwReadLen, NULL, 0, NULL,
                                   NULL);
    if (read_len)
    {
        ReadBuffer = HeapAlloc(GetProcessHeap(),0,read_len);
        WideCharToMultiByte(CP_ACP, 0, lpRead, dwReadLen, ReadBuffer, read_len,
                            NULL, NULL);
    }

    rc =  ImmSetCompositionStringA(hIMC, dwIndex, CompBuffer, comp_len,
                                   ReadBuffer, read_len);

    HeapFree(GetProcessHeap(), 0, CompBuffer);
    HeapFree(GetProcessHeap(), 0, ReadBuffer);

    return rc;
}

/***********************************************************************
 *		ImmSetCompositionWindow (IMM32.@)
 */
BOOL WINAPI ImmSetCompositionWindow(
  HIMC hIMC, LPCOMPOSITIONFORM lpCompForm)
{
    DWORD dwImeThreadId, dwThreadId;
    LPINPUTCONTEXT pIC;
    HWND hWnd;

    dwImeThreadId = NtUserQueryInputContext(hIMC, 1);
    dwThreadId = GetCurrentThreadId();
    if (dwImeThreadId != dwThreadId)
        return FALSE;

    pIC = ImmLockIMC(hIMC);
    if (pIC == NULL)
        return FALSE;

    pIC->cfCompForm = *lpCompForm;
    pIC->fdwInit |= INIT_COMPFORM;

    hWnd = pIC->hWnd;

    ImmUnlockIMC(hIMC);

    Imm32NotifyAction(hIMC, hWnd, NI_CONTEXTUPDATED, 0,
                      IMC_SETCOMPOSITIONWINDOW, IMN_SETCOMPOSITIONWINDOW, 0);
    return TRUE;
}

/***********************************************************************
 *		ImmSetConversionStatus (IMM32.@)
 */
BOOL WINAPI ImmSetConversionStatus(
  HIMC hIMC, DWORD fdwConversion, DWORD fdwSentence)
{
    DWORD oldConversion, oldSentence;
    InputContextData *data = get_imc_data(hIMC);

    TRACE("%p %d %d\n", hIMC, fdwConversion, fdwSentence);

    if (!data)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    if (IMM_IsCrossThreadAccess(NULL, hIMC))
        return FALSE;

    if ( fdwConversion != data->IMC.fdwConversion )
    {
        oldConversion = data->IMC.fdwConversion;
        data->IMC.fdwConversion = fdwConversion;
        ImmNotifyIME(hIMC, NI_CONTEXTUPDATED, oldConversion, IMC_SETCONVERSIONMODE);
        ImmInternalSendIMENotify(data, IMN_SETCONVERSIONMODE, 0);
    }
    if ( fdwSentence != data->IMC.fdwSentence )
    {
        oldSentence = data->IMC.fdwSentence;
        data->IMC.fdwSentence = fdwSentence;
        ImmNotifyIME(hIMC, NI_CONTEXTUPDATED, oldSentence, IMC_SETSENTENCEMODE);
        ImmInternalSendIMENotify(data, IMN_SETSENTENCEMODE, 0);
    }

    return TRUE;
}

/***********************************************************************
 *		ImmLockImeDpi (IMM32.@)
 */
PIMEDPI WINAPI ImmLockImeDpi(HKL hKL)
{
    PIMEDPI pImeDpi = NULL;

    TRACE("ImmLockImeDpi(%p)\n", hKL);

    RtlEnterCriticalSection(&g_csImeDpi);

    /* Find by hKL */
    for (pImeDpi = g_pImeDpiList; pImeDpi; pImeDpi = pImeDpi->pNext)
    {
        if (pImeDpi->hKL == hKL) /* found */
        {
            /* lock if possible */
            if (pImeDpi->dwFlags & IMEDPI_FLAG_UNKNOWN)
                pImeDpi = NULL;
            else
                ++(pImeDpi->cLockObj);
            break;
        }
    }

    RtlLeaveCriticalSection(&g_csImeDpi);
    return pImeDpi;
}

/***********************************************************************
 *		ImmUnlockImeDpi (IMM32.@)
 */
VOID WINAPI ImmUnlockImeDpi(PIMEDPI pImeDpi)
{
    PIMEDPI *ppEntry;

    TRACE("ImmUnlockImeDpi(%p)\n", pImeDpi);

    if (pImeDpi == NULL)
        return;

    RtlEnterCriticalSection(&g_csImeDpi);

    /* unlock */
    --(pImeDpi->cLockObj);
    if (pImeDpi->cLockObj != 0)
    {
        RtlLeaveCriticalSection(&g_csImeDpi);
        return;
    }

    if ((pImeDpi->dwFlags & IMEDPI_FLAG_UNKNOWN) == 0)
    {
        if ((pImeDpi->dwFlags & IMEDPI_FLAG_UNKNOWN2) == 0 ||
            (pImeDpi->dwUnknown1 & 1) == 0)
        {
            RtlLeaveCriticalSection(&g_csImeDpi);
            return;
        }
    }

    /* Remove from list */
    for (ppEntry = &g_pImeDpiList; *ppEntry; ppEntry = &((*ppEntry)->pNext))
    {
        if (*ppEntry == pImeDpi) /* found */
        {
            *ppEntry = pImeDpi->pNext;
            break;
        }
    }

    Imm32FreeImeDpi(pImeDpi, TRUE);
    HeapFree(g_hImm32Heap, 0, pImeDpi);

    RtlLeaveCriticalSection(&g_csImeDpi);
}

/***********************************************************************
 *		ImmSetOpenStatus (IMM32.@)
 */
BOOL WINAPI ImmSetOpenStatus(HIMC hIMC, BOOL fOpen)
{
    DWORD dwImeThreadId, dwThreadId, dwConversion;
    LPINPUTCONTEXT pIC;
    HWND hWnd;
    BOOL bHasChange = FALSE;

    TRACE("ImmSetOpenStatus(%p, %d)\n", hIMC, fOpen);

    dwImeThreadId = Imm32QueryInputContext(hIMC, 1);
    dwThreadId = GetCurrentThreadId();
    if (dwImeThreadId != dwThreadId)
        return FALSE;

    pIC = ImmLockIMC(hIMC);
    if (pIC == NULL)
        return FALSE;

    if (pIC->fOpen != fOpen)
    {
        pIC->fOpen = fOpen;
        hWnd = pIC->hWnd;
        dwConversion = pIC->fdwConversion;
        bHasChange = TRUE;
    }

    ImmUnlockIMC(hIMC);

    if (bHasChange)
    {
        Imm32NotifyAction(hIMC, hWnd, NI_CONTEXTUPDATED, 0,
                          IMC_SETOPENSTATUS, IMN_SETOPENSTATUS, 0);
        Imm32NotifyIMEStatus(hWnd, hIMC, dwConversion);
    }

    return TRUE;
}

/***********************************************************************
 *		ImmSetStatusWindowPos (IMM32.@)
 */
BOOL WINAPI ImmSetStatusWindowPos(HIMC hIMC, LPPOINT lpptPos)
{
    LPINPUTCONTEXT pIC;
    HWND hWnd;
    DWORD dwImeThreadId, dwThreadId;

    TRACE("ImmSetStatusWindowPos(%p, {%ld, %ld})\n", hIMC, lpptPos->x, lpptPos->y);

    dwImeThreadId = Imm32QueryInputContext(hIMC, 1);
    dwThreadId = GetCurrentThreadId();
    if (dwImeThreadId != dwThreadId)
        return FALSE;

    pIC = ImmLockIMC(hIMC);
    if (!pIC)
        return FALSE;

    hWnd = pIC->hWnd;
    pIC->ptStatusWndPos = *lpptPos;
    pIC->fdwInit |= INIT_STATUSWNDPOS;

    ImmUnlockIMC(hIMC);

    Imm32NotifyAction(hIMC, hWnd, NI_CONTEXTUPDATED, 0,
                      IMC_SETSTATUSWINDOWPOS, IMN_SETSTATUSWINDOWPOS, 0);
    return TRUE;
}

/***********************************************************************
 *              ImmCreateSoftKeyboard(IMM32.@)
 */
HWND WINAPI ImmCreateSoftKeyboard(UINT uType, UINT hOwner, int x, int y)
{
    FIXME("(%d, %d, %d, %d): stub\n", uType, hOwner, x, y);
    SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
    return 0;
}

/***********************************************************************
 *              ImmDestroySoftKeyboard(IMM32.@)
 */
BOOL WINAPI ImmDestroySoftKeyboard(HWND hSoftWnd)
{
    TRACE("(%p)\n", hSoftWnd);
    return DestroyWindow(hSoftWnd);
}

/***********************************************************************
 *              ImmShowSoftKeyboard(IMM32.@)
 */
BOOL WINAPI ImmShowSoftKeyboard(HWND hSoftWnd, int nCmdShow)
{
    TRACE("(%p, %d)\n", hSoftWnd, nCmdShow);
    if (hSoftWnd)
        return ShowWindow(hSoftWnd, nCmdShow);
    return FALSE;
}

/***********************************************************************
 *		ImmSimulateHotKey (IMM32.@)
 */
BOOL WINAPI ImmSimulateHotKey(HWND hWnd, DWORD dwHotKeyID)
{
    HIMC hIMC;
    DWORD dwThreadId;
    HKL hKL;
    BOOL ret;

    TRACE("ImmSimulateHotKey(%p, 0x%lX)\n", hWnd, dwHotKeyID);

    hIMC = ImmGetContext(hWnd);
    dwThreadId = GetWindowThreadProcessId(hWnd, NULL);
    hKL = GetKeyboardLayout(dwThreadId);
    ret = Imm32ProcessHotKey(hWnd, hIMC, hKL, dwHotKeyID);
    ImmReleaseContext(hWnd, hIMC);
    return ret;
}

/***********************************************************************
 *		ImmUnregisterWordA (IMM32.@)
 */
BOOL WINAPI ImmUnregisterWordA(
  HKL hKL, LPCSTR lpszReading, DWORD dwStyle, LPCSTR lpszUnregister)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);
    TRACE("(%p, %s, %d, %s):\n", hKL, debugstr_a(lpszReading), dwStyle,
            debugstr_a(lpszUnregister));
    if (immHkl->hIME && immHkl->pImeUnregisterWord)
    {
        if (!is_kbd_ime_unicode(immHkl))
            return immHkl->pImeUnregisterWord((LPCWSTR)lpszReading,dwStyle,
                                              (LPCWSTR)lpszUnregister);
        else
        {
            LPWSTR lpszwReading = strdupAtoW(lpszReading);
            LPWSTR lpszwUnregister = strdupAtoW(lpszUnregister);
            BOOL rc;

            rc = immHkl->pImeUnregisterWord(lpszwReading,dwStyle,lpszwUnregister);
            HeapFree(GetProcessHeap(),0,lpszwReading);
            HeapFree(GetProcessHeap(),0,lpszwUnregister);
            return rc;
        }
    }
    else
        return FALSE;
}

/***********************************************************************
 *		ImmUnregisterWordW (IMM32.@)
 */
BOOL WINAPI ImmUnregisterWordW(
  HKL hKL, LPCWSTR lpszReading, DWORD dwStyle, LPCWSTR lpszUnregister)
{
    ImmHkl *immHkl = IMM_GetImmHkl(hKL);
    TRACE("(%p, %s, %d, %s):\n", hKL, debugstr_w(lpszReading), dwStyle,
            debugstr_w(lpszUnregister));
    if (immHkl->hIME && immHkl->pImeUnregisterWord)
    {
        if (is_kbd_ime_unicode(immHkl))
            return immHkl->pImeUnregisterWord(lpszReading,dwStyle,lpszUnregister);
        else
        {
            LPSTR lpszaReading = strdupWtoA(lpszReading);
            LPSTR lpszaUnregister = strdupWtoA(lpszUnregister);
            BOOL rc;

            rc = immHkl->pImeUnregisterWord((LPCWSTR)lpszaReading,dwStyle,
                                            (LPCWSTR)lpszaUnregister);
            HeapFree(GetProcessHeap(),0,lpszaReading);
            HeapFree(GetProcessHeap(),0,lpszaUnregister);
            return rc;
        }
    }
    else
        return FALSE;
}

/***********************************************************************
 *		ImmGetImeMenuItemsA (IMM32.@)
 */
DWORD WINAPI ImmGetImeMenuItemsA( HIMC hIMC, DWORD dwFlags, DWORD dwType,
   LPIMEMENUITEMINFOA lpImeParentMenu, LPIMEMENUITEMINFOA lpImeMenu,
    DWORD dwSize)
{
    InputContextData *data = get_imc_data(hIMC);
    TRACE("(%p, %i, %i, %p, %p, %i):\n", hIMC, dwFlags, dwType,
        lpImeParentMenu, lpImeMenu, dwSize);

    if (!data)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0;
    }

    if (data->immKbd->hIME && data->immKbd->pImeGetImeMenuItems)
    {
        if (!is_himc_ime_unicode(data) || (!lpImeParentMenu && !lpImeMenu))
            return data->immKbd->pImeGetImeMenuItems(hIMC, dwFlags, dwType,
                                (IMEMENUITEMINFOW*)lpImeParentMenu,
                                (IMEMENUITEMINFOW*)lpImeMenu, dwSize);
        else
        {
            IMEMENUITEMINFOW lpImeParentMenuW;
            IMEMENUITEMINFOW *lpImeMenuW, *parent = NULL;
            DWORD rc;

            if (lpImeParentMenu)
                parent = &lpImeParentMenuW;
            if (lpImeMenu)
            {
                int count = dwSize / sizeof(LPIMEMENUITEMINFOA);
                dwSize = count * sizeof(IMEMENUITEMINFOW);
                lpImeMenuW = HeapAlloc(GetProcessHeap(), 0, dwSize);
            }
            else
                lpImeMenuW = NULL;

            rc = data->immKbd->pImeGetImeMenuItems(hIMC, dwFlags, dwType,
                                parent, lpImeMenuW, dwSize);

            if (lpImeParentMenu)
            {
                memcpy(lpImeParentMenu,&lpImeParentMenuW,sizeof(IMEMENUITEMINFOA));
                lpImeParentMenu->hbmpItem = lpImeParentMenuW.hbmpItem;
                WideCharToMultiByte(CP_ACP, 0, lpImeParentMenuW.szString,
                    -1, lpImeParentMenu->szString, IMEMENUITEM_STRING_SIZE,
                    NULL, NULL);
            }
            if (lpImeMenu && rc)
            {
                unsigned int i;
                for (i = 0; i < rc; i++)
                {
                    memcpy(&lpImeMenu[i],&lpImeMenuW[1],sizeof(IMEMENUITEMINFOA));
                    lpImeMenu[i].hbmpItem = lpImeMenuW[i].hbmpItem;
                    WideCharToMultiByte(CP_ACP, 0, lpImeMenuW[i].szString,
                        -1, lpImeMenu[i].szString, IMEMENUITEM_STRING_SIZE,
                        NULL, NULL);
                }
            }
            HeapFree(GetProcessHeap(),0,lpImeMenuW);
            return rc;
        }
    }
    else
        return 0;
}

/***********************************************************************
*		ImmGetImeMenuItemsW (IMM32.@)
*/
DWORD WINAPI ImmGetImeMenuItemsW( HIMC hIMC, DWORD dwFlags, DWORD dwType,
   LPIMEMENUITEMINFOW lpImeParentMenu, LPIMEMENUITEMINFOW lpImeMenu,
   DWORD dwSize)
{
    InputContextData *data = get_imc_data(hIMC);
    TRACE("(%p, %i, %i, %p, %p, %i):\n", hIMC, dwFlags, dwType,
        lpImeParentMenu, lpImeMenu, dwSize);

    if (!data)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return 0;
    }

    if (data->immKbd->hIME && data->immKbd->pImeGetImeMenuItems)
    {
        if (is_himc_ime_unicode(data) || (!lpImeParentMenu && !lpImeMenu))
            return data->immKbd->pImeGetImeMenuItems(hIMC, dwFlags, dwType,
                                lpImeParentMenu, lpImeMenu, dwSize);
        else
        {
            IMEMENUITEMINFOA lpImeParentMenuA;
            IMEMENUITEMINFOA *lpImeMenuA, *parent = NULL;
            DWORD rc;

            if (lpImeParentMenu)
                parent = &lpImeParentMenuA;
            if (lpImeMenu)
            {
                int count = dwSize / sizeof(LPIMEMENUITEMINFOW);
                dwSize = count * sizeof(IMEMENUITEMINFOA);
                lpImeMenuA = HeapAlloc(GetProcessHeap(), 0, dwSize);
            }
            else
                lpImeMenuA = NULL;

            rc = data->immKbd->pImeGetImeMenuItems(hIMC, dwFlags, dwType,
                                (IMEMENUITEMINFOW*)parent,
                                (IMEMENUITEMINFOW*)lpImeMenuA, dwSize);

            if (lpImeParentMenu)
            {
                memcpy(lpImeParentMenu,&lpImeParentMenuA,sizeof(IMEMENUITEMINFOA));
                lpImeParentMenu->hbmpItem = lpImeParentMenuA.hbmpItem;
                MultiByteToWideChar(CP_ACP, 0, lpImeParentMenuA.szString,
                    -1, lpImeParentMenu->szString, IMEMENUITEM_STRING_SIZE);
            }
            if (lpImeMenu && rc)
            {
                unsigned int i;
                for (i = 0; i < rc; i++)
                {
                    memcpy(&lpImeMenu[i],&lpImeMenuA[1],sizeof(IMEMENUITEMINFOA));
                    lpImeMenu[i].hbmpItem = lpImeMenuA[i].hbmpItem;
                    MultiByteToWideChar(CP_ACP, 0, lpImeMenuA[i].szString,
                        -1, lpImeMenu[i].szString, IMEMENUITEM_STRING_SIZE);
                }
            }
            HeapFree(GetProcessHeap(),0,lpImeMenuA);
            return rc;
        }
    }
    else
        return 0;
}

/***********************************************************************
*		ImmLockIMC(IMM32.@)
*/
LPINPUTCONTEXT WINAPI ImmLockIMC(HIMC hIMC)
{
    InputContextData *data = get_imc_data(hIMC);

    if (!data)
        return NULL;
    data->dwLock++;
    return &data->IMC;
}

/***********************************************************************
*		ImmUnlockIMC(IMM32.@)
*/
BOOL WINAPI ImmUnlockIMC(HIMC hIMC)
{
    PCLIENTIMC pClientImc;
    HIMC hClientImc;

    pClientImc = ImmLockClientImc(hIMC);
    if (pClientImc == NULL)
        return FALSE;

    hClientImc = pClientImc->hImc;
    if (hClientImc)
        LocalUnlock(hClientImc);

    InterlockedDecrement(&pClientImc->cLockObj);
    ImmUnlockClientImc(pClientImc);
    return TRUE;
}

/***********************************************************************
*		ImmGetIMCLockCount(IMM32.@)
*/
DWORD WINAPI ImmGetIMCLockCount(HIMC hIMC)
{
    DWORD ret;
    HIMC hClientImc;
    PCLIENTIMC pClientImc;

    pClientImc = ImmLockClientImc(hIMC);
    if (pClientImc == NULL)
        return 0;

    ret = 0;
    hClientImc = pClientImc->hImc;
    if (hClientImc)
        ret = (LocalFlags(hClientImc) & LMEM_LOCKCOUNT);

    ImmUnlockClientImc(pClientImc);
    return ret;
}

/***********************************************************************
*		ImmCreateIMCC(IMM32.@)
*/
HIMCC  WINAPI ImmCreateIMCC(DWORD size)
{
    if (size < 4)
        size = 4;
    return LocalAlloc(LHND, size);
}

/***********************************************************************
*       ImmDestroyIMCC(IMM32.@)
*/
HIMCC WINAPI ImmDestroyIMCC(HIMCC block)
{
    if (block)
        return LocalFree(block);
    return NULL;
}

/***********************************************************************
*		ImmLockIMCC(IMM32.@)
*/
LPVOID WINAPI ImmLockIMCC(HIMCC imcc)
{
    if (imcc)
        return LocalLock(imcc);
    return NULL;
}

/***********************************************************************
*		ImmUnlockIMCC(IMM32.@)
*/
BOOL WINAPI ImmUnlockIMCC(HIMCC imcc)
{
    if (imcc)
        return LocalUnlock(imcc);
    return FALSE;
}

/***********************************************************************
*		ImmGetIMCCLockCount(IMM32.@)
*/
DWORD WINAPI ImmGetIMCCLockCount(HIMCC imcc)
{
    return LocalFlags(imcc) & LMEM_LOCKCOUNT;
}

/***********************************************************************
*		ImmReSizeIMCC(IMM32.@)
*/
HIMCC  WINAPI ImmReSizeIMCC(HIMCC imcc, DWORD size)
{
    if (!imcc)
        return NULL;
    return LocalReAlloc(imcc, size, LHND);
}

/***********************************************************************
*		ImmGetIMCCSize(IMM32.@)
*/
DWORD WINAPI ImmGetIMCCSize(HIMCC imcc)
{
    if (imcc)
        return LocalSize(imcc);
    return 0;
}

/***********************************************************************
*		ImmGenerateMessage(IMM32.@)
*/
BOOL WINAPI ImmGenerateMessage(HIMC hIMC)
{
    InputContextData *data = get_imc_data(hIMC);

    if (!data)
    {
        SetLastError(ERROR_INVALID_HANDLE);
        return FALSE;
    }

    TRACE("%i messages queued\n",data->IMC.dwNumMsgBuf);
    if (data->IMC.dwNumMsgBuf > 0)
    {
        LPTRANSMSG lpTransMsg;
        HIMCC hMsgBuf;
        DWORD i, dwNumMsgBuf;

        /* We are going to detach our hMsgBuff so that if processing messages
           generates new messages they go into a new buffer */
        hMsgBuf = data->IMC.hMsgBuf;
        dwNumMsgBuf = data->IMC.dwNumMsgBuf;

        data->IMC.hMsgBuf = ImmCreateIMCC(0);
        data->IMC.dwNumMsgBuf = 0;

        lpTransMsg = ImmLockIMCC(hMsgBuf);
        for (i = 0; i < dwNumMsgBuf; i++)
            ImmInternalSendIMEMessage(data, lpTransMsg[i].message, lpTransMsg[i].wParam, lpTransMsg[i].lParam);

        ImmUnlockIMCC(hMsgBuf);
        ImmDestroyIMCC(hMsgBuf);
    }

    return TRUE;
}

/***********************************************************************
*       ImmTranslateMessage(IMM32.@)
*       ( Undocumented, call internally and from user32.dll )
*/
BOOL WINAPI ImmTranslateMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lKeyData)
{
    InputContextData *data;
    HIMC imc = ImmGetContext(hwnd);
    BYTE state[256];
    UINT scancode;
    LPVOID list = 0;
    UINT msg_count;
    UINT uVirtKey;
    static const DWORD list_count = 10;

    TRACE("%p %x %x %x\n",hwnd, msg, (UINT)wParam, (UINT)lKeyData);

    if (imc)
        data = imc;
    else
        return FALSE;

    if (!data->immKbd->hIME || !data->immKbd->pImeToAsciiEx)
        return FALSE;

    GetKeyboardState(state);
    scancode = lKeyData >> 0x10 & 0xff;

    list = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, list_count * sizeof(TRANSMSG) + sizeof(DWORD));
    ((DWORD*)list)[0] = list_count;

    if (data->immKbd->imeInfo.fdwProperty & IME_PROP_KBD_CHAR_FIRST)
    {
        WCHAR chr;

        if (!is_himc_ime_unicode(data))
            ToAscii(data->lastVK, scancode, state, &chr, 0);
        else
            ToUnicodeEx(data->lastVK, scancode, state, &chr, 1, 0, GetKeyboardLayout(0));
        uVirtKey = MAKELONG(data->lastVK,chr);
    }
    else
        uVirtKey = data->lastVK;

    msg_count = data->immKbd->pImeToAsciiEx(uVirtKey, scancode, state, list, 0, imc);
    TRACE("%i messages generated\n",msg_count);
    if (msg_count && msg_count <= list_count)
    {
        UINT i;
        LPTRANSMSG msgs = (LPTRANSMSG)((LPBYTE)list + sizeof(DWORD));

        for (i = 0; i < msg_count; i++)
            ImmInternalPostIMEMessage(data, msgs[i].message, msgs[i].wParam, msgs[i].lParam);
    }
    else if (msg_count > list_count)
        ImmGenerateMessage(imc);

    HeapFree(GetProcessHeap(),0,list);

    data->lastVK = VK_PROCESSKEY;

    return (msg_count > 0);
}

/***********************************************************************
*		ImmProcessKey(IMM32.@)
*       ( Undocumented, called from user32.dll )
*/
BOOL WINAPI ImmProcessKey(HWND hwnd, HKL hKL, UINT vKey, LPARAM lKeyData, DWORD unknown)
{
    InputContextData *data;
    HIMC imc = ImmGetContext(hwnd);
    BYTE state[256];

    TRACE("%p %p %x %x %x\n",hwnd, hKL, vKey, (UINT)lKeyData, unknown);

    if (imc)
        data = imc;
    else
        return FALSE;

    /* Make sure we are inputting to the correct keyboard */
    if (data->immKbd->hkl != hKL)
    {
        ImmHkl *new_hkl = IMM_GetImmHkl(hKL);
        if (new_hkl)
        {
            data->immKbd->pImeSelect(imc, FALSE);
            data->immKbd->uSelected--;
            data->immKbd = new_hkl;
            data->immKbd->pImeSelect(imc, TRUE);
            data->immKbd->uSelected++;
        }
        else
            return FALSE;
    }

    if (!data->immKbd->hIME || !data->immKbd->pImeProcessKey)
        return FALSE;

    GetKeyboardState(state);
    if (data->immKbd->pImeProcessKey(imc, vKey, lKeyData, state))
    {
        data->lastVK = vKey;
        return TRUE;
    }

    data->lastVK = VK_PROCESSKEY;
    return FALSE;
}

/***********************************************************************
*		ImmDisableTextFrameService(IMM32.@)
*/
BOOL WINAPI ImmDisableTextFrameService(DWORD dwThreadId)
{
    FIXME("Stub\n");
    return FALSE;
}

/***********************************************************************
 *              ImmEnumInputContext(IMM32.@)
 */
BOOL WINAPI ImmEnumInputContext(DWORD dwThreadId, IMCENUMPROC lpfn, LPARAM lParam)
{
    HIMC *phList;
    DWORD dwIndex, dwCount;
    BOOL ret = TRUE;
    HIMC hIMC;

    TRACE("ImmEnumInputContext(%lu, %p, %p)\n", dwThreadId, lpfn, lParam);

    dwCount = Imm32AllocAndBuildHimcList(dwThreadId, &phList);
    if (!dwCount)
        return FALSE;

    for (dwIndex = 0; dwIndex < dwCount; ++dwIndex)
    {
        hIMC = phList[dwIndex];
        ret = (*lpfn)(hIMC, lParam);
        if (!ret)
            break;
    }

    HeapFree(g_hImm32Heap, 0, phList);
    return ret;
}

/***********************************************************************
 *              ImmGetHotKey(IMM32.@)
 */

BOOL WINAPI
ImmGetHotKey(IN DWORD dwHotKey,
             OUT LPUINT lpuModifiers,
             OUT LPUINT lpuVKey,
             OUT LPHKL lphKL)
{
    TRACE("%lx, %p, %p, %p\n", dwHotKey, lpuModifiers, lpuVKey, lphKL);
    if (lpuModifiers && lpuVKey)
        return NtUserGetImeHotKey(dwHotKey, lpuModifiers, lpuVKey, lphKL);
    return FALSE;
}

/***********************************************************************
 *              ImmDisableLegacyIME(IMM32.@)
 */
BOOL WINAPI ImmDisableLegacyIME(void)
{
    FIXME("stub\n");
    return TRUE;
}

/***********************************************************************
 *              ImmSetActiveContext(IMM32.@)
 */
BOOL WINAPI ImmSetActiveContext(HWND hwnd, HIMC hIMC, BOOL fFlag)
{
    FIXME("(%p, %p, %d): stub\n", hwnd, hIMC, fFlag);
    return FALSE;
}

/***********************************************************************
 *              ImmSetActiveContextConsoleIME(IMM32.@)
 */
BOOL WINAPI ImmSetActiveContextConsoleIME(HWND hwnd, BOOL fFlag)
{
    HIMC hIMC;
    TRACE("(%p, %d)\n", hwnd, fFlag);

    hIMC = ImmGetContext(hwnd);
    if (hIMC)
        return ImmSetActiveContext(hwnd, hIMC, fFlag);
    return FALSE;
}

/***********************************************************************
*		ImmRegisterClient(IMM32.@)
*       ( Undocumented, called from user32.dll )
*/
BOOL WINAPI ImmRegisterClient(PVOID ptr, /* FIXME: should point to SHAREDINFO structure */
                              HINSTANCE hMod)
{
    FIXME("Stub\n");
    return TRUE;
}

/***********************************************************************
 *		CtfImmIsTextFrameServiceDisabled(IMM32.@)
 */
BOOL WINAPI CtfImmIsTextFrameServiceDisabled(VOID)
{
    PTEB pTeb = NtCurrentTeb();
    if (((PW32CLIENTINFO)pTeb->Win32ClientInfo)->CI_flags & CI_TFSDISABLED)
        return TRUE;
    return FALSE;
}

/***********************************************************************
 *              ImmGetImeInfoEx (IMM32.@)
 */

static BOOL APIENTRY Imm32GetImeInfoEx(PIMEINFOEX pImeInfoEx, IMEINFOEXCLASS SearchType)
{
    return NtUserGetImeInfoEx(pImeInfoEx, SearchType);
}

BOOL WINAPI
ImmGetImeInfoEx(PIMEINFOEX pImeInfoEx,
                IMEINFOEXCLASS SearchType,
                PVOID pvSearchKey)
{
    BOOL bDisabled = FALSE;
    HKL hKL;
    PTEB pTeb;

    switch (SearchType)
    {
        case ImeInfoExKeyboardLayout:
            break;

        case ImeInfoExImeWindow:
            bDisabled = CtfImmIsTextFrameServiceDisabled();
            SearchType = ImeInfoExKeyboardLayout;
            break;

        case ImeInfoExImeFileName:
            StringCchCopyW(pImeInfoEx->wszImeFile, _countof(pImeInfoEx->wszImeFile),
                           pvSearchKey);
            goto Quit;
    }

    hKL = *(HKL*)pvSearchKey;
    pImeInfoEx->hkl = hKL;

    if (!IS_IME_HKL(hKL))
    {
        if (g_dwImm32Flags & IMM32_FLAG_CICERO_ENABLED)
        {
            pTeb = NtCurrentTeb();
            if (((PW32CLIENTINFO)pTeb->Win32ClientInfo)->W32ClientInfo[0] & 2)
                return FALSE;
            if (!bDisabled)
                goto Quit;
        }
        return FALSE;
    }

Quit:
    return Imm32GetImeInfoEx(pImeInfoEx, SearchType);
}

static BOOL APIENTRY Imm32InitInstance(HMODULE hMod)
{
    NTSTATUS status;
    SYSTEM_BASIC_INFORMATION info;

    if (hMod)
        g_hImm32Inst = hMod;

    if (g_bClientRegd)
        return TRUE;

    status = RtlInitializeCriticalSection(&g_csImeDpi);
    if (NT_ERROR(status))
        return FALSE;

    status = NtQuerySystemInformation(SystemBasicInformation, &info, sizeof(info), NULL);
    if (NT_ERROR(status))
        return FALSE;

    g_MaximumUserModeAddress = info.MaximumUserModeAddress;
    g_bClientRegd = TRUE;
    return TRUE;
}

BOOL WINAPI User32InitializeImmEntryTable(DWORD);

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    HKL hKL;
    HWND hWnd;
    PTEB pTeb;

    TRACE("DllMain(%p, 0x%X, %p)\n", hinstDLL, fdwReason, lpReserved);

    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            if (!Imm32InitInstance(hinstDLL))
                return FALSE;
            if (!User32InitializeImmEntryTable(IMM_INIT_MAGIC))
                return FALSE;
            break;

        case DLL_THREAD_ATTACH:
            break;

        case DLL_THREAD_DETACH:
            if (g_psi == NULL || !(g_psi->dwSRVIFlags & SRVINFO_IMM32))
                return TRUE;

            pTeb = NtCurrentTeb();
            if (pTeb->Win32ThreadInfo == NULL)
                return TRUE;

            hKL = GetKeyboardLayout(0);
            hWnd = (HWND)Imm32GetThreadState(THREADSTATE_CAPTUREWINDOW);
            Imm32CleanupContext(hWnd, hKL, TRUE);
            break;

        case DLL_PROCESS_DETACH:
            RtlDeleteCriticalSection(&g_csImeDpi);
            break;
    }

    return TRUE;
}
