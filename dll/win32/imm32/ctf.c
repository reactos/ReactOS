/*
 * PROJECT:     ReactOS IMM32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Implementing the IMM32 Cicero-aware Text Framework (CTF)
 * COPYRIGHT:   Copyright 2022-2023 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>
 */

#include "precomp.h"
#include <msctf.h>
#include <ctfutb.h>

WINE_DEFAULT_DEBUG_CHANNEL(imm);

BOOL
Imm32GetFn(
    _Inout_opt_ FARPROC *ppfn,
    _Inout_ HINSTANCE *phinstDLL,
    _In_ LPCWSTR pszDllName,
    _In_ LPCSTR pszFuncName)
{
    WCHAR szPath[MAX_PATH];

    if (*ppfn)
        return TRUE;

    if (*phinstDLL == NULL)
    {
        Imm32GetSystemLibraryPath(szPath, _countof(szPath), pszDllName);
        *phinstDLL = LoadLibraryExW(szPath, NULL, 0);
        if (*phinstDLL == NULL)
            return FALSE;
    }

    *ppfn = (FARPROC)GetProcAddress(*phinstDLL, pszFuncName);
    return *ppfn != NULL;
}

#define IMM32_GET_FN(ppfn, phinstDLL, dll_name, func_name) \
    Imm32GetFn((FARPROC*)(ppfn), (phinstDLL), (dll_name), #func_name)

/***********************************************************************
 * OLE32.DLL
 */

HINSTANCE g_hOle32 = NULL;

#define OLE32_FN(name) g_pfnOLE32_##name

typedef HRESULT (WINAPI *FN_CoInitializeEx)(LPVOID, DWORD);
typedef VOID    (WINAPI *FN_CoUninitialize)(VOID);
typedef HRESULT (WINAPI *FN_CoRegisterInitializeSpy)(IInitializeSpy*, ULARGE_INTEGER*);
typedef HRESULT (WINAPI *FN_CoRevokeInitializeSpy)(ULARGE_INTEGER);

FN_CoInitializeEx           OLE32_FN(CoInitializeEx)            = NULL;
FN_CoUninitialize           OLE32_FN(CoUninitialize)            = NULL;
FN_CoRegisterInitializeSpy  OLE32_FN(CoRegisterInitializeSpy)   = NULL;
FN_CoRevokeInitializeSpy    OLE32_FN(CoRevokeInitializeSpy)     = NULL;

#define Imm32GetOle32Fn(func_name) \
    IMM32_GET_FN(&OLE32_FN(func_name), &g_hOle32, L"ole32.dll", #func_name)

HRESULT Imm32CoInitializeEx(VOID)
{
    if (!Imm32GetOle32Fn(CoInitializeEx))
        return E_FAIL;

    return OLE32_FN(CoInitializeEx)(NULL, COINIT_APARTMENTTHREADED);
}

VOID Imm32CoUninitialize(VOID)
{
    if (!Imm32GetOle32Fn(CoUninitialize))
        return;

    OLE32_FN(CoUninitialize)();
}

HRESULT Imm32CoRegisterInitializeSpy(IInitializeSpy* spy, ULARGE_INTEGER* cookie)
{
    if (!Imm32GetOle32Fn(CoRegisterInitializeSpy))
        return E_FAIL;

    return OLE32_FN(CoRegisterInitializeSpy)(spy, cookie);
}

HRESULT Imm32CoRevokeInitializeSpy(ULARGE_INTEGER cookie)
{
    if (!Imm32GetOle32Fn(CoRevokeInitializeSpy))
        return E_FAIL;

    return OLE32_FN(CoRevokeInitializeSpy)(cookie);
}

/***********************************************************************
 * MSCTF.DLL
 */

HINSTANCE g_hMsctf = NULL;

#define MSCTF_FN(name) g_pfnMSCTF_##name

typedef HRESULT (WINAPI *FN_TF_CreateLangBarMgr)(ITfLangBarMgr**);
typedef VOID    (WINAPI *FN_TF_InvalidAssemblyListCacheIfExist)(VOID);

FN_TF_CreateLangBarMgr                MSCTF_FN(TF_CreateLangBarMgr)                = NULL;
FN_TF_InvalidAssemblyListCacheIfExist MSCTF_FN(TF_InvalidAssemblyListCacheIfExist) = NULL;

#define Imm32GetMsctfFn(func_name) \
    IMM32_GET_FN(&MSCTF_FN(func_name), &g_hMsctf, L"msctf.dll", #func_name)

HRESULT Imm32TF_CreateLangBarMgr(_Inout_ ITfLangBarMgr **ppBarMgr)
{
    if (!Imm32GetMsctfFn(TF_CreateLangBarMgr))
        return E_FAIL;

    return MSCTF_FN(TF_CreateLangBarMgr)(ppBarMgr);
}

VOID Imm32TF_InvalidAssemblyListCacheIfExist(VOID)
{
    if (!Imm32GetMsctfFn(TF_InvalidAssemblyListCacheIfExist))
        return;

    MSCTF_FN(TF_InvalidAssemblyListCacheIfExist)();
}

/***********************************************************************
 * CTF IME support
 *
 * TSF stands for "Text Services Framework". "Cicero" is the code name of TSF.
 * CTF stands for "Cicero-aware Text Framework".
 *
 * Comparing with old-style IMM IME, the combination of CTF IME and TSF provides
 * new-style and high-level input method.
 *
 * The CTF IME file is a DLL file that the software developer distributes.
 * The export functions of the CTF IME file are defined in "CtfImeTable.h" of
 * this folder.
 */

/* "Active IMM" compatibility flags */
DWORD g_aimm_compat_flags = 0;

/* The instance of the CTF IME file */
HINSTANCE g_hCtfIme = NULL;

/* Define the function types (FN_...) for CTF IME functions */
#undef DEFINE_CTF_IME_FN
#define DEFINE_CTF_IME_FN(func_name, ret_type, params) \
    typedef ret_type (WINAPI *FN_##func_name)params;
#include "CtfImeTable.h"

/* Define the global variables (g_pfn...) for CTF IME functions */
#undef DEFINE_CTF_IME_FN
#define DEFINE_CTF_IME_FN(func_name, ret_type, params) \
    FN_##func_name g_pfn##func_name = NULL;
#include "CtfImeTable.h"

/* The macro that gets the variable name from the CTF IME function name */
#define CTF_IME_FN(func_name) g_pfn##func_name

/* The type of ApphelpCheckIME function in apphelp.dll */
typedef BOOL (WINAPI *FN_ApphelpCheckIME)(_In_z_ LPCWSTR AppName);

/* FIXME: This is kernel32 function. We have to declare this in some header. */
BOOL WINAPI
BaseCheckAppcompatCache(_In_z_ LPCWSTR ApplicationName,
                        _In_ HANDLE FileHandle,
                        _In_opt_z_ LPCWSTR Environment,
                        _Out_ PULONG pdwReason);

/***********************************************************************
 * This function checks whether the app's IME is disabled by application
 * compatibility patcher.
 */
BOOL
Imm32CheckAndApplyAppCompat(
    _In_ ULONG dwReason,
    _In_z_ LPCWSTR pszAppName)
{
    HINSTANCE hinstApphelp;
    FN_ApphelpCheckIME pApphelpCheckIME;

    /* Query the application compatibility patcher */
    if (BaseCheckAppcompatCache(pszAppName, INVALID_HANDLE_VALUE, NULL, &dwReason))
        return TRUE; /* The app's IME is not disabled */

    /* Load apphelp.dll if necessary */
    hinstApphelp = GetModuleHandleW(L"apphelp.dll");
    if (!hinstApphelp)
    {
        hinstApphelp = LoadLibraryW(L"apphelp.dll");
        if (!hinstApphelp)
            return TRUE; /* There is no apphelp.dll. The app's IME is not disabled */
    }

    /* Is ApphelpCheckIME implemented? */
    pApphelpCheckIME = (FN_ApphelpCheckIME)GetProcAddress(hinstApphelp, "ApphelpCheckIME");
    if (!pApphelpCheckIME)
        return TRUE; /* Not implemented. The app's IME is not disabled */

    /* Is the app's IME disabled or not? */
    return pApphelpCheckIME(pszAppName);
}

/***********************************************************************
 * This function loads the CTF IME file if necessary and establishes
 * communication with the CTF IME.
 */
HINSTANCE
Imm32LoadCtfIme(VOID)
{
    BOOL bSuccess = FALSE;
    IMEINFOEX ImeInfoEx;
    WCHAR szImeFile[MAX_PATH];

    /* Lock the IME interface */
    RtlEnterCriticalSection(&gcsImeDpi);

    do
    {
        if (g_hCtfIme) /* Already loaded? */
        {
            bSuccess = TRUE;
            break;
        }

        /*
         * NOTE: (HKL)0x04090409 is English US keyboard (default).
         * The Cicero keyboard logically uses English US keyboard.
         */
        if (!ImmLoadLayout((HKL)ULongToHandle(0x04090409), &ImeInfoEx))
            break;

        /* Build a path string in system32. The installed IME file must be in system32. */
        Imm32GetSystemLibraryPath(szImeFile, _countof(szImeFile), ImeInfoEx.wszImeFile);

        /* Is the CTF IME disabled by app compatibility patcher? */
        if (!Imm32CheckAndApplyAppCompat(0, szImeFile))
            break; /* This IME is disabled */

        /* Load a CTF IME file */
        g_hCtfIme = LoadLibraryW(szImeFile);
        if (!g_hCtfIme)
            break;

        /* Assume success */
        bSuccess = TRUE;

        /* Retrieve the CTF IME functions */
#undef DEFINE_CTF_IME_FN
#define DEFINE_CTF_IME_FN(func_name, ret_type, params) \
        CTF_IME_FN(func_name) = (FN_##func_name)GetProcAddress(g_hCtfIme, #func_name); \
        if (!CTF_IME_FN(func_name)) \
        { \
            bSuccess = FALSE; /* Failed */ \
            break; \
        }
#include "CtfImeTable.h"
    } while (0);

    /* Unload the CTF IME if failed */
    if (!bSuccess)
    {
        /* Set NULL to the function pointers */
#undef DEFINE_CTF_IME_FN
#define DEFINE_CTF_IME_FN(func_name, ret_type, params) CTF_IME_FN(func_name) = NULL;
#include "CtfImeTable.h"

        if (g_hCtfIme)
        {
            FreeLibrary(g_hCtfIme);
            g_hCtfIme = NULL;
        }
    }

    /* Unlock the IME interface */
    RtlLeaveCriticalSection(&gcsImeDpi);

    return g_hCtfIme;
}

/***********************************************************************
 * This function calls the same name function of the CTF IME side.
 */
HRESULT
CtfImeCreateThreadMgr(VOID)
{
    if (!Imm32LoadCtfIme())
        return E_FAIL;

    return CTF_IME_FN(CtfImeCreateThreadMgr)();
}

/***********************************************************************
 * This function calls the same name function of the CTF IME side.
 */
HRESULT
CtfImeDestroyThreadMgr(VOID)
{
    if (!Imm32LoadCtfIme())
        return E_FAIL;

    return CTF_IME_FN(CtfImeDestroyThreadMgr)();
}

/***********************************************************************
 *		CtfAImmIsIME (IMM32.@)
 *
 * @return TRUE if CTF IME or IMM IME is enabled.
 */
BOOL WINAPI
CtfAImmIsIME(_In_ HKL hKL)
{
    TRACE("(%p)\n", hKL);
    if (!Imm32LoadCtfIme())
        return ImmIsIME(hKL);
    return CTF_IME_FN(CtfImeIsIME)(hKL);
}

/***********************************************************************
 *		CtfImmIsCiceroStartedInThread (IMM32.@)
 *
 * @return TRUE if Cicero is started in the current thread.
 */
BOOL WINAPI
CtfImmIsCiceroStartedInThread(VOID)
{
    TRACE("()\n");
    return !!(GetWin32ClientInfo()->CI_flags & 0x200);
}

/***********************************************************************
 *		CtfImmSetAppCompatFlags (IMM32.@)
 *
 * Sets the application compatibility flags.
 */
VOID WINAPI
CtfImmSetAppCompatFlags(_In_ DWORD dwFlags)
{
    TRACE("(0x%08X)\n", dwFlags);
    if (!(dwFlags & 0xF0FFFFFF))
        g_aimm_compat_flags = dwFlags;
}

/***********************************************************************
 * This function calls the same name function of the CTF IME side.
 */
HRESULT
CtfImeCreateInputContext(
    _In_ HIMC hIMC)
{
    if (!Imm32LoadCtfIme())
        return E_FAIL;

    return CTF_IME_FN(CtfImeCreateInputContext)(hIMC);
}

/***********************************************************************
 * This function calls the same name function of the CTF IME side.
 */
HRESULT
CtfImeDestroyInputContext(_In_ HIMC hIMC)
{
    if (!Imm32LoadCtfIme())
        return E_FAIL;

    return CTF_IME_FN(CtfImeDestroyInputContext)(hIMC);
}

/***********************************************************************
 * The callback function to activate CTF IMEs. Used in CtfAImmActivate.
 */
static BOOL CALLBACK
Imm32EnumCreateCtfICProc(
    _In_ HIMC hIMC,
    _In_ LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    CtfImeCreateInputContext(hIMC);
    return TRUE; /* Continue */
}

/***********************************************************************
 * This function calls CtfImeDestroyInputContext if possible.
 */
HRESULT
CtfImmTIMDestroyInputContext(
    _In_ HIMC hIMC)
{
    if (!IS_CICERO_MODE() || (GetWin32ClientInfo()->dwCompatFlags2 & 2))
        return E_NOINTERFACE;

    return CtfImeDestroyInputContext(hIMC);
}

HRESULT
CtfImmTIMCreateInputContext(
    _In_ HIMC hIMC)
{
    TRACE("(%p)\n", hIMC);
    return E_NOTIMPL;
}

/***********************************************************************
 *      CtfAImmActivate (IMM32.@)
 *
 * This function activates "Active IMM" (AIMM) and TSF.
 */
HRESULT WINAPI
CtfAImmActivate(
    _Out_opt_ HINSTANCE *phinstCtfIme)
{
    HRESULT hr;
    HINSTANCE hinstCtfIme;

    TRACE("(%p)\n", phinstCtfIme);

    /* Load a CTF IME file if necessary */
    hinstCtfIme = Imm32LoadCtfIme();

    /* Create a thread manager of the CTF IME */
    hr = CtfImeCreateThreadMgr();
    if (hr == S_OK)
    {
        /* Update CI_... flags of the thread client info */
        GetWin32ClientInfo()->CI_flags |= CI_AIMMACTIVATED; /* Activate AIMM */
        GetWin32ClientInfo()->CI_flags &= ~CI_TSFDISABLED;  /* Enable TSF */

        /* Create the CTF input contexts */
        ImmEnumInputContext(0, Imm32EnumCreateCtfICProc, 0);
    }

    if (phinstCtfIme)
        *phinstCtfIme = hinstCtfIme;

    return hr;
}

/***********************************************************************
 *      CtfAImmDeactivate (IMM32.@)
 *
 * This function de-activates "Active IMM" (AIMM) and TSF.
 */
HRESULT WINAPI
CtfAImmDeactivate(
    _In_ BOOL bDestroy)
{
    HRESULT hr;

    if (!bDestroy)
        return E_FAIL;

    hr = CtfImeDestroyThreadMgr();
    if (hr == S_OK)
    {
        GetWin32ClientInfo()->CI_flags &= ~CI_AIMMACTIVATED; /* Deactivate AIMM */
        GetWin32ClientInfo()->CI_flags |= CI_TSFDISABLED;    /* Disable TSF */
    }

    return hr;
}

/***********************************************************************
 *		CtfImmIsCiceroEnabled (IMM32.@)
 *
 * @return TRUE if Cicero is enabled.
 */
BOOL WINAPI
CtfImmIsCiceroEnabled(VOID)
{
    return IS_CICERO_MODE();
}

/***********************************************************************
 *		CtfImmIsTextFrameServiceDisabled(IMM32.@)
 *
 * @return TRUE if TSF is disabled.
 */
BOOL WINAPI
CtfImmIsTextFrameServiceDisabled(VOID)
{
    return !!(GetWin32ClientInfo()->CI_flags & CI_TSFDISABLED);
}

/***********************************************************************
 *		CtfImmTIMActivate(IMM32.@)
 */
HRESULT WINAPI
CtfImmTIMActivate(_In_ HKL hKL)
{
    FIXME("(%p)\n", hKL);
    return E_NOTIMPL;
}

/***********************************************************************
 *		CtfImmHideToolbarWnd(IMM32.@)
 *
 * Used with CtfImmRestoreToolbarWnd.
 */
DWORD WINAPI
CtfImmHideToolbarWnd(VOID)
{
    ITfLangBarMgr *pBarMgr;
    DWORD dwShowFlags = 0;
    BOOL bShown;

    TRACE("()\n");

    if (FAILED(Imm32TF_CreateLangBarMgr(&pBarMgr)))
        return dwShowFlags;

    if (SUCCEEDED(pBarMgr->lpVtbl->GetShowFloatingStatus(pBarMgr, &dwShowFlags)))
    {
        bShown = !(dwShowFlags & 0x800);
        dwShowFlags &= 0xF;
        if (bShown)
            pBarMgr->lpVtbl->ShowFloating(pBarMgr, 8);
    }

    pBarMgr->lpVtbl->Release(pBarMgr);
    return dwShowFlags;
}

/***********************************************************************
 *		CtfImmRestoreToolbarWnd(IMM32.@)
 *
 * Used with CtfImmHideToolbarWnd.
 */
VOID WINAPI
CtfImmRestoreToolbarWnd(
    _In_ LPVOID pUnused,
    _In_ DWORD dwShowFlags)
{
    HRESULT hr;
    ITfLangBarMgr *pBarMgr;

    UNREFERENCED_PARAMETER(pUnused);

    TRACE("(%p, 0x%X)\n", pUnused, dwShowFlags);

    hr = Imm32TF_CreateLangBarMgr(&pBarMgr);
    if (FAILED(hr))
        return;

    if (dwShowFlags)
        pBarMgr->lpVtbl->ShowFloating(pBarMgr, dwShowFlags);

    pBarMgr->lpVtbl->Release(pBarMgr);
}

BOOL Imm32InsideLoaderLock(VOID)
{
    return (NtCurrentTeb()->ProcessEnvironmentBlock->LoaderLock->OwningThread ==
            NtCurrentTeb()->ClientId.UniqueThread);
}

/* FIXME: Use RTL */
BOOL WINAPI RtlDllShutdownInProgress(VOID)
{
    return FALSE;
}

/***********************************************************************
 *		CtfImmDispatchDefImeMessage(IMM32.@)
 */
LRESULT WINAPI
CtfImmDispatchDefImeMessage(
    _In_ HWND hWnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam)
{
    TRACE("(%p, %u, %p, %p)\n", hWnd, uMsg, wParam, lParam);

    if (RtlDllShutdownInProgress() || Imm32InsideLoaderLock() || !Imm32LoadCtfIme())
        return 0;

    return CTF_IME_FN(CtfImeDispatchDefImeMessage)(hWnd, uMsg, wParam, lParam);
}

/***********************************************************************
 *		CtfImmIsGuidMapEnable(IMM32.@)
 */
BOOL WINAPI
CtfImmIsGuidMapEnable(
    _In_ HIMC hIMC)
{
    DWORD dwThreadId;
    HKL hKL;
    PIMEDPI pImeDpi;
    BOOL ret = FALSE;

    TRACE("(%p)\n", hIMC);

    if (!IS_CICERO_MODE() || IS_16BIT_MODE())
        return ret;

    dwThreadId = (DWORD)NtUserQueryInputContext(hIMC, QIC_INPUTTHREADID);
    hKL = GetKeyboardLayout(dwThreadId);

    if (IS_IME_HKL(hKL))
        return ret;

    pImeDpi = Imm32FindOrLoadImeDpi(hKL);
    if (IS_NULL_UNEXPECTEDLY(pImeDpi))
        return ret;

    ret = pImeDpi->CtfImeIsGuidMapEnable(hIMC);

    ImmUnlockImeDpi(pImeDpi);
    return ret;
}

/***********************************************************************
 *		CtfImmGetGuidAtom(IMM32.@)
 */
HRESULT WINAPI
CtfImmGetGuidAtom(
    _In_ HIMC hIMC,
    _In_ DWORD dwUnknown,
    _Out_ LPDWORD pdwGuidAtom)
{
    HRESULT hr = E_FAIL;
    PIMEDPI pImeDpi;
    DWORD dwThreadId;
    HKL hKL;

    TRACE("(%p, 0xlX, %p)\n", hIMC, dwUnknown, pdwGuidAtom);

    *pdwGuidAtom = 0;

    if (!IS_CICERO_MODE() || IS_16BIT_MODE())
        return hr;

    dwThreadId = (DWORD)NtUserQueryInputContext(hIMC, QIC_INPUTTHREADID);
    hKL = GetKeyboardLayout(dwThreadId);
    if (IS_IME_HKL(hKL))
        return S_OK;

    pImeDpi = Imm32FindOrLoadImeDpi(hKL);
    if (IS_NULL_UNEXPECTEDLY(pImeDpi))
        return hr;

    hr = pImeDpi->CtfImeGetGuidAtom(hIMC, dwUnknown, pdwGuidAtom);

    ImmUnlockImeDpi(pImeDpi);
    return hr;
}
