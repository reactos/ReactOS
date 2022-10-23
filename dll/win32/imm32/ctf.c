/*
 * PROJECT:     ReactOS IMM32
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Implementing the IMM32 Cicero-aware Text Framework (CTF)
 * COPYRIGHT:   Copyright 2022 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>
 */

#include "precomp.h"

WINE_DEFAULT_DEBUG_CHANNEL(imm);

/*
 * NOTE: Microsoft CTF protocol has vulnerability.
 *       If insecure, we don't follow the dangerous design.
 *
 * https://www.zdnet.com/article/vulnerability-in-microsoft-ctf-protocol-goes-back-to-windows-xp/
 * https://googleprojectzero.blogspot.com/2019/08/down-rabbit-hole.html
 */

// Win: LoadCtfIme
HMODULE APIENTRY Imm32LoadCtfIme(VOID)
{
    return NULL;
}

// Win: Internal_CtfImeDestroyInputContext
HRESULT APIENTRY Imm32CtfImeDestroyInputContext(HIMC hIMC)
{
    if (!Imm32LoadCtfIme())
        return E_FAIL;

#if 1
    FIXME("(%p)\n", hIMC);
    return E_NOTIMPL;
#else
    return g_pfnCtfImeDestroyInputContext(hIMC);
#endif
}

// Win: CtfImmTIMDestroyInputContext
HRESULT APIENTRY CtfImmTIMDestroyInputContext(HIMC hIMC)
{
    if (!IS_CICERO_MODE() || (GetWin32ClientInfo()->dwCompatFlags2 & 2))
        return E_NOINTERFACE;

    return Imm32CtfImeDestroyInputContext(hIMC);
}

// Win: CtfImmTIMCreateInputContext
HRESULT APIENTRY CtfImmTIMCreateInputContext(HIMC hIMC)
{
    TRACE("(%p)\n", hIMC);
    return E_NOTIMPL;
}

/***********************************************************************
 *		CtfImmIsCiceroEnabled (IMM32.@)
 */
BOOL WINAPI CtfImmIsCiceroEnabled(VOID)
{
    return IS_CICERO_MODE();
}

/***********************************************************************
 *		CtfImmIsTextFrameServiceDisabled(IMM32.@)
 */
BOOL WINAPI CtfImmIsTextFrameServiceDisabled(VOID)
{
    return !!(GetWin32ClientInfo()->CI_flags & CI_TFSDISABLED);
}

/***********************************************************************
 *		CtfImmTIMActivate(IMM32.@)
 */
HRESULT WINAPI CtfImmTIMActivate(HKL hKL)
{
    FIXME("(%p)\n", hKL);
    return E_NOTIMPL;
}

/***********************************************************************
 *		CtfImmRestoreToolbarWnd(IMM32.@)
 */
VOID WINAPI CtfImmRestoreToolbarWnd(DWORD dwStatus)
{
    FIXME("(0x%lx)\n", dwStatus);
}

/***********************************************************************
 *		CtfImmHideToolbarWnd(IMM32.@)
 */
DWORD WINAPI CtfImmHideToolbarWnd(VOID)
{
    FIXME("()\n");
    return 0;
}

/***********************************************************************
 *		CtfImmDispatchDefImeMessage(IMM32.@)
 */
LRESULT WINAPI CtfImmDispatchDefImeMessage(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    /* FIXME("(%p, %u, %p, %p)\n", hWnd, uMsg, wParam, lParam); */
    return 0;
}

/***********************************************************************
 *		CtfImmIsGuidMapEnable(IMM32.@)
 */
BOOL WINAPI CtfImmIsGuidMapEnable(HIMC hIMC)
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
HRESULT WINAPI CtfImmGetGuidAtom(HIMC hIMC, DWORD dwUnknown, LPDWORD pdwGuidAtom)
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
