/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Private header for imm32.dll
 * COPYRIGHT:   Copyright 2021 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

BOOL WINAPI
ImmGetImeInfoEx(PIMEINFOEX pImeInfoEx, IMEINFOEXCLASS SearchType, PVOID pvSearchKey);

BOOL WINAPI ImmLoadLayout(HKL hKL, PIMEINFOEX pImeInfoEx);
PCLIENTIMC WINAPI ImmLockClientImc(HIMC hImc);
VOID WINAPI ImmUnlockClientImc(PCLIENTIMC pClientImc);
PIMEDPI WINAPI ImmLockImeDpi(HKL hKL);
VOID WINAPI ImmUnlockImeDpi(PIMEDPI pImeDpi);
HRESULT WINAPI CtfImmTIMActivate(HKL hKL);
DWORD WINAPI ImmGetAppCompatFlags(HIMC hIMC);

HRESULT WINAPI CtfAImmActivate(_Out_opt_ HINSTANCE *phinstCtfIme);
HRESULT WINAPI CtfAImmDeactivate(_In_ BOOL bDestroy);
BOOL WINAPI CtfAImmIsIME(_In_ HKL hKL);
BOOL WINAPI CtfImmIsCiceroStartedInThread(VOID);
VOID WINAPI CtfImmSetAppCompatFlags(_In_ DWORD dwFlags);
DWORD WINAPI CtfImmHideToolbarWnd(VOID);
VOID WINAPI CtfImmRestoreToolbarWnd(_In_ LPVOID pUnused, _In_ DWORD dwShowFlags);

LRESULT WINAPI
CtfImmDispatchDefImeMessage(
    _In_ HWND hWnd,
    _In_ UINT uMsg,
    _In_ WPARAM wParam,
    _In_ LPARAM lParam);

#ifdef __cplusplus
} // extern "C"
#endif
