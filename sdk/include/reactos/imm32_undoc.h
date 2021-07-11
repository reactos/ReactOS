/*
 * PROJECT:     ReactOS Kernel
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Private header for imm32.dll
 * COPYRIGHT:   Copyright 2021 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>
 */

#pragma once

/* unconfirmed */
typedef struct tagCLIENTIMC
{
    HIMC hImc;
    LONG cLockObj;
    DWORD dwFlags;
    DWORD unknown;
    RTL_CRITICAL_SECTION cs;
    DWORD unknown2;
    DWORD unknown3;
    BOOL bUnknown4;
} CLIENTIMC, *PCLIENTIMC;

/* flags for CLIENTIMC */
#define CLIENTIMC_WIDE (1 << 0)
#define CLIENTIMC_DISABLED (1 << 6)
#define CLIENTIMC_UNKNOWN2 (1 << 8)

#ifdef __cplusplus
extern "C" {
#endif

BOOL WINAPI
ImmGetImeInfoEx(PIMEINFOEX pImeInfoEx, IMEINFOEXCLASS SearchType, PVOID pvSearchKey);

PCLIENTIMC WINAPI ImmLockClientImc(HIMC hImc);
VOID WINAPI ImmUnlockClientImc(PCLIENTIMC pClientImc);

#ifdef __cplusplus
} // extern "C"
#endif
