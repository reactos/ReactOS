/*
 * PROJECT:     ReactOS Explorer
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     Utility for shdocvw.dll
 * COPYRIGHT:   Copyright 2024 Whindmar Saksit <whindsaks@proton.me>
 */

#pragma once

EXTERN_C HRESULT SHELL_GetIDListFromObject(IUnknown *punk, PIDLIST_ABSOLUTE *ppidl);
EXTERN_C BOOL SHELL_IsEqualAbsoluteID(PCIDLIST_ABSOLUTE a, PCIDLIST_ABSOLUTE b);
EXTERN_C BOOL SHELL_IsVerb(IContextMenu *pcm, UINT_PTR idCmd, LPCWSTR Verb);
EXTERN_C BOOL _ILIsDesktop(LPCITEMIDLIST pidl);

EXTERN_C BOOL WINAPI
IEILIsEqual(_In_ LPCITEMIDLIST pidl1, _In_ LPCITEMIDLIST pidl2, _In_ BOOL bUnknown);
