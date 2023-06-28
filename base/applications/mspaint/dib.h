/*
 * PROJECT:    PAINT for ReactOS
 * LICENSE:    LGPL-2.0-or-later (https://spdx.org/licenses/LGPL-2.0-or-later)
 * PURPOSE:    Some DIB related functions
 * COPYRIGHT:  Copyright 2015 Benedikt Freisen <b.freisen@gmx.net>
 */

#pragma once

HBITMAP CreateDIBWithProperties(int width, int height);
HBITMAP CreateMonoBitmap(int width, int height, BOOL bWhite);
HBITMAP CreateColorDIB(int width, int height, COLORREF rgb);
HBITMAP CachedBufferDIB(HBITMAP hbm, int minimalWidth, int minimalHeight);

HBITMAP CopyMonoImage(HBITMAP hbm, INT cx = 0, INT cy = 0);

static inline HBITMAP CopyDIBImage(HBITMAP hbm, INT cx = 0, INT cy = 0)
{
    return (HBITMAP)CopyImage(hbm, IMAGE_BITMAP, cx, cy, LR_COPYRETURNORG | LR_CREATEDIBSECTION);
}

int GetDIBWidth(HBITMAP hbm);

int GetDIBHeight(HBITMAP hbm);

BOOL SaveDIBToFile(HBITMAP hBitmap, LPCTSTR FileName, HDC hDC);

HBITMAP DoLoadImageFile(HWND hwnd, LPCTSTR name, BOOL fIsMainFile);

void ShowFileLoadError(LPCTSTR name);

HBITMAP SetBitmapAndInfo(HBITMAP hBitmap, LPCTSTR name, DWORD dwFileSize, BOOL isFile);

HBITMAP Rotate90DegreeBlt(HDC hDC1, INT cx, INT cy, BOOL bRight, BOOL bMono);

HBITMAP SkewDIB(HDC hDC1, HBITMAP hbm, INT nDegree, BOOL bVertical, BOOL bMono = FALSE);

float PpcmFromDpi(float dpi);

#define ROUND(x) (INT)((x) + 0.5)

HGLOBAL BitmapToClipboardDIB(HBITMAP hBitmap);
HBITMAP BitmapFromClipboardDIB(HGLOBAL hGlobal);
HBITMAP BitmapFromHEMF(HENHMETAFILE hEMF);
