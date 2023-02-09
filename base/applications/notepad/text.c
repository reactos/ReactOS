/*
 *  Notepad (text.c)
 *
 *  Copyright 1998,99 Marcel Baur <mbaur@g26.ethz.ch>
 *  Copyright 2002 Sylvain Petreolle <spetreolle@yahoo.fr>
 *  Copyright 2002 Andriy Palamarchuk
 *  Copyright 2019-2023 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include "notepad.h"
#include <assert.h>

BOOL IsTextNonZeroASCII(const void *pText, DWORD dwSize)
{
    const signed char *pBytes = pText;
    while (dwSize-- > 0)
    {
        if (*pBytes <= 0)
            return FALSE;

        ++pBytes;
    }
    return TRUE;
}

ENCODING AnalyzeEncoding(const char *pBytes, DWORD dwSize)
{
    INT flags = IS_TEXT_UNICODE_STATISTICS | IS_TEXT_UNICODE_REVERSE_STATISTICS;

    if (dwSize <= 1 || IsTextNonZeroASCII(pBytes, dwSize))
        return ENCODING_ANSI;

    if (IsTextUnicode(pBytes, dwSize, &flags))
        return ENCODING_UTF16LE;

    if ((flags & IS_TEXT_UNICODE_REVERSE_MASK) && !(flags & IS_TEXT_UNICODE_ILLEGAL_CHARS))
        return ENCODING_UTF16BE;

    /* is it UTF-8? */
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, pBytes, dwSize, NULL, 0))
        return ENCODING_UTF8;

    return ENCODING_ANSI;
}

static VOID
ReplaceNewLines(LPWSTR pszNew, SIZE_T cchNew, LPCWSTR pszOld, SIZE_T cchOld)
{
    BOOL bPrevCR = FALSE;
    SIZE_T ichNew, ichOld;

    for (ichOld = ichNew = 0; ichOld < cchOld; ++ichOld)
    {
        WCHAR ch = pszOld[ichOld];

        if (ch == L'\n')
        {
            if (!bPrevCR)
            {
                pszNew[ichNew++] = L'\r';
                pszNew[ichNew++] = L'\n';
            }
        }
        else if (ch == '\r')
        {
            pszNew[ichNew++] = L'\r';
            pszNew[ichNew++] = L'\n';
        }
        else
        {
            pszNew[ichNew++] = ch;
        }

        bPrevCR = (ch == L'\r');
    }

    pszNew[ichNew] = UNICODE_NULL;
    assert(ichNew == cchNew);
}

static BOOL
ProcessNewLinesAndNulls(HLOCAL *phLocal, LPWSTR *ppszText, SIZE_T *pcchText, EOLN *piEoln)
{
    SIZE_T ich, cchText = *pcchText, adwEolnCount[3] = { 0, 0, 0 }, cNonCRLFs;
    LPWSTR pszText = *ppszText;
    EOLN iEoln;
    BOOL bPrevCR = FALSE;

    /* Replace '\0' with SPACE. Count newlines. */
    for (ich = 0; ich < cchText; ++ich)
    {
        WCHAR ch = pszText[ich];
        if (ch == UNICODE_NULL)
            pszText[ich] = L' ';

        if (ch == L'\n')
        {
            if (bPrevCR)
            {
                adwEolnCount[EOLN_CR]--;
                adwEolnCount[EOLN_CRLF]++;
            }
            else
            {
                adwEolnCount[EOLN_LF]++;
            }
        }
        else if (ch == '\r')
        {
            adwEolnCount[EOLN_CR]++;
        }

        bPrevCR = (ch == L'\r');
    }

    /* Choose the newline code */
    if (adwEolnCount[EOLN_CR] > adwEolnCount[EOLN_CRLF])
        iEoln = EOLN_CR;
    else if (adwEolnCount[EOLN_LF] > adwEolnCount[EOLN_CRLF])
        iEoln = EOLN_LF;
    else
        iEoln = EOLN_CRLF;

    cNonCRLFs = adwEolnCount[EOLN_CR] + adwEolnCount[EOLN_LF];
    if (cNonCRLFs != 0)
    {
        /* Allocate a buffer for EM_SETHANDLE */
        SIZE_T cchNew = cchText + cNonCRLFs;
        HLOCAL hLocal = LocalAlloc(LMEM_MOVEABLE, (cchNew + 1) * sizeof(WCHAR));
        LPWSTR pszNew = LocalLock(hLocal);
        if (!pszNew)
        {
            LocalFree(hLocal);
            return FALSE; /* Failure */
        }

        ReplaceNewLines(pszNew, cchNew, pszText, cchText);

        /* Replace with new data */
        LocalUnlock(*phLocal);
        LocalFree(*phLocal);
        *phLocal = hLocal;
        *ppszText = pszNew;
        *pcchText = cchNew;
    }

    *piEoln = iEoln;
    return TRUE;
}

BOOL
ReadText(HANDLE hFile, HLOCAL *phLocal, ENCODING *pencFile, EOLN *piEoln)
{
    PCHAR pBytes = NULL;
    LPWSTR pszText, pszNewText = NULL;
    DWORD dwSize, dwPos;
    SIZE_T i, cchText, cbContent;
    BOOL bSuccess = FALSE;
    ENCODING encFile = ENCODING_ANSI;
    UINT iCodePage;
    HANDLE hMapping = INVALID_HANDLE_VALUE;
    HLOCAL hNewLocal;

    dwSize = GetFileSize(hFile, NULL);
    if (dwSize == INVALID_FILE_SIZE)
        goto done;

    if (dwSize == 0) // If file is empty
    {
        hNewLocal = LocalReAlloc(*phLocal, sizeof(UNICODE_NULL), LMEM_MOVEABLE);
        pszNewText = LocalLock(hNewLocal);
        if (hNewLocal == NULL || pszNewText == NULL)
            goto done;

        *pszNewText = UNICODE_NULL;
        LocalUnlock(hNewLocal);

        *phLocal = hNewLocal;
        *piEoln = EOLN_CRLF;
        *pencFile = ENCODING_UTF8;
        return TRUE;
    }

    hMapping = CreateFileMappingW(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapping == NULL)
        goto done;

    pBytes = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, dwSize);
    if (!pBytes)
        goto done;

    /* Look for Byte Order Marks */
    dwPos = 0;
    if ((dwSize >= 2) && (pBytes[0] == 0xFF) && (pBytes[1] == 0xFE))
    {
        encFile = ENCODING_UTF16LE;
        dwPos += 2;
    }
    else if ((dwSize >= 2) && (pBytes[0] == 0xFE) && (pBytes[1] == 0xFF))
    {
        encFile = ENCODING_UTF16BE;
        dwPos += 2;
    }
    else if ((dwSize >= 3) && (pBytes[0] == 0xEF) && (pBytes[1] == 0xBB) && (pBytes[2] == 0xBF))
    {
        encFile = ENCODING_UTF8BOM;
        dwPos += 3;
    }
    else
    {
        encFile = AnalyzeEncoding((const char *)pBytes, dwSize);
    }

    switch(encFile)
    {
    case ENCODING_UTF16BE:
    case ENCODING_UTF16LE:
    {
        /* Re-allocate the buffer for EM_SETHANDLE */
        pszText = (LPWSTR) &pBytes[dwPos];
        cchText = (dwSize - dwPos) / sizeof(WCHAR);
        hNewLocal = LocalReAlloc(*phLocal, (cchText + 1) * sizeof(WCHAR), LMEM_MOVEABLE);
        pszNewText = LocalLock(hNewLocal);
        if (pszNewText == NULL)
            goto done;

        *phLocal = hNewLocal;
        CopyMemory(pszNewText, pszText, cchText * sizeof(WCHAR));

        if (encFile == ENCODING_UTF16BE) /* big endian; Swap bytes */
        {
            BYTE tmp, *pb = (LPBYTE)pszNewText;
            for (i = 0; i < cchText * 2; i += 2)
            {
                tmp = pb[i];
                pb[i] = pb[i + 1];
                pb[i + 1] = tmp;
            }
        }
        break;
    }

    case ENCODING_ANSI:
    case ENCODING_UTF8:
    case ENCODING_UTF8BOM:
    {
        iCodePage = ((encFile == ENCODING_UTF8 || encFile == ENCODING_UTF8BOM) ? CP_UTF8 : CP_ACP);

        /* Get ready for ANSI-to-Wide conversion */
        cbContent = dwSize - dwPos;
        cchText = 0;
        if (cbContent > 0)
        {
            cchText = MultiByteToWideChar(iCodePage, 0, &pBytes[dwPos], (INT)cbContent, NULL, 0);
            if (cchText == 0)
                goto done;
        }

        /* Re-allocate the buffer for EM_SETHANDLE */
        hNewLocal = LocalReAlloc(*phLocal, (cchText + 1) * sizeof(WCHAR), LMEM_MOVEABLE);
        pszNewText = LocalLock(hNewLocal);
        if (!pszNewText)
            goto done;
        *phLocal = hNewLocal;

        /* Do ANSI-to-Wide conversion */
        if (cbContent > 0)
        {
            if (!MultiByteToWideChar(iCodePage, 0,
                                     &pBytes[dwPos], (INT)cbContent, pszNewText, (INT)cchText))
            {
                goto done;
            }
        }
        break;
    }

    DEFAULT_UNREACHABLE;
    }

    pszNewText[cchText] = UNICODE_NULL;

    if (!ProcessNewLinesAndNulls(phLocal, &pszNewText, &cchText, piEoln))
        goto done;

    *pencFile = encFile;
    bSuccess = TRUE;

done:
    if (pBytes)
        UnmapViewOfFile(pBytes);
    if (hMapping != INVALID_HANDLE_VALUE)
        CloseHandle(hMapping);
    if (pszNewText)
        LocalUnlock(*phLocal);
    return bSuccess;
}

static BOOL WriteEncodedText(HANDLE hFile, LPCWSTR pszText, DWORD dwTextLen, ENCODING encFile)
{
    LPBYTE pBytes = NULL;
    LPBYTE pAllocBuffer = NULL;
    DWORD dwPos = 0;
    DWORD dwByteCount;
    BYTE buffer[1024];
    UINT iCodePage = 0;
    DWORD dwDummy, i;
    BOOL bSuccess = FALSE;
    int iBufferSize, iRequiredBytes;
    BYTE b;

    while(dwPos < dwTextLen)
    {
        switch(encFile)
        {
            case ENCODING_UTF16LE:
                pBytes = (LPBYTE) &pszText[dwPos];
                dwByteCount = (dwTextLen - dwPos) * sizeof(WCHAR);
                dwPos = dwTextLen;
                break;

            case ENCODING_UTF16BE:
                dwByteCount = (dwTextLen - dwPos) * sizeof(WCHAR);
                if (dwByteCount > sizeof(buffer))
                    dwByteCount = sizeof(buffer);

                memcpy(buffer, &pszText[dwPos], dwByteCount);
                for (i = 0; i < dwByteCount; i += 2)
                {
                    b = buffer[i+0];
                    buffer[i+0] = buffer[i+1];
                    buffer[i+1] = b;
                }
                pBytes = (LPBYTE) &buffer[dwPos];
                dwPos += dwByteCount / sizeof(WCHAR);
                break;

            case ENCODING_ANSI:
            case ENCODING_UTF8:
            case ENCODING_UTF8BOM:
                if (encFile == ENCODING_UTF8 || encFile == ENCODING_UTF8BOM)
                    iCodePage = CP_UTF8;
                else
                    iCodePage = CP_ACP;

                iRequiredBytes = WideCharToMultiByte(iCodePage, 0, &pszText[dwPos], dwTextLen - dwPos, NULL, 0, NULL, NULL);
                if (iRequiredBytes <= 0)
                {
                    goto done;
                }
                else if (iRequiredBytes < sizeof(buffer))
                {
                    pBytes = buffer;
                    iBufferSize = sizeof(buffer);
                }
                else
                {
                    pAllocBuffer = (LPBYTE) HeapAlloc(GetProcessHeap(), 0, iRequiredBytes);
                    if (!pAllocBuffer)
                        return FALSE;
                    pBytes = pAllocBuffer;
                    iBufferSize = iRequiredBytes;
                }

                dwByteCount = WideCharToMultiByte(iCodePage, 0, &pszText[dwPos], dwTextLen - dwPos, (LPSTR) pBytes, iBufferSize, NULL, NULL);
                if (!dwByteCount)
                    goto done;

                dwPos = dwTextLen;
                break;

            default:
                goto done;
        }

        if (!WriteFile(hFile, pBytes, dwByteCount, &dwDummy, NULL))
            goto done;

        /* free the buffer, if we have allocated one */
        if (pAllocBuffer)
        {
            HeapFree(GetProcessHeap(), 0, pAllocBuffer);
            pAllocBuffer = NULL;
        }
    }
    bSuccess = TRUE;

done:
    if (pAllocBuffer)
        HeapFree(GetProcessHeap(), 0, pAllocBuffer);
    return bSuccess;
}

BOOL WriteText(HANDLE hFile, LPCWSTR pszText, DWORD dwTextLen, ENCODING encFile, EOLN iEoln)
{
    WCHAR wcBom;
    LPCWSTR pszLF = L"\n";
    DWORD dwPos, dwNext;

    /* Write the proper byte order marks if not ANSI or UTF-8 without BOM */
    if (encFile != ENCODING_ANSI && encFile != ENCODING_UTF8)
    {
        wcBom = 0xFEFF;
        if (!WriteEncodedText(hFile, &wcBom, 1, encFile))
            return FALSE;
    }

    dwPos = 0;

    /* pszText eoln are always \r\n */

    do
    {
        /* Find the next eoln */
        dwNext = dwPos;
        while(dwNext < dwTextLen)
        {
            if (pszText[dwNext] == '\r' && pszText[dwNext + 1] == '\n')
                break;
            dwNext++;
        }

        if (dwNext != dwTextLen)
        {
            switch (iEoln)
            {
            case EOLN_LF:
                /* Write text (without eoln) */
                if (!WriteEncodedText(hFile, &pszText[dwPos], dwNext - dwPos, encFile))
                    return FALSE;
                /* Write eoln */
                if (!WriteEncodedText(hFile, pszLF, 1, encFile))
                    return FALSE;
                break;
            case EOLN_CR:
                /* Write text (including \r as eoln) */
                if (!WriteEncodedText(hFile, &pszText[dwPos], dwNext - dwPos + 1, encFile))
                    return FALSE;
                break;
            case EOLN_CRLF:
                /* Write text (including \r\n as eoln) */
                if (!WriteEncodedText(hFile, &pszText[dwPos], dwNext - dwPos + 2, encFile))
                    return FALSE;
                break;
            default:
                return FALSE;
            }
        }
        else
        {
            /* Write text (without eoln, since this is the end of the file) */
            if (!WriteEncodedText(hFile, &pszText[dwPos], dwNext - dwPos, encFile))
                return FALSE;
        }

        /* Skip \r\n */
        dwPos = dwNext + 2;
    }
    while (dwPos < dwTextLen);

    return TRUE;
}
