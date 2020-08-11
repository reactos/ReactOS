/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     LGPL-2.0-or-later (https://spdx.org/licenses/LGPL-2.0-or-later)
 * PURPOSE:     Test for SHChangeNotify
 * COPYRIGHT:   Copyright 2020 Katayama Hirofumi MZ (katayama.hirofumi.mz@gmail.com)
 */

#include "shelltest.h"
#include <shlwapi.h>
#include <stdio.h>
#include "SHChangeNotify.h"

#define DONT_SEND 0x24242424

static HWND s_hwnd = NULL;
static const WCHAR s_szName[] = L"SHChangeNotify testcase";
static WCHAR s_szSubProgram[MAX_PATH];

typedef void (*ACTION)(void);

typedef struct TEST_ENTRY
{
    INT line;
    DWORD event;
    LPCVOID item1;
    LPCVOID item2;
    LPCSTR pattern;
    ACTION action;
    LPCWSTR path1;
    LPCWSTR path2;
} TEST_ENTRY;

static BOOL
DoCreateEmptyFile(LPCWSTR pszFileName)
{
    FILE *fp = _wfopen(pszFileName, L"wb");
    fclose(fp);
    return fp != NULL;
}

static void
DoAction1(void)
{
    ok_int(CreateDirectoryW(s_dir2, NULL), TRUE);
}

static void
DoAction2(void)
{
    ok_int(RemoveDirectoryW(s_dir2), TRUE);
}

static void
DoAction3(void)
{
    ok_int(MoveFileExW(s_dir2, s_dir3, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING), TRUE);
}

static void
DoAction4(void)
{
    ok_int(DoCreateEmptyFile(s_file1), TRUE);
}

static void
DoAction5(void)
{
    ok_int(MoveFileExW(s_file1, s_file2, MOVEFILE_COPY_ALLOWED | MOVEFILE_REPLACE_EXISTING), TRUE);
}

static void
DoAction6(void)
{
    ok_int(DeleteFileW(s_file2), TRUE);
}

static void
DoAction7(void)
{
    DeleteFileW(s_file1);
    DeleteFileW(s_file2);
    ok_int(RemoveDirectoryW(s_dir3), TRUE);
}

static void
DoAction8(void)
{
    BOOL ret = RemoveDirectoryW(s_dir1);
    ok(ret, "RemoveDirectoryW failed. GetLastError() == %ld\n", GetLastError());
}

static const TEST_ENTRY s_TestEntriesMode0[] =
{
    {__LINE__, SHCNE_MKDIR, s_dir2, NULL, NULL, DoAction1, NULL, NULL},
    {__LINE__, SHCNE_RMDIR, s_dir2, NULL, "000010000", NULL, s_dir2, L""},
    {__LINE__, SHCNE_RMDIR, s_dir2, NULL, "000010000", DoAction2, s_dir2, L""},
    {__LINE__, SHCNE_MKDIR, s_dir2, NULL, "000100000", DoAction1, s_dir2, L""},
    {__LINE__, SHCNE_RENAMEFOLDER, s_dir2, s_dir3, "000000010", NULL, s_dir2, s_dir3},
    {__LINE__, SHCNE_RENAMEFOLDER, s_dir2, s_dir3, "000000010", DoAction3, s_dir2, s_dir3},
    {__LINE__, SHCNE_CREATE, s_file1, NULL, "010000000", NULL, s_file1, L""},
    {__LINE__, SHCNE_CREATE, s_file1, s_file2, "010000000", NULL, s_file1, s_file2},
    {__LINE__, SHCNE_CREATE, s_file1, NULL, "010000000", DoAction4, s_file1, L""},
    {__LINE__, SHCNE_RENAMEITEM, s_file1, s_file2, "100000000", NULL, s_file1, s_file2},
    {__LINE__, SHCNE_RENAMEITEM, s_file1, s_file2, "100000000", DoAction5, s_file1, s_file2},
    {__LINE__, SHCNE_RENAMEITEM, s_file1, s_file2, "100000000", NULL, s_file1, s_file2},
    {__LINE__, SHCNE_UPDATEITEM, s_file1, NULL, "000000100", NULL, s_file1, L""},
    {__LINE__, SHCNE_UPDATEITEM, s_file2, NULL, "000000100", NULL, s_file2, L""},
    {__LINE__, SHCNE_DELETE, s_file1, NULL, "001000000", NULL, s_file1, L""},
    {__LINE__, SHCNE_DELETE, s_file2, NULL, "001000000", NULL, s_file2, L""},
    {__LINE__, SHCNE_DELETE, s_file2, NULL, "001000000", DoAction6, s_file2, L""},
    {__LINE__, SHCNE_DELETE, s_file2, NULL, "001000000", NULL, s_file2, L""},
    {__LINE__, SHCNE_DELETE, s_file1, NULL, "001000000", NULL, s_file1, L""},
    {__LINE__, SHCNE_RMDIR, s_dir2, NULL, "000010000", NULL, s_dir2, L""},
    {__LINE__, SHCNE_RMDIR, s_dir3, NULL, "000010000", DoAction7, s_dir3, L""},
    {__LINE__, SHCNE_RMDIR, s_dir1, NULL, "000010000", NULL, s_dir1, L""},
    {__LINE__, SHCNE_RMDIR, s_dir1, NULL, "000010000", DoAction8, s_dir1, L""},
};

#define s_TestEntriesMode1 s_TestEntriesMode0
#define s_TestEntriesMode2 s_TestEntriesMode0

static const TEST_ENTRY s_TestEntriesMode3[] =
{
    {__LINE__, DONT_SEND, s_dir2, NULL, NULL, DoAction1, NULL, NULL},
    {__LINE__, DONT_SEND, s_dir2, NULL, "000010000", DoAction2, s_dir2, L""},
    {__LINE__, DONT_SEND, s_dir2, NULL, "000100000", DoAction1, s_dir2, L""},
    {__LINE__, DONT_SEND, s_dir2, s_dir3, "000000010", DoAction3, s_dir2, s_dir3},
    {__LINE__, DONT_SEND, s_file1, NULL, "010000000", DoAction4, s_file1, L""},
    {__LINE__, DONT_SEND, s_file1, s_file2, "100000000", DoAction5, s_file1, s_file2},
    {__LINE__, DONT_SEND, s_file2, NULL, "001000000", DoAction6, s_file2, L""},
    {__LINE__, DONT_SEND, s_dir3, NULL, "000010000", DoAction7, s_dir3, L""},
};

static const TEST_ENTRY s_TestEntriesMode4[] =
{
    {__LINE__, DONT_SEND, s_dir2, NULL, NULL, DoAction1, NULL, NULL},
    {__LINE__, DONT_SEND, s_dir2, NULL, "000010000", DoAction2, s_dir2, L""},
    {__LINE__, DONT_SEND, s_dir2, NULL, "000100000", DoAction1, s_dir2, L""},
    {__LINE__, DONT_SEND, s_dir2, s_dir3, "000000010", DoAction3, s_dir2, s_dir3},
    {__LINE__, DONT_SEND, s_file1, NULL, "010000000", DoAction4, s_file1, L""},
    {__LINE__, DONT_SEND, s_file1, s_file2, "100000000", DoAction5, s_file1, s_file2},
    {__LINE__, DONT_SEND, s_file2, NULL, "001000000", DoAction6, s_file2, L""},
    {__LINE__, DONT_SEND, s_dir3, NULL, "000010000", DoAction7, s_dir3, L""},
};

static const TEST_ENTRY s_TestEntriesMode5[] =
{
    {__LINE__, SHCNE_MKDIR, s_dir2, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_RMDIR, s_dir2, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_MKDIR, s_dir2, NULL, "000000000", DoAction1, NULL, NULL},
    {__LINE__, SHCNE_RMDIR, s_dir2, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_RMDIR, s_dir2, NULL, "000000000", DoAction2, NULL, NULL},
    {__LINE__, SHCNE_MKDIR, s_dir2, NULL, "000000000", DoAction1, NULL, NULL},
    {__LINE__, SHCNE_RENAMEFOLDER, s_dir2, s_dir3, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_RENAMEFOLDER, s_dir2, s_dir3, "000000000", DoAction3, NULL, NULL},
    {__LINE__, SHCNE_CREATE, s_file1, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_CREATE, s_file1, s_file2, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_CREATE, s_file1, NULL, "000000000", DoAction4, NULL, NULL},
    {__LINE__, SHCNE_RENAMEITEM, s_file1, s_file2, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_RENAMEITEM, s_file1, s_file2, "000000000", DoAction5, NULL, NULL},
    {__LINE__, SHCNE_RENAMEITEM, s_file1, s_file2, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_UPDATEITEM, s_file1, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_UPDATEITEM, s_file2, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_UPDATEITEM, s_file1, s_file2, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_UPDATEITEM, s_file2, s_file1, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_DELETE, s_file1, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_DELETE, s_file2, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_DELETE, s_file2, s_file1, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_DELETE, s_file1, s_file2, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_DELETE, s_file2, NULL, "000000000", DoAction6, NULL, NULL},
    {__LINE__, SHCNE_DELETE, s_file2, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_DELETE, s_file1, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_INTERRUPT | SHCNE_RMDIR, s_dir1, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_INTERRUPT | SHCNE_RMDIR, s_dir2, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_INTERRUPT | SHCNE_RMDIR, s_dir3, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_INTERRUPT | SHCNE_RMDIR, s_dir1, s_dir2, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_INTERRUPT | SHCNE_RMDIR, s_dir1, s_dir3, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_INTERRUPT | SHCNE_RMDIR, s_dir2, s_dir1, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_INTERRUPT | SHCNE_RMDIR, s_dir2, s_dir3, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_INTERRUPT | SHCNE_RMDIR, s_dir3, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_INTERRUPT | SHCNE_RMDIR, s_dir3, NULL, "000000000", DoAction7, NULL, NULL},
    {__LINE__, SHCNE_INTERRUPT | SHCNE_RMDIR, s_dir1, NULL, "000000000", NULL, NULL, NULL},
    {__LINE__, SHCNE_INTERRUPT | SHCNE_RMDIR, s_dir1, NULL, "000000000", DoAction8, NULL, NULL},
};

LPCSTR PatternFromFlags(DWORD flags)
{
    static char s_buf[TYPE_FREESPACE + 1 + 1];
    DWORD i;
    for (i = 0; i <= TYPE_FREESPACE; ++i)
    {
        s_buf[i] = (char)('0' + !!(flags & (1 << i)));
    }
    s_buf[i] = 0;
    return s_buf;
}

static BOOL
DoGetClipText(LPWSTR pszPath1, LPWSTR pszPath2)
{
    pszPath1[0] = pszPath2[0] = 0;

    if (!IsClipboardFormatAvailable(CF_UNICODETEXT))
        return FALSE;

    if (!OpenClipboard(NULL))
        return FALSE;

    WCHAR szText[MAX_PATH * 2];
    HGLOBAL hGlobal = GetClipboardData(CF_UNICODETEXT);
    LPWSTR psz = (LPWSTR)GlobalLock(hGlobal);
    lstrcpynW(szText, psz, _countof(szText));
    GlobalUnlock(hGlobal);
    CloseClipboard();

    LPWSTR pch = wcschr(szText, L'|');
    if (pch == NULL)
        return FALSE;

    *pch = 0;
    lstrcpynW(pszPath1, szText, MAX_PATH);
    lstrcpynW(pszPath2, pch + 1, MAX_PATH);
    return TRUE;
}

static void
DoTestEntry(const TEST_ENTRY *entry, SIZE_T nIndex)
{
    if (entry->action)
    {
        (*entry->action)();
    }

    if (entry->event != DONT_SEND)
    {
        SHChangeNotify(entry->event, SHCNF_PATHW | SHCNF_FLUSH, entry->item1, entry->item2);
    }
    else
    {
        SHChangeNotify(0, SHCNF_FLUSH, NULL, NULL);
    }

    DWORD flags = SendMessageW(s_hwnd, WM_GET_NOTIFY_FLAGS, 0, 0);
    LPCSTR pattern = PatternFromFlags(flags);

    if (entry->pattern)
    {
        ok(lstrcmpA(pattern, entry->pattern) == 0 ||
           lstrcmpA(pattern, "000001000") == 0, // SHCNE_UPDATEDIR
           "Line %d: pattern mismatch '%s'\n", entry->line, pattern);
    }

    SendMessageW(s_hwnd, WM_SET_PATHS, 0, 0);
    Sleep(100);

    WCHAR szPath1[MAX_PATH], szPath2[MAX_PATH];
    szPath1[0] = szPath2[0] = 0;
    BOOL bOK = DoGetClipText(szPath1, szPath2);

    if (lstrcmpA(pattern, "000001000") == 0) // SHCNE_UPDATEDIR
    {
        ok(bOK && lstrcmpiW(s_dir1, szPath1) == 0,
           "Line %d: path1 mismatch '%S' (%d)\n", entry->line, szPath1, bOK);
        ok(bOK && lstrcmpiW(L"", szPath2) == 0,
           "Line %d: path2 mismatch '%S' (%d)\n", entry->line, szPath2, bOK);
    }
    else
    {
        if (entry->path1)
            ok(bOK && lstrcmpiW(entry->path1, szPath1) == 0,
               "Line %d: path1 mismatch '%S' (%d)\n", entry->line, szPath1, bOK);
        if (entry->path2)
            ok(bOK && lstrcmpiW(entry->path2, szPath2) == 0,
               "Line %d: path2 mismatch '%S' (%d)\n", entry->line, szPath2, bOK);
    }

    SendMessageW(s_hwnd, WM_CLEAR_FLAGS, 0, 0);
}

static BOOL
DoInit(void)
{
    DoInitPaths();

    CreateDirectoryW(s_dir1, NULL);

    return PathIsDirectoryW(s_dir1);
}

static void
DoEnd(HWND hwnd)
{
    DeleteFileW(s_file1);
    DeleteFileW(s_file2);
    RemoveDirectoryW(s_dir3);
    RemoveDirectoryW(s_dir2);
    RemoveDirectoryW(s_dir1);

    SendMessageW(s_hwnd, WM_COMMAND, IDOK, 0);
}

static BOOL
GetSubProgramPath(void)
{
    GetModuleFileNameW(NULL, s_szSubProgram, _countof(s_szSubProgram));
    PathRemoveFileSpecW(s_szSubProgram);
    PathAppendW(s_szSubProgram, L"shell-notify.exe");

    if (!PathFileExistsW(s_szSubProgram))
    {
        PathRemoveFileSpecW(s_szSubProgram);
        PathAppendW(s_szSubProgram, L"testdata\\shell-notify.exe");

        if (!PathFileExistsW(s_szSubProgram))
        {
            return FALSE;
        }
    }

    return TRUE;
}

static void
JustDoIt(INT nMode)
{
    trace("nMode: %d\n", nMode);
    SHChangeNotify(0, SHCNF_FLUSH, NULL, NULL);

    if (!DoInit())
    {
        skip("Unable to initialize.\n");
        return;
    }

    WCHAR szParams[8];
    wsprintfW(szParams, L"%u", nMode);

    HINSTANCE hinst = ShellExecuteW(NULL, NULL, s_szSubProgram, szParams, NULL, SW_SHOWNORMAL);
    if ((INT_PTR)hinst <= 32)
    {
        skip("Unable to run shell-notify.exe.\n");
        return;
    }

    for (int i = 0; i < 15; ++i)
    {
        s_hwnd = FindWindowW(s_szName, s_szName);
        if (s_hwnd)
            break;

        Sleep(50);
    }

    if (!s_hwnd)
    {
        skip("Unable to find window.\n");
        return;
    }

    switch (nMode)
    {
        case 0:
        case 1:
        case 2:
            for (size_t i = 0; i < _countof(s_TestEntriesMode0); ++i)
            {
                DoTestEntry(&s_TestEntriesMode0[i], i);
            }
            break;
        case 3:
            for (size_t i = 0; i < _countof(s_TestEntriesMode3); ++i)
            {
                DoTestEntry(&s_TestEntriesMode3[i], i);
            }
            break;
        case 4:
            for (size_t i = 0; i < _countof(s_TestEntriesMode4); ++i)
            {
                DoTestEntry(&s_TestEntriesMode4[i], i);
            }
            break;
        case 5:
            for (size_t i = 0; i < _countof(s_TestEntriesMode5); ++i)
            {
                DoTestEntry(&s_TestEntriesMode5[i], i);
            }
            break;
    }

    DoEnd(s_hwnd);

    for (int i = 0; i < 15; ++i)
    {
        s_hwnd = FindWindowW(s_szName, s_szName);
        if (!s_hwnd)
            break;

        Sleep(50);
    }
}

START_TEST(SHChangeNotify)
{
    if (!GetSubProgramPath())
    {
        skip("shell-notify.exe not found\n");
    }

    JustDoIt(0);
    JustDoIt(1);
    JustDoIt(2);
    JustDoIt(3);
    JustDoIt(4);
    JustDoIt(5);
}
