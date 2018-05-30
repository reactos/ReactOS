/*
 *    Open With  Context Menu extension
 *
 * Copyright 2007 Johannes Anderwald <johannes.anderwald@reactos.org>
 * Copyright 2016-2018 Katayama Hirofumi MZ <katayama.hirofumi.mz@gmail.com>
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

#include "precomp.h"

WINE_DEFAULT_DEBUG_CHANNEL (fprop);

/// Folder Options:
/// CLASSKEY = HKEY_CLASSES_ROOT\CLSID\{6DFD7C5C-2451-11d3-A299-00C04F8EF6AF}
/// DefaultIcon = %SystemRoot%\system32\SHELL32.dll,-210
/// Verbs: Open / RunAs
///       Cmd: rundll32.exe shell32.dll,Options_RunDLL 0

/// ShellFolder Attributes: 0x0

typedef struct
{
    WCHAR FileExtension[30];
    WCHAR FileDescription[100];
    WCHAR ClassKey[MAX_PATH];
    WCHAR ClassName[64];
    DWORD EditFlags;
    WCHAR AppName[64];
    HICON hIconLarge;
    HICON hIconSmall;
    WCHAR ProgramPath[MAX_PATH];
    WCHAR IconPath[MAX_PATH];
    INT nIconIndex;
} FOLDER_FILE_TYPE_ENTRY, *PFOLDER_FILE_TYPE_ENTRY;

// uniquely-defined icon entry for Advanced Settings
typedef struct ADVANCED_ICON
{
    WCHAR   szPath[MAX_PATH];
    UINT    nIconIndex;
} ADVANCED_ICON;

// predefined icon IDs (See CreateTreeImageList function below)
#define I_CHECKED                   0
#define I_UNCHECKED                 1
#define I_CHECKED_DISABLED          2
#define I_UNCHECKED_DISABLED        3
#define I_RADIO_CHECKED             4
#define I_RADIO_UNCHECKED           5
#define I_RADIO_CHECKED_DISABLED    6
#define I_RADIO_UNCHECKED_DISABLED  7

#define PREDEFINED_ICON_COUNT       8

// definition of icon stock
static ADVANCED_ICON *  s_AdvancedIcons         = NULL;
static INT              s_AdvancedIconCount     = 0;
static HIMAGELIST       s_hImageList            = NULL;

static INT
Advanced_FindIcon(LPCWSTR pszPath, UINT nIconIndex)
{
    for (INT i = PREDEFINED_ICON_COUNT; i < s_AdvancedIconCount; ++i)
    {
        ADVANCED_ICON *pIcon = &s_AdvancedIcons[i];
        if (pIcon->nIconIndex == nIconIndex &&
            lstrcmpiW(pIcon->szPath, pszPath) == 0)
        {
            return i;   // icon ID
        }
    }
    return -1;  // not found
}

static INT
Advanced_AddIcon(LPCWSTR pszPath, UINT nIconIndex)
{
    ADVANCED_ICON *pAllocated;

    // return the ID if already existed
    INT nIconID = Advanced_FindIcon(pszPath, nIconIndex);
    if (nIconID != -1)
        return nIconID;     // already exists

    // extract a small icon
    HICON hIconSmall = NULL;
    ExtractIconExW(pszPath, nIconIndex, NULL, &hIconSmall, 1);
    if (hIconSmall == NULL)
        return -1;      // failure

    // resize s_AdvancedIcons
    size_t Size = (s_AdvancedIconCount + 1) * sizeof(ADVANCED_ICON);
    pAllocated = (ADVANCED_ICON *)realloc(s_AdvancedIcons, Size);
    if (pAllocated == NULL)
        return -1;      // failure
    else
        s_AdvancedIcons = pAllocated;

    // save icon information
    ADVANCED_ICON *pIcon = &s_AdvancedIcons[s_AdvancedIconCount];
    lstrcpynW(pIcon->szPath, pszPath, _countof(pIcon->szPath));
    pIcon->nIconIndex = nIconIndex;

    // add the icon to the image list
    ImageList_AddIcon(s_hImageList, hIconSmall);

    // increment the counter
    nIconID = s_AdvancedIconCount;
    ++s_AdvancedIconCount;

    DestroyIcon(hIconSmall);

    return nIconID;     // newly-added icon ID
}

// types of Advanced Setting entry
typedef enum ADVANCED_ENTRY_TYPE
{
    AETYPE_GROUP,
    AETYPE_CHECKBOX,
    AETYPE_RADIO,
} ADVANCED_ENTRY_TYPE;

// an entry info of Advanced Settings
typedef struct ADVANCED_ENTRY
{
    DWORD   dwID;                   // entry ID
    DWORD   dwParentID;             // parent entry ID
    DWORD   dwResourceID;           // resource ID
    WCHAR   szKeyName[64];          // entry key name
    DWORD   dwType;                 // ADVANCED_ENTRY_TYPE
    WCHAR   szText[MAX_PATH];       // text
    INT     nIconID;                // icon ID (See ADVANCED_ICON)

    HKEY    hkeyRoot;               // registry root key
    WCHAR   szRegPath[MAX_PATH];    // registry path
    WCHAR   szValueName[64];        // registry value name

    DWORD   dwCheckedValue;         // checked value
    DWORD   dwUncheckedValue;       // unchecked value
    DWORD   dwDefaultValue;         // defalut value
    BOOL    bHasUncheckedValue;     // If FALSE, UncheckedValue is invalid

    HTREEITEM   hItem;              // for TreeView
    BOOL        bGrayed;            // disabled?
    BOOL        bChecked;           // checked?
} ADVANCED_ENTRY, *PADVANCED_ENTRY;

// definition of advanced entries
static ADVANCED_ENTRY *     s_Advanced = NULL;
static INT                  s_AdvancedCount = 0;

static HBITMAP
Create24BppBitmap(HDC hDC, INT cx, INT cy)
{
    BITMAPINFO bi;
    LPVOID pvBits;

    ZeroMemory(&bi, sizeof(bi));
    bi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bi.bmiHeader.biWidth = cx;
    bi.bmiHeader.biHeight = cy;
    bi.bmiHeader.biPlanes = 1;
    bi.bmiHeader.biBitCount = 24;
    bi.bmiHeader.biCompression = BI_RGB;

    HBITMAP hbm = CreateDIBSection(hDC, &bi, DIB_RGB_COLORS, &pvBits, NULL, 0);
    return hbm;
}

static HBITMAP BitmapFromIcon(HICON hIcon, INT cx, INT cy)
{
    HDC hDC = CreateCompatibleDC(NULL);
    if (!hDC)
        return NULL;

    HBITMAP hbm = Create24BppBitmap(hDC, cx, cy);
    if (!hbm)
    {
        DeleteDC(hDC);
        return NULL;
    }

    HGDIOBJ hbmOld = SelectObject(hDC, hbm);
    {
        RECT rc = { 0, 0, cx, cy };
        FillRect(hDC, &rc, HBRUSH(COLOR_3DFACE + 1));
        if (hIcon)
        {
            DrawIconEx(hDC, 0, 0, hIcon, cx, cy, 0, NULL, DI_NORMAL);
        }
    }
    SelectObject(hDC, hbmOld);
    DeleteDC(hDC);

    return hbm;
}

static HBITMAP
CreateCheckImage(HDC hDC, BOOL bCheck, BOOL bEnabled = TRUE)
{
    INT cxSmallIcon = GetSystemMetrics(SM_CXSMICON);
    INT cySmallIcon = GetSystemMetrics(SM_CYSMICON);

    HBITMAP hbm = Create24BppBitmap(hDC, cxSmallIcon, cySmallIcon);
    if (hbm == NULL)
        return NULL;    // failure

    RECT Rect, BoxRect;
    SetRect(&Rect, 0, 0, cxSmallIcon, cySmallIcon);
    BoxRect = Rect;
    InflateRect(&BoxRect, -1, -1);

    HGDIOBJ hbmOld = SelectObject(hDC, hbm);
    {
        UINT uState = DFCS_BUTTONCHECK | DFCS_FLAT | DFCS_MONO;
        if (bCheck)
            uState |= DFCS_CHECKED;
        if (!bEnabled)
            uState |= DFCS_INACTIVE;
        DrawFrameControl(hDC, &BoxRect, DFC_BUTTON, uState);
    }
    SelectObject(hDC, hbmOld);

    return hbm;     // success
}

static HBITMAP
CreateCheckMask(HDC hDC)
{
    INT cxSmallIcon = GetSystemMetrics(SM_CXSMICON);
    INT cySmallIcon = GetSystemMetrics(SM_CYSMICON);

    HBITMAP hbm = CreateBitmap(cxSmallIcon, cySmallIcon, 1, 1, NULL);
    if (hbm == NULL)
        return NULL;    // failure

    RECT Rect, BoxRect;
    SetRect(&Rect, 0, 0, cxSmallIcon, cySmallIcon);
    BoxRect = Rect;
    InflateRect(&BoxRect, -1, -1);

    HGDIOBJ hbmOld = SelectObject(hDC, hbm);
    {
        FillRect(hDC, &Rect, HBRUSH(GetStockObject(WHITE_BRUSH)));
        FillRect(hDC, &BoxRect, HBRUSH(GetStockObject(BLACK_BRUSH)));
    }
    SelectObject(hDC, hbmOld);

    return hbm;     // success
}

static HBITMAP
CreateRadioImage(HDC hDC, BOOL bCheck, BOOL bEnabled = TRUE)
{
    INT cxSmallIcon = GetSystemMetrics(SM_CXSMICON);
    INT cySmallIcon = GetSystemMetrics(SM_CYSMICON);

    HBITMAP hbm = Create24BppBitmap(hDC, cxSmallIcon, cySmallIcon);
    if (hbm == NULL)
        return NULL;    // failure

    RECT Rect, BoxRect;
    SetRect(&Rect, 0, 0, cxSmallIcon, cySmallIcon);
    BoxRect = Rect;
    InflateRect(&BoxRect, -1, -1);

    HGDIOBJ hbmOld = SelectObject(hDC, hbm);
    {
        UINT uState = DFCS_BUTTONRADIOIMAGE | DFCS_FLAT | DFCS_MONO;
        if (bCheck)
            uState |= DFCS_CHECKED;
        if (!bEnabled)
            uState |= DFCS_INACTIVE;
        DrawFrameControl(hDC, &BoxRect, DFC_BUTTON, uState);
    }
    SelectObject(hDC, hbmOld);

    return hbm;     // success
}

static HBITMAP
CreateRadioMask(HDC hDC)
{
    INT cxSmallIcon = GetSystemMetrics(SM_CXSMICON);
    INT cySmallIcon = GetSystemMetrics(SM_CYSMICON);

    HBITMAP hbm = CreateBitmap(cxSmallIcon, cySmallIcon, 1, 1, NULL);
    if (hbm == NULL)
        return NULL;    // failure

    RECT Rect, BoxRect;
    SetRect(&Rect, 0, 0, cxSmallIcon, cySmallIcon);
    BoxRect = Rect;
    InflateRect(&BoxRect, -1, -1);

    HGDIOBJ hbmOld = SelectObject(hDC, hbm);
    {
        FillRect(hDC, &Rect, HBRUSH(GetStockObject(WHITE_BRUSH)));
        UINT uState = DFCS_BUTTONRADIOMASK | DFCS_FLAT | DFCS_MONO;
        DrawFrameControl(hDC, &BoxRect, DFC_BUTTON, uState);
    }
    SelectObject(hDC, hbmOld);

    return hbm;     // success
}

static HIMAGELIST
CreateTreeImageList(VOID)
{
    HIMAGELIST hImageList;
    hImageList = ImageList_Create(16, 16, ILC_COLOR24 | ILC_MASK, 9, 1);
    if (hImageList == NULL)
        return NULL;    // failure

    // free if existed
    if (s_AdvancedIcons)
    {
        free(s_AdvancedIcons);
        s_AdvancedIcons = NULL;
    }
    s_AdvancedIconCount = 0;

    // allocate now
    ADVANCED_ICON *pAllocated;
    size_t Size = PREDEFINED_ICON_COUNT * sizeof(ADVANCED_ICON);
    pAllocated = (ADVANCED_ICON *)calloc(1, Size);
    if (pAllocated == NULL)
        return NULL;    // failure

    s_AdvancedIconCount = PREDEFINED_ICON_COUNT;
    s_AdvancedIcons = pAllocated;

    // add the predefined icons

    HDC hDC = CreateCompatibleDC(NULL);
    HBITMAP hbmMask = CreateCheckMask(hDC);

    HBITMAP hbmChecked, hbmUnchecked;

    hbmChecked = CreateCheckImage(hDC, TRUE);
    ImageList_Add(hImageList, hbmChecked, hbmMask);
    DeleteObject(hbmChecked);

    hbmUnchecked = CreateCheckImage(hDC, FALSE);
    ImageList_Add(hImageList, hbmUnchecked, hbmMask);
    DeleteObject(hbmUnchecked);

    hbmChecked = CreateCheckImage(hDC, TRUE, FALSE);
    ImageList_Add(hImageList, hbmChecked, hbmMask);
    DeleteObject(hbmChecked);

    hbmUnchecked = CreateCheckImage(hDC, FALSE, FALSE);
    ImageList_Add(hImageList, hbmUnchecked, hbmMask);
    DeleteObject(hbmUnchecked);

    DeleteObject(hbmMask);
    hbmMask = CreateRadioMask(hDC);

    hbmChecked = CreateRadioImage(hDC, TRUE);
    ImageList_Add(hImageList, hbmChecked, hbmMask);
    DeleteObject(hbmChecked);

    hbmUnchecked = CreateRadioImage(hDC, FALSE);
    ImageList_Add(hImageList, hbmUnchecked, hbmMask);
    DeleteObject(hbmUnchecked);

    hbmChecked = CreateRadioImage(hDC, TRUE, FALSE);
    ImageList_Add(hImageList, hbmChecked, hbmMask);
    DeleteObject(hbmChecked);

    hbmUnchecked = CreateRadioImage(hDC, FALSE, FALSE);
    ImageList_Add(hImageList, hbmUnchecked, hbmMask);
    DeleteObject(hbmUnchecked);

    DeleteObject(hbmMask);

    return hImageList;
}

static ADVANCED_ENTRY *
Advanced_GetItem(DWORD dwID)
{
    if (dwID == DWORD(-1))
        return NULL;

    for (INT i = 0; i < s_AdvancedCount; ++i)
    {
        ADVANCED_ENTRY *pEntry = &s_Advanced[i];
        if (pEntry->dwID == dwID)
            return pEntry;
    }
    return NULL;    // failure
}

static INT
Advanced_GetImage(ADVANCED_ENTRY *pEntry)
{
    switch (pEntry->dwType)
    {
        case AETYPE_GROUP:
            return pEntry->nIconID;

        case AETYPE_CHECKBOX:
            if (pEntry->bGrayed)
            {
                if (pEntry->bChecked)
                    return I_CHECKED_DISABLED;
                else
                    return I_UNCHECKED_DISABLED;
            }
            else
            {
                if (pEntry->bChecked)
                    return I_CHECKED;
                else
                    return I_UNCHECKED;
            }

        case AETYPE_RADIO:
            if (pEntry->bGrayed)
            {
                if (pEntry->bChecked)
                    return I_RADIO_CHECKED_DISABLED;
                else
                    return I_RADIO_UNCHECKED_DISABLED;
            }
            else
            {
                if (pEntry->bChecked)
                    return I_RADIO_CHECKED;
                else
                    return I_RADIO_UNCHECKED;
            }
    }
    return -1;  // failure
}

static VOID
Advanced_InsertEntry(HWND hwndTreeView, ADVANCED_ENTRY *pEntry)
{
    ADVANCED_ENTRY *pParent = Advanced_GetItem(pEntry->dwParentID);
    HTREEITEM hParent = TVI_ROOT;
    if (pParent)
        hParent = pParent->hItem;

    TV_INSERTSTRUCT Insertion;
    ZeroMemory(&Insertion, sizeof(Insertion));
    Insertion.hParent = hParent;
    Insertion.hInsertAfter = TVI_LAST;
    Insertion.item.mask =
        TVIF_TEXT | TVIF_IMAGE | TVIF_SELECTEDIMAGE | TVIF_PARAM;
    Insertion.item.pszText = pEntry->szText;

    INT iImage = Advanced_GetImage(pEntry);
    Insertion.item.iImage = Insertion.item.iSelectedImage = iImage;
    Insertion.item.lParam = pEntry->dwID;
    pEntry->hItem = TreeView_InsertItem(hwndTreeView, &Insertion);
}

static VOID
Advanced_InsertAll(HWND hwndTreeView)
{
    TreeView_DeleteAllItems(hwndTreeView);

    // insert the entries
    ADVANCED_ENTRY *pEntry;
    for (INT i = 0; i < s_AdvancedCount; ++i)
    {
        pEntry = &s_Advanced[i];
        Advanced_InsertEntry(hwndTreeView, pEntry);
    }

    // expand all
    for (INT i = 0; i < s_AdvancedCount; ++i)
    {
        pEntry = &s_Advanced[i];
        if (pEntry->dwType == AETYPE_GROUP)
        {
            TreeView_Expand(hwndTreeView, pEntry->hItem, TVE_EXPAND);
        }
    }
}

static BOOL
Advanced_LoadTree(HKEY hKey, LPCWSTR pszKeyName, DWORD dwParentID)
{
    DWORD dwIndex;
    WCHAR szKeyName[64], szText[MAX_PATH], *pch;
    DWORD Size, Value;
    ADVANCED_ENTRY *pAllocated;

    // resize s_Advanced
    Size = (s_AdvancedCount + 1) * sizeof(ADVANCED_ENTRY);
    pAllocated = (ADVANCED_ENTRY *)realloc(s_Advanced, Size);
    if (pAllocated == NULL)
        return FALSE;   // failure
    else
        s_Advanced = pAllocated;

    ADVANCED_ENTRY *pEntry = &s_Advanced[s_AdvancedCount];

    // dwID, dwParentID, szKeyName
    pEntry->dwID = s_AdvancedCount;
    pEntry->dwParentID = dwParentID;
    lstrcpynW(pEntry->szKeyName, pszKeyName, _countof(pEntry->szKeyName));

    // Text, ResourceID
    pEntry->szText[0] = 0;
    pEntry->dwResourceID = 0;
    szText[0] = 0;
    Size = sizeof(szText);
    RegQueryValueExW(hKey, L"Text", NULL, NULL, LPBYTE(szText), &Size);
    if (szText[0] == L'@')
    {
        pch = wcsrchr(szText, L',');
        if (pch)
        {
            *pch = 0;
            dwIndex = abs(_wtoi(pch + 1));
            pEntry->dwResourceID = dwIndex;
        }
        HINSTANCE hInst = LoadLibraryW(&szText[1]);
        LoadStringW(hInst, dwIndex, szText, _countof(szText));
        FreeLibrary(hInst);
    }
    else
    {
        pEntry->dwResourceID = DWORD(-1);
    }
    lstrcpynW(pEntry->szText, szText, _countof(pEntry->szText));

    // Type
    szText[0] = 0;
    RegQueryValueExW(hKey, L"Type", NULL, NULL, LPBYTE(szText), &Size);
    if (lstrcmpiW(szText, L"checkbox") == 0)
        pEntry->dwType = AETYPE_CHECKBOX;
    else if (lstrcmpiW(szText, L"radio") == 0)
        pEntry->dwType = AETYPE_RADIO;
    else if (lstrcmpiW(szText, L"group") == 0)
        pEntry->dwType = AETYPE_GROUP;
    else
        return FALSE;   // failure

    pEntry->nIconID = -1;
    if (pEntry->dwType == AETYPE_GROUP)
    {
        // Bitmap (Icon)
        UINT nIconIndex = 0;
        Size = sizeof(szText);
        szText[0] = 0;
        RegQueryValueExW(hKey, L"Bitmap", NULL, NULL, LPBYTE(szText), &Size);

        WCHAR szExpanded[MAX_PATH];
        ExpandEnvironmentStringsW(szText, szExpanded, _countof(szExpanded));
        pch = wcsrchr(szExpanded, L',');
        if (pch)
        {
            *pch = 0;
            nIconIndex = abs(_wtoi(pch + 1));
        }
        pEntry->nIconID = Advanced_AddIcon(szExpanded, nIconIndex);
    }

    if (pEntry->dwType == AETYPE_GROUP)
    {
        pEntry->hkeyRoot = NULL;
        pEntry->szRegPath[0] = 0;
        pEntry->szValueName[0] = 0;
        pEntry->dwCheckedValue = 0;
        pEntry->bHasUncheckedValue = FALSE;
        pEntry->dwUncheckedValue = 0;
        pEntry->dwDefaultValue = 0;
        pEntry->hItem = NULL;
        pEntry->bGrayed = FALSE;
        pEntry->bChecked = FALSE;
    }
    else
    {
        // HKeyRoot
        Value = DWORD(HKEY_CURRENT_USER);
        Size = sizeof(Value);
        RegQueryValueExW(hKey, L"HKeyRoot", NULL, NULL, LPBYTE(&Value), &Size);
        pEntry->hkeyRoot = HKEY(Value);

        // RegPath
        pEntry->szRegPath[0] = 0;
        Size = sizeof(szText);
        RegQueryValueExW(hKey, L"RegPath", NULL, NULL, LPBYTE(szText), &Size);
        lstrcpynW(pEntry->szRegPath, szText, _countof(pEntry->szRegPath));

        // ValueName
        pEntry->szValueName[0] = 0;
        Size = sizeof(szText);
        RegQueryValueExW(hKey, L"ValueName", NULL, NULL, LPBYTE(szText), &Size);
        lstrcpynW(pEntry->szValueName, szText, _countof(pEntry->szValueName));

        // CheckedValue
        Size = sizeof(Value);
        Value = 0x00000001;
        RegQueryValueExW(hKey, L"CheckedValue", NULL, NULL, LPBYTE(&Value), &Size);
        pEntry->dwCheckedValue = Value;

        // UncheckedValue
        Size = sizeof(Value);
        Value = 0x00000000;
        pEntry->bHasUncheckedValue = TRUE;
        if (RegQueryValueExW(hKey, L"UncheckedValue", NULL,
                             NULL, LPBYTE(&Value), &Size) != ERROR_SUCCESS)
        {
            pEntry->bHasUncheckedValue = FALSE;
        }
        pEntry->dwUncheckedValue = Value;

        // DefaultValue
        Size = sizeof(Value);
        Value = 0x00000001;
        RegQueryValueExW(hKey, L"DefaultValue", NULL, NULL, LPBYTE(&Value), &Size);
        pEntry->dwDefaultValue = Value;

        // hItem
        pEntry->hItem = NULL;

        // bGrayed, bChecked
        HKEY hkeyTarget;
        Value = pEntry->dwDefaultValue;
        pEntry->bGrayed = TRUE;
        if (RegOpenKeyExW(HKEY(pEntry->hkeyRoot), pEntry->szRegPath, 0,
                          KEY_READ, &hkeyTarget) == ERROR_SUCCESS)
        {
            Size = sizeof(Value);
            if (RegQueryValueExW(hkeyTarget, pEntry->szValueName, NULL, NULL,
                                 LPBYTE(&Value), &Size) == ERROR_SUCCESS)
            {
                pEntry->bGrayed = FALSE;
            }
            RegCloseKey(hkeyTarget);
        }
        pEntry->bChecked = (Value == pEntry->dwCheckedValue);
    }

    // Grayed (ReactOS extension)
    Size = sizeof(Value);
    Value = FALSE;
    RegQueryValueExW(hKey, L"Grayed", NULL, NULL, LPBYTE(&Value), &Size);
    if (!pEntry->bGrayed)
        pEntry->bGrayed = Value;

    BOOL bIsGroup = (pEntry->dwType == AETYPE_GROUP);
    dwParentID = pEntry->dwID;
    ++s_AdvancedCount;

    if (!bIsGroup)
        return TRUE;    // success

    // load the children
    dwIndex = 0;
    while (RegEnumKeyW(hKey, dwIndex, szKeyName,
                       _countof(szKeyName)) == ERROR_SUCCESS)
    {
        HKEY hkeyChild;
        if (RegOpenKeyExW(hKey, szKeyName, 0, KEY_READ,
                          &hkeyChild) != ERROR_SUCCESS)
        {
            ++dwIndex;
            continue;   // failure
        }

        Advanced_LoadTree(hkeyChild, szKeyName, dwParentID);
        RegCloseKey(hkeyChild);

        ++dwIndex;
    }

    return TRUE;    // success
}

static BOOL
Advanced_LoadAll(VOID)
{
    static const WCHAR s_szAdvanced[] =
        L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced";

    // free if already existed
    if (s_Advanced)
    {
        free(s_Advanced);
        s_Advanced = NULL;
    }
    s_AdvancedCount = 0;

    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, s_szAdvanced, 0,
                      KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        return FALSE;   // failure
    }

    // load the children
    WCHAR szKeyName[64];
    DWORD dwIndex = 0;
    while (RegEnumKeyW(hKey, dwIndex, szKeyName,
                       _countof(szKeyName)) == ERROR_SUCCESS)
    {
        HKEY hkeyChild;
        if (RegOpenKeyExW(hKey, szKeyName, 0, KEY_READ,
                          &hkeyChild) != ERROR_SUCCESS)
        {
            ++dwIndex;
            continue;   // failure
        }

        Advanced_LoadTree(hkeyChild, szKeyName, DWORD(-1));
        RegCloseKey(hkeyChild);

        ++dwIndex;
    }

    RegCloseKey(hKey);

    return TRUE;    // success
}

static int
Advanced_Compare(const void *x, const void *y)
{
    ADVANCED_ENTRY *pEntry1 = (ADVANCED_ENTRY *)x;
    ADVANCED_ENTRY *pEntry2 = (ADVANCED_ENTRY *)y;

    DWORD dwParentID1 = pEntry1->dwParentID;
    DWORD dwParentID2 = pEntry2->dwParentID;

    if (dwParentID1 == dwParentID2)
        return lstrcmpi(pEntry1->szText, pEntry2->szText);

    DWORD i, m, n;
    const UINT MAX_DEPTH = 32;
    ADVANCED_ENTRY *pArray1[MAX_DEPTH];
    ADVANCED_ENTRY *pArray2[MAX_DEPTH];

    // Make ancestor lists
    for (i = m = n = 0; i < MAX_DEPTH; ++i)
    {
        ADVANCED_ENTRY *pParent1 = Advanced_GetItem(dwParentID1);
        ADVANCED_ENTRY *pParent2 = Advanced_GetItem(dwParentID2);
        if (!pParent1 && !pParent2)
            break;

        if (pParent1)
        {
            pArray1[m++] = pParent1;
            dwParentID1 = pParent1->dwParentID;
        }
        if (pParent2)
        {
            pArray2[n++] = pParent2;
            dwParentID2 = pParent2->dwParentID;
        }
    }

    UINT k = min(m, n);
    for (i = 0; i < k; ++i)
    {
        INT nCompare = lstrcmpi(pArray1[m - i - 1]->szText, pArray2[n - i - 1]->szText);
        if (nCompare < 0)
            return -1;
        if (nCompare > 0)
            return 1;
    }

    if (m < n)
        return -1;
    if (m > n)
        return 1;
    return lstrcmpi(pEntry1->szText, pEntry2->szText);
}

static VOID
Advanced_SortAll(VOID)
{
    qsort(s_Advanced, s_AdvancedCount, sizeof(ADVANCED_ENTRY), Advanced_Compare);
}

EXTERN_C HPSXA WINAPI SHCreatePropSheetExtArrayEx(HKEY hKey, LPCWSTR pszSubKey, UINT max_iface, IDataObject *pDataObj);

static VOID
UpdateGeneralIcons(HWND hDlg)
{
    HWND hwndTaskIcon, hwndFolderIcon, hwndClickIcon;
    HICON hTaskIcon = NULL, hFolderIcon = NULL, hClickIcon = NULL;
    LPTSTR lpTaskIconName = NULL, lpFolderIconName = NULL, lpClickIconName = NULL;

    // show task setting icon
    if(IsDlgButtonChecked(hDlg, IDC_FOLDER_OPTIONS_COMMONTASKS) == BST_CHECKED)
        lpTaskIconName = MAKEINTRESOURCE(IDI_SHELL_SHOW_COMMON_TASKS);
    else if(IsDlgButtonChecked(hDlg, IDC_FOLDER_OPTIONS_CLASSICFOLDERS) == BST_CHECKED)
        lpTaskIconName = MAKEINTRESOURCE(IDI_SHELL_CLASSIC_FOLDERS);

    if (lpTaskIconName)
    {
        hTaskIcon = (HICON)LoadImage(shell32_hInstance,
                                              lpTaskIconName,
                                              IMAGE_ICON,
                                              0,
                                              0,
                                              LR_DEFAULTCOLOR);
        if (hTaskIcon)
        {
            hwndTaskIcon = GetDlgItem(hDlg,
                                    IDC_FOLDER_OPTIONS_TASKICON);
            if (hwndTaskIcon)
            {
                SendMessage(hwndTaskIcon,
                            STM_SETIMAGE,
                            IMAGE_ICON,
                            (LPARAM)hTaskIcon);
            }
        }
    }
    
    // show Folder setting icons
    if(IsDlgButtonChecked(hDlg, IDC_FOLDER_OPTIONS_SAMEWINDOW) == BST_CHECKED)
        lpFolderIconName = MAKEINTRESOURCE(IDI_SHELL_OPEN_IN_SOME_WINDOW);
    else if(IsDlgButtonChecked(hDlg, IDC_FOLDER_OPTIONS_OWNWINDOW) == BST_CHECKED)
        lpFolderIconName = MAKEINTRESOURCE(IDI_SHELL_OPEN_IN_NEW_WINDOW);
    
    if (lpFolderIconName)
    {
        hFolderIcon = (HICON)LoadImage(shell32_hInstance,
                                              lpFolderIconName,
                                              IMAGE_ICON,
                                              0,
                                              0,
                                              LR_DEFAULTCOLOR);
        if (hFolderIcon)
        {
            hwndFolderIcon = GetDlgItem(hDlg,
                                    IDC_FOLDER_OPTIONS_FOLDERICON);
            if (hwndFolderIcon)
            {
                SendMessage(hwndFolderIcon,
                            STM_SETIMAGE,
                            IMAGE_ICON,
                            (LPARAM)hFolderIcon);
            }
        }
    }

    // Show click setting icon
    if(IsDlgButtonChecked(hDlg, IDC_FOLDER_OPTIONS_SINGLECLICK) == BST_CHECKED)
        lpClickIconName = MAKEINTRESOURCE(IDI_SHELL_SINGLE_CLICK_TO_OPEN);
    else if(IsDlgButtonChecked(hDlg, IDC_FOLDER_OPTIONS_DOUBLECLICK) == BST_CHECKED)
        lpClickIconName = MAKEINTRESOURCE(IDI_SHELL_DOUBLE_CLICK_TO_OPEN);

    if (lpClickIconName)
    {
        hClickIcon = (HICON)LoadImage(shell32_hInstance,
                                              lpClickIconName,
                                              IMAGE_ICON,
                                              0,
                                              0,
                                              LR_DEFAULTCOLOR);
        if (hClickIcon)
        {
            hwndClickIcon = GetDlgItem(hDlg,
                                    IDC_FOLDER_OPTIONS_CLICKICON);
            if (hwndClickIcon)
            {
                SendMessage(hwndClickIcon,
                            STM_SETIMAGE,
                            IMAGE_ICON,
                            (LPARAM)hClickIcon);
            }
        }
    }

    // Clean up
    if(hTaskIcon)
        DeleteObject(hTaskIcon);
    if(hFolderIcon)
        DeleteObject(hFolderIcon);
    if(hClickIcon)
        DeleteObject(hClickIcon);
    
    return;
}

INT_PTR
CALLBACK
FolderOptionsGeneralDlg(
    HWND hwndDlg,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam
)
{
    switch(uMsg)
    {
        case WM_INITDIALOG:
            // FIXME
            break;
            
        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDC_FOLDER_OPTIONS_COMMONTASKS:
                case IDC_FOLDER_OPTIONS_CLASSICFOLDERS:
                case IDC_FOLDER_OPTIONS_SAMEWINDOW:
                case IDC_FOLDER_OPTIONS_OWNWINDOW:
                case IDC_FOLDER_OPTIONS_SINGLECLICK:
                case IDC_FOLDER_OPTIONS_DOUBLECLICK:
                    if (HIWORD(wParam) == BN_CLICKED)
                    {
                        UpdateGeneralIcons(hwndDlg);

                        /* Enable the 'Apply' button */
                        PropSheet_Changed(GetParent(hwndDlg), hwndDlg);
                    }
                    break;
            }
            break;

        case WM_NOTIFY:
        {
            LPNMHDR pnmh = (LPNMHDR)lParam;

            switch (pnmh->code)
            {
                case PSN_SETACTIVE:
                    break;

                case PSN_APPLY:
                    break;
            }
            break;
        }
        
        case WM_DESTROY:
            break;
         
         default: 
             return FALSE;
    }
    return FALSE;
}

static BOOL
ViewDlg_OnInitDialog(HWND hwndDlg)
{
    HWND hwndTreeView = GetDlgItem(hwndDlg, 14003);

    s_hImageList = CreateTreeImageList();
    TreeView_SetImageList(hwndTreeView, s_hImageList, TVSIL_NORMAL);

    Advanced_LoadAll();
    Advanced_SortAll();
    Advanced_InsertAll(hwndTreeView);

    return TRUE;    // set focus
}

static BOOL
ViewDlg_ToggleCheckItem(HWND hwndDlg, HTREEITEM hItem)
{
    HWND hwndTreeView = GetDlgItem(hwndDlg, 14003);

    // get the item
    TV_ITEM Item;
    INT i;
    ZeroMemory(&Item, sizeof(Item));
    Item.mask = TVIF_HANDLE | TVIF_IMAGE | TVIF_PARAM;
    Item.hItem = hItem;
    if (!TreeView_GetItem(hwndTreeView, &Item))
        return FALSE;       // no such item

    ADVANCED_ENTRY *pEntry = Advanced_GetItem(Item.lParam);
    if (pEntry == NULL)
        return FALSE;       // no such item
    if (pEntry->bGrayed)
        return FALSE;       // disabled

    // toggle check mark
    Item.mask = TVIF_HANDLE | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
    switch (pEntry->dwType)
    {
        case AETYPE_CHECKBOX:
            pEntry->bChecked = !pEntry->bChecked;
            break;

        case AETYPE_RADIO:
            // reset all the entries of the same parent
            for (i = 0; i < s_AdvancedCount; ++i)
            {
                ADVANCED_ENTRY *pEntry2 = &s_Advanced[i];
                if (pEntry->dwParentID == pEntry2->dwParentID)
                {
                    pEntry2->bChecked = FALSE;

                    Item.hItem = pEntry2->hItem;
                    INT iImage = Advanced_GetImage(pEntry2);
                    Item.iImage = Item.iSelectedImage = iImage;
                    TreeView_SetItem(hwndTreeView, &Item);
                }
            }
            pEntry->bChecked = TRUE;
            break;

        default:
            return FALSE;   // failure
    }
    Item.iImage = Item.iSelectedImage = Advanced_GetImage(pEntry);
    Item.hItem = hItem;
    TreeView_SetItem(hwndTreeView, &Item);

    // redraw the item
    RECT rcItem;
    TreeView_GetItemRect(hwndTreeView, hItem, &rcItem, FALSE);
    InvalidateRect(hwndTreeView, &rcItem, TRUE);
    return TRUE;    // success
}

static VOID
ViewDlg_OnTreeViewClick(HWND hwndDlg)
{
    HWND hwndTreeView = GetDlgItem(hwndDlg, 14003);

    // do hit test to get the clicked item
    TV_HITTESTINFO HitTest;
    ZeroMemory(&HitTest, sizeof(HitTest));
    DWORD dwPos = GetMessagePos();
    HitTest.pt.x = LOWORD(dwPos);
    HitTest.pt.y = HIWORD(dwPos);
    ScreenToClient(hwndTreeView, &HitTest.pt);
    HTREEITEM hItem = TreeView_HitTest(hwndTreeView, &HitTest);

    // toggle the check mark if possible
    if (ViewDlg_ToggleCheckItem(hwndDlg, hItem))
    {
        // property sheet was changed
        PropSheet_Changed(GetParent(hwndDlg), hwndDlg);
    }
}

static void
ViewDlg_OnTreeViewKeyDown(HWND hwndDlg, TV_KEYDOWN *KeyDown)
{
    HWND hwndTreeView = GetDlgItem(hwndDlg, 14003);

    if (KeyDown->wVKey == VK_SPACE)
    {
        // [Space] key was pressed
        HTREEITEM hItem = TreeView_GetSelection(hwndTreeView);
        if (ViewDlg_ToggleCheckItem(hwndDlg, hItem))
        {
            PropSheet_Changed(GetParent(hwndDlg), hwndDlg);
        }
    }
}

static INT_PTR
ViewDlg_OnTreeCustomDraw(HWND hwndDlg, NMTVCUSTOMDRAW *Draw)
{
    NMCUSTOMDRAW& nmcd = Draw->nmcd;
    switch (nmcd.dwDrawStage)
    {
        case CDDS_PREPAINT:
            return CDRF_NOTIFYITEMDRAW;     // for CDDS_ITEMPREPAINT

        case CDDS_ITEMPREPAINT:
            if (!(nmcd.uItemState & CDIS_SELECTED)) // not selected
            {
                LPARAM lParam = nmcd.lItemlParam;
                ADVANCED_ENTRY *pEntry = Advanced_GetItem(lParam);
                if (pEntry && pEntry->bGrayed) // disabled
                {
                    // draw as grayed
                    Draw->clrText = GetSysColor(COLOR_GRAYTEXT);
                    Draw->clrTextBk = GetSysColor(COLOR_WINDOW);
                    return CDRF_NEWFONT;
                }
            }
            break;

        default:
            break;
    }
    return CDRF_DODEFAULT;
}

static VOID
Advanced_RestoreDefaults(HWND hwndDlg)
{
    HWND hwndTreeView = GetDlgItem(hwndDlg, 14003);

    for (INT i = 0; i < s_AdvancedCount; ++i)
    {
        // ignore if the type is group
        ADVANCED_ENTRY *pEntry = &s_Advanced[i];
        if (pEntry->dwType == AETYPE_GROUP)
            continue;

        // set default value on registry
        HKEY hKey;
        if (RegOpenKeyExW(HKEY(pEntry->hkeyRoot), pEntry->szRegPath,
                          0, KEY_WRITE, &hKey) != ERROR_SUCCESS)
        {
            continue;
        }
        RegSetValueExW(hKey, pEntry->szValueName, 0, REG_DWORD,
                       LPBYTE(pEntry->dwDefaultValue), sizeof(DWORD));
        RegCloseKey(hKey);

        // update check status
        pEntry->bChecked = (pEntry->dwCheckedValue == pEntry->dwDefaultValue);

        // update the image
        TV_ITEM Item;
        ZeroMemory(&Item, sizeof(Item));
        Item.mask = TVIF_HANDLE | TVIF_IMAGE | TVIF_SELECTEDIMAGE;
        Item.hItem = pEntry->hItem;
        Item.iImage = Item.iSelectedImage = Advanced_GetImage(pEntry);
        TreeView_SetItem(hwndTreeView, &Item);
    }

    PropSheet_Changed(GetParent(hwndDlg), hwndDlg);
}

/* FIXME: These macros should not be defined here */
#ifndef SSF_SHOWSUPERHIDDEN
    #define SSF_SHOWSUPERHIDDEN     0x00040000
#endif
#ifndef SSF_SEPPROCESS
    #define SSF_SEPPROCESS          0x00080000
#endif

static VOID
ScanAdvancedSettings(SHELLSTATE *pSS, DWORD *pdwMask)
{
    for (INT i = 0; i < s_AdvancedCount; ++i)
    {
        const ADVANCED_ENTRY *pEntry = &s_Advanced[i];
        if (pEntry->dwType == AETYPE_GROUP || pEntry->bGrayed)
            continue;

        BOOL bChecked = pEntry->bChecked;

        // FIXME: Add more items
        if (lstrcmpiW(pEntry->szKeyName, L"SuperHidden") == 0)
        {
            pSS->fShowSuperHidden = !bChecked ? 1 : 0;
            *pdwMask |= SSF_SHOWSUPERHIDDEN;
            continue;
        }
        if (lstrcmpiW(pEntry->szKeyName, L"DesktopProcess") == 0)
        {
            pSS->fSepProcess = bChecked ? 1 : 0;
            *pdwMask |= SSF_SEPPROCESS;
            continue;
        }
        if (lstrcmpiW(pEntry->szKeyName, L"SHOWALL") == 0)
        {
            pSS->fShowAllObjects = !bChecked ? 1 : 0;
            *pdwMask |= SSF_SHOWALLOBJECTS;
            continue;
        }
        if (lstrcmpiW(pEntry->szKeyName, L"HideFileExt") == 0)
        {
            pSS->fShowExtensions = !bChecked ? 1 : 0;
            *pdwMask |= SSF_SHOWEXTENSIONS;
            continue;
        }
        if (lstrcmpiW(pEntry->szKeyName, L"ShowCompColor") == 0)
        {
            pSS->fShowCompColor = bChecked ? 1 : 0;
            *pdwMask |= SSF_SHOWCOMPCOLOR;
            continue;
        }
        if (lstrcmpiW(pEntry->szKeyName, L"ShowInfoTip") == 0)
        {
            pSS->fShowInfoTip = bChecked ? 1 : 0;
            *pdwMask |= SSF_SHOWINFOTIP;
            continue;
        }
    }
}

extern "C"
VOID WINAPI SHGetSetSettings(LPSHELLSTATE lpss, DWORD dwMask, BOOL bSet);

static BOOL CALLBACK RefreshBrowsersCallback (HWND hWnd, LPARAM msg)
{
    WCHAR ClassName[100];
    if (GetClassName(hWnd, ClassName, 100))
    {
        if (!wcscmp(ClassName, L"Progman") || 
            !wcscmp(ClassName, L"CabinetWClass") ||
            !wcscmp(ClassName, L"ExploreWClass"))
        {
            PostMessage(hWnd, WM_COMMAND, FCIDM_DESKBROWSER_REFRESH, 0);
        }
    }
    return TRUE;
}

static VOID
ViewDlg_Apply(HWND hwndDlg)
{
    for (INT i = 0; i < s_AdvancedCount; ++i)
    {
        // ignore the entry if the type is group or the entry is grayed
        ADVANCED_ENTRY *pEntry = &s_Advanced[i];
        if (pEntry->dwType == AETYPE_GROUP || pEntry->bGrayed)
            continue;

        // open the registry key
        HKEY hkeyTarget;
        if (RegOpenKeyExW(HKEY(pEntry->hkeyRoot), pEntry->szRegPath, 0,
                          KEY_WRITE, &hkeyTarget) != ERROR_SUCCESS)
        {
            continue;
        }

        // checked or unchecked?
        DWORD dwValue, dwSize;
        if (pEntry->bChecked)
        {
            dwValue = pEntry->dwCheckedValue;
        }
        else
        {
            if (pEntry->bHasUncheckedValue)
            {
                dwValue = pEntry->dwUncheckedValue;
            }
            else
            {
                // there is no unchecked value
                RegCloseKey(hkeyTarget);
                continue;   // ignore
            }
        }

        // set the value
        dwSize = sizeof(dwValue);
        RegSetValueExW(hkeyTarget, pEntry->szValueName, 0, REG_DWORD,
                       LPBYTE(&dwValue), dwSize);

        // close now
        RegCloseKey(hkeyTarget);
    }

    // scan advanced settings for user's settings
    DWORD dwMask = 0;
    SHELLSTATE ShellState;
    ZeroMemory(&ShellState, sizeof(ShellState));
    ScanAdvancedSettings(&ShellState, &dwMask);

    // update user's settings
    SHGetSetSettings(&ShellState, dwMask, TRUE);

    // notify all
    SendMessage(HWND_BROADCAST, WM_WININICHANGE, 0, 0);
    
    EnumWindows(RefreshBrowsersCallback, NULL);
}

INT_PTR CALLBACK
FolderOptionsViewDlg(
    HWND    hwndDlg,
    UINT    uMsg,
    WPARAM  wParam,
    LPARAM  lParam)
{
    INT_PTR Result;
    NMTVCUSTOMDRAW *Draw;

    switch(uMsg)
    {
        case WM_INITDIALOG:
            return ViewDlg_OnInitDialog(hwndDlg);

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case 14004: // Restore Defaults
                    Advanced_RestoreDefaults(hwndDlg);
                    break;
            }
            break;

        case WM_NOTIFY:
            switch (LPNMHDR(lParam)->code)
            {
                case NM_CLICK:  // clicked on treeview
                    ViewDlg_OnTreeViewClick(hwndDlg);
                    break;

                case NM_CUSTOMDRAW:     // custom draw (for graying)
                    Draw = (NMTVCUSTOMDRAW *)lParam;
                    Result = ViewDlg_OnTreeCustomDraw(hwndDlg, Draw);
                    SetWindowLongPtr(hwndDlg, DWLP_MSGRESULT, Result);
                    return Result;

                case TVN_KEYDOWN:       // key is down
                    ViewDlg_OnTreeViewKeyDown(hwndDlg, (TV_KEYDOWN *)lParam);
                    break;

                case PSN_APPLY:         // [Apply] is clicked
                    ViewDlg_Apply(hwndDlg);
                    break;

                default:
                    break;
            }
            break;
    }

    return FALSE;
}

static
VOID
InitializeFileTypesListCtrlColumns(HWND hDlgCtrl)
{
    RECT clientRect;
    LVCOLUMNW col;
    WCHAR szName[50];
    DWORD dwStyle;
    int columnSize = 140;


    if (!LoadStringW(shell32_hInstance, IDS_COLUMN_EXTENSION, szName, sizeof(szName) / sizeof(WCHAR)))
    {
        /* default to english */
        wcscpy(szName, L"Extensions");
    }

    /* make sure its null terminated */
    szName[(sizeof(szName)/sizeof(WCHAR))-1] = 0;

    GetClientRect(hDlgCtrl, &clientRect);
    ZeroMemory(&col, sizeof(LV_COLUMN));
    columnSize = 140; //FIXME
    col.iSubItem   = 0;
    col.mask      = LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM | LVCF_FMT;
    col.fmt = LVCFMT_FIXED_WIDTH;
    col.cx         = columnSize | LVCFMT_LEFT;
    col.cchTextMax = wcslen(szName);
    col.pszText    = szName;
    (void)SendMessageW(hDlgCtrl, LVM_INSERTCOLUMNW, 0, (LPARAM)&col);

    if (!LoadStringW(shell32_hInstance, IDS_FILE_TYPES, szName, sizeof(szName) / sizeof(WCHAR)))
    {
        /* default to english */
        wcscpy(szName, L"File Types");
        ERR("Failed to load localized string!\n");
    }

    col.iSubItem   = 1;
    col.cx         = clientRect.right - clientRect.left - columnSize;
    col.cchTextMax = wcslen(szName);
    col.pszText    = szName;
    (void)SendMessageW(hDlgCtrl, LVM_INSERTCOLUMNW, 1, (LPARAM)&col);

    /* set full select style */
    dwStyle = (DWORD) SendMessage(hDlgCtrl, LVM_GETEXTENDEDLISTVIEWSTYLE, 0, 0);
    dwStyle = dwStyle | LVS_EX_FULLROWSELECT;
    SendMessage(hDlgCtrl, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, dwStyle);
}

static BOOL
DeleteExt(HWND hwndDlg, LPCWSTR pszExt)
{
    if (*pszExt != L'.')
        return FALSE;

    // open ".ext" key
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, pszExt, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return FALSE;

    // query "extfile" key name
    WCHAR szValue[64] = { 0 };
    DWORD cbValue = sizeof(szValue);
    RegQueryValueExW(hKey, NULL, NULL, NULL, LPBYTE(szValue), &cbValue);
    RegCloseKey(hKey);

    // delete "extfile" key (if any)
    if (szValue[0])
        SHDeleteKeyW(HKEY_CLASSES_ROOT, szValue);

    // delete ".ext" key
    return SHDeleteKeyW(HKEY_CLASSES_ROOT, pszExt) == ERROR_SUCCESS;
}

static inline HICON
DoExtractIcon(PFOLDER_FILE_TYPE_ENTRY Entry, LPCWSTR IconPath,
              INT iIndex = 0, BOOL bSmall = FALSE)
{
    HICON hIcon = NULL;

    if (iIndex < 0)
    {
        // A negative value will be interpreted as a negated resource ID.
        iIndex = -iIndex;

        INT cx, cy;
        HINSTANCE hDLL = LoadLibraryExW(IconPath, NULL, LOAD_LIBRARY_AS_DATAFILE);
        if (bSmall)
        {
            cx = GetSystemMetrics(SM_CXSMICON);
            cy = GetSystemMetrics(SM_CYSMICON);
        }
        else
        {
            cx = GetSystemMetrics(SM_CXICON);
            cy = GetSystemMetrics(SM_CYICON);
        }
        hIcon = HICON(LoadImageW(hDLL, MAKEINTRESOURCEW(iIndex), IMAGE_ICON,
                                 cx, cy, 0));
        FreeLibrary(hDLL);
    }
    else
    {
        // A positive value is icon index.
        if (bSmall)
            ExtractIconExW(IconPath, iIndex, NULL, &hIcon, 1);
        else
            ExtractIconExW(IconPath, iIndex, &hIcon, NULL, 1);
    }
    return hIcon;
}

static void
DoFileTypeIconLocation(PFOLDER_FILE_TYPE_ENTRY Entry, LPCWSTR IconLocation)
{
    // Expand the REG_EXPAND_SZ string by environment variables
    WCHAR szLocation[MAX_PATH + 32];
    if (!ExpandEnvironmentStringsW(IconLocation, szLocation, _countof(szLocation)))
    {
        return;
    }

    Entry->nIconIndex = PathParseIconLocationW(szLocation);
    StringCchCopyW(Entry->IconPath, _countof(Entry->IconPath), szLocation);
    Entry->hIconLarge = DoExtractIcon(Entry, szLocation, Entry->nIconIndex, FALSE);
    Entry->hIconSmall = DoExtractIcon(Entry, szLocation, Entry->nIconIndex, TRUE);
}

static BOOL
GetFileTypeIconsEx(PFOLDER_FILE_TYPE_ENTRY Entry, LPCWSTR IconLocation)
{
    Entry->hIconLarge = Entry->hIconSmall = NULL;

    if (lstrcmpiW(Entry->FileExtension, L".exe") == 0 ||
        lstrcmpiW(Entry->FileExtension, L".scr") == 0)
    {
        // It's an executable
        Entry->hIconLarge = LoadIconW(shell32_hInstance, MAKEINTRESOURCEW(IDI_SHELL_EXE));
        Entry->hIconSmall = HICON(LoadImageW(shell32_hInstance, MAKEINTRESOURCEW(IDI_SHELL_EXE), IMAGE_ICON,
            GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON), 0));
        StringCchCopyW(Entry->IconPath, _countof(Entry->IconPath), L"%SystemRoot%\\system32\\shell32.dll");
        Entry->nIconIndex = -IDI_SHELL_EXE;
    }
    else if (lstrcmpW(IconLocation, L"%1") == 0)
    {
        return FALSE;   // self icon
    }
    else
    {
        DoFileTypeIconLocation(Entry, IconLocation);
    }

    return Entry->hIconLarge && Entry->hIconSmall;
}

static BOOL
GetFileTypeIconsByKey(HKEY hKey, PFOLDER_FILE_TYPE_ENTRY Entry)
{
    Entry->hIconLarge = Entry->hIconSmall = NULL;

    // Open the "DefaultIcon" registry key
    HKEY hDefIconKey;
    LONG nResult = RegOpenKeyExW(hKey, L"DefaultIcon", 0, KEY_READ, &hDefIconKey);
    if (nResult != ERROR_SUCCESS)
        return FALSE;

    // Get the icon location
    WCHAR szLocation[MAX_PATH + 32] = { 0 };
    DWORD dwSize = sizeof(szLocation);
    nResult = RegQueryValueExW(hDefIconKey, NULL, NULL, NULL, LPBYTE(szLocation), &dwSize);

    RegCloseKey(hDefIconKey);

    if (nResult != ERROR_SUCCESS || szLocation[0] == 0)
        return FALSE;

    return GetFileTypeIconsEx(Entry, szLocation);
}

static BOOL
QueryFileDescription(LPCWSTR ProgramPath, LPWSTR pszName, INT cchName)
{
    SHFILEINFOW FileInfo = { 0 };
    if (SHGetFileInfoW(ProgramPath, 0, &FileInfo, sizeof(FileInfo), SHGFI_DISPLAYNAME))
    {
        StringCchCopyW(pszName, cchName, FileInfo.szDisplayName);
        return TRUE;
    }

    return !!GetFileTitleW(ProgramPath, pszName, cchName);
}

static void
SetFileTypeEntryDefaultIcon(PFOLDER_FILE_TYPE_ENTRY Entry)
{
    Entry->hIconLarge = LoadIconW(shell32_hInstance, MAKEINTRESOURCEW(IDI_SHELL_FOLDER_OPTIONS));
    INT cxSmall = GetSystemMetrics(SM_CXSMICON);
    INT cySmall = GetSystemMetrics(SM_CYSMICON);
    Entry->hIconSmall = HICON(LoadImageW(shell32_hInstance, MAKEINTRESOURCEW(IDI_SHELL_FOLDER_OPTIONS),
                                         IMAGE_ICON, cxSmall, cySmall, 0));
    StringCchCopyW(Entry->IconPath, _countof(Entry->IconPath), L"%SystemRoot%\\system32\\shell32.dll");
    Entry->nIconIndex = -IDI_SHELL_FOLDER_OPTIONS;
}

static BOOL
InsertFileType(HWND hListView, LPCWSTR szName, INT iItem, LPCWSTR szFile)
{
    PFOLDER_FILE_TYPE_ENTRY Entry;
    HKEY hKey;
    LVITEMW lvItem;
    DWORD dwSize;
    DWORD dwType;

    if (szName[0] != L'.')
    {
        /* FIXME handle URL protocol handlers */
        return FALSE;
    }

    // get imagelists of listview
    HIMAGELIST himlLarge = ListView_GetImageList(hListView, LVSIL_NORMAL);
    HIMAGELIST himlSmall = ListView_GetImageList(hListView, LVSIL_SMALL);

    /* allocate file type entry */
    Entry = (PFOLDER_FILE_TYPE_ENTRY)HeapAlloc(GetProcessHeap(), 0, sizeof(FOLDER_FILE_TYPE_ENTRY));
    if (!Entry)
        return FALSE;

    /* open key */
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, szName, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, Entry);
        return FALSE;
    }

    /* FIXME check for duplicates */

    /* query for the default key */
    dwSize = sizeof(Entry->ClassKey);
    if (RegQueryValueExW(hKey, NULL, NULL, NULL, (LPBYTE)Entry->ClassKey, &dwSize) != ERROR_SUCCESS)
    {
        /* no link available */
        Entry->ClassKey[0] = 0;
    }

    Entry->ClassName[0] = 0;
    if (Entry->ClassKey[0])
    {
        HKEY hTemp;
        /* try open linked key */
        if (RegOpenKeyExW(HKEY_CLASSES_ROOT, Entry->ClassKey, 0, KEY_READ, &hTemp) == ERROR_SUCCESS)
        {
            DWORD dwSize = sizeof(Entry->ClassName);
            RegQueryValueExW(hTemp, NULL, NULL, NULL, LPBYTE(Entry->ClassName), &dwSize);

            /* use linked key */
            RegCloseKey(hKey);
            hKey = hTemp;
        }
    }

    /* read friendly type name */
    if (RegLoadMUIStringW(hKey, L"FriendlyTypeName", Entry->FileDescription, sizeof(Entry->FileDescription), NULL, 0, NULL) != ERROR_SUCCESS)
    {
        /* read file description */
        dwSize = sizeof(Entry->FileDescription);
        Entry->FileDescription[0] = 0;

        /* read default key */
        RegQueryValueExW(hKey, NULL, NULL, NULL, (LPBYTE)Entry->FileDescription, &dwSize);
    }

    /* Read the EditFlags value */
    Entry->EditFlags = 0;
    if (!RegQueryValueExW(hKey, L"EditFlags", NULL, &dwType, NULL, &dwSize))
    {
        if ((dwType == REG_DWORD || dwType == REG_BINARY) && dwSize == sizeof(DWORD))
            RegQueryValueExW(hKey, L"EditFlags", NULL, NULL, (LPBYTE)&Entry->EditFlags, &dwSize);
    }

    /* convert extension to upper case */
    wcscpy(Entry->FileExtension, szName);
    _wcsupr(Entry->FileExtension);

    /* get icon */
    if (!GetFileTypeIconsByKey(hKey, Entry))
    {
        // set default icon
        SetFileTypeEntryDefaultIcon(Entry);
    }

    /* close key */
    RegCloseKey(hKey);

    // get program path and app name
    DWORD cch = _countof(Entry->ProgramPath);
    if (S_OK == AssocQueryStringW(ASSOCF_INIT_IGNOREUNKNOWN, ASSOCSTR_EXECUTABLE,
                                  Entry->FileExtension, NULL, Entry->ProgramPath, &cch))
    {
        QueryFileDescription(Entry->ProgramPath, Entry->AppName, _countof(Entry->AppName));
    }
    else
    {
        Entry->ProgramPath[0] = Entry->AppName[0] = 0;
    }

    // add icon to imagelist
    INT iLargeImage = -1, iSmallImage = -1;
    if (Entry->hIconLarge && Entry->hIconSmall)
    {
        iLargeImage = ImageList_AddIcon(himlLarge, Entry->hIconLarge);
        iSmallImage = ImageList_AddIcon(himlSmall, Entry->hIconSmall);
        ASSERT(iLargeImage == iSmallImage);
    }

    /* Do not add excluded entries */
    if (Entry->EditFlags & 0x00000001) //FTA_Exclude
    {
        DestroyIcon(Entry->hIconLarge);
        DestroyIcon(Entry->hIconSmall);
        HeapFree(GetProcessHeap(), 0, Entry);
        return FALSE;
    }

    if (!Entry->FileDescription[0])
    {
        /* construct default 'FileExtensionFile' by formatting the uppercase extension
           with IDS_FILE_EXT_TYPE, outputting something like a l18n 'INI File' */

        StringCchPrintf(Entry->FileDescription, _countof(Entry->FileDescription), szFile, &Entry->FileExtension[1]);
    }

    ZeroMemory(&lvItem, sizeof(LVITEMW));
    lvItem.mask = LVIF_TEXT | LVIF_PARAM | LVIF_IMAGE;
    lvItem.iSubItem = 0;
    lvItem.pszText = &Entry->FileExtension[1];
    lvItem.iItem = iItem;
    lvItem.lParam = (LPARAM)Entry;
    lvItem.iImage = iSmallImage;
    SendMessageW(hListView, LVM_INSERTITEMW, 0, (LPARAM)&lvItem);

    ZeroMemory(&lvItem, sizeof(LVITEMW));
    lvItem.mask = LVIF_TEXT;
    lvItem.pszText = Entry->FileDescription;
    lvItem.iItem = iItem;
    lvItem.iSubItem = 1;
    ListView_SetItem(hListView, &lvItem);

    return TRUE;
}

static
int
CALLBACK
ListViewCompareProc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort)
{
    PFOLDER_FILE_TYPE_ENTRY Entry1, Entry2;
    int x;

    Entry1 = (PFOLDER_FILE_TYPE_ENTRY)lParam1;
    Entry2 = (PFOLDER_FILE_TYPE_ENTRY)lParam2;

    x = wcsicmp(Entry1->FileExtension, Entry2->FileExtension);
    if (x != 0)
        return x;

    return wcsicmp(Entry1->FileDescription, Entry2->FileDescription);
}

static
PFOLDER_FILE_TYPE_ENTRY
InitializeFileTypesListCtrl(HWND hwndDlg)
{
    HWND hDlgCtrl;
    DWORD dwIndex = 0;
    WCHAR szName[50];
    WCHAR szFile[100];
    DWORD dwName;
    LVITEMW lvItem;
    INT iItem = 0;
    HIMAGELIST himlLarge, himlSmall;

    // create imagelists
    himlLarge = ImageList_Create(GetSystemMetrics(SM_CXICON), GetSystemMetrics(SM_CYICON),
                                 ILC_COLOR32 | ILC_MASK, 256, 20);
    himlSmall = ImageList_Create(GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON),
                                 ILC_COLOR32 | ILC_MASK, 256, 20);

    // set imagelists to listview.
    hDlgCtrl = GetDlgItem(hwndDlg, IDC_FILETYPES_LISTVIEW);
    ListView_SetImageList(hDlgCtrl, himlLarge, LVSIL_NORMAL);
    ListView_SetImageList(hDlgCtrl, himlSmall, LVSIL_SMALL);

    InitializeFileTypesListCtrlColumns(hDlgCtrl);

    szFile[0] = 0;
    if (!LoadStringW(shell32_hInstance, IDS_FILE_EXT_TYPE, szFile, _countof(szFile)))
    {
        /* default to english */
        wcscpy(szFile, L"%s File");
    }
    szFile[(_countof(szFile)) - 1] = 0;

    dwName = _countof(szName);

    while (RegEnumKeyExW(HKEY_CLASSES_ROOT, dwIndex++, szName, &dwName, NULL, NULL, NULL, NULL) == ERROR_SUCCESS)
    {
        if (InsertFileType(hDlgCtrl, szName, iItem, szFile))
            ++iItem;
        dwName = _countof(szName);
    }

    /* Leave if the list is empty */
    if (iItem == 0)
        return NULL;

    /* sort list */
    ListView_SortItems(hDlgCtrl, ListViewCompareProc, NULL);

    /* select first item */
    ZeroMemory(&lvItem, sizeof(LVITEMW));
    lvItem.mask = LVIF_STATE;
    lvItem.stateMask = (UINT)-1;
    lvItem.state = LVIS_FOCUSED | LVIS_SELECTED;
    lvItem.iItem = 0;
    ListView_SetItem(hDlgCtrl, &lvItem);

    lvItem.mask = LVIF_PARAM;
    ListView_GetItem(hDlgCtrl, &lvItem);

    return (PFOLDER_FILE_TYPE_ENTRY)lvItem.lParam;
}

static inline
PFOLDER_FILE_TYPE_ENTRY
GetListViewEntry(HWND hListView, INT iItem = -1)
{
    if (iItem == -1)
    {
        iItem = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
        if (iItem == -1)
            return NULL;
    }

    LV_ITEMW lvItem = { LVIF_PARAM, iItem };
    if (ListView_GetItem(hListView, &lvItem))
        return (PFOLDER_FILE_TYPE_ENTRY)lvItem.lParam;

    return NULL;
}

struct NEWEXT_DIALOG
{
    HWND hwndLV;
    RECT rcDlg;
    BOOL bAdvanced;
    INT dy;
    WCHAR szExt[16];
    WCHAR szFileType[64];
};

static VOID
NewExtDlg_OnAdvanced(HWND hwndDlg, NEWEXT_DIALOG *pNewExt)
{
    // If "Advanced" button was clicked, then we shrink or expand the dialog.
    WCHAR szText[64];
    RECT rc, rc1, rc2;

    GetWindowRect(hwndDlg, &rc);
    rc.bottom = rc.top + (pNewExt->rcDlg.bottom - pNewExt->rcDlg.top);

    GetWindowRect(GetDlgItem(hwndDlg, IDOK), &rc1);
    MapWindowPoints(NULL, hwndDlg, (POINT *)&rc1, 2);

    GetWindowRect(GetDlgItem(hwndDlg, IDCANCEL), &rc2);
    MapWindowPoints(NULL, hwndDlg, (POINT *)&rc2, 2);

    if (pNewExt->bAdvanced)
    {
        rc1.top += pNewExt->dy;
        rc1.bottom += pNewExt->dy;

        rc2.top += pNewExt->dy;
        rc2.bottom += pNewExt->dy;

        ShowWindow(GetDlgItem(hwndDlg, IDC_NEWEXT_ASSOC), SW_SHOWNOACTIVATE);
        ShowWindow(GetDlgItem(hwndDlg, IDC_NEWEXT_COMBOBOX), SW_SHOWNOACTIVATE);

        LoadStringW(shell32_hInstance, IDS_NEWEXT_ADVANCED_LEFT, szText, _countof(szText));
        SetDlgItemTextW(hwndDlg, IDC_NEWEXT_ADVANCED, szText);

        SetFocus(GetDlgItem(hwndDlg, IDC_NEWEXT_COMBOBOX));
    }
    else
    {
        rc1.top -= pNewExt->dy;
        rc1.bottom -= pNewExt->dy;

        rc2.top -= pNewExt->dy;
        rc2.bottom -= pNewExt->dy;

        ShowWindow(GetDlgItem(hwndDlg, IDC_NEWEXT_ASSOC), SW_HIDE);
        ShowWindow(GetDlgItem(hwndDlg, IDC_NEWEXT_COMBOBOX), SW_HIDE);

        LoadStringW(shell32_hInstance, IDS_NEWEXT_ADVANCED_RIGHT, szText, _countof(szText));
        SetDlgItemTextW(hwndDlg, IDC_NEWEXT_ADVANCED, szText);

        rc.bottom -= pNewExt->dy;

        LoadStringW(shell32_hInstance, IDS_NEWEXT_NEW, szText, _countof(szText));
        SetDlgItemTextW(hwndDlg, IDC_NEWEXT_COMBOBOX, szText);
    }

    HDWP hDWP = BeginDeferWindowPos(3);

    if (hDWP)
        hDWP = DeferWindowPos(hDWP, GetDlgItem(hwndDlg, IDOK), NULL,
                              rc1.left, rc1.top, rc1.right - rc1.left, rc1.bottom - rc1.top,
                              SWP_NOACTIVATE | SWP_NOZORDER);
    if (hDWP)
        hDWP = DeferWindowPos(hDWP, GetDlgItem(hwndDlg, IDCANCEL), NULL,
                              rc2.left, rc2.top, rc2.right - rc2.left, rc2.bottom - rc2.top,
                              SWP_NOACTIVATE | SWP_NOZORDER);
    if (hDWP)
        hDWP = DeferWindowPos(hDWP, hwndDlg, NULL,
                              rc.left, rc.top, rc.right - rc.left, rc.bottom - rc.top,
                              SWP_NOACTIVATE | SWP_NOZORDER);

    if (hDWP)
        EndDeferWindowPos(hDWP);
}

static BOOL
NewExtDlg_OnInitDialog(HWND hwndDlg, NEWEXT_DIALOG *pNewExt)
{
    WCHAR szText[64];

    pNewExt->bAdvanced = FALSE;

    GetWindowRect(hwndDlg, &pNewExt->rcDlg);

    RECT rc1, rc2;
    GetWindowRect(GetDlgItem(hwndDlg, IDC_NEWEXT_EDIT), &rc1);
    GetWindowRect(GetDlgItem(hwndDlg, IDC_NEWEXT_COMBOBOX), &rc2);
    pNewExt->dy = rc2.top - rc1.top;

    LoadStringW(shell32_hInstance, IDS_NEWEXT_NEW, szText, _countof(szText));
    SendDlgItemMessageW(hwndDlg, IDC_NEWEXT_COMBOBOX, CB_ADDSTRING, 0, (LPARAM)szText);
    SendDlgItemMessageW(hwndDlg, IDC_NEWEXT_COMBOBOX, CB_SETCURSEL, 0, 0);

    SendDlgItemMessageW(hwndDlg, IDC_NEWEXT_EDIT, EM_SETLIMITTEXT, _countof(pNewExt->szExt) - 1, 0);

    NewExtDlg_OnAdvanced(hwndDlg, pNewExt);

    return TRUE;
}

static LPCWSTR s_pszSpace = L" \t\n\r\f\v";

static BOOL
NewExtDlg_OnOK(HWND hwndDlg, NEWEXT_DIALOG *pNewExt)
{
    LV_FINDINFO find;
    INT iItem;

    GetDlgItemTextW(hwndDlg, IDC_NEWEXT_EDIT, pNewExt->szExt, _countof(pNewExt->szExt));
    StrTrimW(pNewExt->szExt, s_pszSpace);
    CharUpperW(pNewExt->szExt);

    GetDlgItemTextW(hwndDlg, IDC_NEWEXT_COMBOBOX, pNewExt->szFileType, _countof(pNewExt->szFileType));
    StrTrimW(pNewExt->szFileType, s_pszSpace);

    if (pNewExt->szExt[0] == 0)
    {
        WCHAR szText[128], szTitle[128];
        LoadStringW(shell32_hInstance, IDS_NEWEXT_SPECIFY_EXT, szText, _countof(szText));
        szText[_countof(szText) - 1] = 0;
        LoadStringW(shell32_hInstance, IDS_FILE_TYPES, szTitle, _countof(szTitle));
        szTitle[_countof(szTitle) - 1] = 0;
        MessageBoxW(hwndDlg, szText, szTitle, MB_ICONERROR);
        return FALSE;
    }

    ZeroMemory(&find, sizeof(find));
    find.flags = LVFI_STRING;
    if (pNewExt->szExt[0] == L'.')
    {
        find.psz = &pNewExt->szExt[1];
    }
    else
    {
        find.psz = pNewExt->szExt;
    }

    iItem = ListView_FindItem(pNewExt->hwndLV, -1, &find);
    if (iItem >= 0)
    {
        // already exists
        WCHAR szText[256], szFormat[256], szTitle[64], szFileType[64];

        // get file type
        LV_ITEM item;
        ZeroMemory(&item, sizeof(item));
        item.mask = LVIF_TEXT;
        item.pszText = szFileType;
        item.cchTextMax = _countof(szFileType);
        item.iItem = iItem;
        item.iSubItem = 1;
        ListView_GetItem(pNewExt->hwndLV, &item);

        // get text
        LoadStringW(shell32_hInstance, IDS_NEWEXT_ALREADY_ASSOC, szFormat, _countof(szFormat));
        szText[_countof(szFormat) - 1] = 0;
        StringCchPrintfW(szText, _countof(szText), szFormat, find.psz, szFileType, find.psz, szFileType);

        // get title
        LoadStringW(shell32_hInstance, IDS_NEWEXT_EXT_IN_USE, szTitle, _countof(szTitle));
        szTitle[_countof(szTitle) - 1] = 0;

        if (MessageBoxW(hwndDlg, szText, szTitle, MB_ICONWARNING | MB_YESNO) == IDNO)
        {
            return FALSE;
        }

        // Delete the extension
        CStringW strExt(L".");
        strExt += find.psz;
        strExt.MakeLower();
        DeleteExt(hwndDlg, strExt);

        // Delete the item
        ListView_DeleteItem(pNewExt->hwndLV, iItem);
    }

    EndDialog(hwndDlg, IDOK);
    return TRUE;
}

// IDD_NEWEXTENSION dialog
INT_PTR
CALLBACK
NewExtensionDlgProc(
    HWND hwndDlg,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam)
{
    static NEWEXT_DIALOG *s_pNewExt = NULL;

    switch (uMsg)
    {
        case WM_INITDIALOG:
            s_pNewExt = (NEWEXT_DIALOG *)lParam;
            NewExtDlg_OnInitDialog(hwndDlg, s_pNewExt);
            return TRUE;

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDOK:
                    NewExtDlg_OnOK(hwndDlg, s_pNewExt);
                    break;

                case IDCANCEL:
                    EndDialog(hwndDlg, IDCANCEL);
                    break;

                case IDC_NEWEXT_ADVANCED:
                    s_pNewExt->bAdvanced = !s_pNewExt->bAdvanced;
                    NewExtDlg_OnAdvanced(hwndDlg, s_pNewExt);
                    break;
            }
            break;
    }
    return 0;
}

static BOOL
FileTypesDlg_AddExt(HWND hwndDlg, LPCWSTR pszExt, LPCWSTR pszFileType)
{
    DWORD dwValue = 1;
    HKEY hKey;
    WCHAR szKey[13];    // max. "ft4294967295" + "\0"
    LONG nResult;

    // Search the next "ft%06u" key name
    do
    {
        StringCchPrintfW(szKey, _countof(szKey), TEXT("ft%06u"), dwValue);

        nResult = RegOpenKeyEx(HKEY_CLASSES_ROOT, szKey, 0, KEY_READ, &hKey);
        if (nResult != ERROR_SUCCESS)
            break;

        RegCloseKey(hKey);
        ++dwValue;
    } while (dwValue != 0);

    RegCloseKey(hKey);

    if (dwValue == 0)
        return FALSE;

    // Create new "ft%06u" key
    nResult = RegCreateKeyEx(HKEY_CLASSES_ROOT, szKey, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (ERROR_SUCCESS != nResult)
        return FALSE;

    RegCloseKey(hKey);

    // Create the ".ext" key
    WCHAR szExt[16];
    if (*pszExt == L'.')
        ++pszExt;
    StringCchPrintfW(szExt, _countof(szExt), TEXT(".%s"), pszExt);
    CharLowerW(szExt);
    nResult = RegCreateKeyEx(HKEY_CLASSES_ROOT, szExt, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    CharUpperW(szExt);
    if (ERROR_SUCCESS != nResult)
        return FALSE;

    // Set the default value of ".ext" to "ft%06u"
    DWORD dwSize = (lstrlen(szKey) + 1) * sizeof(WCHAR);
    RegSetValueExW(hKey, NULL, 0, REG_SZ, (BYTE *)szKey, dwSize);

    RegCloseKey(hKey);

    // Make up the file type name
    WCHAR szFile[100], szFileFormat[100];
    LoadStringW(shell32_hInstance, IDS_FILE_EXT_TYPE, szFileFormat, _countof(szFileFormat));
    szFile[_countof(szFileFormat) - 1] = 0;
    StringCchPrintfW(szFile, _countof(szFile), szFileFormat, &szExt[1]);

    // Insert an item to the listview
    HWND hListView = GetDlgItem(hwndDlg, IDC_FILETYPES_LISTVIEW);
    INT iItem = ListView_GetItemCount(hListView);
    if (!InsertFileType(hListView, szExt, iItem, szFile))
        return FALSE;

    LV_ITEM item;
    ZeroMemory(&item, sizeof(item));
    item.mask = LVIF_STATE | LVIF_TEXT;
    item.iItem = iItem;
    item.state = LVIS_SELECTED | LVIS_FOCUSED;
    item.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
    item.pszText = &szExt[1];
    ListView_SetItem(hListView, &item);

    item.pszText = szFile;
    item.iSubItem = 1;
    ListView_SetItem(hListView, &item);

    ListView_EnsureVisible(hListView, iItem, FALSE);

    return TRUE;
}

static BOOL
FileTypesDlg_RemoveExt(HWND hwndDlg)
{
    HWND hListView = GetDlgItem(hwndDlg, IDC_FILETYPES_LISTVIEW);

    INT iItem = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
    if (iItem == -1)
        return FALSE;

    WCHAR szExt[20];
    szExt[0] = L'.';
    ListView_GetItemText(hListView, iItem, 0, &szExt[1], _countof(szExt) - 1);
    CharLowerW(szExt);

    DeleteExt(hwndDlg, szExt);
    ListView_DeleteItem(hListView, iItem);
    return TRUE;
}

static void
FileTypesDlg_OnItemChanging(HWND hwndDlg, PFOLDER_FILE_TYPE_ENTRY pEntry)
{
    WCHAR Buffer[255];
    static HBITMAP s_hbmProgram = NULL;

    // format buffer and set groupbox text
    CStringW strFormat(MAKEINTRESOURCEW(IDS_FILE_DETAILS));
    StringCchPrintfW(Buffer, _countof(Buffer), strFormat, &pEntry->FileExtension[1]);
    SetDlgItemTextW(hwndDlg, IDC_FILETYPES_DETAILS_GROUPBOX, Buffer);

    // format buffer and set description
    strFormat.LoadString(IDS_FILE_DETAILSADV);
    StringCchPrintfW(Buffer, _countof(Buffer), strFormat,
                     &pEntry->FileExtension[1], pEntry->FileDescription,
                     pEntry->FileDescription);
    SetDlgItemTextW(hwndDlg, IDC_FILETYPES_DESCRIPTION, Buffer);

    // delete previous program image
    if (s_hbmProgram)
    {
        DeleteObject(s_hbmProgram);
        s_hbmProgram = NULL;
    }

    // set program image
    HICON hIconSm = NULL;
    ExtractIconExW(pEntry->ProgramPath, 0, NULL, &hIconSm, 1);
    s_hbmProgram = BitmapFromIcon(hIconSm, 16, 16);
    DestroyIcon(hIconSm);
    SendDlgItemMessageW(hwndDlg, IDC_FILETYPES_ICON, STM_SETIMAGE, IMAGE_BITMAP, LPARAM(s_hbmProgram));

    // set program name
    if (pEntry->AppName[0])
        SetDlgItemTextW(hwndDlg, IDC_FILETYPES_APPNAME, pEntry->AppName);
    else
        SetDlgItemTextW(hwndDlg, IDC_FILETYPES_APPNAME, L"ReactOS");

    /* Enable the Delete button */
    if (pEntry->EditFlags & 0x00000010) // FTA_NoRemove
        EnableWindow(GetDlgItem(hwndDlg, IDC_FILETYPES_DELETE), FALSE);
    else
        EnableWindow(GetDlgItem(hwndDlg, IDC_FILETYPES_DELETE), TRUE);
}

struct EDITTYPE_DIALOG
{
    HWND hwndLV;
    FOLDER_FILE_TYPE_ENTRY *pEntry;
    CSimpleMap<CStringW, CStringW> CommandLineMap;
    WCHAR szIconPath[MAX_PATH];
    INT nIconIndex;
    WCHAR szDefaultVerb[64];
};

static BOOL
EditTypeDlg_ReadClass(HWND hwndDlg, EDITTYPE_DIALOG *pEditType, LPCWSTR ClassKey)
{
    // open class key
    HKEY hClassKey;
    if (RegOpenKeyExW(HKEY_CLASSES_ROOT, ClassKey, 0, KEY_READ, &hClassKey) != ERROR_SUCCESS)
        return FALSE;

    // open "shell" key
    HKEY hShellKey;
    if (RegOpenKeyExW(hClassKey, L"shell", 0, KEY_READ, &hShellKey) != ERROR_SUCCESS)
    {
        RegCloseKey(hClassKey);
        return FALSE;
    }

    WCHAR DefaultVerb[64];
    DWORD dwSize = sizeof(DefaultVerb);
    if (RegQueryValueExW(hShellKey, NULL, NULL, NULL, LPBYTE(DefaultVerb), &dwSize) == ERROR_SUCCESS)
    {
        StringCchCopyW(pEditType->szDefaultVerb, _countof(pEditType->szDefaultVerb), DefaultVerb);
    }
    else
    {
        StringCchCopyW(pEditType->szDefaultVerb, _countof(pEditType->szDefaultVerb), L"open");
    }

    // enumerate shell verbs
    WCHAR szVerbName[64];
    DWORD dwIndex = 0;
    while (RegEnumKeyW(hShellKey, dwIndex, szVerbName, _countof(szVerbName)) == ERROR_SUCCESS)
    {
        // open verb key
        HKEY hVerbKey;
        LONG nResult = RegOpenKeyExW(hShellKey, szVerbName, 0, KEY_READ, &hVerbKey);
        if (nResult == ERROR_SUCCESS)
        {
            // open command key
            HKEY hCommandKey;
            nResult = RegOpenKeyExW(hVerbKey, L"command", 0, KEY_READ, &hCommandKey);
            if (nResult == ERROR_SUCCESS)
            {
                // get command line
                WCHAR szValue[MAX_PATH + 32];
                dwSize = sizeof(szValue);
                nResult = RegQueryValueExW(hCommandKey, NULL, NULL, NULL, LPBYTE(szValue), &dwSize);
                if (nResult == ERROR_SUCCESS)
                {
                    pEditType->CommandLineMap.SetAt(szVerbName, szValue);
                }

                RegCloseKey(hCommandKey);
            }

            RegCloseKey(hVerbKey);
        }
        SendDlgItemMessageW(hwndDlg, IDC_EDITTYPE_LISTBOX, LB_ADDSTRING, 0, LPARAM(szVerbName));
        ++dwIndex;
    }

    RegCloseKey(hShellKey);
    RegCloseKey(hClassKey);

    return TRUE;
}

static BOOL
EditTypeDlg_WriteClass(HWND hwndDlg, EDITTYPE_DIALOG *pEditType,
                       LPCWSTR ClassKey, LPCWSTR ClassName, INT cchName)
{
    FOLDER_FILE_TYPE_ENTRY *pEntry = pEditType->pEntry;

    if (ClassKey[0] == 0)
        return FALSE;

    // create or open class key
    HKEY hClassKey;
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, ClassKey, 0, NULL, 0, KEY_WRITE, NULL, &hClassKey, NULL) != ERROR_SUCCESS)
        return FALSE;

    // create "DefaultIcon" key
    if (pEntry->IconPath[0])
    {
        HKEY hDefaultIconKey;
        if (RegCreateKeyExW(hClassKey, L"DefaultIcon", 0, NULL, 0, KEY_WRITE, NULL, &hDefaultIconKey, NULL) == ERROR_SUCCESS)
        {
            WCHAR szText[MAX_PATH];
            StringCchPrintfW(szText, _countof(szText), L"%s,%d", pEntry->IconPath, pEntry->nIconIndex);

            // set icon location
            DWORD dwSize = (lstrlenW(szText) + 1) * sizeof(WCHAR);
            RegSetValueExW(hDefaultIconKey, NULL, 0, REG_EXPAND_SZ, LPBYTE(szText), dwSize);

            RegCloseKey(hDefaultIconKey);
        }
    }

    // create "shell" key
    HKEY hShellKey;
    if (RegCreateKeyExW(hClassKey, L"shell", 0, NULL, 0, KEY_WRITE, NULL, &hShellKey, NULL) != ERROR_SUCCESS)
    {
        RegCloseKey(hClassKey);
        return FALSE;
    }

    // delete shell commands
    WCHAR szVerbName[64];
    DWORD dwIndex = 0;
    while (RegEnumKeyW(hShellKey, dwIndex, szVerbName, _countof(szVerbName)) == ERROR_SUCCESS)
    {
        if (pEditType->CommandLineMap.FindKey(szVerbName) == -1)
        {
            // doesn't exist in CommandLineMap, then delete it
            if (SHDeleteKeyW(hShellKey, szVerbName) == ERROR_SUCCESS)
            {
                --dwIndex;
            }
        }
        ++dwIndex;
    }

    // set default action
    RegSetValueExW(hShellKey, NULL, 0, REG_SZ, LPBYTE(pEditType->szDefaultVerb), sizeof(pEditType->szDefaultVerb));

    // write shell commands
    const INT nCount = pEditType->CommandLineMap.GetSize();
    for (INT i = 0; i < nCount; ++i)
    {
        CStringW& key = pEditType->CommandLineMap.GetKeyAt(i);
        CStringW& value = pEditType->CommandLineMap.GetValueAt(i);

        // create verb key
        HKEY hVerbKey;
        if (RegCreateKeyExW(hShellKey, key, 0, NULL, 0, KEY_WRITE, NULL, &hVerbKey, NULL) == ERROR_SUCCESS)
        {
            // create command key
            HKEY hCommandKey;
            if (RegCreateKeyExW(hVerbKey, L"command", 0, NULL, 0, KEY_WRITE, NULL, &hCommandKey, NULL) == ERROR_SUCCESS)
            {
                // write the default value
                DWORD dwSize = (value.GetLength() + 1) * sizeof(WCHAR);
                RegSetValueExW(hCommandKey, NULL, 0, REG_EXPAND_SZ, LPBYTE(LPCWSTR(value)), dwSize);

                RegCloseKey(hCommandKey);
            }

            RegCloseKey(hVerbKey);
        }
    }

    // set class name to class key
    RegSetValueExW(hClassKey, NULL, 0, REG_SZ, LPBYTE(ClassName), cchName);

    RegCloseKey(hShellKey);
    RegCloseKey(hClassKey);

    return TRUE;
}

static BOOL
EditTypeDlg_OnInitDialog(HWND hwndDlg, EDITTYPE_DIALOG *pEditType)
{
    FOLDER_FILE_TYPE_ENTRY *pEntry = pEditType->pEntry;
    StringCchCopyW(pEditType->szIconPath, _countof(pEditType->szIconPath), pEntry->IconPath);
    pEditType->nIconIndex = pEntry->nIconIndex;
    StringCchCopyW(pEditType->szDefaultVerb, _countof(pEditType->szDefaultVerb), L"open");

    // set info
    SendDlgItemMessageW(hwndDlg, IDC_EDITTYPE_ICON, STM_SETICON, (WPARAM)pEntry->hIconLarge, 0);
    SetDlgItemTextW(hwndDlg, IDC_EDITTYPE_TEXT, pEntry->ClassName);
    EditTypeDlg_ReadClass(hwndDlg, pEditType, pEntry->ClassKey);
    InvalidateRect(GetDlgItem(hwndDlg, IDC_EDITTYPE_LISTBOX), NULL, TRUE);

    // is listbox empty?
    if (SendDlgItemMessageW(hwndDlg, IDC_EDITTYPE_LISTBOX, LB_GETCOUNT, 0, 0) == 0)
    {
        EnableWindow(GetDlgItem(hwndDlg, IDC_EDITTYPE_EDIT_BUTTON), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_EDITTYPE_REMOVE), FALSE);
        EnableWindow(GetDlgItem(hwndDlg, IDC_EDITTYPE_SET_DEFAULT), FALSE);
    }
    else
    {
        // select first item
        SendDlgItemMessageW(hwndDlg, IDC_EDITTYPE_LISTBOX, LB_SETCURSEL, 0, 0);
    }

    EnableWindow(GetDlgItem(hwndDlg, IDC_EDITTYPE_SAME_WINDOW), FALSE);

    return TRUE;
}

static BOOL
EditTypeDlg_OnRemove(HWND hwndDlg, EDITTYPE_DIALOG *pEditType)
{
    // get current selection
    INT iItem = SendDlgItemMessageW(hwndDlg, IDC_EDITTYPE_LISTBOX, LB_GETCURSEL, 0, 0);
    if (iItem == LB_ERR)
        return FALSE;

    // ask user for removal
    CStringW strText(MAKEINTRESOURCEW(IDS_REMOVE_ACTION));
    CStringW strTitle(MAKEINTRESOURCEW(IDS_FILE_TYPES));
    if (MessageBoxW(hwndDlg, strText, strTitle, MB_ICONINFORMATION | MB_YESNO) == IDNO)
        return FALSE;

    // get text
    WCHAR szText[64];
    szText[0] = 0;
    SendDlgItemMessageW(hwndDlg, IDC_EDITTYPE_LISTBOX, LB_GETTEXT, iItem, (LPARAM)szText);
    StrTrimW(szText, s_pszSpace);

    // remove it
    pEditType->CommandLineMap.Remove(szText);
    SendDlgItemMessageW(hwndDlg, IDC_EDITTYPE_LISTBOX, LB_DELETESTRING, iItem, 0);
    return TRUE;
}

static BOOL
EditTypeDlg_UpdateEntryIcon(HWND hwndDlg, EDITTYPE_DIALOG *pEditType, LPCWSTR IconPath, INT IconIndex)
{
    FOLDER_FILE_TYPE_ENTRY *pEntry = pEditType->pEntry;

    BOOL bIconSet = FALSE;
    if (IconPath && IconPath[0])
    {
        DestroyIcon(pEntry->hIconLarge);
        DestroyIcon(pEntry->hIconSmall);
        pEntry->hIconLarge = DoExtractIcon(pEntry, IconPath, IconIndex, FALSE);
        pEntry->hIconSmall = DoExtractIcon(pEntry, IconPath, IconIndex, TRUE);

        bIconSet = (pEntry->hIconLarge && pEntry->hIconSmall);
    }
    if (bIconSet)
    {
        StringCchCopyW(pEntry->IconPath, _countof(pEntry->IconPath), IconPath);
        pEntry->nIconIndex = IconIndex;
    }
    else
    {
        SetFileTypeEntryDefaultIcon(pEntry);
    }

    HWND hListView = pEditType->hwndLV;
    HIMAGELIST himlLarge = ListView_GetImageList(hListView, LVSIL_NORMAL);
    HIMAGELIST himlSmall = ListView_GetImageList(hListView, LVSIL_SMALL);

    INT iLargeImage = ImageList_AddIcon(himlLarge, pEntry->hIconLarge);
    INT iSmallImage = ImageList_AddIcon(himlSmall, pEntry->hIconSmall);
    ASSERT(iLargeImage == iSmallImage);

    INT iItem = ListView_GetNextItem(hListView, -1, LVNI_SELECTED);
    if (iItem != -1)
    {
        LV_ITEMW Item = { LVIF_IMAGE, iItem };
        Item.iImage = iSmallImage;
        ListView_SetItem(hListView, &Item);
    }
    return TRUE;
}

static void
EditTypeDlg_OnOK(HWND hwndDlg, EDITTYPE_DIALOG *pEditType)
{
    FOLDER_FILE_TYPE_ENTRY *pEntry = pEditType->pEntry;

    // get class name
    GetDlgItemTextW(hwndDlg, IDC_EDITTYPE_TEXT, pEntry->ClassName, _countof(pEntry->ClassName));
    StrTrimW(pEntry->ClassName, s_pszSpace);

    // update entry icon
    EditTypeDlg_UpdateEntryIcon(hwndDlg, pEditType, pEditType->szIconPath, pEditType->nIconIndex);

    // write registry
    EditTypeDlg_WriteClass(hwndDlg, pEditType, pEntry->ClassKey, pEntry->ClassName, _countof(pEntry->ClassName));

    // update the icon cache
    SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_FLUSHNOWAIT, NULL, NULL);

    EndDialog(hwndDlg, IDOK);
}

struct ACTION_DIALOG
{
    HWND hwndLB;
    WCHAR ClassName[64];
    WCHAR szAction[64];
    WCHAR szApp[MAX_PATH];
    BOOL bUseDDE;
};

static void
NewAct_OnOK(HWND hwndDlg, ACTION_DIALOG *pNewAct)
{
    GetDlgItemTextW(hwndDlg, IDC_ACTION_ACTION, pNewAct->szAction, _countof(pNewAct->szAction));
    GetDlgItemTextW(hwndDlg, IDC_ACTION_APP, pNewAct->szApp, _countof(pNewAct->szApp));
    StrTrimW(pNewAct->szAction, s_pszSpace);
    StrTrimW(pNewAct->szApp, s_pszSpace);
    if (pNewAct->szAction[0] == 0)
    {
        // action is empty, error
        HWND hwndCtrl = GetDlgItem(hwndDlg, IDC_ACTION_ACTION);
        SendMessageW(hwndCtrl, EM_SETSEL, 0, -1);
        SetFocus(hwndCtrl);
        CStringW strText(MAKEINTRESOURCEW(IDS_SPECIFY_ACTION));
        CStringW strTitle(MAKEINTRESOURCEW(IDS_FILE_TYPES));
        MessageBoxW(hwndDlg, strText, strTitle, MB_ICONERROR);
        return;
    }
    if (pNewAct->szApp[0] == 0 || GetFileAttributesW(pNewAct->szApp) == 0xFFFFFFFF)
    {
        // app is invalid
        HWND hwndCtrl = GetDlgItem(hwndDlg, IDC_ACTION_APP);
        SendMessageW(hwndCtrl, EM_SETSEL, 0, -1);
        SetFocus(hwndCtrl);
        CStringW strText(MAKEINTRESOURCEW(IDS_INVALID_PROGRAM));
        CStringW strTitle(MAKEINTRESOURCEW(IDS_FILE_TYPES));
        MessageBoxW(hwndDlg, strText, strTitle, MB_ICONERROR);
        return;
    }
    EndDialog(hwndDlg, IDOK);
}

static void
Action_OnBrowse(HWND hwndDlg, ACTION_DIALOG *pNewAct, BOOL bEdit = FALSE)
{
    WCHAR szFile[MAX_PATH];
    szFile[0] = 0;

    WCHAR szFilter[MAX_PATH];
    LoadStringW(shell32_hInstance, IDS_EXE_FILTER, szFilter, _countof(szFilter));

    CStringW strTitle(MAKEINTRESOURCEW(IDS_OPEN_WITH));

    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = OPENFILENAME_SIZE_VERSION_400W;
    ofn.hwndOwner = hwndDlg;
    ofn.lpstrFilter = szFilter;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = _countof(szFile);
    ofn.lpstrTitle = strTitle;
    ofn.Flags = OFN_ENABLESIZING | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    ofn.lpstrDefExt = L"exe";
    if (GetOpenFileNameW(&ofn))
    {
        if (bEdit)
        {
            CStringW str = szFile;
            str += L" \"%1\"";
            SetDlgItemTextW(hwndDlg, IDC_ACTION_APP, str);
        }
        else
        {
            SetDlgItemTextW(hwndDlg, IDC_ACTION_APP, szFile);
        }
    }
}

INT_PTR CALLBACK
NewActionDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    static ACTION_DIALOG *s_pNewAct = NULL;

    switch (uMsg)
    {
        case WM_INITDIALOG:
            s_pNewAct = (ACTION_DIALOG *)lParam;
            s_pNewAct->bUseDDE = FALSE;
            EnableWindow(GetDlgItem(hwndDlg, IDC_ACTION_USE_DDE), FALSE);
            return TRUE;

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDOK:
                    NewAct_OnOK(hwndDlg, s_pNewAct);
                    break;

                case IDCANCEL:
                    EndDialog(hwndDlg, IDCANCEL);
                    break;

                case IDC_ACTION_BROWSE:
                    Action_OnBrowse(hwndDlg, s_pNewAct, FALSE);
                    break;
            }
            break;
    }
    return 0;
}

static void
EditAct_OnOK(HWND hwndDlg, ACTION_DIALOG *pEditAct)
{
    GetDlgItemTextW(hwndDlg, IDC_ACTION_ACTION, pEditAct->szAction, _countof(pEditAct->szAction));
    GetDlgItemTextW(hwndDlg, IDC_ACTION_APP, pEditAct->szApp, _countof(pEditAct->szApp));
    StrTrimW(pEditAct->szAction, s_pszSpace);
    StrTrimW(pEditAct->szApp, s_pszSpace);
    if (pEditAct->szAction[0] == 0)
    {
        HWND hwndCtrl = GetDlgItem(hwndDlg, IDC_ACTION_ACTION);
        SendMessageW(hwndCtrl, EM_SETSEL, 0, -1);
        SetFocus(hwndCtrl);
        CStringW strText(MAKEINTRESOURCEW(IDS_SPECIFY_ACTION));
        CStringW strTitle(MAKEINTRESOURCEW(IDS_FILE_TYPES));
        MessageBoxW(hwndDlg, strText, strTitle, MB_ICONERROR);
    }
    if (pEditAct->szApp[0] == 0)
    {
        HWND hwndCtrl = GetDlgItem(hwndDlg, IDC_ACTION_APP);
        SendMessageW(hwndCtrl, EM_SETSEL, 0, -1);
        SetFocus(hwndCtrl);
        CStringW strText(MAKEINTRESOURCEW(IDS_INVALID_PROGRAM));
        CStringW strTitle(MAKEINTRESOURCEW(IDS_FILE_TYPES));
        MessageBoxW(hwndDlg, strText, strTitle, MB_ICONERROR);
    }
    EndDialog(hwndDlg, IDOK);
}

INT_PTR CALLBACK
EditActionDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    static ACTION_DIALOG *s_pEditAct = NULL;

    switch (uMsg)
    {
        case WM_INITDIALOG:
            s_pEditAct = (ACTION_DIALOG *)lParam;
            s_pEditAct->bUseDDE = FALSE;
            SetDlgItemTextW(hwndDlg, IDC_ACTION_ACTION, s_pEditAct->szAction);
            SetDlgItemTextW(hwndDlg, IDC_ACTION_APP, s_pEditAct->szApp);
            EnableWindow(GetDlgItem(hwndDlg, IDC_ACTION_USE_DDE), FALSE);
            EnableWindow(GetDlgItem(hwndDlg, IDC_ACTION_ACTION), FALSE);
            {
                // set title
                CStringW str(MAKEINTRESOURCEW(IDS_EDITING_ACTION));
                str += s_pEditAct->ClassName;
                SetWindowTextW(hwndDlg, str);
            }
            return TRUE;

        case WM_COMMAND:
            switch (LOWORD(wParam))
            {
                case IDOK:
                    EditAct_OnOK(hwndDlg, s_pEditAct);
                    break;

                case IDCANCEL:
                    EndDialog(hwndDlg, IDCANCEL);
                    break;

                case IDC_ACTION_BROWSE:
                    Action_OnBrowse(hwndDlg, s_pEditAct, TRUE);
                    break;
            }
            break;
    }
    return 0;
}

static void
EditTypeDlg_OnChangeIcon(HWND hwndDlg, EDITTYPE_DIALOG *pEditType)
{
    WCHAR szPath[MAX_PATH];
    INT IconIndex;

    ExpandEnvironmentStringsW(pEditType->szIconPath, szPath, _countof(szPath));
    IconIndex = pEditType->nIconIndex;
    if (PickIconDlg(hwndDlg, szPath, _countof(szPath), &IconIndex))
    {
        // replace Windows directory with "%SystemRoot%" (for portability)
        WCHAR szWinDir[MAX_PATH];
        GetWindowsDirectoryW(szWinDir, _countof(szWinDir));
        if (wcsstr(szPath, szWinDir) == 0)
        {
            CStringW str(L"%SystemRoot%");
            str += &szPath[wcslen(szWinDir)];
            StringCchCopyW(szPath, _countof(szPath), LPCWSTR(str));
        }

        // update FOLDER_FILE_TYPE_ENTRY
        FOLDER_FILE_TYPE_ENTRY *pEntry = pEditType->pEntry;
        DestroyIcon(pEntry->hIconLarge);
        DestroyIcon(pEntry->hIconSmall);
        pEntry->hIconLarge = DoExtractIcon(pEntry, szPath, IconIndex, FALSE);
        pEntry->hIconSmall = DoExtractIcon(pEntry, szPath, IconIndex, TRUE);

        // update EDITTYPE_DIALOG
        StringCchCopyW(pEditType->szIconPath, _countof(pEditType->szIconPath), szPath);
        pEditType->nIconIndex = IconIndex;

        // set icon to dialog
        SendDlgItemMessageW(hwndDlg, IDC_EDITTYPE_ICON, STM_SETICON, (WPARAM)pEntry->hIconLarge, 0);
    }
}

static BOOL
EditTypeDlg_OnDrawItem(HWND hwndDlg, LPDRAWITEMSTRUCT pDraw, EDITTYPE_DIALOG *pEditType)
{
    WCHAR szText[64];
    HFONT hFont, hFont2;

    if (!pDraw)
        return FALSE;

    // fill rect and set colors
    if (pDraw->itemState & ODS_SELECTED)
    {
        FillRect(pDraw->hDC, &pDraw->rcItem, HBRUSH(COLOR_HIGHLIGHT + 1));
        SetTextColor(pDraw->hDC, GetSysColor(COLOR_HIGHLIGHTTEXT));
        SetBkColor(pDraw->hDC, GetSysColor(COLOR_HIGHLIGHT));
    }
    else
    {
        FillRect(pDraw->hDC, &pDraw->rcItem, HBRUSH(COLOR_WINDOW + 1));
        SetTextColor(pDraw->hDC, GetSysColor(COLOR_WINDOWTEXT));
        SetBkColor(pDraw->hDC, GetSysColor(COLOR_WINDOW));
    }

    // get listbox text
    SendDlgItemMessageW(hwndDlg, IDC_EDITTYPE_LISTBOX, LB_GETTEXT, pDraw->itemID, (LPARAM)szText);

    // is it default?
    hFont = (HFONT)SendDlgItemMessageW(hwndDlg, IDC_EDITTYPE_LISTBOX, WM_GETFONT, 0, 0);
    if (lstrcmpiW(pEditType->szDefaultVerb, szText) == 0)
    {
        // default. set bold
        LOGFONTW lf;
        GetObject(hFont, sizeof(lf), &lf);
        lf.lfWeight = FW_BOLD;
        hFont2 = CreateFontIndirectW(&lf);
        if (hFont2)
        {
            HGDIOBJ hFontOld = SelectObject(pDraw->hDC, hFont2);
            InflateRect(&pDraw->rcItem, -2, -2);
            DrawTextW(pDraw->hDC, szText, -1, &pDraw->rcItem, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
            InflateRect(&pDraw->rcItem, 2, 2);
            SelectObject(pDraw->hDC, hFontOld);
            DeleteObject(hFont2);
        }
    }
    else
    {
        // non-default
        InflateRect(&pDraw->rcItem, -2, -2);
        DrawTextW(pDraw->hDC, szText, -1, &pDraw->rcItem, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
        InflateRect(&pDraw->rcItem, 2, 2);
    }

    // draw focus rect
    if (pDraw->itemState & ODS_FOCUS)
    {
        DrawFocusRect(pDraw->hDC, &pDraw->rcItem);
    }
    return TRUE;
}

static BOOL
EditTypeDlg_OnMeasureItem(HWND hwndDlg, LPMEASUREITEMSTRUCT pMeasure, EDITTYPE_DIALOG *pEditType)
{
    if (!pMeasure)
        return FALSE;

    HWND hwndLB = GetDlgItem(hwndDlg, IDC_EDITTYPE_LISTBOX);

    RECT rc;
    GetClientRect(hwndLB, &rc);

    HDC hDC = GetDC(hwndLB);
    if (hDC)
    {
        TEXTMETRICW tm;
        GetTextMetricsW(hDC, &tm);
        pMeasure->itemWidth = rc.right - rc.left;
        pMeasure->itemHeight = tm.tmHeight + 4;
        ReleaseDC(hwndLB, hDC);
        return TRUE;
    }
    return FALSE;
}

static void
EditTypeDlg_OnCommand(HWND hwndDlg, UINT id, UINT code, EDITTYPE_DIALOG *pEditType)
{
    INT iItem, iIndex;
    ACTION_DIALOG action;
    switch (id)
    {
        case IDOK:
            EditTypeDlg_OnOK(hwndDlg, pEditType);
            break;

        case IDCANCEL:
            EndDialog(hwndDlg, IDCANCEL);
            break;

        case IDC_EDITTYPE_CHANGE_ICON:
            EditTypeDlg_OnChangeIcon(hwndDlg, pEditType);
            break;

        case IDC_EDITTYPE_NEW:
            action.bUseDDE = FALSE;
            action.hwndLB = GetDlgItem(hwndDlg, IDC_EDITTYPE_LISTBOX);
            StringCchPrintfW(action.ClassName, _countof(action.ClassName), pEditType->pEntry->ClassName);
            // open 'New Action' dialog
            if (IDOK == DialogBoxParamW(shell32_hInstance, MAKEINTRESOURCEW(IDD_ACTION), hwndDlg,
                                        NewActionDlgProc, LPARAM(&action)))
            {
                if (SendMessageW(action.hwndLB, LB_FINDSTRING, -1, (LPARAM)action.szAction) != LB_ERR)
                {
                    // already exists, error
                    HWND hwndCtrl = GetDlgItem(hwndDlg, IDC_ACTION_ACTION);
                    SendMessageW(hwndCtrl, EM_SETSEL, 0, -1);
                    SetFocus(hwndCtrl);

                    CStringW strText, strTitle(MAKEINTRESOURCEW(IDS_FILE_TYPES));
                    strText.Format(IDS_ACTION_EXISTS, action.szAction);
                    MessageBoxW(hwndDlg, strText, strTitle, MB_ICONERROR);
                }
                else
                {
                    // add it
                    CStringW strCommandLine = action.szApp;
                    strCommandLine += L" \"%1\"";
                    pEditType->CommandLineMap.SetAt(action.szAction, strCommandLine);
                    SendMessageW(action.hwndLB, LB_ADDSTRING, 0, LPARAM(action.szAction));
                    if (SendMessageW(action.hwndLB, LB_GETCOUNT, 0, 0) == 1)
                    {
                        // set default
                        StringCchCopyW(pEditType->szDefaultVerb, _countof(pEditType->szDefaultVerb), action.szAction);
                        InvalidateRect(action.hwndLB, NULL, TRUE);
                    }
                }
            }
            break;

        case IDC_EDITTYPE_LISTBOX:
            if (code == LBN_SELCHANGE)
            {
                action.hwndLB = GetDlgItem(hwndDlg, IDC_EDITTYPE_LISTBOX);
                INT iItem = SendMessageW(action.hwndLB, LB_GETCURSEL, 0, 0);
                SendMessageW(action.hwndLB, LB_GETTEXT, iItem, LPARAM(action.szAction));
                if (lstrcmpiW(action.szAction, pEditType->szDefaultVerb) == 0)
                {
                    EnableWindow(GetDlgItem(hwndDlg, IDC_EDITTYPE_SET_DEFAULT), FALSE);
                }
                else
                {
                    EnableWindow(GetDlgItem(hwndDlg, IDC_EDITTYPE_SET_DEFAULT), TRUE);
                }
                break;
            }
            else if (code != LBN_DBLCLK)
            {
                break;
            }
            // FALL THROUGH

        case IDC_EDITTYPE_EDIT_BUTTON:
            action.bUseDDE = FALSE;
            action.hwndLB = GetDlgItem(hwndDlg, IDC_EDITTYPE_LISTBOX);
            StringCchPrintfW(action.ClassName, _countof(action.ClassName), pEditType->pEntry->ClassName);
            iItem = SendMessageW(action.hwndLB, LB_GETCURSEL, 0, 0);
            if (iItem == LB_ERR)
                break;

            // get action
            SendMessageW(action.hwndLB, LB_GETTEXT, iItem, LPARAM(action.szAction));

            // get app
            {
                iIndex = pEditType->CommandLineMap.FindKey(action.szAction);
                CStringW str = pEditType->CommandLineMap.GetValueAt(iIndex);
                StringCchCopyW(action.szApp, _countof(action.szApp), LPCWSTR(str));
            }

            // open dialog
            if (IDOK == DialogBoxParamW(shell32_hInstance, MAKEINTRESOURCEW(IDD_ACTION), hwndDlg,
                                        EditActionDlgProc, LPARAM(&action)))
            {
                SendMessageW(action.hwndLB, LB_DELETESTRING, iItem, 0);
                SendMessageW(action.hwndLB, LB_INSERTSTRING, iItem, LPARAM(action.szAction));
                pEditType->CommandLineMap.SetAt(action.szAction, action.szApp);
            }
            break;

        case IDC_EDITTYPE_REMOVE:
            EditTypeDlg_OnRemove(hwndDlg, pEditType);
            break;

        case IDC_EDITTYPE_SET_DEFAULT:
            action.hwndLB = GetDlgItem(hwndDlg, IDC_EDITTYPE_LISTBOX);
            iItem = SendMessageW(action.hwndLB, LB_GETCURSEL, 0, 0);
            if (iItem == LB_ERR)
                break;

            SendMessageW(action.hwndLB, LB_GETTEXT, iItem, LPARAM(action.szAction));

            // set default
            StringCchCopyW(pEditType->szDefaultVerb, _countof(pEditType->szDefaultVerb), action.szAction);
            EnableWindow(GetDlgItem(hwndDlg, IDC_EDITTYPE_SET_DEFAULT), FALSE);
            InvalidateRect(action.hwndLB, NULL, TRUE);
            break;
    }
}

INT_PTR CALLBACK
EditTypeDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    static EDITTYPE_DIALOG *s_pEditType = NULL;
    LPDRAWITEMSTRUCT pDraw;
    LPMEASUREITEMSTRUCT pMeasure;

    switch (uMsg)
    {
        case WM_INITDIALOG:
            s_pEditType = (EDITTYPE_DIALOG *)lParam;
            return EditTypeDlg_OnInitDialog(hwndDlg, s_pEditType);

        case WM_DRAWITEM:
            pDraw = LPDRAWITEMSTRUCT(lParam);
            return EditTypeDlg_OnDrawItem(hwndDlg, pDraw, s_pEditType);

        case WM_MEASUREITEM:
            pMeasure = LPMEASUREITEMSTRUCT(lParam);
            return EditTypeDlg_OnMeasureItem(hwndDlg, pMeasure, s_pEditType);

        case WM_COMMAND:
            EditTypeDlg_OnCommand(hwndDlg, LOWORD(wParam), HIWORD(wParam), s_pEditType);
            break;
    }

    return 0;
}

static void
EditTypeDlg_OnDelete(HWND hwndDlg)
{
    CStringW strRemoveExt(MAKEINTRESOURCEW(IDS_REMOVE_EXT));
    CStringW strTitle(MAKEINTRESOURCEW(IDS_FILE_TYPES));
    if (MessageBoxW(hwndDlg, strRemoveExt, strTitle, MB_ICONQUESTION | MB_YESNO) == IDYES)
    {
        FileTypesDlg_RemoveExt(hwndDlg);
    }
}

// IDD_FOLDER_OPTIONS_FILETYPES dialog
INT_PTR
CALLBACK
FolderOptionsFileTypesDlg(
    HWND hwndDlg,
    UINT uMsg,
    WPARAM wParam,
    LPARAM lParam)
{
    LPNMLISTVIEW lppl;
    PFOLDER_FILE_TYPE_ENTRY pItem;
    OPENASINFO Info;
    NEWEXT_DIALOG newext;
    EDITTYPE_DIALOG edittype;

    switch(uMsg)
    {
        case WM_INITDIALOG:
            pItem = InitializeFileTypesListCtrl(hwndDlg);

            /* Disable the Delete button if the listview is empty or
               the selected item should not be deleted by the user */
            if (pItem == NULL || (pItem->EditFlags & 0x00000010)) // FTA_NoRemove
                EnableWindow(GetDlgItem(hwndDlg, IDC_FILETYPES_DELETE), FALSE);
            return TRUE;

        case WM_COMMAND:
            switch(LOWORD(wParam))
            {
                case IDC_FILETYPES_NEW:
                    newext.hwndLV = GetDlgItem(hwndDlg, IDC_FILETYPES_LISTVIEW);
                    if (IDOK == DialogBoxParamW(shell32_hInstance, MAKEINTRESOURCEW(IDD_NEWEXTENSION),
                                                hwndDlg, NewExtensionDlgProc, (LPARAM)&newext))
                    {
                        FileTypesDlg_AddExt(hwndDlg, newext.szExt, newext.szFileType);
                    }
                    break;

                case IDC_FILETYPES_DELETE:
                    EditTypeDlg_OnDelete(hwndDlg);
                    break;

                case IDC_FILETYPES_CHANGE:
                    pItem = GetListViewEntry(GetDlgItem(hwndDlg, IDC_FILETYPES_LISTVIEW));
                    if (pItem)
                    {
                        Info.oaifInFlags = OAIF_ALLOW_REGISTRATION | OAIF_REGISTER_EXT;
                        Info.pcszClass = pItem->FileExtension;
                        SHOpenWithDialog(hwndDlg, &Info);
                    }
                    break;

                case IDC_FILETYPES_ADVANCED:
                    edittype.hwndLV = GetDlgItem(hwndDlg, IDC_FILETYPES_LISTVIEW);
                    edittype.pEntry = GetListViewEntry(edittype.hwndLV);
                    DialogBoxParamW(shell32_hInstance, MAKEINTRESOURCEW(IDD_EDITTYPE),
                                    hwndDlg, EditTypeDlgProc, (LPARAM)&edittype);
                    break;
            }
            break;

        case WM_NOTIFY:
            lppl = (LPNMLISTVIEW) lParam;
            switch (lppl->hdr.code)
            {
                case LVN_KEYDOWN:
                {
                    LV_KEYDOWN *pKeyDown = (LV_KEYDOWN *)lParam;
                    if (pKeyDown->wVKey == VK_DELETE)
                    {
                        EditTypeDlg_OnDelete(hwndDlg);
                    }
                    break;
                }

                case NM_DBLCLK:
                    edittype.hwndLV = GetDlgItem(hwndDlg, IDC_FILETYPES_LISTVIEW);
                    edittype.pEntry = GetListViewEntry(edittype.hwndLV);
                    DialogBoxParamW(shell32_hInstance, MAKEINTRESOURCEW(IDD_EDITTYPE),
                                    hwndDlg, EditTypeDlgProc, (LPARAM)&edittype);
                    break;

                case LVN_DELETEALLITEMS:
                    return FALSE;   // send LVN_DELETEITEM

                case LVN_DELETEITEM:
                    pItem = GetListViewEntry(lppl->hdr.hwndFrom, lppl->iItem);
                    if (pItem)
                    {
                        DestroyIcon(pItem->hIconLarge);
                        DestroyIcon(pItem->hIconSmall);
                        HeapFree(GetProcessHeap(), 0, pItem);
                    }
                    return FALSE;

                case LVN_ITEMCHANGING:
                    pItem = GetListViewEntry(lppl->hdr.hwndFrom, lppl->iItem);
                    if (!pItem)
                    {
                        return TRUE;
                    }

                    if (!(lppl->uOldState & LVIS_FOCUSED) && (lppl->uNewState & LVIS_FOCUSED))
                    {
                        FileTypesDlg_OnItemChanging(hwndDlg, pItem);
                    }
                    break;

                case PSN_SETACTIVE:
                    /* On page activation, set the focus to the listview */
                    SetFocus(GetDlgItem(hwndDlg, IDC_FILETYPES_LISTVIEW));
                    break;
            }
            break;
    }

    return FALSE;
}

static
VOID
ShowFolderOptionsDialog(HWND hWnd, HINSTANCE hInst)
{
    PROPSHEETHEADERW pinfo;
    HPROPSHEETPAGE hppages[3];
    HPROPSHEETPAGE hpage;
    UINT num_pages = 0;
    WCHAR szOptions[100];

    hpage = SH_CreatePropertySheetPage(IDD_FOLDER_OPTIONS_GENERAL, FolderOptionsGeneralDlg, 0, NULL);
    if (hpage)
        hppages[num_pages++] = hpage;

    hpage = SH_CreatePropertySheetPage(IDD_FOLDER_OPTIONS_VIEW, FolderOptionsViewDlg, 0, NULL);
    if (hpage)
        hppages[num_pages++] = hpage;

    hpage = SH_CreatePropertySheetPage(IDD_FOLDER_OPTIONS_FILETYPES, FolderOptionsFileTypesDlg, 0, NULL);
    if (hpage)
        hppages[num_pages++] = hpage;

    szOptions[0] = L'\0';
    LoadStringW(shell32_hInstance, IDS_FOLDER_OPTIONS, szOptions, sizeof(szOptions) / sizeof(WCHAR));
    szOptions[(sizeof(szOptions)/sizeof(WCHAR))-1] = L'\0';

    memset(&pinfo, 0x0, sizeof(PROPSHEETHEADERW));
    pinfo.dwSize = sizeof(PROPSHEETHEADERW);
    pinfo.dwFlags = PSH_NOCONTEXTHELP;
    pinfo.nPages = num_pages;
    pinfo.phpage = hppages;
    pinfo.pszCaption = szOptions;

    PropertySheetW(&pinfo);
}

static
VOID
Options_RunDLLCommon(HWND hWnd, HINSTANCE hInst, int fOptions, DWORD nCmdShow)
{
    switch(fOptions)
    {
        case 0:
            ShowFolderOptionsDialog(hWnd, hInst);
            break;

        case 1:
            // show taskbar options dialog
            FIXME("notify explorer to show taskbar options dialog");
            //PostMessage(GetShellWindow(), WM_USER+22, fOptions, 0);
            break;

        default:
            FIXME("unrecognized options id %d\n", fOptions);
    }
}

/*************************************************************************
 *              Options_RunDLL (SHELL32.@)
 */
EXTERN_C VOID WINAPI Options_RunDLL(HWND hWnd, HINSTANCE hInst, LPCSTR cmd, DWORD nCmdShow)
{
    Options_RunDLLCommon(hWnd, hInst, StrToIntA(cmd), nCmdShow);
}

/*************************************************************************
 *              Options_RunDLLA (SHELL32.@)
 */
EXTERN_C VOID WINAPI Options_RunDLLA(HWND hWnd, HINSTANCE hInst, LPCSTR cmd, DWORD nCmdShow)
{
    Options_RunDLLCommon(hWnd, hInst, StrToIntA(cmd), nCmdShow);
}

/*************************************************************************
 *              Options_RunDLLW (SHELL32.@)
 */
EXTERN_C VOID WINAPI Options_RunDLLW(HWND hWnd, HINSTANCE hInst, LPCWSTR cmd, DWORD nCmdShow)
{
    Options_RunDLLCommon(hWnd, hInst, StrToIntW(cmd), nCmdShow);
}
