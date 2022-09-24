/*
 * PROJECT:         input.dll
 * FILE:            dll/cpl/input/settings_page.c
 * PURPOSE:         input.dll
 * PROGRAMMERS:     Dmitry Chapyshev (dmitry@reactos.org)
 *                  Katayama Hirofumi MZ (katayama.hirofumi.mz@gmail.com)
 */

#include "input.h"
#include "layout_list.h"
#include "locale_list.h"
#include "input_list.h"

static HICON
CreateLayoutIcon(LPWSTR szLayout, BOOL bIsDefault)
{
    INT width = GetSystemMetrics(SM_CXSMICON) * 2;
    INT height = GetSystemMetrics(SM_CYSMICON);
    HDC hdc;
    HDC hdcsrc;
    HBITMAP hBitmap;
    HICON hIcon = NULL;

    hdcsrc = GetDC(NULL);
    hdc = CreateCompatibleDC(hdcsrc);
    hBitmap = CreateCompatibleBitmap(hdcsrc, width, height);

    ReleaseDC(NULL, hdcsrc);

    if (hdc && hBitmap)
    {
        HBITMAP hBmpNew;

        hBmpNew = CreateBitmap(width, height, 1, 1, NULL);
        if (hBmpNew)
        {
            LOGFONTW lf;

            if (SystemParametersInfoW(SPI_GETICONTITLELOGFONT, sizeof(lf), &lf, 0))
            {
                ICONINFO IconInfo;
                HFONT hFont;

                hFont = CreateFontIndirectW(&lf);

                if (hFont != NULL)
                {
                    HBITMAP hBmpOld;

                    hBmpOld = SelectObject(hdc, hBitmap);

                    if (hBmpOld != NULL)
                    {
                        RECT rect;

                        SetRect(&rect, 0, 0, width / 2, height);

                        if (bIsDefault != FALSE)
                        {
                            SetBkColor(hdc, GetSysColor(COLOR_WINDOW));
                            SetTextColor(hdc, GetSysColor(COLOR_WINDOWTEXT));

                            ExtTextOutW(hdc, rect.left, rect.top, ETO_OPAQUE, &rect, L"", 0, NULL);

                            SelectObject(hdc, hFont);
                            DrawFrameControl(hdc, &rect, DFC_MENU, DFCS_MENUBULLET);
                        }
                        else
                        {
                            FillRect(hdc, &rect, GetSysColorBrush(COLOR_WINDOW));
                        }

                        SetRect(&rect, width / 2, 0, width, height);

                        SetBkColor(hdc, GetSysColor(COLOR_HIGHLIGHT));
                        SetTextColor(hdc, GetSysColor(COLOR_HIGHLIGHTTEXT));

                        ExtTextOutW(hdc, rect.left, rect.top, ETO_OPAQUE, &rect, L"", 0, NULL);

                        SelectObject(hdc, hFont);
                        DrawTextW(hdc, szLayout, 2, &rect, DT_SINGLELINE | DT_CENTER | DT_VCENTER);

                        SelectObject(hdc, hBmpNew);

                        PatBlt(hdc, 0, 0, width, height, BLACKNESS);

                        SelectObject(hdc, hBmpOld);

                        IconInfo.hbmColor = hBitmap;
                        IconInfo.hbmMask = hBmpNew;
                        IconInfo.fIcon = TRUE;

                        hIcon = CreateIconIndirect(&IconInfo);

                        DeleteObject(hBmpOld);
                    }

                    DeleteObject(hFont);
                }
            }

            DeleteObject(hBmpNew);
        }
    }

    DeleteDC(hdc);
    DeleteObject(hBitmap);

    return hIcon;
}


static VOID
SetControlsState(HWND hwndDlg)
{
    HWND hwndList = GetDlgItem(hwndDlg, IDC_KEYLAYOUT_LIST);
    INT iSelected = ListView_GetNextItem(hwndList, -1, LVNI_SELECTED);
    INT nCount = ListView_GetItemCount(hwndList);
    BOOL bCanRemove = (iSelected != -1) && (nCount >= 2);
    BOOL bCanDefault = (iSelected != -1) && (nCount >= 2);
    BOOL bCanProp = (iSelected != -1);

    LV_ITEM item = { LVIF_PARAM, iSelected };
    if (ListView_GetItem(hwndList, &item))
    {
        INPUT_LIST_NODE *pInput = (INPUT_LIST_NODE*)item.lParam;

        if (pInput && (pInput->wFlags & INPUT_LIST_NODE_FLAG_DEFAULT))
        {
            bCanDefault = FALSE;
        }
    }

    EnableWindow(GetDlgItem(hwndDlg, IDC_REMOVE_BUTTON), bCanRemove);
    EnableWindow(GetDlgItem(hwndDlg, IDC_PROP_BUTTON), bCanProp);
    EnableWindow(GetDlgItem(hwndDlg, IDC_SET_DEFAULT), bCanDefault);
}

static VOID
AddToInputListView(HWND hwndList, INPUT_LIST_NODE *pInputNode)
{
    INT ItemIndex, ImageIndex = -1;
    LV_ITEM item;
    HIMAGELIST hImageList = ListView_GetImageList(hwndList, LVSIL_SMALL);

    if (hImageList != NULL)
    {
        HICON hLayoutIcon;

        hLayoutIcon = CreateLayoutIcon(pInputNode->pszIndicator,
                                       (pInputNode->wFlags & INPUT_LIST_NODE_FLAG_DEFAULT));
        if (hLayoutIcon != NULL)
        {
            ImageIndex = ImageList_AddIcon(hImageList, hLayoutIcon);
            DestroyIcon(hLayoutIcon);
        }
    }

    ZeroMemory(&item, sizeof(item));
    item.mask    = LVIF_TEXT | LVIF_PARAM | LVIF_IMAGE;
    item.pszText = pInputNode->pLocale->pszName;
    item.iItem   = ListView_GetItemCount(hwndList);
    item.lParam  = (LPARAM)pInputNode;
    item.iImage  = ImageIndex;
    ItemIndex = ListView_InsertItem(hwndList, &item);

    ListView_SetItemText(hwndList, ItemIndex, 1, pInputNode->pLayout->pszName);
}


static VOID
UpdateInputListView(HWND hwndList)
{
    INPUT_LIST_NODE *pNode;
    HIMAGELIST hImageList = ListView_GetImageList(hwndList, LVSIL_SMALL);
    INT iSelected = ListView_GetNextItem(hwndList, -1, LVNI_SELECTED);

    if (hImageList)
    {
        ImageList_RemoveAll(hImageList);
    }

    ListView_DeleteAllItems(hwndList);

    for (pNode = InputList_GetFirst(); pNode != NULL; pNode = pNode->pNext)
    {
        if (pNode->wFlags & INPUT_LIST_NODE_FLAG_DELETED)
            continue;

        AddToInputListView(hwndList, pNode);
    }

    if (iSelected != -1)
    {
        INT nCount = ListView_GetItemCount(hwndList);
        LV_ITEM item = { LVIF_STATE };
        item.state = item.stateMask = LVIS_SELECTED;
        item.iItem = ((nCount == iSelected) ? nCount - 1 : iSelected);
        ListView_SetItem(hwndList, &item);
    }

    InvalidateRect(hwndList, NULL, TRUE);
}


static VOID
OnInitSettingsPage(HWND hwndDlg)
{
    HWND hwndInputList = GetDlgItem(hwndDlg, IDC_KEYLAYOUT_LIST);

    LayoutList_Create();
    LocaleList_Create();
    InputList_Create();

    if (hwndInputList != NULL)
    {
        WCHAR szBuffer[MAX_STR_LEN];
        HIMAGELIST hLayoutImageList;
        LV_COLUMN column = { LVCF_FMT | LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM };

        ListView_SetExtendedListViewStyle(hwndInputList, LVS_EX_FULLROWSELECT);

        LoadStringW(hApplet, IDS_LANGUAGE, szBuffer, ARRAYSIZE(szBuffer));
        column.fmt      = LVCFMT_LEFT;
        column.iSubItem = 0;
        column.pszText  = szBuffer;
        column.cx       = 175;
        ListView_InsertColumn(hwndInputList, 0, &column);

        LoadStringW(hApplet, IDS_LAYOUT, szBuffer, ARRAYSIZE(szBuffer));
        column.fmt      = LVCFMT_RIGHT;
        column.cx       = 155;
        column.iSubItem = 1;
        column.pszText  = szBuffer;
        ListView_InsertColumn(hwndInputList, 1, &column);

        hLayoutImageList = ImageList_Create(GetSystemMetrics(SM_CXSMICON) * 2,
                                            GetSystemMetrics(SM_CYSMICON),
                                            ILC_COLOR8 | ILC_MASK, 0, 0);
        if (hLayoutImageList != NULL)
        {
            HIMAGELIST hOldImagelist = ListView_SetImageList(hwndInputList, hLayoutImageList, LVSIL_SMALL);
            ImageList_Destroy(hOldImagelist);
        }

        UpdateInputListView(hwndInputList);
    }

    SetControlsState(hwndDlg);
}


static VOID
OnDestroySettingsPage(HWND hwndDlg)
{
    LayoutList_Destroy();
    LocaleList_Destroy();
    InputList_Destroy();
}


VOID
OnCommandSettingsPage(HWND hwndDlg, WPARAM wParam)
{
    switch (LOWORD(wParam))
    {
        case IDC_ADD_BUTTON:
        {
            if (DialogBoxW(hApplet,
                           MAKEINTRESOURCEW(IDD_ADD),
                           hwndDlg,
                           AddDialogProc) == IDOK)
            {
                UpdateInputListView(GetDlgItem(hwndDlg, IDC_KEYLAYOUT_LIST));
                SetControlsState(hwndDlg);
                PropSheet_Changed(GetParent(hwndDlg), hwndDlg);
            }
        }
        break;

        case IDC_REMOVE_BUTTON:
        {
            HWND hwndList = GetDlgItem(hwndDlg, IDC_KEYLAYOUT_LIST);
            if (hwndList)
            {
                LVITEM item = { LVIF_PARAM };
                item.iItem = ListView_GetNextItem(hwndList, -1, LVNI_SELECTED);

                if (ListView_GetItem(hwndList, &item))
                {
                    InputList_Remove((INPUT_LIST_NODE*) item.lParam);
                    UpdateInputListView(hwndList);
                    SetControlsState(hwndDlg);
                    PropSheet_Changed(GetParent(hwndDlg), hwndDlg);
                }
            }
        }
        break;

        case IDC_PROP_BUTTON:
        {
            HWND hwndList = GetDlgItem(hwndDlg, IDC_KEYLAYOUT_LIST);
            if (hwndList)
            {
                LVITEM item = { LVIF_PARAM };
                item.iItem = ListView_GetNextItem(hwndList, -1, LVNI_SELECTED);

                if (ListView_GetItem(hwndList, &item))
                {
                    if (DialogBoxParamW(hApplet,
                                        MAKEINTRESOURCEW(IDD_INPUT_LANG_PROP),
                                        hwndDlg,
                                        EditDialogProc,
                                        item.lParam) == IDOK)
                    {
                        UpdateInputListView(hwndList);
                        SetControlsState(hwndDlg);
                        PropSheet_Changed(GetParent(hwndDlg), hwndDlg);
                    }
                }
            }
        }
        break;

        case IDC_SET_DEFAULT:
        {
            HWND hwndList = GetDlgItem(hwndDlg, IDC_KEYLAYOUT_LIST);
            if (hwndList)
            {
                LVITEM item = { LVIF_PARAM };
                item.iItem = ListView_GetNextItem(hwndList, -1, LVNI_SELECTED);

                if (ListView_GetItem(hwndList, &item))
                {
                    InputList_SetDefault((INPUT_LIST_NODE*) item.lParam);
                    UpdateInputListView(hwndList);
                    SetControlsState(hwndDlg);
                    PropSheet_Changed(GetParent(hwndDlg), hwndDlg);
                }
            }
        }
        break;

        case IDC_KEY_SET_BTN:
        {
            DialogBoxW(hApplet,
                       MAKEINTRESOURCEW(IDD_KEYSETTINGS),
                       hwndDlg,
                       KeySettingsDialogProc);
        }
        break;
    }
}

static BOOL IsRebootNeeded(VOID)
{
    INPUT_LIST_NODE *pNode;

    for (pNode = InputList_GetFirst(); pNode != NULL; pNode = pNode->pNext)
    {
        if (IS_IME_HKL(pNode->hkl)) /* IME? */
        {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL EnableProcessPrivileges(LPCWSTR lpPrivilegeName, BOOL bEnable)
{
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tokenPrivileges;
    BOOL Ret;

    Ret = OpenProcessToken(GetCurrentProcess(),
                           TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                           &hToken);
    if (!Ret)
        return Ret;     // failure

    Ret = LookupPrivilegeValueW(NULL, lpPrivilegeName, &luid);
    if (Ret)
    {
        tokenPrivileges.PrivilegeCount = 1;
        tokenPrivileges.Privileges[0].Luid = luid;
        tokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

        Ret = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, 0, 0, 0);
    }

    CloseHandle(hToken);
    return Ret;
}

static VOID
OnNotifySettingsPage(HWND hwndDlg, LPARAM lParam)
{
    LPNMHDR header = (LPNMHDR)lParam;

    switch (header->code)
    {
        case LVN_ITEMCHANGED:
        {
            if (header->idFrom == IDC_KEYLAYOUT_LIST)
            {
                SetControlsState(hwndDlg);
            }
        }
        break;

        case PSN_APPLY:
        {
            BOOL bRebootNeeded = IsRebootNeeded();

            /* Write Input Methods list to registry */
            if (InputList_Process() && bRebootNeeded)
            {
                /* Needs reboot */
                WCHAR szNeedsReboot[128], szLanguage[64];
                LoadStringW(hApplet, IDS_REBOOT_NOW, szNeedsReboot, _countof(szNeedsReboot));
                LoadStringW(hApplet, IDS_LANGUAGE, szLanguage, _countof(szLanguage));

                if (MessageBoxW(hwndDlg, szNeedsReboot, szLanguage,
                                MB_ICONINFORMATION | MB_YESNOCANCEL) == IDYES)
                {
                    EnableProcessPrivileges(SE_SHUTDOWN_NAME, TRUE);
                    ExitWindowsEx(EWX_REBOOT | EWX_FORCE, 0);
                }
            }
        }
        break;
    }
}


INT_PTR CALLBACK
SettingsPageProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_INITDIALOG:
            OnInitSettingsPage(hwndDlg);
            break;

        case WM_DESTROY:
            OnDestroySettingsPage(hwndDlg);
            break;

        case WM_COMMAND:
            OnCommandSettingsPage(hwndDlg, wParam);
            break;

        case WM_NOTIFY:
            OnNotifySettingsPage(hwndDlg, lParam);
            break;
    }

    return FALSE;
}
