/*
 * PROJECT:     ReactOS Task Manager
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     "About" dialog box of Task Manager
 * COPYRIGHT:   Copyright (C) 1999-2001 Brian Palmer <brianp@reactos.org>
 */

#include "precomp.h"

void OnAbout(void)
{
    WCHAR szTaskmgr[128];
    HICON taskmgrIcon = LoadIcon(hInst, MAKEINTRESOURCE(IDI_TASKMANAGER));

    LoadStringW(hInst, IDS_APP_TITLE, szTaskmgr, sizeof(szTaskmgr)/sizeof(WCHAR));
    ShellAboutW(hMainWnd, szTaskmgr, NULL, taskmgrIcon);
    DeleteObject(taskmgrIcon);
}
