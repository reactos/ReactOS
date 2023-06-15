/*
 * PROJECT:     ReactOS Task Manager
 * LICENSE:     LGPL-2.1-or-later (https://spdx.org/licenses/LGPL-2.1-or-later)
 * PURPOSE:     The Process page
 * COPYRIGHT:   Copyright (C) 1999-2001 Brian Palmer <brianp@reactos.org>
 *              Copyright (C) 2009 Maxime Vernier <maxime.vernier@gmail.com>
 *              Copyright (C) 2022 Thamatip Chitpong <tangaming123456@outlook.com>
 */

#pragma once

extern	HWND		hProcessPage;				/* Process List Property Page */
extern	HWND		hProcessPageListCtrl;			/* Process ListCtrl Window */
extern	HWND		hProcessPageHeaderCtrl;			/* Process Header Control */
extern	HWND		hProcessPageEndProcessButton;		/* Process End Process button */
extern	HWND		hProcessPageShowAllProcessesButton;	/* Process Show All Processes checkbox */

INT_PTR CALLBACK	ProcessPageWndProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
void				RefreshProcessPage(void);
DWORD               GetSelectedProcessId(void);
void                ProcessPage_OnProperties(void);
void                ProcessPage_OnOpenFileLocation(void);
