/*
 * COPYRIGHT:   See COPYING in the top level directory
 * PROJECT:     ReactOS Sound Volume Control
 * FILE:        base/applications/sndvol32/dialog.c
 * PROGRAMMERS: Johannes Anderwald
 */

#include "sndvol32.h"


VOID
ConvertRect(LPRECT lpRect, UINT xBaseUnit, UINT yBaseUnit)
{
    lpRect->left = MulDiv(lpRect->left, xBaseUnit, 4);
    lpRect->right = MulDiv(lpRect->right, xBaseUnit, 4);
    lpRect->top = MulDiv(lpRect->top, yBaseUnit, 8);
    lpRect->bottom = MulDiv(lpRect->bottom, yBaseUnit, 8);
}

LPVOID
LoadDialogResource(
    IN HMODULE hModule,
    IN LPCWSTR ResourceName,
    OUT LPDWORD ResourceLength)
{
    HRSRC hSrc;
    HGLOBAL hRes;
    PVOID Result;

    /* find resource */
    hSrc = FindResourceW(hModule, ResourceName, (LPCWSTR)RT_DIALOG);

    if (!hSrc)
    {
        /* failed to find resource */
        return NULL;
    }

    /* now load the resource */
    hRes = LoadResource(hAppInstance, hSrc);
    if (!hRes)
    {
        /* failed to load resource */
        return NULL;
    }

    /* now lock the resource */
    Result = LockResource(hRes);

    if (!Result)
    {
        /* failed to lock resource */
        return NULL;
    }

    if (ResourceLength)
    {
        /* store output length */
        *ResourceLength = SizeofResource(hAppInstance, hSrc);
    }

    /* done */
    return Result;
}

LPWORD
AddDialogControl(
    IN HWND hwndDialog,
    IN HWND * OutWnd,
    IN LPRECT DialogOffset,
    IN PDLGITEMTEMPLATE DialogItem,
    IN DWORD DialogIdMultiplier,
    IN HFONT hFont,
    UINT xBaseUnit,
    UINT yBaseUnit)
{
    RECT rect;
    LPWORD Offset;
    LPWSTR ClassName, WindowName = NULL;
    HWND hwnd;
    DWORD wID;
    INT nSteps, i;

    /* initialize client rectangle */
    rect.left = DialogItem->x;
    rect.top = DialogItem->y;
    rect.right = DialogItem->x + DialogItem->cx;
    rect.bottom = DialogItem->y + DialogItem->cy;

    /* Convert Dialog units to pixes */
    ConvertRect(&rect, xBaseUnit, yBaseUnit);

    rect.left += DialogOffset->left;
    rect.right += DialogOffset->left;
    rect.top += DialogOffset->top;
    rect.bottom += DialogOffset->top;

    /* move offset after dialog item */
    Offset = (LPWORD)(DialogItem + 1);

    if (*Offset == 0xFFFF)
    {
        /* class is encoded as type */
        Offset++;

        /* get control type */
        switch(*Offset)
        {
            case 0x80:
                ClassName = L"button";
                WindowName = (LPWSTR)(Offset + 1);
                break ;
            case 0x82:
                ClassName = L"static";
                WindowName = (LPWSTR)(Offset + 1);
                break;
            default:
               /* FIXME */
               assert(0);
               ClassName = NULL;
        }
    }
    else
    {
        /* class name is encoded as string */
        ClassName = (LPWSTR)Offset;

        /* move offset to the end of class string */
        Offset += wcslen(ClassName);

        /* get window name */
        WindowName = (LPWSTR)(Offset + 1);
    }
    
    /* move offset past class type/string */
    Offset++;

    if (DialogItem->id == MAXWORD)
    {
        /* id is not important */
        wID = DialogItem->id;
    }
    else
    {
        /* calculate id */
        wID = DialogItem->id * (DialogIdMultiplier + 1);

    }

    /* now create the window */
    hwnd = CreateWindowExW(DialogItem->dwExtendedStyle,
                           ClassName,
                           WindowName,
                           DialogItem->style,
                           rect.left,
                           rect.top,
                           rect.right - rect.left,
                           rect.bottom - rect.top,
                           hwndDialog,
                           UlongToPtr(wID),
                           hAppInstance,
                           NULL);

    /* sanity check */
    assert(hwnd);

    /* store window */
    *OutWnd = hwnd;

    /* check if this the track bar */
    if (!wcsicmp(ClassName, L"msctls_trackbar32"))
    {
        if (DialogItem->style & TBS_VERT)
        {
            /* Vertical trackbar: Volume */

            /* set up range */
            SendMessage(hwnd, TBM_SETRANGE, (WPARAM)TRUE, (LPARAM)MAKELONG(0, VOLUME_STEPS));

            /* set up page size */
            SendMessage(hwnd, TBM_SETPAGESIZE, 0, (LPARAM)VOLUME_PAGE_SIZE);

            /* set position */
            SendMessage(hwnd, TBM_SETPOS, (WPARAM)TRUE, (LPARAM)0);

            /* Calculate and set ticks */
            nSteps = (VOLUME_STEPS / (VOLUME_TICKS + 1));
            if (VOLUME_STEPS % (VOLUME_TICKS + 1) != 0)
                nSteps++;
            for (i = nSteps; i < VOLUME_STEPS; i += nSteps)
                SendMessage(hwnd, TBM_SETTIC, 0, (LPARAM)i);
        }
        else
        {
            /* Horizontal trackbar: Balance */

            /* set up range */
            SendMessage(hwnd, TBM_SETRANGE, (WPARAM)TRUE, (LPARAM)MAKELONG(0, BALANCE_STEPS));

            /* set up page size */
            SendMessage(hwnd, TBM_SETPAGESIZE, 0, (LPARAM)BALANCE_PAGE_SIZE);

            /* set position */
            SendMessage(hwnd, TBM_SETPOS, (WPARAM)TRUE, (LPARAM)BALANCE_STEPS / 2);

            /* Calculate and set ticks */
            nSteps = (BALANCE_STEPS / (BALANCE_TICKS + 1));
            if (BALANCE_STEPS % (BALANCE_TICKS + 1) != 0)
                nSteps++;
            for (i = nSteps; i < BALANCE_STEPS; i += nSteps)
                SendMessage(hwnd, TBM_SETTIC, 0, (LPARAM)i);
        }
    }
    else if (!wcsicmp(ClassName, L"static") || !wcsicmp(ClassName, L"button"))
    {
        /* set font */
        SendMessageW(hwnd, WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    //ShowWindow(hwnd, SW_SHOWNORMAL);

    if (WindowName != NULL)
    {
        /* move offset past window name */
        Offset += wcslen(WindowName) + 1;
    }

    /* check if there is additional data */
    if (*Offset == 0)
    {
        /* no additional data */
        Offset++;
    }
    else
    {
        /* FIXME: Determine whether this should be "Offset += 1 + *Offset" to explicitly skip the data count too. */
        /* skip past additional data */
        Offset += *Offset;
    }

    /* make sure next template is word-aligned */
    Offset = (LPWORD)(((ULONG_PTR)Offset + 3) & ~3);

    /* done */
    return Offset;
}

VOID
LoadDialogControls(
    IN PMIXER_WINDOW MixerWindow,
    LPRECT DialogOffset,
    WORD ItemCount,
    PDLGITEMTEMPLATE DialogItem,
    DWORD DialogIdMultiplier,
    UINT xBaseUnit,
    UINT yBaseUnit)
{
    LPWORD Offset;
    WORD Index;

    /* sanity check */
    assert(ItemCount);

    if (MixerWindow->Window)
        MixerWindow->Window = (HWND*)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MixerWindow->Window, (MixerWindow->WindowCount + ItemCount) * sizeof(HWND));
    else
        MixerWindow->Window = (HWND*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ItemCount * sizeof(HWND));
    if (!MixerWindow->Window)
    {
        /* no memory */
        return;
    }

    /* enumerate now all controls */
    for (Index = 0; Index < ItemCount; Index++)
    {
        /* add controls */
        Offset = AddDialogControl(MixerWindow->hWnd, &MixerWindow->Window[MixerWindow->WindowCount], DialogOffset, DialogItem, DialogIdMultiplier, MixerWindow->hFont, xBaseUnit, yBaseUnit);

        /* sanity check */
        assert(Offset);

        /* move dialog item to new offset */
        DialogItem =(PDLGITEMTEMPLATE)Offset;

        /* increment window count */
        MixerWindow->WindowCount++;
    }
}

VOID
LoadDialog(
    IN HMODULE hModule,
    IN PMIXER_WINDOW MixerWindow,
    IN LPCWSTR DialogResId,
    IN DWORD Index)
{
    LPDLGTEMPLATE DlgTemplate;
    PDLGITEMTEMPLATE DlgItem;
    RECT dialogRect;
    LPWORD Offset;
    WORD FontSize;
    WCHAR FontName[100];
    WORD Length;
    int width;

    DWORD units = GetDialogBaseUnits();
    UINT xBaseUnit = LOWORD(units);
    UINT yBaseUnit = HIWORD(units);

    /* first load the dialog resource */
    DlgTemplate = (LPDLGTEMPLATE)LoadDialogResource(hModule, DialogResId, NULL);
    if (!DlgTemplate)
    {
        /* failed to load resource */
        return;
    }

    /* Now walk past the dialog header */
    Offset = (LPWORD)(DlgTemplate + 1);

    /* FIXME: support menu */
    assert(*Offset == 0);
    Offset++;

    /* FIXME: support classes */
    assert(*Offset == 0);
    Offset++;

    /* FIXME: support titles */
    assert(*Offset == 0);
    Offset++;

    /* get font size */
    FontSize = *Offset;
    Offset++;

    /* calculate font length */
    Length = wcslen((LPWSTR)Offset) + 1;
    assert(Length < (sizeof(FontName) / sizeof(WCHAR)));

    /* copy font */
    wcscpy(FontName, (LPWSTR)Offset);

    if (DlgTemplate->style & DS_SETFONT)
    {
        HDC hDC;

        hDC = GetDC(0);

        if (!MixerWindow->hFont)
        {
            int pixels = MulDiv(FontSize, GetDeviceCaps(hDC, LOGPIXELSY), 72);
            MixerWindow->hFont = CreateFontW(-pixels, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, FF_DONTCARE, FontName);
        }

        if (MixerWindow->hFont)
        {
            SIZE charSize;
            HFONT hOldFont;

            hOldFont = SelectObject(hDC, MixerWindow->hFont);
            charSize.cx = GdiGetCharDimensions(hDC, NULL, &charSize.cy);
            if (charSize.cx)
            {
                xBaseUnit = charSize.cx;
                yBaseUnit = charSize.cy;
            }
            SelectObject(hDC, hOldFont);
        }
    }

//    assert(MixerWindow->hFont);

    /* move offset after font name */
    Offset += Length;

    /* offset is now at first dialog item control */
    DlgItem = (PDLGITEMTEMPLATE)Offset;

    dialogRect.left = 0;
    dialogRect.right = DlgTemplate->cx;
    dialogRect.top = 0;
    dialogRect.bottom = DlgTemplate->cy;

    ConvertRect(&dialogRect, xBaseUnit, yBaseUnit);

    width = dialogRect.right - dialogRect.left;

    dialogRect.left += MixerWindow->rect.right;
    dialogRect.right += MixerWindow->rect.right;
    dialogRect.top += MixerWindow->rect.top;
    dialogRect.bottom += MixerWindow->rect.top;

    MixerWindow->rect.right += width;
    if ((dialogRect.bottom - dialogRect.top) > (MixerWindow->rect.bottom - MixerWindow->rect.top))
        MixerWindow->rect.bottom = MixerWindow->rect.top + dialogRect.bottom - dialogRect.top;

    /* now add the controls */
    LoadDialogControls(MixerWindow, &dialogRect, DlgTemplate->cdit, DlgItem, Index, xBaseUnit, yBaseUnit);
}

BOOL
CALLBACK
EnumConnectionsCallback(
    PSND_MIXER Mixer,
    DWORD LineID,
    LPMIXERLINE Line,
    PVOID Context)
{
    WCHAR LineName[MIXER_LONG_NAME_CHARS];
    DWORD Flags;
    DWORD wID;
    UINT ControlCount = 0, Index;
    LPMIXERCONTROL Control = NULL;
    HWND hDlgCtrl;
    PPREFERENCES_CONTEXT PrefContext = (PPREFERENCES_CONTEXT)Context;

    if (Line->cControls != 0)
    {
      /* get line name */
      if (SndMixerGetLineName(PrefContext->MixerWindow->Mixer, PrefContext->SelectedLine, LineName, MIXER_LONG_NAME_CHARS, TRUE) == -1)
      {
          /* failed to get line name */
          LineName[0] = L'\0';
      }

      /* check if line is found in registry settings */
      if (ReadLineConfig(PrefContext->DeviceName,
                         LineName,
                         Line->szName,
                         &Flags))
      {
          /* is it selected */
          if (Flags != 0x4)
          {
              int dlgId = (PrefContext->MixerWindow->Mode == SMALL_MODE) ? IDD_SMALL_MASTER : IDD_NORMAL_MASTER;

              /* load dialog resource */
              LoadDialog(hAppInstance, PrefContext->MixerWindow, MAKEINTRESOURCE(dlgId), PrefContext->Count);

              /* get id */
              wID = (PrefContext->Count + 1) * IDC_LINE_NAME;

              /* set line name */
              SetDlgItemTextW(PrefContext->MixerWindow->hWnd, wID, Line->szName);

              /* query controls */
              if (SndMixerQueryControls(Mixer, &ControlCount, Line, &Control) != FALSE)
              {
                  /* now go through all controls and update their states */
                  for(Index = 0; Index < Line->cControls; Index++)
                  {
                      if ((Control[Index].dwControlType & MIXERCONTROL_CT_CLASS_MASK) == MIXERCONTROL_CT_CLASS_SWITCH)
                      {
                          MIXERCONTROLDETAILS_BOOLEAN Details;

                          /* get volume control details */
                          if (SndMixerGetVolumeControlDetails(Mixer, Control[Index].dwControlID, sizeof(MIXERCONTROLDETAILS_BOOLEAN), (LPVOID)&Details) != -1)
                          {
                              /* update dialog control */
                              wID = (PrefContext->Count + 1) * IDC_LINE_SWITCH;

                              /* get dialog control */
                              hDlgCtrl = GetDlgItem(PrefContext->MixerWindow->hWnd, wID);

                              if (hDlgCtrl != NULL)
                              {
                                  /* check state */
                                  if (SendMessageW(hDlgCtrl, BM_GETCHECK, 0, 0) != Details.fValue)
                                  {
                                      /* update control state */
                                      SendMessageW(hDlgCtrl, BM_SETCHECK, (WPARAM)Details.fValue, 0);
                                  }
                              }
                          }
                      }
                      else if ((Control[Index].dwControlType & MIXERCONTROL_CT_CLASS_MASK) == MIXERCONTROL_CT_CLASS_FADER)
                      {
                          MIXERCONTROLDETAILS_UNSIGNED Details;

                          /* get volume control details */
                          if (SndMixerGetVolumeControlDetails(Mixer, Control[Index].dwControlID, sizeof(MIXERCONTROLDETAILS_UNSIGNED), (LPVOID)&Details) != -1)
                          {
                              /* update dialog control */
                              DWORD Position;
                              DWORD Step = 0x10000 / VOLUME_STEPS;

                              /* FIXME: give me granularity */
                              Position = VOLUME_STEPS - (Details.dwValue / Step);

                              /* FIXME support left - right slider */
                              wID = (PrefContext->Count + 1) * IDC_LINE_SLIDER_VERT;

                              /* get dialog control */
                              hDlgCtrl = GetDlgItem(PrefContext->MixerWindow->hWnd, wID);

                              if (hDlgCtrl != NULL)
                              {
                                  /* check state */
                                  LRESULT OldPosition = SendMessageW(hDlgCtrl, TBM_GETPOS, 0, 0);
                                  if (OldPosition != Position)
                                  {
                                      /* update control state */
                                      SendMessageW(hDlgCtrl, TBM_SETPOS, (WPARAM)TRUE, Position + Index);
                                  }
                              }
                          }
                      }
                  }

                  /* free controls */
                  HeapFree(GetProcessHeap(), 0, Control);
              }

              /* increment dialog count */
              PrefContext->Count++;
          }
      }
    }
    return TRUE;
}

VOID
LoadDialogCtrls(
    PPREFERENCES_CONTEXT PrefContext)
{
    HWND hDlgCtrl;
    RECT statusRect;

    /* set dialog count to zero */
    PrefContext->Count = 0;

    SetRectEmpty(&PrefContext->MixerWindow->rect);

    /* enumerate controls */
    SndMixerEnumConnections(PrefContext->MixerWindow->Mixer, PrefContext->SelectedLine, EnumConnectionsCallback, (PVOID)PrefContext);

    if (PrefContext->MixerWindow->hStatusBar)
    {
        GetWindowRect(PrefContext->MixerWindow->hStatusBar, &statusRect);
        PrefContext->MixerWindow->rect.bottom += (statusRect.bottom - statusRect.top);
    }

    /* now move the window */
    AdjustWindowRect(&PrefContext->MixerWindow->rect, WS_DLGFRAME | WS_CAPTION | WS_MINIMIZEBOX | WS_SYSMENU | WS_CLIPCHILDREN | WS_CLIPSIBLINGS | WS_VISIBLE, TRUE);
    SetWindowPos(PrefContext->MixerWindow->hWnd, HWND_TOP, PrefContext->MixerWindow->rect.left, PrefContext->MixerWindow->rect.top, PrefContext->MixerWindow->rect.right - PrefContext->MixerWindow->rect.left, PrefContext->MixerWindow->rect.bottom - PrefContext->MixerWindow->rect.top, SWP_NOMOVE | SWP_NOZORDER);

    /* get last line separator */
    hDlgCtrl = GetDlgItem(PrefContext->MixerWindow->hWnd, IDC_LINE_SEP * PrefContext->Count);

    if (hDlgCtrl != NULL)
    {
        /* hide last separator */
        ShowWindow(hDlgCtrl, SW_HIDE);
    }
}

VOID
UpdateDialogLineSwitchControl(
    PPREFERENCES_CONTEXT PrefContext,
    LPMIXERLINE Line,
    LONG fValue)
{
    DWORD Index;
    DWORD wID;
    HWND hDlgCtrl;
    WCHAR LineName[MIXER_LONG_NAME_CHARS];

    /* find the index of this line */
    for(Index = 0; Index < PrefContext->Count; Index++)
    {
        /* get id */
        wID = (Index + 1) * IDC_LINE_NAME;

        if (GetDlgItemText(PrefContext->MixerWindow->hWnd, wID, LineName, MIXER_LONG_NAME_CHARS) == 0)
        {
            /* failed to retrieve id */
            continue;
        }

        /* check if the line name matches */
        if (!wcsicmp(LineName, Line->szName))
        {
            /* found matching line name */
            wID = (Index + 1) * IDC_LINE_SWITCH;

            /* get dialog control */
            hDlgCtrl = GetDlgItem(PrefContext->MixerWindow->hWnd, wID);

            if (hDlgCtrl != NULL)
            {
                /* check state */
                if (SendMessageW(hDlgCtrl, BM_GETCHECK, 0, 0) != fValue)
                {
                    /* update control state */
                    SendMessageW(hDlgCtrl, BM_SETCHECK, (WPARAM)fValue, 0);
                }
            }
            break;
        }
    }
}

VOID
UpdateDialogLineSliderControl(
    PPREFERENCES_CONTEXT PrefContext,
    LPMIXERLINE Line,
    DWORD dwControlID,
    DWORD dwDialogID,
    DWORD Position)
{
    DWORD Index;
    DWORD wID;
    HWND hDlgCtrl;
    WCHAR LineName[MIXER_LONG_NAME_CHARS];

    /* find the index of this line */
    for(Index = 0; Index < PrefContext->Count; Index++)
    {
        /* get id */
        wID = (Index + 1) * IDC_LINE_NAME;

        if (GetDlgItemText(PrefContext->MixerWindow->hWnd, wID, LineName, MIXER_LONG_NAME_CHARS) == 0)
        {
            /* failed to retrieve id */
            continue;
        }

        /* check if the line name matches */
        if (!wcsicmp(LineName, Line->szName))
        {
            /* found matching line name */
            wID = (Index + 1) * dwDialogID;

            /* get dialog control */
            hDlgCtrl = GetDlgItem(PrefContext->MixerWindow->hWnd, wID);

            if (hDlgCtrl != NULL)
            {
                /* check state */
                LRESULT OldPosition = SendMessageW(hDlgCtrl, TBM_GETPOS, 0, 0);
                if (OldPosition != Position)
                {
                    /* update control state */
                    SendMessageW(hDlgCtrl, TBM_SETPOS, (WPARAM)TRUE, Position + Index);
                }
            }
            break;
        }
    }
}
