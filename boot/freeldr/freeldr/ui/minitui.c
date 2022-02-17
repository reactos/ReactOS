/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         FreeLoader
 * FILE:            boot/freeldr/freeldr/ui/minitui.c
 * PURPOSE:         Mini Text UI interface
 * PROGRAMMERS:     Brian Palmer <brianp@sginet.com>
 *                  Hervé Poussineau
 */

#include <freeldr.h>

/* NTLDR or Vista+ BOOTMGR progress-bar style */
// #define NTLDR_PROGRESSBAR
// #define BTMGR_PROGRESSBAR /* Default style */

#ifndef _M_ARM

VOID MiniTuiDrawBackdrop(VOID)
{
    /* Fill in a black background */
    TuiFillArea(0, 0, UiScreenWidth - 1, UiScreenHeight - 1, 0, 0);

    /* Update the screen buffer */
    VideoCopyOffScreenBufferToVRAM();
}

VOID MiniTuiDrawStatusText(PCSTR StatusText)
{
    /* Minimal UI doesn't have a status bar */
}

#endif // _M_ARM

VOID
MiniTuiDrawProgressBarCenter(
    _In_ ULONG Position,
    _In_ ULONG Range,
    _Inout_z_ PSTR ProgressText)
{
    ULONG Left, Top, Right, Bottom, Width, Height;

    /* Build the coordinates and sizes */
#ifdef NTLDR_PROGRESSBAR
    Height = 2;
    Width  = UiScreenWidth;
    Left = 0;
    Top  = UiScreenHeight - Height - 2;
#else // BTMGR_PROGRESSBAR
    Height = 3;
    Width  = UiScreenWidth - 4;
    Left = 2;
    Top  = UiScreenHeight - Height - 3;
#endif
    Right  = Left + Width - 1;
    Bottom = Top + Height - 1;

    /* Draw the progress bar */
    MiniTuiDrawProgressBar(Left, Top, Right, Bottom, Position, Range, ProgressText);
}

VOID
MiniTuiDrawProgressBar(
    _In_ ULONG Left,
    _In_ ULONG Top,
    _In_ ULONG Right,
    _In_ ULONG Bottom,
    _In_ ULONG Position,
    _In_ ULONG Range,
    _Inout_z_ PSTR ProgressText)
{
    ULONG ProgressBarWidth, i;

    /* Calculate the width of the bar proper */
    ProgressBarWidth = Right - Left + 1;

    /* Clip the position */
    if (Position > Range)
        Position = Range;

    /* First make sure the progress bar text fits */
    UiTruncateStringEllipsis(ProgressText, ProgressBarWidth);

    /* Clear the text area */
    TuiFillArea(Left, Top, Right,
#ifdef NTLDR_PROGRESSBAR
                Bottom - 1,
#else // BTMGR_PROGRESSBAR
                Bottom - 2, // One empty line between text and bar.
#endif
                ' ', ATTR(UiTextColor, UiMenuBgColor));

    /* Draw the "Loading..." text */
    TuiDrawCenteredText(Left, Top, Right,
#ifdef NTLDR_PROGRESSBAR
                        Bottom - 1,
#else // BTMGR_PROGRESSBAR
                        Bottom - 2, // One empty line between text and bar.
#endif
                        ProgressText, ATTR(UiTextColor, UiMenuBgColor));

    /* Draw the percent complete -- Use the fill character */
    for (i = 0; i < (Position * ProgressBarWidth) / Range; i++)
    {
        TuiDrawText(Left + i, Bottom,
                    "\xDB", ATTR(UiTextColor, UiMenuBgColor));
    }
    /* Fill the remaining with blanks */
    TuiFillArea(Left + i, Bottom, Right, Bottom,
                ' ', ATTR(UiTextColor, UiMenuBgColor));

#ifndef _M_ARM
    TuiUpdateDateTime();
    VideoCopyOffScreenBufferToVRAM();
#endif
}

VOID
MiniTuiDrawMenu(
    _In_ PUI_MENU_INFO MenuInfo)
{
    ULONG i;

#ifndef _M_ARM
    /* Draw the backdrop */
    UiDrawBackdrop();
#endif

    /* No GUI status bar text, just minimal text. Show the menu header. */
    if (MenuInfo->MenuHeader)
    {
        UiVtbl.DrawText(0,
                        MenuInfo->Top - 2,
                        MenuInfo->MenuHeader,
                        ATTR(UiMenuFgColor, UiMenuBgColor));
    }

    /* Now tell the user how to choose */
    UiVtbl.DrawText(0,
                    MenuInfo->Bottom + 1,
                    "Use \x18 and \x19 to move the highlight to your choice.",
                    ATTR(UiMenuFgColor, UiMenuBgColor));
    UiVtbl.DrawText(0,
                    MenuInfo->Bottom + 2,
                    "Press ENTER to choose.",
                    ATTR(UiMenuFgColor, UiMenuBgColor));

    /* And show the menu footer */
    if (MenuInfo->MenuFooter)
    {
        UiVtbl.DrawText(0,
                        UiScreenHeight - 4,
                        MenuInfo->MenuFooter,
                        ATTR(UiMenuFgColor, UiMenuBgColor));
    }

    /* Draw the menu box */
    TuiDrawMenuBox(MenuInfo);

    /* Draw each line of the menu */
    for (i = 0; i < MenuInfo->MenuItemCount; i++)
    {
        TuiDrawMenuItem(MenuInfo, i);
    }

    /* Display the boot options if needed */
    if (MenuInfo->ShowBootOptions)
    {
        DisplayBootTimeOptions();
    }

#ifndef _M_ARM
    VideoCopyOffScreenBufferToVRAM();
#endif
}

#ifndef _M_ARM

const UIVTBL MiniTuiVtbl =
{
    TuiInitialize,
    TuiUnInitialize,
    MiniTuiDrawBackdrop,
    TuiFillArea,
    TuiDrawShadow,
    TuiDrawBox,
    TuiDrawText,
    TuiDrawText2,
    TuiDrawCenteredText,
    MiniTuiDrawStatusText,
    TuiUpdateDateTime,
    TuiMessageBox,
    TuiMessageBoxCritical,
    MiniTuiDrawProgressBarCenter,
    MiniTuiDrawProgressBar,
    TuiEditBox,
    TuiTextToColor,
    TuiTextToFillStyle,
    MiniTuiDrawBackdrop, /* no FadeIn */
    TuiFadeOut,
    TuiDisplayMenu,
    MiniTuiDrawMenu,
};

#endif // _M_ARM
