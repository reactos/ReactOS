/*
 * PROJECT:         ReactOS Boot Loader
 * LICENSE:         BSD - See COPYING.ARM in the top level directory
 * FILE:            boot/freeldr/freeldr/ui/directui.c
 * PURPOSE:         FreeLDR UI Routines
 * PROGRAMMERS:     ReactOS Portable Systems Group
 */

#ifdef _M_ARM

#include <freeldr.h>

/* GLOBALS ********************************************************************/

ULONG UiScreenWidth;
ULONG UiScreenHeight;
UCHAR UiMenuFgColor = COLOR_GRAY;
UCHAR UiMenuBgColor = COLOR_BLACK;
UCHAR UiTextColor = COLOR_GRAY;
UCHAR UiSelectedTextColor = COLOR_BLACK;
UCHAR UiSelectedTextBgColor = COLOR_GRAY;
CHAR UiTimeText[260] = "Seconds until highlighted choice will be started automatically:   ";

/* FUNCTIONS ******************************************************************/

BOOLEAN
UiInitialize(IN BOOLEAN ShowUi)
{
    ULONG Depth;

    /* Nothing to do */
    if (!ShowUi) return TRUE;

    /* Set mode and query size */
    MachVideoSetDisplayMode(NULL, TRUE);
    MachVideoGetDisplaySize(&UiScreenWidth, &UiScreenHeight, &Depth);

    /* Clear the screen */
    UiDrawBackdrop();
    return TRUE;
}

VOID
UiUnInitialize(IN PCSTR BootText)
{
    /* Nothing to do */
    return;
}

VOID
UiDrawBackdrop(VOID)
{
    /* Clear the screen */
    MachVideoClearScreen(ATTR(COLOR_WHITE, COLOR_BLACK));
}

VOID
UiDrawText(
    _In_ ULONG X,
    _In_ ULONG Y,
    _In_ PCSTR Text,
    _In_ UCHAR Attr)
{
    TuiDrawText2(X, Y, 0 /*(ULONG)strlen(Text)*/, Text, Attr);
}

VOID
UiDrawText2(
    _In_ ULONG X,
    _In_ ULONG Y,
    _In_opt_ ULONG MaxNumChars,
    _In_reads_or_z_(MaxNumChars) PCSTR Text,
    _In_ UCHAR Attr)
{
    TuiDrawText2(X, Y, MaxNumChars, Text, Attr);
}

VOID
UiDrawCenteredText(
    _In_ ULONG Left,
    _In_ ULONG Top,
    _In_ ULONG Right,
    _In_ ULONG Bottom,
    _In_ PCSTR TextString,
    _In_ UCHAR Attr)
{
    TuiDrawCenteredText(Left, Top, Right, Bottom, TextString, Attr);
}

VOID
UiDrawStatusText(IN PCSTR StatusText)
{
    return;
}

VOID
UiInfoBox(IN PCSTR MessageText)
{
    TuiPrintf(MessageText);
}

VOID
UiMessageBox(IN PCSTR MessageText)
{
    TuiPrintf(MessageText);
}

VOID
UiMessageBoxCritical(IN PCSTR MessageText)
{
    TuiPrintf(MessageText);
}

VOID
UiDrawProgressBarCenter(
    _In_ ULONG Position,
    _In_ ULONG Range,
    _Inout_z_ PSTR ProgressText)
{
    MiniTuiDrawProgressBarCenter(Position, Range, ProgressText);
}

VOID
UiDrawProgressBar(
    _In_ ULONG Left,
    _In_ ULONG Top,
    _In_ ULONG Right,
    _In_ ULONG Bottom,
    _In_ ULONG Position,
    _In_ ULONG Range,
    _Inout_z_ PSTR ProgressText)
{
    MiniTuiDrawProgressBar(Left, Top, Right, Bottom, Position, Range, ProgressText);
}

VOID
UiShowMessageBoxesInSection(
    IN ULONG_PTR SectionId)
{
    return;
}

VOID
UiShowMessageBoxesInArgv(
    IN ULONG Argc,
    IN PCHAR Argv[])
{
    return;
}

VOID
UiTruncateStringEllipsis(IN PCHAR StringText,
                         IN ULONG MaxChars)
{
    /* If it's too large, just add some ellipsis past the maximum */
    if (strlen(StringText) > MaxChars)
        strcpy(&StringText[MaxChars - 3], "...");
}

VOID
UiDrawMenuBox(IN PUI_MENU_INFO MenuInfo)
{
    CHAR MenuLineText[80], TempString[80];
    ULONG i;

    /* If there is a timeout draw the time remaining */
    if (MenuInfo->MenuTimeRemaining >= 0)
    {
        /* Copy the integral time text string, and remove the last 2 chars */
        strcpy(TempString, UiTimeText);
        i = strlen(TempString);
        TempString[i - 2] = 0;

        /* Display the first part of the string and the remaining time */
        strcpy(MenuLineText, TempString);
        _itoa(MenuInfo->MenuTimeRemaining, TempString, 10);
        strcat(MenuLineText, TempString);

        /* Add the last 2 chars */
        strcat(MenuLineText, &UiTimeText[i - 2]);

        /* Display under the menu directly */
        UiDrawText(0,
                   MenuInfo->Bottom + 4,
                   MenuLineText,
                   ATTR(UiMenuFgColor, UiMenuBgColor));
    }
    else
    {
        /* Erase the timeout string with spaces, and 0-terminate for sure */
        for (i=0; i<sizeof(MenuLineText)-1; i++)
        {
            MenuLineText[i] = ' ';
        }
        MenuLineText[sizeof(MenuLineText)-1] = 0;

        /* Draw this "empty" string to erase */
        UiDrawText(0,
                   MenuInfo->Bottom + 4,
                   MenuLineText,
                   ATTR(UiMenuFgColor, UiMenuBgColor));
    }

    /* Loop each item */
    for (i = 0; i < MenuInfo->MenuItemCount; i++)
    {
        /* Check if it's a separator */
        if (MenuInfo->MenuItemList[i] == NULL)
        {
            /* Draw the separator line */
            UiDrawText(MenuInfo->Left,
                       MenuInfo->Top + i + 1,
                       "\xC7",
                       ATTR(UiMenuFgColor, UiMenuBgColor));
            UiDrawText(MenuInfo->Right,
                       MenuInfo->Top + i + 1,
                       "\xB6",
                       ATTR(UiMenuFgColor, UiMenuBgColor));
        }
    }
}

VOID
UiDrawMenuItem(IN PUI_MENU_INFO MenuInfo,
               IN ULONG MenuItemNumber)
{
    CHAR MenuLineText[80];
    UCHAR Attribute = ATTR(UiTextColor, UiMenuBgColor);

    /* Simply left-align it */
    MenuLineText[0] = '\0';
    strcat(MenuLineText, "    ");

    /* Now append the text string */
    if (MenuInfo->MenuItemList[MenuItemNumber])
        strcat(MenuLineText, MenuInfo->MenuItemList[MenuItemNumber]);

    /* If it is a separator */
    if (MenuInfo->MenuItemList[MenuItemNumber] == NULL)
    {
        /* Make it a separator line and use menu colors */
        memset(MenuLineText, 0, sizeof(MenuLineText));
        memset(MenuLineText, 0xC4, (MenuInfo->Right - MenuInfo->Left - 1));
        Attribute = ATTR(UiMenuFgColor, UiMenuBgColor);
    }
    else if (MenuItemNumber == MenuInfo->SelectedMenuItem)
    {
        /*  If this is the selected item, use the selected colors */
        Attribute = ATTR(UiSelectedTextColor, UiSelectedTextBgColor);
    }

    /* Draw the item */
    UiDrawText(MenuInfo->Left + 1,
               MenuInfo->Top + 1 + MenuItemNumber,
               MenuLineText,
               Attribute);
}

VOID
UiDrawMenu(IN PUI_MENU_INFO MenuInfo)
{
    ULONG i;

    /* No GUI status bar text, just minimal text. Show the menu header. */
    if (MenuInfo->MenuHeader)
    {
        UiDrawText(0,
                   MenuInfo->Top - 2,
                   MenuInfo->MenuHeader,
                   ATTR(UiMenuFgColor, UiMenuBgColor));
    }

    /* Now tell the user how to choose */
    UiDrawText(0,
               MenuInfo->Bottom + 1,
               "Use \x18 and \x19 to move the highlight to your choice.",
               ATTR(UiMenuFgColor, UiMenuBgColor));
    UiDrawText(0,
               MenuInfo->Bottom + 2,
               "Press ENTER to choose.",
               ATTR(UiMenuFgColor, UiMenuBgColor));

    /* And show the menu footer */
    if (MenuInfo->MenuFooter)
    {
        UiDrawText(0,
                   UiScreenHeight - 4,
                   MenuInfo->MenuFooter,
                   ATTR(UiMenuFgColor, UiMenuBgColor));
    }

    /* Draw the menu box */
    UiDrawMenuBox(MenuInfo);

    /* Draw each line of the menu */
    for (i = 0; i < MenuInfo->MenuItemCount; i++)
    {
        UiDrawMenuItem(MenuInfo, i);
    }

    /* Display the boot options if needed */
    if (MenuInfo->ShowBootOptions)
    {
        DisplayBootTimeOptions();
    }
}

ULONG
UiProcessMenuKeyboardEvent(IN PUI_MENU_INFO MenuInfo,
                           IN UiMenuKeyPressFilterCallback KeyPressFilter)
{
    ULONG KeyEvent = 0;
    ULONG Selected, Count;

    /* Check for a keypress */
    if (!MachConsKbHit())
        return 0; // None, bail out

    /* Check if the timeout is not already complete */
    if (MenuInfo->MenuTimeRemaining != -1)
    {
        /* Cancel it and remove it */
        MenuInfo->MenuTimeRemaining = -1;
        UiDrawMenuBox(MenuInfo);
    }

    /* Get the key (get the extended key if needed) */
    KeyEvent = MachConsGetCh();
    if (KeyEvent == KEY_EXTENDED)
        KeyEvent = MachConsGetCh();

    /*
     * Call the supplied key filter callback function to see
     * if it is going to handle this keypress.
     */
    if (KeyPressFilter &&
        KeyPressFilter(KeyEvent, MenuInfo->SelectedMenuItem, MenuInfo->Context))
    {
        /* It processed the key character, so redraw and exit */
        UiDrawMenu(MenuInfo);
        return 0;
    }

    /* Process the key */
    if ((KeyEvent == KEY_UP  ) || (KeyEvent == KEY_DOWN) ||
        (KeyEvent == KEY_HOME) || (KeyEvent == KEY_END ))
    {
        /* Get the current selected item and count */
        Selected = MenuInfo->SelectedMenuItem;
        Count = MenuInfo->MenuItemCount - 1;

        /* Check the key and change the selected menu item */
        if ((KeyEvent == KEY_UP) && (Selected > 0))
        {
            /* Deselect previous item and go up */
            MenuInfo->SelectedMenuItem--;
            UiDrawMenuItem(MenuInfo, Selected);
            Selected--;

            // Skip past any separators
            if ((Selected > 0) &&
                (MenuInfo->MenuItemList[Selected] == NULL))
            {
                MenuInfo->SelectedMenuItem--;
            }
        }
        else if ( ((KeyEvent == KEY_UP) && (Selected == 0)) ||
                   (KeyEvent == KEY_END) )
        {
            /* Go to the end */
            MenuInfo->SelectedMenuItem = Count;
            UiDrawMenuItem(MenuInfo, Selected);
        }
        else if ((KeyEvent == KEY_DOWN) && (Selected < Count))
        {
            /* Deselect previous item and go down */
            MenuInfo->SelectedMenuItem++;
            UiDrawMenuItem(MenuInfo, Selected);
            Selected++;

            // Skip past any separators
            if ((Selected < Count) &&
                (MenuInfo->MenuItemList[Selected] == NULL))
            {
                MenuInfo->SelectedMenuItem++;
            }
        }
        else if ( ((KeyEvent == KEY_DOWN) && (Selected == Count)) ||
                   (KeyEvent == KEY_HOME) )
        {
            /* Go to the beginning */
            MenuInfo->SelectedMenuItem = 0;
            UiDrawMenuItem(MenuInfo, Selected);
        }

        /* Select new item and update video buffer */
        UiDrawMenuItem(MenuInfo, MenuInfo->SelectedMenuItem);
    }

    /*  Return the pressed key */
    return KeyEvent;
}

VOID
UiCalcMenuBoxSize(IN PUI_MENU_INFO MenuInfo)
{
    ULONG i, Width = 0, Height, Length;

    /* Height is the menu item count plus 2 (top border & bottom border) */
    Height = MenuInfo->MenuItemCount + 2;
    Height -= 1; // Height is zero-based

    /* Loop every item */
    for (i = 0; i < MenuInfo->MenuItemCount; i++)
    {
        /* Get the string length and make it become the new width if necessary */
        if (MenuInfo->MenuItemList[i])
        {
            Length = (ULONG)strlen(MenuInfo->MenuItemList[i]);
            if (Length > Width) Width = Length;
        }
    }

    /* Allow room for left & right borders, plus 8 spaces on each side */
    Width += 18;

    /* Put the menu in the default left-corner position */
    MenuInfo->Left = -1;
    MenuInfo->Top = 4;

    /* The other margins are the same */
    MenuInfo->Right = (MenuInfo->Left) + Width;
    MenuInfo->Bottom = (MenuInfo->Top) + Height;
}

BOOLEAN
UiDisplayMenu(
    IN PCSTR MenuHeader,
    IN PCSTR MenuFooter OPTIONAL,
    IN BOOLEAN ShowBootOptions,
    IN PCSTR MenuItemList[],
    IN ULONG MenuItemCount,
    IN ULONG DefaultMenuItem,
    IN LONG MenuTimeOut,
    OUT PULONG SelectedMenuItem,
    IN BOOLEAN CanEscape,
    IN UiMenuKeyPressFilterCallback KeyPressFilter OPTIONAL,
    IN PVOID Context OPTIONAL)
{
    UI_MENU_INFO MenuInformation;
    ULONG LastClockSecond;
    ULONG CurrentClockSecond;
    ULONG KeyPress;

    /*
     * Before taking any default action if there is no timeout,
     * check whether the supplied key filter callback function
     * may handle a specific user keypress. If it does, the
     * timeout is cancelled.
     */
    if (!MenuTimeOut && KeyPressFilter && MachConsKbHit())
    {
        /* Get the key (get the extended key if needed) */
        KeyPress = MachConsGetCh();
        if (KeyPress == KEY_EXTENDED)
            KeyPress = MachConsGetCh();

        /*
         * Call the supplied key filter callback function to see
         * if it is going to handle this keypress.
         */
        if (KeyPressFilter(KeyPress, DefaultMenuItem, Context))
        {
            /* It processed the key character, cancel the timeout */
            MenuTimeOut = -1;
        }
    }

    /* Check if there's no timeout */
    if (!MenuTimeOut)
    {
        /* Return the default selected item */
        if (SelectedMenuItem) *SelectedMenuItem = DefaultMenuItem;
        return TRUE;
    }

    /* Setup the MENU_INFO structure */
    MenuInformation.MenuHeader = MenuHeader;
    MenuInformation.MenuFooter = MenuFooter;
    MenuInformation.ShowBootOptions = ShowBootOptions;
    MenuInformation.MenuItemList = MenuItemList;
    MenuInformation.MenuItemCount = MenuItemCount;
    MenuInformation.MenuTimeRemaining = MenuTimeOut;
    MenuInformation.SelectedMenuItem = DefaultMenuItem;
    MenuInformation.Context = Context;

    /* Calculate the size of the menu box */
    UiCalcMenuBoxSize(&MenuInformation);

    /* Draw the menu */
    UiDrawMenu(&MenuInformation);

    /* Get the current second of time */
    LastClockSecond = ArcGetTime()->Second;

    /* Process keys */
    while (TRUE)
    {
        /* Process key presses */
        KeyPress = UiProcessMenuKeyboardEvent(&MenuInformation, KeyPressFilter);

        /* Check for ENTER or ESC */
        if (KeyPress == KEY_ENTER) break;
        if (CanEscape && KeyPress == KEY_ESC) return FALSE;

        /* Check if there is a countdown */
        if (MenuInformation.MenuTimeRemaining > 0)
        {
            /* Get the updated time, seconds only */
            CurrentClockSecond = ArcGetTime()->Second;

            /* Check if more then a second has now elapsed */
            if (CurrentClockSecond != LastClockSecond)
            {
                /* Update the time information */
                LastClockSecond = CurrentClockSecond;
                MenuInformation.MenuTimeRemaining--;

                /* Update the menu */
                UiDrawMenuBox(&MenuInformation);
            }
        }
        else if (MenuInformation.MenuTimeRemaining == 0)
        {
            /* A time out occurred, exit this loop and return default OS */
            break;
        }
    }

    /* Return the selected item */
    if (SelectedMenuItem) *SelectedMenuItem = MenuInformation.SelectedMenuItem;
    return TRUE;
}

#endif // _M_ARM
