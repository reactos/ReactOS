/*
 * PROJECT:     PAINT for ReactOS
 * LICENSE:     LGPL
 * FILE:        base/applications/mspaint/main.cpp
 * PURPOSE:     Initializing everything
 * PROGRAMMERS: Benedikt Freisen
 */

#include "precomp.h"

/* FUNCTIONS ********************************************************/

POINT start;
POINT last;

ToolsModel toolsModel;

SelectionModel selectionModel;

PaletteModel paletteModel;

RegistrySettings registrySettings;

ImageModel imageModel;
BOOL askBeforeEnlarging = FALSE;  // TODO: initialize from registry

HWND hStatusBar;
CHOOSECOLOR choosecolor;
OPENFILENAME ofn;
OPENFILENAME sfn;
HICON hNontranspIcon;
HICON hTranspIcon;

HINSTANCE hProgInstance;

TCHAR filepathname[1000];
BOOL isAFile = FALSE;
BOOL imageSaved = FALSE;
int fileSize;
int fileHPPM = 2834;
int fileVPPM = 2834;
SYSTEMTIME fileTime;

BOOL showGrid = FALSE;
BOOL showMiniature = FALSE;

CMainWindow mainWindow;
CFullscreenWindow fullscreenWindow;
CMiniatureWindow miniature;
CToolBox toolBoxContainer;
CToolSettingsWindow toolSettingsWindow;
CPaletteWindow paletteWindow;
CCanvasWindow canvasWindow;
CSelectionWindow selectionWindow;
CImgAreaWindow imageArea;
CTextEditWindow textEditWindow;

// get file name extension from filter string
static BOOL
FileExtFromFilter(LPTSTR pExt, LPCTSTR pTitle, OPENFILENAME *pOFN)
{
    LPTSTR pchExt = pExt;
    *pchExt = 0;

    DWORD nIndex = 1;
    for (LPCTSTR pch = pOFN->lpstrFilter; *pch; ++nIndex)
    {
        pch += lstrlen(pch) + 1;
        if (pOFN->nFilterIndex == nIndex)
        {
            for (++pch; *pch && *pch != _T(';'); ++pch)
            {
                *pchExt++ = *pch;
            }
            *pchExt = 0;
            CharLower(pExt);
            return TRUE;
        }
        pch += lstrlen(pch) + 1;
    }
    return FALSE;
}

// Hook procedure for OPENFILENAME to change the file name extension
static UINT_PTR APIENTRY
OFNHookProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    HWND hParent;
    OFNOTIFY *pon;
    switch (uMsg)
    {
    case WM_NOTIFY:
        pon = (OFNOTIFY *)lParam;
        if (pon->hdr.code == CDN_TYPECHANGE)
        {
            hParent = GetParent(hwnd);
            TCHAR Path[MAX_PATH];
            SendMessage(hParent, CDM_GETFILEPATH, _countof(Path), (LPARAM)Path);
            LPTSTR pchTitle = _tcsrchr(Path, _T('\\'));
            if (pchTitle == NULL)
                pchTitle = _tcsrchr(Path, _T('/'));

            LPTSTR pch = _tcsrchr((pchTitle ? pchTitle : Path), _T('.'));
            if (pch && pchTitle)
            {
                pchTitle++;
                *pch = 0;
                FileExtFromFilter(pch, pchTitle, pon->lpOFN);
                SendMessage(hParent, CDM_SETCONTROLTEXT, 0x047c, (LPARAM)pchTitle);
                lstrcpyn(pon->lpOFN->lpstrFile, Path, pon->lpOFN->nMaxFile);
            }
        }
        break;
    }
    return 0;
}

/* entry point */

int WINAPI
_tWinMain (HINSTANCE hThisInstance, HINSTANCE hPrevInstance, LPTSTR lpszArgument, INT nCmdShow)
{
    MSG messages;            /* Here messages to the application are saved */

    HMENU menu;
    HACCEL haccel;

    TCHAR sfnFilename[1000];
    TCHAR sfnFiletitle[256];
    TCHAR ofnFilename[1000];
    TCHAR ofnFiletitle[256];
    static COLORREF custColors[16] = {
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff,
        0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff, 0xffffff
    };

#ifdef _DEBUG
    /* Report any memory leaks on exit */
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF);
#endif

    hProgInstance = hThisInstance;

    /* initialize common controls library */
    INITCOMMONCONTROLSEX iccx;
    iccx.dwSize = sizeof(iccx);
    iccx.dwICC = ICC_STANDARD_CLASSES | ICC_USEREX_CLASSES | ICC_BAR_CLASSES;
    InitCommonControlsEx(&iccx);

    /* load settings from registry */
    registrySettings.Load(nCmdShow);
    showMiniature = registrySettings.ShowThumbnail;
    ::LoadString(hThisInstance, IDS_DEFAULTFILENAME, filepathname, _countof(filepathname));

    // Create the main window
    mainWindow.DoCreate();

    /* loading and setting the window menu from resource */
    menu = LoadMenu(hThisInstance, MAKEINTRESOURCE(ID_MENU));
    mainWindow.SetMenu(menu);

    // Load the access keys
    haccel = ::LoadAccelerators(hThisInstance, MAKEINTRESOURCE(800));

    /* initializing the CHOOSECOLOR structure for use with ChooseColor */
    ZeroMemory(&choosecolor, sizeof(choosecolor));
    choosecolor.lStructSize    = sizeof(CHOOSECOLOR);
    choosecolor.hwndOwner      = mainWindow;
    choosecolor.rgbResult      = 0x00ffffff;
    choosecolor.lpCustColors   = custColors;

    /* initializing the OPENFILENAME structure for use with GetOpenFileName and GetSaveFileName */
    ofnFilename[0] = 0;
    CString strImporters;
    CSimpleArray<GUID> aguidFileTypesI;
    CString strAllPictureFiles;
    strAllPictureFiles.LoadString(hThisInstance, IDS_ALLPICTUREFILES);
    CImage::GetImporterFilterString(strImporters, aguidFileTypesI, strAllPictureFiles, CImage::excludeDefaultLoad, _T('\0'));
//     CAtlStringW strAllFiles;
//     strAllFiles.LoadString(hThisInstance, IDS_ALLFILES);
//     strImporters = strAllFiles + CAtlStringW(_T("|*.*|")).Replace('|', '\0') + strImporters;
    ZeroMemory(&ofn, sizeof(OPENFILENAME));
    ofn.lStructSize    = sizeof(OPENFILENAME);
    ofn.hwndOwner      = mainWindow;
    ofn.hInstance      = hThisInstance;
    ofn.lpstrFilter    = strImporters;
    ofn.lpstrFile      = ofnFilename;
    ofn.nMaxFile       = _countof(ofnFilename);
    ofn.lpstrFileTitle = ofnFiletitle;
    ofn.nMaxFileTitle  = _countof(ofnFiletitle);
    ofn.Flags          = OFN_EXPLORER | OFN_HIDEREADONLY;
    ofn.lpstrDefExt    = L"png";

    CopyMemory(sfnFilename, filepathname, sizeof(filepathname));
    CString strExporters;
    CSimpleArray<GUID> aguidFileTypesE;
    CImage::GetExporterFilterString(strExporters, aguidFileTypesE, NULL, CImage::excludeDefaultSave, _T('\0'));
    ZeroMemory(&sfn, sizeof(OPENFILENAME));
    sfn.lStructSize    = sizeof(OPENFILENAME);
    sfn.hwndOwner      = mainWindow;
    sfn.hInstance      = hThisInstance;
    sfn.lpstrFilter    = strExporters;
    sfn.lpstrFile      = sfnFilename;
    sfn.nMaxFile       = _countof(sfnFilename);
    sfn.lpstrFileTitle = sfnFiletitle;
    sfn.nMaxFileTitle  = _countof(sfnFiletitle);
    sfn.Flags          = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY | OFN_EXPLORER | OFN_ENABLEHOOK;
    sfn.lpfnHook       = OFNHookProc;
    sfn.lpstrDefExt    = L"png";
    // Choose PNG
    for (INT i = 0; i < aguidFileTypesE.GetSize(); ++i)
    {
        if (aguidFileTypesE[i] == Gdiplus::ImageFormatPNG)
        {
            sfn.nFilterIndex = i + 1;
            break;
        }
    }

    /* placing the size boxes around the image */
    imageArea.SendMessage(WM_SIZE, 0, 0);

    /* Make the window visible on the screen */
    mainWindow.ShowWindow(registrySettings.WindowPlacement.showCmd);

    /* Run the message loop. It will run until GetMessage() returns 0 */
    while (GetMessage(&messages, NULL, 0, 0))
    {
        if (fontsDialog.IsWindow() && IsDialogMessage(fontsDialog, &messages))
            continue;

        if (TranslateAccelerator(mainWindow, haccel, &messages))
            continue;

        /* Translate virtual-key messages into character messages */
        TranslateMessage(&messages);
        /* Send message to WindowProcedure */
        DispatchMessage(&messages);
    }

    ::DestroyAcceleratorTable(haccel);

    // Write back settings to registry
    registrySettings.Store();

    // The value that PostQuitMessage() gave
    return (INT)messages.wParam;
}
