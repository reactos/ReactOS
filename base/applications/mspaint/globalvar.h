/*
 * PROJECT:     PAINT for ReactOS
 * LICENSE:     LGPL
 * FILE:        base/applications/mspaint/globalvar.h
 * PURPOSE:     Declaring global variables for later initialization
 * PROGRAMMERS: Benedikt Freisen
 */

#pragma once

/* VARIABLES declared in main.cpp ***********************************/

class RegistrySettings;
extern RegistrySettings registrySettings;

class ImageModel;
extern ImageModel imageModel;
extern BOOL askBeforeEnlarging;

extern POINT start;
extern POINT last;

class ToolsModel;
extern ToolsModel toolsModel;

class SelectionModel;
extern SelectionModel selectionModel;

class PaletteModel;
extern PaletteModel paletteModel;

extern HWND hStatusBar;
extern CHOOSECOLOR choosecolor;
extern OPENFILENAME ofn;
extern OPENFILENAME sfn;
extern HICON hNontranspIcon;
extern HICON hTranspIcon;

extern HCURSOR hCurFill;
extern HCURSOR hCurColor;
extern HCURSOR hCurZoom;
extern HCURSOR hCurPen;
extern HCURSOR hCurAirbrush;

extern HINSTANCE hProgInstance;

extern TCHAR filepathname[1000];
extern BOOL isAFile;
extern BOOL imageSaved;
extern int fileSize;
extern int fileHPPM;
extern int fileVPPM;
extern SYSTEMTIME fileTime;

extern BOOL showGrid;
extern BOOL showMiniature;

class CMainWindow;
class CFullscreenWindow;
class CMiniatureWindow;
class CToolBox;
class CToolSettingsWindow;
class CPaletteWindow;
class CCanvasWindow;
class CSelectionWindow;
class CImgAreaWindow;
class CSizeboxWindow;
class CTextEditWindow;

extern CMainWindow mainWindow;
extern CFullscreenWindow fullscreenWindow;
extern CMiniatureWindow miniature;
extern CToolBox toolBoxContainer;
extern CToolSettingsWindow toolSettingsWindow;
extern CPaletteWindow paletteWindow;
extern CCanvasWindow canvasWindow;
extern CSelectionWindow selectionWindow;
extern CImgAreaWindow imageArea;
extern CTextEditWindow textEditWindow;

/* VARIABLES declared in dialogs.cpp ********************************/

class CMirrorRotateDialog;
class CAttributesDialog;
class CStretchSkewDialog;
class CFontsDialog;

extern CMirrorRotateDialog mirrorRotateDialog;
extern CAttributesDialog attributesDialog;
extern CStretchSkewDialog stretchSkewDialog;
extern CFontsDialog fontsDialog;
