/*
 * PROJECT:     ReactOS Applications Manager
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * FILE:        base/applications/rapps/available.cpp
 * PURPOSE:     Classes for working with available applications
 * COPYRIGHT:   Copyright 2009 Dmitry Chapyshev           (dmitry@reactos.org)
 *              Copyright 2015 Ismael Ferreras Morezuelas (swyterzone+ros@gmail.com)
 *              Copyright 2017 Alexander Shaposhnikov     (sanchaez@reactos.org)
 */
#include "rapps.h"

#include "available.h"
#include "misc.h"
#include "dialogs.h"

#include <atlcoll.h>
#include <atlsimpcoll.h>
#include <atlstr.h>

 // CAvailableApplicationInfo
CAvailableApplicationInfo::CAvailableApplicationInfo(const ATL::CStringW& sFileNameParam, AvailableStrings& AvlbStrings)
    : m_IsSelected(FALSE), m_LicenseType(LICENSE_NONE), m_SizeBytes(0), m_sFileName(sFileNameParam),
    m_IsInstalled(FALSE), m_HasLanguageInfo(FALSE), m_HasInstalledVersion(FALSE)
{
    RetrieveGeneralInfo(AvlbStrings);
}

VOID CAvailableApplicationInfo::RefreshAppInfo(AvailableStrings& AvlbStrings)
{
    if (m_szUrlDownload.IsEmpty())
    {
        RetrieveGeneralInfo(AvlbStrings);
    }
}

// Lazily load general info from the file
VOID CAvailableApplicationInfo::RetrieveGeneralInfo(AvailableStrings& AvlbStrings)
{
    m_Parser = new CConfigParser(m_sFileName);

    m_Parser->GetInt(L"Category", m_Category);

    if (!GetString(L"Name", m_szName)
        || !GetString(L"URLDownload", m_szUrlDownload))
    {
        delete m_Parser;
        return;
    }

    GetString(L"RegName", m_szRegName);
    GetString(L"Version", m_szVersion);
    GetString(L"License", m_szLicense);
    GetString(L"Description", m_szDesc);
    GetString(L"URLSite", m_szUrlSite);
    GetString(L"SHA1", m_szSHA1);

    static_assert(MAX_SNAPSHOT_NUM < 10000, "MAX_SNAPSHOT_NUM is too big");
    for (int i = 0; i < MAX_SNAPSHOT_NUM; i++)
    {
        WCHAR SnapshotField[sizeof("Snapshot") + 4];
        wsprintfW(SnapshotField, L"Snapshot%d", i + 1);
        ATL::CStringW SnapshotLocation;
        if (!GetString(SnapshotField, SnapshotLocation))
        {
            continue;
        }


        if (PathIsURLW(SnapshotLocation.GetString()))
        {
            m_szSnapshotLocation.Add(SnapshotLocation);
        }
        else
        {
            // TODO: Does the filename contain anything stuff like "\\" ".." ":" "<" ">" ?
            // these stuff may lead to security issues

            ATL::CStringW SnapshotName = AvlbStrings.szAppsPath;
            PathAppendW(SnapshotName.GetBuffer(MAX_PATH), L"snapshots");
            PathAppendW(SnapshotName.GetBuffer(), SnapshotLocation.GetString());
            SnapshotName.ReleaseBuffer();
            m_szSnapshotLocation.Add(SnapshotName);
        }
    }

    RetrieveSize();
    RetrieveLicenseType();
    RetrieveLanguages();
    RetrieveInstalledStatus();

    if (m_IsInstalled)
    {
        RetrieveInstalledVersion();
    }

    delete m_Parser;
}

VOID CAvailableApplicationInfo::RetrieveInstalledStatus()
{
    m_IsInstalled = ::GetInstalledVersion(NULL, m_szRegName)
        || ::GetInstalledVersion(NULL, m_szName);
}

VOID CAvailableApplicationInfo::RetrieveInstalledVersion()
{
    ATL::CStringW szNameVersion;
    szNameVersion = m_szName + L" " + m_szVersion;
    m_HasInstalledVersion = ::GetInstalledVersion(&m_szInstalledVersion, m_szRegName)
        || ::GetInstalledVersion(&m_szInstalledVersion, m_szName)
        || ::GetInstalledVersion(&m_szInstalledVersion, szNameVersion);
}

VOID CAvailableApplicationInfo::RetrieveLanguages()
{
    const WCHAR cDelimiter = L'|';
    ATL::CStringW szBuffer;

    // TODO: Get multiline parameter
    if (!m_Parser->GetString(L"Languages", szBuffer))
    {
        m_HasLanguageInfo = FALSE;
        return;
    }

    // Parse parameter string
    ATL::CStringW m_szLocale;
    INT iLCID;
    for (INT i = 0; szBuffer[i] != UNICODE_NULL; ++i)
    {
        if (szBuffer[i] != cDelimiter && szBuffer[i] != L'\n')
        {
            m_szLocale += szBuffer[i];
        }
        else
        {
            if (StrToIntExW(m_szLocale.GetString(), STIF_DEFAULT, &iLCID))
            {
                m_LanguageLCIDs.Add(static_cast<LCID>(iLCID));
                m_szLocale.Empty();
            }
        }
    }

    // For the text after delimiter
    if (!m_szLocale.IsEmpty())
    {
        if (StrToIntExW(m_szLocale.GetString(), STIF_DEFAULT, &iLCID))
        {
            m_LanguageLCIDs.Add(static_cast<LCID>(iLCID));
        }
    }

    m_HasLanguageInfo = TRUE;
}

VOID CAvailableApplicationInfo::RetrieveLicenseType()
{
    INT IntBuffer;

    m_Parser->GetInt(L"LicenseType", IntBuffer);

    if (IsLicenseType(IntBuffer))
    {
        m_LicenseType = static_cast<LicenseType>(IntBuffer);
    }
    else
    {
        m_LicenseType = LICENSE_NONE;
    }
}

VOID CAvailableApplicationInfo::RetrieveSize()
{
    INT iSizeBytes;

    if (!m_Parser->GetInt(L"SizeBytes", iSizeBytes))
    {
        // fall back to "Size" string
        GetString(L"Size", m_szSize);
        return;
    }

    m_SizeBytes = iSizeBytes;
    StrFormatByteSizeW(iSizeBytes, m_szSize.GetBuffer(MAX_PATH), MAX_PATH);
    m_szSize.ReleaseBuffer();
}

BOOL CAvailableApplicationInfo::FindInLanguages(LCID what) const
{
    if (!m_HasLanguageInfo)
    {
        return FALSE;
    }

    //Find locale code in the list
    const INT nLanguagesSize = m_LanguageLCIDs.GetSize();
    for (INT i = 0; i < nLanguagesSize; ++i)
    {
        if (m_LanguageLCIDs[i] == what)
        {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL CAvailableApplicationInfo::HasLanguageInfo() const
{
    return m_HasLanguageInfo;
}

BOOL CAvailableApplicationInfo::HasNativeLanguage() const
{
    return FindInLanguages(GetUserDefaultLCID());
}

BOOL CAvailableApplicationInfo::HasEnglishLanguage() const
{
    return FindInLanguages(MAKELCID(MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), SORT_DEFAULT));
}

BOOL CAvailableApplicationInfo::IsInstalled() const
{
    return m_IsInstalled;
}

BOOL CAvailableApplicationInfo::HasInstalledVersion() const
{
    return m_HasInstalledVersion;
}

BOOL CAvailableApplicationInfo::HasUpdate() const
{
    return (m_szInstalledVersion.Compare(m_szVersion) < 0) ? TRUE : FALSE;
}

BOOL CAvailableApplicationInfo::RetrieveSnapshot(UINT Index,ATL::CStringW& SnapshotFileName) const
{
    if (Index >= (UINT)m_szSnapshotLocation.GetSize())
    {
        return FALSE;
    }
    SnapshotFileName = m_szSnapshotLocation[Index];
    return TRUE;
}

VOID CAvailableApplicationInfo::SetLastWriteTime(FILETIME* ftTime)
{
    RtlCopyMemory(&m_ftCacheStamp, ftTime, sizeof(FILETIME));
}

inline BOOL CAvailableApplicationInfo::GetString(LPCWSTR lpKeyName, ATL::CStringW& ReturnedString)
{
    if (!m_Parser->GetString(lpKeyName, ReturnedString))
    {
        ReturnedString.Empty();
        return FALSE;
    }
    return TRUE;
}
// CAvailableApplicationInfo

// AvailableStrings
AvailableStrings::AvailableStrings()
{
    //FIXME: maybe provide a fallback?
    if (GetStorageDirectory(szPath))
    {
        szAppsPath = szPath;
        PathAppendW(szAppsPath.GetBuffer(MAX_PATH), L"rapps");
        szAppsPath.ReleaseBuffer();

        szCabName = L"rappmgr.cab";
        szCabDir = szPath;
        szCabPath = szCabDir;
        PathAppendW(szCabPath.GetBuffer(MAX_PATH), szCabName);
        szCabPath.ReleaseBuffer();

        szSearchPath = szAppsPath;
        PathAppendW(szSearchPath.GetBuffer(MAX_PATH), L"*.txt");
        szSearchPath.ReleaseBuffer();
    }
}
// AvailableStrings

// CAvailableApps
AvailableStrings CAvailableApps::m_Strings;

CAvailableApps::CAvailableApps()
{
}

VOID CAvailableApps::FreeCachedEntries()
{
    POSITION InfoListPosition = m_InfoList.GetHeadPosition();

    /* loop and deallocate all the cached app infos in the list */
    while (InfoListPosition)
    {
        CAvailableApplicationInfo* Info = m_InfoList.GetNext(InfoListPosition);
        delete Info;
    }

    m_InfoList.RemoveAll();
}

VOID CAvailableApps::DeleteCurrentAppsDB()
{
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW FindFileData;

    hFind = FindFirstFileW(m_Strings.szSearchPath.GetString(), &FindFileData);

    if (hFind != INVALID_HANDLE_VALUE)
    {
        ATL::CStringW szTmp;
        do
        {
            szTmp = m_Strings.szAppsPath;
            PathAppendW(szTmp.GetBuffer(MAX_PATH), FindFileData.cFileName);
            szTmp.ReleaseBuffer();
            DeleteFileW(szTmp.GetString());
        } while (FindNextFileW(hFind, &FindFileData) != 0);
        FindClose(hFind);
    }

    RemoveDirectoryW(m_Strings.szAppsPath);
    RemoveDirectoryW(m_Strings.szPath);
}

BOOL CAvailableApps::UpdateAppsDB()
{
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW FindFileData;

    if (!CreateDirectoryW(m_Strings.szPath, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
    {
        return FALSE;
    }

    //if there are some files in the db folder - we're good
    hFind = FindFirstFileW(m_Strings.szSearchPath, &FindFileData);
    if (hFind != INVALID_HANDLE_VALUE)
    {
        FindClose(hFind);
        return TRUE;
    }

    DownloadApplicationsDB(SettingsInfo.bUseSource ? SettingsInfo.szSourceURL : APPLICATION_DATABASE_URL,
        !SettingsInfo.bUseSource);
    
    if (!ExtractFilesFromCab(m_Strings.szCabName, 
                             m_Strings.szCabDir,
                             m_Strings.szAppsPath))
    {
        return FALSE;
    }

    DeleteFileW(m_Strings.szCabPath);

    return TRUE;
}

BOOL CAvailableApps::ForceUpdateAppsDB()
{
    DeleteCurrentAppsDB();
    return UpdateAppsDB();
}

BOOL CAvailableApps::Enum(INT EnumType, AVAILENUMPROC lpEnumProc, PVOID param)
{

    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAW FindFileData;

    hFind = FindFirstFileW(m_Strings.szSearchPath.GetString(), &FindFileData);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        //no db yet
        return FALSE;
    }

    do
    {
        // loop for all the cached entries
        POSITION CurrentListPosition = m_InfoList.GetHeadPosition();
        CAvailableApplicationInfo* Info = NULL;

        while (CurrentListPosition != NULL)
        {
            POSITION LastListPosition = CurrentListPosition;
            Info = m_InfoList.GetNext(CurrentListPosition);

            // do we already have this entry in cache?
            if (Info->m_sFileName == FindFileData.cFileName)
            {
                // is it current enough, or the file has been modified since our last time here?
                if (CompareFileTime(&FindFileData.ftLastWriteTime, &Info->m_ftCacheStamp) == 1)
                {
                    // recreate our cache, this is the slow path
                    m_InfoList.RemoveAt(LastListPosition);

                    delete Info;
                    Info = NULL;
                    break;
                }
                else
                {
                    // speedy path, compare directly, we already have the data
                    goto skip_if_cached;
                }
            }
        }

        // create a new entry
        Info = new CAvailableApplicationInfo(FindFileData.cFileName, m_Strings);

        // set a timestamp for the next time
        Info->SetLastWriteTime(&FindFileData.ftLastWriteTime);
        m_InfoList.AddTail(Info);

skip_if_cached:
        if (EnumType == Info->m_Category
            || EnumType == ENUM_ALL_AVAILABLE
            || (EnumType == ENUM_CAT_SELECTED && Info->m_IsSelected))
        {
            Info->RefreshAppInfo(m_Strings);

            if (lpEnumProc)
                lpEnumProc(Info, m_Strings.szAppsPath.GetString(), param);
        }
    } while (FindNextFileW(hFind, &FindFileData) != 0);

    FindClose(hFind);
    return TRUE;
}

CAvailableApplicationInfo* CAvailableApps::FindInfo(const ATL::CStringW& szAppName) const
{
    if (m_InfoList.IsEmpty())
    {
        return NULL;
    }

    // linear search
    POSITION CurrentListPosition = m_InfoList.GetHeadPosition();
    CAvailableApplicationInfo* info;
    while (CurrentListPosition != NULL)
    {
        info = m_InfoList.GetNext(CurrentListPosition);
        if (info->m_szName.CompareNoCase(szAppName) == 0)
        {
            return info;
        }
    }
    return NULL;
}

ATL::CSimpleArray<CAvailableApplicationInfo> CAvailableApps::FindInfoList(const ATL::CSimpleArray<ATL::CStringW> &arrAppsNames) const
{
    ATL::CSimpleArray<CAvailableApplicationInfo> result;
    for (INT i = 0; i < arrAppsNames.GetSize(); ++i)
    {
        CAvailableApplicationInfo* Info = FindInfo(arrAppsNames[i]);
        if (Info)
        {
            result.Add(*Info);
        }
    }
    return result;
}

ATL::CSimpleArray<CAvailableApplicationInfo> CAvailableApps::GetSelected() const
{
    ATL::CSimpleArray<CAvailableApplicationInfo> result;
    POSITION CurrentListPosition = m_InfoList.GetHeadPosition();
    CAvailableApplicationInfo* Info;

    while (CurrentListPosition != NULL)
    {
        Info = m_InfoList.GetNext(CurrentListPosition);
        if (Info->m_IsSelected)
        {
            result.Add(*Info);
        }
    }
    return result;
}

const ATL::CStringW& CAvailableApps::GetFolderPath() const
{
    return m_Strings.szPath;
}

const ATL::CStringW& CAvailableApps::GetAppPath() const
{
    return m_Strings.szAppsPath;
}

const ATL::CStringW& CAvailableApps::GetCabPath() const
{
    return m_Strings.szCabPath;
}
// CAvailableApps
