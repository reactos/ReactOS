/*
 * PROJECT:     ReactOS Service Control Manager
 * LICENSE:     GPL - See COPYING in the top level directory
 * FILE:        base/system/services/controlset.c
 * PURPOSE:     Control Set Management
 * COPYRIGHT:   Copyright 2012 Eric Kohl
 *
 */

/* INCLUDES *****************************************************************/

#include "services.h"
#include <ndk/cmfuncs.h> // For NtInitializeRegistry()

#define NDEBUG
#include <debug.h>

LSTATUS WINAPI RegCopyTreeW(_In_ HKEY, _In_opt_ LPCWSTR, _In_ HKEY);
LSTATUS WINAPI RegDeleteTreeW(_In_ HKEY, _In_opt_ LPCWSTR);

/* GLOBALS *******************************************************************/

static BOOL bBootAccepted = FALSE;

/* FUNCTIONS *****************************************************************/

static
DWORD
ScmGetControlSetValues(
    PDWORD pdwCurrentControlSet,
    PDWORD pdwDefaultControlSet,
    PDWORD pdwFailedControlSet,
    PDWORD pdwLastKnownGoodControlSet)
{
    HKEY hSelectKey;
    DWORD dwType;
    DWORD dwSize;
    DWORD dwError;

    DPRINT("ScmGetControlSetValues() called\n");

    dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"System\\Select",
                            0,
                            KEY_READ,
                            &hSelectKey);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    dwSize = sizeof(DWORD);
    dwError = RegQueryValueExW(hSelectKey,
                               L"Current",
                               0,
                               &dwType,
                               (LPBYTE)pdwCurrentControlSet,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
    {
        *pdwCurrentControlSet = 0;
    }

    dwSize = sizeof(DWORD);
    dwError = RegQueryValueExW(hSelectKey,
                               L"Default",
                               0,
                               &dwType,
                               (LPBYTE)pdwDefaultControlSet,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
    {
        *pdwDefaultControlSet = 0;
    }

    dwSize = sizeof(DWORD);
    dwError = RegQueryValueExW(hSelectKey,
                               L"Failed",
                               0,
                               &dwType,
                               (LPBYTE)pdwFailedControlSet,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
    {
        *pdwFailedControlSet = 0;
    }

    dwSize = sizeof(DWORD);
    dwError = RegQueryValueExW(hSelectKey,
                               L"LastKnownGood",
                               0,
                               &dwType,
                               (LPBYTE)pdwLastKnownGoodControlSet,
                               &dwSize);
    if (dwError != ERROR_SUCCESS)
    {
        *pdwLastKnownGoodControlSet = 0;
    }

    RegCloseKey(hSelectKey);

    DPRINT("ControlSets:\n");
    DPRINT("Current: %lu\n", *pdwCurrentControlSet);
    DPRINT("Default: %lu\n", *pdwDefaultControlSet);
    DPRINT("Failed: %lu\n", *pdwFailedControlSet);
    DPRINT("LastKnownGood: %lu\n", *pdwLastKnownGoodControlSet);

    return dwError;
}

static
DWORD
ScmSetLastKnownGoodControlSet(
    DWORD dwControlSet)
{
    HKEY hSelectKey;
    DWORD dwError;

    dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"System\\Select",
                            0,
                            KEY_WRITE,
                            &hSelectKey);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    dwError = RegSetValueExW(hSelectKey,
                             L"LastKnownGood",
                             0,
                             REG_DWORD,
                             (LPBYTE)&dwControlSet,
                             sizeof(dwControlSet));

    RegFlushKey(hSelectKey);
    RegCloseKey(hSelectKey);

    return dwError;
}

static
BOOL
ScmIsSetupInProgress(VOID)
{
    /* Cached value so as not to call the registry every time */
    static DWORD dwSetupInProgress = (DWORD)-1;

    HKEY hKey;
    DWORD dwError;
    DWORD dwType;
    DWORD dwSize;

    /* Return the cached value if applicable */
    if (dwSetupInProgress != (DWORD)-1)
        return (BOOL)dwSetupInProgress;

    /* Assume no Setup is in progress */
    dwSetupInProgress = FALSE;

    /* Open key */
    dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            L"SYSTEM\\Setup",
                            0,
                            KEY_QUERY_VALUE,
                            &hKey);
    if (dwError != ERROR_SUCCESS)
        return FALSE;

    /* Read value */
    dwSize = sizeof(dwSetupInProgress);
    dwError = RegQueryValueExW(hKey,
                               L"SystemSetupInProgress",
                               NULL,
                               &dwType,
                               (LPBYTE)&dwSetupInProgress,
                               &dwSize);
    RegCloseKey(hKey);
    if (dwError != ERROR_SUCCESS)
        return FALSE;

    /* Normalize the value and return it */
    dwSetupInProgress = !!dwSetupInProgress;
    return (BOOL)dwSetupInProgress;
}

static
DWORD
ScmCopyControlSet(
    DWORD dwSourceControlSet,
    DWORD dwDestinationControlSet)
{
    WCHAR szSourceControlSetName[32];
    WCHAR szDestinationControlSetName[32];
    HKEY hSourceControlSetKey = NULL;
    HKEY hDestinationControlSetKey = NULL;
    DWORD dwDisposition;
    DWORD dwError;

    /* Create the source control set name */
    swprintf(szSourceControlSetName, L"SYSTEM\\ControlSet%03lu", dwSourceControlSet);
    DPRINT("Source control set: %S\n", szSourceControlSetName);

    /* Create the destination control set name */
    swprintf(szDestinationControlSetName, L"SYSTEM\\ControlSet%03lu", dwDestinationControlSet);
    DPRINT("Destination control set: %S\n", szDestinationControlSetName);

    /* Open the source control set key */
    dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            szSourceControlSetName,
                            0,
                            KEY_READ,
                            &hSourceControlSetKey);
    if (dwError != ERROR_SUCCESS)
        goto done;

    /* Create the destination control set key */
    dwError = RegCreateKeyExW(HKEY_LOCAL_MACHINE,
                              szDestinationControlSetName,
                              0,
                              NULL,
                              REG_OPTION_NON_VOLATILE,
                              KEY_WRITE,
                              NULL,
                              &hDestinationControlSetKey,
                              &dwDisposition);
    if (dwError != ERROR_SUCCESS)
        goto done;

    /* Copy the source control set to the destination control set */
    dwError = RegCopyTreeW(hSourceControlSetKey,
                           NULL,
                           hDestinationControlSetKey);
    if (dwError != ERROR_SUCCESS)
        goto done;

    RegFlushKey(hDestinationControlSetKey);

done:
    if (hDestinationControlSetKey)
        RegCloseKey(hDestinationControlSetKey);

    if (hSourceControlSetKey)
        RegCloseKey(hSourceControlSetKey);

    return dwError;
}

static
DWORD
ScmDeleteControlSet(
    DWORD dwControlSet)
{
    WCHAR szControlSetName[32];
    HKEY hControlSetKey = NULL;
    DWORD dwError;

    DPRINT("ScmDeleteControSet(%lu)\n", dwControlSet);

__debugbreak();
    /* Create the control set name */
    swprintf(szControlSetName, L"SYSTEM\\ControlSet%03lu", dwControlSet);
    DPRINT("Control set: %S\n", szControlSetName);

    /* Open the control set key */
    dwError = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                            szControlSetName,
                            0,
                            DELETE | KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE | KEY_SET_VALUE,
                            &hControlSetKey);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    /* Delete the control set */
#if 0
    dwError = RegDeleteTreeW(hControlSetKey, L"");
#else
    dwError = RegDeleteTreeW(hControlSetKey, NULL);   // Delete the values and subkeys.
    if (dwError == ERROR_SUCCESS)
        dwError = RegDeleteKeyW(hControlSetKey, L""); // And delete the key itself.
#endif

    /* Close the control set key */
    RegCloseKey(hControlSetKey);

#if 0
    /* Finally delete the key */
    if (dwError == ERROR_SUCCESS)
        dwError = RegDeleteKeyW(HKEY_LOCAL_MACHINE, szControlSetName);
#endif

    return dwError;
}

DWORD
ScmCreateLastKnownGoodControlSet(VOID)
{
    DWORD dwCurrentControlSet, dwDefaultControlSet;
    DWORD dwFailedControlSet, dwLastKnownGoodControlSet;
    DWORD dwNewControlSet;
    DWORD dwError;
    NTSTATUS Status;

    ASSERT(!bBootAccepted);

__debugbreak();
    /* Get the control set values */
    dwError = ScmGetControlSetValues(&dwCurrentControlSet,
                                     &dwDefaultControlSet,
                                     &dwFailedControlSet,
                                     &dwLastKnownGoodControlSet);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    /* First boot after setup? */
    if (!ScmIsSetupInProgress() &&
        (dwCurrentControlSet == dwLastKnownGoodControlSet))
    {
        DPRINT("First boot after setup\n");

        /* Search for a new control set number */
        for (dwNewControlSet = 1; dwNewControlSet < 1000; dwNewControlSet++)
        {
            if ((dwNewControlSet != dwCurrentControlSet) &&
                (dwNewControlSet != dwDefaultControlSet) &&
                (dwNewControlSet != dwFailedControlSet) &&
                (dwNewControlSet != dwLastKnownGoodControlSet))
            {
                break;
            }
        }

        /* Fail if we did not find an unused control set */
        if (dwNewControlSet >= 1000)
        {
            DPRINT1("Too many control sets\n");
            return ERROR_NO_MORE_ITEMS;
        }

        /* Copy the current control set */
        dwError = ScmCopyControlSet(dwCurrentControlSet, dwNewControlSet);
        if (dwError != ERROR_SUCCESS)
            return dwError;

        /* Set the new 'LastKnownGood' control set */
        dwError = ScmSetLastKnownGoodControlSet(dwNewControlSet);
        if (dwError != ERROR_SUCCESS)
            return dwError;

        /* Tell the kernel that the CurrentControlSet is good */
        Status = NtInitializeRegistry(CM_BOOT_FLAG_ACCEPTED + dwNewControlSet);
        if (!NT_SUCCESS(Status))
        {
            DPRINT1("NtInitializeRegistry() failed (Status 0x%08lx)\n", Status);
            return RtlNtStatusToDosError(Status);
        }

        /*
         * Accept the boot here in order to prevent the creation of
         * another control set when a user is going to get logged on.
         */
        bBootAccepted = TRUE;
        dwError = ERROR_SUCCESS;
    }

    return dwError;
}

DWORD
ScmAcceptBoot(VOID)
{
    DWORD dwCurrentControlSet, dwDefaultControlSet;
    DWORD dwFailedControlSet, dwLastKnownGoodControlSet;
    DWORD dwNewControlSet;
    DWORD dwError;
    NTSTATUS Status;

    DPRINT("ScmAcceptBoot()\n");

__debugbreak();

    if (bBootAccepted)
    {
        DPRINT1("Boot has already been accepted\n");
        return ERROR_BOOT_ALREADY_ACCEPTED;
    }

    /* Get the control set values */
    dwError = ScmGetControlSetValues(&dwCurrentControlSet,
                                     &dwDefaultControlSet,
                                     &dwFailedControlSet,
                                     &dwLastKnownGoodControlSet);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    /* Search for a new control set number */
    for (dwNewControlSet = 1; dwNewControlSet < 1000; dwNewControlSet++)
    {
        if ((dwNewControlSet != dwCurrentControlSet) &&
            (dwNewControlSet != dwDefaultControlSet) &&
            (dwNewControlSet != dwFailedControlSet) &&
            (dwNewControlSet != dwLastKnownGoodControlSet))
        {
            break;
        }
    }

    /* Fail if we did not find an unused control set */
    if (dwNewControlSet >= 1000)
    {
        DPRINT1("Too many control sets\n");
        return ERROR_NO_MORE_ITEMS;
    }

    /* Copy the current control set */
    dwError = ScmCopyControlSet(dwCurrentControlSet, dwNewControlSet);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    /* Delete the current last known good control set, if it is not used anywhere else */
    if ((dwLastKnownGoodControlSet != dwCurrentControlSet) &&
        (dwLastKnownGoodControlSet != dwDefaultControlSet) &&
        (dwLastKnownGoodControlSet != dwFailedControlSet))
    {
        ScmDeleteControlSet(dwLastKnownGoodControlSet);
    }

    /* Set the new 'LastKnownGood' control set */
    dwError = ScmSetLastKnownGoodControlSet(dwNewControlSet);
    if (dwError != ERROR_SUCCESS)
        return dwError;

    /* Tell the kernel that the CurrentControlSet is good */
    Status = NtInitializeRegistry(CM_BOOT_FLAG_ACCEPTED + dwNewControlSet);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtInitializeRegistry() failed (Status 0x%08lx)\n", Status);
        return RtlNtStatusToDosError(Status);
    }

    bBootAccepted = TRUE;
    return ERROR_SUCCESS;
}

DWORD
ScmRestoreLastKnownGood(VOID)
{
    DPRINT("ScmRestoreLastKnownGood()\n");

    if (bBootAccepted)
    {
        DPRINT1("Boot has already been accepted\n");
        return ERROR_BOOT_ALREADY_ACCEPTED;
    }

    // FIXME: Restore the LKG and reboot.
    return ERROR_SUCCESS;
}

/* EOF */
