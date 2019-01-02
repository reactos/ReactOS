/*
 * PROJECT:     ReactOS Setup Library
 * LICENSE:     GPL-2.0+ (https://spdx.org/licenses/GPL-2.0+)
 * PURPOSE:     Partition list functions
 * COPYRIGHT:   Copyright 2003-2018 Casper S. Hornstrup (chorns@users.sourceforge.net)
 */

#include "precomp.h"
#include <ntddscsi.h>

#include "partlist.h"
#include "fsutil.h"

#define NDEBUG
#include <debug.h>

//#define DUMP_PARTITION_TABLE

#include <pshpack1.h>

typedef struct _REG_DISK_MOUNT_INFO
{
    ULONG Signature;
    LARGE_INTEGER StartingOffset;
} REG_DISK_MOUNT_INFO, *PREG_DISK_MOUNT_INFO;

#include <poppack.h>


/* HELPERS FOR PARTITION TYPES **********************************************/

/*
 * This partition type list was ripped from the kernelDisk.c module of
 * the Visopsys Operating System (see license below), and completed with
 * information from Paragon Hard-Disk Manager, and the following websites:
 * http://www.win.tue.nl/~aeb/partitions/partition_types-1.html
 * https://en.wikipedia.org/wiki/Partition_type#List_of_partition_IDs
 */
/*
 * kernelDisk.c
 *
 * Visopsys Operating System
 * Copyright (C) 1998-2015 J. Andrew McLaughlin
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/* This is a table for keeping known partition type codes and descriptions */
PARTITION_TYPE PartitionTypes[NUM_PARTITION_TYPE_ENTRIES] =
{
    { 0x00, "(Empty)" },
    { 0x01, "FAT12" },
    { 0x02, "XENIX root" },
    { 0x03, "XENIX usr" },
    { 0x04, "FAT16 (< 32 MB)" },
    { 0x05, "Extended" },
    { 0x06, "FAT16" },
    { 0x07, "NTFS/HPFS/exFAT" },
    { 0x08, "OS/2 or AIX boot" },
    { 0x09, "AIX data" },
    { 0x0A, "OS/2 Boot Manager" },
    { 0x0B, "FAT32" },
    { 0x0C, "FAT32 (LBA)" },
    { 0x0E, "FAT16 (LBA)" },
    { 0x0F, "Extended (LBA)" },
    { 0x10, "OPUS" },
    { 0x11, "Hidden FAT12" },
    { 0x12, "FAT diagnostic (Compaq)" },
    { 0x13, "BTRON" },
    { 0x14, "Hidden FAT16 (< 32 MB)" },
    { 0x16, "Hidden FAT16" },
    { 0x17, "Hidden HPFS or NTFS" },
    { 0x18, "AST SmartSleep" },
    { 0x1B, "Hidden FAT32" },
    { 0x1C, "Hidden FAT32 (LBA)" },
    { 0x1E, "Hidden FAT16 (LBA)" },
    { 0x24, "NEC DOS 3.x" },
    { 0x27, "Hidden WinRE NTFS" },
    { 0x2A, "AtheOS File System (AFS)" },
    { 0x2B, "SyllableSecure (SylStor)" },
    { 0x32, "NOS" },
    { 0x35, "JFS on OS/2 or eCS" },
    { 0x38, "THEOS v3.2 2GB partition" },
    { 0x39, "Plan 9" },
    { 0x3A, "THEOS v4 4GB partition" },
    { 0x3B, "THEOS v4 extended partition" },
    { 0x3C, "PartitionMagic recovery partition" },
    { 0x3D, "Hidden NetWare" },
    { 0x40, "Lynx" },
    { 0x41, "PowerPC PReP boot" },
    { 0x42, "Win2K Dynamic Volume extended" },
    { 0x43, "Old Linux" },
    { 0x44, "GoBack" },
    { 0x45, "Priam or Boot-US Boot Manager" },
    { 0x4D, "QNX4.x" },
    { 0x4E, "QNX4.x 2nd partition" },
    { 0x4F, "QNX4.x 3rd partition" },
    { 0x50, "OnTrack Disk Manager R/O" },
    { 0x51, "OnTrack Disk Manager R/W or Novell" },
    { 0x52, "CP/M" },
    { 0x53, "OnTrack DM6 Aux3" },
    { 0x54, "OnTrack DM6 Dynamic Drive Overlay" },
    { 0x55, "EZ-Drive" },
    { 0x56, "Golden Bow VFeature Partitioned Volume" },
    { 0x5C, "Priam EDisk" },
    { 0x61, "SpeedStor" },
    { 0x62, "Pick" },
    { 0x63, "GNU HURD or Unix System V (SCO, ISC Unix, UnixWare)" },
    { 0x64, "Novell NetWare 286, 2.xx" },
    { 0x65, "Novell NetWare 386, 3.xx or 4.xx" },
    { 0x66, "Novell NetWare SMS Partition" },
    { 0x67, "Novell" },
    { 0x68, "Novell" },
    { 0x69, "Novell NetWare 5+" },
    { 0x70, "DiskSecure Multi-Boot" },
    { 0x75, "IBM PC/IX" },
    { 0x7E, "Veritas VxVM public" },
    { 0x7F, "Veritas VxVM private" },
    { 0x80, "Old MINIX" },
    { 0x81, "Linux or MINIX" },
    { 0x82, "Linux swap or Solaris" },
    { 0x83, "Linux Native" },
    { 0x84, "Hibernate" },
    { 0x85, "Extended Linux" },
    { 0x86, "FAT16 mirrored" },
    { 0x87, "HPFS or NTFS mirrored" },
    { 0x88, "Linux plaintext partition table" },
    { 0x8B, "FAT32 mirrored" },
    { 0x8C, "FAT32 (LBA) mirrored" },
    { 0x8E, "Linux LVM" },
    { 0x93, "Hidden Linux" },
    { 0x94, "Amoeba BBT" },
    { 0x96, "CDFS/ISO-9660" },
    { 0x9F, "BSD/OS" },
    { 0xA0, "Laptop Hibernate" },
    { 0xA1, "Laptop Hibernate (NEC 6000H)" },
    { 0xA5, "BSD, NetBSD, FreeBSD" },
    { 0xA6, "OpenBSD" },
    { 0xA7, "NeXTStep" },
    { 0xA8, "Darwin UFS" },      // Also known as "OS-X"
    { 0xA9, "NetBSD" },
    { 0xAB, "Darwin boot" },
    { 0xAF, "Apple HFS" },
    { 0xB6, "NT FAT16 corrupt mirror" },
    { 0xB7, "BSDI BSD/386 FS" }, // Alternatively, "NT NTFS corrupt mirror"
    { 0xB8, "BSDI BSD/386 swap" },
    { 0xBB, "Boot Wizard hidden" },
    { 0xBC, "Paragon Backup capsule" },
    { 0xBE, "Solaris 8 boot partition" },
    { 0xBF, "Solaris 10 x86" },
    { 0xC0, "NTFT" },            // Alternatively, "CTOS" or "REAL/32 or DR-DOS or Novell-DOS secure partition"
    { 0xC1, "DR-DOS FAT12" },
    { 0xC2, "Hidden Linux" },
    { 0xC3, "Hidden Linux swap" },
    { 0xC4, "DR-DOS FAT16 (< 32 MB)" },
    { 0xC5, "DR-DOS Extended" },
    { 0xC6, "DR-DOS FAT16" },
    { 0xC7, "HPFS mirrored" },   // Alternatively, "Syrinx boot"
    { 0xCB, "DR-DOS FAT32" },
    { 0xCC, "DR-DOS FAT32 (LBA)" },
    { 0xCE, "DR-DOS FAT16 (LBA)" },
    { 0xD0, "MDOS" },
    { 0xD1, "MDOS FAT12" },
    { 0xD4, "MDOS FAT16 (< 32 MB)" },
    { 0xD5, "MDOS Extended" },
    { 0xD6, "MDOS FAT16" },
    { 0xD8, "CP/M-86" },
    { 0xDB, "Digital Research CP/M" },
    { 0xDE, "Dell OEM" },
    { 0xDF, "BootIt EMBRM (FAT16/32)" },
    { 0xE1, "SpeedStor FAT12" },
    { 0xE3, "SpeedStor (0xE3)" },
    { 0xE4, "SpeedStor FAT16" },
    { 0xE5, "Tandy MSDOS" },
    { 0xE6, "SpeedStor (0xE6)" },
    { 0xE8, "Linux Unified Key Setup partition" },
    { 0xEA, "Rufus private partition" },
    { 0xEB, "BeOS BFS" },
    { 0xEC, "SkyOS SkyFS" },
    { 0xEE, "EFI GPT protective" },
    { 0xEF, "EFI System partition" },
    { 0xF0, "Linux/PA-RISC boot loader" },
    { 0xF1, "SpeedStor (0xF1)" },
    { 0xF2, "DOS 3.3+ second" },
    { 0xF4, "SpeedStor (0xF4)" },
    { 0xF5, "SpeedStor (0xF5)" },
    { 0xF6, "SpeedStor (0xF6)" },
    { 0xFA, "Bochs" },
    { 0xFB, "VMware FS" },
    { 0xFC, "VMware swap" },
    { 0xFD, "Linux RAID auto" },
    { 0xFE, "NT hidden partition" },
    { 0xFF, "XENIX Bad Block Table" },
};


/* FUNCTIONS ****************************************************************/

#ifdef DUMP_PARTITION_TABLE
static
VOID
DumpPartitionTable(
    PDISKENTRY DiskEntry)
{
    PPARTITION_INFORMATION PartitionInfo;
    ULONG i;

    DbgPrint("\n");
    DbgPrint("Index  Start         Length        Hidden      Nr  Type  Boot  RW\n");
    DbgPrint("-----  ------------  ------------  ----------  --  ----  ----  --\n");

    for (i = 0; i < DiskEntry->LayoutBuffer->PartitionCount; i++)
    {
        PartitionInfo = &DiskEntry->LayoutBuffer->PartitionEntry[i];
        DbgPrint("  %3lu  %12I64u  %12I64u  %10lu  %2lu    %2x     %c   %c\n",
                 i,
                 PartitionInfo->StartingOffset.QuadPart / DiskEntry->BytesPerSector,
                 PartitionInfo->PartitionLength.QuadPart / DiskEntry->BytesPerSector,
                 PartitionInfo->HiddenSectors,
                 PartitionInfo->PartitionNumber,
                 PartitionInfo->PartitionType,
                 PartitionInfo->BootIndicator ? '*': ' ',
                 PartitionInfo->RewritePartition ? 'Y': 'N');
    }

    DbgPrint("\n");
}
#endif


ULONGLONG
AlignDown(
    IN ULONGLONG Value,
    IN ULONG Alignment)
{
    ULONGLONG Temp;

    Temp = Value / Alignment;

    return Temp * Alignment;
}

ULONGLONG
AlignUp(
    IN ULONGLONG Value,
    IN ULONG Alignment)
{
    ULONGLONG Temp, Result;

    Temp = Value / Alignment;

    Result = Temp * Alignment;
    if (Value % Alignment)
        Result += Alignment;

    return Result;
}

ULONGLONG
RoundingDivide(
   IN ULONGLONG Dividend,
   IN ULONGLONG Divisor)
{
    return (Dividend + Divisor / 2) / Divisor;
}


static
VOID
GetDriverName(
    IN PDISKENTRY DiskEntry)
{
    RTL_QUERY_REGISTRY_TABLE QueryTable[2];
    WCHAR KeyName[32];
    NTSTATUS Status;

    RtlInitUnicodeString(&DiskEntry->DriverName, NULL);

    RtlStringCchPrintfW(KeyName, ARRAYSIZE(KeyName),
                        L"\\Scsi\\Scsi Port %hu",
                        DiskEntry->Port);

    RtlZeroMemory(&QueryTable, sizeof(QueryTable));

    QueryTable[0].Name = L"Driver";
    QueryTable[0].Flags = RTL_QUERY_REGISTRY_DIRECT;
    QueryTable[0].EntryContext = &DiskEntry->DriverName;

    /* This will allocate DiskEntry->DriverName if needed */
    Status = RtlQueryRegistryValues(RTL_REGISTRY_DEVICEMAP,
                                    KeyName,
                                    QueryTable,
                                    NULL,
                                    NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("RtlQueryRegistryValues() failed (Status %lx)\n", Status);
    }
}

static
VOID
AssignDriveLetters(
    IN PPARTLIST List)
{
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;
    PLIST_ENTRY Entry1;
    PLIST_ENTRY Entry2;
    WCHAR Letter;

    Letter = L'C';

    /* Assign drive letters to primary partitions */
    for (Entry1 = List->DiskListHead.Flink;
         Entry1 != &List->DiskListHead;
         Entry1 = Entry1->Flink)
    {
        DiskEntry = CONTAINING_RECORD(Entry1, DISKENTRY, ListEntry);

        for (Entry2 = DiskEntry->PrimaryPartListHead.Flink;
             Entry2 != &DiskEntry->PrimaryPartListHead;
             Entry2 = Entry2->Flink)
        {
            PartEntry = CONTAINING_RECORD(Entry2, PARTENTRY, ListEntry);

            PartEntry->DriveLetter = 0;

            if (PartEntry->IsPartitioned &&
                !IsContainerPartition(PartEntry->PartitionType))
            {
                if (IsRecognizedPartition(PartEntry->PartitionType) ||
                    (PartEntry->PartitionType == PARTITION_ENTRY_UNUSED &&
                     PartEntry->SectorCount.QuadPart != 0LL))
                {
                    if (Letter <= L'Z')
                    {
                        PartEntry->DriveLetter = Letter;
                        Letter++;
                    }
                }
            }
        }
    }

    /* Assign drive letters to logical drives */
    for (Entry1 = List->DiskListHead.Flink;
         Entry1 != &List->DiskListHead;
         Entry1 = Entry1->Flink)
    {
        DiskEntry = CONTAINING_RECORD(Entry1, DISKENTRY, ListEntry);

        for (Entry2 = DiskEntry->LogicalPartListHead.Flink;
             Entry2 != &DiskEntry->LogicalPartListHead;
             Entry2 = Entry2->Flink)
        {
            PartEntry = CONTAINING_RECORD(Entry2, PARTENTRY, ListEntry);

            PartEntry->DriveLetter = 0;

            if (PartEntry->IsPartitioned)
            {
                if (IsRecognizedPartition(PartEntry->PartitionType) ||
                    (PartEntry->PartitionType == PARTITION_ENTRY_UNUSED &&
                     PartEntry->SectorCount.QuadPart != 0LL))
                {
                    if (Letter <= L'Z')
                    {
                        PartEntry->DriveLetter = Letter;
                        Letter++;
                    }
                }
            }
        }
    }
}

static NTSTATUS
NTAPI
DiskIdentifierQueryRoutine(
    PWSTR ValueName,
    ULONG ValueType,
    PVOID ValueData,
    ULONG ValueLength,
    PVOID Context,
    PVOID EntryContext)
{
    PBIOSDISKENTRY BiosDiskEntry = (PBIOSDISKENTRY)Context;
    UNICODE_STRING NameU;

    if (ValueType == REG_SZ &&
        ValueLength == 20 * sizeof(WCHAR))
    {
        NameU.Buffer = (PWCHAR)ValueData;
        NameU.Length = NameU.MaximumLength = 8 * sizeof(WCHAR);
        RtlUnicodeStringToInteger(&NameU, 16, &BiosDiskEntry->Checksum);

        NameU.Buffer = (PWCHAR)ValueData + 9;
        RtlUnicodeStringToInteger(&NameU, 16, &BiosDiskEntry->Signature);

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}

static NTSTATUS
NTAPI
DiskConfigurationDataQueryRoutine(
    PWSTR ValueName,
    ULONG ValueType,
    PVOID ValueData,
    ULONG ValueLength,
    PVOID Context,
    PVOID EntryContext)
{
    PBIOSDISKENTRY BiosDiskEntry = (PBIOSDISKENTRY)Context;
    PCM_FULL_RESOURCE_DESCRIPTOR FullResourceDescriptor;
    PCM_DISK_GEOMETRY_DEVICE_DATA DiskGeometry;
    ULONG i;

    if (ValueType != REG_FULL_RESOURCE_DESCRIPTOR ||
        ValueLength < sizeof(CM_FULL_RESOURCE_DESCRIPTOR))
        return STATUS_UNSUCCESSFUL;

    FullResourceDescriptor = (PCM_FULL_RESOURCE_DESCRIPTOR)ValueData;

    /* Hm. Version and Revision are not set on Microsoft Windows XP... */
#if 0
    if (FullResourceDescriptor->PartialResourceList.Version != 1 ||
        FullResourceDescriptor->PartialResourceList.Revision != 1)
        return STATUS_UNSUCCESSFUL;
#endif

    for (i = 0; i < FullResourceDescriptor->PartialResourceList.Count; i++)
    {
        if (FullResourceDescriptor->PartialResourceList.PartialDescriptors[i].Type != CmResourceTypeDeviceSpecific ||
            FullResourceDescriptor->PartialResourceList.PartialDescriptors[i].u.DeviceSpecificData.DataSize != sizeof(CM_DISK_GEOMETRY_DEVICE_DATA))
            continue;

        DiskGeometry = (PCM_DISK_GEOMETRY_DEVICE_DATA)&FullResourceDescriptor->PartialResourceList.PartialDescriptors[i + 1];
        BiosDiskEntry->DiskGeometry = *DiskGeometry;

        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}

static NTSTATUS
NTAPI
SystemConfigurationDataQueryRoutine(
    PWSTR ValueName,
    ULONG ValueType,
    PVOID ValueData,
    ULONG ValueLength,
    PVOID Context,
    PVOID EntryContext)
{
    PCM_FULL_RESOURCE_DESCRIPTOR FullResourceDescriptor;
    PCM_INT13_DRIVE_PARAMETER* Int13Drives = (PCM_INT13_DRIVE_PARAMETER*)Context;
    ULONG i;

    if (ValueType != REG_FULL_RESOURCE_DESCRIPTOR ||
        ValueLength < sizeof(CM_FULL_RESOURCE_DESCRIPTOR))
        return STATUS_UNSUCCESSFUL;

    FullResourceDescriptor = (PCM_FULL_RESOURCE_DESCRIPTOR)ValueData;

    /* Hm. Version and Revision are not set on Microsoft Windows XP... */
#if 0
    if (FullResourceDescriptor->PartialResourceList.Version != 1 ||
        FullResourceDescriptor->PartialResourceList.Revision != 1)
        return STATUS_UNSUCCESSFUL;
#endif

    for (i = 0; i < FullResourceDescriptor->PartialResourceList.Count; i++)
    {
        if (FullResourceDescriptor->PartialResourceList.PartialDescriptors[i].Type != CmResourceTypeDeviceSpecific ||
            FullResourceDescriptor->PartialResourceList.PartialDescriptors[i].u.DeviceSpecificData.DataSize % sizeof(CM_INT13_DRIVE_PARAMETER) != 0)
            continue;

        *Int13Drives = (CM_INT13_DRIVE_PARAMETER*)RtlAllocateHeap(ProcessHeap, 0,
                       FullResourceDescriptor->PartialResourceList.PartialDescriptors[i].u.DeviceSpecificData.DataSize);
        if (*Int13Drives == NULL)
            return STATUS_NO_MEMORY;

        memcpy(*Int13Drives,
               &FullResourceDescriptor->PartialResourceList.PartialDescriptors[i + 1],
               FullResourceDescriptor->PartialResourceList.PartialDescriptors[i].u.DeviceSpecificData.DataSize);
        return STATUS_SUCCESS;
    }

    return STATUS_UNSUCCESSFUL;
}


static VOID
EnumerateBiosDiskEntries(
    IN PPARTLIST PartList)
{
    RTL_QUERY_REGISTRY_TABLE QueryTable[3];
    WCHAR Name[120];
    ULONG AdapterCount;
    ULONG DiskCount;
    NTSTATUS Status;
    PCM_INT13_DRIVE_PARAMETER Int13Drives;
    PBIOSDISKENTRY BiosDiskEntry;

#define ROOT_NAME   L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System\\MultifunctionAdapter"

    memset(QueryTable, 0, sizeof(QueryTable));

    QueryTable[1].Name = L"Configuration Data";
    QueryTable[1].QueryRoutine = SystemConfigurationDataQueryRoutine;
    Int13Drives = NULL;
    Status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE,
                                    L"\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System",
                                    &QueryTable[1],
                                    (PVOID)&Int13Drives,
                                    NULL);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Unable to query the 'Configuration Data' key in '\\Registry\\Machine\\HARDWARE\\DESCRIPTION\\System', status=%lx\n", Status);
        return;
    }

    AdapterCount = 0;
    while (TRUE)
    {
        RtlStringCchPrintfW(Name, ARRAYSIZE(Name),
                            L"%s\\%lu",
                            ROOT_NAME, AdapterCount);
        Status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE,
                                        Name,
                                        &QueryTable[2],
                                        NULL,
                                        NULL);
        if (!NT_SUCCESS(Status))
        {
            break;
        }

        RtlStringCchPrintfW(Name, ARRAYSIZE(Name),
                            L"%s\\%lu\\DiskController",
                            ROOT_NAME, AdapterCount);
        Status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE,
                                        Name,
                                        &QueryTable[2],
                                        NULL,
                                        NULL);
        if (NT_SUCCESS(Status))
        {
            while (TRUE)
            {
                RtlStringCchPrintfW(Name, ARRAYSIZE(Name),
                                    L"%s\\%lu\\DiskController\\0",
                                    ROOT_NAME, AdapterCount);
                Status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE,
                                                Name,
                                                &QueryTable[2],
                                                NULL,
                                                NULL);
                if (!NT_SUCCESS(Status))
                {
                    RtlFreeHeap(ProcessHeap, 0, Int13Drives);
                    return;
                }

                RtlStringCchPrintfW(Name, ARRAYSIZE(Name),
                                    L"%s\\%lu\\DiskController\\0\\DiskPeripheral",
                                    ROOT_NAME, AdapterCount);
                Status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE,
                                                Name,
                                                &QueryTable[2],
                                                NULL,
                                                NULL);
                if (NT_SUCCESS(Status))
                {
                    QueryTable[0].Name = L"Identifier";
                    QueryTable[0].QueryRoutine = DiskIdentifierQueryRoutine;
                    QueryTable[1].Name = L"Configuration Data";
                    QueryTable[1].QueryRoutine = DiskConfigurationDataQueryRoutine;

                    DiskCount = 0;
                    while (TRUE)
                    {
                        BiosDiskEntry = (BIOSDISKENTRY*)RtlAllocateHeap(ProcessHeap, HEAP_ZERO_MEMORY, sizeof(BIOSDISKENTRY));
                        if (BiosDiskEntry == NULL)
                        {
                            break;
                        }

                        RtlStringCchPrintfW(Name, ARRAYSIZE(Name),
                                            L"%s\\%lu\\DiskController\\0\\DiskPeripheral\\%lu",
                                            ROOT_NAME, AdapterCount, DiskCount);
                        Status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE,
                                                        Name,
                                                        QueryTable,
                                                        (PVOID)BiosDiskEntry,
                                                        NULL);
                        if (!NT_SUCCESS(Status))
                        {
                            RtlFreeHeap(ProcessHeap, 0, BiosDiskEntry);
                            break;
                        }

                        BiosDiskEntry->DiskNumber = DiskCount;
                        BiosDiskEntry->Recognized = FALSE;

                        if (DiskCount < Int13Drives[0].NumberDrives)
                        {
                            BiosDiskEntry->Int13DiskData = Int13Drives[DiskCount];
                        }
                        else
                        {
                            DPRINT1("Didn't find int13 drive datas for disk %u\n", DiskCount);
                        }

                        InsertTailList(&PartList->BiosDiskListHead, &BiosDiskEntry->ListEntry);

                        DPRINT("DiskNumber:        %lu\n", BiosDiskEntry->DiskNumber);
                        DPRINT("Signature:         %08lx\n", BiosDiskEntry->Signature);
                        DPRINT("Checksum:          %08lx\n", BiosDiskEntry->Checksum);
                        DPRINT("BytesPerSector:    %lu\n", BiosDiskEntry->DiskGeometry.BytesPerSector);
                        DPRINT("NumberOfCylinders: %lu\n", BiosDiskEntry->DiskGeometry.NumberOfCylinders);
                        DPRINT("NumberOfHeads:     %lu\n", BiosDiskEntry->DiskGeometry.NumberOfHeads);
                        DPRINT("DriveSelect:       %02x\n", BiosDiskEntry->Int13DiskData.DriveSelect);
                        DPRINT("MaxCylinders:      %lu\n", BiosDiskEntry->Int13DiskData.MaxCylinders);
                        DPRINT("SectorsPerTrack:   %d\n", BiosDiskEntry->Int13DiskData.SectorsPerTrack);
                        DPRINT("MaxHeads:          %d\n", BiosDiskEntry->Int13DiskData.MaxHeads);
                        DPRINT("NumberDrives:      %d\n", BiosDiskEntry->Int13DiskData.NumberDrives);

                        DiskCount++;
                    }
                }

                RtlFreeHeap(ProcessHeap, 0, Int13Drives);
                return;
            }
        }

        AdapterCount++;
    }

    RtlFreeHeap(ProcessHeap, 0, Int13Drives);

#undef ROOT_NAME
}



/*
 * Inserts the disk region represented by PartEntry into either the primary
 * or the logical partition list of the given disk.
 * The lists are kept sorted by increasing order of start sectors.
 * Of course no disk region should overlap at all with one another.
 */
static
VOID
InsertDiskRegion(
    IN PDISKENTRY DiskEntry,
    IN PPARTENTRY PartEntry,
    IN BOOLEAN LogicalPartition)
{
    PLIST_ENTRY List;
    PLIST_ENTRY Entry;
    PPARTENTRY PartEntry2;

    /* Use the correct partition list */
    if (LogicalPartition)
        List = &DiskEntry->LogicalPartListHead;
    else
        List = &DiskEntry->PrimaryPartListHead;

    /* Find the first disk region before which we need to insert the new one */
    for (Entry = List->Flink; Entry != List; Entry = Entry->Flink)
    {
        PartEntry2 = CONTAINING_RECORD(Entry, PARTENTRY, ListEntry);

        /* Ignore any unused empty region */
        if ((PartEntry2->PartitionType == PARTITION_ENTRY_UNUSED &&
             PartEntry2->StartSector.QuadPart == 0) || PartEntry2->SectorCount.QuadPart == 0)
        {
            continue;
        }

        /* If the current region ends before the one to be inserted, try again */
        if (PartEntry2->StartSector.QuadPart + PartEntry2->SectorCount.QuadPart - 1 < PartEntry->StartSector.QuadPart)
            continue;

        /*
         * One of the disk region boundaries crosses the desired region
         * (it starts after the desired region, or ends before the end
         * of the desired region): this is an impossible situation because
         * disk regions (partitions) cannot overlap!
         * Throw an error and bail out.
         */
        if (max(PartEntry->StartSector.QuadPart, PartEntry2->StartSector.QuadPart)
            <=
            min( PartEntry->StartSector.QuadPart +  PartEntry->SectorCount.QuadPart - 1,
                PartEntry2->StartSector.QuadPart + PartEntry2->SectorCount.QuadPart - 1))
        {
            DPRINT1("Disk region overlap problem, stopping there!\n"
                    "Partition to be inserted:\n"
                    "    StartSector = %I64u ; EndSector = %I64u\n"
                    "Existing disk region:\n"
                    "    StartSector = %I64u ; EndSector = %I64u\n",
                     PartEntry->StartSector.QuadPart,
                     PartEntry->StartSector.QuadPart +  PartEntry->SectorCount.QuadPart - 1,
                    PartEntry2->StartSector.QuadPart,
                    PartEntry2->StartSector.QuadPart + PartEntry2->SectorCount.QuadPart - 1);
            return;
        }

        /* We have found the first region before which the new one has to be inserted */
        break;
    }

    /* Insert the disk region */
    InsertTailList(Entry, &PartEntry->ListEntry);
}

static
PPARTENTRY
CreateInsertBlankRegion(
    IN PDISKENTRY DiskEntry,
    IN OUT PLIST_ENTRY ListHead,
    IN ULONGLONG StartSector,
    IN ULONGLONG SectorCount,
    IN BOOLEAN LogicalSpace)
{
    PPARTENTRY NewPartEntry;

    NewPartEntry = RtlAllocateHeap(ProcessHeap,
                                   HEAP_ZERO_MEMORY,
                                   sizeof(PARTENTRY));
    if (NewPartEntry == NULL)
        return NULL;

    NewPartEntry->DiskEntry = DiskEntry;

    NewPartEntry->IsPartitioned = FALSE;
    NewPartEntry->FormatState = Unformatted;
    NewPartEntry->FileSystem  = NULL;

    NewPartEntry->StartSector.QuadPart = StartSector;
    NewPartEntry->SectorCount.QuadPart = SectorCount;

    DPRINT1("First Sector : %I64u\n", NewPartEntry->StartSector.QuadPart);
    DPRINT1("Last Sector  : %I64u\n", NewPartEntry->StartSector.QuadPart + NewPartEntry->SectorCount.QuadPart - 1);
    DPRINT1("Total Sectors: %I64u\n", NewPartEntry->SectorCount.QuadPart);

    /* Insert the table into the list */
    InsertTailList(ListHead, &NewPartEntry->ListEntry);

    return NewPartEntry;
}

static
// BOOLEAN
PPARTENTRY
InitializePartitionEntry(
    IN PDISKENTRY DiskEntry,
    IN PPARTENTRY PartEntry,
    IN ULONGLONG SectorCount,
    IN BOOLEAN AutoCreate)
{
    PPARTENTRY NewPartEntry;

    DPRINT1("Current partition sector count: %I64u\n", PartEntry->SectorCount.QuadPart);

    if ((AutoCreate != FALSE) ||
        (AlignDown(PartEntry->StartSector.QuadPart + SectorCount, DiskEntry->SectorAlignment) -
                   PartEntry->StartSector.QuadPart == PartEntry->SectorCount.QuadPart))
    {
        DPRINT1("Convert existing partition entry\n");

        /* Convert current entry to 'new (unformatted)' */
        PartEntry->IsPartitioned = TRUE;
        PartEntry->New = TRUE;
        PartEntry->PartitionType = PARTITION_ENTRY_UNUSED;
        PartEntry->FormatState = Unformatted;
        PartEntry->FileSystem  = NULL;
        PartEntry->AutoCreate = AutoCreate;
        PartEntry->BootIndicator = FALSE;
        PartEntry->LogicalPartition = FALSE;

        NewPartEntry = PartEntry;
    }
    else
    {
        DPRINT1("Add new partition entry\n");

        /* Insert and initialize a new partition entry */
        NewPartEntry = RtlAllocateHeap(ProcessHeap,
                                       HEAP_ZERO_MEMORY,
                                       sizeof(PARTENTRY));
        if (NewPartEntry == NULL)
            return NULL;

        /* Insert the new entry into the list */
        InsertTailList(&PartEntry->ListEntry,
                       &NewPartEntry->ListEntry);

        NewPartEntry->DiskEntry = DiskEntry;

        NewPartEntry->IsPartitioned = TRUE;
        NewPartEntry->New = TRUE;
        NewPartEntry->PartitionType = PARTITION_ENTRY_UNUSED;
        NewPartEntry->FormatState = Unformatted;
        NewPartEntry->FileSystem  = NULL;
        NewPartEntry->BootIndicator = FALSE;
        NewPartEntry->LogicalPartition = FALSE;

        NewPartEntry->StartSector.QuadPart = PartEntry->StartSector.QuadPart;
        NewPartEntry->SectorCount.QuadPart = AlignDown(NewPartEntry->StartSector.QuadPart + SectorCount, DiskEntry->SectorAlignment) -
                                             NewPartEntry->StartSector.QuadPart;

        PartEntry->StartSector.QuadPart = NewPartEntry->StartSector.QuadPart + NewPartEntry->SectorCount.QuadPart;
        PartEntry->SectorCount.QuadPart -= (PartEntry->StartSector.QuadPart - NewPartEntry->StartSector.QuadPart);
    }

    DPRINT1("First Sector : %I64u\n", NewPartEntry->StartSector.QuadPart);
    DPRINT1("Last Sector  : %I64u\n", NewPartEntry->StartSector.QuadPart + NewPartEntry->SectorCount.QuadPart - 1);
    DPRINT1("Total Sectors: %I64u\n", NewPartEntry->SectorCount.QuadPart);

    return NewPartEntry;
}


static
VOID
AddPartitionToDisk(
    IN ULONG DiskNumber,
    IN PDISKENTRY DiskEntry,
    IN ULONG PartitionIndex,
    IN BOOLEAN LogicalPartition)
{
    NTSTATUS Status;
    PPARTITION_INFORMATION PartitionInfo;
    PPARTENTRY PartEntry;
    HANDLE FileHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    WCHAR Buffer[MAX_PATH];
    UNICODE_STRING Name;
    UCHAR LabelBuffer[sizeof(FILE_FS_VOLUME_INFORMATION) + 256 * sizeof(WCHAR)];
    PFILE_FS_VOLUME_INFORMATION LabelInfo = (PFILE_FS_VOLUME_INFORMATION)LabelBuffer;

    PartitionInfo = &DiskEntry->LayoutBuffer->PartitionEntry[PartitionIndex];

    if (PartitionInfo->PartitionType == PARTITION_ENTRY_UNUSED ||
        ((LogicalPartition != FALSE) && IsContainerPartition(PartitionInfo->PartitionType)))
    {
        return;
    }

    PartEntry = RtlAllocateHeap(ProcessHeap,
                                HEAP_ZERO_MEMORY,
                                sizeof(PARTENTRY));
    if (PartEntry == NULL)
        return;

    PartEntry->DiskEntry = DiskEntry;

    PartEntry->StartSector.QuadPart = (ULONGLONG)PartitionInfo->StartingOffset.QuadPart / DiskEntry->BytesPerSector;
    PartEntry->SectorCount.QuadPart = (ULONGLONG)PartitionInfo->PartitionLength.QuadPart / DiskEntry->BytesPerSector;

    PartEntry->BootIndicator = PartitionInfo->BootIndicator;
    PartEntry->PartitionType = PartitionInfo->PartitionType;
    PartEntry->HiddenSectors = PartitionInfo->HiddenSectors;

    PartEntry->LogicalPartition = LogicalPartition;
    PartEntry->IsPartitioned = TRUE;
    PartEntry->OnDiskPartitionNumber = PartitionInfo->PartitionNumber;
    PartEntry->PartitionNumber = PartitionInfo->PartitionNumber;
    PartEntry->PartitionIndex = PartitionIndex;

    if (IsContainerPartition(PartEntry->PartitionType))
    {
        PartEntry->FormatState = Unformatted;
        PartEntry->FileSystem  = NULL;

        if (LogicalPartition == FALSE && DiskEntry->ExtendedPartition == NULL)
            DiskEntry->ExtendedPartition = PartEntry;
    }
    else if (IsRecognizedPartition(PartEntry->PartitionType))
    {
        ASSERT(PartitionInfo->RecognizedPartition);

        PartEntry->FileSystem = GetFileSystem(PartEntry);
        if (PartEntry->FileSystem)
            PartEntry->FormatState = Preformatted;
        else
            PartEntry->FormatState = Unformatted;
        // PartEntry->FormatState = UnknownFormat;
    }
    else
    {
        /* Unknown partition, hence unknown partition format (may or may not be actually formatted) */
        PartEntry->FormatState = UnknownFormat;
    }

    /* Initialize the partition volume label */
    RtlZeroMemory(PartEntry->VolumeLabel, sizeof(PartEntry->VolumeLabel));

    /* Open the volume, ignore any errors */
    RtlStringCchPrintfW(Buffer, ARRAYSIZE(Buffer),
                        L"\\Device\\Harddisk%lu\\Partition%lu",
                        DiskEntry->DiskNumber,
                        PartEntry->PartitionNumber);
    RtlInitUnicodeString(&Name, Buffer);

    InitializeObjectAttributes(&ObjectAttributes,
                               &Name,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    Status = NtOpenFile(&FileHandle,
                        FILE_READ_DATA | SYNCHRONIZE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    if (NT_SUCCESS(Status))
    {
        /* Retrieve the partition volume label */
        Status = NtQueryVolumeInformationFile(FileHandle,
                                              &IoStatusBlock,
                                              &LabelBuffer,
                                              sizeof(LabelBuffer),
                                              FileFsVolumeInformation);
        /* Close the handle */
        NtClose(FileHandle);

        /* Check for success */
        if (NT_SUCCESS(Status))
        {
            /* Copy the (possibly truncated) volume label and NULL-terminate it */
            RtlStringCbCopyNW(PartEntry->VolumeLabel, sizeof(PartEntry->VolumeLabel),
                              LabelInfo->VolumeLabel, LabelInfo->VolumeLabelLength);
        }
        else
        {
            DPRINT1("NtQueryVolumeInformationFile() failed, Status 0x%08lx\n", Status);
        }
    }
    else
    {
        DPRINT1("NtOpenFile() failed, Status 0x%08lx\n", Status);
    }

    InsertDiskRegion(DiskEntry, PartEntry, LogicalPartition);
}

static
VOID
ScanForUnpartitionedDiskSpace(
    IN PDISKENTRY DiskEntry)
{
    ULONGLONG StartSector;
    ULONGLONG SectorCount;
    ULONGLONG LastStartSector;
    ULONGLONG LastSectorCount;
    ULONGLONG LastUnusedSectorCount;
    PPARTENTRY PartEntry;
    PPARTENTRY NewPartEntry;
    PLIST_ENTRY Entry;

    DPRINT("ScanForUnpartitionedDiskSpace()\n");

    if (IsListEmpty(&DiskEntry->PrimaryPartListHead))
    {
        DPRINT1("No primary partition!\n");

        /* Create a partition entry that represents the empty disk */

        if (DiskEntry->SectorAlignment < 2048)
            StartSector = 2048ULL;
        else
            StartSector = (ULONGLONG)DiskEntry->SectorAlignment;
        SectorCount = AlignDown(DiskEntry->SectorCount.QuadPart, DiskEntry->SectorAlignment) - StartSector;

        NewPartEntry = CreateInsertBlankRegion(DiskEntry,
                                               &DiskEntry->PrimaryPartListHead,
                                               StartSector,
                                               SectorCount,
                                               FALSE);
        if (NewPartEntry == NULL)
            DPRINT1("Failed to create a new empty region for full disk space!\n");

        return;
    }

    /* Start partition at head 1, cylinder 0 */
    if (DiskEntry->SectorAlignment < 2048)
        LastStartSector = 2048ULL;
    else
        LastStartSector = (ULONGLONG)DiskEntry->SectorAlignment;
    LastSectorCount = 0ULL;
    LastUnusedSectorCount = 0ULL;

    for (Entry = DiskEntry->PrimaryPartListHead.Flink;
         Entry != &DiskEntry->PrimaryPartListHead;
         Entry = Entry->Flink)
    {
        PartEntry = CONTAINING_RECORD(Entry, PARTENTRY, ListEntry);

        if (PartEntry->PartitionType != PARTITION_ENTRY_UNUSED ||
            PartEntry->SectorCount.QuadPart != 0ULL)
        {
            LastUnusedSectorCount =
                PartEntry->StartSector.QuadPart - (LastStartSector + LastSectorCount);

            if (PartEntry->StartSector.QuadPart > (LastStartSector + LastSectorCount) &&
                LastUnusedSectorCount >= (ULONGLONG)DiskEntry->SectorAlignment)
            {
                DPRINT("Unpartitioned disk space %I64u sectors\n", LastUnusedSectorCount);

                StartSector = LastStartSector + LastSectorCount;
                SectorCount = AlignDown(StartSector + LastUnusedSectorCount, DiskEntry->SectorAlignment) - StartSector;

                /* Insert the table into the list */
                NewPartEntry = CreateInsertBlankRegion(DiskEntry,
                                                       &PartEntry->ListEntry,
                                                       StartSector,
                                                       SectorCount,
                                                       FALSE);
                if (NewPartEntry == NULL)
                {
                    DPRINT1("Failed to create a new empty region for disk space!\n");
                    return;
                }
            }

            LastStartSector = PartEntry->StartSector.QuadPart;
            LastSectorCount = PartEntry->SectorCount.QuadPart;
        }
    }

    /* Check for trailing unpartitioned disk space */
    if ((LastStartSector + LastSectorCount) < DiskEntry->SectorCount.QuadPart)
    {
        LastUnusedSectorCount = AlignDown(DiskEntry->SectorCount.QuadPart - (LastStartSector + LastSectorCount), DiskEntry->SectorAlignment);

        if (LastUnusedSectorCount >= (ULONGLONG)DiskEntry->SectorAlignment)
        {
            DPRINT("Unpartitioned disk space: %I64u sectors\n", LastUnusedSectorCount);

            StartSector = LastStartSector + LastSectorCount;
            SectorCount = AlignDown(StartSector + LastUnusedSectorCount, DiskEntry->SectorAlignment) - StartSector;

            /* Append the table to the list */
            NewPartEntry = CreateInsertBlankRegion(DiskEntry,
                                                   &DiskEntry->PrimaryPartListHead,
                                                   StartSector,
                                                   SectorCount,
                                                   FALSE);
            if (NewPartEntry == NULL)
            {
                DPRINT1("Failed to create a new empty region for trailing disk space!\n");
                return;
            }
        }
    }

    if (DiskEntry->ExtendedPartition != NULL)
    {
        if (IsListEmpty(&DiskEntry->LogicalPartListHead))
        {
            DPRINT1("No logical partition!\n");

            /* Create a partition entry that represents the empty extended partition */

            StartSector = DiskEntry->ExtendedPartition->StartSector.QuadPart + (ULONGLONG)DiskEntry->SectorAlignment;
            SectorCount = DiskEntry->ExtendedPartition->SectorCount.QuadPart - (ULONGLONG)DiskEntry->SectorAlignment;

            NewPartEntry = CreateInsertBlankRegion(DiskEntry,
                                                   &DiskEntry->LogicalPartListHead,
                                                   StartSector,
                                                   SectorCount,
                                                   TRUE);
            if (NewPartEntry == NULL)
            {
                DPRINT1("Failed to create a new empty region for full extended partition space!\n");
                return;
            }
            NewPartEntry->LogicalPartition = TRUE;

            return;
        }

        /* Start partition at head 1, cylinder 0 */
        LastStartSector = DiskEntry->ExtendedPartition->StartSector.QuadPart + (ULONGLONG)DiskEntry->SectorAlignment;
        LastSectorCount = 0ULL;
        LastUnusedSectorCount = 0ULL;

        for (Entry = DiskEntry->LogicalPartListHead.Flink;
             Entry != &DiskEntry->LogicalPartListHead;
             Entry = Entry->Flink)
        {
            PartEntry = CONTAINING_RECORD(Entry, PARTENTRY, ListEntry);

            if (PartEntry->PartitionType != PARTITION_ENTRY_UNUSED ||
                PartEntry->SectorCount.QuadPart != 0ULL)
            {
                LastUnusedSectorCount =
                    PartEntry->StartSector.QuadPart - (ULONGLONG)DiskEntry->SectorAlignment - (LastStartSector + LastSectorCount);

                if ((PartEntry->StartSector.QuadPart - (ULONGLONG)DiskEntry->SectorAlignment) > (LastStartSector + LastSectorCount) &&
                    LastUnusedSectorCount >= (ULONGLONG)DiskEntry->SectorAlignment)
                {
                    DPRINT("Unpartitioned disk space %I64u sectors\n", LastUnusedSectorCount);

                    StartSector = LastStartSector + LastSectorCount;
                    SectorCount = AlignDown(StartSector + LastUnusedSectorCount, DiskEntry->SectorAlignment) - StartSector;

                    /* Insert the table into the list */
                    NewPartEntry = CreateInsertBlankRegion(DiskEntry,
                                                           &PartEntry->ListEntry,
                                                           StartSector,
                                                           SectorCount,
                                                           TRUE);
                    if (NewPartEntry == NULL)
                    {
                        DPRINT1("Failed to create a new empty region for extended partition space!\n");
                        return;
                    }
                    NewPartEntry->LogicalPartition = TRUE;
                }

                LastStartSector = PartEntry->StartSector.QuadPart;
                LastSectorCount = PartEntry->SectorCount.QuadPart;
            }
        }

        /* Check for trailing unpartitioned disk space */
        if ((LastStartSector + LastSectorCount) < DiskEntry->ExtendedPartition->StartSector.QuadPart + DiskEntry->ExtendedPartition->SectorCount.QuadPart)
        {
            LastUnusedSectorCount = AlignDown(DiskEntry->ExtendedPartition->StartSector.QuadPart +
                                              DiskEntry->ExtendedPartition->SectorCount.QuadPart - (LastStartSector + LastSectorCount),
                                              DiskEntry->SectorAlignment);

            if (LastUnusedSectorCount >= (ULONGLONG)DiskEntry->SectorAlignment)
            {
                DPRINT("Unpartitioned disk space: %I64u sectors\n", LastUnusedSectorCount);

                StartSector = LastStartSector + LastSectorCount;
                SectorCount = AlignDown(StartSector + LastUnusedSectorCount, DiskEntry->SectorAlignment) - StartSector;

                /* Append the table to the list */
                NewPartEntry = CreateInsertBlankRegion(DiskEntry,
                                                       &DiskEntry->LogicalPartListHead,
                                                       StartSector,
                                                       SectorCount,
                                                       TRUE);
                if (NewPartEntry == NULL)
                {
                    DPRINT1("Failed to create a new empty region for extended partition space!\n");
                    return;
                }
                NewPartEntry->LogicalPartition = TRUE;
            }
        }
    }

    DPRINT("ScanForUnpartitionedDiskSpace() done\n");
}

static
VOID
SetDiskSignature(
    IN PPARTLIST List,
    IN PDISKENTRY DiskEntry)
{
    LARGE_INTEGER SystemTime;
    TIME_FIELDS TimeFields;
    PLIST_ENTRY Entry2;
    PDISKENTRY DiskEntry2;
    PUCHAR Buffer;

    if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
    {
        DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
        return;
    }

    Buffer = (PUCHAR)&DiskEntry->LayoutBuffer->Signature;

    while (TRUE)
    {
        NtQuerySystemTime(&SystemTime);
        RtlTimeToTimeFields(&SystemTime, &TimeFields);

        Buffer[0] = (UCHAR)(TimeFields.Year & 0xFF) + (UCHAR)(TimeFields.Hour & 0xFF);
        Buffer[1] = (UCHAR)(TimeFields.Year >> 8) + (UCHAR)(TimeFields.Minute & 0xFF);
        Buffer[2] = (UCHAR)(TimeFields.Month & 0xFF) + (UCHAR)(TimeFields.Second & 0xFF);
        Buffer[3] = (UCHAR)(TimeFields.Day & 0xFF) + (UCHAR)(TimeFields.Milliseconds & 0xFF);

        if (DiskEntry->LayoutBuffer->Signature == 0)
        {
            continue;
        }

        /* Check if the signature already exist */
        /* FIXME:
         *   Check also signatures from disks, which are
         *   not visible (bootable) by the bios.
         */
        for (Entry2 = List->DiskListHead.Flink;
             Entry2 != &List->DiskListHead;
             Entry2 = Entry2->Flink)
        {
            DiskEntry2 = CONTAINING_RECORD(Entry2, DISKENTRY, ListEntry);

            if (DiskEntry2->DiskStyle == PARTITION_STYLE_GPT)
            {
                DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
                continue;
            }

            if (DiskEntry != DiskEntry2 &&
                DiskEntry->LayoutBuffer->Signature == DiskEntry2->LayoutBuffer->Signature)
                break;
        }

        if (Entry2 == &List->DiskListHead)
            break;
    }
}

static
VOID
UpdateDiskSignatures(
    IN PPARTLIST List)
{
    PLIST_ENTRY Entry;
    PDISKENTRY DiskEntry;

    /* Update each disk */
    for (Entry = List->DiskListHead.Flink;
         Entry != &List->DiskListHead;
         Entry = Entry->Flink)
    {
        DiskEntry = CONTAINING_RECORD(Entry, DISKENTRY, ListEntry);

        if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
        {
            DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
            continue;
        }

        if (DiskEntry->LayoutBuffer &&
            DiskEntry->LayoutBuffer->Signature == 0)
        {
            SetDiskSignature(List, DiskEntry);
            DiskEntry->LayoutBuffer->PartitionEntry[0].RewritePartition = TRUE;
        }
    }
}

static
VOID
AddDiskToList(
    IN HANDLE FileHandle,
    IN ULONG DiskNumber,
    IN PPARTLIST List)
{
    DISK_GEOMETRY DiskGeometry;
    SCSI_ADDRESS ScsiAddress;
    PDISKENTRY DiskEntry;
    IO_STATUS_BLOCK Iosb;
    NTSTATUS Status;
    PPARTITION_SECTOR Mbr;
    PULONG Buffer;
    LARGE_INTEGER FileOffset;
    WCHAR Identifier[20];
    ULONG Checksum;
    ULONG Signature;
    ULONG i;
    PLIST_ENTRY ListEntry;
    PBIOSDISKENTRY BiosDiskEntry;
    ULONG LayoutBufferSize;
    PDRIVE_LAYOUT_INFORMATION NewLayoutBuffer;

    /* Retrieve the drive geometry */
    Status = NtDeviceIoControlFile(FileHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &Iosb,
                                   IOCTL_DISK_GET_DRIVE_GEOMETRY,
                                   NULL,
                                   0,
                                   &DiskGeometry,
                                   sizeof(DiskGeometry));
    if (!NT_SUCCESS(Status))
        return;

    if (DiskGeometry.MediaType != FixedMedia &&
        DiskGeometry.MediaType != RemovableMedia)
    {
        return;
    }

    /*
     * FIXME: Here we suppose the disk is always SCSI. What if it is
     * of another type? To check this we need to retrieve the name of
     * the driver the disk device belongs to.
     */
    Status = NtDeviceIoControlFile(FileHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &Iosb,
                                   IOCTL_SCSI_GET_ADDRESS,
                                   NULL,
                                   0,
                                   &ScsiAddress,
                                   sizeof(ScsiAddress));
    if (!NT_SUCCESS(Status))
        return;

    /*
     * Check whether the disk is initialized, by looking at its MBR.
     * NOTE that this must be generalized to GPT disks as well!
     */

    Mbr = (PARTITION_SECTOR*)RtlAllocateHeap(ProcessHeap,
                                             0,
                                             DiskGeometry.BytesPerSector);
    if (Mbr == NULL)
        return;

    FileOffset.QuadPart = 0;
    Status = NtReadFile(FileHandle,
                        NULL,
                        NULL,
                        NULL,
                        &Iosb,
                        (PVOID)Mbr,
                        DiskGeometry.BytesPerSector,
                        &FileOffset,
                        NULL);
    if (!NT_SUCCESS(Status))
    {
        RtlFreeHeap(ProcessHeap, 0, Mbr);
        DPRINT1("NtReadFile failed, status=%x\n", Status);
        return;
    }
    Signature = Mbr->Signature;

    /* Calculate the MBR checksum */
    Checksum = 0;
    Buffer = (PULONG)Mbr;
    for (i = 0; i < 128; i++)
    {
        Checksum += Buffer[i];
    }
    Checksum = ~Checksum + 1;

    RtlStringCchPrintfW(Identifier, ARRAYSIZE(Identifier),
                        L"%08x-%08x-A", Checksum, Signature);
    DPRINT("Identifier: %S\n", Identifier);

    DiskEntry = RtlAllocateHeap(ProcessHeap,
                                HEAP_ZERO_MEMORY,
                                sizeof(DISKENTRY));
    if (DiskEntry == NULL)
    {
        RtlFreeHeap(ProcessHeap, 0, Mbr);
        DPRINT1("Failed to allocate a new disk entry.\n");
        return;
    }

//    DiskEntry->Checksum = Checksum;
//    DiskEntry->Signature = Signature;
    DiskEntry->BiosFound = FALSE;

    /*
     * Check if this disk has a valid MBR: verify its signature,
     * and whether its two first bytes are a valid instruction
     * (related to this, see IsThereAValidBootSector() in partlist.c).
     *
     * See also ntoskrnl/fstub/fstubex.c!FstubDetectPartitionStyle().
     */

    // DiskEntry->NoMbr = (Mbr->Magic != PARTITION_MAGIC || (*(PUSHORT)Mbr->BootCode) == 0x0000);

    /* If we have not the 0xAA55 then it's raw partition */
    if (Mbr->Magic != PARTITION_MAGIC)
    {
        DiskEntry->DiskStyle = PARTITION_STYLE_RAW;
    }
    /* Check partitions types: if first is 0xEE and all the others 0, we have GPT */
    else if (Mbr->Partition[0].PartitionType == EFI_PMBR_OSTYPE_EFI &&
             Mbr->Partition[1].PartitionType == 0 &&
             Mbr->Partition[2].PartitionType == 0 &&
             Mbr->Partition[3].PartitionType == 0)
    {
        DiskEntry->DiskStyle = PARTITION_STYLE_GPT;
    }
    /* Otherwise, partition table is in MBR */
    else
    {
        DiskEntry->DiskStyle = PARTITION_STYLE_MBR;
    }

    /* Free the MBR sector buffer */
    RtlFreeHeap(ProcessHeap, 0, Mbr);


    for (ListEntry = List->BiosDiskListHead.Flink;
         ListEntry != &List->BiosDiskListHead;
         ListEntry = ListEntry->Flink)
    {
        BiosDiskEntry = CONTAINING_RECORD(ListEntry, BIOSDISKENTRY, ListEntry);
        /* FIXME:
         *   Compare the size from bios and the reported size from driver.
         *   If we have more than one disk with a zero or with the same signature
         *   we must create new signatures and reboot. After the reboot,
         *   it is possible to identify the disks.
         */
        if (BiosDiskEntry->Signature == Signature &&
            BiosDiskEntry->Checksum == Checksum &&
            !BiosDiskEntry->Recognized)
        {
            if (!DiskEntry->BiosFound)
            {
                DiskEntry->BiosDiskNumber = BiosDiskEntry->DiskNumber;
                DiskEntry->BiosFound = TRUE;
                BiosDiskEntry->Recognized = TRUE;
            }
            else
            {
                // FIXME: What to do?
            }
        }
    }

    if (!DiskEntry->BiosFound)
    {
#if 0
        RtlFreeHeap(ProcessHeap, 0, DiskEntry);
        return;
#else
        DPRINT1("WARNING: Setup could not find a matching BIOS disk entry. Disk %d is not be bootable by the BIOS!\n", DiskNumber);
#endif
    }

    InitializeListHead(&DiskEntry->PrimaryPartListHead);
    InitializeListHead(&DiskEntry->LogicalPartListHead);

    DiskEntry->Cylinders = DiskGeometry.Cylinders.QuadPart;
    DiskEntry->TracksPerCylinder = DiskGeometry.TracksPerCylinder;
    DiskEntry->SectorsPerTrack = DiskGeometry.SectorsPerTrack;
    DiskEntry->BytesPerSector = DiskGeometry.BytesPerSector;

    DPRINT("Cylinders %I64u\n", DiskEntry->Cylinders);
    DPRINT("TracksPerCylinder %lu\n", DiskEntry->TracksPerCylinder);
    DPRINT("SectorsPerTrack %lu\n", DiskEntry->SectorsPerTrack);
    DPRINT("BytesPerSector %lu\n", DiskEntry->BytesPerSector);

    DiskEntry->SectorCount.QuadPart = DiskGeometry.Cylinders.QuadPart *
                                      (ULONGLONG)DiskGeometry.TracksPerCylinder *
                                      (ULONGLONG)DiskGeometry.SectorsPerTrack;

    DiskEntry->SectorAlignment = DiskGeometry.SectorsPerTrack;
    DiskEntry->CylinderAlignment = DiskGeometry.TracksPerCylinder *
                                   DiskGeometry.SectorsPerTrack;

    DPRINT("SectorCount %I64u\n", DiskEntry->SectorCount.QuadPart);
    DPRINT("SectorAlignment %lu\n", DiskEntry->SectorAlignment);

    DiskEntry->DiskNumber = DiskNumber;
    DiskEntry->Port = ScsiAddress.PortNumber;
    DiskEntry->Bus = ScsiAddress.PathId;
    DiskEntry->Id = ScsiAddress.TargetId;

    GetDriverName(DiskEntry);
    /*
     * Actually it would be more correct somehow to use:
     *
     * OBJECT_NAME_INFORMATION NameInfo; // ObjectNameInfo;
     * ULONG ReturnedLength;
     *
     * Status = NtQueryObject(SomeHandleToTheDisk,
     *                        ObjectNameInformation,
     *                        &NameInfo,
     *                        sizeof(NameInfo),
     *                        &ReturnedLength);
     * etc...
     *
     * See examples in https://git.reactos.org/?p=reactos.git;a=blob;f=reactos/ntoskrnl/io/iomgr/error.c;hb=2f3a93ee9cec8322a86bf74b356f1ad83fc912dc#l267
     */

    InsertAscendingList(&List->DiskListHead, DiskEntry, DISKENTRY, ListEntry, DiskNumber);


    /*
     * We now retrieve the disk partition layout
     */

    /*
     * Stop there now if the disk is GPT-partitioned,
     * since we currently do not support such disks.
     */
    if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
    {
        DPRINT1("GPT-partitioned disk detected, not currently supported by SETUP!\n");
        return;
    }

    /* Allocate a layout buffer with 4 partition entries first */
    LayoutBufferSize = sizeof(DRIVE_LAYOUT_INFORMATION) +
                       ((4 - ANYSIZE_ARRAY) * sizeof(PARTITION_INFORMATION));
    DiskEntry->LayoutBuffer = RtlAllocateHeap(ProcessHeap,
                                              HEAP_ZERO_MEMORY,
                                              LayoutBufferSize);
    if (DiskEntry->LayoutBuffer == NULL)
    {
        DPRINT1("Failed to allocate the disk layout buffer!\n");
        return;
    }

    /* Keep looping while the drive layout buffer is too small */
    for (;;)
    {
        DPRINT1("Buffer size: %lu\n", LayoutBufferSize);
        Status = NtDeviceIoControlFile(FileHandle,
                                       NULL,
                                       NULL,
                                       NULL,
                                       &Iosb,
                                       IOCTL_DISK_GET_DRIVE_LAYOUT,
                                       NULL,
                                       0,
                                       DiskEntry->LayoutBuffer,
                                       LayoutBufferSize);
        if (NT_SUCCESS(Status))
            break;

        if (Status != STATUS_BUFFER_TOO_SMALL)
        {
            DPRINT1("NtDeviceIoControlFile() failed (Status: 0x%08lx)\n", Status);
            return;
        }

        LayoutBufferSize += 4 * sizeof(PARTITION_INFORMATION);
        NewLayoutBuffer = RtlReAllocateHeap(ProcessHeap,
                                            HEAP_ZERO_MEMORY,
                                            DiskEntry->LayoutBuffer,
                                            LayoutBufferSize);
        if (NewLayoutBuffer == NULL)
        {
            DPRINT1("Failed to reallocate the disk layout buffer!\n");
            return;
        }

        DiskEntry->LayoutBuffer = NewLayoutBuffer;
    }

    DPRINT1("PartitionCount: %lu\n", DiskEntry->LayoutBuffer->PartitionCount);

#ifdef DUMP_PARTITION_TABLE
    DumpPartitionTable(DiskEntry);
#endif

    if (DiskEntry->LayoutBuffer->PartitionEntry[0].StartingOffset.QuadPart != 0 &&
        DiskEntry->LayoutBuffer->PartitionEntry[0].PartitionLength.QuadPart != 0 &&
        DiskEntry->LayoutBuffer->PartitionEntry[0].PartitionType != PARTITION_ENTRY_UNUSED)
    {
        if ((DiskEntry->LayoutBuffer->PartitionEntry[0].StartingOffset.QuadPart / DiskEntry->BytesPerSector) % DiskEntry->SectorsPerTrack == 0)
        {
            DPRINT("Use %lu Sector alignment!\n", DiskEntry->SectorsPerTrack);
        }
        else if (DiskEntry->LayoutBuffer->PartitionEntry[0].StartingOffset.QuadPart % (1024 * 1024) == 0)
        {
            DPRINT1("Use megabyte (%lu Sectors) alignment!\n", (1024 * 1024) / DiskEntry->BytesPerSector);
        }
        else
        {
            DPRINT1("No matching alignment found! Partition 1 starts at %I64u\n", DiskEntry->LayoutBuffer->PartitionEntry[0].StartingOffset.QuadPart);
        }
    }
    else
    {
        DPRINT1("No valid partition table found! Use megabyte (%lu Sectors) alignment!\n", (1024 * 1024) / DiskEntry->BytesPerSector);
    }

    if (DiskEntry->LayoutBuffer->PartitionCount == 0)
    {
        DiskEntry->NewDisk = TRUE;
        DiskEntry->LayoutBuffer->PartitionCount = 4;

        for (i = 0; i < 4; i++)
        {
            DiskEntry->LayoutBuffer->PartitionEntry[i].RewritePartition = TRUE;
        }
    }
    else
    {
        /* Enumerate and add the first four primary partitions */
        for (i = 0; i < 4; i++)
        {
            AddPartitionToDisk(DiskNumber, DiskEntry, i, FALSE);
        }

        /* Enumerate and add the remaining partitions as logical ones */
        for (i = 4; i < DiskEntry->LayoutBuffer->PartitionCount; i += 4)
        {
            AddPartitionToDisk(DiskNumber, DiskEntry, i, TRUE);
        }
    }

    ScanForUnpartitionedDiskSpace(DiskEntry);
}

PPARTLIST
CreatePartitionList(VOID)
{
    PPARTLIST List;
    OBJECT_ATTRIBUTES ObjectAttributes;
    SYSTEM_DEVICE_INFORMATION Sdi;
    IO_STATUS_BLOCK Iosb;
    ULONG ReturnSize;
    NTSTATUS Status;
    ULONG DiskNumber;
    WCHAR Buffer[MAX_PATH];
    UNICODE_STRING Name;
    HANDLE FileHandle;

    List = (PPARTLIST)RtlAllocateHeap(ProcessHeap,
                                      0,
                                      sizeof(PARTLIST));
    if (List == NULL)
        return NULL;

    List->CurrentDisk = NULL;
    List->CurrentPartition = NULL;

    List->SystemPartition = NULL;
    List->OriginalSystemPartition = NULL;

    InitializeListHead(&List->DiskListHead);
    InitializeListHead(&List->BiosDiskListHead);

    /*
     * Enumerate the disks seen by the BIOS; this will be used later
     * to map drives seen by NTOS with their corresponding BIOS names.
     */
    EnumerateBiosDiskEntries(List);

    /* Enumerate disks seen by NTOS */
    Status = NtQuerySystemInformation(SystemDeviceInformation,
                                      &Sdi,
                                      sizeof(Sdi),
                                      &ReturnSize);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtQuerySystemInformation() failed, Status 0x%08lx", Status);
        RtlFreeHeap(ProcessHeap, 0, List);
        return NULL;
    }

    for (DiskNumber = 0; DiskNumber < Sdi.NumberOfDisks; DiskNumber++)
    {
        RtlStringCchPrintfW(Buffer, ARRAYSIZE(Buffer),
                            L"\\Device\\Harddisk%lu\\Partition0",
                            DiskNumber);
        RtlInitUnicodeString(&Name, Buffer);

        InitializeObjectAttributes(&ObjectAttributes,
                                   &Name,
                                   OBJ_CASE_INSENSITIVE,
                                   NULL,
                                   NULL);

        Status = NtOpenFile(&FileHandle,
                            FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                            &ObjectAttributes,
                            &Iosb,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            FILE_SYNCHRONOUS_IO_NONALERT);
        if (NT_SUCCESS(Status))
        {
            AddDiskToList(FileHandle, DiskNumber, List);
            NtClose(FileHandle);
        }
    }

    UpdateDiskSignatures(List);

    AssignDriveLetters(List);

    /* Search for first usable disk and partition */
    if (IsListEmpty(&List->DiskListHead))
    {
        List->CurrentDisk = NULL;
        List->CurrentPartition = NULL;
    }
    else
    {
        List->CurrentDisk = CONTAINING_RECORD(List->DiskListHead.Flink,
                                              DISKENTRY,
                                              ListEntry);

        if (IsListEmpty(&List->CurrentDisk->PrimaryPartListHead))
        {
            List->CurrentPartition = NULL;
        }
        else
        {
            List->CurrentPartition = CONTAINING_RECORD(List->CurrentDisk->PrimaryPartListHead.Flink,
                                                       PARTENTRY,
                                                       ListEntry);
        }
    }

    return List;
}

VOID
DestroyPartitionList(
    IN PPARTLIST List)
{
    PDISKENTRY DiskEntry;
    PBIOSDISKENTRY BiosDiskEntry;
    PPARTENTRY PartEntry;
    PLIST_ENTRY Entry;

    /* Release disk and partition info */
    while (!IsListEmpty(&List->DiskListHead))
    {
        Entry = RemoveHeadList(&List->DiskListHead);
        DiskEntry = CONTAINING_RECORD(Entry, DISKENTRY, ListEntry);

        /* Release driver name */
        RtlFreeUnicodeString(&DiskEntry->DriverName);

        /* Release primary partition list */
        while (!IsListEmpty(&DiskEntry->PrimaryPartListHead))
        {
            Entry = RemoveHeadList(&DiskEntry->PrimaryPartListHead);
            PartEntry = CONTAINING_RECORD(Entry, PARTENTRY, ListEntry);

            RtlFreeHeap(ProcessHeap, 0, PartEntry);
        }

        /* Release logical partition list */
        while (!IsListEmpty(&DiskEntry->LogicalPartListHead))
        {
            Entry = RemoveHeadList(&DiskEntry->LogicalPartListHead);
            PartEntry = CONTAINING_RECORD(Entry, PARTENTRY, ListEntry);

            RtlFreeHeap(ProcessHeap, 0, PartEntry);
        }

        /* Release layout buffer */
        if (DiskEntry->LayoutBuffer != NULL)
            RtlFreeHeap(ProcessHeap, 0, DiskEntry->LayoutBuffer);

        /* Release disk entry */
        RtlFreeHeap(ProcessHeap, 0, DiskEntry);
    }

    /* Release the bios disk info */
    while (!IsListEmpty(&List->BiosDiskListHead))
    {
        Entry = RemoveHeadList(&List->BiosDiskListHead);
        BiosDiskEntry = CONTAINING_RECORD(Entry, BIOSDISKENTRY, ListEntry);

        RtlFreeHeap(ProcessHeap, 0, BiosDiskEntry);
    }

    /* Release list head */
    RtlFreeHeap(ProcessHeap, 0, List);
}

PDISKENTRY
GetDiskByBiosNumber(
    IN PPARTLIST List,
    IN ULONG BiosDiskNumber)
{
    PDISKENTRY DiskEntry;
    PLIST_ENTRY Entry;

    /* Loop over the disks and find the correct one */
    for (Entry = List->DiskListHead.Flink;
         Entry != &List->DiskListHead;
         Entry = Entry->Flink)
    {
        DiskEntry = CONTAINING_RECORD(Entry, DISKENTRY, ListEntry);

        if (DiskEntry->BiosDiskNumber == BiosDiskNumber)
        {
            /* Disk found */
            return DiskEntry;
        }
    }

    /* Disk not found, stop there */
    return NULL;
}

PDISKENTRY
GetDiskByNumber(
    IN PPARTLIST List,
    IN ULONG DiskNumber)
{
    PDISKENTRY DiskEntry;
    PLIST_ENTRY Entry;

    /* Loop over the disks and find the correct one */
    for (Entry = List->DiskListHead.Flink;
         Entry != &List->DiskListHead;
         Entry = Entry->Flink)
    {
        DiskEntry = CONTAINING_RECORD(Entry, DISKENTRY, ListEntry);

        if (DiskEntry->DiskNumber == DiskNumber)
        {
            /* Disk found */
            return DiskEntry;
        }
    }

    /* Disk not found, stop there */
    return NULL;
}

PDISKENTRY
GetDiskBySCSI(
    IN PPARTLIST List,
    IN USHORT Port,
    IN USHORT Bus,
    IN USHORT Id)
{
    PDISKENTRY DiskEntry;
    PLIST_ENTRY Entry;

    /* Loop over the disks and find the correct one */
    for (Entry = List->DiskListHead.Flink;
         Entry != &List->DiskListHead;
         Entry = Entry->Flink)
    {
        DiskEntry = CONTAINING_RECORD(Entry, DISKENTRY, ListEntry);

        if (DiskEntry->Port == Port &&
            DiskEntry->Bus  == Bus  &&
            DiskEntry->Id   == Id)
        {
            /* Disk found */
            return DiskEntry;
        }
    }

    /* Disk not found, stop there */
    return NULL;
}

PDISKENTRY
GetDiskBySignature(
    IN PPARTLIST List,
    IN ULONG Signature)
{
    PDISKENTRY DiskEntry;
    PLIST_ENTRY Entry;

    /* Loop over the disks and find the correct one */
    for (Entry = List->DiskListHead.Flink;
         Entry != &List->DiskListHead;
         Entry = Entry->Flink)
    {
        DiskEntry = CONTAINING_RECORD(Entry, DISKENTRY, ListEntry);

        if (DiskEntry->LayoutBuffer->Signature == Signature)
        {
            /* Disk found */
            return DiskEntry;
        }
    }

    /* Disk not found, stop there */
    return NULL;
}

PPARTENTRY
GetPartition(
    // IN PPARTLIST List,
    IN PDISKENTRY DiskEntry,
    IN ULONG PartitionNumber)
{
    PPARTENTRY PartEntry;
    PLIST_ENTRY Entry;

    if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
    {
        DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
        return NULL;
    }

    /* Disk found, loop over the primary partitions first... */
    for (Entry = DiskEntry->PrimaryPartListHead.Flink;
         Entry != &DiskEntry->PrimaryPartListHead;
         Entry = Entry->Flink)
    {
        PartEntry = CONTAINING_RECORD(Entry, PARTENTRY, ListEntry);

        if (PartEntry->PartitionNumber == PartitionNumber)
        {
            /* Partition found */
            return PartEntry;
        }
    }

    /* ... then over the logical partitions if needed */
    for (Entry = DiskEntry->LogicalPartListHead.Flink;
         Entry != &DiskEntry->LogicalPartListHead;
         Entry = Entry->Flink)
    {
        PartEntry = CONTAINING_RECORD(Entry, PARTENTRY, ListEntry);

        if (PartEntry->PartitionNumber == PartitionNumber)
        {
            /* Partition found */
            return PartEntry;
        }
    }

    /* The partition was not found on the disk, stop there */
    return NULL;
}

BOOLEAN
GetDiskOrPartition(
    IN PPARTLIST List,
    IN ULONG DiskNumber,
    IN ULONG PartitionNumber OPTIONAL,
    OUT PDISKENTRY* pDiskEntry,
    OUT PPARTENTRY* pPartEntry OPTIONAL)
{
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry = NULL;

    /* Find the disk */
    DiskEntry = GetDiskByNumber(List, DiskNumber);
    if (!DiskEntry)
        return FALSE;

    /* If we have a partition (PartitionNumber != 0), find it */
    if (PartitionNumber != 0)
    {
        if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
        {
            DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
            return FALSE;
        }

        PartEntry = GetPartition(/*List,*/ DiskEntry, PartitionNumber);
        if (!PartEntry)
            return FALSE;
        ASSERT(PartEntry->DiskEntry == DiskEntry);
    }

    /* Return the disk (and optionally the partition) */
    *pDiskEntry = DiskEntry;
    if (pPartEntry) *pPartEntry = PartEntry;
    return TRUE;
}

//
// NOTE: Was introduced broken in r6258 by Casper
//
BOOLEAN
SelectPartition(
    IN PPARTLIST List,
    IN ULONG DiskNumber,
    IN ULONG PartitionNumber)
{
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;

    DiskEntry = GetDiskByNumber(List, DiskNumber);
    if (!DiskEntry)
        return FALSE;

    PartEntry = GetPartition(/*List,*/ DiskEntry, PartitionNumber);
    if (!PartEntry)
        return FALSE;

    ASSERT(PartEntry->DiskEntry == DiskEntry);
    ASSERT(DiskEntry->DiskNumber == DiskNumber);
    ASSERT(PartEntry->PartitionNumber == PartitionNumber);

    List->CurrentDisk = DiskEntry;
    List->CurrentPartition = PartEntry;
    return TRUE;
}

PPARTENTRY
GetNextPartition(
    IN PPARTLIST List)
{
    PLIST_ENTRY DiskListEntry;
    PLIST_ENTRY PartListEntry;
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;

    /* Fail if no disks are available */
    if (IsListEmpty(&List->DiskListHead))
        return NULL;

    /* Check for next usable entry on current disk */
    if (List->CurrentPartition != NULL)
    {
        if (List->CurrentPartition->LogicalPartition)
        {
            /* Logical partition */

            PartListEntry = List->CurrentPartition->ListEntry.Flink;
            if (PartListEntry != &List->CurrentDisk->LogicalPartListHead)
            {
                /* Next logical partition */
                PartEntry = CONTAINING_RECORD(PartListEntry, PARTENTRY, ListEntry);

                List->CurrentPartition = PartEntry;
                return List->CurrentPartition;
            }
            else
            {
                PartListEntry = List->CurrentDisk->ExtendedPartition->ListEntry.Flink;
                if (PartListEntry != &List->CurrentDisk->PrimaryPartListHead)
                {
                    PartEntry = CONTAINING_RECORD(PartListEntry, PARTENTRY, ListEntry);

                    List->CurrentPartition = PartEntry;
                    return List->CurrentPartition;
                }
            }
        }
        else
        {
            /* Primary or extended partition */

            if (List->CurrentPartition->IsPartitioned &&
                IsContainerPartition(List->CurrentPartition->PartitionType))
            {
                /* First logical partition */
                PartListEntry = List->CurrentDisk->LogicalPartListHead.Flink;
                if (PartListEntry != &List->CurrentDisk->LogicalPartListHead)
                {
                    PartEntry = CONTAINING_RECORD(PartListEntry, PARTENTRY, ListEntry);

                    List->CurrentPartition = PartEntry;
                    return List->CurrentPartition;
                }
            }
            else
            {
                /* Next primary partition */
                PartListEntry = List->CurrentPartition->ListEntry.Flink;
                if (PartListEntry != &List->CurrentDisk->PrimaryPartListHead)
                {
                    PartEntry = CONTAINING_RECORD(PartListEntry, PARTENTRY, ListEntry);

                    List->CurrentPartition = PartEntry;
                    return List->CurrentPartition;
                }
            }
        }
    }

    /* Search for the first partition entry on the next disk */
    for (DiskListEntry = List->CurrentDisk->ListEntry.Flink;
         DiskListEntry != &List->DiskListHead;
         DiskListEntry = DiskListEntry->Flink)
    {
        DiskEntry = CONTAINING_RECORD(DiskListEntry, DISKENTRY, ListEntry);

        if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
        {
            DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
            continue;
        }

        PartListEntry = DiskEntry->PrimaryPartListHead.Flink;
        if (PartListEntry != &DiskEntry->PrimaryPartListHead)
        {
            PartEntry = CONTAINING_RECORD(PartListEntry, PARTENTRY, ListEntry);

            List->CurrentDisk = DiskEntry;
            List->CurrentPartition = PartEntry;
            return List->CurrentPartition;
        }
    }

    return NULL;
}

PPARTENTRY
GetPrevPartition(
    IN PPARTLIST List)
{
    PLIST_ENTRY DiskListEntry;
    PLIST_ENTRY PartListEntry;
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;

    /* Fail if no disks are available */
    if (IsListEmpty(&List->DiskListHead))
        return NULL;

    /* Check for previous usable entry on current disk */
    if (List->CurrentPartition != NULL)
    {
        if (List->CurrentPartition->LogicalPartition)
        {
            /* Logical partition */
            PartListEntry = List->CurrentPartition->ListEntry.Blink;
            if (PartListEntry != &List->CurrentDisk->LogicalPartListHead)
            {
                /* Previous logical partition */
                PartEntry = CONTAINING_RECORD(PartListEntry, PARTENTRY, ListEntry);
            }
            else
            {
                /* Extended partition */
                PartEntry = List->CurrentDisk->ExtendedPartition;
            }

            List->CurrentPartition = PartEntry;
            return List->CurrentPartition;
        }
        else
        {
            /* Primary or extended partition */

            PartListEntry = List->CurrentPartition->ListEntry.Blink;
            if (PartListEntry != &List->CurrentDisk->PrimaryPartListHead)
            {
                PartEntry = CONTAINING_RECORD(PartListEntry, PARTENTRY, ListEntry);

                if (PartEntry->IsPartitioned &&
                    IsContainerPartition(PartEntry->PartitionType))
                {
                    PartListEntry = List->CurrentDisk->LogicalPartListHead.Blink;
                    PartEntry = CONTAINING_RECORD(PartListEntry, PARTENTRY, ListEntry);
                }

                List->CurrentPartition = PartEntry;
                return List->CurrentPartition;
            }
        }
    }

    /* Search for the last partition entry on the previous disk */
    for (DiskListEntry = List->CurrentDisk->ListEntry.Blink;
         DiskListEntry != &List->DiskListHead;
         DiskListEntry = DiskListEntry->Blink)
    {
        DiskEntry = CONTAINING_RECORD(DiskListEntry, DISKENTRY, ListEntry);

        if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
        {
            DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
            continue;
        }

        PartListEntry = DiskEntry->PrimaryPartListHead.Blink;
        if (PartListEntry != &DiskEntry->PrimaryPartListHead)
        {
            PartEntry = CONTAINING_RECORD(PartListEntry, PARTENTRY, ListEntry);

            if (PartEntry->IsPartitioned &&
                IsContainerPartition(PartEntry->PartitionType))
            {
                PartListEntry = DiskEntry->LogicalPartListHead.Blink;
                if (PartListEntry != &DiskEntry->LogicalPartListHead)
                {
                    PartEntry = CONTAINING_RECORD(PartListEntry, PARTENTRY, ListEntry);

                    List->CurrentDisk = DiskEntry;
                    List->CurrentPartition = PartEntry;
                    return List->CurrentPartition;
                }
            }
            else
            {
                List->CurrentDisk = DiskEntry;
                List->CurrentPartition = PartEntry;
                return List->CurrentPartition;
            }
        }
    }

    return NULL;
}

// static
FORCEINLINE
BOOLEAN
IsEmptyLayoutEntry(
    IN PPARTITION_INFORMATION PartitionInfo)
{
    if (PartitionInfo->StartingOffset.QuadPart == 0 &&
        PartitionInfo->PartitionLength.QuadPart == 0)
    {
        return TRUE;
    }

    return FALSE;
}

// static
FORCEINLINE
BOOLEAN
IsSamePrimaryLayoutEntry(
    IN PPARTITION_INFORMATION PartitionInfo,
    IN PDISKENTRY DiskEntry,
    IN PPARTENTRY PartEntry)
{
    if (PartitionInfo->StartingOffset.QuadPart == PartEntry->StartSector.QuadPart * DiskEntry->BytesPerSector &&
        PartitionInfo->PartitionLength.QuadPart == PartEntry->SectorCount.QuadPart * DiskEntry->BytesPerSector)
//        PartitionInfo->PartitionType == PartEntry->PartitionType
    {
        return TRUE;
    }

    return FALSE;
}

static
ULONG
GetPrimaryPartitionCount(
    IN PDISKENTRY DiskEntry)
{
    PLIST_ENTRY Entry;
    PPARTENTRY PartEntry;
    ULONG Count = 0;

    if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
    {
        DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
        return 0;
    }

    for (Entry = DiskEntry->PrimaryPartListHead.Flink;
         Entry != &DiskEntry->PrimaryPartListHead;
         Entry = Entry->Flink)
    {
        PartEntry = CONTAINING_RECORD(Entry, PARTENTRY, ListEntry);
        if (PartEntry->IsPartitioned)
            Count++;
    }

    return Count;
}

static
ULONG
GetLogicalPartitionCount(
    IN PDISKENTRY DiskEntry)
{
    PLIST_ENTRY ListEntry;
    PPARTENTRY PartEntry;
    ULONG Count = 0;

    if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
    {
        DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
        return 0;
    }

    for (ListEntry = DiskEntry->LogicalPartListHead.Flink;
         ListEntry != &DiskEntry->LogicalPartListHead;
         ListEntry = ListEntry->Flink)
    {
        PartEntry = CONTAINING_RECORD(ListEntry, PARTENTRY, ListEntry);
        if (PartEntry->IsPartitioned)
            Count++;
    }

    return Count;
}

static
BOOLEAN
ReAllocateLayoutBuffer(
    IN PDISKENTRY DiskEntry)
{
    PDRIVE_LAYOUT_INFORMATION NewLayoutBuffer;
    ULONG NewPartitionCount;
    ULONG CurrentPartitionCount = 0;
    ULONG LayoutBufferSize;
    ULONG i;

    DPRINT1("ReAllocateLayoutBuffer()\n");

    NewPartitionCount = 4 + GetLogicalPartitionCount(DiskEntry) * 4;

    if (DiskEntry->LayoutBuffer)
        CurrentPartitionCount = DiskEntry->LayoutBuffer->PartitionCount;

    DPRINT1("CurrentPartitionCount: %lu ; NewPartitionCount: %lu\n",
            CurrentPartitionCount, NewPartitionCount);

    if (CurrentPartitionCount == NewPartitionCount)
        return TRUE;

    LayoutBufferSize = sizeof(DRIVE_LAYOUT_INFORMATION) +
                       ((NewPartitionCount - ANYSIZE_ARRAY) * sizeof(PARTITION_INFORMATION));
    NewLayoutBuffer = RtlReAllocateHeap(ProcessHeap,
                                        HEAP_ZERO_MEMORY,
                                        DiskEntry->LayoutBuffer,
                                        LayoutBufferSize);
    if (NewLayoutBuffer == NULL)
    {
        DPRINT1("Failed to allocate the new layout buffer (size: %lu)\n", LayoutBufferSize);
        return FALSE;
    }

    NewLayoutBuffer->PartitionCount = NewPartitionCount;

    /* If the layout buffer grows, make sure the new (empty) entries are written to the disk */
    if (NewPartitionCount > CurrentPartitionCount)
    {
        for (i = CurrentPartitionCount; i < NewPartitionCount; i++)
        {
            NewLayoutBuffer->PartitionEntry[i].RewritePartition = TRUE;
        }
    }

    DiskEntry->LayoutBuffer = NewLayoutBuffer;

    return TRUE;
}

static
VOID
UpdateDiskLayout(
    IN PDISKENTRY DiskEntry)
{
    PPARTITION_INFORMATION PartitionInfo;
    PPARTITION_INFORMATION LinkInfo = NULL;
    PLIST_ENTRY ListEntry;
    PPARTENTRY PartEntry;
    LARGE_INTEGER HiddenSectors64;
    ULONG Index;
    ULONG PartitionNumber = 1;

    DPRINT1("UpdateDiskLayout()\n");

    if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
    {
        DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
        return;
    }

    /* Resize the layout buffer if necessary */
    if (ReAllocateLayoutBuffer(DiskEntry) == FALSE)
    {
        DPRINT("ReAllocateLayoutBuffer() failed.\n");
        return;
    }

    /* Update the primary partition table */
    Index = 0;
    for (ListEntry = DiskEntry->PrimaryPartListHead.Flink;
         ListEntry != &DiskEntry->PrimaryPartListHead;
         ListEntry = ListEntry->Flink)
    {
        PartEntry = CONTAINING_RECORD(ListEntry, PARTENTRY, ListEntry);

        if (PartEntry->IsPartitioned)
        {
            PartitionInfo = &DiskEntry->LayoutBuffer->PartitionEntry[Index];
            PartEntry->PartitionIndex = Index;

            /* Reset the current partition number only for newly-created partitions */
            if (PartEntry->New)
                PartEntry->PartitionNumber = 0;

            PartEntry->OnDiskPartitionNumber = (!IsContainerPartition(PartEntry->PartitionType)) ? PartitionNumber : 0;

            if (!IsSamePrimaryLayoutEntry(PartitionInfo, DiskEntry, PartEntry))
            {
                DPRINT1("Updating primary partition entry %lu\n", Index);

                PartitionInfo->StartingOffset.QuadPart = PartEntry->StartSector.QuadPart * DiskEntry->BytesPerSector;
                PartitionInfo->PartitionLength.QuadPart = PartEntry->SectorCount.QuadPart * DiskEntry->BytesPerSector;
                PartitionInfo->HiddenSectors = PartEntry->StartSector.LowPart;
                PartitionInfo->PartitionNumber = PartEntry->PartitionNumber;
                PartitionInfo->PartitionType = PartEntry->PartitionType;
                PartitionInfo->BootIndicator = PartEntry->BootIndicator;
                PartitionInfo->RecognizedPartition = IsRecognizedPartition(PartEntry->PartitionType);
                PartitionInfo->RewritePartition = TRUE;
            }

            if (!IsContainerPartition(PartEntry->PartitionType))
                PartitionNumber++;

            Index++;
        }
    }

    ASSERT(Index <= 4);

    /* Update the logical partition table */
    Index = 4;
    for (ListEntry = DiskEntry->LogicalPartListHead.Flink;
         ListEntry != &DiskEntry->LogicalPartListHead;
         ListEntry = ListEntry->Flink)
    {
        PartEntry = CONTAINING_RECORD(ListEntry, PARTENTRY, ListEntry);

        if (PartEntry->IsPartitioned)
        {
            PartitionInfo = &DiskEntry->LayoutBuffer->PartitionEntry[Index];
            PartEntry->PartitionIndex = Index;

            DPRINT1("Updating logical partition entry %lu\n", Index);

            /* Reset the current partition number only for newly-created partitions */
            if (PartEntry->New)
                PartEntry->PartitionNumber = 0;

            PartEntry->OnDiskPartitionNumber = PartitionNumber;

            PartitionInfo->StartingOffset.QuadPart = PartEntry->StartSector.QuadPart * DiskEntry->BytesPerSector;
            PartitionInfo->PartitionLength.QuadPart = PartEntry->SectorCount.QuadPart * DiskEntry->BytesPerSector;
            PartitionInfo->HiddenSectors = DiskEntry->SectorAlignment;
            PartitionInfo->PartitionNumber = PartEntry->PartitionNumber;
            PartitionInfo->PartitionType = PartEntry->PartitionType;
            PartitionInfo->BootIndicator = FALSE;
            PartitionInfo->RecognizedPartition = IsRecognizedPartition(PartEntry->PartitionType);
            PartitionInfo->RewritePartition = TRUE;

            /* Fill the link entry of the previous partition entry */
            if (LinkInfo != NULL)
            {
                LinkInfo->StartingOffset.QuadPart = (PartEntry->StartSector.QuadPart - DiskEntry->SectorAlignment) * DiskEntry->BytesPerSector;
                LinkInfo->PartitionLength.QuadPart = (PartEntry->StartSector.QuadPart + DiskEntry->SectorAlignment) * DiskEntry->BytesPerSector;
                HiddenSectors64.QuadPart = PartEntry->StartSector.QuadPart - DiskEntry->SectorAlignment - DiskEntry->ExtendedPartition->StartSector.QuadPart;
                LinkInfo->HiddenSectors = HiddenSectors64.LowPart;
                LinkInfo->PartitionNumber = 0;
                LinkInfo->PartitionType = PARTITION_EXTENDED;
                LinkInfo->BootIndicator = FALSE;
                LinkInfo->RecognizedPartition = FALSE;
                LinkInfo->RewritePartition = TRUE;
            }

            /* Save a pointer to the link entry of the current partition entry */
            LinkInfo = &DiskEntry->LayoutBuffer->PartitionEntry[Index + 1];

            PartitionNumber++;
            Index += 4;
        }
    }

    /* Wipe unused primary partition entries */
    for (Index = GetPrimaryPartitionCount(DiskEntry); Index < 4; Index++)
    {
        DPRINT1("Primary partition entry %lu\n", Index);

        PartitionInfo = &DiskEntry->LayoutBuffer->PartitionEntry[Index];

        if (!IsEmptyLayoutEntry(PartitionInfo))
        {
            DPRINT1("Wiping primary partition entry %lu\n", Index);

            PartitionInfo->StartingOffset.QuadPart = 0;
            PartitionInfo->PartitionLength.QuadPart = 0;
            PartitionInfo->HiddenSectors = 0;
            PartitionInfo->PartitionNumber = 0;
            PartitionInfo->PartitionType = PARTITION_ENTRY_UNUSED;
            PartitionInfo->BootIndicator = FALSE;
            PartitionInfo->RecognizedPartition = FALSE;
            PartitionInfo->RewritePartition = TRUE;
        }
    }

    /* Wipe unused logical partition entries */
    for (Index = 4; Index < DiskEntry->LayoutBuffer->PartitionCount; Index++)
    {
        if (Index % 4 >= 2)
        {
            DPRINT1("Logical partition entry %lu\n", Index);

            PartitionInfo = &DiskEntry->LayoutBuffer->PartitionEntry[Index];

            if (!IsEmptyLayoutEntry(PartitionInfo))
            {
                DPRINT1("Wiping partition entry %lu\n", Index);

                PartitionInfo->StartingOffset.QuadPart = 0;
                PartitionInfo->PartitionLength.QuadPart = 0;
                PartitionInfo->HiddenSectors = 0;
                PartitionInfo->PartitionNumber = 0;
                PartitionInfo->PartitionType = PARTITION_ENTRY_UNUSED;
                PartitionInfo->BootIndicator = FALSE;
                PartitionInfo->RecognizedPartition = FALSE;
                PartitionInfo->RewritePartition = TRUE;
            }
        }
    }

    DiskEntry->Dirty = TRUE;

#ifdef DUMP_PARTITION_TABLE
    DumpPartitionTable(DiskEntry);
#endif
}

static
PPARTENTRY
GetPrevUnpartitionedEntry(
    IN PDISKENTRY DiskEntry,
    IN PPARTENTRY PartEntry)
{
    PPARTENTRY PrevPartEntry;
    PLIST_ENTRY ListHead;

    if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
    {
        DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
        return NULL;
    }

    if (PartEntry->LogicalPartition)
        ListHead = &DiskEntry->LogicalPartListHead;
    else
        ListHead = &DiskEntry->PrimaryPartListHead;

    if (PartEntry->ListEntry.Blink != ListHead)
    {
        PrevPartEntry = CONTAINING_RECORD(PartEntry->ListEntry.Blink,
                                          PARTENTRY,
                                          ListEntry);
        if (PrevPartEntry->IsPartitioned == FALSE)
            return PrevPartEntry;
    }

    return NULL;
}

static
PPARTENTRY
GetNextUnpartitionedEntry(
    IN PDISKENTRY DiskEntry,
    IN PPARTENTRY PartEntry)
{
    PPARTENTRY NextPartEntry;
    PLIST_ENTRY ListHead;

    if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
    {
        DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
        return NULL;
    }

    if (PartEntry->LogicalPartition)
        ListHead = &DiskEntry->LogicalPartListHead;
    else
        ListHead = &DiskEntry->PrimaryPartListHead;

    if (PartEntry->ListEntry.Flink != ListHead)
    {
        NextPartEntry = CONTAINING_RECORD(PartEntry->ListEntry.Flink,
                                          PARTENTRY,
                                          ListEntry);
        if (NextPartEntry->IsPartitioned == FALSE)
            return NextPartEntry;
    }

    return NULL;
}

BOOLEAN
CreatePrimaryPartition(
    IN PPARTLIST List,
    IN ULONGLONG SectorCount,
    IN BOOLEAN AutoCreate)
{
    ERROR_NUMBER Error;
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;

    DPRINT1("CreatePrimaryPartition(%I64u)\n", SectorCount);

    if (List == NULL ||
        List->CurrentDisk == NULL ||
        List->CurrentPartition == NULL ||
        List->CurrentPartition->IsPartitioned)
    {
        return FALSE;
    }

    Error = PrimaryPartitionCreationChecks(List);
    if (Error != NOT_AN_ERROR)
    {
        DPRINT1("PrimaryPartitionCreationChecks() failed with error %lu\n", Error);
        return FALSE;
    }

    DiskEntry = List->CurrentDisk;
    PartEntry = List->CurrentPartition;

    /* Convert the current entry, or insert and initialize a new partition entry */
    PartEntry = InitializePartitionEntry(DiskEntry, PartEntry, SectorCount, AutoCreate);
    if (PartEntry == NULL)
        return FALSE;

    UpdateDiskLayout(DiskEntry);

    AssignDriveLetters(List);

    return TRUE;
}

static
VOID
AddLogicalDiskSpace(
    IN PDISKENTRY DiskEntry)
{
    ULONGLONG StartSector;
    ULONGLONG SectorCount;
    PPARTENTRY NewPartEntry;

    DPRINT1("AddLogicalDiskSpace()\n");

    /* Create a partition entry that represents the empty space in the container partition */

    StartSector = DiskEntry->ExtendedPartition->StartSector.QuadPart + (ULONGLONG)DiskEntry->SectorAlignment;
    SectorCount = DiskEntry->ExtendedPartition->SectorCount.QuadPart - (ULONGLONG)DiskEntry->SectorAlignment;

    NewPartEntry = CreateInsertBlankRegion(DiskEntry,
                                           &DiskEntry->LogicalPartListHead,
                                           StartSector,
                                           SectorCount,
                                           TRUE);
    if (NewPartEntry == NULL)
    {
        DPRINT1("Failed to create a new empty region for extended partition space!\n");
        return;
    }
    NewPartEntry->LogicalPartition = TRUE;
}

BOOLEAN
CreateExtendedPartition(
    IN PPARTLIST List,
    IN ULONGLONG SectorCount)
{
    ERROR_NUMBER Error;
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;

    DPRINT1("CreateExtendedPartition(%I64u)\n", SectorCount);

    if (List == NULL ||
        List->CurrentDisk == NULL ||
        List->CurrentPartition == NULL ||
        List->CurrentPartition->IsPartitioned)
    {
        return FALSE;
    }

    Error = ExtendedPartitionCreationChecks(List);
    if (Error != NOT_AN_ERROR)
    {
        DPRINT1("ExtendedPartitionCreationChecks() failed with error %lu\n", Error);
        return FALSE;
    }

    DiskEntry = List->CurrentDisk;
    PartEntry = List->CurrentPartition;

    /* Convert the current entry, or insert and initialize a new partition entry */
    PartEntry = InitializePartitionEntry(DiskEntry, PartEntry, SectorCount, FALSE);
    if (PartEntry == NULL)
        return FALSE;

    if (PartEntry->StartSector.QuadPart < 1450560)
    {
        /* Partition starts below the 8.4GB boundary ==> CHS partition */
        PartEntry->PartitionType = PARTITION_EXTENDED;
    }
    else
    {
        /* Partition starts above the 8.4GB boundary ==> LBA partition */
        PartEntry->PartitionType = PARTITION_XINT13_EXTENDED;
    }

    // FIXME? Possibly to make GetNextUnformattedPartition work (i.e. skip the extended partition container)
    PartEntry->New = FALSE;
    PartEntry->FormatState = Formatted;

    DiskEntry->ExtendedPartition = PartEntry;

    AddLogicalDiskSpace(DiskEntry);

    UpdateDiskLayout(DiskEntry);

    AssignDriveLetters(List);

    return TRUE;
}

BOOLEAN
CreateLogicalPartition(
    IN PPARTLIST List,
    IN ULONGLONG SectorCount,
    IN BOOLEAN AutoCreate)
{
    ERROR_NUMBER Error;
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;

    DPRINT1("CreateLogicalPartition(%I64u)\n", SectorCount);

    if (List == NULL ||
        List->CurrentDisk == NULL ||
        List->CurrentPartition == NULL ||
        List->CurrentPartition->IsPartitioned)
    {
        return FALSE;
    }

    Error = LogicalPartitionCreationChecks(List);
    if (Error != NOT_AN_ERROR)
    {
        DPRINT1("LogicalPartitionCreationChecks() failed with error %lu\n", Error);
        return FALSE;
    }

    DiskEntry = List->CurrentDisk;
    PartEntry = List->CurrentPartition;

    /* Convert the current entry, or insert and initialize a new partition entry */
    PartEntry = InitializePartitionEntry(DiskEntry, PartEntry, SectorCount, AutoCreate);
    if (PartEntry == NULL)
        return FALSE;

    PartEntry->LogicalPartition = TRUE;

    UpdateDiskLayout(DiskEntry);

    AssignDriveLetters(List);

    return TRUE;
}

static
NTSTATUS
DismountVolume(
    IN PPARTENTRY PartEntry)
{
    NTSTATUS Status;
    NTSTATUS LockStatus;
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES ObjectAttributes;
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE PartitionHandle;
    WCHAR Buffer[MAX_PATH];

    /* Check whether the partition is valid and may have been mounted in the system */
    if (!PartEntry->IsPartitioned ||
        PartEntry->PartitionType == PARTITION_ENTRY_UNUSED ||
        IsContainerPartition(PartEntry->PartitionType)     ||
        !IsRecognizedPartition(PartEntry->PartitionType)   ||
        PartEntry->FormatState == Unformatted /* || PartEntry->FormatState == UnknownFormat */ ||
        PartEntry->FileSystem == NULL ||
        PartEntry->PartitionNumber == 0)
    {
        /* The partition is not mounted, so just return success */
        return STATUS_SUCCESS;
    }

    /* Open the volume */
    RtlStringCchPrintfW(Buffer, ARRAYSIZE(Buffer),
                        L"\\Device\\Harddisk%lu\\Partition%lu",
                        PartEntry->DiskEntry->DiskNumber,
                        PartEntry->PartitionNumber);
    RtlInitUnicodeString(&Name, Buffer);

    InitializeObjectAttributes(&ObjectAttributes,
                               &Name,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    Status = NtOpenFile(&PartitionHandle,
                        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                        &ObjectAttributes,
                        &IoStatusBlock,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("ERROR: Cannot open volume %wZ for dismounting! (Status 0x%lx)\n", &Name, Status);
        return Status;
    }

    /* Lock the volume */
    LockStatus = NtFsControlFile(PartitionHandle,
                                 NULL,
                                 NULL,
                                 NULL,
                                 &IoStatusBlock,
                                 FSCTL_LOCK_VOLUME,
                                 NULL,
                                 0,
                                 NULL,
                                 0);
    if (!NT_SUCCESS(LockStatus))
    {
        DPRINT1("WARNING: Failed to lock volume! Operations may fail! (Status 0x%lx)\n", LockStatus);
    }

    /* Dismount the volume */
    Status = NtFsControlFile(PartitionHandle,
                             NULL,
                             NULL,
                             NULL,
                             &IoStatusBlock,
                             FSCTL_DISMOUNT_VOLUME,
                             NULL,
                             0,
                             NULL,
                             0);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("Failed to unmount volume (Status 0x%lx)\n", Status);
    }

    /* Unlock the volume */
    LockStatus = NtFsControlFile(PartitionHandle,
                                 NULL,
                                 NULL,
                                 NULL,
                                 &IoStatusBlock,
                                 FSCTL_UNLOCK_VOLUME,
                                 NULL,
                                 0,
                                 NULL,
                                 0);
    if (!NT_SUCCESS(LockStatus))
    {
        DPRINT1("Failed to unlock volume (Status 0x%lx)\n", LockStatus);
    }

    /* Close the volume */
    NtClose(PartitionHandle);

    return Status;
}

VOID
DeleteCurrentPartition(
    IN PPARTLIST List)
{
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;
    PPARTENTRY PrevPartEntry;
    PPARTENTRY NextPartEntry;
    PPARTENTRY LogicalPartEntry;
    PLIST_ENTRY Entry;

    if (List == NULL ||
        List->CurrentDisk == NULL ||
        List->CurrentPartition == NULL ||
        List->CurrentPartition->IsPartitioned == FALSE)
    {
        return;
    }

    /* Clear the system disk and partition pointers if the system partition is being deleted */
    if (List->SystemPartition == List->CurrentPartition)
    {
        List->SystemPartition = NULL;
    }

    DiskEntry = List->CurrentDisk;
    PartEntry = List->CurrentPartition;

    /* Check which type of partition (primary/logical or extended) is being deleted */
    if (DiskEntry->ExtendedPartition == PartEntry)
    {
        /* An extended partition is being deleted: delete all logical partition entries */
        while (!IsListEmpty(&DiskEntry->LogicalPartListHead))
        {
            Entry = RemoveHeadList(&DiskEntry->LogicalPartListHead);
            LogicalPartEntry = CONTAINING_RECORD(Entry, PARTENTRY, ListEntry);

            /* Dismount the logical partition */
            DismountVolume(LogicalPartEntry);

            /* Delete it */
            RtlFreeHeap(ProcessHeap, 0, LogicalPartEntry);
        }

        DiskEntry->ExtendedPartition = NULL;
    }
    else
    {
        /* A primary partition is being deleted: dismount it */
        DismountVolume(PartEntry);
    }

    /* Adjust unpartitioned disk space entries */

    /* Get pointer to previous and next unpartitioned entries */
    PrevPartEntry = GetPrevUnpartitionedEntry(DiskEntry, PartEntry);
    NextPartEntry = GetNextUnpartitionedEntry(DiskEntry, PartEntry);

    if (PrevPartEntry != NULL && NextPartEntry != NULL)
    {
        /* Merge previous, current and next unpartitioned entry */

        /* Adjust the previous entries length */
        PrevPartEntry->SectorCount.QuadPart += (PartEntry->SectorCount.QuadPart + NextPartEntry->SectorCount.QuadPart);

        /* Remove the current entry */
        RemoveEntryList(&PartEntry->ListEntry);
        RtlFreeHeap(ProcessHeap, 0, PartEntry);

        /* Remove the next entry */
        RemoveEntryList(&NextPartEntry->ListEntry);
        RtlFreeHeap(ProcessHeap, 0, NextPartEntry);

        /* Update current partition */
        List->CurrentPartition = PrevPartEntry;
    }
    else if (PrevPartEntry != NULL && NextPartEntry == NULL)
    {
        /* Merge current and previous unpartitioned entry */

        /* Adjust the previous entries length */
        PrevPartEntry->SectorCount.QuadPart += PartEntry->SectorCount.QuadPart;

        /* Remove the current entry */
        RemoveEntryList(&PartEntry->ListEntry);
        RtlFreeHeap(ProcessHeap, 0, PartEntry);

        /* Update current partition */
        List->CurrentPartition = PrevPartEntry;
    }
    else if (PrevPartEntry == NULL && NextPartEntry != NULL)
    {
        /* Merge current and next unpartitioned entry */

        /* Adjust the next entries offset and length */
        NextPartEntry->StartSector.QuadPart = PartEntry->StartSector.QuadPart;
        NextPartEntry->SectorCount.QuadPart += PartEntry->SectorCount.QuadPart;

        /* Remove the current entry */
        RemoveEntryList(&PartEntry->ListEntry);
        RtlFreeHeap(ProcessHeap, 0, PartEntry);

        /* Update current partition */
        List->CurrentPartition = NextPartEntry;
    }
    else
    {
        /* Nothing to merge but change current entry */
        PartEntry->IsPartitioned = FALSE;
        PartEntry->PartitionType = PARTITION_ENTRY_UNUSED;
        PartEntry->FormatState = Unformatted;
        PartEntry->FileSystem  = NULL;
        PartEntry->DriveLetter = 0;
        PartEntry->OnDiskPartitionNumber = 0;
        PartEntry->PartitionNumber = 0;
        // PartEntry->PartitionIndex = 0;
    }

    UpdateDiskLayout(DiskEntry);

    AssignDriveLetters(List);
}

VOID
CheckActiveSystemPartition(
    IN PPARTLIST List)
{
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;
    PLIST_ENTRY ListEntry;

    PFILE_SYSTEM FileSystem;

    /* Check for empty disk list */
    if (IsListEmpty(&List->DiskListHead))
    {
        List->SystemPartition = NULL;
        List->OriginalSystemPartition = NULL;
        return;
    }

    /* Choose the currently selected disk */
    DiskEntry = List->CurrentDisk;

    /* Check for empty partition list */
    if (IsListEmpty(&DiskEntry->PrimaryPartListHead))
    {
        List->SystemPartition = NULL;
        List->OriginalSystemPartition = NULL;
        return;
    }

    if (List->SystemPartition != NULL)
    {
        /* We already have an active system partition */
        DPRINT1("Use the current system partition %lu in disk %lu, drive letter %C\n",
                List->SystemPartition->PartitionNumber,
                List->SystemPartition->DiskEntry->DiskNumber,
                (List->SystemPartition->DriveLetter == 0) ? L'-' : List->SystemPartition->DriveLetter);
        return;
    }

    DPRINT("We are here (1)!\n");

    List->SystemPartition = NULL;
    List->OriginalSystemPartition = NULL;

    /* Retrieve the first partition of the disk */
    PartEntry = CONTAINING_RECORD(DiskEntry->PrimaryPartListHead.Flink,
                                  PARTENTRY,
                                  ListEntry);
    ASSERT(DiskEntry == PartEntry->DiskEntry);
    List->SystemPartition = PartEntry;

    //
    // See: https://svn.reactos.org/svn/reactos/trunk/reactos/base/setup/usetup/partlist.c?r1=63355&r2=63354&pathrev=63355#l2318
    //

    /* Check if the disk is new and if so, use its first partition as the active system partition */
    if (DiskEntry->NewDisk)
    {
        if (PartEntry->PartitionType == PARTITION_ENTRY_UNUSED || PartEntry->BootIndicator == FALSE)
        {
            ASSERT(DiskEntry == PartEntry->DiskEntry);
            List->SystemPartition = PartEntry;

            List->OriginalSystemPartition = List->SystemPartition;

            DPRINT1("Use new first active system partition %lu in disk %lu, drive letter %C\n",
                    List->SystemPartition->PartitionNumber,
                    List->SystemPartition->DiskEntry->DiskNumber,
                    (List->SystemPartition->DriveLetter == 0) ? L'-' : List->SystemPartition->DriveLetter);

            goto SetSystemPartition;
        }

        // FIXME: What to do??
        DPRINT1("NewDisk TRUE but first partition is used?\n");
    }

    DPRINT("We are here (2)!\n");

    /*
     * The disk is not new, check if any partition is initialized;
     * if not, the first one becomes the system partition.
     */
    for (ListEntry = DiskEntry->PrimaryPartListHead.Flink;
         ListEntry != &DiskEntry->PrimaryPartListHead;
         ListEntry = ListEntry->Flink)
    {
        /* Retrieve the partition */
        PartEntry = CONTAINING_RECORD(ListEntry,
                                      PARTENTRY,
                                      ListEntry);

        /* Check if the partition is partitioned and is used */
        if (PartEntry->PartitionType != PARTITION_ENTRY_UNUSED || PartEntry->BootIndicator != FALSE)
        {
            break;
        }
    }
    if (ListEntry == &DiskEntry->PrimaryPartListHead)
    {
        /*
         * OK we haven't encountered any used and active partition,
         * so use the first one as the system partition.
         */
        ASSERT(DiskEntry == List->SystemPartition->DiskEntry);
        List->OriginalSystemPartition = List->SystemPartition; // First PartEntry

        DPRINT1("Use first active system partition %lu in disk %lu, drive letter %C\n",
                List->SystemPartition->PartitionNumber,
                List->SystemPartition->DiskEntry->DiskNumber,
                (List->SystemPartition->DriveLetter == 0) ? L'-' : List->SystemPartition->DriveLetter);

        goto SetSystemPartition;
    }

    List->SystemPartition = NULL;
    List->OriginalSystemPartition = NULL;

    DPRINT("We are here (3)!\n");

    /* The disk is not new, scan all partitions to find the (active) system partition */
    for (ListEntry = DiskEntry->PrimaryPartListHead.Flink;
         ListEntry != &DiskEntry->PrimaryPartListHead;
         ListEntry = ListEntry->Flink)
    {
        /* Retrieve the partition */
        PartEntry = CONTAINING_RECORD(ListEntry,
                                      PARTENTRY,
                                      ListEntry);

        /* Check if the partition is partitioned and used */
        if (PartEntry->IsPartitioned &&
            PartEntry->PartitionType != PARTITION_ENTRY_UNUSED)
        {
            /* Check if the partition is active */
            if (PartEntry->BootIndicator)
            {
                /* Yes, we found it */
                ASSERT(DiskEntry == PartEntry->DiskEntry);
                List->SystemPartition = PartEntry;

                DPRINT1("Found active system partition %lu in disk %lu, drive letter %C\n",
                        PartEntry->PartitionNumber,
                        DiskEntry->DiskNumber,
                        (PartEntry->DriveLetter == 0) ? L'-' : PartEntry->DriveLetter);
                break;
            }
        }
    }

    /* Check if we have found the system partition */
    if (List->SystemPartition == NULL)
    {
        /* Nothing, use the alternative system partition */
        DPRINT1("No system partition found, use the alternative partition!\n");
        goto UseAlternativeSystemPartition;
    }

    /* Save it */
    List->OriginalSystemPartition = List->SystemPartition;

    /*
     * ADDITIONAL CHECKS / BIG HACK:
     *
     * Retrieve its file system and check whether we have
     * write support for it. If that is the case we are fine
     * and we can use it directly. However if we don't have
     * write support we will need to change the active system
     * partition.
     *
     * NOTE that this is completely useless on architectures
     * where a real system partition is required, as on these
     * architectures the partition uses the FAT FS, for which
     * we do have write support.
     * NOTE also that for those architectures looking for a
     * partition boot indicator is insufficient.
     */
    FileSystem = GetFileSystem(List->OriginalSystemPartition);
    if (FileSystem == NULL)
    {
        DPRINT1("System partition %lu in disk %lu with no FS?!\n",
                List->OriginalSystemPartition->PartitionNumber,
                List->OriginalSystemPartition->DiskEntry->DiskNumber);
        goto FindAndUseAlternativeSystemPartition;
    }
    // HACK: WARNING: We cannot write on this FS yet!
    // See fsutil.c:GetFileSystem()
    if (List->OriginalSystemPartition->PartitionType == PARTITION_IFS)
    {
        DPRINT1("Recognized file system %S that doesn't support write support yet!\n",
                FileSystem->FileSystemName);
        goto FindAndUseAlternativeSystemPartition;
    }

    DPRINT1("Use existing active system partition %lu in disk %lu, drive letter %C\n",
            List->SystemPartition->PartitionNumber,
            List->SystemPartition->DiskEntry->DiskNumber,
            (List->SystemPartition->DriveLetter == 0) ? L'-' : List->SystemPartition->DriveLetter);

    return;

FindAndUseAlternativeSystemPartition:
    /*
     * We are here because we have not found any (active) candidate
     * system partition that we know how to support. What we are going
     * to do is to change the existing system partition and use the
     * partition on which we install ReactOS as the new system partition,
     * and then we will need to add in FreeLdr's entry a boot entry to boot
     * from the original system partition.
     */

    /* Unset the old system partition */
    List->SystemPartition->BootIndicator = FALSE;
    List->SystemPartition->DiskEntry->LayoutBuffer->PartitionEntry[List->SystemPartition->PartitionIndex].BootIndicator = FALSE;
    List->SystemPartition->DiskEntry->LayoutBuffer->PartitionEntry[List->SystemPartition->PartitionIndex].RewritePartition = TRUE;
    List->SystemPartition->DiskEntry->Dirty = TRUE;

UseAlternativeSystemPartition:
    List->SystemPartition = List->CurrentPartition;

    DPRINT1("Use alternative active system partition %lu in disk %lu, drive letter %C\n",
            List->SystemPartition->PartitionNumber,
            List->SystemPartition->DiskEntry->DiskNumber,
            (List->SystemPartition->DriveLetter == 0) ? L'-' : List->SystemPartition->DriveLetter);

SetSystemPartition:
    /* Set the new active system partition */
    List->SystemPartition->BootIndicator = TRUE;
    List->SystemPartition->DiskEntry->LayoutBuffer->PartitionEntry[List->SystemPartition->PartitionIndex].BootIndicator = TRUE;
    List->SystemPartition->DiskEntry->LayoutBuffer->PartitionEntry[List->SystemPartition->PartitionIndex].RewritePartition = TRUE;
    List->SystemPartition->DiskEntry->Dirty = TRUE;
}

static
NTSTATUS
WritePartitions(
    IN PPARTLIST List,
    IN PDISKENTRY DiskEntry)
{
    NTSTATUS Status;
    OBJECT_ATTRIBUTES ObjectAttributes;
    UNICODE_STRING Name;
    HANDLE FileHandle;
    IO_STATUS_BLOCK Iosb;
    ULONG BufferSize;
    PPARTITION_INFORMATION PartitionInfo;
    ULONG PartitionCount;
    PLIST_ENTRY ListEntry;
    PPARTENTRY PartEntry;
    WCHAR DstPath[MAX_PATH];

    DPRINT("WritePartitions() Disk: %lu\n", DiskEntry->DiskNumber);

    RtlStringCchPrintfW(DstPath, ARRAYSIZE(DstPath),
                        L"\\Device\\Harddisk%lu\\Partition0",
                        DiskEntry->DiskNumber);
    RtlInitUnicodeString(&Name, DstPath);

    InitializeObjectAttributes(&ObjectAttributes,
                               &Name,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    Status = NtOpenFile(&FileHandle,
                        GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                        &ObjectAttributes,
                        &Iosb,
                        0,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtOpenFile() failed (Status %lx)\n", Status);
        return Status;
    }

#ifdef DUMP_PARTITION_TABLE
    DumpPartitionTable(DiskEntry);
#endif

    //
    // FIXME: We first *MUST* use IOCTL_DISK_CREATE_DISK to initialize
    // the disk in MBR or GPT format in case the disk was not initialized!!
    // For this we must ask the user which format to use.
    //

    /* Save the original partition count to be restored later (see comment below) */
    PartitionCount = DiskEntry->LayoutBuffer->PartitionCount;

    /* Set the new disk layout and retrieve its updated version with possibly modified partition numbers */
    BufferSize = sizeof(DRIVE_LAYOUT_INFORMATION) +
                 ((PartitionCount - 1) * sizeof(PARTITION_INFORMATION));
    Status = NtDeviceIoControlFile(FileHandle,
                                   NULL,
                                   NULL,
                                   NULL,
                                   &Iosb,
                                   IOCTL_DISK_SET_DRIVE_LAYOUT,
                                   DiskEntry->LayoutBuffer,
                                   BufferSize,
                                   DiskEntry->LayoutBuffer,
                                   BufferSize);
    NtClose(FileHandle);

    /*
     * IOCTL_DISK_SET_DRIVE_LAYOUT calls IoWritePartitionTable(), which converts
     * DiskEntry->LayoutBuffer->PartitionCount into a partition *table* count,
     * where such a table is expected to enumerate up to 4 partitions:
     * partition *table* count == ROUND_UP(PartitionCount, 4) / 4 .
     * Due to this we need to restore the original PartitionCount number.
     */
    DiskEntry->LayoutBuffer->PartitionCount = PartitionCount;

    /* Check whether the IOCTL_DISK_SET_DRIVE_LAYOUT call succeeded */
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("IOCTL_DISK_SET_DRIVE_LAYOUT failed (Status 0x%08lx)\n", Status);
        return Status;
    }

#ifdef DUMP_PARTITION_TABLE
    DumpPartitionTable(DiskEntry);
#endif

    /* Update the partition numbers */

    /* Update the primary partition table */
    for (ListEntry = DiskEntry->PrimaryPartListHead.Flink;
         ListEntry != &DiskEntry->PrimaryPartListHead;
         ListEntry = ListEntry->Flink)
    {
        PartEntry = CONTAINING_RECORD(ListEntry, PARTENTRY, ListEntry);

        if (PartEntry->IsPartitioned)
        {
            PartitionInfo = &DiskEntry->LayoutBuffer->PartitionEntry[PartEntry->PartitionIndex];
            PartEntry->PartitionNumber = PartitionInfo->PartitionNumber;
        }
    }

    /* Update the logical partition table */
    for (ListEntry = DiskEntry->LogicalPartListHead.Flink;
         ListEntry != &DiskEntry->LogicalPartListHead;
         ListEntry = ListEntry->Flink)
    {
        PartEntry = CONTAINING_RECORD(ListEntry, PARTENTRY, ListEntry);

        if (PartEntry->IsPartitioned)
        {
            PartitionInfo = &DiskEntry->LayoutBuffer->PartitionEntry[PartEntry->PartitionIndex];
            PartEntry->PartitionNumber = PartitionInfo->PartitionNumber;
        }
    }

    //
    // NOTE: Originally (see r40437), we used to install here also a new MBR
    // for this disk (by calling InstallMbrBootCodeToDisk), only if:
    // DiskEntry->NewDisk == TRUE and DiskEntry->BiosDiskNumber == 0.
    // Then after that, both DiskEntry->NewDisk and DiskEntry->NoMbr were set
    // to FALSE. In the other place (in usetup.c) where InstallMbrBootCodeToDisk
    // was called too, the installation test was modified by checking whether
    // DiskEntry->NoMbr was TRUE (instead of NewDisk).
    //

    // DiskEntry->Dirty = FALSE;

    return Status;
}

BOOLEAN
WritePartitionsToDisk(
    IN PPARTLIST List)
{
    PLIST_ENTRY Entry;
    PDISKENTRY DiskEntry;

    if (List == NULL)
        return TRUE;

    for (Entry = List->DiskListHead.Flink;
         Entry != &List->DiskListHead;
         Entry = Entry->Flink)
    {
        DiskEntry = CONTAINING_RECORD(Entry, DISKENTRY, ListEntry);

        if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
        {
            DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
            continue;
        }

        if (DiskEntry->Dirty != FALSE)
        {
            WritePartitions(List, DiskEntry);
            DiskEntry->Dirty = FALSE;
        }
    }

    return TRUE;
}

BOOLEAN
SetMountedDeviceValue(
    IN WCHAR Letter,
    IN ULONG Signature,
    IN LARGE_INTEGER StartingOffset)
{
    OBJECT_ATTRIBUTES ObjectAttributes;
    WCHAR ValueNameBuffer[16];
    UNICODE_STRING KeyName = RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\MountedDevices");
    UNICODE_STRING ValueName;
    REG_DISK_MOUNT_INFO MountInfo;
    NTSTATUS Status;
    HANDLE KeyHandle;

    RtlStringCchPrintfW(ValueNameBuffer, ARRAYSIZE(ValueNameBuffer),
                        L"\\DosDevices\\%c:", Letter);
    RtlInitUnicodeString(&ValueName, ValueNameBuffer);

    InitializeObjectAttributes(&ObjectAttributes,
                               &KeyName,
                               OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);

    Status =  NtOpenKey(&KeyHandle,
                        KEY_ALL_ACCESS,
                        &ObjectAttributes);
    if (!NT_SUCCESS(Status))
    {
        Status = NtCreateKey(&KeyHandle,
                             KEY_ALL_ACCESS,
                             &ObjectAttributes,
                             0,
                             NULL,
                             REG_OPTION_NON_VOLATILE,
                             NULL);
    }

    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtCreateKey() failed (Status %lx)\n", Status);
        return FALSE;
    }

    MountInfo.Signature = Signature;
    MountInfo.StartingOffset = StartingOffset;
    Status = NtSetValueKey(KeyHandle,
                           &ValueName,
                           0,
                           REG_BINARY,
                           (PVOID)&MountInfo,
                           sizeof(MountInfo));
    NtClose(KeyHandle);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("NtSetValueKey() failed (Status %lx)\n", Status);
        return FALSE;
    }

    return TRUE;
}

BOOLEAN
SetMountedDeviceValues(
    IN PPARTLIST List)
{
    PLIST_ENTRY Entry1, Entry2;
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;
    LARGE_INTEGER StartingOffset;

    if (List == NULL)
        return FALSE;

    for (Entry1 = List->DiskListHead.Flink;
         Entry1 != &List->DiskListHead;
         Entry1 = Entry1->Flink)
    {
        DiskEntry = CONTAINING_RECORD(Entry1,
                                      DISKENTRY,
                                      ListEntry);

        if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
        {
            DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
            continue;
        }

        for (Entry2 = DiskEntry->PrimaryPartListHead.Flink;
             Entry2 != &DiskEntry->PrimaryPartListHead;
             Entry2 = Entry2->Flink)
        {
            PartEntry = CONTAINING_RECORD(Entry2, PARTENTRY, ListEntry);
            if (PartEntry->IsPartitioned)
            {
                /* Assign a "\DosDevices\#:" mount point to this partition */
                if (PartEntry->DriveLetter)
                {
                    StartingOffset.QuadPart = PartEntry->StartSector.QuadPart * DiskEntry->BytesPerSector;
                    if (!SetMountedDeviceValue(PartEntry->DriveLetter,
                                               DiskEntry->LayoutBuffer->Signature,
                                               StartingOffset))
                    {
                        return FALSE;
                    }
                }
            }
        }

        for (Entry2 = DiskEntry->LogicalPartListHead.Flink;
             Entry2 != &DiskEntry->LogicalPartListHead;
             Entry2 = Entry2->Flink)
        {
            PartEntry = CONTAINING_RECORD(Entry2, PARTENTRY, ListEntry);
            if (PartEntry->IsPartitioned)
            {
                /* Assign a "\DosDevices\#:" mount point to this partition */
                if (PartEntry->DriveLetter)
                {
                    StartingOffset.QuadPart = PartEntry->StartSector.QuadPart * DiskEntry->BytesPerSector;
                    if (!SetMountedDeviceValue(PartEntry->DriveLetter,
                                               DiskEntry->LayoutBuffer->Signature,
                                               StartingOffset))
                    {
                        return FALSE;
                    }
                }
            }
        }
    }

    return TRUE;
}

VOID
SetPartitionType(
    IN PPARTENTRY PartEntry,
    IN UCHAR PartitionType)
{
    PDISKENTRY DiskEntry = PartEntry->DiskEntry;

    PartEntry->PartitionType = PartitionType;

    DiskEntry->Dirty = TRUE;
    DiskEntry->LayoutBuffer->PartitionEntry[PartEntry->PartitionIndex].PartitionType = PartitionType;
    DiskEntry->LayoutBuffer->PartitionEntry[PartEntry->PartitionIndex].RecognizedPartition = IsRecognizedPartition(PartitionType);
    DiskEntry->LayoutBuffer->PartitionEntry[PartEntry->PartitionIndex].RewritePartition = TRUE;
}

ERROR_NUMBER
PrimaryPartitionCreationChecks(
    IN PPARTLIST List)
{
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;

    DiskEntry = List->CurrentDisk;
    PartEntry = List->CurrentPartition;

    if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
    {
        DPRINT1("GPT-partitioned disk detected, not currently supported by SETUP!\n");
        return ERROR_WARN_PARTITION;
    }

    /* Fail if the partition is already in use */
    if (PartEntry->IsPartitioned)
        return ERROR_NEW_PARTITION;

    /* Fail if there are already 4 primary partitions in the list */
    if (GetPrimaryPartitionCount(DiskEntry) >= 4)
        return ERROR_PARTITION_TABLE_FULL;

    return ERROR_SUCCESS;
}

ERROR_NUMBER
ExtendedPartitionCreationChecks(
    IN PPARTLIST List)
{
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;

    DiskEntry = List->CurrentDisk;
    PartEntry = List->CurrentPartition;

    if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
    {
        DPRINT1("GPT-partitioned disk detected, not currently supported by SETUP!\n");
        return ERROR_WARN_PARTITION;
    }

    /* Fail if the partition is already in use */
    if (PartEntry->IsPartitioned)
        return ERROR_NEW_PARTITION;

    /* Fail if there are already 4 primary partitions in the list */
    if (GetPrimaryPartitionCount(DiskEntry) >= 4)
        return ERROR_PARTITION_TABLE_FULL;

    /* Fail if there is another extended partition in the list */
    if (DiskEntry->ExtendedPartition != NULL)
        return ERROR_ONLY_ONE_EXTENDED;

    return ERROR_SUCCESS;
}

ERROR_NUMBER
LogicalPartitionCreationChecks(
    IN PPARTLIST List)
{
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;

    DiskEntry = List->CurrentDisk;
    PartEntry = List->CurrentPartition;

    if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
    {
        DPRINT1("GPT-partitioned disk detected, not currently supported by SETUP!\n");
        return ERROR_WARN_PARTITION;
    }

    /* Fail if the partition is already in use */
    if (PartEntry->IsPartitioned)
        return ERROR_NEW_PARTITION;

    return ERROR_SUCCESS;
}

BOOLEAN
GetNextUnformattedPartition(
    IN PPARTLIST List,
    OUT PDISKENTRY *pDiskEntry OPTIONAL,
    OUT PPARTENTRY *pPartEntry)
{
    PLIST_ENTRY Entry1, Entry2;
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;

    for (Entry1 = List->DiskListHead.Flink;
         Entry1 != &List->DiskListHead;
         Entry1 = Entry1->Flink)
    {
        DiskEntry = CONTAINING_RECORD(Entry1,
                                      DISKENTRY,
                                      ListEntry);

        if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
        {
            DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
            continue;
        }

        for (Entry2 = DiskEntry->PrimaryPartListHead.Flink;
             Entry2 != &DiskEntry->PrimaryPartListHead;
             Entry2 = Entry2->Flink)
        {
            PartEntry = CONTAINING_RECORD(Entry2, PARTENTRY, ListEntry);
            if (PartEntry->IsPartitioned && PartEntry->New)
            {
                ASSERT(DiskEntry == PartEntry->DiskEntry);
                if (pDiskEntry) *pDiskEntry = DiskEntry;
                *pPartEntry = PartEntry;
                return TRUE;
            }
        }

        for (Entry2 = DiskEntry->LogicalPartListHead.Flink;
             Entry2 != &DiskEntry->LogicalPartListHead;
             Entry2 = Entry2->Flink)
        {
            PartEntry = CONTAINING_RECORD(Entry2, PARTENTRY, ListEntry);
            if (PartEntry->IsPartitioned && PartEntry->New)
            {
                ASSERT(DiskEntry == PartEntry->DiskEntry);
                if (pDiskEntry) *pDiskEntry = DiskEntry;
                *pPartEntry = PartEntry;
                return TRUE;
            }
        }
    }

    if (pDiskEntry) *pDiskEntry = NULL;
    *pPartEntry = NULL;

    return FALSE;
}

BOOLEAN
GetNextUncheckedPartition(
    IN PPARTLIST List,
    OUT PDISKENTRY *pDiskEntry OPTIONAL,
    OUT PPARTENTRY *pPartEntry)
{
    PLIST_ENTRY Entry1, Entry2;
    PDISKENTRY DiskEntry;
    PPARTENTRY PartEntry;

    for (Entry1 = List->DiskListHead.Flink;
         Entry1 != &List->DiskListHead;
         Entry1 = Entry1->Flink)
    {
        DiskEntry = CONTAINING_RECORD(Entry1,
                                      DISKENTRY,
                                      ListEntry);

        if (DiskEntry->DiskStyle == PARTITION_STYLE_GPT)
        {
            DPRINT("GPT-partitioned disk detected, not currently supported by SETUP!\n");
            continue;
        }

        for (Entry2 = DiskEntry->PrimaryPartListHead.Flink;
             Entry2 != &DiskEntry->PrimaryPartListHead;
             Entry2 = Entry2->Flink)
        {
            PartEntry = CONTAINING_RECORD(Entry2, PARTENTRY, ListEntry);
            if (PartEntry->NeedsCheck == TRUE)
            {
                ASSERT(DiskEntry == PartEntry->DiskEntry);
                if (pDiskEntry) *pDiskEntry = DiskEntry;
                *pPartEntry = PartEntry;
                return TRUE;
            }
        }

        for (Entry2 = DiskEntry->LogicalPartListHead.Flink;
             Entry2 != &DiskEntry->LogicalPartListHead;
             Entry2 = Entry2->Flink)
        {
            PartEntry = CONTAINING_RECORD(Entry2, PARTENTRY, ListEntry);
            if (PartEntry->NeedsCheck == TRUE)
            {
                ASSERT(DiskEntry == PartEntry->DiskEntry);
                if (pDiskEntry) *pDiskEntry = DiskEntry;
                *pPartEntry = PartEntry;
                return TRUE;
            }
        }
    }

    if (pDiskEntry) *pDiskEntry = NULL;
    *pPartEntry = NULL;

    return FALSE;
}

/* EOF */
