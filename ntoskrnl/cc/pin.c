/*
 * COPYRIGHT:       See COPYING in the top level directory
 * PROJECT:         ReactOS kernel
 * FILE:            ntoskrnl/cc/pin.c
 * PURPOSE:         Implements cache managers pinning interface
 *
 * PROGRAMMERS:     ?
                    Pierre Schweitzer (pierre@reactos.org)
 */

/* INCLUDES ******************************************************************/

#include <ntoskrnl.h>
#define NDEBUG
#include <debug.h>

/* GLOBALS *******************************************************************/

extern NPAGED_LOOKASIDE_LIST iBcbLookasideList;

/* Counters:
 * - Number of calls to CcMapData that could wait
 * - Number of calls to CcMapData that couldn't wait
 * - Number of calls to CcPinRead that could wait
 * - Number of calls to CcPinRead that couldn't wait
 */
ULONG CcMapDataWait = 0;
ULONG CcMapDataNoWait = 0;
ULONG CcPinReadWait = 0;
ULONG CcPinReadNoWait = 0;

/* FUNCTIONS *****************************************************************/

/*
 * @implemented
 */
BOOLEAN
NTAPI
CcMapData (
    IN PFILE_OBJECT FileObject,
    IN PLARGE_INTEGER FileOffset,
    IN ULONG Length,
    IN ULONG Flags,
    OUT PVOID *pBcb,
    OUT PVOID *pBuffer)
{
    LONGLONG ReadOffset;
    BOOLEAN Valid;
    PROS_SHARED_CACHE_MAP SharedCacheMap;
    PROS_VACB Vacb;
    NTSTATUS Status;
    PINTERNAL_BCB iBcb;
    LONGLONG ROffset;

    DPRINT("CcMapData(FileObject 0x%p, FileOffset %I64x, Length %lu, Flags 0x%lx,"
           " pBcb 0x%p, pBuffer 0x%p)\n", FileObject, FileOffset->QuadPart,
           Length, Flags, pBcb, pBuffer);

    if (Flags & MAP_WAIT)
    {
        ++CcMapDataWait;
    }
    else
    {
        ++CcMapDataNoWait;
    }

    ReadOffset = FileOffset->QuadPart;

    ASSERT(FileObject);
    ASSERT(FileObject->SectionObjectPointer);
    ASSERT(FileObject->SectionObjectPointer->SharedCacheMap);

    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;
    ASSERT(SharedCacheMap);

    DPRINT("SectionSize %I64x, FileSize %I64x\n",
           SharedCacheMap->SectionSize.QuadPart,
           SharedCacheMap->FileSize.QuadPart);

    if (ReadOffset % VACB_MAPPING_GRANULARITY + Length > VACB_MAPPING_GRANULARITY)
    {
        CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx -> FALSE\n",
            FileObject, FileOffset, Length, Flags);
        ExRaiseStatus(STATUS_INVALID_PARAMETER);
        return FALSE;
    }

    ROffset = ROUND_DOWN(ReadOffset, VACB_MAPPING_GRANULARITY);
    Status = CcRosRequestVacb(SharedCacheMap,
                              ROffset,
                              pBuffer,
                              &Valid,
                              &Vacb);
    if (!NT_SUCCESS(Status))
    {
        CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx -> FALSE\n",
            FileObject, FileOffset, Length, Flags);
        ExRaiseStatus(Status);
        return FALSE;
    }

    if (!Valid)
    {
        if (!(Flags & MAP_WAIT))
        {
            CcRosReleaseVacb(SharedCacheMap, Vacb, FALSE, FALSE, FALSE);
            CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx -> FALSE\n",
                FileObject, FileOffset, Length, Flags);
            return FALSE;
        }

        Status = CcReadVirtualAddress(Vacb);
        if (!NT_SUCCESS(Status))
        {
            CcRosReleaseVacb(SharedCacheMap, Vacb, FALSE, FALSE, FALSE);
            CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx -> FALSE\n",
                FileObject, FileOffset, Length, Flags);
            ExRaiseStatus(Status);
            return FALSE;
        }
    }

    *pBuffer = (PUCHAR)*pBuffer + ReadOffset % VACB_MAPPING_GRANULARITY;
    iBcb = ExAllocateFromNPagedLookasideList(&iBcbLookasideList);
    if (iBcb == NULL)
    {
        CcRosReleaseVacb(SharedCacheMap, Vacb, TRUE, FALSE, FALSE);
        CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx -> FALSE\n",
            FileObject, FileOffset, Length, Flags);
        ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
        return FALSE;
    }

    RtlZeroMemory(iBcb, sizeof(*iBcb));
    iBcb->PFCB.NodeTypeCode = 0xDE45; /* Undocumented (CAPTIVE_PUBLIC_BCB_NODETYPECODE) */
    iBcb->PFCB.NodeByteSize = sizeof(PUBLIC_BCB);
    iBcb->PFCB.MappedLength = Length;
    iBcb->PFCB.MappedFileOffset = *FileOffset;
    iBcb->Vacb = Vacb;
    iBcb->Dirty = FALSE;
    iBcb->Pinned = FALSE;
    iBcb->RefCount = 1;
    ExInitializeResourceLite(&iBcb->Lock);
    *pBcb = (PVOID)iBcb;

    CCTRACE(CC_API_DEBUG, "FileObject=%p FileOffset=%p Length=%lu Flags=0x%lx -> TRUE Bcb=%p\n",
        FileObject, FileOffset, Length, Flags, iBcb);
    return TRUE;
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
CcPinMappedData (
    IN	PFILE_OBJECT FileObject,
    IN	PLARGE_INTEGER FileOffset,
    IN	ULONG Length,
    IN	ULONG Flags,
    OUT	PVOID * Bcb)
{
    PROS_SHARED_CACHE_MAP SharedCacheMap;

    CCTRACE(CC_API_DEBUG, "FileOffset=%p FileOffset=%p Length=%lu Flags=0x%lx\n",
        FileObject, FileOffset, Length, Flags);

    ASSERT(FileObject);
    ASSERT(FileObject->SectionObjectPointer);
    ASSERT(FileObject->SectionObjectPointer->SharedCacheMap);

    SharedCacheMap = FileObject->SectionObjectPointer->SharedCacheMap;
    ASSERT(SharedCacheMap);
    ASSERT(SharedCacheMap->PinAccess);

    /* no-op for current implementation. */
    return TRUE;
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
CcPinRead (
    IN	PFILE_OBJECT FileObject,
    IN	PLARGE_INTEGER FileOffset,
    IN	ULONG Length,
    IN	ULONG Flags,
    OUT	PVOID * Bcb,
    OUT	PVOID * Buffer)
{
    PINTERNAL_BCB iBcb;

    CCTRACE(CC_API_DEBUG, "FileOffset=%p FileOffset=%p Length=%lu Flags=0x%lx\n",
        FileObject, FileOffset, Length, Flags);

    if (Flags & PIN_WAIT)
    {
        ++CcPinReadWait;
    }
    else
    {
        ++CcPinReadNoWait;
    }

    if (CcMapData(FileObject, FileOffset, Length, Flags, Bcb, Buffer))
    {
        if (CcPinMappedData(FileObject, FileOffset, Length, Flags, Bcb))
        {
            iBcb = *Bcb;

            ASSERT(iBcb->Pinned == FALSE);

            iBcb->Pinned = TRUE;
            iBcb->Vacb->PinCount++;

            if (Flags & PIN_EXCLUSIVE)
            {
                ExAcquireResourceExclusiveLite(&iBcb->Lock, TRUE);
            }
            else
            {
                ExAcquireResourceSharedLite(&iBcb->Lock, TRUE);
            }

            return TRUE;
        }
        else
            CcUnpinData(*Bcb);
    }
    return FALSE;
}

/*
 * @unimplemented
 */
BOOLEAN
NTAPI
CcPreparePinWrite (
    IN	PFILE_OBJECT FileObject,
    IN	PLARGE_INTEGER FileOffset,
    IN	ULONG Length,
    IN	BOOLEAN Zero,
    IN	ULONG Flags,
    OUT	PVOID * Bcb,
    OUT	PVOID * Buffer)
{
    CCTRACE(CC_API_DEBUG, "FileOffset=%p FileOffset=%p Length=%lu Zero=%d Flags=0x%lx\n",
        FileObject, FileOffset, Length, Zero, Flags);

    /*
     * FIXME: This is function is similar to CcPinRead, but doesn't
     * read the data if they're not present. Instead it should just
     * prepare the VACBs and zero them out if Zero != FALSE.
     *
     * For now calling CcPinRead is better than returning error or
     * just having UNIMPLEMENTED here.
     */
    return CcPinRead(FileObject, FileOffset, Length, Flags, Bcb, Buffer);
}

/*
 * @implemented
 */
VOID NTAPI
CcSetDirtyPinnedData (
    IN PVOID Bcb,
    IN PLARGE_INTEGER Lsn)
{
    PINTERNAL_BCB iBcb = Bcb;

    CCTRACE(CC_API_DEBUG, "Bcb=%p Lsn=%p\n",
        Bcb, Lsn);

    iBcb->Dirty = TRUE;
}


/*
 * @implemented
 */
VOID NTAPI
CcUnpinData (
    IN PVOID Bcb)
{
    CCTRACE(CC_API_DEBUG, "Bcb=%p\n", Bcb);

    CcUnpinDataForThread(Bcb, (ERESOURCE_THREAD)PsGetCurrentThread());
}

/*
 * @unimplemented
 */
VOID
NTAPI
CcUnpinDataForThread (
    IN	PVOID Bcb,
    IN	ERESOURCE_THREAD ResourceThreadId)
{
    PINTERNAL_BCB iBcb = Bcb;

    CCTRACE(CC_API_DEBUG, "Bcb=%p ResourceThreadId=%lu\n", Bcb, ResourceThreadId);

    if (iBcb->Pinned)
    {
        ExReleaseResourceForThreadLite(&iBcb->Lock, ResourceThreadId);
        iBcb->Pinned = FALSE;
        iBcb->Vacb->PinCount--;
    }

    if (--iBcb->RefCount == 0)
    {
        CcRosReleaseVacb(iBcb->Vacb->SharedCacheMap,
                         iBcb->Vacb,
                         TRUE,
                         iBcb->Dirty,
                         FALSE);

        ExDeleteResourceLite(&iBcb->Lock);
        ExFreeToNPagedLookasideList(&iBcbLookasideList, iBcb);
    }
}

/*
 * @implemented
 */
VOID
NTAPI
CcRepinBcb (
    IN	PVOID Bcb)
{
    PINTERNAL_BCB iBcb = Bcb;

    CCTRACE(CC_API_DEBUG, "Bcb=%p\n", Bcb);

    iBcb->RefCount++;
}

/*
 * @unimplemented
 */
VOID
NTAPI
CcUnpinRepinnedBcb (
    IN	PVOID Bcb,
    IN	BOOLEAN WriteThrough,
    IN	PIO_STATUS_BLOCK IoStatus)
{
    PINTERNAL_BCB iBcb = Bcb;

    CCTRACE(CC_API_DEBUG, "Bcb=%p WriteThrough=%d\n", Bcb, WriteThrough);

    IoStatus->Status = STATUS_SUCCESS;
    if (--iBcb->RefCount == 0)
    {
        IoStatus->Information = 0;
        if (WriteThrough)
        {
            if (iBcb->Vacb->Dirty)
            {
                IoStatus->Status = CcRosFlushVacb(iBcb->Vacb);
            }
            else
            {
                IoStatus->Status = STATUS_SUCCESS;
            }
        }
        else
        {
            IoStatus->Status = STATUS_SUCCESS;
        }

        if (iBcb->Pinned)
        {
            ExReleaseResourceLite(&iBcb->Lock);
            iBcb->Pinned = FALSE;
            iBcb->Vacb->PinCount--;
            ASSERT(iBcb->Vacb->PinCount == 0);
        }

        CcRosReleaseVacb(iBcb->Vacb->SharedCacheMap,
                         iBcb->Vacb,
                         TRUE,
                         iBcb->Dirty,
                         FALSE);

        ExDeleteResourceLite(&iBcb->Lock);
        ExFreeToNPagedLookasideList(&iBcbLookasideList, iBcb);
    }
}
