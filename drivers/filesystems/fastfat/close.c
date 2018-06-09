/*
 * COPYRIGHT:        See COPYING in the top level directory
 * PROJECT:          ReactOS kernel
 * FILE:             drivers/filesystems/fastfat/close.c
 * PURPOSE:          VFAT Filesystem
 * PROGRAMMER:       Jason Filby (jasonfilby@yahoo.com)
 */

/* INCLUDES *****************************************************************/

#include "vfat.h"

#define NDEBUG
#include <debug.h>

/* FUNCTIONS ****************************************************************/

/*
 * FUNCTION: Closes a file
 */
NTSTATUS
VfatCloseFile(
    PDEVICE_EXTENSION DeviceExt,
    PFILE_OBJECT FileObject)
{
    PVFATFCB pFcb;
    PVFATCCB pCcb;
    BOOLEAN IsVolume;
    NTSTATUS Status = STATUS_SUCCESS;

    DPRINT("VfatCloseFile(DeviceExt %p, FileObject %p)\n",
            DeviceExt, FileObject);

    /* FIXME : update entry in directory? */
    pCcb = (PVFATCCB) (FileObject->FsContext2);
    pFcb = (PVFATFCB) (FileObject->FsContext);

    if (pFcb == NULL)
    {
        return STATUS_SUCCESS;
    }

    IsVolume = BooleanFlagOn(pFcb->Flags, FCB_IS_VOLUME);
    if (IsVolume)
    {
        DPRINT("Volume\n");
        FileObject->FsContext2 = NULL;
    }
    else
    {
        if (pFcb->OpenHandleCount == 0 && BooleanFlagOn(pFcb->Flags, FCB_CACHE_INITIALIZED))
        {
            PFILE_OBJECT tmpFileObject;
            tmpFileObject = pFcb->FileObject;
            if (tmpFileObject != NULL)
            {
                pFcb->FileObject = NULL;
                CcUninitializeCacheMap(tmpFileObject, NULL, NULL);
                ClearFlag(pFcb->Flags, FCB_CACHE_INITIALIZED);
                ObDereferenceObject(tmpFileObject);
            }
        }

#ifdef KDBG
        pFcb->Flags |= FCB_CLOSED;
#endif
        vfatReleaseFCB(DeviceExt, pFcb);
    }

    FileObject->FsContext2 = NULL;
    FileObject->FsContext = NULL;
    FileObject->SectionObjectPointer = NULL;

    if (pCcb)
    {
        vfatDestroyCCB(pCcb);
    }

#ifdef ENABLE_SWAPOUT
    if (IsVolume && DeviceExt->OpenHandleCount == 0)
    {
        VfatCheckForDismount(DeviceExt, FALSE);
    }
#endif

    return Status;
}

/*
 * FUNCTION: Closes a file
 */
NTSTATUS
VfatClose(
    PVFAT_IRP_CONTEXT IrpContext)
{
    NTSTATUS Status;

    DPRINT("VfatClose(DeviceObject %p, Irp %p)\n", IrpContext->DeviceObject, IrpContext->Irp);

    if (IrpContext->DeviceObject == VfatGlobalData->DeviceObject)
    {
        DPRINT("Closing file system\n");
        IrpContext->Irp->IoStatus.Information = 0;
        return STATUS_SUCCESS;
    }
    if (!ExAcquireResourceExclusiveLite(&IrpContext->DeviceExt->DirResource, BooleanFlagOn(IrpContext->Flags, IRPCONTEXT_CANWAIT)))
    {
        return VfatMarkIrpContextForQueue(IrpContext);
    }

    Status = VfatCloseFile(IrpContext->DeviceExt, IrpContext->FileObject);
    ExReleaseResourceLite(&IrpContext->DeviceExt->DirResource);

    IrpContext->Irp->IoStatus.Information = 0;

    return Status;
}

/* EOF */
