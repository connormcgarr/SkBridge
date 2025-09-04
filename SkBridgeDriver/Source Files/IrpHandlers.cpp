/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeDriver/IrpHandlers.cpp
*
* @summary:   IRP handler routines.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#include "IrpHandlers.hpp"
#include "Shared.hpp"
#include "SkImplementations.hpp"
#include "Helpers.hpp"

PAGED_FILE()

//
// Helpers.cpp
//
extern bool g_KnownOffsetArrayInitialized;

/**
*
* @brief        Handle IRP_MJ_CREATE.
* @param[in]    DeviceObject - SkBridge DEVICE_OBJECT.
* @param[in]	Irp - Associated IRP.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleCreateMajorFunction (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/**
*
* @brief        Handle IRP_MJ_CLOSE.
* @param[in]    DeviceObject - SkBridge DEVICE_OBJECT.
* @param[in]	Irp - Associated IRP.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleCloseMajorFunction (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

/**
*
* @brief        Handle IRP_MJ_DEVICE_CONTROL.
* @param[in]    DeviceObject - SkBridge DEVICE_OBJECT.
* @param[in]	Irp - Associated IRP.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleIoctlMajorFunciton (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
{
    NTSTATUS status;
    ULONG ioctl;
    ULONG inBufferSize;
    ULONG outBufferSize;
    PIO_STACK_LOCATION irpStackLocation;
    PVOID buffer;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    UNREFERENCED_PARAMETER(DeviceObject);

    irpStackLocation = IoGetCurrentIrpStackLocation(Irp);

    NT_ASSERT(irpStackLocation != NULL);

    //
    // Default to nothing back to user mode.
    //
    Irp->IoStatus.Information = 0;

    status = STATUS_SUCCESS;
    inBufferSize = irpStackLocation->Parameters.DeviceIoControl.InputBufferLength;
    outBufferSize = irpStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
    buffer = Irp->AssociatedIrp.SystemBuffer;
    ioctl = irpStackLocation->Parameters.DeviceIoControl.IoControlCode;

    //
    // Validate
    //
    if (METHOD_FROM_CTL_CODE(ioctl) != METHOD_BUFFERED)
    {
        status = STATUS_INVALID_DEVICE_REQUEST;
        goto Exit;
    }

    if (buffer == NULL)
    {
        NT_ASSERT(buffer != NULL);
        goto Exit;
    }

    //
    // Handle the IOCTL
    //
    switch (ioctl)
    {
        case SKBRIDGE_IOCTL_DISPATCH_SECURE_CALL:
            //
            // Nothing matters if we are not initialized.
            //
            if (!g_KnownOffsetArrayInitialized)
            {
                NT_ASSERT(g_KnownOffsetArrayInitialized);
                DbgPrint("[-] Error! Known structure offset array has not been initialized.\n");
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            if (inBufferSize != sizeof(SKBRIDGE_SECURE_CALL_DATA))
            {
                NT_ASSERT(inBufferSize == sizeof(SKBRIDGE_SECURE_CALL_DATA));
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            if (outBufferSize != sizeof(SKBRIDGE_SECURE_CALL_DATA))
            {
                NT_ASSERT(outBufferSize == sizeof(SKBRIDGE_SECURE_CALL_DATA));
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            //
            // Issue the secure call to VTL 1
            //
            status = IssueSecureCall(buffer);
            if (!NT_SUCCESS(status))
            {
                goto Exit;
            }

            //
            // Copy this much data back to user-mode.
            //
            Irp->IoStatus.Information = sizeof(SKBRIDGE_SECURE_CALL_DATA);
            break;

        case SKBRIDGE_IOCTL_INIT_KERNEL_STRUCTS:
            if (g_KnownOffsetArrayInitialized)
            {
                //
                // No need to process if we are already initialized.
                //
                goto Exit;
            }

            if (inBufferSize != sizeof(SKBRIDGE_INIT_DATA))
            {
                NT_ASSERT(inBufferSize == sizeof(SKBRIDGE_INIT_DATA));
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            if (outBufferSize != 0)
            {
                NT_ASSERT(outBufferSize == 0);
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            //
            // We have to, unfortunately, access some "undocumented" structure offsets.
            // We do our best to try and let user-mode get the offsets from the symbols
            // and then ship them down to us.
            //
            InitializeSkBridgeOffsets(reinterpret_cast<PSKBRIDGE_INIT_DATA>(buffer));

            break;

        default:
            NT_ASSERT(FALSE);
            status = STATUS_INVALID_PARAMETER;
            break;
    }

Exit:
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}