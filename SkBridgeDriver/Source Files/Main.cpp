/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeDriver/Main.cpp
*
* @summary:   SkBridgeDriver entry point.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#include <ntddk.h>
#include <Wdmsec.h>
#include "Helpers.hpp"
#include "SkDefs.hpp"
#include "IrpHandlers.hpp"

PAGED_FILE()

/**
*
* @brief        DriverUnload routine for driver unloads.
* @param[in]    DriverObject - SkBridge DRIVER_OBJECT.
*
*/
static
_Function_class_(DRIVER_UNLOAD)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
void
DriverUnload (
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    if (DriverObject->DeviceObject != NULL)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
    }

    return;
}

/**
*
* @brief        SkBridgeDriver entry point.
* @param[in]    DriverObject - SkBridge DRIVER_OBJECT.
* @param[in]	RegistryPath - Pointer to string with driver registry key.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\SkBridge");

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    status = STATUS_SUCCESS;

    DriverObject->DriverUnload = DriverUnload;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    status = IoCreateDeviceSecure(DriverObject,
                                  0,
                                  &deviceName,
                                  FILE_DEVICE_UNKNOWN,
                                  FILE_DEVICE_SECURE_OPEN,
                                  FALSE,
                                  &SDDL_DEVOBJ_SYS_ALL_ADM_ALL,
                                  NULL,
                                  &deviceObject);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    DriverObject->DeviceObject = deviceObject;

    //
    // Specify which IRPs we will handle.
    //
    DriverObject->MajorFunction[IRP_MJ_CREATE] = HandleCreateMajorFunction;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = HandleCloseMajorFunction;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = HandleIoctlMajorFunciton;

    deviceObject->Flags |= DO_BUFFERED_IO;
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

Exit:
    return status;
}