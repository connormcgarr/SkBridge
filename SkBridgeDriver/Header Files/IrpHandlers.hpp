/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeDriver/IrpHandlers.hpp
*
* @summary:   Various IRP-related definitions.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#pragma once
#include <ntddk.h>

//
// Functions
//
_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleCreateMajorFunction (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleCloseMajorFunction (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );

_IRQL_requires_(PASSIVE_LEVEL)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS
HandleIoctlMajorFunciton (
    _Inout_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    );