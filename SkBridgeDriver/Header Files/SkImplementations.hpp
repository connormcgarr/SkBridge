/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeDriver/SkImplementations.cpp
*
* @summary:   Secure call implementation header.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#pragma once
#include <ntddk.h>
#include "SkDefs.hpp"
#include "Shared.hpp"

//
// Helper struct for secure calls issued over APC.
//
typedef struct _SECURE_CALL_APC_ARGS
{
    SECURE_CALL_ARGS SecureCallArgs;
    ULONG SecureCallType;
    NTSTATUS Status;
} SECURE_CALL_APC_ARGS, *PSECURE_CALL_APC_ARGS;

//
// Function definitions
//
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
IssueSecureCall (
    _In_ PVOID SecureCallData
    );