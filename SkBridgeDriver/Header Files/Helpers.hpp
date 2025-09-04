/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeDriver/Helpers.hpp
*
* @summary:   Various helper routine definitions.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#pragma once
#include <ntddk.h>
#include "Shared.hpp"
#include "SkDefs.hpp"

#define PAGED_FILE()                \
    __pragma(bss_seg("PAGEBBS"))    \
    __pragma(code_seg("PAGE"))      \
    __pragma(data_seg("PAGEDATA"))  \
    __pragma(const_seg("PAGERO"))

#define MY_POOL_TAG 0x1337

//
// System Informer
//
typedef struct _NON_PAGED_DEBUG_INFO NON_PAGED_DEBUG_INFO, * PNON_PAGED_DEBUG_INFO;

typedef struct _KLDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    PVOID ExceptionTable;
    ULONG ExceptionTableSize;
    PVOID GpValue;
    PNON_PAGED_DEBUG_INFO NonPagedDebugInfo;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    union
    {
        USHORT SignatureLevel : 4;
        USHORT SignatureType : 3;
        USHORT Frozen : 2;
        USHORT HotPatch : 1;
        USHORT Unused : 6;
        USHORT EntireField;
    } u1;
    PVOID SectionPointer;
    ULONG CheckSum;
    ULONG CoverageSectionSize;
    PVOID CoverageSection;
    PVOID LoadedImports;
    union
    {
        PVOID Spare;
        struct _KLDR_DATA_TABLE_ENTRY* NtDataTableEntry; // win11
    };
    ULONG SizeOfImageNotRounded;
    ULONG TimeDateStamp;
} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

typedef enum _KAPC_ENVIRONMENT
{
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

typedef
_Function_class_(KNORMAL_ROUTINE)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
NTAPI
KNORMAL_ROUTINE (
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2
    );
typedef KNORMAL_ROUTINE *PKNORMAL_ROUTINE;

typedef
_Function_class_(KRUNDOWN_ROUTINE)
_IRQL_requires_(PASSIVE_LEVEL)
_IRQL_requires_same_
VOID
NTAPI
KRUNDOWN_ROUTINE (
    _In_ PRKAPC Apc
    );
typedef KRUNDOWN_ROUTINE *PKRUNDOWN_ROUTINE;

typedef
_Function_class_(KKERNEL_ROUTINE)
_IRQL_requires_(APC_LEVEL)
_IRQL_requires_same_
VOID
NTAPI
KKERNEL_ROUTINE (
    _In_ PRKAPC Apc,
    _Inout_ _Deref_pre_maybenull_ PKNORMAL_ROUTINE *NormalRoutine,
    _Inout_ _Deref_pre_maybenull_ PVOID* NormalContext,
    _Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument1,
    _Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument2
    );

typedef KKERNEL_ROUTINE *PKKERNEL_ROUTINE;

typedef
NTSTATUS
(__fastcall* VslpEnterIumSecureMode_t)(
    _In_ ULONG Unknown,
    _In_ ULONG SecureCallNumber,
    _In_ ULONG Unknown1,
    _In_ PVOID SecureCallArguments
    );

EXTERN_C_START
NTKERNELAPI
VOID
KeInitializeApc (
    _Out_ PKAPC Apc,
    _In_ PKTHREAD Thread,
    _In_ KAPC_ENVIRONMENT Environment,
    _In_opt_ PKKERNEL_ROUTINE KernelRoutine,
    _In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
    _In_opt_ PKNORMAL_ROUTINE NormalRoutine,
    _In_ KPROCESSOR_MODE ProcessorMode,
    _In_opt_ PVOID NormalContext
    );

NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc (
    _Inout_ PRKAPC Apc,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_ KPRIORITY Increment
    );

PVOID
RtlPcToFileHeader (
    _In_ PVOID PcValue,
    _Out_ PVOID* BaseOfImage
    );
EXTERN_C_END

//
// Function definitions
//
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SkBridgeDataToSecureCallParameters (
    _In_ PSKBRIDGE_SECURE_CALL_DATA SecureCallData,
    _Out_ PSECURE_CALL_ARGS SecureCallArgs
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
CleanupSecureCallResources (
    _In_ PSKBRIDGE_SECURE_CALL_DATA SecureCallData,
    _In_ PSECURE_CALL_ARGS SecureCallArgs
    );

_IRQL_requires_max_(PASSIVE_LEVEL)
void
InitializeSkBridgeOffsets (
    _In_ PSKBRIDGE_INIT_DATA InitData
    );