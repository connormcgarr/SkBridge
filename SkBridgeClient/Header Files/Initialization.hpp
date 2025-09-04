/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeClient/Initialization.hpp
*
* @summary:   SkBridge initialization definitions.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#pragma once
#pragma once
#include <Windows.h>
#include <dbghelp.h>
#include <stdio.h>

//
// Enum of symbol types.
//
// From https://github.com/Microsoft/microsoft-pdb/blob/master/include/cvconst.h
//
enum SymTagEnum
{
    SymTagNull,
    SymTagExe,
    SymTagCompiland,
    SymTagCompilandDetails,
    SymTagCompilandEnv,
    SymTagFunction,
    SymTagBlock,
    SymTagData,
    SymTagAnnotation,
    SymTagLabel,
    SymTagPublicSymbol,
    SymTagUDT,
    SymTagEnum,
    SymTagFunctionType,
    SymTagPointerType,
    SymTagArrayType,
    SymTagBaseType,
    SymTagTypedef,
    SymTagBaseClass,
    SymTagFriend,
    SymTagFunctionArgType,
    SymTagFuncDebugStart,
    SymTagFuncDebugEnd,
    SymTagUsingNamespace,
    SymTagVTableShape,
    SymTagVTable,
    SymTagCustom,
    SymTagThunk,
    SymTagCustomType,
    SymTagManagedType,
    SymTagDimension,
    SymTagCallSite,
    SymTagInlineSite,
    SymTagBaseInterface,
    SymTagVectorType,
    SymTagMatrixType,
    SymTagHLSLType,
    SymTagCaller,
    SymTagCallee,
    SymTagExport,
    SymTagHeapAllocationSite,
    SymTagCoffGroup,
    SymTagMax
};

//
// Function prototypes
//
typedef
DWORD
(*SymGetOptions_T) ();

typedef
BOOL
(*SymInitializeW_T) (
    _In_ HANDLE hProcess,
    _In_opt_ PCWSTR UserSearchPath,
    _In_ BOOL fInvadeProcess
    );

typedef
DWORD
(*SymSetOptions_T) (
    _In_ DWORD SymOptions
    );

typedef
BOOL
(*SymCleanup_T) (
    _In_ HANDLE hProcess
    );

typedef
BOOL
(*SymSetSearchPathW_T) (
    _In_ HANDLE hProcess,
    _In_opt_ PCWSTR SearchPath
    );

typedef
DWORD64
(*SymLoadModuleExW_T) (
    _In_ HANDLE hProcess,
    _In_opt_ HANDLE hFile,
    _In_opt_ PCWSTR ImageName,
    _In_opt_ PCWSTR ModuleName,
    _In_ DWORD64 BaseOfDll,
    _In_ DWORD DllSize,
    _In_opt_ PMODLOAD_DATA Data,
    _In_ DWORD Flags
    );

typedef
BOOL
(*SymFromAddrW_T) (
    _In_ HANDLE hProcess,
    _In_ DWORD64 Address,
    _Out_opt_ PDWORD64 Displacement,
    _Inout_ PSYMBOL_INFOW Symbol
    );

typedef
BOOL
(*SymGetTypeFromNameW_T) (
    _In_ HANDLE hProcess,
    _In_ ULONG64 BaseOfDll,
    _In_ PCWSTR Name,
    _Inout_ PSYMBOL_INFOW Symbol
    );

typedef
BOOL
(*SymGetTypeInfo_T) (
    _In_ HANDLE hProcess,
    _In_ ULONG64 BaseOfDll,
    _In_ ULONG TypeId,
    _In_ IMAGEHLP_SYMBOL_TYPE_INFO GetType,
    _Out_ PVOID pInfo
    );

//
// Function definitions
//
bool
InitializeSkBridge ();

void
CleanupSymbols ();