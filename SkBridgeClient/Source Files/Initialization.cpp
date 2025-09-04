/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeClient/Initialization.cpp
*
* @summary:   Initializes SkBridge crucial functionality, like secure calls and structure offsets.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#include "Shared.hpp"
#include "Helpers.hpp"
#include "Initialization.hpp"
#include <iostream>
#include <string.h>
#include <unordered_map>

//
// "Base" address of NT for symbols
//
static ULONG_PTR k_NtBaseAddress = 0;

//
// Functionality for symbols
//
SymGetOptions_T SymGetOptions_I = NULL;
SymInitializeW_T SymInitializeW_I = NULL;
SymSetOptions_T SymSetOptions_I = NULL;
SymCleanup_T SymCleanup_I = NULL;
SymSetSearchPathW_T SymSetSearchPathW_I = NULL;
SymLoadModuleExW_T SymLoadModuleExW_I = NULL;
SymFromAddrW_T SymFromAddrW_I = NULL;
SymGetTypeFromNameW_T SymGetTypeFromNameW_I = NULL;
SymGetTypeInfo_T SymGetTypeInfo_I = NULL;

/**
*
* @brief        Creates a mapping of secure call numbers to their nt!_SKSERVICE enum value.
*
*/
static
bool
CreateListOfValidSecureCalls ()
{
    bool result;
    SYMBOL_INFOW symbol;
    ULONG childrenCount;
    TI_FINDCHILDREN_PARAMS* childrenSyms;
    SIZE_T childrenSymSize;
    wchar_t* childSymName;
    ULONG index;
    VARIANT secureCallValue;

    result = false;
    childrenCount = 0;
    childrenSyms = NULL;
    childrenSymSize = 0;
    childSymName = NULL;
    index = 0;

    RtlZeroMemory(&symbol, sizeof(symbol));
    RtlZeroMemory(&secureCallValue, sizeof(secureCallValue));

    symbol.SizeOfStruct = sizeof(SYMBOL_INFOW);
    symbol.MaxNameLen = 0;

    if (SymGetTypeFromNameW_I(GetCurrentProcess(),
                              k_NtBaseAddress,
                              L"_SKSERVICE",
                              &symbol) == FALSE)
    {
        wprintf(L"[-] Error! SymGetTypeFromNameW failed in CreateListOfValidSecureCalls. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    //
    // Preserve the index
    //
    index = symbol.TypeIndex;

    if (SymGetTypeInfo_I(GetCurrentProcess(),
                         k_NtBaseAddress,
                         index,
                         TI_GET_CHILDRENCOUNT,
                         &childrenCount) == FALSE)
    {
        wprintf(L"[-] Error! SymGetTypeInfo_I failed in CreateListOfValidSecureCalls. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    childrenSymSize = sizeof(TI_FINDCHILDREN_PARAMS) + childrenCount * sizeof(ULONG);
    childrenSyms = static_cast<TI_FINDCHILDREN_PARAMS*>(malloc(childrenSymSize));
    if (childrenSyms == NULL)
    {
        wprintf(L"[-] Error! malloc failed in CreateListOfValidSecureCalls. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    RtlZeroMemory(childrenSyms, childrenSymSize);

    childrenSyms->Count = childrenCount;
    childrenSyms->Start = 0;

    if (SymGetTypeInfo_I(GetCurrentProcess(),
                         k_NtBaseAddress,
                         index,
                         TI_FINDCHILDREN,
                         childrenSyms) == FALSE)
    {
        wprintf(L"[-] Error! SymGetTypeInfo_I failed in CreateListOfValidSecureCalls. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    for (ULONG i = 0; i < childrenSyms->Count; i++)
    {
        if (SymGetTypeInfo_I(GetCurrentProcess(),
                             k_NtBaseAddress,
                             childrenSyms->ChildId[i],
                             TI_GET_SYMNAME,
                             &childSymName) == FALSE)
        {
            wprintf(L"[-] Error! SymGetTypeInfo_I failed in CreateListOfValidSecureCalls. (GLE: %d)\n", GetLastError());
            goto Exit;
        }

        if (SymGetTypeInfo_I(GetCurrentProcess(),
                             k_NtBaseAddress,
                             childrenSyms->ChildId[i],
                             TI_GET_VALUE,
                             &secureCallValue) == FALSE)
        {
            wprintf(L"[-] Error! SymGetTypeInfo_I failed in CreateListOfValidSecureCalls. (GLE: %d)\n", GetLastError());
            goto Exit;
        }

        AddToKnownSecureCalls(childSymName, secureCallValue.ulVal);

        childSymName = NULL;
    }

    result = true;

Exit:
    if (childrenSyms != NULL)
    {
        free(childrenSyms);
    }

    return result;
}

/**
*
* @brief        Initializes all symbol-related functionality.
* @return       true on success, otherwise false.
*
*/
static
bool
InitializeSymbols ()
{
    bool result;
    HMODULE dbgHelp;
    DWORD symOptions;
    BOOL res;
    ULONG size;
    ULONG neededSize;
    std::wstring dbgHelpPath;
    wchar_t* currentDirectory;

    result = false;
    symOptions = 0;
    res = FALSE;
    size = 0;
    neededSize = 0;
    currentDirectory = NULL;

    neededSize = GetCurrentDirectoryW(0, NULL);
    if (neededSize == 0)
    {
        wprintf(L"[-] Error! GetCurrentDirectoryW failed in InitializeSymbols. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    size = (neededSize * sizeof(wchar_t) + sizeof(UNICODE_NULL));
    
    currentDirectory = static_cast<wchar_t*>(malloc(size));
    if (currentDirectory == NULL)
    {
        wprintf(L"[-] Error! malloc failed in InitializeSymbols. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    if (GetCurrentDirectoryW(neededSize,
                             currentDirectory) == 0)
    {
        wprintf(L"[-] Error! GetCurrentDirectoryW failed in InitializeSymbols. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    //
    // Get the relative path to dbghelp
    //
    dbgHelpPath = std::wstring(currentDirectory);
    dbgHelpPath.append(L"\\dbghelp.dll");

    dbgHelp = LoadLibraryW(dbgHelpPath.c_str());
    if (dbgHelp == NULL)
    {
        wprintf(L"[-] Error! LoadLibraryW failed in InitializeSymbols. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    //
    // Resolve all of the functions. The built-in dbghelp is broken because of its implicit load
    // of symsrv.dll (which doesn't exist in System32). We ship the DLLs from the SDK and, therefore,
    // need to resolve our target functions.
    //
    SymGetOptions_I = reinterpret_cast<SymGetOptions_T>(GetProcAddress(dbgHelp, "SymGetOptions"));
    SymInitializeW_I = reinterpret_cast<SymInitializeW_T>(GetProcAddress(dbgHelp, "SymInitializeW"));
    SymSetOptions_I = reinterpret_cast<SymSetOptions_T>(GetProcAddress(dbgHelp, "SymSetOptions"));
    SymCleanup_I = reinterpret_cast<SymCleanup_T>(GetProcAddress(dbgHelp, "SymCleanup"));
    SymSetSearchPathW_I = reinterpret_cast<SymSetSearchPathW_T>(GetProcAddress(dbgHelp, "SymSetSearchPathW"));
    SymLoadModuleExW_I = reinterpret_cast<SymLoadModuleExW_T>(GetProcAddress(dbgHelp, "SymLoadModuleExW"));
    SymFromAddrW_I = reinterpret_cast<SymFromAddrW_T>(GetProcAddress(dbgHelp, "SymFromAddrW"));
    SymGetTypeFromNameW_I = reinterpret_cast<SymGetTypeFromNameW_T>(GetProcAddress(dbgHelp, "SymGetTypeFromNameW"));
    SymGetTypeInfo_I = reinterpret_cast<SymGetTypeInfo_T>(GetProcAddress(dbgHelp, "SymGetTypeInfo"));

    if ((SymGetOptions_I == NULL) ||
        (SymInitializeW_I == NULL) ||
        (SymSetOptions_I == NULL) ||
        (SymCleanup_I == NULL) ||
        (SymSetSearchPathW_I == NULL) ||
        (SymLoadModuleExW_I == NULL) ||
        (SymFromAddrW_I == NULL) ||
        (SymGetTypeFromNameW_I == NULL) ||
        (SymGetTypeInfo_I == NULL))
    {
        wprintf(L"[-] Error! GetProcAddress failed in InitializeSymbols. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    symOptions = (SymGetOptions_I() |
                  SYMOPT_AUTO_PUBLICS |
                  SYMOPT_CASE_INSENSITIVE |
                  SYMOPT_UNDNAME |
                  SYMOPT_DEFERRED_LOADS);

    SymSetOptions_I(symOptions);

    res = SymInitializeW_I(GetCurrentProcess(),
                           NULL,
                           FALSE);
    if (res == FALSE)
    {
        wprintf(L"[-] Error! SymInitializeW failed in InitializeSymbols. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    if (SymSetSearchPathW_I(GetCurrentProcess(),
                            L"srv*C:\\Symbols*http://msdl.microsoft.com/download/symbols") == FALSE)
    {
        wprintf(L"[-] Error! SymSetSearchPathW failed in InitializeSymbols. (GLE: %d)\n", GetLastError());
        goto Exit;
    }


    //
    // Load NT into the process.
    //
    k_NtBaseAddress = SymLoadModuleExW_I(GetCurrentProcess(),
                                         NULL,
                                         L"C:\\Windows\\system32\\ntoskrnl.exe",
                                         NULL,
                                         0,
                                         0,
                                         NULL,
                                         0);
    if (k_NtBaseAddress == 0)
    {
        wprintf(L"[-] Error! SymLoadModuleExW failed in InitializeSymbols. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    CreateListOfValidSecureCalls();

    result = true;

Exit:
    if (currentDirectory != NULL)
    {
        free(currentDirectory);
    }

    return result;
}

/**
*
* @brief          Retrieves an offset from a target structure symbol name.
* @param[in]      TargetStructure - The target base structure name (e.g., _KTHREAD).
* @param[in]      TargetFieldName - The target field name in the specified structure.
* @param[out,opt] ChildSymbolIndex - The symbol index of the found field name for further processing
*                                    by other callers (like indexing the child structure again).
* @return         The offset on success, otherwise 0.
*
*/
static
ULONGLONG
GetFieldOffsetFromStructure (
    _In_ const wchar_t* TargetStructure,
    _In_ const wchar_t* TargetFieldName,
    _Out_opt_ ULONG* ChildSymbolIndex
    )
{
    SYMBOL_INFOW symbol;
    ULONG childrenCount;
    TI_FINDCHILDREN_PARAMS* childrenSyms;
    SIZE_T childrenSymSize;
    wchar_t* childSymName;
    ULONG index;
    VARIANT structureOffset;

    childrenCount = 0;
    childrenSyms = NULL;
    childrenSymSize = 0;
    childSymName = NULL;
    index = 0;

    RtlZeroMemory(&symbol, sizeof(symbol));
    RtlZeroMemory(&structureOffset, sizeof(structureOffset));

    symbol.SizeOfStruct = sizeof(SYMBOL_INFOW);
    symbol.MaxNameLen = 0;

    if (SymGetTypeFromNameW_I(GetCurrentProcess(),
                              k_NtBaseAddress,
                              TargetStructure,
                              &symbol) == FALSE)
    {
        wprintf(L"[-] Error! SymGetTypeFromNameW failed in GetKernelStructureOffsets. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    //
    // Preserve the index
    //
    index = symbol.TypeIndex;

    if (SymGetTypeInfo_I(GetCurrentProcess(),
                         k_NtBaseAddress,
                         index,
                         TI_GET_CHILDRENCOUNT,
                         &childrenCount) == FALSE)
    {
        wprintf(L"[-] Error! SymGetTypeInfo_I failed in GetKernelStructureOffsets. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    childrenSymSize = sizeof(TI_FINDCHILDREN_PARAMS) + childrenCount * sizeof(ULONG);
    childrenSyms = static_cast<TI_FINDCHILDREN_PARAMS*>(malloc(childrenSymSize));
    if (childrenSyms == NULL)
    {
        wprintf(L"[-] Error! malloc failed in GetKernelStructureOffsets. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    RtlZeroMemory(childrenSyms, childrenSymSize);

    childrenSyms->Count = childrenCount;
    childrenSyms->Start = 0;

    if (SymGetTypeInfo_I(GetCurrentProcess(),
                         k_NtBaseAddress,
                         index,
                         TI_FINDCHILDREN,
                         childrenSyms) == FALSE)
    {
        wprintf(L"[-] Error! SymGetTypeInfo_I failed in GetKernelStructureOffsets. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    for (ULONG i = 0; i < childrenSyms->Count; i++)
    {
        if (SymGetTypeInfo_I(GetCurrentProcess(),
                             k_NtBaseAddress,
                             childrenSyms->ChildId[i],
                             TI_GET_SYMNAME,
                             &childSymName) == FALSE)
        {
            wprintf(L"[-] Error! SymGetTypeInfo_I failed in GetKernelStructureOffsets. (GLE: %d)\n", GetLastError());
            goto Exit;
        }

        if (wcscmp(childSymName, TargetFieldName) != 0)
        {
            continue;
        }

        if (SymGetTypeInfo_I(GetCurrentProcess(),
                             k_NtBaseAddress,
                             childrenSyms->ChildId[i],
                             TI_GET_OFFSET,
                             &structureOffset) == FALSE)
        {
            wprintf(L"[-] Error! SymGetTypeInfo_I failed in CreateListOfValidSecureCalls. (GLE: %d)\n", GetLastError());
            goto Exit;
        }

        if (ChildSymbolIndex != NULL)
        {
            *ChildSymbolIndex = childrenSyms->ChildId[i];
        }

        break;
    }

Exit:
    if (childrenSyms != NULL)
    {
        free(childrenSyms);
    }

    return static_cast<ULONGLONG>(structureOffset.vt);
}

/**
*
* @brief        Retrieves an offset from a target union symbol name.
* @param[in]    ChildSymbolIndex - The symbol index from a child union value (e.g. CONTROL_AREA.u1).
* @param[in]    TargetFieldName - The target field name in the specified union.
* @param[in]    NextSymbolIndex - The symbol index from a child structure of the target union
*                                 for further processing by other callers.
* @return       The offset on success, otherwise 0.
*
*/
static
ULONGLONG
GetStructureOffsetFromChildUnion (
    _In_ ULONG ChildSymbolIndex,
    _In_ const wchar_t* TargetFieldName,
    _Out_opt_ ULONG* NextSymbolIndex
    )
{
    ULONG symTag;
    ULONG typeId;
    ULONG nextId;
    ULONG childrenCount;
    TI_FINDCHILDREN_PARAMS* childrenSyms;
    SIZE_T childrenSymSize;
    wchar_t* childSymName;
    VARIANT structureOffset;

    symTag = 0;
    typeId = 0;
    nextId = 0;
    childrenCount = 0;
    childrenSyms = NULL;
    childrenSymSize = 0;
    childSymName = NULL;

    RtlZeroMemory(&structureOffset, sizeof(structureOffset));

    if (SymGetTypeInfo_I(GetCurrentProcess(), k_NtBaseAddress, ChildSymbolIndex, TI_GET_SYMTAG, &symTag) == FALSE)
    {
        wprintf(L"[-] Error! SymGetTypeInfo_I failed in GetStructureOffsetFromUnion. (GLE: 0x%lx)\n", GetLastError());
        goto Exit;
    }

    typeId = ChildSymbolIndex;

    //
    // Only User-defined types (UDT) have children. Keep "going down" until we hit the first structure.
    //
    while (symTag != SymTagUDT)
    {
        nextId = 0;

        if (SymGetTypeInfo_I(GetCurrentProcess(),
                             k_NtBaseAddress,
                             typeId,
                             TI_GET_TYPE,
                             &nextId) == FALSE)
        {
            wprintf(L"[-] Error! SymGetTypeInfo_I failed in GetStructureOffsetFromUnion. (GLE: 0x%lx)\n", GetLastError());
            goto Exit;
        }

        typeId = nextId;

        if (SymGetTypeInfo_I(GetCurrentProcess(),
                             k_NtBaseAddress,
                             typeId,
                             TI_GET_SYMTAG,
                             &symTag) == FALSE)
        {
            wprintf(L"[-] Error! SymGetTypeInfo_I failed in GetStructureOffsetFromUnion. (GLE: %d)\n", GetLastError());
            goto Exit;
        }
    }

    if (SymGetTypeInfo_I(GetCurrentProcess(),
                         k_NtBaseAddress,
                         typeId,
                         TI_GET_CHILDRENCOUNT,
                         &childrenCount) == FALSE)
    {
        wprintf(L"[-] Error! SymGetTypeInfo_I failed in GetKernelStructureOffsets. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    childrenSymSize = sizeof(TI_FINDCHILDREN_PARAMS) + childrenCount * sizeof(ULONG);
    childrenSyms = static_cast<TI_FINDCHILDREN_PARAMS*>(malloc(childrenSymSize));
    if (childrenSyms == NULL)
    {
        wprintf(L"[-] Error! malloc failed in GetKernelStructureOffsets. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    RtlZeroMemory(childrenSyms, childrenSymSize);

    childrenSyms->Count = childrenCount;
    childrenSyms->Start = 0;

    if (SymGetTypeInfo_I(GetCurrentProcess(),
                         k_NtBaseAddress,
                         typeId,
                         TI_FINDCHILDREN,
                         childrenSyms) == FALSE)
    {
        wprintf(L"[-] Error! SymGetTypeInfo_I failed in GetKernelStructureOffsets. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    for (ULONG i = 0; i < childrenSyms->Count; i++)
    {
        if (SymGetTypeInfo_I(GetCurrentProcess(),
                             k_NtBaseAddress,
                             childrenSyms->ChildId[i],
                             TI_GET_SYMNAME,
                             &childSymName) == FALSE)
        {
            wprintf(L"[-] Error! SymGetTypeInfo_I failed in GetKernelStructureOffsets. (GLE: %d)\n", GetLastError());
            goto Exit;
        }

        if (wcscmp(childSymName, TargetFieldName) != 0)
        {
            continue;
        }

        if (SymGetTypeInfo_I(GetCurrentProcess(),
                             k_NtBaseAddress,
                             childrenSyms->ChildId[i],
                             TI_GET_OFFSET,
                             &structureOffset) == FALSE)
        {
            wprintf(L"[-] Error! SymGetTypeInfo_I failed in CreateListOfValidSecureCalls. (GLE: %d)\n", GetLastError());
            goto Exit;
        }

        //
        // This is a common pattern in Windows. You will have a union followed
        // by effectively an "unamed" structure, such STRUCT.u.e.FIRSTFIELD.
        // When this happens, the offset is usually 0. In these cases a caller would
        // need to invoke this function twice. Once to get "e" offset and then another
        // to get FIRSTFIELD's offset. Provide the type index for "e".
        //
        if (structureOffset.vt == 0)
        {
            if (NextSymbolIndex != NULL)
            {
                *NextSymbolIndex = childrenSyms->ChildId[i];
            }
        }

        break;
    }

Exit:
    if (childrenSyms != NULL)
    {
        free(childrenSyms);
    }

    return static_cast<ULONGLONG>(structureOffset.vt);

}

/**
*
* @brief        Retrieves the offset of nt!VslpEnterIumSecureModeOffset from the
*               base address of NT.
* @return       The offset on success, otherwise 0.
*
*/
static
ULONGLONG
GetVslpEnterIumSecureModeOffset ()
{
    SYMBOL_INFOW symbol;
    ULONGLONG offset;

    RtlZeroMemory(&symbol, sizeof(symbol));

    symbol.SizeOfStruct = sizeof(SYMBOL_INFOW);
    symbol.MaxNameLen = 0;
    offset = 0;

    if (SymGetTypeFromNameW_I(GetCurrentProcess(),
                              k_NtBaseAddress,
                              L"VslpEnterIumSecureMode",
                              &symbol) == FALSE)
    {
        wprintf(L"[-] Error! SymGetTypeFromNameW failed in GetKernelStructureOffsets. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    offset = (symbol.Address - k_NtBaseAddress);

Exit:
    return offset;
}

/**
*
* @brief        Sends the init IOCTL to SkBridgeDriver.
* @param[in]    The init data for SkBridgeDriver.
* @return       true on success, otherwise false.
*
*/
static
bool
DoSkBridgeDriverInitialization (
    _In_ PSKBRIDGE_INIT_DATA SkBridgeInitData
    )
{
    bool result;
    HANDLE skBridgeDevice;
    DWORD bytesReturned;

    result = false;
    bytesReturned = 0;

    skBridgeDevice = OpenSkBridgeDriver();
    if (skBridgeDevice == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] Error! OpenSkBridgeDriver failed in DoSkBridgeDriverInitialization. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    if (DeviceIoControl(skBridgeDevice,
                        SKBRIDGE_IOCTL_INIT_KERNEL_STRUCTS,
                        SkBridgeInitData,
                        sizeof(SKBRIDGE_INIT_DATA),
                        NULL,
                        0,
                        &bytesReturned,
                        NULL) == FALSE)
    {
        wprintf(L"[-] Error! Failed to send IOCTL to SkBridgeDriver. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    result = true;

Exit:
    if ((skBridgeDevice != INVALID_HANDLE_VALUE) &&
        (skBridgeDevice != NULL))
    {
        CloseHandle(skBridgeDevice);
    }

    return result;
}

/**
*
* @brief        Performs the init for SkBridge/SkBridgeClient.
* @return       true on success, otherwise false.
*
*/
bool
InitializeSkBridge ()
{
    bool result;
    ULONGLONG offsetArray[StructureOffsetMax];
    ULONG childSymbolIndex;
    SKBRIDGE_INIT_DATA initData;
    
    result = false;
    childSymbolIndex = 0;

    RtlZeroMemory(&offsetArray, sizeof(offsetArray));

    RtlZeroMemory(&initData, sizeof(initData));

    //
    // Initialize the symbols and get the valid secure call values + offsets
    //
    if (!InitializeSymbols())
    {
        goto Exit;
    }

    initData.StructureOffsetArray[StructureOffsetSecureStateOffset] = GetFieldOffsetFromStructure(L"_KPROCESS",
                                                                                                  L"SecureState",
                                                                                                  NULL);

    initData.StructureOffsetArray[StructureOffsetSecureThreadCookieOffset] = GetFieldOffsetFromStructure(L"_KTHREAD",
                                                                                                         L"SecureThreadCookie",
                                                                                                         NULL);

    initData.StructureOffsetArray[StructureOffsetSectionObjectOffset] = GetFieldOffsetFromStructure(L"_EPROCESS",
                                                                                                    L"SectionObject",
                                                                                                    NULL);

    initData.StructureOffsetArray[StructureOffsetControlAreaOffset] = GetFieldOffsetFromStructure(L"_SECTION",
                                                                                                  L"u1",
                                                                                                  NULL);

    //
    // The "ImageInfoRef" structure requires a bit more massaging. This is because we have to get the control
    // area structure and then index a union and then a structure to finally get the ImageInfoRef.
    //
    initData.StructureOffsetArray[StructureOffsetImageInfoRefOffset] = GetFieldOffsetFromStructure(L"_CONTROL_AREA",
                                                                                                   L"u2",
                                                                                                   &childSymbolIndex);

    initData.StructureOffsetArray[StructureOffsetImageInfoRefOffset] += GetStructureOffsetFromChildUnion(childSymbolIndex,
                                                                                                         L"e2",
                                                                                                         &childSymbolIndex);

    initData.StructureOffsetArray[StructureOffsetImageInfoRefOffset] += GetStructureOffsetFromChildUnion(childSymbolIndex,
                                                                                                         L"ImageInfoRef",
                                                                                                         &childSymbolIndex);

    initData.StructureOffsetArray[StructureOffsetStrongImageReferenceOffset] = GetFieldOffsetFromStructure(L"_MI_IMAGE_ADDITIONAL_INFO",
                                                                                                           L"StrongImageReference",
                                                                                                           NULL);

    //
    // Make sure we have valid offsets.
    //
    for (ULONG i = 0; i < _ARRAYSIZE(initData.StructureOffsetArray); i++)
    {
        if (initData.StructureOffsetArray[i] == 0)
        {
            goto Exit;
        }
    }

    //
    // Get the RVA of VslpEnterIumSecureMode
    //
    initData.VslpEnterIumSecureModeOffset = GetVslpEnterIumSecureModeOffset();
    if (initData.VslpEnterIumSecureModeOffset == 0)
    {
        goto Exit;
    }

    //
    // Ship the information to the SkBridgeDriver.
    //
    result = DoSkBridgeDriverInitialization(&initData);

Exit:
    return result;
}

/**
*
* @brief        Performs cleanup of symbol functionality.
*
*/
void
CleanupSymbols ()
{
    SymCleanup_I(GetCurrentProcess());
}