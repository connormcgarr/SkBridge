/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeClient/Helpers.cpp
*
* @summary:   Various helper routines.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#include "Helpers.hpp"
#include "Shared.hpp"
#include "Initialization.hpp"
#include <unordered_map>
#include <string>

//
// Mapping of all secure calls, using the number as an index.
//
static std::unordered_map<std::wstring, ULONG> k_SecureCallValues;

/**
*
* @brief        Opens the SkBridgeDriver.
* @return       HANDLE to SkBridgeDriver on success, otherwise INVALID_HANDLE_VALUE.
*
*/
HANDLE
OpenSkBridgeDriver ()
{
    return CreateFileW(k_SkBridgeDeviceName,
                       GENERIC_READ | GENERIC_WRITE,
                       0,
                       NULL,
                       OPEN_EXISTING,
                       0, 
                       NULL);
}

/**
*
* @brief        Retrieves the PID associated with LsaIso.
* @param[out]   ProcessId - The PID of LsaIso on success.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
NTSTATUS
GetLsaIsoPid (
    _Out_ PULONG ProcessId
    )
{
    NTSTATUS status;
    PSYSTEM_PROCESS_INFORMATION processInfo;
    ULONG size;
    PVOID buffer;
    UNICODE_STRING lsaIso;
    
    RtlInitUnicodeString(&lsaIso, L"LsaIso.exe");

    status = STATUS_NOT_FOUND;
    processInfo = NULL;
    size = 0;
    buffer = NULL;
    *ProcessId = 0;

    NtQuerySystemInformation(SystemProcessInformation,
                             NULL,
                             0,
                             &size);
    if (size == 0)
    {
        goto Exit;
    }

    buffer = malloc(size);

    if (buffer == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(buffer);

    status = NtQuerySystemInformation(SystemProcessInformation,
                                      processInfo,
                                      size,
                                      &size);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    while (processInfo->NextEntryOffset != 0)
    {
        //
        // It is okay to skip over the first one
        //
        processInfo = PSYSTEM_PROCESS_INFORMATION((unsigned char*)processInfo + processInfo->NextEntryOffset);

        //
        // Some processes (like the Idle process) have no name.
        //
        if (processInfo->ImageName.Buffer == NULL)
        {
            continue;
        }

        //
        // Target process?
        //
        if (RtlCompareUnicodeString(&processInfo->ImageName,
                                    &lsaIso,
                                    FALSE) != 0)
        {
            continue;
        }
        
        *ProcessId = HandleToULong(processInfo->UniqueProcessId);

        status = STATUS_SUCCESS;
        break;
    }

Exit:
    if (buffer != NULL)
    {
        free(buffer);
    }

    return status;
}

/**
*
* @brief        Retrieves a TID associated with LsaIso.
* @param[out]   ProcessId - A TID of LsaIso on success.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
NTSTATUS
GetLsaIsoTid (
    _Out_ PULONG ThreadId
    )
{
    NTSTATUS status;
    PSYSTEM_PROCESS_INFORMATION_REDEF processInfo;
    ULONG size;
    PVOID buffer;
    UNICODE_STRING lsaIso;
    
    RtlInitUnicodeString(&lsaIso, L"LsaIso.exe");

    status = STATUS_NOT_FOUND;
    processInfo = NULL;
    size = 0;
    buffer = NULL;
    *ThreadId = 0;

    NtQuerySystemInformation(SystemProcessInformation,
                             NULL,
                             0,
                             &size);
    if (size == 0)
    {
        goto Exit;
    }

    buffer = malloc(size);

    if (buffer == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    processInfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION_REDEF>(buffer);

    status = NtQuerySystemInformation(SystemProcessInformation,
                                      processInfo,
                                      size,
                                      &size);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    while (processInfo->NextEntryOffset != 0)
    {
        //
        // It is okay to skip over the first one
        //
        processInfo = PSYSTEM_PROCESS_INFORMATION_REDEF((unsigned char*)processInfo + processInfo->NextEntryOffset);

        //
        // Some processes (like the Idle process) have no name.
        //
        if (processInfo->ImageName.Buffer == NULL)
        {
            continue;
        }

        //
        // Target process?
        //
        if (RtlCompareUnicodeString(&processInfo->ImageName,
                                    &lsaIso,
                                    FALSE) != 0)
        {
            continue;
        }

        //
        // Return the first thread
        //       
        *ThreadId = HandleToULong(processInfo->Threads->ClientId.UniqueThread);

        status = STATUS_SUCCESS;
        break;
    }

Exit:
    if (buffer != NULL)
    {
        free(buffer);
    }

    return status;
}

/**
*
* @brief       Retrieves the kernel-mode load address of a target driver.
* @param[in]   TargetDriverName - The target driver.
* @return      The loaded address on success, otherwise 0.
*
*/
ULONG_PTR
GetBaseImageOfTargetDriver (
    _In_ const char* TargetDriverName
    )
{
    NTSTATUS status;
    ULONG_PTR driverBase;
    PRTL_PROCESS_MODULES modules;
    ULONG modulesLength;
    HANDLE token;
    TOKEN_PRIVILEGES tokenPrivs;
    LUID luid;

    driverBase = 0;
    modulesLength = 0;
    modules = NULL;
    RtlZeroMemory(&tokenPrivs, sizeof(tokenPrivs));
    RtlZeroMemory(&luid, sizeof(luid));

    //
    // Need SeDebugPrivilege
    //
    if (OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES |
                         TOKEN_QUERY,
                         &token) != TRUE)
    {
        wprintf(L"[-] Error OpenProcessToken failed in GetBaseImageOfTargetDriver! (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    if (LookupPrivilegeValueW(NULL,
                              SE_DEBUG_NAME,
                              &luid) != TRUE)
    {
        wprintf(L"[-] Error LookupPrivilegeValueW failed in GetBaseImageOfTargetDriver! (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    tokenPrivs.PrivilegeCount = 1;
    tokenPrivs.Privileges[0].Luid = luid;
    tokenPrivs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (AdjustTokenPrivileges(token,
                              FALSE,
                              &tokenPrivs,
                              sizeof(tokenPrivs),
                              NULL,
                              NULL) != TRUE)
    {
        wprintf(L"[-] Error AdjustTokenPrivileges failed in GetBaseImageOfTargetDriver! (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    //
    // Now get the target section object. Get the needed length first.
    //
    NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation),
                             NULL,
                             0,
                             &modulesLength);

    modules = static_cast<PRTL_PROCESS_MODULES>(malloc(modulesLength));
    if (modules == NULL)
    {
        wprintf(L"[-] Error malloc failed in GetBaseImageOfTargetDriver! (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    RtlZeroMemory(modules, modulesLength);

    //
    // Now get everything.
    //
    status = NtQuerySystemInformation(static_cast<SYSTEM_INFORMATION_CLASS>(SystemModuleInformation),
                                      modules,
                                      modulesLength,
                                      &modulesLength);
    if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH)
    {
        wprintf(L"[-] Error! NtQuerySystemInformation failed in GetBaseImageOfTargetDriver. (GLE: %d)\n", GetLastError());
        status = STATUS_NOT_IMPLEMENTED;
        goto Exit;
    }

    for (ULONG i = 0; i < modules->NumberOfModules; i++)
    {
        //
        // Is this our driver?
        //
        if (strcmp(reinterpret_cast<char*>(modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName),
                   TargetDriverName) == 0)
        {
            driverBase = reinterpret_cast<ULONG_PTR>(modules->Modules[i].ImageBase);
            break;
        }
    }

Exit:
    if (modules != NULL)
    {
        free(modules);
    }

    return driverBase;
}

/**
*
* @brief        Wrapper function to issue the secure call IOCTL to SkBridgeDriver.
* @param[in]    SecureCallData - The secure call data/parameters for the target secure call.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
NTSTATUS
VslpEnterIumSecureModeWrapper (
    _In_ PSKBRIDGE_SECURE_CALL_DATA SecureCallData
    )
{
    NTSTATUS status;
    HANDLE skBridgeDevice;
    ULONG bytesReturned;

    status = STATUS_SUCCESS;

    skBridgeDevice = OpenSkBridgeDriver();
    if (skBridgeDevice == INVALID_HANDLE_VALUE)
    {
        wprintf(L"[-] Error! SkBridgeDriver is not installed. (GLE: %d)\n", GetLastError());
        status = STATUS_NOT_IMPLEMENTED;
        goto Exit;
    }

    if (DeviceIoControl(skBridgeDevice,
                        SKBRIDGE_IOCTL_DISPATCH_SECURE_CALL,
                        SecureCallData,
                        sizeof(SKBRIDGE_SECURE_CALL_DATA),
                        SecureCallData,
                        sizeof(SKBRIDGE_SECURE_CALL_DATA),
                        &bytesReturned,
                        NULL) == FALSE)
    {
        wprintf(L"[-] Error! Failed to send IOCTL to SkBridgeDriver. (GLE: %d)\n", GetLastError());
        status = STATUS_NOT_IMPLEMENTED;
        goto Exit;
    }

Exit:
    if ((skBridgeDevice != INVALID_HANDLE_VALUE) &&
        (skBridgeDevice != NULL))
    {
        CloseHandle(skBridgeDevice);
    }

    return status;
}

/**
*
* @brief        Fills out the mapping of nt!_SKSERVICE symbol names to secure call values.
* @param[in]    SkServiceEnumValue - The target nt!_SKSERVICE symbol name to add.
* @param[in]    SecureCallValue - The associated "actual" secure call numerical value.
*
*/
void
AddToKnownSecureCalls (
    _In_ wchar_t* SkServiceEnumValue,
    _In_ ULONG SecureCallValue
    )
{
    k_SecureCallValues.insert({ std::wstring(SkServiceEnumValue), SecureCallValue });
    LocalFree(SkServiceEnumValue);
}

/**
*
* @brief        Retrieves the numerical secure call value associated with an nt!_SKSERVICE name.
* @param[in]    SkServiceEnumValue - The target nt!_SKSERVICE symbol name to retrieve.
* @return       The secure call numerical value on success, otherwise 0.
*
*/
ULONG
GetSecureCallValue (
    _In_ const wchar_t* SkServiceEnumValue
    )
{
    auto it = k_SecureCallValues.find(std::wstring(SkServiceEnumValue));
    return it->second;
}

/**
*
* @brief        Releases/cleans up resources for the SkBridgeClient application.
*
*/
void
CleanupSkBridgeClient ()
{
    CleanupSymbols();
}