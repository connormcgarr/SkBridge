/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeDriver/Helpers.cpp
*
* @summary:   Various helper routines.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#include <ntifs.h>
#include "SkDefs.hpp"
#include "Helpers.hpp"

PAGED_FILE()

//
// All kernel loaded images.
//
static PLIST_ENTRY PsLoadedModuleList = NULL;
static PERESOURCE PsLoadedModuleResource = NULL;

//
// SkImplementations.cpp
//
extern VslpEnterIumSecureMode_t VslpEnterIumSecureMode;

//
// "Initialization" array of offsets that comes from SkBridgeClient.
//
bool g_KnownOffsetArrayInitialized = false;
SKBRIDGE_INIT_DATA k_SkBridgeInitData;


/**
*
* @brief        Retrieves the offset for a target structure member.
* @param[in]    TargetStructure - Target value from the StructureOffsets enum.
* @return       The offset on success, otherwise 0.
*
*/
static
FORCEINLINE
_IRQL_requires_max_(PASSIVE_LEVEL)
ULONGLONG
GetKernelStructureOffset (
    _In_ StructureOffsets TargetStructure
    )
{
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    if (!g_KnownOffsetArrayInitialized)
    {
        NT_ASSERT(g_KnownOffsetArrayInitialized);
        return 0;
    }

    return k_SkBridgeInitData.StructureOffsetArray[TargetStructure];
}

/**
*
* @brief        Retrieves a handle to the associated section object for the image of a process.
* @param[in]    TargetProcessId - The target process.
* @param[in]	SectionObjectHandle - Handle to the section object.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
static
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
GetProcessSectionObjectHandleFromPid (
    _In_ ULONGLONG TargetProcessId,
    _Out_ PHANDLE SectionObjectHandle
    )
{
    NTSTATUS status;
    PEPROCESS process;
    PVOID processSectionObject;
    HANDLE sectionObjectHandle;
    ULONGLONG offset;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    status = STATUS_SUCCESS;
    process = NULL;
    processSectionObject = NULL;
    sectionObjectHandle = NULL;
    *SectionObjectHandle = NULL;
    offset = 0;

    if (TargetProcessId == 0)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    status = PsLookupProcessByProcessId(HANDLE(TargetProcessId),
                                        &process);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // Get the section object.
    //
    offset = GetKernelStructureOffset(StructureOffsetSectionObjectOffset);
    if (offset == 0)
    {
        goto Exit;
    }

    processSectionObject = (PVOID)*(ULONGLONG*)((unsigned char*)process + offset);

    //
    // Open a handle to it.
    //
    status = ObOpenObjectByPointer(processSectionObject,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   GENERIC_ALL,
                                   NULL,
                                   KernelMode,
                                   &sectionObjectHandle);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    *SectionObjectHandle = sectionObjectHandle;

Exit:
    if (process != NULL)
    {
        ObDereferenceObject(process);
    }

    return status;
}

/**
*
* @brief        Retrieves a secure image handle from a target process.
* @param[in]    TargetProcessId - The target process.
* @param[in]	SecureImageHandle - Handle to the secure image object.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
static
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
GetSecureImageHandleFromProcessId (
    _In_ ULONGLONG TargetProcessId,
    _Out_ PULONGLONG SecureImageHandle
    )
{
    NTSTATUS status;
    PEPROCESS process;
    PVOID processSectionObject;
    PVOID controlArea;
    PVOID imageInfoRef;
    ULONGLONG secureImageHandle;
    ULONGLONG offset;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    status = STATUS_SUCCESS;
    process = NULL;
    processSectionObject = NULL;
    controlArea = NULL;
    imageInfoRef = NULL;
    secureImageHandle = NULL;
    *SecureImageHandle = 0;
    offset = 0;

    if (TargetProcessId == 0)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    status = PsLookupProcessByProcessId(HANDLE(TargetProcessId),
                                        &process);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // First, the section object.
    //
    offset = GetKernelStructureOffset(StructureOffsetSectionObjectOffset);
    if (offset == 0)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    processSectionObject = (PVOID)*(ULONGLONG*)((unsigned char*)process + offset);

    //
    // Next, the Control Area.
    //
    offset = 0;
    offset = GetKernelStructureOffset(StructureOffsetControlAreaOffset);
    if (offset == 0)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    controlArea = (PVOID)*(ULONGLONG*)((unsigned char*)processSectionObject + offset);

    //
    // Next, the ImageInfoRef structure.
    //
    offset = 0;
    offset = GetKernelStructureOffset(StructureOffsetImageInfoRefOffset);
    if (offset == 0)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    imageInfoRef = (PVOID)*(ULONGLONG*)((unsigned char*)controlArea + offset);

    //
    // Last, the offset to StrongImageReference (our secure image handle)
    //
    offset = 0;
    offset = GetKernelStructureOffset(StructureOffsetStrongImageReferenceOffset);
    if (offset == 0)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    secureImageHandle = *(ULONGLONG*)((unsigned char*)imageInfoRef + offset);
    *SecureImageHandle = secureImageHandle;

    //
    // We are done with the process
    //
    ObDereferenceObject(process);

Exit:
    return status;
}

/**
*
* @brief        Retrieves a secure image handle from a target kernel mode image.
* @param[in]    KernelImageBase - The target image address.
* @param[in]	SecureImageHandle - Handle to the secure image object.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
static
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
GetSecureImageHandleFromKernelImageBase (
    _In_ ULONG_PTR KernelImageBase,
    _Out_ PULONGLONG SecureImageHandle
    )
{
    NTSTATUS status;
    bool resourceAcquired;
    PVOID sectionObject;
    PKLDR_DATA_TABLE_ENTRY entry;
    ULONGLONG offset;
    PVOID controlArea;
    PVOID imageInfoRef;
    ULONGLONG secureImageHandle;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    status = STATUS_SUCCESS;
    resourceAcquired = false;
    sectionObject = 0;
    entry = NULL;
    offset = 0;
    controlArea = NULL;
    imageInfoRef = NULL;
    secureImageHandle = 0;

    *SecureImageHandle = NULL;

    if (ExAcquireResourceSharedLite(PsLoadedModuleResource,
                                    TRUE) == FALSE)
    {
        status = STATUS_RESOURCE_IN_USE;
        goto Exit;
    }

    resourceAcquired = true;

    //
    // Find our target image and extract the section object.
    //
    for (PLIST_ENTRY link = PsLoadedModuleList->Flink;
         link != PsLoadedModuleList;
         link = link->Flink)
    {
        entry = CONTAINING_RECORD(link, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (entry->DllBase == reinterpret_cast<PVOID>(KernelImageBase))
        {
            //
            // We found our image. Extract the section object.
            //
            sectionObject = entry->SectionPointer;
            break;
        }
    }

    if (sectionObject == 0)
    {
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    //
    // We found the section object!
    //

    //
    // First, the Control Area.
    //
    offset = 0;
    offset = GetKernelStructureOffset(StructureOffsetControlAreaOffset);
    if (offset == 0)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    controlArea = (PVOID)*(ULONGLONG*)((unsigned char*)sectionObject + offset);

    //
    // Next, the ImageInfoRef structure.
    //
    offset = 0;
    offset = GetKernelStructureOffset(StructureOffsetImageInfoRefOffset);
    if (offset == 0)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    imageInfoRef = (PVOID)*(ULONGLONG*)((unsigned char*)controlArea + offset);

    //
    // Last, the offset to StrongImageReference (our secure image handle)
    //
    offset = 0;
    offset = GetKernelStructureOffset(StructureOffsetStrongImageReferenceOffset);
    if (offset == 0)
    {
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    secureImageHandle = *(ULONGLONG*)((unsigned char*)imageInfoRef + offset);
    *SecureImageHandle = secureImageHandle;

Exit:
    if (resourceAcquired)
    {
        ExReleaseResourceLite(PsLoadedModuleResource);
    }

    return status;
}

/**
*
* @brief        Creates an MDL to describe a target secure call parameter.
* @param[in]    TargetParameter - The target parameter value.
* @param[in]	TargetSize - Target parameter size.
* @return       MDL on success, otherwise NULL.
*
*/
static
_IRQL_requires_max_(PASSIVE_LEVEL)
PMDL
EncapsulateParameterAsMdl (
    _In_ ULONGLONG TargetParameter,
    _In_ ULONG TargetSize
    )
{
    PMDL mdl;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    mdl = NULL;

    if ((TargetParameter == NULL) ||
        (TargetSize == 0))
    {
        goto Exit;
    }

    mdl = IoAllocateMdl((PVOID)(TargetParameter),
                        TargetSize,
                        FALSE,
                        FALSE,
                        NULL);
    if (mdl == NULL)
    {
        goto Exit;
    }

Exit:
    return mdl;
}

/**
*
* @brief        Converts the IOCTL data from SkBridgeClient to actual secure call args
*               and performs parameter transformation where necessary.
* @param[in]    SecureCallData - The data from SkBridgeClient.
* @param[out]	SecureCallArgs - The final secure call arguments.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.
*
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
SkBridgeDataToSecureCallParameters (
    _In_ PSKBRIDGE_SECURE_CALL_DATA SecureCallData,
    _Out_ PSECURE_CALL_ARGS SecureCallArgs
    )
{
    NTSTATUS status;
    SECURE_CALL_ARGS secureCallArgs;
    PSKBRIDGE_GENERIC_SECURE_CALL_FIELD parameters;
    ULONG* parameterOptions;
    ULONGLONG* translatedParameters;
    PETHREAD thread;
    PEPROCESS process;
    PMDL mdl;
    HANDLE handle;
    ULONGLONG secureImageHandle;
    ULONGLONG* targetArray;
    UCHAR numberOfArrayElements;
    PHYSICAL_ADDRESS physicalAddress;
    ULONG targetArgumentIndex;
    ULONGLONG offset;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    status = STATUS_SUCCESS;
    parameters = NULL;
    parameterOptions = NULL;
    thread = NULL;
    process = NULL;
    mdl = NULL;
    handle = NULL;
    secureImageHandle = 0;
    targetArray = NULL;
    numberOfArrayElements = 0;
    targetArgumentIndex = 0;
    offset = 0;

    RtlZeroMemory(&secureCallArgs, sizeof(secureCallArgs));
    RtlZeroMemory(&physicalAddress, sizeof(physicalAddress));

    if (SecureCallArgs == NULL)
    {
        goto Exit;
    }

    parameters = &SecureCallData->SecureCallFields.Field1;
    parameterOptions = &SecureCallData->SecureCallFieldDescriptors.Field1Descriptor;
    translatedParameters = &secureCallArgs.Field1;

    for (ULONG i = 0; i <= MAX_NUMBER_OF_SECURE_CALL_PARAMETERS; i++)
    {
        //
        // Ensure no one "fakes" cleanup on us.
        //
        parameterOptions[i] &= ~ScDescOptReleaseResource;

        //
        // Do we need to re-interpret this parameter?
        //
        if (parameterOptions[i] == ScDescOptNone)
        {
            //
            // No, don't need to do anything. Insert the parameter directly.
            //
            translatedParameters[i] = parameters[i].u.Value;
            continue;
        }

        //
        // This parameter needs to be re-interpreted to something else. Determine what we need to do.
        //

        //
        // Encapsulates a parameter as an MDL. Some parameters require conversion _and then_
        // a conversion to MDL. We first handle situations where we need to translate to an MDL.
        //
        if (parameterOptions[i] == ScDescOptEncapsulateAsMdl)
        {
            mdl = NULL;
            mdl = EncapsulateParameterAsMdl(parameters[i].u.Value,
                                            parameters[i].OptionalMdlSize);
            if (mdl == NULL)
            {
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            parameterOptions[i] |= ScDescOptReleaseResource;
            translatedParameters[i] = (ULONGLONG)mdl;
            
            //
            // No need to check everything else, only MDL encapsulation was set.
            //
            continue;
        }

        //
        // PID -> E(K)PROCESS
        //
        if ((parameterOptions[i] & ScDescOptPidToProcessObject) == ScDescOptPidToProcessObject)
        {
            status = PsLookupProcessByProcessId(ULongToHandle((ULONG)parameters[i].u.Value),
                                                &process);
            if (!NT_SUCCESS(status))
            {
                goto Exit;
            }

            if ((parameterOptions[i] & ScDescOptEncapsulateAsMdl) == ScDescOptEncapsulateAsMdl)
            {
                mdl = NULL;
                mdl = EncapsulateParameterAsMdl(reinterpret_cast<ULONGLONG>(process),
                                                parameters[i].OptionalMdlSize);
                if (mdl == NULL)
                {
                    //
                    // Cleanup before leaving.
                    //
                    ObDereferenceObject(process);

                    status = STATUS_INVALID_PARAMETER;
                    goto Exit;
                }

                //
                // We no longer need the process object.
                //
                ObDereferenceObject(process);

                parameterOptions[i] |= ScDescOptReleaseResource;
                translatedParameters[i] = (ULONGLONG)mdl;
            }
            else
            {
                //
                // Only the process was requested.
                //
                parameterOptions[i] |= ScDescOptReleaseResource;
                translatedParameters[i] = (ULONGLONG)process;
            }
        }

        //
        // PID -> E(K)PROCESS -> secure process handle
        //
        if ((parameterOptions[i] & ScDescOptPidToSecureProcessHandle) == ScDescOptPidToSecureProcessHandle)
        {
            //
            // This is a "direct" value which never will be encapsulated by an MDL.
            //
            if ((parameterOptions[i] & ScDescOptEncapsulateAsMdl) == ScDescOptEncapsulateAsMdl)
            {
                NT_ASSERT(FALSE);
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            status = PsLookupProcessByProcessId(ULongToHandle((ULONG)parameters[i].u.Value),
                                                &process);
            if (!NT_SUCCESS(status))
            {
                goto Exit;
            }

            offset = 0;
            offset = GetKernelStructureOffset(StructureOffsetSecureStateOffset);
            if (offset == 0)
            {
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            translatedParameters[i] = *(ULONGLONG*)((unsigned char*)process + offset);

            //
            // We only need the object to get the secure process handle.
            // No cleanup needed afterwards, just dereference after the operation.
            //
            ObDereferenceObject(process);
        }

        //
        // TID -> E(K)THREAD
        //
        if ((parameterOptions[i] & ScDescOptTidToThreadObject) == ScDescOptTidToThreadObject)
        {
            status = PsLookupThreadByThreadId(ULongToHandle((ULONG)parameters[i].u.Value),
                                              &thread);
            if (!NT_SUCCESS(status))
            {
                goto Exit;
            }

            if ((parameterOptions[i] & ScDescOptEncapsulateAsMdl) == ScDescOptEncapsulateAsMdl)
            {
                mdl = NULL;
                mdl = EncapsulateParameterAsMdl(reinterpret_cast<ULONGLONG>(thread),
                                                parameters[i].OptionalMdlSize);
                if (mdl == NULL)
                {
                    //
                    // Cleanup before leaving.
                    //
                    ObDereferenceObject(thread);

                    status = STATUS_INVALID_PARAMETER;
                    goto Exit;
                }

                //
                // No longer need the thread object
                //
                ObDereferenceObject(thread);

                parameterOptions[i] |= ScDescOptReleaseResource;
                translatedParameters[i] = (ULONGLONG)mdl;
            }
            else
            {
                //
                // Only the thread was requested.
                //
                parameterOptions[i] |= ScDescOptReleaseResource;
                translatedParameters[i] = (ULONGLONG)thread;
            }
        }

        //
        // TID -> E(K)THREAD -> secure thread cookie
        //
        if ((parameterOptions[i] & ScDescOptTidToSecureThreadCookie) == ScDescOptTidToSecureThreadCookie)
        {
            //
            // This is a "direct" value which never will be encapsulated by an MDL.
            //
            if ((parameterOptions[i] & ScDescOptEncapsulateAsMdl) == ScDescOptEncapsulateAsMdl)
            {
                NT_ASSERT(FALSE);
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            status = PsLookupThreadByThreadId(ULongToHandle((ULONG)parameters[i].u.Value),
                                              &thread);
            if (!NT_SUCCESS(status))
            {
                goto Exit;
            }

            offset = 0;
            offset = GetKernelStructureOffset(StructureOffsetSecureThreadCookieOffset);
            if (offset == 0)
            {
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            translatedParameters[i] = *(ULONGLONG*)((unsigned char*)thread + offset);

            //
            // We only need the object to get the secure thread cookie.
            // No cleanup needed afterwards, just dereference after the operation.
            //
            ObDereferenceObject(thread);
        }

        //
        // PID -> handle of the section object of the target process
        //
        if ((parameterOptions[i] & ScDescOptPidToSectionObjectHandle) == ScDescOptPidToSectionObjectHandle)
        {
            status = GetProcessSectionObjectHandleFromPid(parameters[i].u.Value,
                                                          &handle);
            if (!NT_SUCCESS(status))
            {
                goto Exit;
            }

            parameterOptions[i] |= ScDescOptReleaseResource;
            translatedParameters[i] = (ULONGLONG)handle;
        }

        //
        // PID -> handle of the associated secure image
        //
        if ((parameterOptions[i] & ScDescOptPidToSecureImageHandle) == ScDescOptPidToSecureImageHandle)
        {
            //
            // This is a "direct" value which never will be encapsulated by an MDL.
            //
            if ((parameterOptions[i] & ScDescOptEncapsulateAsMdl) == ScDescOptEncapsulateAsMdl)
            {
                NT_ASSERT(FALSE);
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            status = GetSecureImageHandleFromProcessId(parameters[i].u.Value,
                                                       &secureImageHandle);
            if (!NT_SUCCESS(status))
            {
                goto Exit;
            }

            translatedParameters[i] = (ULONGLONG)secureImageHandle;
        }

        //
        // Loaded kernel image base -> handle of the associated secure image
        //
        if ((parameterOptions[i] & ScDescOptKernelImageBaseToSecureImageHandle) == ScDescOptKernelImageBaseToSecureImageHandle)
        {
            //
            // This is a "direct" value which never will be encapsulated by an MDL.
            //
            if ((parameterOptions[i] & ScDescOptEncapsulateAsMdl) == ScDescOptEncapsulateAsMdl)
            {
                NT_ASSERT(FALSE);
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            status = GetSecureImageHandleFromKernelImageBase(parameters[i].u.Value,
                                                             &secureImageHandle);
            if (!NT_SUCCESS(status))
            {
                goto Exit;
            }

            translatedParameters[i] = (ULONGLONG)secureImageHandle;
        }

        //
        // VA to into PFNs (not physical address, but PFN).
        //
        if ((parameterOptions[i] & ScDescOptConvertVirtualAddressToPageFrameNumber) == ScDescOptConvertVirtualAddressToPageFrameNumber)
        {
            if (parameters[i].u.Value == 0)
            {
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            physicalAddress = MmGetPhysicalAddress((PVOID)parameters[i].u.Value);
            translatedParameters[i] = (physicalAddress.QuadPart >> PAGE_SHIFT);
        }

        //
        // What this will do is use the provided argument as an index into the already-translated parameters.
        // If it is an MDL, it will set "this" target parameter, which is provided as an "argument number",
        // to the PFN of the target MDL.
        // 
        // A very common pattern is:
        // 
        // Field1 = MDL
        // Field2 = PFN_OF(MDL)
        //
        if ((parameterOptions[i] & ScDescOptGetPfnForMdlAtTargetArgumentField) == ScDescOptGetPfnForMdlAtTargetArgumentField)
        {
            //
            // If this is a valid target it will be 1 byte, so we can cast
            // to ULONG.
            //
            targetArgumentIndex = static_cast<ULONG>(parameters[i].u.Value);

            //
            // First, validate that target field index is valid and is an MDL.
            //
            if ((targetArgumentIndex < 1) ||
                (targetArgumentIndex > MAX_NUMBER_OF_SECURE_CALL_PARAMETERS))
            {
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            //
            // This is the argument number, but we are treating the arguments
            // as an array starting at index 0. so Field1 technically is index 0,
            // Field2 is index 1, etc.
            //
            targetArgumentIndex--;

            //
            // Make sure we are dealing with an MDL.
            //
            if ((parameterOptions[targetArgumentIndex] & ScDescOptEncapsulateAsMdl) == 0)
            {
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            //
            // Extract the MDL from the translated parameter. If it is not an MDL, bail.
            // In all tested secure call scenarios the MDL comes _before_ the PFN - so it should
            // be present.
            //
            if ((translatedParameters[targetArgumentIndex] == 0) &&
                ((translatedParameters[targetArgumentIndex] & 0xfffff00000000000) != 0xfffff00000000000))
            {
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            physicalAddress = MmGetPhysicalAddress((PVOID)translatedParameters[targetArgumentIndex]);
            translatedParameters[i] = (physicalAddress.QuadPart >> PAGE_SHIFT);
        }
    }

    RtlCopyMemory(SecureCallArgs,
                  &secureCallArgs,
                  sizeof(secureCallArgs));

Exit:
    return status;
}

/**
*
* @brief        Cleans up any resources allocated from secure call parameter transformation.
* @param[in]    SecureCallData - The data from SkBridgeClient.
* @param[int]	SecureCallArgs - The final secure call arguments.
*
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
void
CleanupSecureCallResources (
    _In_ PSKBRIDGE_SECURE_CALL_DATA SecureCallData,
    _In_ PSECURE_CALL_ARGS SecureCallArgs
    )
{
    ULONGLONG* parameters;
    ULONG* parameterOptions;
    ULONG objectMask;
    ULONGLONG targetResource;
    ULONG handleMask;
    ULONG mdlMask;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    parameters = &SecureCallArgs->Field1;
    parameterOptions = &SecureCallData->SecureCallFieldDescriptors.Field1Descriptor;
    objectMask = (ScDescOptPidToProcessObject | ScDescOptTidToThreadObject);
    targetResource = 0;
    handleMask = (ScDescOptPidToSectionObjectHandle);
    mdlMask = (ScDescOptEncapsulateAsMdl);

    for (ULONG i = 0; i <= MAX_NUMBER_OF_SECURE_CALL_PARAMETERS; i++)
    {
        targetResource = 0;

        //
        // Make sure we have anyything at all.
        //
        if (parameters[i] == 0)
        {
            continue;
        }

        //
        // SkBridgeDataToSecureCallParameters sets this mask if we need to clean anything up.
        //
        if ((parameterOptions[i] & ScDescOptReleaseResource) == ScDescOptReleaseResource)
        {
            //
            // targetResource is the address of the resource.
            //
            targetResource = parameters[i];

            //
            // Objects
            //
            if ((parameterOptions[i] & objectMask) != 0)
            {
                //
                // There are scenarios where objects are encapsulated
                // as MDLs. If that is the case, we have already dereferenced
                // the object. Just delete the MDL, as the object
                // is nowhere to be found.
                //
                if ((parameterOptions[i] & mdlMask) != 0)
                {
                    IoFreeMdl((PMDL)targetResource);
                    continue;
                }

                ObDereferenceObject((PVOID)targetResource);
            }

            //
            // Handles
            //
            if ((parameterOptions[i] & handleMask) != 0)
            {
                ZwClose((HANDLE)targetResource);
            }

            //
            // MDLs
            //
            if ((parameterOptions[i] & mdlMask) != 0)
            {
                IoFreeMdl((PMDL)targetResource);
            }
        }
    }

    return;
}

/**
*
* @brief        Initializes all offsets for kernel structures and nt!VslpEnterIumSecureMode.
* @param[in]    InitData - Offset information from the symbols via SkBridgeClient.
*
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
void
InitializeSkBridgeOffsets (
    _In_ PSKBRIDGE_INIT_DATA InitData
    )
{
    ULONG_PTR ntBase;
    UNICODE_STRING loadedList = RTL_CONSTANT_STRING(L"PsLoadedModuleList");
    UNICODE_STRING loadedListResource = RTL_CONSTANT_STRING(L"PsLoadedModuleResource");

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    ntBase = 0;

    RtlCopyMemory(&k_SkBridgeInitData,
                  InitData,
                  sizeof(k_SkBridgeInitData));

    //
    // Get the base of NT.
    //
    if (RtlPcToFileHeader(reinterpret_cast<PVOID>(PsGetCurrentProcessId),
                          reinterpret_cast<PVOID*>(&ntBase)) == NULL)
    {
        NT_ASSERT(FALSE);
        goto Exit;
    }

    //
    // Preserve the base address of VslpEnterIumSecureMode.
    //
    VslpEnterIumSecureMode = reinterpret_cast<VslpEnterIumSecureMode_t>(ntBase + k_SkBridgeInitData.VslpEnterIumSecureModeOffset);

    //
    // We also need to resolve PsLoadedModuleList and PsLoadedModuleResource.
    //
    PsLoadedModuleList = reinterpret_cast<PLIST_ENTRY>(MmGetSystemRoutineAddress(&loadedList));
    PsLoadedModuleResource = reinterpret_cast<PERESOURCE>(MmGetSystemRoutineAddress(&loadedListResource));

    if ((PsLoadedModuleList == NULL) ||
        (PsLoadedModuleResource == NULL))
    {
        NT_ASSERT(FALSE);
        goto Exit;
    }

    //
    // User-mode provides the offsets from the symbols.
    //
    if (!g_KnownOffsetArrayInitialized)
    {
        g_KnownOffsetArrayInitialized = true;
    }

Exit:
    return;
}