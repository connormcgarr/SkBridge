/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeClient/Examples.cpp
*
* @summary:   Examples of using the SkBridgeClient to execute secure calls.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#include "Examples.hpp"
#include "Shared.hpp"
#include "Helpers.hpp"

/**
*
* @brief        Issues the SECURESERVICE_GET_TEB_ADDRESS secure call.
*
*/
void
ExampleGetSecureTebAddress ()
{
    NTSTATUS status;
    SKBRIDGE_SECURE_CALL_DATA secureCallData;
    ULONG lsaIsoTid;

    RtlZeroMemory(&secureCallData, sizeof(secureCallData));

    status = STATUS_SUCCESS;

    /*
        0: kd> dx -g @$cursession.Processes.Where(p => p.Name.Contains("LsaIso")).Select(t => t.Threads).Select(t => t.First(t => t.KernelObject.Tcb.SecureThreadCookie)).Select(t => new {ThreadId = t.Id}),d
        ============================
        =           = (+) ThreadId =
        ============================
        = [1000]    - 1004         =
        ============================ 

        ThreadID == 1004
    */

    //
    // TID of LsaIso
    //
    status = GetLsaIsoTid(&lsaIsoTid);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"[-] Error! GetLsaIsoTid failed! (NTSTATUS: %X)\n", status);
        goto Exit;
    }

    secureCallData.SecureCallFields.Field1.u.Value = lsaIsoTid;
    secureCallData.SecureCallFieldDescriptors.Field1Descriptor = ScDescOptTidToSecureThreadCookie;

    //
    // TID of LsaIso
    //
    secureCallData.SecureCallFields.Field2.u.Value = lsaIsoTid;
    secureCallData.SecureCallFieldDescriptors.Field2Descriptor = ScDescOptTidToThreadObject;

    secureCallData.SecureCallType = GetSecureCallValue(L"SECURESERVICE_GET_TEB_ADDRESS");

    status = VslpEnterIumSecureModeWrapper(&secureCallData);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // See if the actual Secure call was successful.
    //
    if (!NT_SUCCESS(secureCallData.Status))
    {
        wprintf(L"[-] Error! Secure call failed (NTSTATUS: %X)\n", secureCallData.Status);
        goto Exit;
    }

    wprintf(L"[+] SECURESERVICE_GET_TEB_ADDRESS succeeded! SKTEB: 0x%llx\n", secureCallData.OptionalOutput);

Exit:
    return;
}

/**
*
* @brief        Issues the SECURESERVICE_GET_PEB_ADDRESS secure call.
*
*/
void
ExampleGetSecurePebAddress ()
{
    NTSTATUS status;
    ULONG lsaIsoPid;
    ULONG lsaIsoTid;
    SKBRIDGE_SECURE_CALL_DATA secureCallData;

    RtlZeroMemory(&secureCallData, sizeof(secureCallData));

    status = STATUS_SUCCESS;
    lsaIsoPid = 0;
    lsaIsoTid = 0;

    /*
        3: kd> dx @$cursession.Processes.Where(p => p.Name.Contains("LsaIso")).Select(p => p.Id),d
        @$cursession.Processes.Where(p => p.Name.Contains("LsaIso")).Select(p => p.Id),d                
            [988]            : 988

            PID == 988
    */

    //
    // PID of LsaIso
    //
    status = GetLsaIsoPid(&lsaIsoPid);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"[-] Error! GetLsaIsoPid failed! (NTSTATUS: %X)\n", status);
        goto Exit;
    }

    //
    // TID of LsaIso
    //
    status = GetLsaIsoTid(&lsaIsoTid);
    if (!NT_SUCCESS(status))
    {
        wprintf(L"[-] Error! GetLsaIsoTid failed! (NTSTATUS: %X)\n", status);
        goto Exit;
    }

    secureCallData.SecureCallFields.Field1.u.Value = lsaIsoPid;
    secureCallData.SecureCallFieldDescriptors.Field1Descriptor = ScDescOptPidToSecureProcessHandle;

    //
    // Please note, this is _not_ necessary for this secure call. This simply exists to outline
    // an example where we want the target secure call to be issued on a _particular thread_ which is a secure thread
    // that has a secure cookie value.
    //
    secureCallData.ExtendedParameters.OptionalSecureThreadCookieThreadId = lsaIsoTid;
    secureCallData.ExtendedParameterOptions = ScExtendedParameterHasSecureThreadCookie;

    secureCallData.SecureCallType = GetSecureCallValue(L"SECURESERVICE_GET_PEB_ADDRESS");

    status = VslpEnterIumSecureModeWrapper(&secureCallData);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // See if the actual Secure call was successful.
    //
    if (!NT_SUCCESS(secureCallData.Status))
    {
        wprintf(L"[-] Error! Secure call failed (NTSTATUS: %X)\n", secureCallData.Status);
        goto Exit;
    }

    wprintf(L"[+] SECURESERVICE_GET_PEB_ADDRESS succeeded! SKPEB: 0x%llx\n", secureCallData.OptionalOutput);

Exit:
    return;
}

/**
*
* @brief        Issues the SECURESERVICE_CREATE_SECURE_ALLOCATION and SECURESERVICE_FILL_SECURE_ALLOCATION
*               secure calls.
*
*/
void
ExampleCreateAndFillSecureAllocation ()
{
    NTSTATUS status;
    SKBRIDGE_SECURE_CALL_DATA secureCallData;
    ULONGLONG secureAllocationHandle;
    PVOID allocation;

    RtlZeroMemory(&secureCallData, sizeof(secureCallData));

    status = STATUS_SUCCESS;
    secureAllocationHandle = 0;

    allocation = malloc(0x1000);
    if (allocation == NULL)
    {
        wprintf(L"[-] Error! malloc failed. (GLE: %d)\n", GetLastError());
        goto Exit;
    }

    memset(allocation, 0x41, 0x1000);

    //
    // Specify the number of bytes in the allocation
    //
    secureCallData.SecureCallFields.Field1.u.Value = 0x1000;

    secureCallData.SecureCallType = GetSecureCallValue(L"SECURESERVICE_CREATE_SECURE_ALLOCATION");

    status = VslpEnterIumSecureModeWrapper(&secureCallData);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    if (!NT_SUCCESS(secureCallData.Status))
    {
        wprintf(L"[-] Error! Secure call failed (NTSTATUS: %X)\n", secureCallData.Status);
        goto Exit;
    }
    //
    // We now have a handle to the secure allocation
    //
    secureAllocationHandle = secureCallData.OptionalOutput;

    wprintf(L"[+] SECURESERVICE_CREATE_SECURE_ALLOCATION succeeded! Secure allocation handle: 0x%llX\n", secureAllocationHandle);

    //
    // Fill the allocation
    //
    RtlZeroMemory(&secureCallData, sizeof(secureCallData));

    //
    // Secure allocation handle
    //
    secureCallData.SecureCallFields.Field1.u.Value = secureAllocationHandle;

    //
    // Offset
    //
    secureCallData.SecureCallFields.Field2.u.Value = 0;

    //
    // Technically MDL describing the allocation.
    // 
    // This setup will ask SkBridge to encapsulate the address as an MDL and to use
    // the following size when creating the MDL.
    //
    secureCallData.SecureCallFields.Field3.u.Value = (ULONGLONG)allocation;
    secureCallData.SecureCallFields.Field3.OptionalMdlSize = 0x1000;
    secureCallData.SecureCallFieldDescriptors.Field3Descriptor = ScDescOptEncapsulateAsMdl;

    //
    // This instructs SkBridgeDriver to make argument 4 the PFN of argument 3 (which is an MDL).
    // This flag requires that the target field has "ScDescOptEncapsulateAsMdl" set.
    // 
    // A very common pattern is to encapsulate a parameter as an MDL and the _next_ parameter becomes the PFN
    // of the MDL which describes the parameter which has been encapsulated by an MDL.
    //
    secureCallData.SecureCallFields.Field4.u.Value = 3;
    secureCallData.SecureCallFieldDescriptors.Field4Descriptor = ScDescOptGetPfnForMdlAtTargetArgumentField;

    secureCallData.SecureCallType = GetSecureCallValue(L"SECURESERVICE_FILL_SECURE_ALLOCATION");

    status = VslpEnterIumSecureModeWrapper(&secureCallData);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // See if the actual Secure call was successful.
    //
    if (!NT_SUCCESS(secureCallData.Status))
    {
        wprintf(L"[-] Error! Secure call failed (NTSTATUS: %X)\n", secureCallData.Status);
        goto Exit;
    }

    wprintf(L"[+] SECURESERVICE_FILL_SECURE_ALLOCATION succeeded!\n");

Exit:
    if (allocation != NULL)
    {
        free(allocation);
    }

    return;
}

/**
*
* @brief        Issues the SECURESERVICE_APPLY_FIXUPS secure call.
*
*/
void
ExampleApplySecureImageFixup ()
{
    NTSTATUS status;
    SKBRIDGE_SECURE_CALL_DATA secureCallData;
    ULONG_PTR kernelBaseImage;

    RtlZeroMemory(&secureCallData, sizeof(secureCallData));

    status = STATUS_SUCCESS;
    kernelBaseImage = GetBaseImageOfTargetDriver("SkBridgeDriver.sys");

    //
    // Secure image handle
    //
    secureCallData.SecureCallFields.Field1.u.Value = kernelBaseImage;
    secureCallData.SecureCallFieldDescriptors.Field1Descriptor = ScDescOptKernelImageBaseToSecureImageHandle;

    //
    // 0 (MI_IMAGE_ADDITIONAL_INFO.DynamicRelocations index); -> indexes the SECURE_IMAGE object in SK's
    // mapping of dynamic relocations.
    //
    secureCallData.SecureCallFields.Field2.u.Value = 0;

    //
    // PFN of image base
    //
    secureCallData.SecureCallFields.Field3.u.Value = kernelBaseImage;
    secureCallData.SecureCallFieldDescriptors.Field3Descriptor = ScDescOptConvertVirtualAddressToPageFrameNumber;

    secureCallData.SecureCallType = GetSecureCallValue(L"SECURESERVICE_APPLY_FIXUPS");

    status = VslpEnterIumSecureModeWrapper(&secureCallData);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // See if the actual Secure call was successful.
    //
    if (!NT_SUCCESS(secureCallData.Status))
    {
        wprintf(L"[-] Error! Secure call failed (NTSTATUS: %X)\n", secureCallData.Status);
        goto Exit;
    }

    wprintf(L"[+] SECURESERVICE_APPLY_FIXUPS succeeded!\n");

Exit:
    return;
}