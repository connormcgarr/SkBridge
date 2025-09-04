/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeDriver/SkImplementations.cpp
*
* @summary:   Secure call implementation.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#include <ntifs.h>
#include "SkImplementations.hpp"
#include "Helpers.hpp"

PAGED_FILE()

//
// nt!VslpEnterIumSecureMode
//
VslpEnterIumSecureMode_t VslpEnterIumSecureMode = NULL;

//
// Just an event object globally to SkImplementation since we only
// are ever going to execute an APC "one-at-a-time"
//
static KEVENT k_ApcEvent = { 0 };

/**
*
* @brief          APC routine for issuing a secure call on a target thread.
* @param[in,out]  NormalRoutine - Unused.
* @param[in,out]  NormalContext - Unused.
* @param[in,out]  SystemArgument1 - The secure call arguments.
* @param[in,out]  SystemArgument2 - Unused.
* 
*/
static
_Function_class_(KKERNEL_ROUTINE)
_IRQL_requires_(APC_LEVEL)
_IRQL_requires_same_
VOID
NTAPI
GenericSecureCallApcRoutine (
    _In_ PKAPC Apc,
    _Inout_ _Deref_pre_maybenull_ PKNORMAL_ROUTINE* NormalRoutine,
    _Inout_ _Deref_pre_maybenull_ PVOID* NormalContext,
    _Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument1,
    _Inout_ _Deref_pre_maybenull_ PVOID* SystemArgument2
    )
{
    NTSTATUS status;
    PSECURE_CALL_APC_ARGS secureArgs;
    PVOID* systemArgument1;

    PAGED_CODE();

    status = STATUS_SUCCESS;
    secureArgs = NULL;
    systemArgument1 = NULL;

    UNREFERENCED_PARAMETER(Apc);
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument2);

    systemArgument1 = SystemArgument1;
    if (systemArgument1 == NULL)
    {
        goto Exit;
    }

    if (*systemArgument1 == NULL)
    {
        goto Exit;
    }

    //
    // We already know systemArgument1, dereferenced, is not NULL.
    //
    secureArgs = reinterpret_cast<PSECURE_CALL_APC_ARGS>(*systemArgument1);

    NT_ASSERT(VslpEnterIumSecureMode != NULL);

    //
    // Only secure calls are supported here (first parameter of 2), but technically
    // it is still possible to issue enclave calls (1) or flushing TB calls (3)
    //
    status = VslpEnterIumSecureMode(2,
                                    secureArgs->SecureCallType,
                                    0,
                                    &secureArgs->SecureCallArgs);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[-] Error! VslpEnterIumSecureMode (via APC) failed (NTSTATUS: %X\n", status);
    }

    //
    // Preserve the status.
    //
    secureArgs->Status = status;

Exit:
    //
    // We are done!
    //
    KeSetEvent(&k_ApcEvent,
               EVENT_INCREMENT,
               FALSE);

    return;
}

/**
*
* @brief        Issues the target secure call.
* @param[in]    SecureCallData - The secure call data from SkBridgeClient.
* @return       STATUS_SUCCESS on success, otherwise appropriate NTSTATUS code.    
*
*/
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
IssueSecureCall (
    _In_ PVOID SecureCallData
    )
{
    NTSTATUS status;
    PSKBRIDGE_SECURE_CALL_DATA secureCallData;
    SECURE_CALL_ARGS originalArgs;
    SECURE_CALL_ARGS secureCallArgs;
    PKTHREAD thread;
    PKAPC apc;
    bool useApc;
    bool releaseThread;
    PSECURE_CALL_APC_ARGS secureCallApcArg;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    status = STATUS_SUCCESS;
    thread = NULL;
    apc = NULL;
    useApc = false;
    releaseThread = false;
    secureCallData = reinterpret_cast<PSKBRIDGE_SECURE_CALL_DATA>(SecureCallData);
    secureCallApcArg = NULL;

    RtlZeroMemory(&secureCallArgs, sizeof(secureCallArgs));
    RtlZeroMemory(&originalArgs, sizeof(originalArgs));

    status = SkBridgeDataToSecureCallParameters(secureCallData,
                                                &secureCallArgs);
    if (!NT_SUCCESS(status))
    {
        goto Exit;
    }

    //
    // Preserve the original arguments for resource cleanup later.
    //
    RtlCopyMemory(&originalArgs,
                  &secureCallArgs,
                  sizeof(originalArgs));

    //
    // Determine if there is a particular thread we need to handle this request on.
    //
    if (secureCallData->ExtendedParameterOptions != ScExtendedParameterOptionsNone)
    {
        if ((secureCallData->ExtendedParameterOptions & ScExtendedParameterHasSecureThreadCookie) == ScExtendedParameterHasSecureThreadCookie)
        {
            //
            // It is true that it is possible to manually set the secure thread cookie value in the "reserved" portion of the secure call arguments.
            // However, testing revealed that if a secure thread cookie was specified and the target operation was a secure call (and not, for instance,
            // and enclave call/secure system call) but the target process was not the secure process associated with the secure thread, the Secure Kernel,
            // when attaching to the target thread specified by the secure thread cookie, returned STATUS_INVALID_PARAMETER. Because of this we can "achieve"
            // the same result by queueing an APC to a thread which has a secure thread cookie value.
            //
            useApc = true;

            if (secureCallData->ExtendedParameters.OptionalSecureThreadCookieThreadId == 0)
            {
                status = STATUS_INVALID_PARAMETER;
                goto Exit;
            }

            //
            // Lookup the target thread.
            //
            status = PsLookupThreadByThreadId(ULongToHandle(secureCallData->ExtendedParameters.OptionalSecureThreadCookieThreadId),
                                              &thread);
            if (!NT_SUCCESS(status))
            {
                DbgPrint("[-] Error! The target thread for specifying a secure thread cookie was invalid! (NTSTATUS: %X\n", status);
                goto Exit;
            }

            releaseThread = true;
        }
    }

    //
    // Do things "directly"
    //
    if (!useApc)
    {
        NT_ASSERT(VslpEnterIumSecureMode != NULL);

        //
        // The first parameter is _always_ 2 (for secure call). It is possible
        // to set this to 1 or 3 for enclaves or flushing the TB.
        //
        status = VslpEnterIumSecureMode(2,
                                        secureCallData->SecureCallType,
                                        0,
                                        &secureCallArgs);
        if (!NT_SUCCESS(status))
        {
            DbgPrint("[-] Error! VslpEnterIumSecureMode failed (NTSTATUS: %X\n", status);
        }

        //
        // We don't want to leak anything which was translated back up to UM.
        //
        RtlZeroMemory(&secureCallData->SecureCallFields,
                      sizeof(secureCallData->SecureCallFields));

        //
        // Update the output buffer with the status of the operation.
        //
        secureCallData->Status = status;

        //
        // At this point we have successfully issued the secure call.
        // However, if the secure call failed we do not want
        // to bubble up the _secure call status_ as the result of the IOCTL
        // which was issued. Now we can "fake" success, and the real result
        // of the secure call will be returned to the user.
        //
        status = STATUS_SUCCESS;

        //
        // We have optional output. It is always located at "Field2".
        // Very few secure calls support more than 1 field of output,
        // but for our purposes we just limit output to 1 field.
        // 
        secureCallData->OptionalOutput = secureCallArgs.Field2;
        goto Exit;
    }

    //
    // We are now going to try issuing the secure call as part of an APC.
    // We should always have a target thread to queue to.
    //
    if (thread == NULL)
    {
        NT_ASSERT(thread != NULL);
        status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    //
    // Allocate memory for the secure args.
    //
    secureCallApcArg = reinterpret_cast<PSECURE_CALL_APC_ARGS>(ExAllocatePool2(POOL_FLAG_PAGED,
                                                               sizeof(SECURE_CALL_APC_ARGS),
                                                               MY_POOL_TAG));
    if (secureCallApcArg == NULL)
    {
        goto Exit;
    }

    //
    // Prepare the args for the APC
    //
    secureCallApcArg->SecureCallType = secureCallData->SecureCallType;

    RtlCopyMemory(&secureCallApcArg->SecureCallArgs,
                  &secureCallArgs,
                  sizeof(secureCallArgs));

    //
    // APCs are still touched at DISPATCH_LEVEL.
    //
    apc = reinterpret_cast<PKAPC>(ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                  sizeof(KAPC),
                                  MY_POOL_TAG));
    if (apc == NULL)
    {
        goto Exit;
    }

    KeInitializeEvent(&k_ApcEvent,
                      SynchronizationEvent,
                      FALSE);

    KeInitializeApc(apc,
                    thread,
                    OriginalApcEnvironment,
                    GenericSecureCallApcRoutine,
                    NULL,
                    NULL,
                    UserMode,
                    NULL);

    //
    // Actually queue the APC!
    //
    if (KeInsertQueueApc(apc,
                         secureCallApcArg,
                         NULL,
                         IO_NO_INCREMENT) == FALSE)
    {
        status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }

    //
    // Wait for the APC to finish.
    //
    status = KeWaitForSingleObject(&k_ApcEvent,
                                   Executive,
                                   KernelMode,
                                   FALSE,
                                   0);
    
    //
    // We don't want to leak anything which was translated back up to UM.
    //
    RtlZeroMemory(&secureCallData->SecureCallFields,
                  sizeof(secureCallData->SecureCallFields));

    //
    // Update the output buffer with the status of the operation.
    //
    secureCallData->Status = secureCallApcArg->Status;

    //
    // We have optional output. It is always located at "Field2".
    // Some secure calls can have more, but for our purposes we
    // just return one field of output, as this is what almost all
    // secure calls do.
    //
    secureCallData->OptionalOutput = secureCallApcArg->SecureCallArgs.Field2;

Exit:
    if (releaseThread)
    {
        ObDereferenceObject(thread);
    }

    if (secureCallApcArg != NULL)
    {
        ExFreePool2(secureCallApcArg,
                    MY_POOL_TAG,
                    NULL,
                    0);
    }

    if (apc)
    {
        ExFreePool2(apc,
                    MY_POOL_TAG,
                    NULL,
                    0);
    }

    //
    // We may have allocated MDLs, opened objects, etc.
    // Clean that up here.
    //
    CleanupSecureCallResources(secureCallData,
                               &originalArgs);

    return status;
}