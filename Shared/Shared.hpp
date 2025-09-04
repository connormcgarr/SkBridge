/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeDriver/Shared.hpp
*
* @summary:   Shared definitions between SkBridgeClient and SkBridgeDriver.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#pragma once

//
// Redefine basic types for sharing this file between UM and KM
//
typedef long LONG;
typedef unsigned long ULONG;
typedef LONG NTSTATUS;
typedef unsigned char UCHAR;
typedef unsigned long long ULONGLONG;

//
// Accepted IOCTLs
//
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

#define SKBRIDGE_IOCTL_DISPATCH_SECURE_CALL \
CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#define SKBRIDGE_IOCTL_INIT_KERNEL_STRUCTS \
CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

//
// Maximum number of secure call parameters
//
#define MAX_NUMBER_OF_SECURE_CALL_PARAMETERS 12

//
// Special Secure Call extended options
//
enum SecureCallExtendedParameterOptions : ULONG
{
    ScExtendedParameterOptionsNone = 0,

    //
    // The secure call needs to be executed in context of a secure thread.
    //
    ScExtendedParameterHasSecureThreadCookie = 0x1,
};

//
// Extended parameters
//
typedef struct _SECURE_CALL_EXTENDED_PARAMETERS
{
    //
    // Some secure calls requie being executed in context of a particular secure process, and not the
    // "Secure System" process. In these cases, a "Secure process handle", part of a secure process EPROCESS object,
    // can be specified. These values are typically 0x140000XXX in value. and can be found in
    // EPROCESS.SecureState.EntireField
    //
    ULONGLONG SecureProcessHandleToUse;

    //
    // Some secure calls require being executed
    // on a secure thread which the Secure Kernel already knows about (KTHREAD.SecureThreadCookie). When this field is set,
    // the secure call will be issued on this thread.
    // 
    // If the "UseThreadWithSecureCookie" option is specified, this is the target thread which will be used (SkBridgeDriver will queue
    // a special APC to this thread)
    // 
    // It is still possible to specify "UseThreadWithSecureCookie" and _not_ specify a particular TID. In this case
    //
    ULONG OptionalSecureThreadCookieThreadId;
}   SECURE_CALL_EXTENDED_PARAMETERS, *PSECURE_CALL_EXTENDED_PARAMETERS;

//
// Secure call parameter descriptor values
//
enum SecureCallParameterDescriptorOptions : ULONG
{
    ScDescOptNone = 0,
    ScDescOptEncapsulateAsMdl = 0x1,
    ScDescOptPidToProcessObject = 0x2,
    ScDescOptPidToSecureProcessHandle = 0x4,
    ScDescOptTidToThreadObject = 0x8,
    ScDescOptTidToSecureThreadCookie = 0x10,

    //
    // A "special" flag which will create a handle to the section object
    // of a loaded image.
    //
    ScDescOptPidToSectionObjectHandle = 0x20,

    //
    // A "special" flag which will retrieve the associated secure image handle
    // from an already-mapped process or kernel-mode image.
    //
    ScDescOptPidToSecureImageHandle = 0x40,
    ScDescOptKernelImageBaseToSecureImageHandle = 0x80,
    
    //
    // Converts the specified VA to PFN
    //
    ScDescOptConvertVirtualAddressToPageFrameNumber = 0x100,

    //
    // A common pattern in SK is to provide the PFN for an MDL,
    // which already describes a parameter, as a parameter itself.
    // This flag instructs SkBridgeDriver as to what argument number
    // the MDL exists at for which this field should be a PFN
    // 
    // An example is Field2.u.Value = address;
    // 
    // If Field2 has the "encapsulate as MDL" flag, set this
    // value to 2. This will make the target argument the PFN
    // of that MDL.
    //
    ScDescOptGetPfnForMdlAtTargetArgumentField = 0x200,

    //
    // Reserved for SkBridgeDriver
    //
    ScDescOptReleaseResource = 0x81000000,
};

typedef struct _SKBRIDGE_GENERIC_SECURE_CALL_FIELD
{
    union
    {
        ULONGLONG Value;
        struct
        {
            ULONG Lower;
            ULONG Upper;
        } ValueAsULong;
    } u;

    ULONG OptionalMdlSize;
} SKBRIDGE_GENERIC_SECURE_CALL_FIELD, *PSKBRIDGE_GENERIC_SECURE_CALL_FIELD;

//
// "Main" Secure call data to send to the SkBridge driver
//
typedef struct _SKBRIDGE_SECURE_CALL_DATA
{
    SECURE_CALL_EXTENDED_PARAMETERS ExtendedParameters;
    ULONGLONG OptionalOutput;
    NTSTATUS Status;
    ULONG SecureCallType;
    ULONG ExtendedParameterOptions;

    struct
    {
        SKBRIDGE_GENERIC_SECURE_CALL_FIELD Field1;
        SKBRIDGE_GENERIC_SECURE_CALL_FIELD Field2;
        SKBRIDGE_GENERIC_SECURE_CALL_FIELD Field3;
        SKBRIDGE_GENERIC_SECURE_CALL_FIELD Field4;
        SKBRIDGE_GENERIC_SECURE_CALL_FIELD Field5;
        SKBRIDGE_GENERIC_SECURE_CALL_FIELD Field6;
        SKBRIDGE_GENERIC_SECURE_CALL_FIELD Field7;
        SKBRIDGE_GENERIC_SECURE_CALL_FIELD Field8;
        SKBRIDGE_GENERIC_SECURE_CALL_FIELD Field9;
        SKBRIDGE_GENERIC_SECURE_CALL_FIELD Field10;
        SKBRIDGE_GENERIC_SECURE_CALL_FIELD Field11;
        SKBRIDGE_GENERIC_SECURE_CALL_FIELD Field12;

    } SecureCallFields;

    struct
    {
        ULONG Field1Descriptor;
        ULONG Field2Descriptor;
        ULONG Field3Descriptor;
        ULONG Field4Descriptor;
        ULONG Field5Descriptor;
        ULONG Field6Descriptor;
        ULONG Field7Descriptor;
        ULONG Field8Descriptor;
        ULONG Field9Descriptor;
        ULONG Field10Descriptor;
        ULONG Field11Descriptor;
        ULONG Field12Descriptor;
    } SecureCallFieldDescriptors;

} SKBRIDGE_SECURE_CALL_DATA, *PSKBRIDGE_SECURE_CALL_DATA;

//
// "Initialization" definitions for known offsets
//
enum StructureOffsets : ULONG
{
    StructureOffsetSecureStateOffset = 0,
    StructureOffsetSecureThreadCookieOffset = 1,
    StructureOffsetSectionObjectOffset = 2,
    StructureOffsetControlAreaOffset = 3,
    StructureOffsetImageInfoRefOffset = 4,
    StructureOffsetStrongImageReferenceOffset = 5,

    //
    // Next value goes here
    //
    StructureOffsetMax
};

typedef struct _SKBRIDGE_INIT_DATA
{
    ULONGLONG StructureOffsetArray[StructureOffsetMax];
    ULONGLONG VslpEnterIumSecureModeOffset;
} SKBRIDGE_INIT_DATA, *PSKBRIDGE_INIT_DATA;