/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeDriver/SkDefs.hpp
*
* @summary:   Various Secure Kernel definitions.
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
// "Generic" secure call structure
//
union SECURE_CALL_RESERVED_FIELD
{
    ULONGLONG ReservedFullField;
    union
    {
        struct
        {
            UINT8 OperationType;
            UINT16 SecureCallOrSystemCallCode;
            ULONG SecureThreadCookie;
        } FieldData;
    } u;
};

typedef struct _SECURE_CALL_ARGS
{
    SECURE_CALL_RESERVED_FIELD Reserved;
    ULONGLONG Field1;
    ULONGLONG Field2;
    ULONGLONG Field3;
    ULONGLONG Field4;
    ULONGLONG Field5;
    ULONGLONG Field6;
    ULONGLONG Field7;
    ULONGLONG Field8;
    ULONGLONG Field9;
    ULONGLONG Field10;
    ULONGLONG Field11;
    ULONGLONG Field12;
} SECURE_CALL_ARGS, *PSECURE_CALL_ARGS;