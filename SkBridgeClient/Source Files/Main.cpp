/*++
* Copyright (c) Connor McGarr. All rights reserved.
*
* @file:      SkBridgeClient/Main.hpp
*
* @summary:   SkBridgeClient entry point.
*
* @author:    Connor McGarr (@33y0re)
*
* @copyright  Use of this source code is governed by a MIT-style license that
*             can be found in the LICENSE file.
*
--*/
#include "Shared.hpp"
#include "Helpers.hpp"
#include "Examples.hpp"
#include "Initialization.hpp"

/**
*
* @brief        SkBridgeClient entry point.
* @param[in]    argc - Number of arguments.
* @param[in]	argv - Argument array.
* @return       ERROR_SUCCESS on success, otherwise appropriate error code.
*
*/
int
wmain (
    _In_ int argc,
    _In_ wchar_t**argv
    )
{
    ULONG error;

    error = ERROR_GEN_FAILURE;

    //
    // Sets up communications, symbols, etc. with SkBridgeDriver.
    //
    if (!InitializeSkBridge())
    {
        goto Exit;
    }
    
    //
    // Examples.cpp
    // 

    //
    // Issue a few secure calls!
    //
    ExampleGetSecureTebAddress();
    ExampleGetSecurePebAddress();
    ExampleCreateAndFillSecureAllocation();
    ExampleApplySecureImageFixup();

    //
    // Tear it all down.
    //
    CleanupSkBridgeClient();

    error = ERROR_SUCCESS;

Exit:
    return error;
}