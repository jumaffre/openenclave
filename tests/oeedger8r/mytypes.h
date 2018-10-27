// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <stdint.h>

// These types are different between MSVC and GCC/Clang, so we define them.
typedef uint16_t oe_wchar_t;
typedef int32_t oe_long_t;
typedef double oe_long_double_t;

typedef struct
{
    int x;
    int y;
} my_type1;

typedef my_type1* my_type2;

typedef my_type1 my_type3[10];
