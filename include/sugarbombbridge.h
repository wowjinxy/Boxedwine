/*
 *  Copyright (C) 2026  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifndef __SUGARBOMB_BRIDGE_H__
#define __SUGARBOMB_BRIDGE_H__

#include <cstddef>
#include <string>

class CPU;

typedef void (*SugarbombNativeCallback)(CPU* cpu);

class SugarbombBridge {
public:
    static U32 registerCallback(const std::string& module, const std::string& name, SugarbombNativeCallback callback);
    static bool dispatch(CPU* cpu, U32 index);
    static std::size_t callbackCount();
#ifdef __TEST
    static void clearForTests();
#endif
};

void callSugarbomb(CPU* cpu, U32 index);

#endif
