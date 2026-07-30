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
class KThread;

typedef void (*SugarbombNativeCallback)(CPU* cpu);
typedef void (*SugarbombPageFaultObserver)(
    KThread* thread,
    U32 address);

class SugarbombBridge {
public:
    static U32 registerCallback(const std::string& module, const std::string& name, SugarbombNativeCallback callback);
    static bool dispatch(CPU* cpu, U32 index);
    static bool callbackName(U32 index, std::string& module, std::string& name);
    static std::size_t callbackCount();
    static void setPageFaultObserver(SugarbombPageFaultObserver observer);
    static void notifyPageFault(KThread* thread, U32 address);
#ifdef __TEST
    static void clearForTests();
#endif
};

class SugarbombThunkArena {
public:
    bool initialize(KThread* thread, U32 base, U32 size, std::string& error);
    bool createThunk(U32 callbackIndex, U16 stackCleanupBytes, U32& guestAddress, std::string& error);
    bool beginUpdate(std::string& error);
    bool finalize(std::string& error);

    U32 base() const { return arenaBase; }
    U32 size() const { return arenaSize; }
    U32 thunkCount() const { return allocatedThunks; }
    bool finalized() const { return isFinalized; }

private:
    KThread* thread = nullptr;
    U32 arenaBase = 0;
    U32 arenaSize = 0;
    U32 nextAddress = 0;
    U32 allocatedThunks = 0;
    bool isFinalized = false;
};

void callSugarbomb(CPU* cpu, U32 index);

#endif
