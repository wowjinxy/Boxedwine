/*
 *  Copyright (C) 2026  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "boxedwine.h"
#include "sugarbombbridge.h"

namespace {

constexpr U32 THUNK_SIZE = 16;

struct SugarbombCallbackEntry {
    std::string module;
    std::string name;
    SugarbombNativeCallback callback = nullptr;
};

std::vector<SugarbombCallbackEntry> callbacks;
std::mutex callbacksMutex;

} // namespace

U32 SugarbombBridge::registerCallback(const std::string& module, const std::string& name, SugarbombNativeCallback callback) {
    std::lock_guard<std::mutex> lock(callbacksMutex);
    SugarbombCallbackEntry entry;
    entry.module = module;
    entry.name = name;
    entry.callback = callback;
    callbacks.push_back(entry);
    return static_cast<U32>(callbacks.size() - 1);
}

bool SugarbombBridge::dispatch(CPU* cpu, U32 index) {
    SugarbombNativeCallback callback = nullptr;
    std::string module;
    std::string name;
    {
        std::lock_guard<std::mutex> lock(callbacksMutex);
        if (index < callbacks.size()) {
            callback = callbacks[index].callback;
            module = callbacks[index].module;
            name = callbacks[index].name;
        }
    }
    if (!callback) {
        if (cpu) {
            cpu->reg[0].u32 = 0xc0000139; // STATUS_ENTRYPOINT_NOT_FOUND
            cpu->thread->terminating = true;
        }
        if (!module.empty() || !name.empty()) {
            kwarn_fmt(
                "Sugarbomb stopped at unresolved Win32 import %s!%s (callback %u)",
                module.c_str(),
                name.c_str(),
                index);
        } else {
            kwarn_fmt("Sugarbomb native callback %u is not registered", index);
        }
        return false;
    }
    callback(cpu);
    return true;
}

bool SugarbombBridge::callbackName(U32 index, std::string& module, std::string& name) {
    std::lock_guard<std::mutex> lock(callbacksMutex);
    if (index >= callbacks.size()) {
        module.clear();
        name.clear();
        return false;
    }
    module = callbacks[index].module;
    name = callbacks[index].name;
    return true;
}

std::size_t SugarbombBridge::callbackCount() {
    std::lock_guard<std::mutex> lock(callbacksMutex);
    return callbacks.size();
}

#ifdef __TEST
void SugarbombBridge::clearForTests() {
    std::lock_guard<std::mutex> lock(callbacksMutex);
    callbacks.clear();
}
#endif

void callSugarbomb(CPU* cpu, U32 index) {
    SugarbombBridge::dispatch(cpu, index);
}

bool SugarbombThunkArena::initialize(KThread* thread, U32 base, U32 size, std::string& error) {
    if (!thread || !thread->memory) {
        error = "Sugarbomb thunk arena requires a guest thread and memory space";
        return false;
    }
    if (!base || !size || (base & K_PAGE_MASK) || (size & K_PAGE_MASK)) {
        error = "Sugarbomb thunk arena must use nonzero page-aligned addresses";
        return false;
    }
    if (thread->memory->mmap(
            thread,
            base,
            size,
            K_PROT_READ | K_PROT_WRITE | K_PROT_EXEC,
            K_MAP_FIXED | K_MAP_PRIVATE | K_MAP_ANONYMOUS,
            -1,
            0) != base) {
        error = "Unable to reserve the Sugarbomb guest thunk arena";
        return false;
    }

    thread->memory->memset(base, static_cast<char>(0xcc), size);
    this->thread = thread;
    this->arenaBase = base;
    this->arenaSize = size;
    this->nextAddress = base;
    this->allocatedThunks = 0;
    this->isFinalized = false;
    return true;
}

bool SugarbombThunkArena::createThunk(
    U32 callbackIndex,
    U16 stackCleanupBytes,
    U32& guestAddress,
    std::string& error) {
    guestAddress = 0;
    if (!thread || !arenaBase) {
        error = "Sugarbomb thunk arena is not initialized";
        return false;
    }
    if (isFinalized) {
        error = "Sugarbomb thunk arena is already executable and read-only";
        return false;
    }
    if (nextAddress < arenaBase || nextAddress - arenaBase > arenaSize - THUNK_SIZE) {
        error = "Sugarbomb guest thunk arena is full";
        return false;
    }

    U8 code[THUNK_SIZE] = {
        0x68, 0, 0, 0, 0,       // push callbackIndex
        0xcd, 0x9c,              // int 9Ch
        0x83, 0xc4, 0x04,        // add esp, 4
        0xc3,                    // ret, or replaced with ret imm16
        0xcc, 0xcc, 0xcc, 0xcc, 0xcc
    };
    code[1] = static_cast<U8>(callbackIndex);
    code[2] = static_cast<U8>(callbackIndex >> 8);
    code[3] = static_cast<U8>(callbackIndex >> 16);
    code[4] = static_cast<U8>(callbackIndex >> 24);
    if (stackCleanupBytes) {
        code[10] = 0xc2;
        code[11] = static_cast<U8>(stackCleanupBytes);
        code[12] = static_cast<U8>(stackCleanupBytes >> 8);
    }

    guestAddress = nextAddress;
    thread->memory->memcpy(guestAddress, code, sizeof(code));
    nextAddress += THUNK_SIZE;
    ++allocatedThunks;
    return true;
}

bool SugarbombThunkArena::beginUpdate(std::string& error) {
    if (!thread || !arenaBase) {
        error = "Sugarbomb thunk arena is not initialized";
        return false;
    }
    if (!isFinalized) {
        return true;
    }
    if (thread->memory->mprotect(
            thread,
            arenaBase,
            arenaSize,
            K_PROT_READ | K_PROT_WRITE | K_PROT_EXEC) != 0) {
        error = "Unable to reopen the Sugarbomb guest thunk arena";
        return false;
    }
    isFinalized = false;
    return true;
}

bool SugarbombThunkArena::finalize(std::string& error) {
    if (!thread || !arenaBase) {
        error = "Sugarbomb thunk arena is not initialized";
        return false;
    }
    if (isFinalized) {
        return true;
    }
    if (thread->memory->mprotect(thread, arenaBase, arenaSize, K_PROT_READ | K_PROT_EXEC) != 0) {
        error = "Unable to make the Sugarbomb guest thunk arena executable";
        return false;
    }
    isFinalized = true;
    return true;
}
