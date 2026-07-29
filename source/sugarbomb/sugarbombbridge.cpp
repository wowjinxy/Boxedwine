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
    {
        std::lock_guard<std::mutex> lock(callbacksMutex);
        if (index < callbacks.size()) {
            callback = callbacks[index].callback;
        }
    }
    if (!callback) {
        if (cpu) {
            cpu->reg[0].u32 = 0xc0000139; // STATUS_ENTRYPOINT_NOT_FOUND
        }
        kwarn_fmt("Sugarbomb native callback %u is not registered", index);
        return false;
    }
    callback(cpu);
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
