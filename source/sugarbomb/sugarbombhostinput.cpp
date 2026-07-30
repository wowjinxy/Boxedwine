/*
 *  Copyright (C) 2026  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "sugarbombhostinput.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef DIRECTINPUT_VERSION
#define DIRECTINPUT_VERSION 0x0800
#endif
#include <Windows.h>
#include <dinput.h>
#ifdef _MSC_VER
#pragma comment(lib, "dinput8.lib")
#pragma comment(lib, "dxguid.lib")
#endif
#endif

struct SugarbombHostInput::Impl {
#ifdef _WIN32
    IDirectInput8A* directInput = nullptr;
#endif
    bool initializationAttempted = false;
};

#ifdef _WIN32

namespace {

constexpr std::uint32_t DIRECTINPUT_OK = 0;
constexpr std::uint32_t DIRECTINPUT_NOT_INITIALIZED =
    0x800401f0;
constexpr std::uint32_t DIRECTINPUT_INVALID_PARAMETER =
    0x80070057;
constexpr std::uint32_t GUID_SYS_MOUSE_DATA1 = 0x6f1d2b60;
constexpr std::uint32_t GUID_SYS_KEYBOARD_DATA1 = 0x6f1d2b61;

IDirectInputDevice8A* nativeDevice(
    SugarbombHostInput::DeviceHandle handle) {
    return reinterpret_cast<IDirectInputDevice8A*>(handle);
}

std::uint32_t directInputResult(HRESULT result) {
    return static_cast<std::uint32_t>(result);
}

bool forceMessageInput() {
    const char* configured =
        std::getenv("SUGARBOMB_MESSAGE_INPUT");
    return configured &&
        *configured &&
        std::strcmp(configured, "0") != 0;
}

} // namespace

#endif

SugarbombHostInput::SugarbombHostInput() : impl(new Impl()) {
}

SugarbombHostInput::~SugarbombHostInput() {
    shutdown();
    delete impl;
}

bool SugarbombHostInput::initialize(std::uint32_t version) {
#ifdef _WIN32
    if (impl->directInput) {
        return true;
    }
    if (impl->initializationAttempted) {
        return false;
    }
    impl->initializationAttempted = true;
    if (forceMessageInput()) {
        std::printf(
            "Sugarbomb native DirectInput: disabled by "
            "SUGARBOMB_MESSAGE_INPUT\n");
        return false;
    }

    IDirectInput8A* directInput = nullptr;
    const HRESULT result = DirectInput8Create(
        GetModuleHandleA(nullptr),
        version,
        IID_IDirectInput8A,
        reinterpret_cast<void**>(&directInput),
        nullptr);
    if (FAILED(result) || !directInput) {
        std::fprintf(
            stderr,
            "Sugarbomb native DirectInput: DirectInput8Create "
            "failed with HRESULT 0x%08X; retaining the message "
            "input fallback\n",
            directInputResult(result));
        return false;
    }
    impl->directInput = directInput;
    std::printf(
        "Sugarbomb native DirectInput: initialized against the "
        "real x64 application process\n");
    return true;
#else
    (void)version;
    impl->initializationAttempted = true;
    return false;
#endif
}

bool SugarbombHostInput::ready() const {
#ifdef _WIN32
    return impl->directInput != nullptr;
#else
    return false;
#endif
}

std::uint32_t SugarbombHostInput::createDevice(
    std::uint32_t guidData1,
    DeviceHandle& device) {
    device = 0;
#ifdef _WIN32
    if (!impl->directInput) {
        return DIRECTINPUT_NOT_INITIALIZED;
    }
    const GUID* guid = nullptr;
    const char* name = "unknown";
    if (guidData1 == GUID_SYS_KEYBOARD_DATA1) {
        guid = &GUID_SysKeyboard;
        name = "keyboard";
    } else if (guidData1 == GUID_SYS_MOUSE_DATA1) {
        guid = &GUID_SysMouse;
        name = "mouse";
    } else {
        return DIRECTINPUT_INVALID_PARAMETER;
    }

    IDirectInputDevice8A* native = nullptr;
    const HRESULT result = impl->directInput->CreateDevice(
        *guid,
        &native,
        nullptr);
    if (SUCCEEDED(result) && native) {
        device = reinterpret_cast<DeviceHandle>(native);
        std::printf(
            "Sugarbomb native DirectInput: created real %s "
            "device %p\n",
            name,
            static_cast<void*>(native));
    }
    return directInputResult(result);
#else
    (void)guidData1;
    return 0x80004001;
#endif
}

void SugarbombHostInput::releaseDevice(DeviceHandle& device) {
#ifdef _WIN32
    IDirectInputDevice8A* native = nativeDevice(device);
    if (native) {
        native->Unacquire();
        native->Release();
    }
#endif
    device = 0;
}

std::uint32_t SugarbombHostInput::setDataFormat(
    DeviceHandle device,
    std::uint32_t guidData1,
    std::uint32_t dataSize) {
#ifdef _WIN32
    IDirectInputDevice8A* native = nativeDevice(device);
    if (!native) {
        return DIRECTINPUT_NOT_INITIALIZED;
    }
    const DIDATAFORMAT* format = nullptr;
    if (guidData1 == GUID_SYS_KEYBOARD_DATA1) {
        format = &c_dfDIKeyboard;
    } else if (guidData1 == GUID_SYS_MOUSE_DATA1) {
        format = dataSize <= sizeof(DIMOUSESTATE)
            ? &c_dfDIMouse
            : &c_dfDIMouse2;
    }
    return format
        ? directInputResult(native->SetDataFormat(format))
        : DIRECTINPUT_INVALID_PARAMETER;
#else
    (void)device;
    (void)guidData1;
    (void)dataSize;
    return 0x80004001;
#endif
}

std::uint32_t SugarbombHostInput::setCooperativeLevel(
    DeviceHandle device,
    std::uintptr_t nativeWindow,
    std::uint32_t flags) {
#ifdef _WIN32
    IDirectInputDevice8A* native = nativeDevice(device);
    HWND window = reinterpret_cast<HWND>(nativeWindow);
    if (!native || !window) {
        return DIRECTINPUT_INVALID_PARAMETER;
    }
    return directInputResult(
        native->SetCooperativeLevel(window, flags));
#else
    (void)device;
    (void)nativeWindow;
    (void)flags;
    return 0x80004001;
#endif
}

std::uint32_t SugarbombHostInput::setBufferSize(
    DeviceHandle device,
    std::uint32_t size) {
#ifdef _WIN32
    IDirectInputDevice8A* native = nativeDevice(device);
    if (!native) {
        return DIRECTINPUT_NOT_INITIALIZED;
    }
    DIPROPDWORD property = {};
    property.diph.dwSize = sizeof(property);
    property.diph.dwHeaderSize = sizeof(property.diph);
    property.diph.dwHow = DIPH_DEVICE;
    property.dwData = size;
    return directInputResult(
        native->SetProperty(
            DIPROP_BUFFERSIZE,
            &property.diph));
#else
    (void)device;
    (void)size;
    return 0x80004001;
#endif
}

std::uint32_t SugarbombHostInput::acquire(
    DeviceHandle device) {
#ifdef _WIN32
    IDirectInputDevice8A* native = nativeDevice(device);
    return native
        ? directInputResult(native->Acquire())
        : DIRECTINPUT_NOT_INITIALIZED;
#else
    (void)device;
    return 0x80004001;
#endif
}

std::uint32_t SugarbombHostInput::unacquire(
    DeviceHandle device) {
#ifdef _WIN32
    IDirectInputDevice8A* native = nativeDevice(device);
    return native
        ? directInputResult(native->Unacquire())
        : DIRECTINPUT_NOT_INITIALIZED;
#else
    (void)device;
    return 0x80004001;
#endif
}

std::uint32_t SugarbombHostInput::getDeviceState(
    DeviceHandle device,
    void* destination,
    std::uint32_t size) {
#ifdef _WIN32
    IDirectInputDevice8A* native = nativeDevice(device);
    if (!native || !destination || !size) {
        return DIRECTINPUT_INVALID_PARAMETER;
    }
    return directInputResult(
        native->GetDeviceState(size, destination));
#else
    (void)device;
    (void)destination;
    (void)size;
    return 0x80004001;
#endif
}

std::uint32_t SugarbombHostInput::getDeviceData(
    DeviceHandle device,
    std::uint32_t requested,
    std::uint32_t flags,
    std::vector<DeviceEvent>& events) {
    events.clear();
#ifdef _WIN32
    IDirectInputDevice8A* native = nativeDevice(device);
    if (!native) {
        return DIRECTINPUT_NOT_INITIALIZED;
    }
    DWORD count = requested == 0xffffffff
        ? 4096
        : std::min<std::uint32_t>(requested, 4096);
    if (!count) {
        return DIRECTINPUT_OK;
    }
    std::vector<DIDEVICEOBJECTDATA> nativeEvents(count);
    const HRESULT result = native->GetDeviceData(
        sizeof(DIDEVICEOBJECTDATA),
        nativeEvents.data(),
        &count,
        flags);
    if (FAILED(result)) {
        return directInputResult(result);
    }
    events.reserve(count);
    for (DWORD index = 0; index < count; ++index) {
        DeviceEvent event;
        event.offset = nativeEvents[index].dwOfs;
        event.data = nativeEvents[index].dwData;
        event.timestamp = nativeEvents[index].dwTimeStamp;
        event.sequence = nativeEvents[index].dwSequence;
        event.applicationData =
            nativeEvents[index].uAppData;
        events.push_back(event);
    }
    return directInputResult(result);
#else
    (void)device;
    (void)requested;
    (void)flags;
    return 0x80004001;
#endif
}

void SugarbombHostInput::shutdown() {
#ifdef _WIN32
    if (impl->directInput) {
        impl->directInput->Release();
        impl->directInput = nullptr;
    }
#endif
    impl->initializationAttempted = false;
}
