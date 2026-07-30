/*
 *  Copyright (C) 2026  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifndef SUGARBOMB_HOST_INPUT_H
#define SUGARBOMB_HOST_INPUT_H

#include <cstdint>
#include <vector>

class SugarbombHostInput {
public:
    using DeviceHandle = std::uintptr_t;

    struct DeviceEvent {
        std::uint32_t offset = 0;
        std::uint32_t data = 0;
        std::uint32_t timestamp = 0;
        std::uint32_t sequence = 0;
        std::uintptr_t applicationData = 0;
    };

    SugarbombHostInput();
    ~SugarbombHostInput();

    SugarbombHostInput(const SugarbombHostInput&) = delete;
    SugarbombHostInput& operator=(const SugarbombHostInput&) = delete;

    bool initialize(std::uint32_t version);
    bool ready() const;
    std::uint32_t createDevice(
        std::uint32_t guidData1,
        DeviceHandle& device);
    void releaseDevice(DeviceHandle& device);
    std::uint32_t setDataFormat(
        DeviceHandle device,
        std::uint32_t guidData1,
        std::uint32_t dataSize);
    std::uint32_t setCooperativeLevel(
        DeviceHandle device,
        std::uintptr_t nativeWindow,
        std::uint32_t flags);
    std::uint32_t setBufferSize(
        DeviceHandle device,
        std::uint32_t size);
    std::uint32_t acquire(DeviceHandle device);
    std::uint32_t unacquire(DeviceHandle device);
    std::uint32_t getDeviceState(
        DeviceHandle device,
        void* destination,
        std::uint32_t size);
    std::uint32_t getDeviceData(
        DeviceHandle device,
        std::uint32_t requested,
        std::uint32_t flags,
        std::vector<DeviceEvent>& events);
    void shutdown();

private:
    struct Impl;
    Impl* impl;
};

#endif
