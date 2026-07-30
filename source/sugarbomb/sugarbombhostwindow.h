/*
 *  Copyright (C) 2026  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifndef SUGARBOMB_HOST_WINDOW_H
#define SUGARBOMB_HOST_WINDOW_H

#include <cstdint>
#include <string>
#include <vector>

class SugarbombHostWindow {
public:
    struct Impl;
    struct Event {
        std::uint32_t guestHandle = 0;
        std::uint32_t message = 0;
        std::uint32_t wordParameter = 0;
        std::uint32_t longParameter = 0;
        std::uint32_t time = 0;
        std::int32_t pointX = 0;
        std::int32_t pointY = 0;
        bool forwardToGuest = true;
        bool relativeMouse = false;
    };

    SugarbombHostWindow();
    ~SugarbombHostWindow();

    SugarbombHostWindow(const SugarbombHostWindow&) = delete;
    SugarbombHostWindow& operator=(const SugarbombHostWindow&) = delete;

    void hideOwnedConsoleWindow();
    void syncGuestWindow(
        std::uint32_t guestHandle,
        const std::string& title,
        std::int32_t x,
        std::int32_t y,
        std::int32_t clientWidth,
        std::int32_t clientHeight,
        bool visible);
    bool activateGuestWindow(std::uint32_t guestHandle);
    bool setActiveGuestWindow(std::uint32_t guestHandle);
    bool focusGuestWindow(std::uint32_t guestHandle);
    bool isGuestWindowForeground(std::uint32_t guestHandle) const;
    bool isGuestWindowActive(std::uint32_t guestHandle) const;
    bool isGuestWindowFocused(std::uint32_t guestHandle) const;
    void setCursorVisible(bool visible);
    bool setMouseCapture(bool captured);
    void destroyGuestWindow(std::uint32_t guestHandle);
    bool pumpMessages(std::vector<Event>* events = nullptr);
    std::uintptr_t nativeHandle() const;
    void present(
        const std::uint32_t* pixels,
        std::uint32_t width,
        std::uint32_t height);
    void shutdown();

private:
    Impl* impl;
};

#endif
