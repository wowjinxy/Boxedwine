/*
 *  Copyright (C) 2026  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "sugarbombhostwindow.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#endif

struct SugarbombHostWindow::Impl {
    std::uint32_t guestHandle = 0;
    std::uint32_t frameWidth = 0;
    std::uint32_t frameHeight = 0;
    std::uint32_t presentCount = 0;
    bool userClosed = false;
    bool intentionalDestroy = false;
    bool shuttingDown = false;
    std::vector<std::uint32_t> framePixels;
#ifdef _WIN32
    HWND window = nullptr;
#endif
};

#ifdef _WIN32

namespace {

constexpr const char* HOST_WINDOW_CLASS =
    "SugarbombFalloutGuestHostWindow";

bool presentationDisabled() {
    const char* configured = std::getenv("SUGARBOMB_NO_HOST_WINDOW");
    return configured && *configured && std::strcmp(configured, "0") != 0;
}

void paintHostWindow(SugarbombHostWindow::Impl* impl, HDC deviceContext) {
    if (!impl || !deviceContext || !impl->window) {
        return;
    }
    RECT client = {};
    GetClientRect(impl->window, &client);
    const int destinationWidth =
        std::max<LONG>(1, client.right - client.left);
    const int destinationHeight =
        std::max<LONG>(1, client.bottom - client.top);
    if (!impl->framePixels.empty() &&
        impl->frameWidth &&
        impl->frameHeight) {
        BITMAPINFO bitmap = {};
        bitmap.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
        bitmap.bmiHeader.biWidth =
            static_cast<LONG>(impl->frameWidth);
        bitmap.bmiHeader.biHeight =
            -static_cast<LONG>(impl->frameHeight);
        bitmap.bmiHeader.biPlanes = 1;
        bitmap.bmiHeader.biBitCount = 32;
        bitmap.bmiHeader.biCompression = BI_RGB;
        SetStretchBltMode(deviceContext, COLORONCOLOR);
        StretchDIBits(
            deviceContext,
            0,
            0,
            destinationWidth,
            destinationHeight,
            0,
            0,
            static_cast<int>(impl->frameWidth),
            static_cast<int>(impl->frameHeight),
            impl->framePixels.data(),
            &bitmap,
            DIB_RGB_COLORS,
            SRCCOPY);
    } else {
        FillRect(
            deviceContext,
            &client,
            reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH)));
    }

    constexpr const char* status =
        "Sugarbomb x64 host | FalloutNV.exe x86 guest";
    SetBkMode(deviceContext, TRANSPARENT);
    SetTextColor(deviceContext, RGB(130, 220, 120));
    TextOutA(
        deviceContext,
        12,
        12,
        status,
        static_cast<int>(std::strlen(status)));
}

LRESULT CALLBACK hostWindowProcedure(
    HWND window,
    UINT message,
    WPARAM wordParameter,
    LPARAM longParameter) {
    SugarbombHostWindow::Impl* impl =
        reinterpret_cast<SugarbombHostWindow::Impl*>(
            GetWindowLongPtrA(window, GWLP_USERDATA));
    if (message == WM_NCCREATE) {
        CREATESTRUCTA* create =
            reinterpret_cast<CREATESTRUCTA*>(longParameter);
        impl = static_cast<SugarbombHostWindow::Impl*>(
            create->lpCreateParams);
        SetWindowLongPtrA(
            window,
            GWLP_USERDATA,
            reinterpret_cast<LONG_PTR>(impl));
    }
    if (impl) {
        switch (message) {
        case WM_ERASEBKGND:
            return 1;
        case WM_PAINT: {
            PAINTSTRUCT paint = {};
            HDC deviceContext = BeginPaint(window, &paint);
            paintHostWindow(impl, deviceContext);
            EndPaint(window, &paint);
            return 0;
        }
        case WM_CLOSE:
            DestroyWindow(window);
            return 0;
        case WM_NCDESTROY:
            impl->window = nullptr;
            if (!impl->intentionalDestroy && !impl->shuttingDown) {
                impl->userClosed = true;
            }
            SetWindowLongPtrA(window, GWLP_USERDATA, 0);
            break;
        default:
            break;
        }
    }
    return DefWindowProcA(
        window,
        message,
        wordParameter,
        longParameter);
}

bool registerHostWindowClass(HINSTANCE instance) {
    WNDCLASSEXA existing = {};
    existing.cbSize = sizeof(existing);
    if (GetClassInfoExA(instance, HOST_WINDOW_CLASS, &existing)) {
        return true;
    }
    WNDCLASSEXA windowClass = {};
    windowClass.cbSize = sizeof(windowClass);
    windowClass.style = CS_HREDRAW | CS_VREDRAW | CS_OWNDC;
    windowClass.lpfnWndProc = hostWindowProcedure;
    windowClass.hInstance = instance;
    windowClass.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    windowClass.hbrBackground =
        reinterpret_cast<HBRUSH>(GetStockObject(BLACK_BRUSH));
    windowClass.lpszClassName = HOST_WINDOW_CLASS;
    return RegisterClassExA(&windowClass) != 0 ||
        GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

} // namespace

#endif

SugarbombHostWindow::SugarbombHostWindow() : impl(new Impl()) {
}

SugarbombHostWindow::~SugarbombHostWindow() {
    shutdown();
    delete impl;
}

void SugarbombHostWindow::syncGuestWindow(
    std::uint32_t guestHandle,
    const std::string& title,
    std::int32_t x,
    std::int32_t y,
    std::int32_t clientWidth,
    std::int32_t clientHeight,
    bool visible) {
#ifdef _WIN32
    if (presentationDisabled() || impl->userClosed) {
        return;
    }
    HINSTANCE instance = GetModuleHandleA(nullptr);
    if (!registerHostWindowClass(instance)) {
        std::fprintf(
            stderr,
            "Sugarbomb host presentation: RegisterClassExA failed "
            "with error %lu\n",
            GetLastError());
        return;
    }
    const std::int32_t safeWidth =
        std::max<std::int32_t>(1, std::min<std::int32_t>(clientWidth, 16384));
    const std::int32_t safeHeight =
        std::max<std::int32_t>(1, std::min<std::int32_t>(clientHeight, 16384));
    const std::string resolvedTitle = title.empty()
        ? "Fallout: New Vegas - Sugarbomb x64 host"
        : title;
    RECT rectangle = {0, 0, safeWidth, safeHeight};
    AdjustWindowRect(&rectangle, WS_OVERLAPPEDWINDOW, FALSE);

    if (!impl->window) {
        impl->window = CreateWindowExA(
            0,
            HOST_WINDOW_CLASS,
            resolvedTitle.c_str(),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            rectangle.right - rectangle.left,
            rectangle.bottom - rectangle.top,
            nullptr,
            nullptr,
            instance,
            impl);
        if (!impl->window) {
            std::fprintf(
                stderr,
                "Sugarbomb host presentation: CreateWindowExA failed "
                "with error %lu\n",
                GetLastError());
            return;
        }
        impl->guestHandle = guestHandle;
        std::printf(
            "Sugarbomb host presentation: mapped guest HWND 0x%08X to "
            "native window %p (%dx%d)\n",
            guestHandle,
            static_cast<void*>(impl->window),
            safeWidth,
            safeHeight);
    }
    if (impl->guestHandle != guestHandle) {
        return;
    }
    SetWindowTextA(impl->window, resolvedTitle.c_str());
    SetWindowPos(
        impl->window,
        nullptr,
        x,
        y,
        rectangle.right - rectangle.left,
        rectangle.bottom - rectangle.top,
        SWP_NOACTIVATE | SWP_NOZORDER);
    ShowWindow(impl->window, visible ? SW_SHOW : SW_HIDE);
    if (visible) {
        UpdateWindow(impl->window);
    }
#else
    (void)guestHandle;
    (void)title;
    (void)x;
    (void)y;
    (void)clientWidth;
    (void)clientHeight;
    (void)visible;
#endif
}

void SugarbombHostWindow::destroyGuestWindow(std::uint32_t guestHandle) {
#ifdef _WIN32
    if (!impl->window || impl->guestHandle != guestHandle) {
        return;
    }
    impl->intentionalDestroy = true;
    DestroyWindow(impl->window);
    impl->intentionalDestroy = false;
    impl->userClosed = false;
    impl->guestHandle = 0;
    impl->framePixels.clear();
#else
    (void)guestHandle;
#endif
}

bool SugarbombHostWindow::pumpMessages() {
#ifdef _WIN32
    MSG message = {};
    while (PeekMessageA(&message, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&message);
        DispatchMessageA(&message);
    }
    return !impl->userClosed;
#else
    return true;
#endif
}

std::uintptr_t SugarbombHostWindow::nativeHandle() const {
#ifdef _WIN32
    return reinterpret_cast<std::uintptr_t>(impl->window);
#else
    return 0;
#endif
}

void SugarbombHostWindow::present(
    const std::uint32_t* pixels,
    std::uint32_t width,
    std::uint32_t height) {
#ifdef _WIN32
    if (!impl->window || !pixels || !width || !height) {
        return;
    }
    const std::size_t pixelCount =
        static_cast<std::size_t>(width) * height;
    impl->framePixels.assign(pixels, pixels + pixelCount);
    impl->frameWidth = width;
    impl->frameHeight = height;
    HDC deviceContext = GetDC(impl->window);
    if (deviceContext) {
        paintHostWindow(impl, deviceContext);
        ReleaseDC(impl->window, deviceContext);
    }
    ++impl->presentCount;
    if (impl->presentCount == 1) {
        std::printf(
            "Sugarbomb host presentation: first guest D3D9 frame "
            "presented at %ux%u\n",
            width,
            height);
    }
#else
    (void)pixels;
    (void)width;
    (void)height;
#endif
}

void SugarbombHostWindow::shutdown() {
#ifdef _WIN32
    impl->shuttingDown = true;
    if (impl->window) {
        DestroyWindow(impl->window);
    }
    pumpMessages();
#endif
    impl->framePixels.clear();
}
