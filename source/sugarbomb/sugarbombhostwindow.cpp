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
    bool visible = false;
    bool cursorVisible = true;
    bool mouseCaptured = false;
    bool rawMouseRegistered = false;
    std::vector<std::uint32_t> framePixels;
    std::vector<SugarbombHostWindow::Event> pendingEvents;
#ifdef _WIN32
    HWND window = nullptr;
#endif
};

#ifdef _WIN32

namespace {

constexpr const char* HOST_WINDOW_CLASS =
    "SugarbombFalloutGuestHostWindow";

bool isGuestInputOrFocusMessage(UINT message) {
    switch (message) {
    case WM_ACTIVATE:
    case WM_SETFOCUS:
    case WM_KILLFOCUS:
    case WM_ACTIVATEAPP:
    case WM_KEYDOWN:
    case WM_KEYUP:
    case WM_CHAR:
    case WM_SYSKEYDOWN:
    case WM_SYSKEYUP:
    case WM_SYSCHAR:
    case WM_MOUSEMOVE:
    case WM_LBUTTONDOWN:
    case WM_LBUTTONUP:
    case WM_LBUTTONDBLCLK:
    case WM_RBUTTONDOWN:
    case WM_RBUTTONUP:
    case WM_RBUTTONDBLCLK:
    case WM_MBUTTONDOWN:
    case WM_MBUTTONUP:
    case WM_MBUTTONDBLCLK:
    case WM_MOUSEWHEEL:
#ifdef WM_XBUTTONDOWN
    case WM_XBUTTONDOWN:
    case WM_XBUTTONUP:
    case WM_XBUTTONDBLCLK:
#endif
#ifdef WM_MOUSEHWHEEL
    case WM_MOUSEHWHEEL:
#endif
        return true;
    default:
        return false;
    }
}

void queueGuestEvent(
    SugarbombHostWindow::Impl* impl,
    UINT message,
    WPARAM wordParameter,
    LPARAM longParameter) {
    if (!impl || !impl->guestHandle ||
        !isGuestInputOrFocusMessage(message)) {
        return;
    }
    SugarbombHostWindow::Event event;
    event.guestHandle = impl->guestHandle;
    event.message = static_cast<std::uint32_t>(message);
    event.wordParameter = static_cast<std::uint32_t>(wordParameter);
    event.longParameter = static_cast<std::uint32_t>(longParameter);
    event.time = static_cast<std::uint32_t>(GetMessageTime());
    DWORD point = GetMessagePos();
    event.pointX = static_cast<std::int16_t>(LOWORD(point));
    event.pointY = static_cast<std::int16_t>(HIWORD(point));
    if (message == WM_SETFOCUS ||
        message == WM_KILLFOCUS) {
        event.wordParameter = 0;
    } else if (message == WM_ACTIVATE ||
               message == WM_ACTIVATEAPP) {
        event.longParameter = 0;
    }
    impl->pendingEvents.push_back(event);
}

void queueRawMouseEvent(
    SugarbombHostWindow::Impl* impl,
    LPARAM longParameter) {
    if (!impl || !impl->guestHandle) {
        return;
    }
    UINT bytes = 0;
    if (GetRawInputData(
            reinterpret_cast<HRAWINPUT>(longParameter),
            RID_INPUT,
            nullptr,
            &bytes,
            sizeof(RAWINPUTHEADER)) != 0 ||
        bytes < sizeof(RAWINPUT)) {
        return;
    }
    std::vector<BYTE> storage(bytes);
    if (GetRawInputData(
            reinterpret_cast<HRAWINPUT>(longParameter),
            RID_INPUT,
            storage.data(),
            &bytes,
            sizeof(RAWINPUTHEADER)) != bytes) {
        return;
    }
    const RAWINPUT* input =
        reinterpret_cast<const RAWINPUT*>(storage.data());
    if (input->header.dwType != RIM_TYPEMOUSE ||
        (input->data.mouse.usFlags & MOUSE_MOVE_ABSOLUTE) ||
        (!input->data.mouse.lLastX && !input->data.mouse.lLastY)) {
        return;
    }
    SugarbombHostWindow::Event event;
    event.guestHandle = impl->guestHandle;
    event.wordParameter =
        static_cast<std::uint32_t>(input->data.mouse.lLastX);
    event.longParameter =
        static_cast<std::uint32_t>(input->data.mouse.lLastY);
    event.time = static_cast<std::uint32_t>(GetMessageTime());
    event.forwardToGuest = false;
    event.relativeMouse = true;
    impl->pendingEvents.push_back(event);
}

void releaseNativeMouseCapture(SugarbombHostWindow::Impl* impl) {
    if (!impl || !impl->mouseCaptured) {
        return;
    }
    if (GetCapture() == impl->window) {
        ReleaseCapture();
    }
    ClipCursor(nullptr);
    impl->mouseCaptured = false;
}

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
        if (message == WM_INPUT) {
            queueRawMouseEvent(impl, longParameter);
        }
        queueGuestEvent(
            impl,
            message,
            wordParameter,
            longParameter);
        switch (message) {
        case WM_ACTIVATEAPP:
            if (!wordParameter) {
                releaseNativeMouseCapture(impl);
            }
            break;
        case WM_KILLFOCUS:
            releaseNativeMouseCapture(impl);
            break;
        case WM_SETCURSOR:
            if (!impl->cursorVisible) {
                SetCursor(nullptr);
                return TRUE;
            }
            break;
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
            releaseNativeMouseCapture(impl);
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

void SugarbombHostWindow::hideOwnedConsoleWindow() {
#ifdef _WIN32
    HWND console = GetConsoleWindow();
    if (!console) {
        return;
    }
    DWORD ownerProcess = 0;
    GetWindowThreadProcessId(console, &ownerProcess);
    if (ownerProcess == GetCurrentProcessId()) {
        ShowWindow(console, SW_HIDE);
    }
#endif
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
        RAWINPUTDEVICE rawMouse = {};
        rawMouse.usUsagePage = 0x01;
        rawMouse.usUsage = 0x02;
        rawMouse.hwndTarget = impl->window;
        impl->rawMouseRegistered =
            RegisterRawInputDevices(
                &rawMouse,
                1,
                sizeof(rawMouse)) != FALSE;
        if (!impl->rawMouseRegistered) {
            std::fprintf(
                stderr,
                "Sugarbomb host input: RegisterRawInputDevices failed "
                "with error %lu; using WM_MOUSEMOVE fallback\n",
                GetLastError());
        }
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
    if (impl->mouseCaptured) {
        setMouseCapture(true);
    }
    bool becameVisible = visible && !impl->visible;
    bool becameHidden = !visible && impl->visible;
    if (becameVisible) {
        ShowWindow(impl->window, SW_SHOW);
        BOOL foreground = SetForegroundWindow(impl->window);
        bool ownsForeground =
            foreground || GetForegroundWindow() == impl->window;
        std::printf(
            "Sugarbomb host presentation: requested native activation "
            "for guest HWND 0x%08X (foreground=%u, owned=%u)\n",
            guestHandle,
            foreground ? 1 : 0,
            ownsForeground ? 1 : 0);
    } else if (becameHidden) {
        ShowWindow(impl->window, SW_HIDE);
    }
    impl->visible = visible;
    if (impl->visible) {
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

bool SugarbombHostWindow::activateGuestWindow(std::uint32_t guestHandle) {
#ifdef _WIN32
    if (!impl->window || impl->guestHandle != guestHandle) {
        return false;
    }
    BOOL foreground = SetForegroundWindow(impl->window);
    return foreground || GetForegroundWindow() == impl->window;
#else
    (void)guestHandle;
    return true;
#endif
}

bool SugarbombHostWindow::isGuestWindowForeground(
    std::uint32_t guestHandle) const {
#ifdef _WIN32
    return impl->window &&
        impl->guestHandle == guestHandle &&
        GetForegroundWindow() == impl->window;
#else
    (void)guestHandle;
    return true;
#endif
}

void SugarbombHostWindow::setCursorVisible(bool visible) {
#ifdef _WIN32
    impl->cursorVisible = visible;
    if (impl->window) {
        SetCursor(visible ? LoadCursorA(nullptr, IDC_ARROW) : nullptr);
    }
#else
    (void)visible;
#endif
}

bool SugarbombHostWindow::setMouseCapture(bool captured) {
#ifdef _WIN32
    if (!captured) {
        bool wasCaptured = impl->mouseCaptured;
        releaseNativeMouseCapture(impl);
        if (wasCaptured) {
            std::printf(
                "Sugarbomb host input: released exclusive mouse capture\n");
        }
        return true;
    }
    if (!impl->window ||
        GetForegroundWindow() != impl->window) {
        return false;
    }
    bool wasCaptured = impl->mouseCaptured;
    RECT client = {};
    if (!GetClientRect(impl->window, &client)) {
        return false;
    }
    POINT upperLeft = {client.left, client.top};
    POINT lowerRight = {client.right, client.bottom};
    if (!ClientToScreen(impl->window, &upperLeft) ||
        !ClientToScreen(impl->window, &lowerRight)) {
        return false;
    }
    RECT screen = {
        upperLeft.x,
        upperLeft.y,
        lowerRight.x,
        lowerRight.y};
    SetCapture(impl->window);
    if (GetCapture() != impl->window ||
        !ClipCursor(&screen)) {
        if (GetCapture() == impl->window) {
            ReleaseCapture();
        }
        ClipCursor(nullptr);
        return false;
    }
    impl->mouseCaptured = true;
    if (!wasCaptured) {
        std::printf(
            "Sugarbomb host input: acquired exclusive mouse capture\n");
    }
    return true;
#else
    (void)captured;
    return true;
#endif
}

void SugarbombHostWindow::destroyGuestWindow(std::uint32_t guestHandle) {
#ifdef _WIN32
    if (!impl->window || impl->guestHandle != guestHandle) {
        return;
    }
    if (impl->rawMouseRegistered) {
        RAWINPUTDEVICE rawMouse = {};
        rawMouse.usUsagePage = 0x01;
        rawMouse.usUsage = 0x02;
        rawMouse.dwFlags = RIDEV_REMOVE;
        RegisterRawInputDevices(
            &rawMouse,
            1,
            sizeof(rawMouse));
        impl->rawMouseRegistered = false;
    }
    impl->intentionalDestroy = true;
    DestroyWindow(impl->window);
    impl->intentionalDestroy = false;
    impl->userClosed = false;
    impl->guestHandle = 0;
    impl->visible = false;
    impl->framePixels.clear();
#else
    (void)guestHandle;
#endif
}

bool SugarbombHostWindow::pumpMessages(std::vector<Event>* events) {
#ifdef _WIN32
    MSG message = {};
    while (PeekMessageA(&message, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&message);
        DispatchMessageA(&message);
    }
    if (events && !impl->pendingEvents.empty()) {
        events->insert(
            events->end(),
            impl->pendingEvents.begin(),
            impl->pendingEvents.end());
    }
    impl->pendingEvents.clear();
    return !impl->userClosed;
#else
    (void)events;
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
    releaseNativeMouseCapture(impl);
    if (impl->rawMouseRegistered) {
        RAWINPUTDEVICE rawMouse = {};
        rawMouse.usUsagePage = 0x01;
        rawMouse.usUsage = 0x02;
        rawMouse.dwFlags = RIDEV_REMOVE;
        RegisterRawInputDevices(
            &rawMouse,
            1,
            sizeof(rawMouse));
        impl->rawMouseRegistered = false;
    }
    if (impl->window) {
        DestroyWindow(impl->window);
    }
    pumpMessages();
#endif
    impl->framePixels.clear();
    impl->pendingEvents.clear();
    impl->visible = false;
}
