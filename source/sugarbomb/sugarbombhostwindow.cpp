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
#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <thread>
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
    struct SyncRequest {
        std::uint32_t guestHandle = 0;
        std::string title;
        std::int32_t x = 0;
        std::int32_t y = 0;
        std::int32_t clientWidth = 1;
        std::int32_t clientHeight = 1;
        bool visible = false;
        std::uint32_t showCommand = 5;
    };

    std::atomic<std::uint32_t> guestHandle{0};
    std::atomic<std::int32_t> guestClientWidth{1};
    std::atomic<std::int32_t> guestClientHeight{1};
    std::uint32_t frameWidth = 0;
    std::uint32_t frameHeight = 0;
    std::uint32_t presentCount = 0;
    std::uint32_t mouseCoordinateTraceCount = 0;
    std::atomic<bool> userClosed{false};
    bool intentionalDestroy = false;
    std::atomic<bool> shuttingDown{false};
    bool visible = false;
    bool cursorVisible = true;
    bool mouseCaptured = false;
    bool rawMouseRegistered = false;
    std::int32_t appliedShowCommand = -1;
    std::mutex eventMutex;
    std::mutex frameMutex;
    std::mutex lifecycleMutex;
    std::mutex syncStateMutex;
    std::condition_variable lifecycleCondition;
    bool startupComplete = false;
    bool startupSucceeded = false;
    SyncRequest startupRequest;
    SyncRequest lastSyncRequest;
    bool lastSyncRequestValid = false;
    std::vector<std::uint32_t> framePixels;
    std::vector<SugarbombHostWindow::Event> pendingEvents;
#ifdef _WIN32
    std::atomic<HWND> window{nullptr};
    std::atomic<DWORD> windowThreadId{0};
    std::thread windowThread;
#endif
};

#ifdef _WIN32

namespace {

constexpr const char* HOST_WINDOW_CLASS =
    "SugarbombFalloutGuestHostWindow";
constexpr UINT WM_SUGARBOMB_SYNC = WM_APP + 0x510;
constexpr UINT WM_SUGARBOMB_ACTIVATE = WM_APP + 0x511;
constexpr UINT WM_SUGARBOMB_CURSOR = WM_APP + 0x512;
constexpr UINT WM_SUGARBOMB_CAPTURE = WM_APP + 0x513;
constexpr UINT WM_SUGARBOMB_DESTROY = WM_APP + 0x514;
constexpr UINT WM_SUGARBOMB_PRESENT = WM_APP + 0x515;
constexpr UINT WM_SUGARBOMB_SET_ACTIVE = WM_APP + 0x516;
constexpr UINT WM_SUGARBOMB_SET_FOCUS = WM_APP + 0x517;
constexpr UINT WM_SUGARBOMB_QUERY_ACTIVE = WM_APP + 0x518;
constexpr UINT WM_SUGARBOMB_QUERY_FOCUS = WM_APP + 0x519;

bool isGuestInputOrFocusMessage(UINT message) {
    switch (message) {
    case WM_ACTIVATE:
    case WM_SETFOCUS:
    case WM_KILLFOCUS:
    case WM_ACTIVATEAPP:
    case WM_CANCELMODE:
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
    case WM_CAPTURECHANGED:
        return true;
    default:
        return false;
    }
}

bool isClientMousePositionMessage(UINT message) {
    switch (message) {
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
#ifdef WM_XBUTTONDOWN
    case WM_XBUTTONDOWN:
    case WM_XBUTTONUP:
    case WM_XBUTTONDBLCLK:
#endif
        return true;
    default:
        return false;
    }
}

LPARAM mapClientMouseToGuest(
    SugarbombHostWindow::Impl* impl,
    LPARAM longParameter) {
    if (!impl) {
        return longParameter;
    }
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    RECT client = {};
    if (!window ||
        !GetClientRect(window, &client)) {
        return longParameter;
    }
    const std::int32_t nativeWidth =
        client.right - client.left;
    const std::int32_t nativeHeight =
        client.bottom - client.top;
    const std::int32_t guestWidth =
        impl->guestClientWidth.load(
            std::memory_order_acquire);
    const std::int32_t guestHeight =
        impl->guestClientHeight.load(
            std::memory_order_acquire);
    if (nativeWidth <= 0 ||
        nativeHeight <= 0 ||
        guestWidth <= 0 ||
        guestHeight <= 0 ||
        (nativeWidth == guestWidth &&
         nativeHeight == guestHeight)) {
        return longParameter;
    }
    const std::int32_t nativeX =
        static_cast<std::int16_t>(
            static_cast<std::uint16_t>(
                longParameter & 0xffff));
    const std::int32_t nativeY =
        static_cast<std::int16_t>(
            static_cast<std::uint16_t>(
                (longParameter >> 16) & 0xffff));
    const auto scaleCoordinate = [](
        std::int32_t value,
        std::int32_t guestExtent,
        std::int32_t nativeExtent) {
        const std::int64_t scaled =
            static_cast<std::int64_t>(value) *
            guestExtent /
            nativeExtent;
        return static_cast<std::int32_t>(
            std::max<std::int64_t>(
                std::numeric_limits<std::int16_t>::min(),
                std::min<std::int64_t>(
                    std::numeric_limits<std::int16_t>::max(),
                    scaled)));
    };
    const std::int32_t guestX =
        scaleCoordinate(
            nativeX,
            guestWidth,
            nativeWidth);
    const std::int32_t guestY =
        scaleCoordinate(
            nativeY,
            guestHeight,
            nativeHeight);
    if (++impl->mouseCoordinateTraceCount <= 8) {
        std::printf(
            "Sugarbomb host input: mapped native mouse (%d,%d) "
            "in %dx%d client to guest (%d,%d) in %dx%d\n",
            nativeX,
            nativeY,
            nativeWidth,
            nativeHeight,
            guestX,
            guestY,
            guestWidth,
            guestHeight);
    }
    return static_cast<LPARAM>(
        static_cast<std::uint16_t>(guestX) |
        (static_cast<std::uint32_t>(
             static_cast<std::uint16_t>(guestY))
         << 16));
}

void queueGuestEvent(
    SugarbombHostWindow::Impl* impl,
    UINT message,
    WPARAM wordParameter,
    LPARAM longParameter) {
    if (!impl ||
        !isGuestInputOrFocusMessage(message)) {
        return;
    }
    const std::uint32_t guestHandle =
        impl->guestHandle.load(std::memory_order_acquire);
    if (!guestHandle) {
        return;
    }
    SugarbombHostWindow::Event event;
    event.guestHandle = guestHandle;
    event.message = static_cast<std::uint32_t>(message);
    event.wordParameter = static_cast<std::uint32_t>(wordParameter);
    event.longParameter = static_cast<std::uint32_t>(
        isClientMousePositionMessage(message)
            ? mapClientMouseToGuest(
                  impl,
                  longParameter)
            : longParameter);
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
    } else if (message == WM_CAPTURECHANGED) {
        event.longParameter = 0;
    }
    std::lock_guard<std::mutex> lock(impl->eventMutex);
    impl->pendingEvents.push_back(event);
}

void queueRawMouseEvent(
    SugarbombHostWindow::Impl* impl,
    LPARAM longParameter) {
    if (!impl) {
        return;
    }
    const std::uint32_t guestHandle =
        impl->guestHandle.load(std::memory_order_acquire);
    if (!guestHandle) {
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
    event.guestHandle = guestHandle;
    event.wordParameter =
        static_cast<std::uint32_t>(input->data.mouse.lLastX);
    event.longParameter =
        static_cast<std::uint32_t>(input->data.mouse.lLastY);
    event.time = static_cast<std::uint32_t>(GetMessageTime());
    event.forwardToGuest = false;
    event.relativeMouse = true;
    std::lock_guard<std::mutex> lock(impl->eventMutex);
    impl->pendingEvents.push_back(event);
}

void releaseNativeMouseCapture(SugarbombHostWindow::Impl* impl) {
    if (!impl || !impl->mouseCaptured) {
        return;
    }
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    if (GetCapture() == window) {
        ReleaseCapture();
    }
    ClipCursor(nullptr);
    impl->mouseCaptured = false;
}

bool clipNativeMouseToClient(SugarbombHostWindow::Impl* impl) {
    if (!impl) {
        return false;
    }
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    if (!window) {
        return false;
    }
    RECT client = {};
    if (!GetClientRect(window, &client)) {
        return false;
    }
    POINT upperLeft = {client.left, client.top};
    POINT lowerRight = {client.right, client.bottom};
    if (!ClientToScreen(window, &upperLeft) ||
        !ClientToScreen(window, &lowerRight)) {
        return false;
    }
    RECT screen = {
        upperLeft.x,
        upperLeft.y,
        lowerRight.x,
        lowerRight.y};
    return ClipCursor(&screen) != FALSE;
}

bool presentationDisabled() {
    const char* configured = std::getenv("SUGARBOMB_NO_HOST_WINDOW");
    return configured && *configured && std::strcmp(configured, "0") != 0;
}

void paintHostWindow(SugarbombHostWindow::Impl* impl, HDC deviceContext) {
    if (!impl || !deviceContext ||
        !impl->window.load(std::memory_order_acquire)) {
        return;
    }
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    RECT client = {};
    GetClientRect(window, &client);
    const int destinationWidth =
        std::max<LONG>(1, client.right - client.left);
    const int destinationHeight =
        std::max<LONG>(1, client.bottom - client.top);
    std::lock_guard<std::mutex> frameLock(impl->frameMutex);
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

void unregisterNativeRawMouse(SugarbombHostWindow::Impl* impl) {
    if (!impl || !impl->rawMouseRegistered) {
        return;
    }
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

bool setNativeMouseCapture(
    SugarbombHostWindow::Impl* impl,
    bool captured) {
    if (!impl) {
        return false;
    }
    if (!captured) {
        const bool wasCaptured = impl->mouseCaptured;
        releaseNativeMouseCapture(impl);
        if (wasCaptured) {
            std::printf(
                "Sugarbomb host input: released exclusive mouse capture\n");
        }
        return true;
    }

    const HWND window =
        impl->window.load(std::memory_order_acquire);
    if (!window || GetForegroundWindow() != window) {
        return false;
    }
    const bool wasCaptured = impl->mouseCaptured;
    SetCapture(window);
    if (GetCapture() != window ||
        !clipNativeMouseToClient(impl)) {
        if (GetCapture() == window) {
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
}

bool applyNativeWindowSync(
    SugarbombHostWindow::Impl* impl,
    const SugarbombHostWindow::Impl::SyncRequest& request) {
    if (!impl) {
        return false;
    }
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    if (!window ||
        impl->guestHandle.load(std::memory_order_acquire) !=
            request.guestHandle) {
        return false;
    }

    const std::int32_t safeWidth =
        std::max<std::int32_t>(
            1,
            std::min<std::int32_t>(
                request.clientWidth,
                16384));
    const std::int32_t safeHeight =
        std::max<std::int32_t>(
            1,
            std::min<std::int32_t>(
                request.clientHeight,
                16384));
    const std::string resolvedTitle = request.title.empty()
        ? "Fallout: New Vegas - Sugarbomb x64 host"
        : request.title;
    RECT rectangle = {0, 0, safeWidth, safeHeight};
    AdjustWindowRect(
        &rectangle,
        WS_OVERLAPPEDWINDOW,
        FALSE);
    impl->guestClientWidth.store(
        safeWidth,
        std::memory_order_release);
    impl->guestClientHeight.store(
        safeHeight,
        std::memory_order_release);

    SetWindowTextA(window, resolvedTitle.c_str());
    SetWindowPos(
        window,
        nullptr,
        request.x,
        request.y,
        rectangle.right - rectangle.left,
        rectangle.bottom - rectangle.top,
        SWP_NOACTIVATE | SWP_NOZORDER);
    if (impl->mouseCaptured) {
        setNativeMouseCapture(impl, true);
    }

    const bool becameVisible =
        request.visible && !impl->visible;
    const bool becameHidden =
        !request.visible && impl->visible;
    const int nativeShowCommand =
        request.showCommand <= SW_FORCEMINIMIZE
            ? static_cast<int>(request.showCommand)
            : SW_SHOW;
    const bool showCommandChanged =
        nativeShowCommand != impl->appliedShowCommand;
    if (request.visible &&
        (becameVisible || showCommandChanged)) {
        // Preserve the guest's ShowWindow request. Windows applies its normal
        // activation policy for SW_SHOW/SW_SHOWNORMAL and its normal
        // non-activation policy for SW_SHOWNA/SW_SHOWNOACTIVATE. Sugarbomb
        // never invents a foreground transfer here.
        ShowWindow(window, nativeShowCommand);
        impl->appliedShowCommand = nativeShowCommand;
        std::printf(
            "Sugarbomb host presentation: showed guest HWND 0x%08X "
            "as a native app window (command=%d, foreground=%u)\n",
            request.guestHandle,
            nativeShowCommand,
            GetForegroundWindow() == window ? 1 : 0);
    } else if (becameHidden) {
        ShowWindow(window, SW_HIDE);
        impl->appliedShowCommand = SW_HIDE;
    }
    impl->visible = request.visible;
    if (impl->visible) {
        InvalidateRect(window, nullptr, FALSE);
    }
    return true;
}

bool sameSyncRequest(
    const SugarbombHostWindow::Impl::SyncRequest& left,
    const SugarbombHostWindow::Impl::SyncRequest& right) {
    return left.guestHandle == right.guestHandle &&
        left.title == right.title &&
        left.x == right.x &&
        left.y == right.y &&
        left.clientWidth == right.clientWidth &&
        left.clientHeight == right.clientHeight &&
        left.visible == right.visible &&
        left.showCommand == right.showCommand;
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
        case WM_SUGARBOMB_SYNC: {
            const auto* request =
                reinterpret_cast<
                    const SugarbombHostWindow::Impl::SyncRequest*>(
                        longParameter);
            return request &&
                applyNativeWindowSync(impl, *request)
                ? TRUE
                : FALSE;
        }
        case WM_SUGARBOMB_ACTIVATE:
            if (static_cast<std::uint32_t>(wordParameter) !=
                impl->guestHandle.load(std::memory_order_acquire)) {
                return FALSE;
            }
            return SetForegroundWindow(window) ||
                GetForegroundWindow() == window
                ? TRUE
                : FALSE;
        case WM_SUGARBOMB_SET_ACTIVE:
            if (wordParameter &&
                static_cast<std::uint32_t>(wordParameter) !=
                    impl->guestHandle.load(std::memory_order_acquire)) {
                return FALSE;
            }
            SetActiveWindow(wordParameter ? window : nullptr);
            return GetActiveWindow() ==
                    (wordParameter ? window : nullptr)
                ? TRUE
                : FALSE;
        case WM_SUGARBOMB_SET_FOCUS:
            if (wordParameter &&
                static_cast<std::uint32_t>(wordParameter) !=
                    impl->guestHandle.load(std::memory_order_acquire)) {
                return FALSE;
            }
            SetFocus(wordParameter ? window : nullptr);
            return GetFocus() == (wordParameter ? window : nullptr)
                ? TRUE
                : FALSE;
        case WM_SUGARBOMB_QUERY_ACTIVE:
            return GetActiveWindow() == window ? TRUE : FALSE;
        case WM_SUGARBOMB_QUERY_FOCUS:
            return GetFocus() == window ? TRUE : FALSE;
        case WM_SUGARBOMB_CURSOR:
            impl->cursorVisible = wordParameter != 0;
            SetCursor(
                impl->cursorVisible
                    ? LoadCursorA(nullptr, IDC_ARROW)
                    : nullptr);
            return TRUE;
        case WM_SUGARBOMB_CAPTURE:
            return setNativeMouseCapture(
                impl,
                wordParameter != 0)
                ? TRUE
                : FALSE;
        case WM_SUGARBOMB_PRESENT:
            InvalidateRect(window, nullptr, FALSE);
            return TRUE;
        case WM_SUGARBOMB_DESTROY:
            impl->intentionalDestroy = true;
            DestroyWindow(window);
            return TRUE;
        case WM_ACTIVATEAPP:
            if (!wordParameter) {
                releaseNativeMouseCapture(impl);
            }
            break;
        case WM_CANCELMODE:
            releaseNativeMouseCapture(impl);
            break;
        case WM_CAPTURECHANGED:
            if (reinterpret_cast<HWND>(longParameter) !=
                impl->window.load(std::memory_order_acquire)) {
                releaseNativeMouseCapture(impl);
            }
            break;
        case WM_KILLFOCUS:
            releaseNativeMouseCapture(impl);
            break;
        case WM_WINDOWPOSCHANGED:
            if (impl->mouseCaptured &&
                !clipNativeMouseToClient(impl)) {
                releaseNativeMouseCapture(impl);
            }
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
            unregisterNativeRawMouse(impl);
            impl->window.store(nullptr, std::memory_order_release);
            impl->visible = false;
            impl->guestHandle.store(0, std::memory_order_release);
            if (!impl->intentionalDestroy &&
                !impl->shuttingDown.load(std::memory_order_acquire)) {
                impl->userClosed.store(true, std::memory_order_release);
            }
            SetWindowLongPtrA(window, GWLP_USERDATA, 0);
            PostQuitMessage(0);
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

void hostWindowThreadMain(SugarbombHostWindow::Impl* impl) {
    if (!impl) {
        return;
    }
    SugarbombHostWindow::Impl::SyncRequest request;
    {
        std::lock_guard<std::mutex> lock(impl->lifecycleMutex);
        request = impl->startupRequest;
    }

    impl->windowThreadId.store(
        GetCurrentThreadId(),
        std::memory_order_release);
    bool succeeded = false;
    HINSTANCE instance = GetModuleHandleA(nullptr);
    if (!registerHostWindowClass(instance)) {
        std::fprintf(
            stderr,
            "Sugarbomb host presentation: RegisterClassExA failed "
            "with error %lu\n",
            GetLastError());
    } else {
        const std::int32_t safeWidth =
            std::max<std::int32_t>(
                1,
                std::min<std::int32_t>(
                    request.clientWidth,
                    16384));
        const std::int32_t safeHeight =
            std::max<std::int32_t>(
                1,
                std::min<std::int32_t>(
                    request.clientHeight,
                    16384));
        const std::string resolvedTitle = request.title.empty()
            ? "Fallout: New Vegas - Sugarbomb x64 host"
            : request.title;
        RECT rectangle = {0, 0, safeWidth, safeHeight};
        AdjustWindowRect(
            &rectangle,
            WS_OVERLAPPEDWINDOW,
            FALSE);
        HWND window = CreateWindowExA(
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
        if (!window) {
            std::fprintf(
                stderr,
                "Sugarbomb host presentation: CreateWindowExA failed "
                "with error %lu\n",
                GetLastError());
        } else {
            impl->window.store(window, std::memory_order_release);
            impl->guestHandle.store(
                request.guestHandle,
                std::memory_order_release);
            RAWINPUTDEVICE rawMouse = {};
            rawMouse.usUsagePage = 0x01;
            rawMouse.usUsage = 0x02;
            rawMouse.hwndTarget = window;
            impl->rawMouseRegistered =
                RegisterRawInputDevices(
                    &rawMouse,
                    1,
                    sizeof(rawMouse)) != FALSE;
            if (!impl->rawMouseRegistered) {
                std::fprintf(
                    stderr,
                    "Sugarbomb host input: RegisterRawInputDevices "
                    "failed with error %lu; using WM_MOUSEMOVE "
                    "fallback\n",
                    GetLastError());
            }
            std::printf(
                "Sugarbomb host presentation: mapped guest HWND "
                "0x%08X to native window %p on UI thread %lu "
                "(%dx%d)\n",
                request.guestHandle,
                static_cast<void*>(window),
                GetCurrentThreadId(),
                safeWidth,
                safeHeight);
            succeeded =
                applyNativeWindowSync(impl, request);
        }
    }

    {
        std::lock_guard<std::mutex> lock(impl->lifecycleMutex);
        impl->startupSucceeded = succeeded;
        impl->startupComplete = true;
    }
    impl->lifecycleCondition.notify_all();
    if (!succeeded) {
        HWND window =
            impl->window.load(std::memory_order_acquire);
        if (window) {
            impl->intentionalDestroy = true;
            DestroyWindow(window);
        }
        impl->windowThreadId.store(0, std::memory_order_release);
        return;
    }

    MSG message = {};
    while (true) {
        const BOOL result =
            GetMessageA(&message, nullptr, 0, 0);
        if (result <= 0) {
            break;
        }
        TranslateMessage(&message);
        DispatchMessageA(&message);
    }

    HWND window =
        impl->window.load(std::memory_order_acquire);
    if (window) {
        impl->intentionalDestroy = true;
        DestroyWindow(window);
    }
    impl->windowThreadId.store(0, std::memory_order_release);
}

bool startHostWindowThread(
    SugarbombHostWindow::Impl* impl,
    const SugarbombHostWindow::Impl::SyncRequest& request) {
    if (!impl) {
        return false;
    }
    if (impl->windowThread.joinable()) {
        impl->windowThread.join();
    }
    {
        std::lock_guard<std::mutex> lock(impl->lifecycleMutex);
        impl->startupRequest = request;
        impl->startupComplete = false;
        impl->startupSucceeded = false;
    }
    impl->intentionalDestroy = false;
    impl->shuttingDown.store(false, std::memory_order_release);
    impl->appliedShowCommand = -1;
    impl->windowThread =
        std::thread(hostWindowThreadMain, impl);

    std::unique_lock<std::mutex> lock(impl->lifecycleMutex);
    impl->lifecycleCondition.wait(
        lock,
        [impl]() {
            return impl->startupComplete;
        });
    const bool succeeded = impl->startupSucceeded;
    lock.unlock();
    if (!succeeded && impl->windowThread.joinable()) {
        impl->windowThread.join();
    }
    return succeeded;
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
    bool visible,
    std::uint32_t showCommand) {
#ifdef _WIN32
    if (presentationDisabled() ||
        impl->userClosed.load(std::memory_order_acquire)) {
        return;
    }
    Impl::SyncRequest request;
    request.guestHandle = guestHandle;
    request.title = title;
    request.x = x;
    request.y = y;
    request.clientWidth = clientWidth;
    request.clientHeight = clientHeight;
    request.visible = visible;
    request.showCommand = showCommand;

    HWND window =
        impl->window.load(std::memory_order_acquire);
    if (!window) {
        if (startHostWindowThread(impl, request)) {
            std::lock_guard<std::mutex> lock(
                impl->syncStateMutex);
            impl->lastSyncRequest = request;
            impl->lastSyncRequestValid = true;
        }
        return;
    }
    if (impl->guestHandle.load(std::memory_order_acquire) !=
        guestHandle) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(
            impl->syncStateMutex);
        if (impl->lastSyncRequestValid &&
            sameSyncRequest(
                impl->lastSyncRequest,
                request)) {
            return;
        }
    }
    if (SendMessageA(
            window,
            WM_SUGARBOMB_SYNC,
            0,
            reinterpret_cast<LPARAM>(&request))) {
        std::lock_guard<std::mutex> lock(
            impl->syncStateMutex);
        impl->lastSyncRequest = request;
        impl->lastSyncRequestValid = true;
    }
#else
    (void)guestHandle;
    (void)title;
    (void)x;
    (void)y;
    (void)clientWidth;
    (void)clientHeight;
    (void)visible;
    (void)showCommand;
#endif
}

bool SugarbombHostWindow::activateGuestWindow(std::uint32_t guestHandle) {
#ifdef _WIN32
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    if (!window ||
        impl->guestHandle.load(std::memory_order_acquire) !=
            guestHandle) {
        return false;
    }
    return SendMessageA(
        window,
        WM_SUGARBOMB_ACTIVATE,
        guestHandle,
        0) != FALSE;
#else
    (void)guestHandle;
    return true;
#endif
}

bool SugarbombHostWindow::setActiveGuestWindow(
    std::uint32_t guestHandle) {
#ifdef _WIN32
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    if (!window ||
        (guestHandle &&
         impl->guestHandle.load(std::memory_order_acquire) !=
             guestHandle)) {
        return false;
    }
    return SendMessageA(
        window,
        WM_SUGARBOMB_SET_ACTIVE,
        guestHandle,
        0) != FALSE;
#else
    (void)guestHandle;
    return true;
#endif
}

bool SugarbombHostWindow::focusGuestWindow(
    std::uint32_t guestHandle) {
#ifdef _WIN32
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    if (!window ||
        (guestHandle &&
         impl->guestHandle.load(std::memory_order_acquire) !=
             guestHandle)) {
        return false;
    }
    return SendMessageA(
        window,
        WM_SUGARBOMB_SET_FOCUS,
        guestHandle,
        0) != FALSE;
#else
    (void)guestHandle;
    return true;
#endif
}

bool SugarbombHostWindow::isGuestWindowForeground(
    std::uint32_t guestHandle) const {
#ifdef _WIN32
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    return window &&
        impl->guestHandle.load(std::memory_order_acquire) ==
            guestHandle &&
        GetForegroundWindow() == window;
#else
    (void)guestHandle;
    return true;
#endif
}

bool SugarbombHostWindow::isGuestWindowActive(
    std::uint32_t guestHandle) const {
#ifdef _WIN32
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    if (!window ||
        impl->guestHandle.load(std::memory_order_acquire) !=
            guestHandle) {
        return false;
    }
    return SendMessageA(
        window,
        WM_SUGARBOMB_QUERY_ACTIVE,
        0,
        0) != FALSE;
#else
    (void)guestHandle;
    return true;
#endif
}

bool SugarbombHostWindow::isGuestWindowFocused(
    std::uint32_t guestHandle) const {
#ifdef _WIN32
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    if (!window ||
        impl->guestHandle.load(std::memory_order_acquire) !=
            guestHandle) {
        return false;
    }
    return SendMessageA(
        window,
        WM_SUGARBOMB_QUERY_FOCUS,
        0,
        0) != FALSE;
#else
    (void)guestHandle;
    return true;
#endif
}

bool SugarbombHostWindow::guestClientToScreen(
    std::int32_t guestX,
    std::int32_t guestY,
    std::int32_t& screenX,
    std::int32_t& screenY) const {
#ifdef _WIN32
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    RECT client = {};
    if (!window || !GetClientRect(window, &client)) {
        return false;
    }
    const std::int32_t nativeWidth =
        client.right - client.left;
    const std::int32_t nativeHeight =
        client.bottom - client.top;
    const std::int32_t guestWidth =
        impl->guestClientWidth.load(std::memory_order_acquire);
    const std::int32_t guestHeight =
        impl->guestClientHeight.load(std::memory_order_acquire);
    if (nativeWidth <= 0 ||
        nativeHeight <= 0 ||
        guestWidth <= 0 ||
        guestHeight <= 0) {
        return false;
    }
    const auto scaleCoordinate = [](
        std::int32_t value,
        std::int32_t nativeExtent,
        std::int32_t guestExtent) {
        return static_cast<LONG>(
            std::max<std::int64_t>(
                std::numeric_limits<LONG>::min(),
                std::min<std::int64_t>(
                    std::numeric_limits<LONG>::max(),
                    static_cast<std::int64_t>(value) *
                        nativeExtent /
                        guestExtent)));
    };
    POINT position = {
        scaleCoordinate(guestX, nativeWidth, guestWidth),
        scaleCoordinate(guestY, nativeHeight, guestHeight)};
    if (!ClientToScreen(window, &position)) {
        return false;
    }
    screenX = position.x;
    screenY = position.y;
    return true;
#else
    screenX = guestX;
    screenY = guestY;
    return true;
#endif
}

void SugarbombHostWindow::setCursorVisible(bool visible) {
#ifdef _WIN32
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    if (window) {
        SendMessageA(
            window,
            WM_SUGARBOMB_CURSOR,
            visible ? 1 : 0,
            0);
    }
#else
    (void)visible;
#endif
}

bool SugarbombHostWindow::setMouseCapture(bool captured) {
#ifdef _WIN32
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    return window &&
        SendMessageA(
            window,
            WM_SUGARBOMB_CAPTURE,
            captured ? 1 : 0,
            0) != FALSE;
#else
    (void)captured;
    return true;
#endif
}

void SugarbombHostWindow::destroyGuestWindow(std::uint32_t guestHandle) {
#ifdef _WIN32
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    if (!window ||
        impl->guestHandle.load(std::memory_order_acquire) !=
            guestHandle) {
        return;
    }
    SendMessageA(window, WM_SUGARBOMB_DESTROY, 0, 0);
    if (impl->windowThread.joinable()) {
        impl->windowThread.join();
    }
    impl->intentionalDestroy = false;
    impl->userClosed.store(false, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lock(
            impl->syncStateMutex);
        impl->lastSyncRequestValid = false;
    }
    {
        std::lock_guard<std::mutex> lock(impl->frameMutex);
        impl->framePixels.clear();
        impl->frameWidth = 0;
        impl->frameHeight = 0;
    }
#else
    (void)guestHandle;
#endif
}

bool SugarbombHostWindow::pumpMessages(std::vector<Event>* events) {
#ifdef _WIN32
    {
        std::lock_guard<std::mutex> lock(impl->eventMutex);
        if (events && !impl->pendingEvents.empty()) {
            events->insert(
                events->end(),
                impl->pendingEvents.begin(),
                impl->pendingEvents.end());
        }
        impl->pendingEvents.clear();
    }
    return !impl->userClosed.load(std::memory_order_acquire);
#else
    (void)events;
    return true;
#endif
}

std::uintptr_t SugarbombHostWindow::nativeHandle() const {
#ifdef _WIN32
    return reinterpret_cast<std::uintptr_t>(
        impl->window.load(std::memory_order_acquire));
#else
    return 0;
#endif
}

void SugarbombHostWindow::present(
    const std::uint32_t* pixels,
    std::uint32_t width,
    std::uint32_t height) {
#ifdef _WIN32
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    if (!window || !pixels || !width || !height) {
        return;
    }
    const std::size_t pixelCount =
        static_cast<std::size_t>(width) * height;
    {
        std::lock_guard<std::mutex> lock(impl->frameMutex);
        impl->framePixels.assign(pixels, pixels + pixelCount);
        impl->frameWidth = width;
        impl->frameHeight = height;
    }
    PostMessageA(window, WM_SUGARBOMB_PRESENT, 0, 0);
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
    impl->shuttingDown.store(true, std::memory_order_release);
    const HWND window =
        impl->window.load(std::memory_order_acquire);
    if (window) {
        SendMessageA(window, WM_SUGARBOMB_DESTROY, 0, 0);
    } else {
        const DWORD threadId =
            impl->windowThreadId.load(std::memory_order_acquire);
        if (threadId) {
            PostThreadMessageA(threadId, WM_QUIT, 0, 0);
        }
    }
    if (impl->windowThread.joinable()) {
        impl->windowThread.join();
    }
    {
        std::lock_guard<std::mutex> lock(
            impl->syncStateMutex);
        impl->lastSyncRequestValid = false;
    }
#endif
    {
        std::lock_guard<std::mutex> lock(impl->frameMutex);
        impl->framePixels.clear();
        impl->frameWidth = 0;
        impl->frameHeight = 0;
    }
    {
        std::lock_guard<std::mutex> lock(impl->eventMutex);
        impl->pendingEvents.clear();
    }
    impl->visible = false;
}
