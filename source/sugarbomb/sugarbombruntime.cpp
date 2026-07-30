/*
 *  Copyright (C) 2026  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "boxedwine.h"
#include "knativethread.h"
#include "pe32loader.h"
#include "sugarbombbridge.h"
#include "sugarbombhostd3d9.h"
#include "sugarbombhostwindow.h"
#include "sugarbombruntime.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#ifdef BOXEDWINE_HOST_EXCEPTIONS
void platformInitExceptionHandling();
#endif

namespace {

constexpr U32 THUNK_BASE = 0x60000000;
constexpr U32 THUNK_SIZE = 0x00100000;
constexpr U32 STACK_BASE = 0x6f800000;
constexpr U32 STACK_SIZE = 0x00800000;
constexpr U32 STACK_TOP = STACK_BASE + STACK_SIZE;
constexpr U32 CHILD_STACK_FIRST_TOP = STACK_BASE;
constexpr U32 CHILD_ENV_FIRST_BASE = 0x7ffc0000;
constexpr U32 CHILD_ENV_SIZE = 0x00010000;
constexpr U32 CHILD_TLS_ARRAY_OFFSET = 0x0000;
constexpr U32 CHILD_TEB_OFFSET = 0xe000;
constexpr U32 ENV_BASE = 0x7ffd8000;
constexpr U32 ENV_SIZE = 0x00008000;
constexpr U32 ANSI_COMMAND_LINE = 0x7ffd8000;
constexpr U32 WIDE_IMAGE_PATH = 0x7ffd8800;
constexpr U32 WIDE_COMMAND_LINE = 0x7ffd9000;
constexpr U32 TLS_ARRAY = 0x7ffda000;
constexpr U32 ANSI_ENVIRONMENT = 0x7ffdb000;
constexpr U32 WIDE_ENVIRONMENT = 0x7ffdb400;
constexpr U32 PROCESS_PARAMETERS = 0x7ffdc000;
constexpr U32 PEB_LDR_DATA = 0x7ffdd000;
constexpr U32 TEB_ADDRESS = 0x7ffde000;
constexpr U32 PEB_ADDRESS = 0x7ffdf000;
constexpr U32 WINDOWS_TEB_SELECTOR = (TLS_ENTRY_START_INDEX << 3) | 3;
constexpr U64 WINDOWS_TO_UNIX_EPOCH_100NS = 116444736000000000ULL;
constexpr U32 GUEST_THREAD_QUANTUM_SLICES = 32;
constexpr U32 PROCESS_HEAP_HANDLE = 0x50000000;
constexpr U32 KERNEL32_MODULE_HANDLE = 0x51000000;
constexpr U32 STDIN_GUEST_HANDLE = 0x52000000;
constexpr U32 STDOUT_GUEST_HANDLE = 0x52000001;
constexpr U32 STDERR_GUEST_HANDLE = 0x52000002;
constexpr U32 GUEST_FILE_HANDLE_BASE = 0x54000000;
constexpr U32 GUEST_FIND_HANDLE_BASE = 0x55000000;
constexpr U32 GUEST_HEAP_BASE = 0x40000000;
constexpr U32 GUEST_HEAP_LIMIT = 0x5f000000;
constexpr U32 GUEST_VIRTUAL_BASE = 0x02000000;
constexpr U32 GUEST_VIRTUAL_LIMIT = 0x3f000000;
constexpr U32 HEAP_ZERO_MEMORY = 0x00000008;
constexpr U32 CREATE_SUSPENDED = 0x00000004;
constexpr U32 STILL_ACTIVE = 259;
constexpr U32 CURRENT_THREAD_PSEUDO_HANDLE = 0xfffffffe;
constexpr U32 USER_ICON_HANDLE = 0x57000001;
constexpr U32 USER_CURSOR_HANDLE = 0x57000002;
constexpr U32 USER_HOOK_HANDLE = 0x57000003;
constexpr U32 GDI_STOCK_OBJECT_HANDLE = 0x58000000;
constexpr U32 MMIO_HANDLE_BASE = 0x59000000;
constexpr U32 D3D9_MODULE_HANDLE = 0x5a000000;
constexpr U32 DIRECTINPUT_VERSION = 0x0800;

class SugarbombRuntimeSession;
SugarbombRuntimeSession* activeSession = nullptr;

std::string lowerAscii(const std::string& value) {
    std::string result = value;
    std::transform(result.begin(), result.end(), result.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return result;
}

void writeUnicodeString(KMemory* memory, U32 descriptor, U32 buffer, const std::string& text) {
    U16 length = static_cast<U16>(std::min<std::size_t>(text.size(), 0x7ffe) * 2);
    memory->writew(descriptor, length);
    memory->writew(descriptor + 2, length + 2);
    memory->writed(descriptor + 4, buffer);
    U32 characters = length / 2;
    for (U32 index = 0; index < characters; ++index) {
        memory->writew(buffer + index * 2, static_cast<U8>(text[index]));
    }
    memory->writew(buffer + length, 0);
}

class SugarbombRuntimeSession {
public:
    int run(const char* imagePath) {
        setvbuf(stdout, nullptr, _IONBF, 0);
        hostWindow.hideOwnedConsoleWindow();
        this->imagePath = imagePath ? imagePath : "";
        this->commandLine = "\"" + this->imagePath + "\"";

        KSystem::startMicroCounter();
        KSystem::init();
        KSystem::videoOption = VIDEO_NO_WINDOW;
#ifdef BOXEDWINE_HOST_EXCEPTIONS
        platformInitExceptionHandling();
#endif

        int result = 1;
        try {
            if (initialize() && execute()) {
                result = stoppedAtUnresolvedImport ? 2 : 0;
            }
        } catch (const std::exception& exception) {
            fprintf(stderr, "Sugarbomb runtime exception: %s\n", exception.what());
        } catch (...) {
            fprintf(stderr, "Sugarbomb runtime stopped after an unknown host exception\n");
        }

        cleanup();
        KSystem::destroy();
        activeSession = nullptr;
        return result;
    }

    static bool resolveImport(
        void* context,
        const Pe32ImportModule& module,
        const Pe32ImportSymbol& symbol,
        U32& guestAddress) {
        SugarbombRuntimeSession* session = static_cast<SugarbombRuntimeSession*>(context);
        std::string moduleName = lowerAscii(module.name);
        std::string symbolName = symbol.byOrdinal
            ? "#" + std::to_string(symbol.ordinal)
            : symbol.name;
        SugarbombNativeCallback callback = nullptr;
        U16 stackCleanupBytes = 0;
        session->findNativeCallback(moduleName, symbolName, callback, stackCleanupBytes);
        if (!callback) {
            callback = callbackUnresolvedImport;
        }

        U32 callbackIndex = SugarbombBridge::registerCallback(module.name, symbolName, callback);
        if (!session->thunks.createThunk(callbackIndex, stackCleanupBytes, guestAddress, session->error)) {
            return false;
        }
        return true;
    }

private:
    enum class GuestWaitKind {
        None,
        KernelObjects,
        Sleep,
        CriticalSection,
        SlimReaderWriterLock,
        ConditionVariable
    };

    struct GuestThreadState {
        KThread* thread = nullptr;
        U32 handle = 0;
        U32 stackBase = 0;
        U32 stackSize = 0;
        U32 environmentBase = 0;
        U32 tebAddress = 0;
        U32 tlsArray = 0;
        std::vector<U32> staticTlsBlocks;
        U32 suspendCount = 0;
        U32 exitCode = STILL_ACTIVE;
        std::string name;
        bool completed = false;
        bool mainThread = false;
        GuestWaitKind waitKind = GuestWaitKind::None;
        std::vector<U32> waitHandles;
        U64 waitDeadline = 0;
        bool waitAll = false;
        U32 waitCriticalSectionAddress = 0;
        U32 waitSlimReaderWriterLockAddress = 0;
        bool waitSlimReaderWriterLockExclusive = false;
        U32 waitConditionVariableAddress = 0;
        bool waitConditionVariableSignaled = false;
    };

    struct StaticTlsTemplate {
        U32 moduleBase = 0;
        U32 slot = 0;
        U32 rawStart = 0;
        U32 rawSize = 0;
        U32 zeroFillSize = 0;
        std::vector<U32> callbacks;
    };

    struct GuestModuleInitializer {
        U32 address = 0;
        U32 moduleBase = 0;
        bool requireSuccess = false;
        bool marksModuleInitialized = false;
        std::string label;
    };

    struct GuestOnExitTable {
        U32 allocation = 0;
        U32 capacity = 0;
        bool owned = false;
    };

    struct PendingGuestFunctionArray {
        U32 nativeThunkStackPointer = 0;
        U32 nativeThunkResumeEip = 0;
        std::vector<U32> functions;
        std::size_t nextIndex = 0;
        bool stopOnFailure = false;
        std::string label;
    };

    struct GuestModule {
        std::string key;
        std::string path;
        Pe32MappedImage image;
        U32 references = 1;
        bool initialized = false;
    };

    struct GuestWindowClass {
        U32 atom = 0;
        U32 style = 0;
        U32 windowProcedure = 0;
        U32 instance = 0;
        U32 icon = 0;
        U32 cursor = 0;
        U32 background = 0;
        std::string name;
    };

    struct GuestWindow {
        U32 handle = 0;
        U32 ownerThreadId = 0;
        U32 extendedStyle = 0;
        U32 style = 0;
        U32 instance = 0;
        U32 parent = 0;
        S32 x = 0;
        S32 y = 0;
        S32 width = 1280;
        S32 height = 720;
        bool visible = false;
        std::string className;
        std::string title;
    };

    struct GuestMessage {
        U32 threadId = 0;
        U32 window = 0;
        U32 message = 0;
        U32 wordParameter = 0;
        U32 longParameter = 0;
        U32 time = 0;
        S32 pointX = 0;
        S32 pointY = 0;
    };

    enum class NativeWindowState {
        Active,
        Focused,
        Foreground
    };

    struct PendingWndProcDispatch {
        U32 nativeThunkStackPointer = 0;
        U32 nativeThunkResumeEip = 0;
        U32 window = 0;
        U32 message = 0;
    };

    enum class DirectInputObjectKind {
        Interface,
        Device
    };

    struct DirectInputDeviceEvent {
        U32 offset = 0;
        U32 data = 0;
        U32 timestamp = 0;
        U32 sequence = 0;
    };

    struct DirectInputObject {
        DirectInputObjectKind kind = DirectInputObjectKind::Interface;
        U32 references = 1;
        U32 deviceGuidData1 = 0;
        U32 dataFormatSize = 0;
        U32 cooperativeWindow = 0;
        U32 cooperativeFlags = 0;
        U32 eventHandle = 0;
        U32 bufferSize = 0;
        bool acquired = false;
        S32 mouseDeltaX = 0;
        S32 mouseDeltaY = 0;
        S32 mouseWheelDelta = 0;
        std::deque<DirectInputDeviceEvent> events;
    };

    struct DirectInputComMethod {
        bool device = false;
        U32 index = 0;
    };

    enum class DirectSoundObjectKind {
        Interface,
        Buffer
    };

    struct DirectSoundObject {
        DirectSoundObjectKind kind = DirectSoundObjectKind::Interface;
        U32 references = 1;
        U32 flags = 0;
        U32 bufferBytes = 0;
        U32 storageAddress = 0;
        U32 frequency = 44100;
        S32 volume = 0;
        S32 pan = 0;
        bool playing = false;
    };

    struct DirectSoundComMethod {
        bool buffer = false;
        U32 index = 0;
    };

    enum class DirectShowInterfaceKind : U32 {
        FilterGraph,
        GraphBuilder,
        MediaControl,
        MediaPosition,
        BasicAudio,
        MediaEvent,
        Count
    };

    struct DirectShowGraph {
        U32 references = 1;
        U32 interfaceAddresses[static_cast<U32>(DirectShowInterfaceKind::Count)] = {};
        double durationSeconds = 180.0;
        double currentPositionSeconds = 0.0;
        U64 runStartedMicroseconds = 0;
        S32 volume = 0;
        U32 filterState = 0;
    };

    struct DirectShowInterface {
        DirectShowInterfaceKind kind = DirectShowInterfaceKind::FilterGraph;
        U32 graphAddress = 0;
    };

    struct DirectShowComMethod {
        DirectShowInterfaceKind kind = DirectShowInterfaceKind::FilterGraph;
        U32 index = 0;
    };

    struct BinkMovie {
        U32 width = 640;
        U32 height = 360;
        U32 frames = 2;
        U32 frame = 1;
        U32 openFlags = 0;
        bool paused = false;
    };

    struct MmioFile {
        U32 guestFileHandle = 0;
        U64 position = 0;
    };

    enum class Direct3DObjectKind {
        Interface,
        Device
    };

    struct Direct3DObject {
        Direct3DObjectKind kind = Direct3DObjectKind::Interface;
        U32 references = 1;
    };

    struct Direct3DComMethod {
        bool device = false;
        U32 index = 0;
    };

    struct Direct3DSurface {
        U32 references = 1;
        U32 width = 0;
        U32 height = 0;
        U32 format = 22;
        U32 usage = 0;
        U32 pool = 0;
        U32 multiSampleType = 0;
        U32 multiSampleQuality = 0;
        U32 storageAddress = 0;
        U32 parentResource = 0;
        U32 parentFace = 0;
        U32 parentLevel = 0;
        U32 lockPitch = 0;
        U32 lockRows = 0;
    };

    enum class Direct3DResourceKind : U32 {
        Texture,
        CubeTexture,
        Buffer,
        Declaration,
        Shader,
        StateBlock,
        Query
    };

    struct Direct3DResource {
        Direct3DResourceKind kind = Direct3DResourceKind::Texture;
        U32 references = 1;
        U32 resourceType = 3;
        U32 width = 1;
        U32 height = 1;
        U32 levels = 1;
        U32 format = 22;
        U32 usage = 0;
        U32 pool = 0;
        U32 length = 0;
        U32 storageAddress = 0;
        U32 lockOffset = 0;
        U32 lockSize = 0;
        U32 lockFace = 0;
        U32 lockLevel = 0;
        U32 lockPitch = 0;
        U32 lockRows = 0;
    };

    struct Direct3DResourceMethod {
        Direct3DResourceKind kind = Direct3DResourceKind::Texture;
        U32 index = 0;
    };

    void direct3DStorageLayout(
        U32 format,
        U32 width,
        U32 height,
        U32& pitch,
        U32& rows) const {
        constexpr U32 D3DFMT_DXT1 = 0x31545844;
        constexpr U32 D3DFMT_DXT2 = 0x32545844;
        constexpr U32 D3DFMT_DXT3 = 0x33545844;
        constexpr U32 D3DFMT_DXT4 = 0x34545844;
        constexpr U32 D3DFMT_DXT5 = 0x35545844;
        if (format == D3DFMT_DXT1 ||
            format == D3DFMT_DXT2 ||
            format == D3DFMT_DXT3 ||
            format == D3DFMT_DXT4 ||
            format == D3DFMT_DXT5) {
            pitch = std::max<U32>(1, (width + 3) / 4) *
                (format == D3DFMT_DXT1 ? 8 : 16);
            rows = std::max<U32>(1, (height + 3) / 4);
            return;
        }
        U32 bytesPerPixel = 4;
        switch (format) {
        case 20: // D3DFMT_R8G8B8
            bytesPerPixel = 3;
            break;
        case 23: // D3DFMT_R5G6B5
        case 24: // D3DFMT_X1R5G5B5
        case 25: // D3DFMT_A1R5G5B5
        case 26: // D3DFMT_A4R4G4B4
        case 29: // D3DFMT_A8R3G3B2
        case 30: // D3DFMT_X4R4G4B4
        case 51: // D3DFMT_A8L8
        case 60: // D3DFMT_V8U8
            bytesPerPixel = 2;
            break;
        case 27: // D3DFMT_R3G3B2
        case 28: // D3DFMT_A8
        case 41: // D3DFMT_P8
        case 50: // D3DFMT_L8
        case 52: // D3DFMT_A4L4
            bytesPerPixel = 1;
            break;
        case 36: // D3DFMT_A16B16G16R16
        case 113: // D3DFMT_A16B16G16R16F
            bytesPerPixel = 8;
            break;
        case 116: // D3DFMT_A32B32G32R32F
            bytesPerPixel = 16;
            break;
        default:
            break;
        }
        pitch = width * bytesPerPixel;
        rows = height;
    }

    bool ensureDirect3DSurfaceStorage(Direct3DSurface& surface) {
        direct3DStorageLayout(
            surface.format,
            surface.width,
            surface.height,
            surface.lockPitch,
            surface.lockRows);
        U64 storageSize64 =
            static_cast<U64>(surface.lockPitch) * surface.lockRows;
        if (!storageSize64 || storageSize64 > 0x10000000) {
            return false;
        }
        if (!surface.storageAddress) {
            surface.storageAddress = allocateGuestHeap(
                static_cast<U32>(storageSize64),
                true);
        }
        return surface.storageAddress != 0;
    }

    void clearDirect3DSurface(Direct3DSurface& surface, U32 color) {
        if (!ensureDirect3DSurfaceStorage(surface)) {
            return;
        }
        const std::size_t pixelCount =
            static_cast<std::size_t>(surface.width) * surface.height;
        if (surface.lockPitch != surface.width * sizeof(U32) ||
            surface.lockRows != surface.height) {
            memory->memset(
                surface.storageAddress,
                static_cast<U8>(color),
                surface.lockPitch * surface.lockRows);
            direct3DLastClearColor = color;
            return;
        }
        direct3DClearPixels.assign(pixelCount, color);
        memory->memcpy(
            surface.storageAddress,
            direct3DClearPixels.data(),
            static_cast<U32>(pixelCount * sizeof(U32)));
        direct3DLastClearColor = color;
    }

    void syncHostWindow(const GuestWindow& guestWindow) {
        hostWindow.syncGuestWindow(
            guestWindow.handle,
            guestWindow.title,
            guestWindow.x,
            guestWindow.y,
            guestWindow.width,
            guestWindow.height,
            guestWindow.visible);
    }

    void destroyHostWindowForGuest(U32 guestHandle) {
        hostWindow.destroyGuestWindow(guestHandle);
    }

    void updateGuestActivationFromHostEvent(
        const SugarbombHostWindow::Event& event) {
        constexpr U32 WM_ACTIVATE_GUEST = 0x0006;
        constexpr U32 WM_SETFOCUS_GUEST = 0x0007;
        constexpr U32 WM_KILLFOCUS_GUEST = 0x0008;
        constexpr U32 WM_ACTIVATEAPP_GUEST = 0x001c;
        if (event.message != WM_ACTIVATE_GUEST &&
            event.message != WM_SETFOCUS_GUEST &&
            event.message != WM_KILLFOCUS_GUEST &&
            event.message != WM_ACTIVATEAPP_GUEST) {
            return;
        }
        bool activated =
            event.message == WM_SETFOCUS_GUEST ||
            (event.message == WM_ACTIVATE_GUEST &&
             (event.wordParameter & 0xffff)) ||
            (event.message == WM_ACTIVATEAPP_GUEST &&
             event.wordParameter);
        U32 topLevel = topLevelGuestWindow(event.guestHandle);
        if (!topLevel) {
            return;
        }
        if (activated) {
            activeWindow = topLevel;
        } else if (activeWindow == topLevel) {
            activeWindow = 0;
        }
    }

    void pumpHostMessages() {
        std::vector<SugarbombHostWindow::Event> events;
        if (!hostWindow.pumpMessages(&events)) {
            runtimeStopping = true;
        }
        for (const SugarbombHostWindow::Event& event : events) {
            updateGuestActivationFromHostEvent(event);
            updateDirectInputFromHostEvent(event);
            if (event.forwardToGuest) {
                enqueueGuestMessage(
                    event.guestHandle,
                    event.message,
                    event.wordParameter,
                    event.longParameter,
                    event.time,
                    event.pointX,
                    event.pointY);
            }
        }
    }

    void presentHostBackBuffer() {
        U32 presentationWindow = topLevelGuestWindow(
            direct3DDeviceWindow ? direct3DDeviceWindow : activeWindow);
        auto guestWindow = guestWindows.find(presentationWindow);
        if (guestWindow == guestWindows.end()) {
            return;
        }
        syncHostWindow(guestWindow->second);
        if (hostDirect3D.ready()) {
            ++guestPresentCount;
            const char* capturePath =
                std::getenv("SUGARBOMB_CAPTURE_FRAME");
            U32 captureAfterPresents = 1;
            if (const char* configured =
                    std::getenv("SUGARBOMB_CAPTURE_AFTER_PRESENTS")) {
                char* end = nullptr;
                unsigned long value = std::strtoul(
                    configured,
                    &end,
                    10);
                if (end != configured && value <= 0xffffffffUL) {
                    captureAfterPresents = static_cast<U32>(value);
                }
            }
            if (!hostFrameCaptured &&
                capturePath &&
                *capturePath &&
                guestPresentCount >= captureAfterPresents) {
                hostFrameCaptured =
                    hostDirect3D.captureRenderTarget(capturePath);
            }
            hostDirect3D.present();
            pumpHostMessages();
            return;
        }
        U32 surfaceAddress = ensureDirect3DBackBuffer();
        auto found = direct3DSurfaces.find(surfaceAddress);
        if (found == direct3DSurfaces.end()) {
            return;
        }
        Direct3DSurface& surface = found->second;
        const U64 byteCount64 =
            static_cast<U64>(surface.width) * surface.height * sizeof(U32);
        if (!byteCount64 || byteCount64 > 0x10000000) {
            return;
        }
        const U32 byteCount = static_cast<U32>(byteCount64);
        hostPresentPixels.resize(byteCount / sizeof(U32));
        if (surface.storageAddress &&
            memory->canRead(surface.storageAddress, byteCount)) {
            memory->memcpy(
                hostPresentPixels.data(),
                surface.storageAddress,
                byteCount);
        } else {
            std::fill(
                hostPresentPixels.begin(),
                hostPresentPixels.end(),
                direct3DLastClearColor);
        }
        hostWindow.present(
            hostPresentPixels.data(),
            surface.width,
            surface.height);
        pumpHostMessages();
    }

    void shutdownHostWindow() {
        const char* finalCapturePath =
            std::getenv("SUGARBOMB_CAPTURE_FINAL_FRAME");
        if (finalCapturePath && *finalCapturePath) {
            hostDirect3D.captureRenderTarget(finalCapturePath);
        }
        const char* finalBackBufferPath =
            std::getenv("SUGARBOMB_CAPTURE_FINAL_BACKBUFFER");
        if (finalBackBufferPath && *finalBackBufferPath) {
            hostDirect3D.captureBackBuffer(finalBackBufferPath);
        }
        hostDirect3D.shutdown();
        hostWindow.shutdown();
        hostPresentPixels.clear();
    }

    bool initialize() {
        std::vector<U8> bytes;
        if (!Pe32Loader::readFile(imagePath.c_str(), bytes, error)) {
            fprintf(stderr, "Sugarbomb could not read the PE32 guest: %s\n", error.c_str());
            return false;
        }

        process = KProcess::create();
        process->name = B("FalloutNV.exe");
        process->commandLine = BString::copy(commandLine.c_str());
        process->memory = KMemory::create(process.get());
        memory = process->memory;
        thread = process->createThread();
        cpu = thread->cpu;
        KThread::setCurrentThread(thread);

        if (!mapRegion(STACK_BASE, STACK_SIZE, K_PROT_READ | K_PROT_WRITE, "guest stack") ||
            !mapRegion(ENV_BASE, ENV_SIZE, K_PROT_READ | K_PROT_WRITE, "Windows process environment") ||
            !thunks.initialize(thread, THUNK_BASE, THUNK_SIZE, error)) {
            fprintf(stderr, "Sugarbomb bootstrap failed: %s\n", error.c_str());
            return false;
        }
        memory->memset(STACK_BASE, 0, STACK_SIZE);
        memory->memset(ENV_BASE, 0, ENV_SIZE);

        activeSession = this;
        if (!Pe32Loader::mapImageWithImports(
                thread,
                bytes,
                0,
                resolveImport,
                this,
                image,
                error)) {
            fprintf(stderr, "Sugarbomb could not map the PE32 guest: %s\n", error.c_str());
            return false;
        }
        if (!mapBundledNvse()) {
            fprintf(
                stderr,
                "Sugarbomb could not stage NVSE in the guest process: %s\n",
                error.c_str());
            return false;
        }

        U32 exitCallback = SugarbombBridge::registerCallback(
            "sugarbomb",
            "ExeEntryPointReturn",
            callbackEntryPointReturn);
        U32 threadExitCallback = SugarbombBridge::registerCallback(
            "sugarbomb",
            "ThreadEntryPointReturn",
            callbackThreadEntryPointReturn);
        U32 wndProcReturnCallback = SugarbombBridge::registerCallback(
            "sugarbomb",
            "GuestWndProcReturn",
            callbackGuestWndProcReturn);
        U32 moduleInitializerReturnCallback =
            SugarbombBridge::registerCallback(
                "sugarbomb",
                "GuestModuleInitializerReturn",
                callbackGuestModuleInitializerReturn);
        U32 guestFunctionArrayReturnCallback =
            SugarbombBridge::registerCallback(
                "sugarbomb",
                "GuestFunctionArrayReturn",
                callbackGuestFunctionArrayReturn);
        if (!thunks.createThunk(exitCallback, 0, entryReturnThunk, error) ||
            !thunks.createThunk(threadExitCallback, 0, threadReturnThunk, error) ||
            !thunks.createThunk(wndProcReturnCallback, 0, wndProcReturnThunk, error) ||
            !thunks.createThunk(
                moduleInitializerReturnCallback,
                0,
                moduleInitializerReturnThunk,
                error) ||
            !thunks.createThunk(
                guestFunctionArrayReturnCallback,
                0,
                guestFunctionArrayReturnThunk,
                error) ||
            !initializeDirectInputComThunks() ||
            !initializeDirectSoundComThunks() ||
            !initializeDirectShowComThunks() ||
            !initializeDirect3DComThunks() ||
            !initializeFalloutCompatibilityThunks() ||
            !thunks.finalize(error)) {
            fprintf(stderr, "Sugarbomb could not finalize native thunks: %s\n", error.c_str());
            return false;
        }

        initializeWindowsEnvironment();
        initializeCpu();
        registerMainGuestThread();
        if (!initializeStaticTlsModules()) {
            fprintf(
                stderr,
                "Sugarbomb could not initialize PE static TLS modules: %s\n",
                error.c_str());
            return false;
        }
        if (!prepareBundledNvseInitialization()) {
            fprintf(
                stderr,
                "Sugarbomb could not prepare NVSE initialization: %s\n",
                error.c_str());
            return false;
        }
        initializeFalloutBootstrapObjects();
        printf(
            "Sugarbomb: mapped PE32 guest at 0x%08X-0x%08X; entry 0x%08X\n",
            image.loadBase,
            image.loadBase + image.info.sizeOfImage,
            image.entryPoint);
        printf(
            "Sugarbomb: installed %u import/host thunks at 0x%08X and Windows TEB at FS:[0]\n",
            thunks.thunkCount(),
            thunks.base());
        return true;
    }

    void initializeFalloutBootstrapObjects() {
        constexpr U32 FALLOUT_140525_IMAGE_BASE = 0x00400000;
        constexpr U32 FALLOUT_140525_IMAGE_SIZE = 0x0107b000;
        constexpr U32 FALLOUT_140525_ENTRY_POINT = 0x00ecc4db;
        constexpr U32 FALLOUT_BINK_MANAGER_POINTER = 0x0126fac4;
        constexpr U32 FALLOUT_BINK_MANAGER_SIZE = 0x54;
        constexpr U32 FALLOUT_BINK_MANAGER_VTABLE = 0x01082564;
        constexpr U32 FALLOUT_BINK_QUEUE_VTABLE = 0x010f1c20;

        if (image.loadBase != FALLOUT_140525_IMAGE_BASE ||
            image.info.sizeOfImage != FALLOUT_140525_IMAGE_SIZE ||
            image.entryPoint != FALLOUT_140525_ENTRY_POINT ||
            !memory->canWrite(FALLOUT_BINK_MANAGER_POINTER, 4) ||
            memory->readd(FALLOUT_BINK_MANAGER_POINTER)) {
            return;
        }

        U32 manager = allocateGuestHeap(FALLOUT_BINK_MANAGER_SIZE, true);
        U32 semaphore = createSemaphore(0, 1, 0);
        if (!manager || !semaphore) {
            return;
        }
        memory->writed(manager, FALLOUT_BINK_MANAGER_VTABLE);
        memory->writeb(manager + 0x23, 1);
        memory->writeb(manager + 0x24, 1);
        memory->writed(manager + 0x34, semaphore);
        memory->writed(manager + 0x38, 1);
        memory->writed(manager + 0x40, FALLOUT_BINK_QUEUE_VTABLE);
        memory->writeb(manager + 0x50, 1);
        memory->writed(FALLOUT_BINK_MANAGER_POINTER, manager);
        printf(
            "Sugarbomb Fallout 1.4: installed bootstrap Bink manager at 0x%08X\n",
            manager);

        constexpr U32 FALLOUT_HAVOK_MEMORY_SYSTEM_POINTER = 0x01268418;
        U32 havokBlock = allocateGuestHeap(0x50, true);
        if (!havokBlock ||
            !memory->canWrite(FALLOUT_HAVOK_MEMORY_SYSTEM_POINTER, 4)) {
            return;
        }
        U32 systemVtable = havokBlock;
        U32 allocatorVtable = havokBlock + 0x20;
        falloutBootstrapMemorySystem = havokBlock + 0x40;
        falloutBootstrapAllocator = havokBlock + 0x44;
        for (U32 index = 0; index < falloutMemorySystemVtable.size(); ++index) {
            memory->writed(
                systemVtable + index * sizeof(U32),
                falloutMemorySystemVtable[index]);
        }
        for (U32 index = 0; index < falloutAllocatorVtable.size(); ++index) {
            memory->writed(
                allocatorVtable + index * sizeof(U32),
                falloutAllocatorVtable[index]);
        }
        memory->writed(falloutBootstrapMemorySystem, systemVtable);
        memory->writed(falloutBootstrapAllocator, allocatorVtable);
        memory->writed(
            FALLOUT_HAVOK_MEMORY_SYSTEM_POINTER,
            falloutBootstrapMemorySystem);
        printf(
            "Sugarbomb Fallout 1.4: installed bootstrap Havok memory system at 0x%08X\n",
            falloutBootstrapMemorySystem);
    }

    bool initializeFalloutCompatibilityThunks() {
        auto create = [&](const char* name,
                          SugarbombNativeCallback callback,
                          U16 cleanup,
                          std::vector<U32>& vtable) {
            U32 callbackIndex = SugarbombBridge::registerCallback(
                "FALLOUTNV.COMPAT",
                name,
                callback);
            U32 guestAddress = 0;
            if (!thunks.createThunk(
                    callbackIndex,
                    cleanup,
                    guestAddress,
                    error)) {
                return false;
            }
            vtable.push_back(guestAddress);
            return true;
        };

        return
            create(
                "BootstrapMemorySystem::Destroy",
                callbackFalloutCompatibilityNoOp,
                4,
                falloutMemorySystemVtable) &&
            create(
                "BootstrapMemorySystem::Method1",
                callbackFalloutCompatibilityNoOp,
                0,
                falloutMemorySystemVtable) &&
            create(
                "BootstrapMemorySystem::Method2",
                callbackFalloutCompatibilityNoOp,
                0,
                falloutMemorySystemVtable) &&
            create(
                "BootstrapMemorySystem::InitializeThread",
                callbackFalloutMemorySystemInitializeThread,
                12,
                falloutMemorySystemVtable) &&
            create(
                "BootstrapMemorySystem::QuitThread",
                callbackFalloutCompatibilityNoOp,
                8,
                falloutMemorySystemVtable) &&
            create(
                "BootstrapAllocator::Destroy",
                callbackFalloutCompatibilityNoOp,
                4,
                falloutAllocatorVtable) &&
            create(
                "BootstrapAllocator::Allocate",
                callbackFalloutAllocatorAllocate,
                4,
                falloutAllocatorVtable) &&
            create(
                "BootstrapAllocator::Free",
                callbackFalloutAllocatorFree,
                8,
                falloutAllocatorVtable) &&
            create(
                "BootstrapAllocator::AllocateBlock",
                callbackFalloutAllocatorAllocate,
                8,
                falloutAllocatorVtable) &&
            create(
                "BootstrapAllocator::FreeBlock",
                callbackFalloutAllocatorFree,
                8,
                falloutAllocatorVtable);
    }

    bool initializeDirectInputComThunks() {
        struct ThunkSpec {
            const char* name;
            U16 stackCleanupBytes;
        };
        static const ThunkSpec interfaceMethods[] = {
            {"IDirectInput8A::QueryInterface", 12},
            {"IDirectInput8A::AddRef", 4},
            {"IDirectInput8A::Release", 4},
            {"IDirectInput8A::CreateDevice", 16},
            {"IDirectInput8A::EnumDevices", 20},
            {"IDirectInput8A::GetDeviceStatus", 8},
            {"IDirectInput8A::RunControlPanel", 12},
            {"IDirectInput8A::Initialize", 12},
            {"IDirectInput8A::FindDevice", 16},
            {"IDirectInput8A::EnumDevicesBySemantics", 24},
            {"IDirectInput8A::ConfigureDevices", 20},
        };
        static const ThunkSpec deviceMethods[] = {
            {"IDirectInputDevice8A::QueryInterface", 12},
            {"IDirectInputDevice8A::AddRef", 4},
            {"IDirectInputDevice8A::Release", 4},
            {"IDirectInputDevice8A::GetCapabilities", 8},
            {"IDirectInputDevice8A::EnumObjects", 16},
            {"IDirectInputDevice8A::GetProperty", 12},
            {"IDirectInputDevice8A::SetProperty", 12},
            {"IDirectInputDevice8A::Acquire", 4},
            {"IDirectInputDevice8A::Unacquire", 4},
            {"IDirectInputDevice8A::GetDeviceState", 12},
            {"IDirectInputDevice8A::GetDeviceData", 20},
            {"IDirectInputDevice8A::SetDataFormat", 8},
            {"IDirectInputDevice8A::SetEventNotification", 8},
            {"IDirectInputDevice8A::SetCooperativeLevel", 12},
            {"IDirectInputDevice8A::GetObjectInfo", 16},
            {"IDirectInputDevice8A::GetDeviceInfo", 8},
            {"IDirectInputDevice8A::RunControlPanel", 12},
            {"IDirectInputDevice8A::Initialize", 16},
            {"IDirectInputDevice8A::CreateEffect", 20},
            {"IDirectInputDevice8A::EnumEffects", 16},
            {"IDirectInputDevice8A::GetEffectInfo", 12},
            {"IDirectInputDevice8A::GetForceFeedbackState", 8},
            {"IDirectInputDevice8A::SendForceFeedbackCommand", 8},
            {"IDirectInputDevice8A::EnumCreatedEffectObjects", 16},
            {"IDirectInputDevice8A::Escape", 8},
            {"IDirectInputDevice8A::Poll", 4},
            {"IDirectInputDevice8A::SendDeviceData", 16},
            {"IDirectInputDevice8A::EnumEffectsInFile", 20},
            {"IDirectInputDevice8A::WriteEffectToFile", 20},
            {"IDirectInputDevice8A::BuildActionMap", 16},
            {"IDirectInputDevice8A::SetActionMap", 16},
            {"IDirectInputDevice8A::GetImageInfo", 8},
        };

        auto createMethods = [&](const ThunkSpec* methods, U32 count, bool device) {
            std::vector<U32>& vtable =
                device ? directInputDeviceVtable : directInputVtable;
            for (U32 index = 0; index < count; ++index) {
                U32 callbackIndex = SugarbombBridge::registerCallback(
                    "DINPUT8.COM",
                    methods[index].name,
                    callbackDirectInputComMethod);
                U32 guestAddress = 0;
                if (!thunks.createThunk(
                        callbackIndex,
                        methods[index].stackCleanupBytes,
                        guestAddress,
                        error)) {
                    return false;
                }
                DirectInputComMethod method;
                method.device = device;
                method.index = index;
                directInputComMethods[callbackIndex] = method;
                vtable.push_back(guestAddress);
            }
            return true;
        };

        return createMethods(
                   interfaceMethods,
                   sizeof(interfaceMethods) / sizeof(interfaceMethods[0]),
                   false) &&
            createMethods(
                deviceMethods,
                sizeof(deviceMethods) / sizeof(deviceMethods[0]),
                true);
    }

    bool initializeDirectSoundComThunks() {
        struct ThunkSpec {
            const char* name;
            U16 stackCleanupBytes;
        };
        static const ThunkSpec interfaceMethods[] = {
            {"IDirectSound8::QueryInterface", 12},
            {"IDirectSound8::AddRef", 4},
            {"IDirectSound8::Release", 4},
            {"IDirectSound8::CreateSoundBuffer", 16},
            {"IDirectSound8::GetCaps", 8},
            {"IDirectSound8::DuplicateSoundBuffer", 12},
            {"IDirectSound8::SetCooperativeLevel", 12},
            {"IDirectSound8::Compact", 4},
            {"IDirectSound8::GetSpeakerConfig", 8},
            {"IDirectSound8::SetSpeakerConfig", 8},
            {"IDirectSound8::Initialize", 8},
            {"IDirectSound8::VerifyCertification", 8},
        };
        static const ThunkSpec bufferMethods[] = {
            {"IDirectSoundBuffer8::QueryInterface", 12},
            {"IDirectSoundBuffer8::AddRef", 4},
            {"IDirectSoundBuffer8::Release", 4},
            {"IDirectSoundBuffer8::GetCaps", 8},
            {"IDirectSoundBuffer8::GetCurrentPosition", 12},
            {"IDirectSoundBuffer8::GetFormat", 16},
            {"IDirectSoundBuffer8::GetVolume", 8},
            {"IDirectSoundBuffer8::GetPan", 8},
            {"IDirectSoundBuffer8::GetFrequency", 8},
            {"IDirectSoundBuffer8::GetStatus", 8},
            {"IDirectSoundBuffer8::Initialize", 12},
            {"IDirectSoundBuffer8::Lock", 32},
            {"IDirectSoundBuffer8::Play", 16},
            {"IDirectSoundBuffer8::SetCurrentPosition", 8},
            {"IDirectSoundBuffer8::SetFormat", 8},
            {"IDirectSoundBuffer8::SetVolume", 8},
            {"IDirectSoundBuffer8::SetPan", 8},
            {"IDirectSoundBuffer8::SetFrequency", 8},
            {"IDirectSoundBuffer8::Stop", 4},
            {"IDirectSoundBuffer8::Unlock", 20},
            {"IDirectSoundBuffer8::Restore", 4},
            {"IDirectSoundBuffer8::SetFX", 16},
            {"IDirectSoundBuffer8::AcquireResources", 16},
            {"IDirectSoundBuffer8::GetObjectInPath", 20},
        };

        auto createMethods = [&](const ThunkSpec* methods, U32 count, bool buffer) {
            std::vector<U32>& vtable =
                buffer ? directSoundBufferVtable : directSoundVtable;
            for (U32 index = 0; index < count; ++index) {
                U32 callbackIndex = SugarbombBridge::registerCallback(
                    "DSOUND.COM",
                    methods[index].name,
                    callbackDirectSoundComMethod);
                U32 guestAddress = 0;
                if (!thunks.createThunk(
                        callbackIndex,
                        methods[index].stackCleanupBytes,
                        guestAddress,
                        error)) {
                    return false;
                }
                DirectSoundComMethod method;
                method.buffer = buffer;
                method.index = index;
                directSoundComMethods[callbackIndex] = method;
                vtable.push_back(guestAddress);
            }
            return true;
        };

        return createMethods(
                   interfaceMethods,
                   sizeof(interfaceMethods) / sizeof(interfaceMethods[0]),
                   false) &&
            createMethods(
                bufferMethods,
                sizeof(bufferMethods) / sizeof(bufferMethods[0]),
                true);
    }

    bool initializeDirect3DComThunks() {
        struct ThunkSpec {
            const char* name;
            U16 stackCleanupBytes;
        };
        static const ThunkSpec interfaceMethods[] = {
            {"IDirect3D9::QueryInterface", 12},
            {"IDirect3D9::AddRef", 4},
            {"IDirect3D9::Release", 4},
            {"IDirect3D9::RegisterSoftwareDevice", 8},
            {"IDirect3D9::GetAdapterCount", 4},
            {"IDirect3D9::GetAdapterIdentifier", 16},
            {"IDirect3D9::GetAdapterModeCount", 12},
            {"IDirect3D9::EnumAdapterModes", 20},
            {"IDirect3D9::GetAdapterDisplayMode", 12},
            {"IDirect3D9::CheckDeviceType", 24},
            {"IDirect3D9::CheckDeviceFormat", 28},
            {"IDirect3D9::CheckDeviceMultiSampleType", 28},
            {"IDirect3D9::CheckDepthStencilMatch", 24},
            {"IDirect3D9::CheckDeviceFormatConversion", 20},
            {"IDirect3D9::GetDeviceCaps", 16},
            {"IDirect3D9::GetAdapterMonitor", 8},
            {"IDirect3D9::CreateDevice", 28},
        };
        static const ThunkSpec deviceMethods[] = {
            {"IDirect3DDevice9::QueryInterface", 12},
            {"IDirect3DDevice9::AddRef", 4},
            {"IDirect3DDevice9::Release", 4},
            {"IDirect3DDevice9::TestCooperativeLevel", 4},
            {"IDirect3DDevice9::GetAvailableTextureMem", 4},
            {"IDirect3DDevice9::EvictManagedResources", 4},
            {"IDirect3DDevice9::GetDirect3D", 8},
            {"IDirect3DDevice9::GetDeviceCaps", 8},
            {"IDirect3DDevice9::GetDisplayMode", 12},
            {"IDirect3DDevice9::GetCreationParameters", 8},
            {"IDirect3DDevice9::SetCursorProperties", 16},
            {"IDirect3DDevice9::SetCursorPosition", 16},
            {"IDirect3DDevice9::ShowCursor", 8},
            {"IDirect3DDevice9::CreateAdditionalSwapChain", 12},
            {"IDirect3DDevice9::GetSwapChain", 12},
            {"IDirect3DDevice9::GetNumberOfSwapChains", 4},
            {"IDirect3DDevice9::Reset", 8},
            {"IDirect3DDevice9::Present", 20},
            {"IDirect3DDevice9::GetBackBuffer", 20},
            {"IDirect3DDevice9::GetRasterStatus", 12},
            {"IDirect3DDevice9::SetDialogBoxMode", 8},
            {"IDirect3DDevice9::SetGammaRamp", 16},
            {"IDirect3DDevice9::GetGammaRamp", 12},
            {"IDirect3DDevice9::CreateTexture", 36},
            {"IDirect3DDevice9::CreateVolumeTexture", 40},
            {"IDirect3DDevice9::CreateCubeTexture", 32},
            {"IDirect3DDevice9::CreateVertexBuffer", 28},
            {"IDirect3DDevice9::CreateIndexBuffer", 28},
            {"IDirect3DDevice9::CreateRenderTarget", 36},
            {"IDirect3DDevice9::CreateDepthStencilSurface", 36},
            {"IDirect3DDevice9::UpdateSurface", 20},
            {"IDirect3DDevice9::UpdateTexture", 12},
            {"IDirect3DDevice9::GetRenderTargetData", 12},
            {"IDirect3DDevice9::GetFrontBufferData", 12},
            {"IDirect3DDevice9::StretchRect", 24},
            {"IDirect3DDevice9::ColorFill", 16},
            {"IDirect3DDevice9::CreateOffscreenPlainSurface", 28},
            {"IDirect3DDevice9::SetRenderTarget", 12},
            {"IDirect3DDevice9::GetRenderTarget", 12},
            {"IDirect3DDevice9::SetDepthStencilSurface", 8},
            {"IDirect3DDevice9::GetDepthStencilSurface", 8},
            {"IDirect3DDevice9::BeginScene", 4},
            {"IDirect3DDevice9::EndScene", 4},
            {"IDirect3DDevice9::Clear", 28},
            {"IDirect3DDevice9::SetTransform", 12},
            {"IDirect3DDevice9::GetTransform", 12},
            {"IDirect3DDevice9::MultiplyTransform", 12},
            {"IDirect3DDevice9::SetViewport", 8},
            {"IDirect3DDevice9::GetViewport", 8},
            {"IDirect3DDevice9::SetMaterial", 8},
            {"IDirect3DDevice9::GetMaterial", 8},
            {"IDirect3DDevice9::SetLight", 12},
            {"IDirect3DDevice9::GetLight", 12},
            {"IDirect3DDevice9::LightEnable", 12},
            {"IDirect3DDevice9::GetLightEnable", 12},
            {"IDirect3DDevice9::SetClipPlane", 12},
            {"IDirect3DDevice9::GetClipPlane", 12},
            {"IDirect3DDevice9::SetRenderState", 12},
            {"IDirect3DDevice9::GetRenderState", 12},
            {"IDirect3DDevice9::CreateStateBlock", 12},
            {"IDirect3DDevice9::BeginStateBlock", 4},
            {"IDirect3DDevice9::EndStateBlock", 8},
            {"IDirect3DDevice9::SetClipStatus", 8},
            {"IDirect3DDevice9::GetClipStatus", 8},
            {"IDirect3DDevice9::GetTexture", 12},
            {"IDirect3DDevice9::SetTexture", 12},
            {"IDirect3DDevice9::GetTextureStageState", 16},
            {"IDirect3DDevice9::SetTextureStageState", 16},
            {"IDirect3DDevice9::GetSamplerState", 16},
            {"IDirect3DDevice9::SetSamplerState", 16},
            {"IDirect3DDevice9::ValidateDevice", 8},
            {"IDirect3DDevice9::SetPaletteEntries", 12},
            {"IDirect3DDevice9::GetPaletteEntries", 12},
            {"IDirect3DDevice9::SetCurrentTexturePalette", 8},
            {"IDirect3DDevice9::GetCurrentTexturePalette", 8},
            {"IDirect3DDevice9::SetScissorRect", 8},
            {"IDirect3DDevice9::GetScissorRect", 8},
            {"IDirect3DDevice9::SetSoftwareVertexProcessing", 8},
            {"IDirect3DDevice9::GetSoftwareVertexProcessing", 4},
            {"IDirect3DDevice9::SetNPatchMode", 8},
            {"IDirect3DDevice9::GetNPatchMode", 4},
            {"IDirect3DDevice9::DrawPrimitive", 16},
            {"IDirect3DDevice9::DrawIndexedPrimitive", 28},
            {"IDirect3DDevice9::DrawPrimitiveUP", 20},
            {"IDirect3DDevice9::DrawIndexedPrimitiveUP", 36},
            {"IDirect3DDevice9::ProcessVertices", 28},
            {"IDirect3DDevice9::CreateVertexDeclaration", 12},
            {"IDirect3DDevice9::SetVertexDeclaration", 8},
            {"IDirect3DDevice9::GetVertexDeclaration", 8},
            {"IDirect3DDevice9::SetFVF", 8},
            {"IDirect3DDevice9::GetFVF", 8},
            {"IDirect3DDevice9::CreateVertexShader", 12},
            {"IDirect3DDevice9::SetVertexShader", 8},
            {"IDirect3DDevice9::GetVertexShader", 8},
            {"IDirect3DDevice9::SetVertexShaderConstantF", 16},
            {"IDirect3DDevice9::GetVertexShaderConstantF", 16},
            {"IDirect3DDevice9::SetVertexShaderConstantI", 16},
            {"IDirect3DDevice9::GetVertexShaderConstantI", 16},
            {"IDirect3DDevice9::SetVertexShaderConstantB", 16},
            {"IDirect3DDevice9::GetVertexShaderConstantB", 16},
            {"IDirect3DDevice9::SetStreamSource", 20},
            {"IDirect3DDevice9::GetStreamSource", 20},
            {"IDirect3DDevice9::SetStreamSourceFreq", 12},
            {"IDirect3DDevice9::GetStreamSourceFreq", 12},
            {"IDirect3DDevice9::SetIndices", 8},
            {"IDirect3DDevice9::GetIndices", 8},
            {"IDirect3DDevice9::CreatePixelShader", 12},
            {"IDirect3DDevice9::SetPixelShader", 8},
            {"IDirect3DDevice9::GetPixelShader", 8},
            {"IDirect3DDevice9::SetPixelShaderConstantF", 16},
            {"IDirect3DDevice9::GetPixelShaderConstantF", 16},
            {"IDirect3DDevice9::SetPixelShaderConstantI", 16},
            {"IDirect3DDevice9::GetPixelShaderConstantI", 16},
            {"IDirect3DDevice9::SetPixelShaderConstantB", 16},
            {"IDirect3DDevice9::GetPixelShaderConstantB", 16},
            {"IDirect3DDevice9::DrawRectPatch", 16},
            {"IDirect3DDevice9::DrawTriPatch", 16},
            {"IDirect3DDevice9::DeletePatch", 8},
            {"IDirect3DDevice9::CreateQuery", 12},
        };
        static const ThunkSpec surfaceMethods[] = {
            {"IDirect3DSurface9::QueryInterface", 12},
            {"IDirect3DSurface9::AddRef", 4},
            {"IDirect3DSurface9::Release", 4},
            {"IDirect3DSurface9::GetDevice", 8},
            {"IDirect3DSurface9::SetPrivateData", 20},
            {"IDirect3DSurface9::GetPrivateData", 16},
            {"IDirect3DSurface9::FreePrivateData", 8},
            {"IDirect3DSurface9::SetPriority", 8},
            {"IDirect3DSurface9::GetPriority", 4},
            {"IDirect3DSurface9::PreLoad", 4},
            {"IDirect3DSurface9::GetType", 4},
            {"IDirect3DSurface9::GetContainer", 12},
            {"IDirect3DSurface9::GetDesc", 8},
            {"IDirect3DSurface9::LockRect", 16},
            {"IDirect3DSurface9::UnlockRect", 4},
            {"IDirect3DSurface9::GetDC", 8},
            {"IDirect3DSurface9::ReleaseDC", 8},
        };
        static const ThunkSpec textureMethods[] = {
            {"IDirect3DTexture9::QueryInterface", 12},
            {"IDirect3DTexture9::AddRef", 4},
            {"IDirect3DTexture9::Release", 4},
            {"IDirect3DTexture9::GetDevice", 8},
            {"IDirect3DTexture9::SetPrivateData", 20},
            {"IDirect3DTexture9::GetPrivateData", 16},
            {"IDirect3DTexture9::FreePrivateData", 8},
            {"IDirect3DTexture9::SetPriority", 8},
            {"IDirect3DTexture9::GetPriority", 4},
            {"IDirect3DTexture9::PreLoad", 4},
            {"IDirect3DTexture9::GetType", 4},
            {"IDirect3DTexture9::SetLOD", 8},
            {"IDirect3DTexture9::GetLOD", 4},
            {"IDirect3DTexture9::GetLevelCount", 4},
            {"IDirect3DTexture9::SetAutoGenFilterType", 8},
            {"IDirect3DTexture9::GetAutoGenFilterType", 4},
            {"IDirect3DTexture9::GenerateMipSubLevels", 4},
            {"IDirect3DTexture9::GetLevelDesc", 12},
            {"IDirect3DTexture9::GetSurfaceLevel", 12},
            {"IDirect3DTexture9::LockRect", 20},
            {"IDirect3DTexture9::UnlockRect", 8},
            {"IDirect3DTexture9::AddDirtyRect", 8},
        };
        static const ThunkSpec cubeTextureMethods[] = {
            {"IDirect3DCubeTexture9::QueryInterface", 12},
            {"IDirect3DCubeTexture9::AddRef", 4},
            {"IDirect3DCubeTexture9::Release", 4},
            {"IDirect3DCubeTexture9::GetDevice", 8},
            {"IDirect3DCubeTexture9::SetPrivateData", 20},
            {"IDirect3DCubeTexture9::GetPrivateData", 16},
            {"IDirect3DCubeTexture9::FreePrivateData", 8},
            {"IDirect3DCubeTexture9::SetPriority", 8},
            {"IDirect3DCubeTexture9::GetPriority", 4},
            {"IDirect3DCubeTexture9::PreLoad", 4},
            {"IDirect3DCubeTexture9::GetType", 4},
            {"IDirect3DCubeTexture9::SetLOD", 8},
            {"IDirect3DCubeTexture9::GetLOD", 4},
            {"IDirect3DCubeTexture9::GetLevelCount", 4},
            {"IDirect3DCubeTexture9::SetAutoGenFilterType", 8},
            {"IDirect3DCubeTexture9::GetAutoGenFilterType", 4},
            {"IDirect3DCubeTexture9::GenerateMipSubLevels", 4},
            {"IDirect3DCubeTexture9::GetLevelDesc", 12},
            {"IDirect3DCubeTexture9::GetCubeMapSurface", 16},
            {"IDirect3DCubeTexture9::LockRect", 24},
            {"IDirect3DCubeTexture9::UnlockRect", 12},
            {"IDirect3DCubeTexture9::AddDirtyRect", 12},
        };
        static const ThunkSpec bufferMethods[] = {
            {"IDirect3DBuffer9::QueryInterface", 12},
            {"IDirect3DBuffer9::AddRef", 4},
            {"IDirect3DBuffer9::Release", 4},
            {"IDirect3DBuffer9::GetDevice", 8},
            {"IDirect3DBuffer9::SetPrivateData", 20},
            {"IDirect3DBuffer9::GetPrivateData", 16},
            {"IDirect3DBuffer9::FreePrivateData", 8},
            {"IDirect3DBuffer9::SetPriority", 8},
            {"IDirect3DBuffer9::GetPriority", 4},
            {"IDirect3DBuffer9::PreLoad", 4},
            {"IDirect3DBuffer9::GetType", 4},
            {"IDirect3DBuffer9::Lock", 20},
            {"IDirect3DBuffer9::Unlock", 4},
            {"IDirect3DBuffer9::GetDesc", 8},
        };
        static const ThunkSpec declarationMethods[] = {
            {"IDirect3DVertexDeclaration9::QueryInterface", 12},
            {"IDirect3DVertexDeclaration9::AddRef", 4},
            {"IDirect3DVertexDeclaration9::Release", 4},
            {"IDirect3DVertexDeclaration9::GetDevice", 8},
            {"IDirect3DVertexDeclaration9::GetDeclaration", 12},
        };
        static const ThunkSpec shaderMethods[] = {
            {"IDirect3DShader9::QueryInterface", 12},
            {"IDirect3DShader9::AddRef", 4},
            {"IDirect3DShader9::Release", 4},
            {"IDirect3DShader9::GetDevice", 8},
            {"IDirect3DShader9::GetFunction", 12},
        };
        static const ThunkSpec stateBlockMethods[] = {
            {"IDirect3DStateBlock9::QueryInterface", 12},
            {"IDirect3DStateBlock9::AddRef", 4},
            {"IDirect3DStateBlock9::Release", 4},
            {"IDirect3DStateBlock9::GetDevice", 8},
            {"IDirect3DStateBlock9::Capture", 4},
            {"IDirect3DStateBlock9::Apply", 4},
        };
        static const ThunkSpec queryMethods[] = {
            {"IDirect3DQuery9::QueryInterface", 12},
            {"IDirect3DQuery9::AddRef", 4},
            {"IDirect3DQuery9::Release", 4},
            {"IDirect3DQuery9::GetDevice", 8},
            {"IDirect3DQuery9::GetType", 4},
            {"IDirect3DQuery9::GetDataSize", 4},
            {"IDirect3DQuery9::Issue", 8},
            {"IDirect3DQuery9::GetData", 16},
        };

        U32 createCallback = SugarbombBridge::registerCallback(
            "D3D9",
            "Direct3DCreate9",
            callbackDirect3DCreate9);
        if (!thunks.createThunk(
                createCallback,
                4,
                direct3DCreate9Thunk,
                error)) {
            return false;
        }

        auto createMethods = [&](const ThunkSpec* methods, U32 count, bool device) {
            std::vector<U32>& vtable = device ? direct3DDeviceVtable : direct3DVtable;
            for (U32 index = 0; index < count; ++index) {
                U32 callbackIndex = SugarbombBridge::registerCallback(
                    "D3D9.COM",
                    methods[index].name,
                    callbackDirect3DComMethod);
                U32 guestAddress = 0;
                if (!thunks.createThunk(
                        callbackIndex,
                        methods[index].stackCleanupBytes,
                        guestAddress,
                        error)) {
                    return false;
                }
                Direct3DComMethod method;
                method.device = device;
                method.index = index;
                direct3DComMethods[callbackIndex] = method;
                vtable.push_back(guestAddress);
            }
            return true;
        };

        if (!createMethods(
                interfaceMethods,
                sizeof(interfaceMethods) / sizeof(interfaceMethods[0]),
                false) ||
            !createMethods(
                deviceMethods,
                sizeof(deviceMethods) / sizeof(deviceMethods[0]),
                true)) {
            return false;
        }
        for (U32 index = 0;
             index < sizeof(surfaceMethods) / sizeof(surfaceMethods[0]);
             ++index) {
            U32 callbackIndex = SugarbombBridge::registerCallback(
                "D3D9.COM",
                surfaceMethods[index].name,
                callbackDirect3DSurfaceMethod);
            U32 guestAddress = 0;
            if (!thunks.createThunk(
                    callbackIndex,
                    surfaceMethods[index].stackCleanupBytes,
                    guestAddress,
                    error)) {
                return false;
            }
            direct3DSurfaceMethods[callbackIndex] = index;
            direct3DSurfaceVtable.push_back(guestAddress);
        }
        auto createResourceMethods = [&](
            const ThunkSpec* methods,
            U32 count,
            Direct3DResourceKind kind) {
            std::vector<U32>& vtable =
                direct3DResourceVtables[static_cast<U32>(kind)];
            for (U32 index = 0; index < count; ++index) {
                U32 callbackIndex = SugarbombBridge::registerCallback(
                    "D3D9.COM",
                    methods[index].name,
                    callbackDirect3DResourceMethod);
                U32 guestAddress = 0;
                if (!thunks.createThunk(
                        callbackIndex,
                        methods[index].stackCleanupBytes,
                        guestAddress,
                        error)) {
                    return false;
                }
                Direct3DResourceMethod method;
                method.kind = kind;
                method.index = index;
                direct3DResourceMethods[callbackIndex] = method;
                vtable.push_back(guestAddress);
            }
            return true;
        };
        return createResourceMethods(
                   textureMethods,
                   sizeof(textureMethods) / sizeof(textureMethods[0]),
                   Direct3DResourceKind::Texture) &&
            createResourceMethods(
                cubeTextureMethods,
                sizeof(cubeTextureMethods) / sizeof(cubeTextureMethods[0]),
                Direct3DResourceKind::CubeTexture) &&
            createResourceMethods(
                bufferMethods,
                sizeof(bufferMethods) / sizeof(bufferMethods[0]),
                Direct3DResourceKind::Buffer) &&
            createResourceMethods(
                declarationMethods,
                sizeof(declarationMethods) / sizeof(declarationMethods[0]),
                Direct3DResourceKind::Declaration) &&
            createResourceMethods(
                shaderMethods,
                sizeof(shaderMethods) / sizeof(shaderMethods[0]),
                Direct3DResourceKind::Shader) &&
            createResourceMethods(
                stateBlockMethods,
                sizeof(stateBlockMethods) / sizeof(stateBlockMethods[0]),
                Direct3DResourceKind::StateBlock) &&
            createResourceMethods(
                queryMethods,
                sizeof(queryMethods) / sizeof(queryMethods[0]),
                Direct3DResourceKind::Query);
    }

    bool appendStaticTlsTemplate(const Pe32MappedImage& mapped) {
        if (!mapped.info.tlsDirectoryRva ||
            mapped.info.tlsDirectorySize < 24) {
            return true;
        }
        if (nextTlsIndex >= 64) {
            error = "PE static TLS module count exceeds the guest TLS array";
            return false;
        }
        U32 directory =
            mapped.loadBase + mapped.info.tlsDirectoryRva;
        if (!memory->canRead(directory, 24)) {
            error = "PE TLS directory is outside the mapped module";
            return false;
        }
        U32 rawStart = memory->readd(directory + 0);
        U32 rawEnd = memory->readd(directory + 4);
        U32 indexAddress = memory->readd(directory + 8);
        U32 callbacksAddress = memory->readd(directory + 12);
        U32 zeroFillSize = memory->readd(directory + 16);
        if (rawEnd < rawStart) {
            error = "PE TLS raw-data range is invalid";
            return false;
        }
        U32 rawSize = rawEnd - rawStart;
        U64 totalSize = static_cast<U64>(rawSize) + zeroFillSize;
        constexpr U32 MAX_STATIC_TLS_BYTES = 64 * 1024 * 1024;
        if (!indexAddress ||
            !memory->canWrite(indexAddress, 4) ||
            totalSize > MAX_STATIC_TLS_BYTES ||
            (rawSize && !memory->canRead(rawStart, rawSize))) {
            error = "PE TLS template is invalid or too large";
            return false;
        }

        StaticTlsTemplate tls;
        tls.moduleBase = mapped.loadBase;
        tls.slot = nextTlsIndex++;
        tls.rawStart = rawStart;
        tls.rawSize = rawSize;
        tls.zeroFillSize = zeroFillSize;
        memory->writed(indexAddress, tls.slot);

        if (callbacksAddress) {
            for (U32 index = 0; index < 1024; ++index) {
                U32 entryAddress = callbacksAddress + index * 4;
                if (!memory->canRead(entryAddress, 4)) {
                    error = "PE TLS callback array is outside the module";
                    return false;
                }
                U32 callback = memory->readd(entryAddress);
                if (!callback) {
                    break;
                }
                if (!memory->canRead(callback, 1)) {
                    error = "PE TLS callback points outside guest code";
                    return false;
                }
                tls.callbacks.push_back(callback);
                if (index == 1023) {
                    error = "PE TLS callback array is not terminated";
                    return false;
                }
            }
        }
        printf(
            "Sugarbomb Win32 loader: registered static TLS slot %u "
            "for module 0x%08X (%u template bytes, %u zero-fill "
            "bytes, %zu callbacks)\n",
            tls.slot,
            tls.moduleBase,
            tls.rawSize,
            tls.zeroFillSize,
            tls.callbacks.size());
        staticTlsTemplates.push_back(std::move(tls));
        return true;
    }

    bool initializeThreadStaticTlsTemplate(
        GuestThreadState& state,
        const StaticTlsTemplate& tls) {
        U32 totalSize = tls.rawSize + tls.zeroFillSize;
        U32 block = allocateGuestHeap(totalSize, true);
        if (!block) {
            error = "Unable to allocate a guest static TLS block";
            return false;
        }
        if (tls.rawSize) {
            memory->memcpy(block, tls.rawStart, tls.rawSize);
        }
        memory->writed(
            state.tlsArray + tls.slot * sizeof(U32),
            block);
        state.staticTlsBlocks.push_back(block);
        return true;
    }

    bool initializeThreadStaticTls(GuestThreadState& state) {
        if (!state.tlsArray ||
            !memory->canWrite(state.tlsArray, 64 * sizeof(U32))) {
            error = "Guest thread TLS array is invalid";
            return false;
        }
        memory->memset(state.tlsArray, 0, 64 * sizeof(U32));
        for (const StaticTlsTemplate& tls : staticTlsTemplates) {
            if (!initializeThreadStaticTlsTemplate(state, tls)) {
                return false;
            }
        }
        return true;
    }

    bool initializeStaticTlsModules() {
        staticTlsTemplates.clear();
        nextTlsIndex = 0;
        if (!appendStaticTlsTemplate(image)) {
            return false;
        }
        for (U32 moduleHandle : guestModuleLoadOrder) {
            auto found = guestModules.find(moduleHandle);
            if (found != guestModules.end() &&
                !appendStaticTlsTemplate(found->second.image)) {
                return false;
            }
        }
        GuestThreadState* mainState = findGuestThread(thread->id);
        if (!mainState ||
            !initializeThreadStaticTls(*mainState)) {
            return false;
        }
        staticTlsInitialized = true;
        return true;
    }

    bool scheduleGuestModuleInitializer(CPU* guestCpu) {
        if (guestModuleInitializerIndex >=
            guestModuleInitializers.size()) {
            initializeCpu();
            printf(
                "Sugarbomb Win32 loader: guest module initialization "
                "completed; transferring to Fallout entry 0x%08X\n",
                image.entryPoint);
            return true;
        }
        const GuestModuleInitializer& initializer =
            guestModuleInitializers[guestModuleInitializerIndex];
        constexpr U32 INITIALIZER_FRAME_BYTES = 16;
        U32 stackPointer = STACK_TOP - INITIALIZER_FRAME_BYTES;
        if (!initializer.address ||
            !memory->canRead(initializer.address, 1) ||
            !memory->canWrite(
                stackPointer,
                INITIALIZER_FRAME_BYTES)) {
            error = "Guest module initializer or stack frame is invalid";
            return false;
        }
        memory->writed(
            stackPointer,
            moduleInitializerReturnThunk);
        memory->writed(stackPointer + 4, initializer.moduleBase);
        memory->writed(stackPointer + 8, 1); // DLL_PROCESS_ATTACH
        memory->writed(stackPointer + 12, 0);
        guestCpu->reg[4].u32 = stackPointer;
        guestCpu->eip.u32 = initializer.address;
        guestCpu->nextOp = nullptr;
        printf(
            "Sugarbomb Win32 loader: calling %s at 0x%08X "
            "(module=0x%08X, reason=DLL_PROCESS_ATTACH)\n",
            initializer.label.c_str(),
            initializer.address,
            initializer.moduleBase);
        return true;
    }

    bool prepareBundledNvseInitialization() {
        const char* configured =
            std::getenv("SUGARBOMB_RUN_NVSE_ENTRY");
        if (!configured ||
            !*configured ||
            std::strcmp(configured, "0") == 0) {
            return true;
        }
        U32 moduleBase = guestModuleHandle("nvse_1_4.dll");
        auto module = guestModules.find(moduleBase);
        if (!moduleBase || module == guestModules.end()) {
            error =
                "SUGARBOMB_RUN_NVSE_ENTRY requested but nvse_1_4.dll "
                "was not staged";
            return false;
        }

        guestModuleInitializers.clear();
        guestModuleInitializerIndex = 0;
        const StaticTlsTemplate* tls = nullptr;
        for (const StaticTlsTemplate& candidate :
             staticTlsTemplates) {
            if (candidate.moduleBase == moduleBase) {
                tls = &candidate;
                break;
            }
        }
        if (tls) {
            for (std::size_t index = 0;
                 index < tls->callbacks.size();
                 ++index) {
                GuestModuleInitializer initializer;
                initializer.address = tls->callbacks[index];
                initializer.moduleBase = moduleBase;
                initializer.label =
                    "nvse_1_4.dll TLS callback #" +
                    std::to_string(index + 1);
                guestModuleInitializers.push_back(
                    std::move(initializer));
            }
        }
        if (module->second.image.info.entryPointRva) {
            GuestModuleInitializer initializer;
            initializer.address =
                module->second.image.entryPoint;
            initializer.moduleBase = moduleBase;
            initializer.requireSuccess = true;
            initializer.marksModuleInitialized = true;
            initializer.label =
                "nvse_1_4.dll PE entry point";
            guestModuleInitializers.push_back(
                std::move(initializer));
        }
        if (guestModuleInitializers.empty()) {
            error = "nvse_1_4.dll has no TLS callbacks or PE entry point";
            return false;
        }
        printf(
            "Sugarbomb NVSE: diagnostic initialization enabled; "
            "queued %zu TLS/entry initializer(s)\n",
            guestModuleInitializers.size());
        return scheduleGuestModuleInitializer(cpu);
    }

    void completeGuestModuleInitializer(CPU* guestCpu) {
        if (guestModuleInitializerIndex >=
            guestModuleInitializers.size()) {
            fprintf(
                stderr,
                "Sugarbomb Win32 loader: initializer return without "
                "a pending initializer\n");
            runtimeStopping = true;
            guestCpu->thread->terminating = true;
            return;
        }
        GuestModuleInitializer initializer =
            guestModuleInitializers[guestModuleInitializerIndex];
        U32 result = guestCpu->reg[0].u32;
        printf(
            "Sugarbomb Win32 loader: %s returned EAX=0x%08X\n",
            initializer.label.c_str(),
            result);
        if (initializer.requireSuccess && !result) {
            fprintf(
                stderr,
                "Sugarbomb Win32 loader: %s rejected "
                "DLL_PROCESS_ATTACH\n",
                initializer.label.c_str());
            runtimeStopping = true;
            guestCpu->thread->terminating = true;
            return;
        }
        if (initializer.marksModuleInitialized) {
            auto module =
                guestModules.find(initializer.moduleBase);
            if (module != guestModules.end()) {
                module->second.initialized = true;
            }
        }
        ++guestModuleInitializerIndex;
        if (!scheduleGuestModuleInitializer(guestCpu)) {
            fprintf(
                stderr,
                "Sugarbomb Win32 loader: could not schedule the next "
                "guest module initializer: %s\n",
                error.c_str());
            runtimeStopping = true;
            guestCpu->thread->terminating = true;
        }
    }

    bool scheduleNextGuestFunction(CPU* guestCpu) {
        U32 threadId = guestCpu->thread->id;
        auto found = pendingGuestFunctionArrays.find(threadId);
        if (found == pendingGuestFunctionArrays.end() ||
            found->second.empty()) {
            error =
                "No pending guest function array for the current thread";
            return false;
        }
        PendingGuestFunctionArray& pending =
            found->second.back();
        if (pending.nextIndex >= pending.functions.size()) {
            return finishGuestFunctionArray(guestCpu, 0);
        }
        U32 function =
            pending.functions[pending.nextIndex++];
        U32 stackPointer =
            pending.nativeThunkStackPointer;
        U32 returnStackPointer =
            (stackPointer & guestCpu->stackNotMask) |
            ((stackPointer - sizeof(U32)) &
             guestCpu->stackMask);
        U32 returnAddress =
            guestCpu->seg[SS].address +
            (returnStackPointer & guestCpu->stackMask);
        if (!memory->canWrite(returnAddress, sizeof(U32))) {
            error =
                "Guest function-array return frame is outside the stack";
            return false;
        }
        guestCpu->reg[4].u32 = stackPointer;
        guestCpu->push32(guestFunctionArrayReturnThunk);
        guestCpu->eip.u32 = function;
        guestCpu->nextOp = nullptr;
        if (++guestFunctionArrayDispatchTraceCount <= 64) {
            printf(
                "Sugarbomb Win32 loader: %s calling guest "
                "function 0x%08X (%zu/%zu)\n",
                pending.label.c_str(),
                function,
                pending.nextIndex,
                pending.functions.size());
        }
        return true;
    }

    bool finishGuestFunctionArray(
        CPU* guestCpu,
        U32 result) {
        U32 threadId = guestCpu->thread->id;
        auto found = pendingGuestFunctionArrays.find(threadId);
        if (found == pendingGuestFunctionArrays.end() ||
            found->second.empty()) {
            error =
                "Guest function-array completion has no pending frame";
            return false;
        }
        PendingGuestFunctionArray pending =
            std::move(found->second.back());
        found->second.pop_back();
        if (found->second.empty()) {
            pendingGuestFunctionArrays.erase(found);
        }
        guestCpu->reg[4].u32 =
            pending.nativeThunkStackPointer;
        guestCpu->eip.u32 =
            pending.nativeThunkResumeEip;
        guestCpu->reg[0].u32 = result;
        guestCpu->nextOp = nullptr;
        printf(
            "Sugarbomb Win32 loader: %s completed with "
            "result 0x%08X\n",
            pending.label.c_str(),
            result);
        return true;
    }

    bool beginGuestFunctionArray(
        CPU* guestCpu,
        U32 first,
        U32 last,
        bool stopOnFailure,
        const char* label) {
        constexpr U32 MAX_FUNCTION_ARRAY_BYTES =
            4 * 1024 * 1024;
        if (last < first ||
            ((last - first) & (sizeof(U32) - 1)) ||
            last - first > MAX_FUNCTION_ARRAY_BYTES ||
            (last != first &&
             !memory->canRead(first, last - first))) {
            error = std::string(label) +
                " received an invalid function-pointer range";
            return false;
        }

        PendingGuestFunctionArray pending;
        pending.nativeThunkStackPointer =
            guestCpu->reg[4].u32;
        pending.nativeThunkResumeEip =
            guestCpu->eip.u32 + 2;
        pending.stopOnFailure = stopOnFailure;
        pending.label = label;
        for (U32 entry = first;
             entry < last;
             entry += sizeof(U32)) {
            U32 function = memory->readd(entry);
            if (!function) {
                continue;
            }
            if (!memory->canRead(function, 1)) {
                error = std::string(label) +
                    " contains a function pointer outside guest code";
                return false;
            }
            pending.functions.push_back(function);
        }
        if (pending.functions.empty()) {
            guestCpu->reg[0].u32 = 0;
            printf(
                "Sugarbomb Win32 loader: %s contained no "
                "guest functions\n",
                label);
            return true;
        }
        pendingGuestFunctionArrays[guestCpu->thread->id]
            .push_back(std::move(pending));
        return scheduleNextGuestFunction(guestCpu);
    }

    void completeGuestFunctionArray(CPU* guestCpu) {
        U32 threadId = guestCpu->thread->id;
        auto found = pendingGuestFunctionArrays.find(threadId);
        if (found == pendingGuestFunctionArrays.end() ||
            found->second.empty()) {
            fprintf(
                stderr,
                "Sugarbomb Win32 loader: guest function return "
                "without a pending array on thread %u\n",
                threadId);
            runtimeStopping = true;
            guestCpu->thread->terminating = true;
            return;
        }
        U32 result = guestCpu->reg[0].u32;
        PendingGuestFunctionArray& pending =
            found->second.back();
        if (pending.stopOnFailure && result) {
            if (!finishGuestFunctionArray(guestCpu, result)) {
                runtimeStopping = true;
                guestCpu->thread->terminating = true;
            }
            return;
        }
        if (!scheduleNextGuestFunction(guestCpu)) {
            fprintf(
                stderr,
                "Sugarbomb Win32 loader: could not continue "
                "guest function array: %s\n",
                error.c_str());
            runtimeStopping = true;
            guestCpu->thread->terminating = true;
        }
    }

    bool execute() {
        printf("Sugarbomb: entering FalloutNV.exe as an x86 guest in the %zu-bit host\n", sizeof(void*) * 8);
        U64 runSliceLimit = std::numeric_limits<U64>::max();
        if (const char* configuredLimit = std::getenv("SUGARBOMB_MAX_RUN_SLICES")) {
            char* end = nullptr;
            unsigned long long parsed = std::strtoull(configuredLimit, &end, 10);
            if (end != configuredLimit &&
                !*end &&
                parsed > 0) {
                runSliceLimit = static_cast<U64>(parsed);
                printf(
                    "Sugarbomb: diagnostic execution budget set to %llu CPU slices\n",
                    static_cast<unsigned long long>(runSliceLimit));
            }
        }
        U64 runDeadline = std::numeric_limits<U64>::max();
        if (const char* configuredMilliseconds =
                std::getenv("SUGARBOMB_MAX_RUN_MILLISECONDS")) {
            char* end = nullptr;
            unsigned long long parsed =
                std::strtoull(configuredMilliseconds, &end, 10);
            if (end != configuredMilliseconds &&
                !*end &&
                parsed > 0 &&
                parsed <= 24ULL * 60 * 60 * 1000) {
                runDeadline =
                    KSystem::getMicroCounter() + parsed * 1000;
                printf(
                    "Sugarbomb: diagnostic wall-clock budget set to %llu ms\n",
                    parsed);
            }
        }
        std::size_t cursor = 0;
        bool wallClockBudgetExhausted = false;
        while (!runtimeStopping && runSlices < runSliceLimit) {
            if ((runSlices & 0x7ff) == 0) {
                pumpHostMessages();
            }
            if (KSystem::getMicroCounter() >= runDeadline) {
                wallClockBudgetExhausted = true;
                break;
            }
            refreshWaitingGuestThreads();
            GuestThreadState* runnable = nextRunnableGuestThread(cursor);
            if (!runnable) {
                U64 earliestDeadline = std::numeric_limits<U64>::max();
                bool pendingWait = false;
                bool pendingSuspendedThread = false;
                for (const auto& state : guestThreads) {
                    if (state->completed || !state->thread || state->thread->terminating) {
                        continue;
                    }
                    if (state->waitKind != GuestWaitKind::None) {
                        pendingWait = true;
                        earliestDeadline = std::min(earliestDeadline, state->waitDeadline);
                    } else if (state->suspendCount) {
                        pendingSuspendedThread = true;
                    }
                }
                if (pendingWait && earliestDeadline != std::numeric_limits<U64>::max()) {
                    KNativeThread::sleep(1);
                    continue;
                }
                if (pendingWait || pendingSuspendedThread) {
                    fprintf(
                        stderr,
                        "Sugarbomb scheduler deadlock: no runnable guest thread (%s)\n",
                        pendingWait ? "only infinite waits remain" : "only suspended threads remain");
                    return false;
                }
                break;
            }
            for (U32 slice = 0;
                 slice < GUEST_THREAD_QUANTUM_SLICES &&
                 runSlices < runSliceLimit;
                 ++slice) {
                runGuestThreadSlice(*runnable);
                if (runtimeStopping ||
                    runnable->completed ||
                    runnable->suspendCount ||
                    runnable->waitKind != GuestWaitKind::None ||
                    !runnable->thread ||
                    runnable->thread->terminating) {
                    break;
                }
            }
        }
        if (runSlices == runSliceLimit || wallClockBudgetExhausted) {
            fprintf(
                stderr,
                "Sugarbomb stopped after the diagnostic %s budget was exhausted "
                "(%llu slices, %u native API calls)\n",
                wallClockBudgetExhausted ? "wall-clock" : "execution",
                static_cast<unsigned long long>(runSlices),
                nativeCallCount);
            for (const auto& state : guestThreads) {
                if (!state->thread) {
                    continue;
                }
                fprintf(
                    stderr,
                    "  tid %u %-24s EIP=0x%08X wait=%u suspend=%u completed=%u\n",
                    state->thread->id,
                    state->name.empty() ? "<unnamed>" : state->name.c_str(),
                    state->thread->cpu->getEipAddress(),
                    static_cast<U32>(state->waitKind),
                    state->suspendCount,
                    state->completed ? 1 : 0);
                printGuestCpuDetails(*state);
                printGuestWaitDetails(*state);
            }
            std::vector<std::pair<std::string, U32>> busiestApis(
                nativeApiCounts.begin(),
                nativeApiCounts.end());
            std::sort(
                busiestApis.begin(),
                busiestApis.end(),
                [](const auto& left, const auto& right) {
                    return left.second > right.second;
                });
            fprintf(stderr, "  busiest native APIs:\n");
            for (U32 index = 0;
                 index < busiestApis.size() && index < 32;
                 ++index) {
                fprintf(
                    stderr,
                    "    %10u  %s\n",
                    busiestApis[index].second,
                    busiestApis[index].first.c_str());
            }
            static const char* graphicsMilestones[] = {
                "D3D9!IDirect3DDevice9::BeginScene",
                "D3D9!IDirect3DDevice9::EndScene",
                "D3D9!IDirect3DDevice9::Present",
                "D3D9!IDirect3DDevice9::Clear",
                "D3D9!IDirect3DDevice9::SetRenderTarget",
                "D3D9!IDirect3DDevice9::DrawPrimitive",
                "D3D9!IDirect3DDevice9::DrawIndexedPrimitive",
                "D3D9!IDirect3DDevice9::StretchRect",
                "D3D9!IDirect3DDevice9::UpdateSurface",
                "D3D9!IDirect3DDevice9::UpdateTexture",
                "D3DX9!D3DXLoadSurfaceFromSurface",
                "D3DX9!D3DXCreateTextureFromFileInMemory",
                "D3DX9!D3DXCreateCubeTextureFromFileInMemory",
            };
            fprintf(stderr, "  graphics API milestones:\n");
            for (const char* milestone : graphicsMilestones) {
                auto count = nativeApiCounts.find(milestone);
                fprintf(
                    stderr,
                    "    %10u  %s\n",
                    count == nativeApiCounts.end() ? 0 : count->second,
                    milestone);
            }
            static const char* messageAndMediaMilestones[] = {
                "USER32!PeekMessageA",
                "USER32!DispatchMessageA",
                "USER32!SendMessageA",
                "USER32!GetAsyncKeyState",
                "SUGARBOMB!GuestWndProcReturn",
                "DINPUT8!IDirectInputDevice8A::Acquire",
                "DINPUT8!IDirectInputDevice8A::GetDeviceState",
                "DINPUT8!IDirectInputDevice8A::GetDeviceData",
                "BINKW32!BinkOpen",
                "BINKW32!BinkWait",
                "BINKW32!BinkDoFrame",
                "BINKW32!BinkNextFrame",
                "BINKW32!BinkCopyToBufferRect",
                "BINKW32!BinkClose",
                "DIRECTSHOW!IMediaPosition::get_CurrentPosition",
                "DIRECTSHOW!IMediaEvent::GetEvent",
            };
            fprintf(stderr, "  message/media API milestones:\n");
            for (const char* milestone : messageAndMediaMilestones) {
                auto count = nativeApiCounts.find(milestone);
                fprintf(
                    stderr,
                    "    %10u  %s\n",
                    count == nativeApiCounts.end() ? 0 : count->second,
                    milestone);
            }
            return false;
        }
        printf(
            "Sugarbomb: guest stopped after %llu CPU slices and %u native API calls at EIP=0x%08X\n",
            static_cast<unsigned long long>(runSlices),
            nativeCallCount,
            lastGuestEip);
        return true;
    }

    void cleanup() {
        shutdownHostWindow();
        if (process) {
            KThread::setCurrentThread(nullptr);
            for (auto& state : guestThreads) {
                if (state->thread && state->thread != thread) {
                    process->deleteThread(state->thread);
                    state->thread = nullptr;
                }
            }
            if (thread) {
                process->deleteThread(thread);
                thread = nullptr;
            }
        }
        guestThreads.clear();
        cpu = nullptr;
        activeCpu = nullptr;
        memory = nullptr;
        process.reset();
    }

    bool mapRegion(U32 base, U32 size, U32 protection, const char* description) {
        if (memory->mmap(
                thread,
                base,
                size,
                protection,
                K_MAP_FIXED | K_MAP_PRIVATE | K_MAP_ANONYMOUS,
                -1,
                0) != base) {
            error = std::string("Unable to map ") + description;
            return false;
        }
        return true;
    }

    std::string guestModuleKey(const std::string& name) const {
        std::string key =
            std::filesystem::path(name).filename().string();
        if (std::filesystem::path(key).extension().empty()) {
            key += ".dll";
        }
        return lowerAscii(key);
    }

    bool guestRangeIsFree(U32 base, U32 size) const {
        if (!base || !size ||
            static_cast<U64>(base) + size >
                std::numeric_limits<U32>::max()) {
            return false;
        }
        U32 firstPage = base >> K_PAGE_SHIFT;
        U32 lastPage =
            static_cast<U32>(
                (static_cast<U64>(base) + size - 1) >>
                K_PAGE_SHIFT);
        for (U32 page = firstPage; page <= lastPage; ++page) {
            if (memory->isPageMapped(page)) {
                return false;
            }
        }
        return true;
    }

    U32 findFreeGuestModuleBase(U32 size) {
        U64 alignedSize =
            (static_cast<U64>(size) + 0xffff) &
            ~static_cast<U64>(0xffff);
        U64 candidate =
            (static_cast<U64>(nextGuestModuleBase) + 0xffff) &
            ~static_cast<U64>(0xffff);
        while (candidate >= 0x18000000 &&
               candidate + alignedSize <= GUEST_VIRTUAL_LIMIT) {
            if (guestRangeIsFree(
                    static_cast<U32>(candidate),
                    static_cast<U32>(alignedSize))) {
                nextGuestModuleBase =
                    static_cast<U32>(candidate + alignedSize);
                return static_cast<U32>(candidate);
            }
            candidate += 0x10000;
        }
        return 0;
    }

    std::string resolveGuestLibraryPath(
        const std::string& requested) const {
        if (requested.empty()) {
            return std::string();
        }
        std::filesystem::path path(requested);
        std::error_code fileError;
        if (std::filesystem::is_regular_file(path, fileError)) {
            return std::filesystem::absolute(path).string();
        }
        std::filesystem::path imageDirectory =
            std::filesystem::path(imagePath).parent_path();
        std::filesystem::path besideImage = imageDirectory / path;
        fileError.clear();
        if (std::filesystem::is_regular_file(
                besideImage,
                fileError)) {
            return std::filesystem::absolute(besideImage).string();
        }
        std::filesystem::path byName =
            imageDirectory / path.filename();
        fileError.clear();
        if (std::filesystem::is_regular_file(byName, fileError)) {
            return std::filesystem::absolute(byName).string();
        }
        return std::string();
    }

    bool mapGuestModule(
        const std::string& requestedPath,
        U32& moduleHandle) {
        moduleHandle = 0;
        std::string path = resolveGuestLibraryPath(requestedPath);
        if (path.empty()) {
            error = "Unable to locate guest DLL " + requestedPath;
            return false;
        }
        std::string key = guestModuleKey(path);
        auto existingName = guestModuleHandles.find(key);
        if (existingName != guestModuleHandles.end()) {
            GuestModule& existing =
                guestModules[existingName->second];
            ++existing.references;
            moduleHandle = existing.image.loadBase;
            return true;
        }

        std::vector<U8> bytes;
        Pe32ImageInfo inspected;
        std::string loadError;
        if (!Pe32Loader::readFile(path.c_str(), bytes, loadError) ||
            !Pe32Loader::inspect(bytes, inspected, loadError)) {
            error = "Unable to inspect guest DLL " + path + ": " +
                loadError;
            return false;
        }
        constexpr U16 IMAGE_FILE_DLL = 0x2000;
        if (!(inspected.characteristics & IMAGE_FILE_DLL)) {
            error = "Guest module is not marked as a DLL: " + path;
            return false;
        }

        U32 loadBase = guestRangeIsFree(
            inspected.imageBase,
            inspected.sizeOfImage)
            ? inspected.imageBase
            : findFreeGuestModuleBase(inspected.sizeOfImage);
        if (!loadBase) {
            error = "Unable to find guest address space for DLL " + path;
            return false;
        }

        bool reopenThunks = thunks.finalized();
        if (reopenThunks && !thunks.beginUpdate(loadError)) {
            error = loadError;
            return false;
        }
        Pe32MappedImage mapped;
        bool mappedSuccessfully = Pe32Loader::mapImageWithImports(
            thread,
            bytes,
            loadBase,
            resolveImport,
            this,
            mapped,
            loadError);
        if (reopenThunks) {
            std::string finalizeError;
            if (!thunks.finalize(finalizeError) &&
                mappedSuccessfully) {
                mappedSuccessfully = false;
                loadError = finalizeError;
            }
        }
        if (!mappedSuccessfully) {
            error = "Unable to map guest DLL " + path + ": " +
                loadError;
            return false;
        }

        GuestModule module;
        module.key = key;
        module.path = path;
        module.image = mapped;
        moduleHandle = mapped.loadBase;
        guestModuleHandles[key] = moduleHandle;
        guestModules[moduleHandle] = std::move(module);
        guestModuleLoadOrder.push_back(moduleHandle);
        if (staticTlsInitialized) {
            std::size_t previousTemplateCount =
                staticTlsTemplates.size();
            if (!appendStaticTlsTemplate(
                    guestModules[moduleHandle].image)) {
                return false;
            }
            if (staticTlsTemplates.size() != previousTemplateCount) {
                const StaticTlsTemplate& tls =
                    staticTlsTemplates.back();
                for (auto& state : guestThreads) {
                    if (!initializeThreadStaticTlsTemplate(
                            *state,
                            tls)) {
                        return false;
                    }
                }
            }
        }
        printf(
            "Sugarbomb Win32 loader: mapped guest DLL %s at "
            "0x%08X-0x%08X (%zu exports, %zu imports)\n",
            path.c_str(),
            mapped.loadBase,
            mapped.loadBase + mapped.info.sizeOfImage,
            mapped.info.exports.size(),
            mapped.info.importSymbolCount());
        return true;
    }

    U32 guestModuleHandle(const std::string& requestedName) const {
        std::string key = guestModuleKey(requestedName);
        auto found = guestModuleHandles.find(key);
        return found == guestModuleHandles.end() ? 0 : found->second;
    }

    U32 guestModuleProcAddress(
        U32 moduleHandle,
        const std::string& name,
        U32 ordinal) const {
        const Pe32ImageInfo* moduleInfo = nullptr;
        U32 loadBase = 0;
        if (moduleHandle == image.loadBase) {
            moduleInfo = &image.info;
            loadBase = image.loadBase;
        } else {
            auto found = guestModules.find(moduleHandle);
            if (found != guestModules.end()) {
                moduleInfo = &found->second.image.info;
                loadBase = found->second.image.loadBase;
            }
        }
        if (!moduleInfo) {
            return 0;
        }
        const Pe32ExportSymbol* symbol = ordinal
            ? moduleInfo->findExport(ordinal)
            : moduleInfo->findExport(name);
        if (!symbol || symbol->forwarded()) {
            return 0;
        }
        return loadBase + symbol->rva;
    }

    bool mapBundledNvse() {
        std::filesystem::path nvsePath =
            std::filesystem::path(imagePath).parent_path() /
            "nvse_1_4.dll";
        std::error_code fileError;
        if (!std::filesystem::is_regular_file(nvsePath, fileError)) {
            printf(
                "Sugarbomb NVSE: no nvse_1_4.dll beside the guest; "
                "continuing without NVSE\n");
            return true;
        }
        U32 moduleHandle = 0;
        if (!mapGuestModule(nvsePath.string(), moduleHandle)) {
            return false;
        }
        const GuestModule& module = guestModules[moduleHandle];
        const Pe32ExportSymbol* start =
            module.image.info.findExport("StartNVSE");
        printf(
            "Sugarbomb NVSE: staged nvse_1_4.dll at 0x%08X; "
            "StartNVSE=%s0x%08X (DllMain not called yet)\n",
            moduleHandle,
            start ? "" : "unavailable/",
            start ? moduleHandle + start->rva : 0);
        return true;
    }

    void initializeWindowsEnvironment() {
        memory->strcpy(ANSI_COMMAND_LINE, commandLine.c_str());
        writeUnicodeString(memory, PROCESS_PARAMETERS + 0x38, WIDE_IMAGE_PATH, imagePath);
        writeUnicodeString(memory, PROCESS_PARAMETERS + 0x40, WIDE_COMMAND_LINE, commandLine);
        memory->strcpy(ANSI_ENVIRONMENT, "PATH=.\0");
        memory->writeb(ANSI_ENVIRONMENT + 7, 0);
        const char* minimalEnvironment = "PATH=.";
        for (U32 index = 0; minimalEnvironment[index]; ++index) {
            memory->writew(WIDE_ENVIRONMENT + index * 2, minimalEnvironment[index]);
        }
        memory->writew(WIDE_ENVIRONMENT + 12, 0);
        memory->writew(WIDE_ENVIRONMENT + 14, 0);

        memory->writed(PROCESS_PARAMETERS + 0x00, 0x1000);
        memory->writed(PROCESS_PARAMETERS + 0x04, 0x290);
        memory->writed(PROCESS_PARAMETERS + 0x08, 1);
        memory->writed(PROCESS_PARAMETERS + 0x48, WIDE_ENVIRONMENT);

        memory->writed(PEB_LDR_DATA + 0x00, 0x30);
        memory->writeb(PEB_LDR_DATA + 0x04, 1);
        initializeListHead(PEB_LDR_DATA + 0x0c);
        initializeListHead(PEB_LDR_DATA + 0x14);
        initializeListHead(PEB_LDR_DATA + 0x1c);

        memory->writeb(PEB_ADDRESS + 0x02, 0);
        memory->writed(PEB_ADDRESS + 0x08, image.loadBase);
        memory->writed(PEB_ADDRESS + 0x0c, PEB_LDR_DATA);
        memory->writed(PEB_ADDRESS + 0x10, PROCESS_PARAMETERS);
        memory->writed(PEB_ADDRESS + 0x18, PROCESS_HEAP_HANDLE);

        memory->writed(TEB_ADDRESS + 0x00, 0xffffffff);
        memory->writed(TEB_ADDRESS + 0x04, STACK_TOP);
        memory->writed(TEB_ADDRESS + 0x08, STACK_BASE);
        memory->writed(TEB_ADDRESS + 0x18, TEB_ADDRESS);
        memory->writed(TEB_ADDRESS + 0x20, process->id);
        memory->writed(TEB_ADDRESS + 0x24, thread->id);
        memory->writed(TEB_ADDRESS + 0x2c, TLS_ARRAY);
        memory->writed(TEB_ADDRESS + 0x30, PEB_ADDRESS);
        memory->writed(TEB_ADDRESS + 0x34, 0);
    }

    void initializeListHead(U32 address) {
        memory->writed(address, address);
        memory->writed(address + 4, address);
    }

    void initializeCpu() {
        struct user_desc teb = {};
        teb.entry_number = TLS_ENTRY_START_INDEX;
        teb.base_addr = TEB_ADDRESS;
        teb.limit = 0xfffff;
        teb.seg_32bit = 1;
        teb.contents = 0;
        teb.read_exec_only = 0;
        teb.limit_in_pages = 1;
        teb.seg_not_present = 0;
        teb.useable = 1;
        thread->setTLS(&teb);

        cpu->reset();
        cpu->setSegment(CS, BOXEDWINE_VISIBLE_USER_CODE_SELECTOR);
        cpu->setSegment(SS, BOXEDWINE_VISIBLE_USER_DATA_SELECTOR);
        cpu->setSegment(DS, BOXEDWINE_VISIBLE_USER_DATA_SELECTOR);
        cpu->setSegment(ES, BOXEDWINE_VISIBLE_USER_DATA_SELECTOR);
        cpu->setSegment(FS, WINDOWS_TEB_SELECTOR);
        cpu->setSegment(GS, 0);

        U32 stackPointer = STACK_TOP - 8;
        memory->writed(stackPointer, entryReturnThunk);
        memory->writed(stackPointer + 4, entryReturnThunk);
        cpu->reg[4].u32 = stackPointer;
        cpu->eip.u32 = image.entryPoint;
        cpu->nextOp = nullptr;
        memory->clearOpCache();
    }

    void registerMainGuestThread() {
        std::unique_ptr<GuestThreadState> state(new GuestThreadState());
        state->thread = thread;
        state->stackBase = STACK_BASE;
        state->stackSize = STACK_SIZE;
        state->environmentBase = ENV_BASE;
        state->tebAddress = TEB_ADDRESS;
        state->tlsArray = TLS_ARRAY;
        state->mainThread = true;
        guestThreads.push_back(std::move(state));
    }

    GuestThreadState* findGuestThread(U32 threadId) {
        for (auto& state : guestThreads) {
            if (state->thread && state->thread->id == threadId) {
                return state.get();
            }
        }
        return nullptr;
    }

    GuestThreadState* nextRunnableGuestThread(std::size_t& cursor) {
        if (guestThreads.empty()) {
            return nullptr;
        }
        std::size_t checked = 0;
        while (checked < guestThreads.size()) {
            if (cursor >= guestThreads.size()) {
                cursor = 0;
            }
            GuestThreadState* state = guestThreads[cursor++].get();
            ++checked;
            if (!state->completed &&
                !state->suspendCount &&
                state->waitKind == GuestWaitKind::None &&
                state->thread &&
                !state->thread->terminating) {
                return state;
            }
        }
        return nullptr;
    }

    void runGuestThreadSlice(GuestThreadState& state) {
        CPU* previousCpu = activeCpu;
        KThread* previousThread = KThread::currentThread();
        activeCpu = state.thread->cpu;
        KThread::setCurrentThread(state.thread);
        activeCpu->run();
        ++runSlices;
        lastGuestEip = activeCpu->getEipAddress();
        if (state.thread->terminating && !state.completed) {
            completeGuestThread(state, state.thread->cpu->reg[0].u32);
        }
        activeCpu = previousCpu;
        KThread::setCurrentThread(previousThread);
    }

    void findNativeCallback(
        const std::string& module,
        const std::string& symbol,
        SugarbombNativeCallback& callback,
        U16& stackCleanupBytes) {
        if (module == "user32.dll") {
            if (symbol == "GetSystemMetrics") {
                callback = callbackGetSystemMetrics;
                stackCleanupBytes = 4;
            } else if (symbol == "FindWindowA") {
                callback = callbackFindWindowA;
                stackCleanupBytes = 8;
            } else if (symbol == "LoadIconA") {
                callback = callbackLoadIconA;
                stackCleanupBytes = 8;
            } else if (symbol == "LoadCursorA") {
                callback = callbackLoadCursorA;
                stackCleanupBytes = 8;
            } else if (symbol == "RegisterClassA") {
                callback = callbackRegisterClassA;
                stackCleanupBytes = 4;
            } else if (symbol == "CreateWindowExA") {
                callback = callbackCreateWindowExA;
                stackCleanupBytes = 48;
            } else if (symbol == "DestroyWindow") {
                callback = callbackDestroyWindow;
                stackCleanupBytes = 4;
            } else if (symbol == "ShowWindow") {
                callback = callbackShowWindow;
                stackCleanupBytes = 8;
            } else if (symbol == "UpdateWindow") {
                callback = callbackUpdateWindow;
                stackCleanupBytes = 4;
            } else if (symbol == "GetClientRect") {
                callback = callbackGetClientRect;
                stackCleanupBytes = 8;
            } else if (symbol == "SetWindowPos") {
                callback = callbackSetWindowPos;
                stackCleanupBytes = 28;
            } else if (symbol == "GetWindow") {
                callback = callbackGetWindow;
                stackCleanupBytes = 8;
            } else if (symbol == "GetActiveWindow") {
                callback = callbackGetActiveWindow;
            } else if (symbol == "GetForegroundWindow") {
                callback = callbackGetForegroundWindow;
            } else if (symbol == "GetFocus") {
                callback = callbackGetFocus;
            } else if (symbol == "SetActiveWindow") {
                callback = callbackSetActiveWindow;
                stackCleanupBytes = 4;
            } else if (symbol == "SetFocus") {
                callback = callbackSetFocus;
                stackCleanupBytes = 4;
            } else if (symbol == "SetForegroundWindow") {
                callback = callbackSetForegroundWindow;
                stackCleanupBytes = 4;
            } else if (symbol == "SetWindowTextA") {
                callback = callbackSetWindowTextA;
                stackCleanupBytes = 8;
            } else if (symbol == "GetWindowTextA") {
                callback = callbackGetWindowTextA;
                stackCleanupBytes = 12;
            } else if (symbol == "GetClassNameA") {
                callback = callbackGetClassNameA;
                stackCleanupBytes = 12;
            } else if (symbol == "GetWindowLongA") {
                callback = callbackGetWindowLongA;
                stackCleanupBytes = 8;
            } else if (symbol == "GetClassLongA") {
                callback = callbackGetClassLongA;
                stackCleanupBytes = 8;
            } else if (symbol == "PeekMessageA") {
                callback = callbackPeekMessageA;
                stackCleanupBytes = 20;
            } else if (symbol == "TranslateMessage") {
                callback = callbackUser32ReturnTrue;
                stackCleanupBytes = 4;
            } else if (symbol == "DispatchMessageA") {
                callback = callbackDispatchMessageA;
                stackCleanupBytes = 4;
            } else if (symbol == "SendMessageA") {
                callback = callbackSendMessageA;
                stackCleanupBytes = 16;
            } else if (symbol == "DefWindowProcA") {
                callback = callbackUser32ReturnZero;
                stackCleanupBytes = 16;
            } else if (symbol == "ShowCursor") {
                callback = callbackShowCursor;
                stackCleanupBytes = 4;
            } else if (symbol == "GetDoubleClickTime") {
                callback = callbackGetDoubleClickTime;
            } else if (symbol == "SwapMouseButton") {
                callback = callbackSwapMouseButton;
                stackCleanupBytes = 4;
            } else if (symbol == "SetWindowsHookExA") {
                callback = callbackSetWindowsHookExA;
                stackCleanupBytes = 16;
            } else if (symbol == "UnhookWindowsHookEx") {
                callback = callbackUser32ReturnTrue;
                stackCleanupBytes = 4;
            } else if (symbol == "CallNextHookEx") {
                callback = callbackUser32ReturnZero;
                stackCleanupBytes = 16;
            } else if (symbol == "SendInput") {
                callback = callbackSendInput;
                stackCleanupBytes = 12;
            } else if (symbol == "GetAsyncKeyState") {
                callback = callbackGetAsyncKeyState;
                stackCleanupBytes = 4;
            } else if (symbol == "EnumChildWindows") {
                callback = callbackUser32ReturnTrue;
                stackCleanupBytes = 12;
            } else if (symbol == "EnumDisplayDevicesA") {
                callback = callbackEnumDisplayDevicesA;
                stackCleanupBytes = 16;
            } else if (symbol == "MessageBoxA") {
                callback = callbackMessageBoxA;
                stackCleanupBytes = 16;
            } else if (symbol == "AdjustWindowRect") {
                callback = callbackUser32ReturnTrue;
                stackCleanupBytes = 12;
            } else if (symbol == "AdjustWindowRectEx") {
                callback = callbackUser32ReturnTrue;
                stackCleanupBytes = 16;
            }
            return;
        }
        if (module == "gdi32.dll") {
            if (symbol == "GetStockObject") {
                callback = callbackGetStockObject;
                stackCleanupBytes = 4;
            }
            return;
        }
        if (module == "shell32.dll") {
            if (symbol == "SHGetFolderPathA") {
                callback = callbackSHGetFolderPathA;
                stackCleanupBytes = 20;
            } else if (symbol == "CommandLineToArgvW") {
                callback = callbackCommandLineToArgvW;
                stackCleanupBytes = 8;
            } else if (symbol == "ShellExecuteA") {
                callback = callbackShellExecuteA;
                stackCleanupBytes = 24;
            }
            return;
        }
        if (module == "d3d9.dll") {
            if (symbol == "D3DPERF_SetOptions") {
                callback = callbackD3DPerfSetOptions;
                stackCleanupBytes = 4;
            }
            return;
        }
        if (module == "d3dx9_38.dll") {
            if (symbol == "D3DXMatrixMultiply") {
                callback = callbackD3DXMatrixMultiply;
                stackCleanupBytes = 12;
            } else if (symbol == "D3DXMatrixMultiplyTranspose") {
                callback = callbackD3DXMatrixMultiplyTranspose;
                stackCleanupBytes = 12;
            } else if (symbol == "D3DXMatrixTranspose") {
                callback = callbackD3DXMatrixTranspose;
                stackCleanupBytes = 8;
            } else if (symbol == "D3DXMatrixInverse") {
                callback = callbackD3DXMatrixInverse;
                stackCleanupBytes = 12;
            } else if (symbol == "D3DXMatrixRotationYawPitchRoll") {
                callback = callbackD3DXMatrixRotationYawPitchRoll;
                stackCleanupBytes = 16;
            } else if (symbol == "D3DXVec4Transform") {
                callback = callbackD3DXVec4Transform;
                stackCleanupBytes = 12;
            } else if (symbol == "D3DXVec3TransformCoord") {
                callback = callbackD3DXVec3TransformCoord;
                stackCleanupBytes = 12;
            } else if (symbol == "D3DXVec3TransformNormal") {
                callback = callbackD3DXVec3TransformNormal;
                stackCleanupBytes = 12;
            } else if (symbol == "D3DXVec3Normalize") {
                callback = callbackD3DXVec3Normalize;
                stackCleanupBytes = 8;
            } else if (symbol == "D3DXPlaneTransform") {
                callback = callbackD3DXPlaneTransform;
                stackCleanupBytes = 12;
            } else if (symbol == "D3DXPlaneNormalize") {
                callback = callbackD3DXPlaneNormalize;
                stackCleanupBytes = 8;
            } else if (symbol == "D3DXGetVertexShaderProfile") {
                callback = callbackD3DXGetVertexShaderProfile;
                stackCleanupBytes = 4;
            } else if (symbol == "D3DXGetPixelShaderProfile") {
                callback = callbackD3DXGetPixelShaderProfile;
                stackCleanupBytes = 4;
            } else if (symbol == "D3DXLoadSurfaceFromSurface") {
                callback = callbackD3DXLoadSurfaceFromSurface;
                stackCleanupBytes = 32;
            } else if (symbol == "D3DXSaveTextureToFileA") {
                callback = callbackD3DXReturnNotImplemented;
                stackCleanupBytes = 16;
            } else if (symbol == "D3DXAssembleShader") {
                callback = callbackD3DXReturnNotImplemented;
                stackCleanupBytes = 28;
            } else if (symbol == "D3DXAssembleShaderFromFileA") {
                callback = callbackD3DXReturnNotImplemented;
                stackCleanupBytes = 24;
            } else if (symbol == "D3DXCompileShaderFromFileA") {
                callback = callbackD3DXReturnNotImplemented;
                stackCleanupBytes = 36;
            } else if (symbol == "D3DXCompileShader") {
                callback = callbackD3DXReturnNotImplemented;
                stackCleanupBytes = 40;
            } else if (symbol == "D3DXGetShaderConstantTable") {
                callback = callbackD3DXReturnNotImplemented;
                stackCleanupBytes = 8;
            } else if (symbol == "D3DXCreateBuffer") {
                callback = callbackD3DXReturnNotImplemented;
                stackCleanupBytes = 8;
            } else if (symbol == "D3DXGetImageInfoFromFileInMemory") {
                callback = callbackD3DXGetImageInfoFromFileInMemory;
                stackCleanupBytes = 12;
            } else if (symbol == "D3DXCreateTextureFromFileInMemory") {
                callback = callbackD3DXCreateTextureFromFileInMemory;
                stackCleanupBytes = 16;
            } else if (symbol == "D3DXCreateCubeTextureFromFileInMemory") {
                callback = callbackD3DXCreateCubeTextureFromFileInMemory;
                stackCleanupBytes = 16;
            } else if (symbol == "D3DXCreateVolumeTextureFromFileInMemory") {
                callback = callbackD3DXReturnNotImplemented;
                stackCleanupBytes = 16;
            }
            return;
        }
        if (module == "winmm.dll") {
            if (symbol == "timeGetTime") {
                callback = callbackTimeGetTime;
            } else if (symbol == "mmioOpenA") {
                callback = callbackMmioOpenA;
                stackCleanupBytes = 12;
            } else if (symbol == "mmioClose") {
                callback = callbackMmioClose;
                stackCleanupBytes = 8;
            } else if (symbol == "mmioRead") {
                callback = callbackMmioRead;
                stackCleanupBytes = 12;
            } else if (symbol == "mmioDescend") {
                callback = callbackMmioDescend;
                stackCleanupBytes = 16;
            } else if (symbol == "mmioAscend") {
                callback = callbackMmioAscend;
                stackCleanupBytes = 12;
            } else if (symbol == "mmioGetInfo") {
                callback = callbackMmioGetInfo;
                stackCleanupBytes = 12;
            } else if (symbol == "mmioAdvance") {
                callback = callbackMmioAdvance;
                stackCleanupBytes = 12;
            }
            return;
        }
        if (module == "dinput8.dll") {
            if (symbol == "DirectInput8Create") {
                callback = callbackDirectInput8Create;
                stackCleanupBytes = 20;
            }
            return;
        }
        if (module == "xinput1_3.dll") {
            if (symbol == "#2" || symbol == "XInputGetState") {
                callback = callbackXInputGetState;
                stackCleanupBytes = 8;
            } else if (symbol == "#3" || symbol == "XInputSetState") {
                callback = callbackXInputSetState;
                stackCleanupBytes = 8;
            }
            return;
        }
        if (module == "dsound.dll") {
            if (symbol == "#11" || symbol == "DirectSoundCreate8") {
                callback = callbackDirectSoundCreate8;
                stackCleanupBytes = 12;
            }
            return;
        }
        if (module == "binkw32.dll") {
            if (symbol == "_BinkSetSoundSystem@8") {
                callback = callbackBinkSetSoundSystem;
                stackCleanupBytes = 8;
            } else if (symbol == "_BinkClose@4") {
                callback = callbackBinkClose;
                stackCleanupBytes = 4;
            } else if (symbol == "_BinkNextFrame@4") {
                callback = callbackBinkNextFrame;
                stackCleanupBytes = 4;
            } else if (symbol == "_BinkWait@4") {
                callback = callbackBinkWait;
                stackCleanupBytes = 4;
            } else if (symbol == "_BinkPause@8") {
                callback = callbackBinkPause;
                stackCleanupBytes = 8;
            } else if (symbol == "_BinkOpenDirectSound@4") {
                callback = callbackBinkOpenDirectSound;
                stackCleanupBytes = 4;
            } else if (symbol == "_BinkOpen@8") {
                callback = callbackBinkOpen;
                stackCleanupBytes = 8;
            } else if (symbol == "_BinkDoFrame@4") {
                callback = callbackBinkDoFrame;
                stackCleanupBytes = 4;
            } else if (symbol == "_BinkCopyToBufferRect@44") {
                callback = callbackBinkCopyToBufferRect;
                stackCleanupBytes = 44;
            }
            return;
        }
        if (module == "advapi32.dll") {
            if (symbol == "GetUserNameA") {
                callback = callbackGetUserNameA;
                stackCleanupBytes = 8;
            } else if (symbol == "RegOpenKeyExA") {
                callback = callbackRegOpenKeyExA;
                stackCleanupBytes = 20;
            } else if (symbol == "RegCreateKeyExA") {
                callback = callbackRegCreateKeyExA;
                stackCleanupBytes = 36;
            } else if (symbol == "RegCloseKey") {
                callback = callbackRegCloseKey;
                stackCleanupBytes = 4;
            } else if (symbol == "RegQueryValueExA") {
                callback = callbackRegQueryValueExA;
                stackCleanupBytes = 24;
            } else if (symbol == "RegSetValueExA") {
                callback = callbackRegSetValueExA;
                stackCleanupBytes = 24;
            }
            return;
        }
        if (module == "steam_api.dll") {
            if (symbol == "SteamAPI_Init" || symbol == "SteamAPI_IsSteamRunning") {
                callback = callbackSteamUnavailable;
            } else if (
                symbol == "SteamFriends" ||
                symbol == "SteamUser" ||
                symbol == "SteamUserStats" ||
                symbol == "SteamApps" ||
                symbol == "SteamUtils") {
                callback = callbackSteamInterfaceUnavailable;
            } else if (
                symbol == "SteamAPI_RegisterCallback" ||
                symbol == "SteamAPI_UnregisterCallback" ||
                symbol == "SteamAPI_RunCallbacks" ||
                symbol == "SteamAPI_Shutdown") {
                callback = callbackSteamNoOp;
            }
            return;
        }
        if (module == "ole32.dll") {
            if (symbol == "CoInitialize") {
                callback = callbackCoInitialize;
                stackCleanupBytes = 4;
            } else if (symbol == "CoInitializeEx") {
                callback = callbackCoInitializeEx;
                stackCleanupBytes = 8;
            } else if (symbol == "CoTaskMemAlloc") {
                callback = callbackCoTaskMemAlloc;
                stackCleanupBytes = 4;
            } else if (symbol == "CoTaskMemFree") {
                callback = callbackCoTaskMemFree;
                stackCleanupBytes = 4;
            } else if (symbol == "CoUninitialize" || symbol == "CoFreeUnusedLibraries") {
                callback = callbackCoNoOp;
            } else if (symbol == "CoCreateInstance") {
                callback = callbackCoCreateInstance;
                stackCleanupBytes = 20;
            }
            return;
        }
        if (module == "vcruntime140.dll" ||
            module == "vcruntime140d.dll") {
            findCrtMemoryCallback(
                symbol,
                callback,
                stackCleanupBytes);
            return;
        }
        if (module == "ucrtbase.dll" ||
            module == "ucrtbased.dll") {
            if (findCrtMemoryCallback(
                    symbol,
                    callback,
                    stackCleanupBytes)) {
            } else if (findUcrtStringCallback(
                           symbol,
                           callback,
                           stackCleanupBytes)) {
            } else if (findUcrtFileCallback(
                           symbol,
                           callback,
                           stackCleanupBytes)) {
            } else if (findUcrtStdioCallback(
                           symbol,
                           callback,
                           stackCleanupBytes)) {
            } else if (findUcrtMathCallback(
                           symbol,
                           callback,
                           stackCleanupBytes)) {
            } else if (symbol == "_initialize_onexit_table") {
                callback = callbackInitializeOnExitTable;
            } else if (symbol == "___lc_codepage_func") {
                callback = callbackUcrtLocaleCodepage;
            } else if (symbol == "_register_onexit_function") {
                callback = callbackRegisterOnExitFunction;
            } else if (symbol == "_configure_narrow_argv") {
                callback = callbackConfigureNarrowArgv;
            } else if (
                symbol == "_initialize_narrow_environment") {
                callback =
                    callbackInitializeNarrowEnvironment;
            } else if (symbol == "_initterm") {
                callback = callbackInitTerm;
            } else if (symbol == "_initterm_e") {
                callback = callbackInitTermE;
            } else if (symbol == "malloc") {
                callback = callbackUcrtMalloc;
            } else if (symbol == "free") {
                callback = callbackUcrtFree;
            } else if (symbol == "realloc") {
                callback = callbackUcrtRealloc;
            } else if (symbol == "_malloc_dbg") {
                callback = callbackUcrtMallocDebug;
            } else if (symbol == "_calloc_dbg") {
                callback = callbackUcrtCallocDebug;
            } else if (symbol == "_free_dbg") {
                callback = callbackUcrtFreeDebug;
            }
            return;
        }
        if (module == "msvcp140.dll" ||
            module == "msvcp140d.dll") {
            if (symbol ==
                "??0_Lockit@std@@QAE@H@Z") {
                callback = callbackMsvcpLockitConstruct;
                stackCleanupBytes = 4;
            } else if (
                symbol == "??1_Lockit@std@@QAE@XZ") {
                callback = callbackMsvcpLockitDestruct;
            }
            return;
        }
        if (module != "kernel32.dll" && module != "kernelbase.dll") {
            return;
        }
        if (symbol == "GetSystemTimeAsFileTime") {
            callback = callbackGetSystemTimeAsFileTime;
            stackCleanupBytes = 4;
        } else if (symbol == "GetCurrentProcessId") {
            callback = callbackGetCurrentProcessId;
        } else if (symbol == "GetCurrentProcess") {
            callback = callbackGetCurrentProcess;
        } else if (symbol == "GetCurrentThreadId") {
            callback = callbackGetCurrentThreadId;
        } else if (symbol == "GetTickCount") {
            callback = callbackGetTickCount;
        } else if (symbol == "QueryPerformanceCounter") {
            callback = callbackQueryPerformanceCounter;
            stackCleanupBytes = 4;
        } else if (symbol == "QueryPerformanceFrequency") {
            callback = callbackQueryPerformanceFrequency;
            stackCleanupBytes = 4;
        } else if (symbol == "GetStartupInfoA") {
            callback = callbackGetStartupInfoA;
            stackCleanupBytes = 4;
        } else if (symbol == "GetCommandLineA") {
            callback = callbackGetCommandLineA;
        } else if (symbol == "GetLastError") {
            callback = callbackGetLastError;
        } else if (symbol == "SetLastError") {
            callback = callbackSetLastError;
            stackCleanupBytes = 4;
        } else if (symbol == "GetModuleHandleA") {
            callback = callbackGetModuleHandleA;
            stackCleanupBytes = 4;
        } else if (symbol == "GetModuleHandleW") {
            callback = callbackGetModuleHandleW;
            stackCleanupBytes = 4;
        } else if (symbol == "GetModuleFileNameA") {
            callback = callbackGetModuleFileNameA;
            stackCleanupBytes = 12;
        } else if (symbol == "GetPrivateProfileIntA") {
            callback = callbackGetPrivateProfileIntA;
            stackCleanupBytes = 16;
        } else if (symbol == "GetPrivateProfileStringA") {
            callback = callbackGetPrivateProfileStringA;
            stackCleanupBytes = 24;
        } else if (symbol == "WritePrivateProfileStringA") {
            callback = callbackWritePrivateProfileStringA;
            stackCleanupBytes = 16;
        } else if (symbol == "GetCurrentDirectoryA") {
            callback = callbackGetCurrentDirectoryA;
            stackCleanupBytes = 8;
        } else if (findKernelDirectoryCallback(
                       symbol,
                       callback,
                       stackCleanupBytes)) {
        } else if (findKernelFileMetadataCallback(
                       symbol,
                       callback,
                       stackCleanupBytes)) {
        } else if (symbol == "CreateFileA") {
            callback = callbackCreateFileA;
            stackCleanupBytes = 28;
        } else if (symbol == "CreateFileW") {
            callback = callbackCreateFileW;
            stackCleanupBytes = 28;
        } else if (symbol == "GetFileSize") {
            callback = callbackGetFileSize;
            stackCleanupBytes = 8;
        } else if (symbol == "GetFileSizeEx") {
            callback = callbackGetFileSizeEx;
            stackCleanupBytes = 8;
        } else if (symbol == "SetFilePointer") {
            callback = callbackSetFilePointer;
            stackCleanupBytes = 16;
        } else if (symbol == "SetFilePointerEx") {
            callback = callbackSetFilePointerEx;
            stackCleanupBytes = 20;
        } else if (symbol == "SetEndOfFile") {
            callback = callbackSetEndOfFile;
            stackCleanupBytes = 4;
        } else if (symbol == "FindFirstFileA") {
            callback = callbackFindFirstFileA;
            stackCleanupBytes = 8;
        } else if (symbol == "FindNextFileA") {
            callback = callbackFindNextFileA;
            stackCleanupBytes = 8;
        } else if (symbol == "FindClose") {
            callback = callbackFindClose;
            stackCleanupBytes = 4;
        } else if (symbol == "CompareFileTime") {
            callback = callbackCompareFileTime;
            stackCleanupBytes = 8;
        } else if (symbol == "lstrcpyA") {
            callback = callbackLstrcpyA;
            stackCleanupBytes = 8;
        } else if (symbol == "lstrcatA") {
            callback = callbackLstrcatA;
            stackCleanupBytes = 8;
        } else if (symbol == "GetCommandLineW") {
            callback = callbackGetCommandLineW;
        } else if (symbol == "GetEnvironmentStrings" || symbol == "GetEnvironmentStringsA") {
            callback = callbackGetEnvironmentStringsA;
        } else if (symbol == "GetEnvironmentStringsW") {
            callback = callbackGetEnvironmentStringsW;
        } else if (symbol == "FreeEnvironmentStringsA") {
            callback = callbackFreeEnvironmentStringsA;
            stackCleanupBytes = 4;
        } else if (symbol == "FreeEnvironmentStringsW") {
            callback = callbackFreeEnvironmentStringsW;
            stackCleanupBytes = 4;
        } else if (symbol == "GetProcAddress") {
            callback = callbackGetProcAddress;
            stackCleanupBytes = 8;
        } else if (symbol == "LoadLibraryA") {
            callback = callbackLoadLibraryA;
            stackCleanupBytes = 4;
        } else if (symbol == "LoadLibraryExA") {
            callback = callbackLoadLibraryExA;
            stackCleanupBytes = 12;
        } else if (symbol == "FreeLibrary") {
            callback = callbackFreeLibrary;
            stackCleanupBytes = 4;
        } else if (symbol == "TlsAlloc") {
            callback = callbackTlsAlloc;
        } else if (symbol == "TlsGetValue") {
            callback = callbackTlsGetValue;
            stackCleanupBytes = 4;
        } else if (symbol == "TlsSetValue") {
            callback = callbackTlsSetValue;
            stackCleanupBytes = 8;
        } else if (symbol == "TlsFree") {
            callback = callbackTlsFree;
            stackCleanupBytes = 4;
        } else if (symbol == "InitializeCriticalSection") {
            callback = callbackInitializeCriticalSection;
            stackCleanupBytes = 4;
        } else if (symbol == "InitializeCriticalSectionAndSpinCount") {
            callback = callbackInitializeCriticalSectionAndSpinCount;
            stackCleanupBytes = 8;
        } else if (symbol == "DeleteCriticalSection") {
            callback = callbackDeleteCriticalSection;
            stackCleanupBytes = 4;
        } else if (symbol == "EnterCriticalSection") {
            callback = callbackEnterCriticalSection;
            stackCleanupBytes = 4;
        } else if (symbol == "TryEnterCriticalSection") {
            callback = callbackTryEnterCriticalSection;
            stackCleanupBytes = 4;
        } else if (symbol == "LeaveCriticalSection") {
            callback = callbackLeaveCriticalSection;
            stackCleanupBytes = 4;
        } else if (findKernelSrwLockCallback(
                       symbol,
                       callback,
                       stackCleanupBytes)) {
        } else if (symbol == "InterlockedExchange") {
            callback = callbackInterlockedExchange;
            stackCleanupBytes = 8;
        } else if (symbol == "InterlockedCompareExchange") {
            callback = callbackInterlockedCompareExchange;
            stackCleanupBytes = 12;
        } else if (symbol == "InterlockedIncrement") {
            callback = callbackInterlockedIncrement;
            stackCleanupBytes = 4;
        } else if (symbol == "InterlockedDecrement") {
            callback = callbackInterlockedDecrement;
            stackCleanupBytes = 4;
        } else if (symbol == "InterlockedExchangeAdd") {
            callback = callbackInterlockedExchangeAdd;
            stackCleanupBytes = 8;
        } else if (symbol == "GetStdHandle") {
            callback = callbackGetStdHandle;
            stackCleanupBytes = 4;
        } else if (symbol == "SetStdHandle") {
            callback = callbackSetStdHandle;
            stackCleanupBytes = 8;
        } else if (symbol == "SetHandleCount") {
            callback = callbackSetHandleCount;
            stackCleanupBytes = 4;
        } else if (symbol == "GetFileType") {
            callback = callbackGetFileType;
            stackCleanupBytes = 4;
        } else if (symbol == "GetConsoleMode") {
            callback = callbackGetConsoleMode;
            stackCleanupBytes = 8;
        } else if (findKernelCodePageCallback(
                       symbol,
                       callback,
                       stackCleanupBytes)) {
        } else if (symbol == "SetUnhandledExceptionFilter") {
            callback = callbackSetUnhandledExceptionFilter;
            stackCleanupBytes = 4;
        } else if (symbol == "UnhandledExceptionFilter") {
            callback = callbackUnhandledExceptionFilter;
            stackCleanupBytes = 4;
        } else if (symbol == "RaiseException") {
            callback = callbackRaiseException;
            stackCleanupBytes = 16;
        } else if (symbol == "IsDebuggerPresent") {
            callback = callbackIsDebuggerPresent;
        } else if (symbol == "OutputDebugStringA") {
            callback = callbackOutputDebugStringA;
            stackCleanupBytes = 4;
        } else if (symbol == "GlobalMemoryStatusEx") {
            callback = callbackGlobalMemoryStatusEx;
            stackCleanupBytes = 4;
        } else if (symbol == "GlobalMemoryStatus") {
            callback = callbackGlobalMemoryStatus;
            stackCleanupBytes = 4;
        } else if (symbol == "GetSystemInfo") {
            callback = callbackGetSystemInfo;
            stackCleanupBytes = 4;
        } else if (symbol == "IsProcessorFeaturePresent") {
            callback = callbackIsProcessorFeaturePresent;
            stackCleanupBytes = 4;
        } else if (findKernelSListCallback(
                       symbol,
                       callback,
                       stackCleanupBytes)) {
        } else if (findKernelVirtualMemoryCallback(
                       symbol,
                       callback,
                       stackCleanupBytes)) {
        } else if (symbol == "CreateSemaphoreA") {
            callback = callbackCreateSemaphoreA;
            stackCleanupBytes = 16;
        } else if (symbol == "ReleaseSemaphore") {
            callback = callbackReleaseSemaphore;
            stackCleanupBytes = 12;
        } else if (symbol == "CreateEventA") {
            callback = callbackCreateEventA;
            stackCleanupBytes = 16;
        } else if (symbol == "SetEvent") {
            callback = callbackSetEvent;
            stackCleanupBytes = 4;
        } else if (symbol == "ResetEvent") {
            callback = callbackResetEvent;
            stackCleanupBytes = 4;
        } else if (symbol == "CreateMutexA") {
            callback = callbackCreateMutexA;
            stackCleanupBytes = 12;
        } else if (symbol == "ReleaseMutex") {
            callback = callbackReleaseMutex;
            stackCleanupBytes = 4;
        } else if (symbol == "WaitForSingleObject") {
            callback = callbackWaitForSingleObject;
            stackCleanupBytes = 8;
        } else if (symbol == "WaitForMultipleObjects") {
            callback = callbackWaitForMultipleObjects;
            stackCleanupBytes = 16;
        } else if (symbol == "Sleep") {
            callback = callbackSleep;
            stackCleanupBytes = 4;
        } else if (symbol == "CreateThread") {
            callback = callbackCreateThread;
            stackCleanupBytes = 24;
        } else if (symbol == "ResumeThread") {
            callback = callbackResumeThread;
            stackCleanupBytes = 4;
        } else if (symbol == "SuspendThread") {
            callback = callbackSuspendThread;
            stackCleanupBytes = 4;
        } else if (symbol == "ExitThread") {
            callback = callbackExitThread;
            stackCleanupBytes = 4;
        } else if (symbol == "GetExitCodeThread") {
            callback = callbackGetExitCodeThread;
            stackCleanupBytes = 8;
        } else if (symbol == "GetCurrentThread") {
            callback = callbackGetCurrentThread;
        } else if (symbol == "SetThreadPriority") {
            callback = callbackSetThreadPriority;
            stackCleanupBytes = 8;
        } else if (symbol == "SetThreadIdealProcessor") {
            callback = callbackSetThreadIdealProcessor;
            stackCleanupBytes = 8;
        } else if (symbol == "WriteFile") {
            callback = callbackWriteFile;
            stackCleanupBytes = 20;
        } else if (symbol == "WriteConsoleA") {
            callback = callbackWriteConsoleA;
            stackCleanupBytes = 20;
        } else if (symbol == "WriteConsoleW") {
            callback = callbackWriteConsoleW;
            stackCleanupBytes = 20;
        } else if (symbol == "ReadFile") {
            callback = callbackReadFile;
            stackCleanupBytes = 20;
        } else if (symbol == "FlushFileBuffers") {
            callback = callbackFlushFileBuffers;
            stackCleanupBytes = 4;
        } else if (symbol == "CloseHandle") {
            callback = callbackCloseHandle;
            stackCleanupBytes = 4;
        } else if (symbol == "HeapCreate") {
            callback = callbackHeapCreate;
            stackCleanupBytes = 12;
        } else if (symbol == "GetProcessHeap") {
            callback = callbackGetProcessHeap;
        } else if (symbol == "HeapAlloc") {
            callback = callbackHeapAlloc;
            stackCleanupBytes = 12;
        } else if (symbol == "HeapReAlloc") {
            callback = callbackHeapReAlloc;
            stackCleanupBytes = 16;
        } else if (symbol == "HeapFree") {
            callback = callbackHeapFree;
            stackCleanupBytes = 12;
        } else if (symbol == "HeapSize") {
            callback = callbackHeapSize;
            stackCleanupBytes = 12;
        } else if (symbol == "LocalFree") {
            callback = callbackLocalFree;
            stackCleanupBytes = 4;
        } else if (symbol == "ExitProcess") {
            callback = callbackExitProcess;
            stackCleanupBytes = 4;
        }
    }

    bool findKernelDirectoryCallback(
        const std::string& symbol,
        SugarbombNativeCallback& callback,
        U16& stackCleanupBytes) {
        if (symbol == "CreateDirectoryA") {
            callback = callbackCreateDirectoryA;
            stackCleanupBytes = 8;
        } else if (symbol == "CreateDirectoryW") {
            callback = callbackCreateDirectoryW;
            stackCleanupBytes = 8;
        } else if (symbol == "CreateDirectoryExA") {
            callback = callbackCreateDirectoryExA;
            stackCleanupBytes = 12;
        } else if (symbol == "CreateDirectoryExW") {
            callback = callbackCreateDirectoryExW;
            stackCleanupBytes = 12;
        } else {
            return false;
        }
        return true;
    }

    bool findKernelFileMetadataCallback(
        const std::string& symbol,
        SugarbombNativeCallback& callback,
        U16& stackCleanupBytes) {
        if (symbol == "DeleteFileA") {
            callback = callbackDeleteFileA;
            stackCleanupBytes = 4;
        } else if (symbol == "DeleteFileW") {
            callback = callbackDeleteFileW;
            stackCleanupBytes = 4;
        } else if (symbol == "GetFileAttributesA") {
            callback = callbackGetFileAttributesA;
            stackCleanupBytes = 4;
        } else if (symbol == "GetFileAttributesW") {
            callback = callbackGetFileAttributesW;
            stackCleanupBytes = 4;
        } else if (symbol == "GetFileAttributesExA") {
            callback = callbackGetFileAttributesExA;
            stackCleanupBytes = 12;
        } else if (symbol == "GetFileAttributesExW") {
            callback = callbackGetFileAttributesExW;
            stackCleanupBytes = 12;
        } else {
            return false;
        }
        return true;
    }

    bool findKernelCodePageCallback(
        const std::string& symbol,
        SugarbombNativeCallback& callback,
        U16& stackCleanupBytes) {
        stackCleanupBytes = 0;
        if (symbol == "GetConsoleCP") {
            callback = callbackGetConsoleCP;
        } else if (symbol == "GetConsoleOutputCP") {
            callback = callbackGetConsoleOutputCP;
        } else if (symbol == "AreFileApisANSI") {
            callback = callbackAreFileApisAnsi;
        } else if (symbol == "SetFileApisToANSI") {
            callback = callbackSetFileApisToAnsi;
        } else if (symbol == "SetFileApisToOEM") {
            callback = callbackSetFileApisToOem;
        } else if (symbol == "GetACP") {
            callback = callbackGetACP;
        } else if (symbol == "GetOEMCP") {
            callback = callbackGetOEMCP;
        } else if (symbol == "GetCPInfo") {
            callback = callbackGetCPInfo;
            stackCleanupBytes = 8;
        } else if (symbol == "IsValidCodePage") {
            callback = callbackIsValidCodePage;
            stackCleanupBytes = 4;
        } else if (symbol == "WideCharToMultiByte") {
            callback = callbackWideCharToMultiByte;
            stackCleanupBytes = 32;
        } else if (symbol == "MultiByteToWideChar") {
            callback = callbackMultiByteToWideChar;
            stackCleanupBytes = 24;
        } else if (symbol == "GetStringTypeW") {
            callback = callbackGetStringTypeW;
            stackCleanupBytes = 16;
        } else if (symbol == "GetStringTypeA") {
            callback = callbackGetStringTypeA;
            stackCleanupBytes = 20;
        } else if (symbol == "LCMapStringW") {
            callback = callbackLCMapStringW;
            stackCleanupBytes = 24;
        } else if (symbol == "LCMapStringA") {
            callback = callbackLCMapStringA;
            stackCleanupBytes = 24;
        } else {
            return false;
        }
        return true;
    }

    bool findKernelSrwLockCallback(
        const std::string& symbol,
        SugarbombNativeCallback& callback,
        U16& stackCleanupBytes) {
        stackCleanupBytes = 4;
        if (symbol == "AcquireSRWLockExclusive") {
            callback = callbackAcquireSrwLockExclusive;
        } else if (symbol == "AcquireSRWLockShared") {
            callback = callbackAcquireSrwLockShared;
        } else if (symbol == "ReleaseSRWLockExclusive") {
            callback = callbackReleaseSrwLockExclusive;
        } else if (symbol == "ReleaseSRWLockShared") {
            callback = callbackReleaseSrwLockShared;
        } else if (symbol == "TryAcquireSRWLockExclusive") {
            callback = callbackTryAcquireSrwLockExclusive;
        } else if (symbol == "TryAcquireSRWLockShared") {
            callback = callbackTryAcquireSrwLockShared;
        } else if (symbol == "SleepConditionVariableSRW") {
            callback = callbackSleepConditionVariableSrw;
            stackCleanupBytes = 16;
        } else if (symbol == "WakeConditionVariable") {
            callback = callbackWakeConditionVariable;
        } else if (symbol == "WakeAllConditionVariable") {
            callback = callbackWakeAllConditionVariable;
        } else {
            return false;
        }
        return true;
    }

    bool findKernelSListCallback(
        const std::string& symbol,
        SugarbombNativeCallback& callback,
        U16& stackCleanupBytes) {
        if (symbol == "InitializeSListHead") {
            callback = callbackInitializeSListHead;
            stackCleanupBytes = 4;
        } else if (symbol == "InterlockedPushEntrySList") {
            callback = callbackInterlockedPushEntrySList;
            stackCleanupBytes = 8;
        } else if (symbol == "InterlockedPopEntrySList") {
            callback = callbackInterlockedPopEntrySList;
            stackCleanupBytes = 4;
        } else if (symbol == "InterlockedFlushSList") {
            callback = callbackInterlockedFlushSList;
            stackCleanupBytes = 4;
        } else if (symbol == "QueryDepthSList") {
            callback = callbackQueryDepthSList;
            stackCleanupBytes = 4;
        } else {
            return false;
        }
        return true;
    }

    bool findKernelVirtualMemoryCallback(
        const std::string& symbol,
        SugarbombNativeCallback& callback,
        U16& stackCleanupBytes) {
        if (symbol == "VirtualAlloc") {
            callback = callbackVirtualAlloc;
            stackCleanupBytes = 16;
        } else if (symbol == "VirtualFree") {
            callback = callbackVirtualFree;
            stackCleanupBytes = 12;
        } else if (symbol == "VirtualProtect") {
            callback = callbackVirtualProtect;
            stackCleanupBytes = 16;
        } else if (symbol == "VirtualQuery") {
            callback = callbackVirtualQuery;
            stackCleanupBytes = 12;
        } else if (symbol == "FlushInstructionCache") {
            callback = callbackFlushInstructionCache;
            stackCleanupBytes = 12;
        } else {
            return false;
        }
        return true;
    }

    bool findCrtMemoryCallback(
        const std::string& symbol,
        SugarbombNativeCallback& callback,
        U16& stackCleanupBytes) {
        stackCleanupBytes = 0; // CRT entry points are cdecl.
        if (symbol == "memset") {
            callback = callbackCrtMemset;
        } else if (symbol == "memcpy") {
            callback = callbackCrtMemcpy;
        } else if (symbol == "memmove") {
            callback = callbackCrtMemmove;
        } else if (symbol == "memcmp") {
            callback = callbackCrtMemcmp;
        } else if (symbol == "memchr") {
            callback = callbackCrtMemchr;
        } else if (symbol == "strchr") {
            callback = callbackCrtStrchr;
        } else if (symbol == "strrchr") {
            callback = callbackCrtStrrchr;
        } else if (symbol == "strstr") {
            callback = callbackCrtStrstr;
        } else {
            return false;
        }
        return true;
    }

    bool findUcrtStringCallback(
        const std::string& symbol,
        SugarbombNativeCallback& callback,
        U16& stackCleanupBytes) {
        stackCleanupBytes = 0; // UCRT string entry points are cdecl.
        if (symbol == "_strdup") {
            callback = callbackUcrtStrdup;
        } else if (symbol == "strlen") {
            callback = callbackUcrtStrlen;
        } else if (symbol == "strcmp") {
            callback = callbackUcrtStrcmp;
        } else if (symbol == "strncmp") {
            callback = callbackUcrtStrncmp;
        } else if (symbol == "_stricmp") {
            callback = callbackUcrtStricmp;
        } else if (symbol == "_strnicmp") {
            callback = callbackUcrtStrnicmp;
        } else if (symbol == "strcpy") {
            callback = callbackUcrtStrcpy;
        } else if (symbol == "strcpy_s") {
            callback = callbackUcrtStrcpyS;
        } else if (symbol == "strcat_s") {
            callback = callbackUcrtStrcatS;
        } else if (symbol == "islower") {
            callback = callbackUcrtIsLower;
        } else if (symbol == "isupper") {
            callback = callbackUcrtIsUpper;
        } else if (symbol == "isalpha") {
            callback = callbackUcrtIsAlpha;
        } else if (symbol == "isdigit") {
            callback = callbackUcrtIsDigit;
        } else if (symbol == "isalnum") {
            callback = callbackUcrtIsAlnum;
        } else if (symbol == "isspace") {
            callback = callbackUcrtIsSpace;
        } else if (symbol == "ispunct") {
            callback = callbackUcrtIsPunct;
        } else if (symbol == "isprint") {
            callback = callbackUcrtIsPrint;
        } else if (symbol == "tolower") {
            callback = callbackUcrtToLower;
        } else if (symbol == "toupper") {
            callback = callbackUcrtToUpper;
        } else if (symbol == "strtol") {
            callback = callbackUcrtStrtol;
        } else if (symbol == "strtoll") {
            callback = callbackUcrtStrtoll;
        } else if (symbol == "strtoul") {
            callback = callbackUcrtStrtoul;
        } else if (symbol == "strtod") {
            callback = callbackUcrtStrtod;
        } else if (symbol == "atoi") {
            callback = callbackUcrtAtoi;
        } else if (symbol == "atof") {
            callback = callbackUcrtAtof;
        } else if (symbol == "_errno") {
            callback = callbackUcrtErrno;
        } else {
            return false;
        }
        return true;
    }

    bool findUcrtFileCallback(
        const std::string& symbol,
        SugarbombNativeCallback& callback,
        U16& stackCleanupBytes) {
        stackCleanupBytes = 0; // UCRT stream functions are cdecl.
        if (symbol == "_fsopen") {
            callback = callbackUcrtFsopen;
        } else if (symbol == "fopen_s") {
            callback = callbackUcrtFopenS;
        } else if (symbol == "fclose") {
            callback = callbackUcrtFclose;
        } else if (symbol == "fread") {
            callback = callbackUcrtFread;
        } else if (symbol == "fwrite") {
            callback = callbackUcrtFwrite;
        } else if (symbol == "fgetc") {
            callback = callbackUcrtFgetc;
        } else if (symbol == "fputc") {
            callback = callbackUcrtFputc;
        } else if (symbol == "fputs") {
            callback = callbackUcrtFputs;
        } else if (symbol == "fflush") {
            callback = callbackUcrtFflush;
        } else if (symbol == "_fseeki64") {
            callback = callbackUcrtFseeki64;
        } else if (symbol == "fgetpos") {
            callback = callbackUcrtFgetpos;
        } else if (symbol == "fsetpos") {
            callback = callbackUcrtFsetpos;
        } else if (symbol == "setvbuf") {
            callback = callbackUcrtSetvbuf;
        } else if (symbol == "ungetc") {
            callback = callbackUcrtUngetc;
        } else if (symbol == "_lock_file") {
            callback = callbackUcrtLockFile;
        } else if (symbol == "_unlock_file") {
            callback = callbackUcrtUnlockFile;
        } else if (symbol == "_get_stream_buffer_pointers") {
            callback = callbackUcrtGetStreamBufferPointers;
        } else if (symbol == "__acrt_iob_func") {
            callback = callbackUcrtIobFunction;
        } else {
            return false;
        }
        return true;
    }

    bool findUcrtStdioCallback(
        const std::string& symbol,
        SugarbombNativeCallback& callback,
        U16& stackCleanupBytes) {
        stackCleanupBytes = 0; // UCRT stdio entry points are cdecl.
        if (symbol == "__stdio_common_vsprintf_s") {
            callback = callbackUcrtStdioCommonVsprintfS;
        } else if (symbol == "__stdio_common_vsprintf") {
            callback = callbackUcrtStdioCommonVsprintf;
        } else if (symbol == "__stdio_common_vfprintf_s") {
            callback = callbackUcrtStdioCommonVfprintfS;
        } else if (symbol == "__stdio_common_vfprintf") {
            callback = callbackUcrtStdioCommonVfprintf;
        } else if (symbol == "__stdio_common_vswprintf") {
            callback = callbackUcrtStdioCommonVswprintf;
        } else if (symbol == "__stdio_common_vsscanf") {
            callback = callbackUcrtStdioCommonVsscanf;
        } else {
            return false;
        }
        return true;
    }

    bool findUcrtMathCallback(
        const std::string& symbol,
        SugarbombNativeCallback& callback,
        U16& stackCleanupBytes) {
        stackCleanupBytes = 0; // UCRT math entry points are cdecl.
        if (symbol == "acos") {
            callback = callbackUcrtAcos;
        } else if (symbol == "asin") {
            callback = callbackUcrtAsin;
        } else if (symbol == "atan") {
            callback = callbackUcrtAtan;
        } else if (symbol == "atan2") {
            callback = callbackUcrtAtan2;
        } else if (symbol == "ceil") {
            callback = callbackUcrtCeil;
        } else if (symbol == "cos") {
            callback = callbackUcrtCos;
        } else if (symbol == "cosh") {
            callback = callbackUcrtCosh;
        } else if (symbol == "exp") {
            callback = callbackUcrtExp;
        } else if (symbol == "fabs") {
            callback = callbackUcrtFabs;
        } else if (symbol == "floor") {
            callback = callbackUcrtFloor;
        } else if (symbol == "log10") {
            callback = callbackUcrtLog10;
        } else if (symbol == "pow") {
            callback = callbackUcrtPow;
        } else if (symbol == "sin") {
            callback = callbackUcrtSin;
        } else if (symbol == "sinh") {
            callback = callbackUcrtSinh;
        } else if (symbol == "sqrt") {
            callback = callbackUcrtSqrt;
        } else if (symbol == "tan") {
            callback = callbackUcrtTan;
        } else if (symbol == "tanh") {
            callback = callbackUcrtTanh;
        } else {
            return false;
        }
        return true;
    }

    static SugarbombRuntimeSession* current(CPU* cpu, const char* api) {
        if (!activeSession) {
            if (cpu) {
                cpu->thread->terminating = true;
            }
            kwarn_fmt("Sugarbomb API %s called without an active runtime", api);
            return nullptr;
        }
        activeSession->activeCpu = cpu;
        ++activeSession->nativeCallCount;
        U32& callCount = activeSession->nativeApiCounts[api];
        ++callCount;
        if (callCount == 1) {
            printf("Sugarbomb Win32: %s\n", api);
        }
        return activeSession;
    }

    static U32 argument(CPU* cpu, U32 index) {
        return cpu->peek32(index + 2);
    }

    static void callbackGetSystemMetrics(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!GetSystemMetrics");
        if (!session) {
            return;
        }
        U32 index = argument(cpu, 0);
        switch (index) {
        case 0: // SM_CXSCREEN
            cpu->reg[0].u32 = 1280;
            break;
        case 1: // SM_CYSCREEN
            cpu->reg[0].u32 = 720;
            break;
        case 2: // SM_CXVSCROLL
        case 3: // SM_CYHSCROLL
            cpu->reg[0].u32 = 17;
            break;
        case 4: // SM_CYCAPTION
            cpu->reg[0].u32 = 23;
            break;
        case 5: // SM_CXBORDER
        case 6: // SM_CYBORDER
            cpu->reg[0].u32 = 1;
            break;
        case 7: // SM_CXDLGFRAME
        case 8: // SM_CYDLGFRAME
            cpu->reg[0].u32 = 3;
            break;
        case 30: // SM_MOUSEPRESENT
        case 43: // SM_CXDRAG
        case 44: // SM_CYDRAG
        case 80: // SM_CMONITORS
            cpu->reg[0].u32 = 1;
            break;
        default:
            cpu->reg[0].u32 = 0;
            break;
        }
        if (++session->systemMetricsCallCount <= 8) {
            printf(
                "Sugarbomb Win32 USER32: GetSystemMetrics(%u) -> %u (tid %u)\n",
                index,
                cpu->reg[0].u32,
                cpu->thread->id);
        }
    }

    static void callbackFindWindowA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!FindWindowA");
        if (session) {
            std::string className = argument(cpu, 0) ? session->readAnsi(argument(cpu, 0)) : "";
            std::string windowName = argument(cpu, 1) ? session->readAnsi(argument(cpu, 1)) : "";
            cpu->reg[0].u32 = session->findGuestWindow(className, windowName);
            printf(
                "Sugarbomb Win32 USER32: FindWindowA(%s, %s) -> 0x%08X\n",
                className.empty() ? "<any>" : className.c_str(),
                windowName.empty() ? "<any>" : windowName.c_str(),
                cpu->reg[0].u32);
        }
    }

    static SugarbombRuntimeSession* currentImportedApi(CPU* cpu) {
        std::string module;
        std::string symbol;
        SugarbombBridge::callbackName(cpu->peek32(0), module, symbol);
        std::string api = module + "!" + symbol;
        return current(cpu, api.c_str());
    }

    static void callbackUser32ReturnTrue(CPU* cpu) {
        if (currentImportedApi(cpu)) {
            cpu->reg[0].u32 = 1;
        }
    }

    static void callbackUser32ReturnZero(CPU* cpu) {
        if (currentImportedApi(cpu)) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackLoadIconA(CPU* cpu) {
        if (current(cpu, "USER32!LoadIconA")) {
            cpu->reg[0].u32 = USER_ICON_HANDLE;
        }
    }

    static void callbackLoadCursorA(CPU* cpu) {
        if (current(cpu, "USER32!LoadCursorA")) {
            cpu->reg[0].u32 = USER_CURSOR_HANDLE;
        }
    }

    static void callbackRegisterClassA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!RegisterClassA");
        if (session) {
            cpu->reg[0].u32 = session->registerGuestWindowClass(argument(cpu, 0));
        }
    }

    static void callbackCreateWindowExA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!CreateWindowExA");
        if (session) {
            cpu->reg[0].u32 = session->createGuestWindow(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3),
                static_cast<S32>(argument(cpu, 4)),
                static_cast<S32>(argument(cpu, 5)),
                static_cast<S32>(argument(cpu, 6)),
                static_cast<S32>(argument(cpu, 7)),
                argument(cpu, 8),
                argument(cpu, 10));
        }
    }

    static void callbackDestroyWindow(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!DestroyWindow");
        if (session) {
            cpu->reg[0].u32 = session->destroyGuestWindow(argument(cpu, 0)) ? 1 : 0;
        }
    }

    static void callbackShowWindow(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!ShowWindow");
        if (session) {
            cpu->reg[0].u32 = session->showGuestWindow(argument(cpu, 0), argument(cpu, 1)) ? 1 : 0;
        }
    }

    static void callbackUpdateWindow(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!UpdateWindow");
        if (session) {
            cpu->reg[0].u32 =
                session->updateGuestWindow(argument(cpu, 0)) ? 1 : 0;
        }
    }

    static void callbackGetClientRect(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!GetClientRect");
        if (session) {
            cpu->reg[0].u32 =
                session->writeGuestClientRect(argument(cpu, 0), argument(cpu, 1)) ? 1 : 0;
        }
    }

    static void callbackSetWindowPos(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!SetWindowPos");
        if (session) {
            cpu->reg[0].u32 = session->setGuestWindowPosition(
                argument(cpu, 0),
                static_cast<S32>(argument(cpu, 2)),
                static_cast<S32>(argument(cpu, 3)),
                static_cast<S32>(argument(cpu, 4)),
                static_cast<S32>(argument(cpu, 5)),
                argument(cpu, 6)) ? 1 : 0;
        }
    }

    static void callbackGetWindow(CPU* cpu) {
        if (current(cpu, "USER32!GetWindow")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackGetActiveWindow(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!GetActiveWindow");
        if (session) {
            cpu->reg[0].u32 =
                session->guestWindowWithNativeState(
                    NativeWindowState::Active);
        }
    }

    static void callbackGetForegroundWindow(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "USER32!GetForegroundWindow");
        if (session) {
            cpu->reg[0].u32 =
                session->guestWindowWithNativeState(
                    NativeWindowState::Foreground);
        }
    }

    static void callbackGetFocus(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "USER32!GetFocus");
        if (session) {
            cpu->reg[0].u32 =
                session->guestWindowWithNativeState(
                    NativeWindowState::Focused);
        }
    }

    static void callbackSetActiveWindow(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "USER32!SetActiveWindow");
        if (session) {
            U32 previous = session->guestWindowWithNativeState(
                NativeWindowState::Active);
            cpu->reg[0].u32 =
                session->setActiveGuestWindow(argument(cpu, 0))
                ? previous
                : 0;
        }
    }

    static void callbackSetFocus(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "USER32!SetFocus");
        if (session) {
            U32 previous = session->guestWindowWithNativeState(
                NativeWindowState::Focused);
            cpu->reg[0].u32 =
                session->focusGuestWindow(argument(cpu, 0))
                ? previous
                : 0;
        }
    }

    static void callbackSetForegroundWindow(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!SetForegroundWindow");
        if (session) {
            cpu->reg[0].u32 =
                session->activateGuestWindow(argument(cpu, 0)) ? 1 : 0;
        }
    }

    static void callbackSetWindowTextA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!SetWindowTextA");
        if (session) {
            cpu->reg[0].u32 =
                session->setGuestWindowText(argument(cpu, 0), argument(cpu, 1)) ? 1 : 0;
        }
    }

    static void callbackGetWindowTextA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!GetWindowTextA");
        if (session) {
            cpu->reg[0].u32 = session->copyGuestWindowString(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                false);
        }
    }

    static void callbackGetClassNameA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!GetClassNameA");
        if (session) {
            cpu->reg[0].u32 = session->copyGuestWindowString(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                true);
        }
    }

    static void callbackGetWindowLongA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!GetWindowLongA");
        if (session) {
            cpu->reg[0].u32 = session->getGuestWindowLong(
                argument(cpu, 0),
                static_cast<S32>(argument(cpu, 1)));
        }
    }

    static void callbackGetClassLongA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!GetClassLongA");
        if (session) {
            cpu->reg[0].u32 = session->getGuestClassLong(
                argument(cpu, 0),
                static_cast<S32>(argument(cpu, 1)));
        }
    }

    static void callbackPeekMessageA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!PeekMessageA");
        if (!session) {
            return;
        }
        cpu->reg[0].u32 = session->peekGuestMessage(
            cpu,
            argument(cpu, 0),
            argument(cpu, 1),
            argument(cpu, 2),
            argument(cpu, 3),
            argument(cpu, 4)) ? 1 : 0;
    }

    static void callbackDispatchMessageA(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "USER32!DispatchMessageA");
        if (session) {
            session->dispatchGuestMessage(cpu, argument(cpu, 0));
        }
    }

    static void callbackSendMessageA(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "USER32!SendMessageA");
        if (session) {
            session->dispatchGuestWindowProcedure(
                cpu,
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3));
        }
    }

    static void callbackShowCursor(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!ShowCursor");
        if (session) {
            session->cursorDisplayCount += argument(cpu, 0) ? 1 : -1;
            session->hostWindow.setCursorVisible(
                session->cursorDisplayCount >= 0);
            cpu->reg[0].u32 = static_cast<U32>(session->cursorDisplayCount);
        }
    }

    static void callbackGetDoubleClickTime(CPU* cpu) {
        if (current(cpu, "USER32!GetDoubleClickTime")) {
            cpu->reg[0].u32 = 500;
        }
    }

    static void callbackSwapMouseButton(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!SwapMouseButton");
        if (session) {
            bool previous = session->mouseButtonsSwapped;
            session->mouseButtonsSwapped = argument(cpu, 0) != 0;
            cpu->reg[0].u32 = previous ? 1 : 0;
        }
    }

    static void callbackGetAsyncKeyState(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "USER32!GetAsyncKeyState");
        if (session) {
            cpu->reg[0].u32 =
                session->getAsyncKeyState(argument(cpu, 0));
        }
    }

    static void callbackSetWindowsHookExA(CPU* cpu) {
        if (current(cpu, "USER32!SetWindowsHookExA")) {
            cpu->reg[0].u32 = USER_HOOK_HANDLE;
        }
    }

    static void callbackSendInput(CPU* cpu) {
        if (current(cpu, "USER32!SendInput")) {
            cpu->reg[0].u32 = argument(cpu, 0);
        }
    }

    static void callbackEnumDisplayDevicesA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!EnumDisplayDevicesA");
        if (session) {
            cpu->reg[0].u32 = session->writeGuestDisplayDevice(
                argument(cpu, 1),
                argument(cpu, 2)) ? 1 : 0;
        }
    }

    static void callbackMessageBoxA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "USER32!MessageBoxA");
        if (session) {
            std::string text = argument(cpu, 1) ? session->readAnsi(argument(cpu, 1)) : "";
            std::string caption = argument(cpu, 2) ? session->readAnsi(argument(cpu, 2)) : "";
            printf(
                "Sugarbomb Win32 USER32: MessageBoxA(%s): %s\n",
                caption.empty() ? "FalloutNV" : caption.c_str(),
                text.c_str());
            cpu->reg[0].u32 = 1; // IDOK
        }
    }

    static void callbackGetStockObject(CPU* cpu) {
        if (current(cpu, "GDI32!GetStockObject")) {
            cpu->reg[0].u32 = GDI_STOCK_OBJECT_HANDLE + argument(cpu, 0);
        }
    }

    static void callbackShellExecuteA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "SHELL32!ShellExecuteA");
        if (session) {
            std::string target = argument(cpu, 2) ? session->readAnsi(argument(cpu, 2)) : "";
            if (lowerAscii(std::filesystem::path(target).filename().string()) ==
                "falloutnvlauncher.exe") {
                printf(
                    "Sugarbomb Win32 SHELL32: suppressed external FalloutNVLauncher.exe handoff; continuing in-process\n");
                cpu->reg[0].u32 = 0;
            } else {
                printf(
                    "Sugarbomb Win32 SHELL32: ShellExecuteA(%s) deferred to host policy\n",
                    target.c_str());
                cpu->reg[0].u32 = 33; // A value greater than 32 means success.
            }
        }
    }

    static void callbackSHGetFolderPathA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "SHELL32!SHGetFolderPathA");
        if (!session) {
            return;
        }
        U32 folder = argument(cpu, 1) & 0xff;
        U32 destination = argument(cpu, 4);
        std::filesystem::path userProfile;
        if (const char* value = std::getenv("USERPROFILE")) {
            userProfile = value;
        } else {
            userProfile = std::filesystem::path(session->imagePath).parent_path();
        }
        std::filesystem::path result;
        switch (folder) {
        case 0x00: // CSIDL_DESKTOP
        case 0x10: // CSIDL_DESKTOPDIRECTORY
            result = userProfile / "Desktop";
            break;
        case 0x05: // CSIDL_PERSONAL
            result = userProfile / "Documents";
            break;
        case 0x1a: // CSIDL_APPDATA
            result = userProfile / "AppData" / "Roaming";
            break;
        case 0x1c: // CSIDL_LOCAL_APPDATA
            result = userProfile / "AppData" / "Local";
            break;
        default:
            result = userProfile;
            break;
        }
        std::string path = result.string();
        if (!destination || !session->memory->canWrite(destination, 260)) {
            cpu->reg[0].u32 = 0x80070057; // E_INVALIDARG
            return;
        }
        session->memory->strcpy(destination, path.c_str());
        printf(
            "Sugarbomb Win32 SHELL32: SHGetFolderPathA(0x%02X) -> %s\n",
            folder,
            path.c_str());
        cpu->reg[0].u32 = 0; // S_OK
    }

    static void callbackCommandLineToArgvW(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "SHELL32!CommandLineToArgvW");
        if (session) {
            cpu->reg[0].u32 = session->commandLineToArgv(
                argument(cpu, 0),
                argument(cpu, 1));
        }
    }

    static void callbackGetUserNameA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "ADVAPI32!GetUserNameA");
        if (!session) {
            return;
        }
        U32 destination = argument(cpu, 0);
        U32 sizeAddress = argument(cpu, 1);
        std::string userName = "Player";
        if (const char* value = std::getenv("USERNAME")) {
            userName = value;
        }
        U32 required = static_cast<U32>(userName.size() + 1);
        if (!sizeAddress || !session->memory->canWrite(sizeAddress, 4)) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 capacity = session->memory->readd(sizeAddress);
        session->memory->writed(sizeAddress, required);
        if (!destination || capacity < required ||
            !session->memory->canWrite(destination, required)) {
            session->setLastError(122);
            cpu->reg[0].u32 = 0;
            return;
        }
        session->memory->strcpy(destination, userName.c_str());
        cpu->reg[0].u32 = 1;
    }

    static void callbackRegOpenKeyExA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "ADVAPI32!RegOpenKeyExA");
        if (!session) {
            return;
        }
        U32 resultAddress = argument(cpu, 4);
        if (!resultAddress || !session->memory->canWrite(resultAddress, 4)) {
            cpu->reg[0].u32 = 87;
            return;
        }
        std::string subKey = argument(cpu, 1)
            ? session->readAnsi(argument(cpu, 1))
            : "";
        U32 parent = argument(cpu, 0);
        auto parentKey = session->registryKeys.find(parent);
        std::string fullKey = parentKey != session->registryKeys.end() &&
                !parentKey->second.empty()
            ? parentKey->second + "\\" + subKey
            : subKey;
        std::string normalized = lowerAscii(fullKey);
        if (normalized == "software\\bethesda softworks\\fallout" ||
            normalized == "software\\bethesda softworks\\falloutnv") {
            U32 handle = session->nextRegistryHandle++;
            session->registryKeys[handle] = fullKey;
            session->memory->writed(resultAddress, handle);
            printf(
                "Sugarbomb Win32 registry: RegOpenKeyExA(%s) -> 0x%08X\n",
                fullKey.c_str(),
                handle);
            cpu->reg[0].u32 = 0;
        } else {
            printf(
                "Sugarbomb Win32 registry: RegOpenKeyExA(%s) -> not found\n",
                fullKey.c_str());
            cpu->reg[0].u32 = 2;
        }
    }

    static void callbackRegCreateKeyExA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "ADVAPI32!RegCreateKeyExA");
        if (!session) {
            return;
        }
        U32 resultAddress = argument(cpu, 7);
        if (!resultAddress || !session->memory->canWrite(resultAddress, 4)) {
            cpu->reg[0].u32 = 87;
            return;
        }
        U32 handle = session->nextRegistryHandle++;
        session->registryKeys[handle] =
            argument(cpu, 1) ? session->readAnsi(argument(cpu, 1)) : "";
        session->memory->writed(resultAddress, handle);
        if (argument(cpu, 8)) {
            session->memory->writed(argument(cpu, 8), 1);
        }
        cpu->reg[0].u32 = 0;
    }

    static void callbackRegCloseKey(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "ADVAPI32!RegCloseKey");
        if (session) {
            U32 handle = argument(cpu, 0);
            if (handle >= 0x80000000 || session->registryKeys.erase(handle)) {
                cpu->reg[0].u32 = 0;
            } else {
                cpu->reg[0].u32 = 6;
            }
        }
    }

    static void callbackRegQueryValueExA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "ADVAPI32!RegQueryValueExA");
        if (!session) {
            return;
        }
        auto key = session->registryKeys.find(argument(cpu, 0));
        if (key == session->registryKeys.end()) {
            cpu->reg[0].u32 = 6;
            return;
        }
        std::string valueName = argument(cpu, 1)
            ? session->readAnsi(argument(cpu, 1))
            : "";
        std::string normalized = lowerAscii(valueName);
        std::string value;
        if (normalized.empty() || normalized == "installed path") {
            value = std::filesystem::path(session->imagePath).parent_path().string();
            if (!value.empty() && value.back() != '\\') {
                value.push_back('\\');
            }
        } else if (normalized == "version") {
            value = "1.4.0.525";
        } else if (normalized == "language") {
            value = "English";
        } else {
            printf(
                "Sugarbomb Win32 registry: RegQueryValueExA(%s, %s) -> not found\n",
                key->second.c_str(),
                valueName.c_str());
            cpu->reg[0].u32 = 2;
            return;
        }
        U32 typeAddress = argument(cpu, 3);
        U32 dataAddress = argument(cpu, 4);
        U32 sizeAddress = argument(cpu, 5);
        if (!sizeAddress || !session->memory->canWrite(sizeAddress, 4)) {
            cpu->reg[0].u32 = 87;
            return;
        }
        U32 required = static_cast<U32>(value.size() + 1);
        U32 capacity = session->memory->readd(sizeAddress);
        session->memory->writed(sizeAddress, required);
        if (typeAddress) {
            session->memory->writed(typeAddress, 1); // REG_SZ
        }
        if (dataAddress) {
            if (capacity < required ||
                !session->memory->canWrite(dataAddress, required)) {
                cpu->reg[0].u32 = 234; // ERROR_MORE_DATA
                return;
            }
            session->memory->strcpy(dataAddress, value.c_str());
        }
        printf(
            "Sugarbomb Win32 registry: RegQueryValueExA(%s, %s) -> %s\n",
            key->second.c_str(),
            valueName.empty() ? "(Default)" : valueName.c_str(),
            value.c_str());
        cpu->reg[0].u32 = 0;
    }

    static void callbackRegSetValueExA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "ADVAPI32!RegSetValueExA");
        if (session) {
            U32 handle = argument(cpu, 0);
            cpu->reg[0].u32 =
                (handle >= 0x80000000 || session->registryKeys.find(handle) != session->registryKeys.end())
                ? 0
                : 6;
        }
    }

    static void callbackBinkSetSoundSystem(CPU* cpu) {
        if (current(cpu, "BINKW32!BinkSetSoundSystem")) {
            cpu->reg[0].u32 = 1;
        }
    }

    static void callbackBinkOpenDirectSound(CPU* cpu) {
        if (current(cpu, "BINKW32!BinkOpenDirectSound")) {
            cpu->reg[0].u32 = 1;
        }
    }

    static void callbackBinkOpen(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "BINKW32!BinkOpen");
        if (!session) {
            return;
        }
        U32 nameAddress = argument(cpu, 0);
        U32 flags = argument(cpu, 1);
        U32 movieAddress = session->allocateGuestHeap(0x100, true);
        if (!movieAddress) {
            cpu->reg[0].u32 = 0;
            return;
        }
        BinkMovie movie;
        movie.openFlags = flags;
        session->binkMovies[movieAddress] = movie;

        // The public BINK header begins with these fields. Keeping them in
        // guest memory lets Fallout's own video wrapper inspect dimensions and
        // frame counts exactly as it does with the original 32-bit DLL.
        session->memory->writed(movieAddress + 0x00, movie.width);
        session->memory->writed(movieAddress + 0x04, movie.height);
        session->memory->writed(movieAddress + 0x08, movie.frames);
        session->memory->writed(movieAddress + 0x0c, movie.frame);
        session->memory->writed(movieAddress + 0x10, 0);
        session->memory->writed(movieAddress + 0x14, 30);
        session->memory->writed(movieAddress + 0x18, 1);
        session->memory->writed(movieAddress + 0x20, flags);
        printf(
            "Sugarbomb Bink: opened %s as synthetic %ux%u/%u-frame movie at 0x%08X\n",
            nameAddress ? session->readAnsi(nameAddress).c_str() : "<memory>",
            movie.width,
            movie.height,
            movie.frames,
            movieAddress);
        cpu->reg[0].u32 = movieAddress;
    }

    static void callbackBinkClose(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "BINKW32!BinkClose");
        if (!session) {
            return;
        }
        U32 movieAddress = argument(cpu, 0);
        session->binkMovies.erase(movieAddress);
        auto allocation = session->heapAllocations.find(movieAddress);
        if (allocation != session->heapAllocations.end()) {
            session->freeGuestHeap(movieAddress);
        }
        cpu->reg[0].u32 = 0;
    }

    static void callbackBinkNextFrame(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "BINKW32!BinkNextFrame");
        if (!session) {
            return;
        }
        U32 movieAddress = argument(cpu, 0);
        auto found = session->binkMovies.find(movieAddress);
        if (found != session->binkMovies.end() && !found->second.paused) {
            BinkMovie& movie = found->second;
            movie.frame = std::min(movie.frame + 1, movie.frames);
            session->memory->writed(movieAddress + 0x0c, movie.frame);
        }
        cpu->reg[0].u32 = 0;
    }

    static void callbackBinkWait(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "BINKW32!BinkWait");
        if (!session) {
            return;
        }
        auto found = session->binkMovies.find(argument(cpu, 0));
        cpu->reg[0].u32 =
            found != session->binkMovies.end() && found->second.paused
            ? 1
            : 0;
    }

    static void callbackBinkPause(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "BINKW32!BinkPause");
        if (!session) {
            return;
        }
        auto found = session->binkMovies.find(argument(cpu, 0));
        if (found == session->binkMovies.end()) {
            cpu->reg[0].u32 = 0;
            return;
        }
        found->second.paused = argument(cpu, 1) != 0;
        cpu->reg[0].u32 = 1;
    }

    static void callbackBinkDoFrame(CPU* cpu) {
        if (current(cpu, "BINKW32!BinkDoFrame")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackBinkCopyToBufferRect(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "BINKW32!BinkCopyToBufferRect");
        if (!session) {
            return;
        }
        cpu->reg[0].u32 =
            session->binkMovies.find(argument(cpu, 0)) !=
                session->binkMovies.end()
            ? 1
            : 0;
    }

    static void callbackSteamUnavailable(CPU* cpu) {
        if (current(cpu, "STEAM_API!Unavailable")) {
            cpu->reg[0].u32 = 1;
        }
    }

    static void callbackSteamInterfaceUnavailable(CPU* cpu) {
        if (current(cpu, "STEAM_API!InterfaceUnavailable")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackSteamNoOp(CPU* cpu) {
        if (current(cpu, "STEAM_API!NoOp")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackCoInitialize(CPU* cpu) {
        if (current(cpu, "OLE32!CoInitialize")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackCoInitializeEx(CPU* cpu) {
        if (current(cpu, "OLE32!CoInitializeEx")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackCoTaskMemAlloc(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "OLE32!CoTaskMemAlloc");
        if (session) {
            cpu->reg[0].u32 = session->allocateGuestHeap(argument(cpu, 0), false);
        }
    }

    static void callbackCoTaskMemFree(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "OLE32!CoTaskMemFree");
        if (session) {
            session->freeGuestHeap(argument(cpu, 0));
        }
    }

    static void callbackCoNoOp(CPU* cpu) {
        if (current(cpu, "OLE32!NoOp")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackCoCreateInstance(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "OLE32!CoCreateInstance");
        if (!session) {
            return;
        }
        U32 classId = argument(cpu, 0);
        U32 outer = argument(cpu, 1);
        U32 interfaceId = argument(cpu, 3);
        U32 resultAddress = argument(cpu, 4);
        if (!resultAddress) {
            cpu->reg[0].u32 = 0x80004003; // E_POINTER
            return;
        }
        session->memory->writed(resultAddress, 0);
        if (outer) {
            cpu->reg[0].u32 = 0x80040110; // CLASS_E_NOAGGREGATION
            return;
        }

        // CLSID_FilterGraph. Fallout uses DirectShow only for streamed music.
        if (classId &&
            session->memory->canRead(classId, 16) &&
            session->memory->readd(classId) == 0xe436ebb3) {
            DirectShowInterfaceKind kind = DirectShowInterfaceKind::FilterGraph;
            if (!session->directShowInterfaceKindForIid(interfaceId, kind)) {
                cpu->reg[0].u32 = 0x80004002; // E_NOINTERFACE
                return;
            }
            U32 graph = session->createDirectShowGraph(kind);
            session->memory->writed(resultAddress, graph);
            printf(
                "Sugarbomb DirectShow: CoCreateInstance(CLSID_FilterGraph) -> 0x%08X\n",
                graph);
            cpu->reg[0].u32 = graph ? 0 : 0x8007000e;
            return;
        }
        cpu->reg[0].u32 = 0x80004002; // E_NOINTERFACE
    }

    bool initializeDirectShowComThunks() {
        struct ThunkSpec {
            const char* name;
            U16 stackCleanupBytes;
        };
        static const ThunkSpec filterGraphMethods[] = {
            {"IFilterGraph::QueryInterface", 12},
            {"IFilterGraph::AddRef", 4},
            {"IFilterGraph::Release", 4},
            {"IFilterGraph::AddFilter", 12},
            {"IFilterGraph::RemoveFilter", 8},
            {"IFilterGraph::EnumFilters", 8},
            {"IFilterGraph::FindFilterByName", 12},
            {"IFilterGraph::ConnectDirect", 16},
            {"IFilterGraph::Reconnect", 8},
            {"IFilterGraph::Disconnect", 8},
            {"IFilterGraph::SetDefaultSyncSource", 4},
        };
        static const ThunkSpec graphBuilderMethods[] = {
            {"IGraphBuilder::QueryInterface", 12},
            {"IGraphBuilder::AddRef", 4},
            {"IGraphBuilder::Release", 4},
            {"IGraphBuilder::AddFilter", 12},
            {"IGraphBuilder::RemoveFilter", 8},
            {"IGraphBuilder::EnumFilters", 8},
            {"IGraphBuilder::FindFilterByName", 12},
            {"IGraphBuilder::ConnectDirect", 16},
            {"IGraphBuilder::Reconnect", 8},
            {"IGraphBuilder::Disconnect", 8},
            {"IGraphBuilder::SetDefaultSyncSource", 4},
            {"IGraphBuilder::Connect", 12},
            {"IGraphBuilder::Render", 8},
            {"IGraphBuilder::RenderFile", 12},
            {"IGraphBuilder::AddSourceFilter", 16},
            {"IGraphBuilder::SetLogFile", 8},
            {"IGraphBuilder::Abort", 4},
            {"IGraphBuilder::ShouldOperationContinue", 4},
        };
        static const ThunkSpec mediaControlMethods[] = {
            {"IMediaControl::QueryInterface", 12},
            {"IMediaControl::AddRef", 4},
            {"IMediaControl::Release", 4},
            {"IMediaControl::GetTypeInfoCount", 8},
            {"IMediaControl::GetTypeInfo", 16},
            {"IMediaControl::GetIDsOfNames", 28},
            {"IMediaControl::Invoke", 36},
            {"IMediaControl::Run", 4},
            {"IMediaControl::Pause", 4},
            {"IMediaControl::Stop", 4},
            {"IMediaControl::GetState", 12},
            {"IMediaControl::RenderFile", 8},
            {"IMediaControl::AddSourceFilter", 12},
            {"IMediaControl::get_FilterCollection", 8},
            {"IMediaControl::get_RegFilterCollection", 8},
            {"IMediaControl::StopWhenReady", 4},
        };
        static const ThunkSpec mediaPositionMethods[] = {
            {"IMediaPosition::QueryInterface", 12},
            {"IMediaPosition::AddRef", 4},
            {"IMediaPosition::Release", 4},
            {"IMediaPosition::GetTypeInfoCount", 8},
            {"IMediaPosition::GetTypeInfo", 16},
            {"IMediaPosition::GetIDsOfNames", 28},
            {"IMediaPosition::Invoke", 36},
            {"IMediaPosition::get_Duration", 8},
            {"IMediaPosition::put_CurrentPosition", 12},
            {"IMediaPosition::get_CurrentPosition", 8},
            {"IMediaPosition::get_StopTime", 8},
            {"IMediaPosition::put_StopTime", 12},
            {"IMediaPosition::get_PrerollTime", 8},
            {"IMediaPosition::put_PrerollTime", 12},
            {"IMediaPosition::put_Rate", 12},
            {"IMediaPosition::get_Rate", 8},
            {"IMediaPosition::CanSeekForward", 8},
            {"IMediaPosition::CanSeekBackward", 8},
        };
        static const ThunkSpec basicAudioMethods[] = {
            {"IBasicAudio::QueryInterface", 12},
            {"IBasicAudio::AddRef", 4},
            {"IBasicAudio::Release", 4},
            {"IBasicAudio::GetTypeInfoCount", 8},
            {"IBasicAudio::GetTypeInfo", 16},
            {"IBasicAudio::GetIDsOfNames", 28},
            {"IBasicAudio::Invoke", 36},
            {"IBasicAudio::put_Volume", 8},
            {"IBasicAudio::get_Volume", 8},
            {"IBasicAudio::put_Balance", 8},
            {"IBasicAudio::get_Balance", 8},
        };
        static const ThunkSpec mediaEventMethods[] = {
            {"IMediaEvent::QueryInterface", 12},
            {"IMediaEvent::AddRef", 4},
            {"IMediaEvent::Release", 4},
            {"IMediaEvent::GetTypeInfoCount", 8},
            {"IMediaEvent::GetTypeInfo", 16},
            {"IMediaEvent::GetIDsOfNames", 28},
            {"IMediaEvent::Invoke", 36},
            {"IMediaEvent::GetEventHandle", 8},
            {"IMediaEvent::GetEvent", 20},
            {"IMediaEvent::WaitForCompletion", 12},
            {"IMediaEvent::CancelDefaultHandling", 8},
            {"IMediaEvent::RestoreDefaultHandling", 8},
            {"IMediaEvent::FreeEventParams", 16},
        };

        auto createMethods = [&](
            const ThunkSpec* methods,
            U32 count,
            DirectShowInterfaceKind kind) {
            std::vector<U32>& vtable =
                directShowVtables[static_cast<U32>(kind)];
            for (U32 index = 0; index < count; ++index) {
                U32 callbackIndex = SugarbombBridge::registerCallback(
                    "DIRECTSHOW.COM",
                    methods[index].name,
                    callbackDirectShowComMethod);
                U32 guestAddress = 0;
                if (!thunks.createThunk(
                        callbackIndex,
                        methods[index].stackCleanupBytes,
                        guestAddress,
                        error)) {
                    return false;
                }
                DirectShowComMethod method;
                method.kind = kind;
                method.index = index;
                directShowComMethods[callbackIndex] = method;
                vtable.push_back(guestAddress);
            }
            return true;
        };

        return
            createMethods(
                filterGraphMethods,
                sizeof(filterGraphMethods) / sizeof(filterGraphMethods[0]),
                DirectShowInterfaceKind::FilterGraph) &&
            createMethods(
                graphBuilderMethods,
                sizeof(graphBuilderMethods) / sizeof(graphBuilderMethods[0]),
                DirectShowInterfaceKind::GraphBuilder) &&
            createMethods(
                mediaControlMethods,
                sizeof(mediaControlMethods) / sizeof(mediaControlMethods[0]),
                DirectShowInterfaceKind::MediaControl) &&
            createMethods(
                mediaPositionMethods,
                sizeof(mediaPositionMethods) / sizeof(mediaPositionMethods[0]),
                DirectShowInterfaceKind::MediaPosition) &&
            createMethods(
                basicAudioMethods,
                sizeof(basicAudioMethods) / sizeof(basicAudioMethods[0]),
                DirectShowInterfaceKind::BasicAudio) &&
            createMethods(
                mediaEventMethods,
                sizeof(mediaEventMethods) / sizeof(mediaEventMethods[0]),
                DirectShowInterfaceKind::MediaEvent);
    }

    bool ensureDirectShowVtables() {
        if (directShowVtableBlock) {
            return true;
        }
        U32 totalBytes = 0;
        for (const auto& entry : directShowVtables) {
            totalBytes += static_cast<U32>(entry.second.size() * sizeof(U32));
        }
        directShowVtableBlock = allocateGuestHeap(totalBytes, true);
        if (!directShowVtableBlock) {
            return false;
        }
        U32 cursor = directShowVtableBlock;
        for (const auto& entry : directShowVtables) {
            directShowVtableAddresses[entry.first] = cursor;
            for (U32 index = 0; index < entry.second.size(); ++index) {
                memory->writed(cursor + index * sizeof(U32), entry.second[index]);
            }
            cursor += static_cast<U32>(entry.second.size() * sizeof(U32));
        }
        return true;
    }

    bool directShowInterfaceKindForIid(
        U32 interfaceId,
        DirectShowInterfaceKind& kind) const {
        if (!interfaceId || !memory->canRead(interfaceId, 16)) {
            return false;
        }
        switch (memory->readd(interfaceId)) {
        case 0x00000000: // IID_IUnknown
        case 0x56a8689f: // IID_IFilterGraph
            kind = DirectShowInterfaceKind::FilterGraph;
            return true;
        case 0x56a868a9: // IID_IGraphBuilder
            kind = DirectShowInterfaceKind::GraphBuilder;
            return true;
        case 0x56a868b1: // IID_IMediaControl
            kind = DirectShowInterfaceKind::MediaControl;
            return true;
        case 0x56a868b2: // IID_IMediaPosition
            kind = DirectShowInterfaceKind::MediaPosition;
            return true;
        case 0x56a868b3: // IID_IBasicAudio
            kind = DirectShowInterfaceKind::BasicAudio;
            return true;
        case 0x56a868b6: // IID_IMediaEvent
        case 0x56a868c0: // IID_IMediaEventEx
            kind = DirectShowInterfaceKind::MediaEvent;
            return true;
        default:
            return false;
        }
    }

    U32 createDirectShowGraph(DirectShowInterfaceKind requestedKind) {
        if (!ensureDirectShowVtables()) {
            return 0;
        }
        constexpr U32 interfaceCount =
            static_cast<U32>(DirectShowInterfaceKind::Count);
        U32 interfaceBlock = allocateGuestHeap(interfaceCount * 8, true);
        if (!interfaceBlock) {
            return 0;
        }
        DirectShowGraph graph;
        for (U32 index = 0; index < interfaceCount; ++index) {
            U32 interfaceAddress = interfaceBlock + index * 8;
            graph.interfaceAddresses[index] = interfaceAddress;
            DirectShowInterface interfaceObject;
            interfaceObject.kind = static_cast<DirectShowInterfaceKind>(index);
            interfaceObject.graphAddress = interfaceBlock;
            directShowInterfaces[interfaceAddress] = interfaceObject;
            memory->writed(interfaceAddress, directShowVtableAddresses[index]);
            memory->writed(interfaceAddress + 4, interfaceBlock);
        }
        directShowGraphs[interfaceBlock] = graph;
        return graph.interfaceAddresses[static_cast<U32>(requestedKind)];
    }

    static void writeGuestDouble(
        SugarbombRuntimeSession* session,
        U32 address,
        double value) {
        if (!address) {
            return;
        }
        U64 bits = 0;
        memcpy(&bits, &value, sizeof(bits));
        session->memory->writeq(address, bits);
    }

    static double argumentDouble(CPU* cpu, U32 index) {
        U64 bits =
            static_cast<U64>(argument(cpu, index)) |
            (static_cast<U64>(argument(cpu, index + 1)) << 32);
        double value = 0.0;
        memcpy(&value, &bits, sizeof(value));
        return value;
    }

    bool readGuestVa32(U32& cursor, U32& value) {
        if (cursor > std::numeric_limits<U32>::max() - 4 ||
            !memory->canRead(cursor, 4)) {
            return false;
        }
        value = memory->readd(cursor);
        cursor += 4;
        return true;
    }

    bool readGuestVa64(U32& cursor, U64& value) {
        if (cursor > std::numeric_limits<U32>::max() - 8 ||
            !memory->canRead(cursor, 8)) {
            return false;
        }
        value = memory->readq(cursor);
        cursor += 8;
        return true;
    }

    bool readGuestWideString(
        U32 address,
        std::string& value,
        U32 limit = 1024 * 1024) {
        value.clear();
        if (!address) {
            return false;
        }
        for (U32 index = 0; index < limit; ++index) {
            const U64 characterAddress =
                static_cast<U64>(address) +
                static_cast<U64>(index) * 2;
            if (characterAddress >
                    std::numeric_limits<U32>::max() - 1ULL ||
                !memory->canRead(
                    static_cast<U32>(characterAddress),
                    2)) {
                return false;
            }
            U16 character =
                memory->readw(static_cast<U32>(characterAddress));
            if (!character) {
                return true;
            }
            value.push_back(
                character <= 0x7f
                ? static_cast<char>(character)
                : '?');
        }
        return false;
    }

    template <typename Value>
    static bool appendHostFormatted(
        std::string& output,
        const std::string& format,
        Value value) {
        int required =
            std::snprintf(nullptr, 0, format.c_str(), value);
        if (required < 0 ||
            static_cast<U64>(output.size()) +
                    static_cast<U32>(required) >
                16 * 1024 * 1024ULL) {
            return false;
        }
        std::vector<char> buffer(
            static_cast<std::size_t>(required) + 1);
        int written = std::snprintf(
            buffer.data(),
            buffer.size(),
            format.c_str(),
            value);
        if (written != required) {
            return false;
        }
        output.append(
            buffer.data(),
            static_cast<std::size_t>(written));
        return true;
    }

    bool formatGuestPrintf(
        const std::string& format,
        U32 vaList,
        bool wideFormat,
        std::string& output) {
        output.clear();
        U32 cursor = vaList;
        for (std::size_t index = 0;
             index < format.size();) {
            if (format[index] != '%') {
                output.push_back(format[index++]);
                continue;
            }
            ++index;
            if (index >= format.size()) {
                return false;
            }
            if (format[index] == '%') {
                output.push_back('%');
                ++index;
                continue;
            }

            std::string flags;
            while (index < format.size() &&
                   std::string("-+ #0").find(format[index]) !=
                       std::string::npos) {
                flags.push_back(format[index++]);
            }

            bool widthPresent = false;
            S32 width = 0;
            if (index < format.size() &&
                format[index] == '*') {
                U32 rawWidth = 0;
                if (!readGuestVa32(cursor, rawWidth)) {
                    return false;
                }
                width = static_cast<S32>(rawWidth);
                widthPresent = true;
                ++index;
                if (width < 0) {
                    if (flags.find('-') == std::string::npos) {
                        flags.push_back('-');
                    }
                    width = width == std::numeric_limits<S32>::min()
                        ? std::numeric_limits<S32>::max()
                        : -width;
                }
            } else {
                while (index < format.size() &&
                       std::isdigit(
                           static_cast<unsigned char>(
                               format[index]))) {
                    widthPresent = true;
                    if (width > 1000000) {
                        return false;
                    }
                    width =
                        width * 10 + (format[index++] - '0');
                }
            }

            bool precisionPresent = false;
            S32 precision = 0;
            if (index < format.size() &&
                format[index] == '.') {
                ++index;
                precisionPresent = true;
                if (index < format.size() &&
                    format[index] == '*') {
                    U32 rawPrecision = 0;
                    if (!readGuestVa32(
                            cursor,
                            rawPrecision)) {
                        return false;
                    }
                    precision =
                        static_cast<S32>(rawPrecision);
                    ++index;
                    if (precision < 0) {
                        precisionPresent = false;
                        precision = 0;
                    }
                } else {
                    while (index < format.size() &&
                           std::isdigit(
                               static_cast<unsigned char>(
                                   format[index]))) {
                        if (precision > 1000000) {
                            return false;
                        }
                        precision =
                            precision * 10 +
                            (format[index++] - '0');
                    }
                }
            }

            std::string length;
            if (index + 2 < format.size() &&
                format.compare(index, 3, "I64") == 0) {
                length = "I64";
                index += 3;
            } else if (
                index + 2 < format.size() &&
                format.compare(index, 3, "I32") == 0) {
                length = "I32";
                index += 3;
            } else if (
                index + 1 < format.size() &&
                (format.compare(index, 2, "hh") == 0 ||
                 format.compare(index, 2, "ll") == 0)) {
                length = format.substr(index, 2);
                index += 2;
            } else if (
                index < format.size() &&
                std::string("hljztLw").find(format[index]) !=
                    std::string::npos) {
                length.push_back(format[index++]);
            }
            if (index >= format.size()) {
                return false;
            }
            char conversion = format[index++];

            std::string hostPrefix = "%" + flags;
            if (widthPresent) {
                hostPrefix += std::to_string(width);
            }
            if (precisionPresent) {
                hostPrefix += "." +
                    std::to_string(precision);
            }

            if (conversion == 'n') {
                U32 destination = 0;
                if (!readGuestVa32(cursor, destination)) {
                    return false;
                }
                U32 size =
                    length == "hh" ? 1 :
                    (length == "h" ? 2 :
                     ((length == "ll" ||
                       length == "I64") ? 8 : 4));
                if (!destination ||
                    !memory->canWrite(destination, size)) {
                    return false;
                }
                if (size == 1) {
                    memory->writeb(
                        destination,
                        static_cast<U8>(output.size()));
                } else if (size == 2) {
                    memory->writew(
                        destination,
                        static_cast<U16>(output.size()));
                } else if (size == 8) {
                    memory->writeq(
                        destination,
                        static_cast<U64>(output.size()));
                } else {
                    memory->writed(
                        destination,
                        static_cast<U32>(output.size()));
                }
                continue;
            }

            if (conversion == 's' ||
                conversion == 'S') {
                U32 source = 0;
                if (!readGuestVa32(cursor, source)) {
                    return false;
                }
                bool wideString =
                    wideFormat
                    ? (conversion == 's' &&
                       length != "h")
                    : ((conversion == 's' &&
                        (length == "l" ||
                         length == "w")) ||
                       (conversion == 'S' &&
                        length != "h"));
                std::string value;
                if (!source) {
                    value = "(null)";
                } else if (wideString) {
                    if (!readGuestWideString(source, value)) {
                        return false;
                    }
                } else {
                    U32 valueLength = 0;
                    if (!guestCStringLength(
                            source,
                            valueLength,
                            1024 * 1024)) {
                        return false;
                    }
                    value = readAnsi(source, valueLength + 1);
                }
                if (!appendHostFormatted(
                        output,
                        hostPrefix + "s",
                        value.c_str())) {
                    return false;
                }
                continue;
            }

            if (conversion == 'c' ||
                conversion == 'C') {
                U32 raw = 0;
                if (!readGuestVa32(cursor, raw)) {
                    return false;
                }
                char character =
                    raw <= 0x7f
                    ? static_cast<char>(raw)
                    : '?';
                if (!appendHostFormatted(
                        output,
                        hostPrefix + "c",
                        character)) {
                    return false;
                }
                continue;
            }

            if (std::string("di").find(conversion) !=
                std::string::npos) {
                S64 value = 0;
                if (length == "ll" ||
                    length == "I64") {
                    U64 raw = 0;
                    if (!readGuestVa64(cursor, raw)) {
                        return false;
                    }
                    value = static_cast<S64>(raw);
                } else {
                    U32 raw = 0;
                    if (!readGuestVa32(cursor, raw)) {
                        return false;
                    }
                    value = length == "hh"
                        ? static_cast<S8>(raw)
                        : (length == "h"
                           ? static_cast<S16>(raw)
                           : static_cast<S32>(raw));
                }
                if (!appendHostFormatted(
                        output,
                        hostPrefix + "ll" + conversion,
                        static_cast<long long>(value))) {
                    return false;
                }
                continue;
            }

            if (std::string("uoxX").find(conversion) !=
                std::string::npos) {
                U64 value = 0;
                if (length == "ll" ||
                    length == "I64") {
                    if (!readGuestVa64(cursor, value)) {
                        return false;
                    }
                } else {
                    U32 raw = 0;
                    if (!readGuestVa32(cursor, raw)) {
                        return false;
                    }
                    value = length == "hh"
                        ? static_cast<U8>(raw)
                        : (length == "h"
                           ? static_cast<U16>(raw)
                           : raw);
                }
                if (!appendHostFormatted(
                        output,
                        hostPrefix + "ll" + conversion,
                        static_cast<unsigned long long>(value))) {
                    return false;
                }
                continue;
            }

            if (conversion == 'p') {
                U32 value = 0;
                if (!readGuestVa32(cursor, value)) {
                    return false;
                }
                char pointer[11] = {};
                std::snprintf(
                    pointer,
                    sizeof(pointer),
                    "0x%08X",
                    value);
                if (!appendHostFormatted(
                        output,
                        hostPrefix + "s",
                        pointer)) {
                    return false;
                }
                continue;
            }

            if (std::string("fFeEgGaA").find(conversion) !=
                std::string::npos) {
                U64 raw = 0;
                if (!readGuestVa64(cursor, raw)) {
                    return false;
                }
                double value = 0.0;
                memcpy(&value, &raw, sizeof(value));
                if (!appendHostFormatted(
                        output,
                        hostPrefix + conversion,
                        value)) {
                    return false;
                }
                continue;
            }
            return false;
        }
        return true;
    }

    bool writeGuestScannedInteger(
        U32 destination,
        const std::string& length,
        U64 value) {
        U32 size =
            length == "hh" ? 1 :
            (length == "h" ? 2 :
             ((length == "ll" ||
               length == "I64" ||
               length == "j") ? 8 : 4));
        if (!destination ||
            !memory->canWrite(destination, size)) {
            return false;
        }
        if (size == 1) {
            memory->writeb(destination, static_cast<U8>(value));
        } else if (size == 2) {
            memory->writew(destination, static_cast<U16>(value));
        } else if (size == 8) {
            memory->writeq(destination, value);
        } else {
            memory->writed(destination, static_cast<U32>(value));
        }
        return true;
    }

    bool formatGuestScanf(
        const std::string& input,
        const std::string& format,
        U32 vaList,
        S32& result) {
        std::size_t inputIndex = 0;
        std::size_t formatIndex = 0;
        U32 cursor = vaList;
        S32 assignments = 0;
        bool inputFailure = false;

        while (formatIndex < format.size()) {
            unsigned char formatCharacter =
                static_cast<unsigned char>(
                    format[formatIndex]);
            if (std::isspace(formatCharacter)) {
                while (formatIndex < format.size() &&
                       std::isspace(
                           static_cast<unsigned char>(
                               format[formatIndex]))) {
                    ++formatIndex;
                }
                while (inputIndex < input.size() &&
                       std::isspace(
                           static_cast<unsigned char>(
                               input[inputIndex]))) {
                    ++inputIndex;
                }
                continue;
            }
            if (format[formatIndex] != '%') {
                if (inputIndex >= input.size()) {
                    inputFailure = true;
                    break;
                }
                if (input[inputIndex] !=
                    format[formatIndex]) {
                    break;
                }
                ++inputIndex;
                ++formatIndex;
                continue;
            }

            ++formatIndex;
            if (formatIndex >= format.size()) {
                result = -1;
                return false;
            }
            if (format[formatIndex] == '%') {
                if (inputIndex >= input.size()) {
                    inputFailure = true;
                    break;
                }
                if (input[inputIndex] != '%') {
                    break;
                }
                ++inputIndex;
                ++formatIndex;
                continue;
            }

            bool suppress = false;
            if (format[formatIndex] == '*') {
                suppress = true;
                ++formatIndex;
            }
            U32 width = 0;
            while (formatIndex < format.size() &&
                   std::isdigit(
                       static_cast<unsigned char>(
                           format[formatIndex]))) {
                if (width > 1000000) {
                    result = -1;
                    return false;
                }
                width =
                    width * 10 +
                    (format[formatIndex++] - '0');
            }

            std::string length;
            if (formatIndex + 2 < format.size() &&
                format.compare(
                    formatIndex,
                    3,
                    "I64") == 0) {
                length = "I64";
                formatIndex += 3;
            } else if (
                formatIndex + 2 < format.size() &&
                format.compare(
                    formatIndex,
                    3,
                    "I32") == 0) {
                length = "I32";
                formatIndex += 3;
            } else if (
                formatIndex + 1 < format.size() &&
                (format.compare(
                     formatIndex,
                     2,
                     "hh") == 0 ||
                 format.compare(
                     formatIndex,
                     2,
                     "ll") == 0)) {
                length = format.substr(formatIndex, 2);
                formatIndex += 2;
            } else if (
                formatIndex < format.size() &&
                std::string("hljztLw").find(
                    format[formatIndex]) !=
                    std::string::npos) {
                length.push_back(format[formatIndex++]);
            }
            if (formatIndex >= format.size()) {
                result = -1;
                return false;
            }
            char conversion = format[formatIndex++];

            if (conversion != 'c' &&
                conversion != 'C' &&
                conversion != '[' &&
                conversion != 'n') {
                while (inputIndex < input.size() &&
                       std::isspace(
                           static_cast<unsigned char>(
                               input[inputIndex]))) {
                    ++inputIndex;
                }
            }

            if (conversion == 'n') {
                if (!suppress) {
                    U32 destination = 0;
                    if (!readGuestVa32(
                            cursor,
                            destination) ||
                        !writeGuestScannedInteger(
                            destination,
                            length,
                            inputIndex)) {
                        result = -1;
                        return false;
                    }
                }
                continue;
            }

            std::size_t available =
                input.size() - inputIndex;
            std::size_t limit =
                width
                ? std::min<std::size_t>(available, width)
                : available;
            if (!limit) {
                inputFailure = true;
                break;
            }

            if (std::string("diuoxXp").find(conversion) !=
                std::string::npos) {
                std::string token =
                    input.substr(inputIndex, limit);
                char* end = nullptr;
                U64 value = 0;
                if (conversion == 'd' ||
                    conversion == 'i') {
                    int base = conversion == 'i' ? 0 : 10;
                    value = static_cast<U64>(
                        std::strtoll(
                            token.c_str(),
                            &end,
                            base));
                } else {
                    int base =
                        conversion == 'o' ? 8 :
                        ((conversion == 'x' ||
                          conversion == 'X' ||
                          conversion == 'p') ? 16 : 10);
                    value = std::strtoull(
                        token.c_str(),
                        &end,
                        base);
                }
                std::size_t consumed =
                    static_cast<std::size_t>(
                        end - token.c_str());
                if (!consumed) {
                    break;
                }
                inputIndex += consumed;
                if (!suppress) {
                    U32 destination = 0;
                    if (!readGuestVa32(
                            cursor,
                            destination) ||
                        !writeGuestScannedInteger(
                            destination,
                            conversion == 'p'
                                ? std::string()
                                : length,
                            value)) {
                        result = -1;
                        return false;
                    }
                    ++assignments;
                }
                continue;
            }

            if (std::string("fFeEgGaA").find(conversion) !=
                std::string::npos) {
                std::string token =
                    input.substr(inputIndex, limit);
                char* end = nullptr;
                double value =
                    std::strtod(token.c_str(), &end);
                std::size_t consumed =
                    static_cast<std::size_t>(
                        end - token.c_str());
                if (!consumed) {
                    break;
                }
                inputIndex += consumed;
                if (!suppress) {
                    U32 destination = 0;
                    bool doubleDestination =
                        length == "l" ||
                        length == "L";
                    U32 size =
                        doubleDestination ? 8 : 4;
                    if (!readGuestVa32(
                            cursor,
                            destination) ||
                        !destination ||
                        !memory->canWrite(
                            destination,
                            size)) {
                        result = -1;
                        return false;
                    }
                    if (doubleDestination) {
                        U64 bits = 0;
                        memcpy(
                            &bits,
                            &value,
                            sizeof(bits));
                        memory->writeq(destination, bits);
                    } else {
                        float single =
                            static_cast<float>(value);
                        U32 bits = 0;
                        memcpy(
                            &bits,
                            &single,
                            sizeof(bits));
                        memory->writed(destination, bits);
                    }
                    ++assignments;
                }
                continue;
            }

            bool scanset = conversion == '[';
            std::array<bool, 256> accepted = {};
            bool invert = false;
            if (scanset) {
                if (formatIndex < format.size() &&
                    format[formatIndex] == '^') {
                    invert = true;
                    ++formatIndex;
                }
                bool first = true;
                int previous = -1;
                while (formatIndex < format.size() &&
                       (first ||
                        format[formatIndex] != ']')) {
                    unsigned char character =
                        static_cast<unsigned char>(
                            format[formatIndex++]);
                    if (character == '-' &&
                        previous >= 0 &&
                        formatIndex < format.size() &&
                        format[formatIndex] != ']') {
                        unsigned char last =
                            static_cast<unsigned char>(
                                format[formatIndex++]);
                        for (int value = previous;
                             value <= last;
                             ++value) {
                            accepted[
                                static_cast<U8>(value)] = true;
                        }
                        previous = last;
                    } else {
                        accepted[character] = true;
                        previous = character;
                    }
                    first = false;
                }
                if (formatIndex >= format.size() ||
                    format[formatIndex] != ']') {
                    result = -1;
                    return false;
                }
                ++formatIndex;
            }

            if (conversion == 's' ||
                conversion == 'S' ||
                conversion == 'c' ||
                conversion == 'C' ||
                scanset) {
                std::size_t consumed = 0;
                if (conversion == 'c' ||
                    conversion == 'C') {
                    consumed = width ? width : 1;
                    if (consumed > available) {
                        inputFailure = true;
                        break;
                    }
                } else {
                    while (consumed < limit) {
                        unsigned char character =
                            static_cast<unsigned char>(
                                input[inputIndex + consumed]);
                        if (scanset) {
                            bool matches =
                                accepted[character];
                            if (invert) {
                                matches = !matches;
                            }
                            if (!matches) {
                                break;
                            }
                        } else if (
                            std::isspace(character)) {
                            break;
                        }
                        ++consumed;
                    }
                    if (!consumed) {
                        break;
                    }
                }
                if (!suppress) {
                    U32 destination = 0;
                    if (!readGuestVa32(
                            cursor,
                            destination)) {
                        result = -1;
                        return false;
                    }
                    bool wideDestination =
                        conversion == 'S' ||
                        conversion == 'C' ||
                        length == "l" ||
                        length == "w";
                    U32 terminator =
                        (conversion == 'c' ||
                         conversion == 'C') ? 0 : 1;
                    U64 required =
                        (consumed + terminator) *
                        (wideDestination ? 2 : 1);
                    if (!destination ||
                        required >
                            std::numeric_limits<U32>::max() ||
                        !memory->canWrite(
                            destination,
                            static_cast<U32>(required))) {
                        result = -1;
                        return false;
                    }
                    for (U32 character = 0;
                         character < consumed;
                         ++character) {
                        U8 value = static_cast<U8>(
                            input[inputIndex + character]);
                        if (wideDestination) {
                            memory->writew(
                                destination + character * 2,
                                value);
                        } else {
                            memory->writeb(
                                destination + character,
                                value);
                        }
                    }
                    if (terminator) {
                        if (wideDestination) {
                            memory->writew(
                                destination +
                                    static_cast<U32>(
                                        consumed) * 2,
                                0);
                        } else {
                            memory->writeb(
                                destination +
                                    static_cast<U32>(
                                        consumed),
                                0);
                        }
                    }
                    ++assignments;
                }
                inputIndex += consumed;
                continue;
            }

            result = -1;
            return false;
        }
        result =
            inputFailure && !assignments
            ? -1
            : assignments;
        return true;
    }

    static void returnGuestDouble(CPU* cpu, double value) {
        U64 bits = 0;
        memcpy(&bits, &value, sizeof(bits));
        cpu->fpu.PREP_PUSH();
        cpu->fpu.FLD_F64(bits, cpu->fpu.STV(0));
    }

    static void callbackUcrtUnaryMath(
        CPU* cpu,
        const char* api,
        double (*operation)(double)) {
        SugarbombRuntimeSession* session =
            current(cpu, api);
        if (session) {
            returnGuestDouble(
                cpu,
                operation(argumentDouble(cpu, 0)));
        }
    }

    static void callbackUcrtBinaryMath(
        CPU* cpu,
        const char* api,
        double (*operation)(double, double)) {
        SugarbombRuntimeSession* session =
            current(cpu, api);
        if (session) {
            returnGuestDouble(
                cpu,
                operation(
                    argumentDouble(cpu, 0),
                    argumentDouble(cpu, 2)));
        }
    }

    static void callbackUcrtAcos(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!acos",
            static_cast<double (*)(double)>(std::acos));
    }

    static void callbackUcrtAsin(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!asin",
            static_cast<double (*)(double)>(std::asin));
    }

    static void callbackUcrtAtan(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!atan",
            static_cast<double (*)(double)>(std::atan));
    }

    static void callbackUcrtAtan2(CPU* cpu) {
        callbackUcrtBinaryMath(
            cpu,
            "UCRT!atan2",
            static_cast<double (*)(double, double)>(
                std::atan2));
    }

    static void callbackUcrtCeil(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!ceil",
            static_cast<double (*)(double)>(std::ceil));
    }

    static void callbackUcrtCos(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!cos",
            static_cast<double (*)(double)>(std::cos));
    }

    static void callbackUcrtCosh(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!cosh",
            static_cast<double (*)(double)>(std::cosh));
    }

    static void callbackUcrtExp(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!exp",
            static_cast<double (*)(double)>(std::exp));
    }

    static void callbackUcrtFabs(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!fabs",
            static_cast<double (*)(double)>(std::fabs));
    }

    static void callbackUcrtFloor(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!floor",
            static_cast<double (*)(double)>(std::floor));
    }

    static void callbackUcrtLog10(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!log10",
            static_cast<double (*)(double)>(std::log10));
    }

    static void callbackUcrtPow(CPU* cpu) {
        callbackUcrtBinaryMath(
            cpu,
            "UCRT!pow",
            static_cast<double (*)(double, double)>(
                std::pow));
    }

    static void callbackUcrtSin(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!sin",
            static_cast<double (*)(double)>(std::sin));
    }

    static void callbackUcrtSinh(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!sinh",
            static_cast<double (*)(double)>(std::sinh));
    }

    static void callbackUcrtSqrt(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!sqrt",
            static_cast<double (*)(double)>(std::sqrt));
    }

    static void callbackUcrtTan(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!tan",
            static_cast<double (*)(double)>(std::tan));
    }

    static void callbackUcrtTanh(CPU* cpu) {
        callbackUcrtUnaryMath(
            cpu,
            "UCRT!tanh",
            static_cast<double (*)(double)>(std::tanh));
    }

    static double directShowPosition(const DirectShowGraph& graph) {
        double position = graph.currentPositionSeconds;
        if (graph.filterState == 2 && graph.runStartedMicroseconds) {
            U64 now = KSystem::getMicroCounter();
            if (now >= graph.runStartedMicroseconds) {
                position +=
                    static_cast<double>(
                        now - graph.runStartedMicroseconds) /
                    1000000.0;
            }
        }
        return std::min(position, graph.durationSeconds);
    }

    static void pauseDirectShowGraph(DirectShowGraph& graph) {
        graph.currentPositionSeconds = directShowPosition(graph);
        graph.runStartedMicroseconds = 0;
    }

    void dispatchDirectShowComMethod(
        CPU* cpu,
        const DirectShowComMethod& method) {
        constexpr U32 S_OK = 0;
        constexpr U32 S_FALSE = 1;
        constexpr U32 E_NOTIMPL = 0x80004001;
        constexpr U32 E_NOINTERFACE = 0x80004002;
        constexpr U32 E_POINTER = 0x80004003;
        constexpr U32 E_ABORT = 0x80004004;

        U32 interfaceAddress = argument(cpu, 0);
        auto interfaceFound = directShowInterfaces.find(interfaceAddress);
        if (interfaceFound == directShowInterfaces.end() ||
            interfaceFound->second.kind != method.kind) {
            cpu->reg[0].u32 = E_POINTER;
            return;
        }
        auto graphFound =
            directShowGraphs.find(interfaceFound->second.graphAddress);
        if (graphFound == directShowGraphs.end()) {
            cpu->reg[0].u32 = E_POINTER;
            return;
        }
        DirectShowGraph& graph = graphFound->second;

        if (method.index == 0) { // QueryInterface
            U32 resultAddress = argument(cpu, 2);
            DirectShowInterfaceKind requested =
                DirectShowInterfaceKind::FilterGraph;
            if (!resultAddress) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            memory->writed(resultAddress, 0);
            if (!directShowInterfaceKindForIid(argument(cpu, 1), requested)) {
                cpu->reg[0].u32 = E_NOINTERFACE;
                return;
            }
            ++graph.references;
            memory->writed(
                resultAddress,
                graph.interfaceAddresses[static_cast<U32>(requested)]);
            cpu->reg[0].u32 = S_OK;
            return;
        }
        if (method.index == 1) { // AddRef
            cpu->reg[0].u32 = ++graph.references;
            return;
        }
        if (method.index == 2) { // Release
            if (graph.references) {
                --graph.references;
            }
            cpu->reg[0].u32 = graph.references;
            return;
        }

        if (method.kind == DirectShowInterfaceKind::FilterGraph ||
            method.kind == DirectShowInterfaceKind::GraphBuilder) {
            switch (method.index) {
            case 3: // AddFilter
            case 4: // RemoveFilter
            case 7: // ConnectDirect
            case 8: // Reconnect
            case 9: // Disconnect
            case 10: // SetDefaultSyncSource
            case 11: // IGraphBuilder::Connect
            case 12: // IGraphBuilder::Render
            case 13: // IGraphBuilder::RenderFile
            case 15: // IGraphBuilder::SetLogFile
            case 16: // IGraphBuilder::Abort
            case 17: // IGraphBuilder::ShouldOperationContinue
                cpu->reg[0].u32 = S_OK;
                return;
            case 5: // EnumFilters
                if (argument(cpu, 1)) {
                    memory->writed(argument(cpu, 1), 0);
                }
                cpu->reg[0].u32 = E_NOTIMPL;
                return;
            case 6: // FindFilterByName
                if (argument(cpu, 2)) {
                    memory->writed(argument(cpu, 2), 0);
                }
                cpu->reg[0].u32 = E_NOTIMPL;
                return;
            case 14: // IGraphBuilder::AddSourceFilter
                if (argument(cpu, 3)) {
                    memory->writed(argument(cpu, 3), 0);
                }
                cpu->reg[0].u32 = E_NOTIMPL;
                return;
            default:
                cpu->reg[0].u32 = E_NOTIMPL;
                return;
            }
        }

        // These four DirectShow automation interfaces inherit IDispatch.
        if (method.index == 3) { // GetTypeInfoCount
            if (argument(cpu, 1)) {
                memory->writed(argument(cpu, 1), 0);
            }
            cpu->reg[0].u32 = S_OK;
            return;
        }
        if (method.index >= 4 && method.index <= 6) {
            cpu->reg[0].u32 = E_NOTIMPL;
            return;
        }

        if (method.kind == DirectShowInterfaceKind::MediaControl) {
            switch (method.index) {
            case 7: // Run
                if (graph.filterState != 2) {
                    graph.runStartedMicroseconds =
                        KSystem::getMicroCounter();
                }
                graph.filterState = 2;
                cpu->reg[0].u32 = S_OK;
                return;
            case 8: // Pause
                pauseDirectShowGraph(graph);
                graph.filterState = 1;
                cpu->reg[0].u32 = S_OK;
                return;
            case 9: // Stop
            case 15: // StopWhenReady
                pauseDirectShowGraph(graph);
                graph.filterState = 0;
                cpu->reg[0].u32 = S_OK;
                return;
            case 10: // GetState
                if (!argument(cpu, 2)) {
                    cpu->reg[0].u32 = E_POINTER;
                } else {
                    memory->writed(argument(cpu, 2), graph.filterState);
                    cpu->reg[0].u32 = S_OK;
                }
                return;
            case 11: // RenderFile
            case 12: // AddSourceFilter
                cpu->reg[0].u32 = S_OK;
                return;
            case 13: // get_FilterCollection
            case 14: // get_RegFilterCollection
                if (argument(cpu, 1)) {
                    memory->writed(argument(cpu, 1), 0);
                }
                cpu->reg[0].u32 = E_NOTIMPL;
                return;
            default:
                cpu->reg[0].u32 = E_NOTIMPL;
                return;
            }
        }

        if (method.kind == DirectShowInterfaceKind::MediaPosition) {
            switch (method.index) {
            case 7: // get_Duration
            case 10: // get_StopTime
                if (!argument(cpu, 1)) {
                    cpu->reg[0].u32 = E_POINTER;
                } else {
                    writeGuestDouble(this, argument(cpu, 1), graph.durationSeconds);
                    cpu->reg[0].u32 = S_OK;
                }
                return;
            case 8: // put_CurrentPosition
                graph.currentPositionSeconds = argumentDouble(cpu, 1);
                if (graph.filterState == 2) {
                    graph.runStartedMicroseconds =
                        KSystem::getMicroCounter();
                }
                cpu->reg[0].u32 = S_OK;
                return;
            case 9: // get_CurrentPosition
                if (!argument(cpu, 1)) {
                    cpu->reg[0].u32 = E_POINTER;
                } else {
                    writeGuestDouble(
                        this,
                        argument(cpu, 1),
                        directShowPosition(graph));
                    cpu->reg[0].u32 = S_OK;
                }
                return;
            case 11: // put_StopTime
            case 13: // put_PrerollTime
            case 14: // put_Rate
                cpu->reg[0].u32 = S_OK;
                return;
            case 12: // get_PrerollTime
                writeGuestDouble(this, argument(cpu, 1), 0.0);
                cpu->reg[0].u32 = argument(cpu, 1) ? S_OK : E_POINTER;
                return;
            case 15: // get_Rate
                writeGuestDouble(this, argument(cpu, 1), 1.0);
                cpu->reg[0].u32 = argument(cpu, 1) ? S_OK : E_POINTER;
                return;
            case 16: // CanSeekForward
            case 17: // CanSeekBackward
                if (argument(cpu, 1)) {
                    memory->writed(argument(cpu, 1), 0xffff);
                    cpu->reg[0].u32 = S_OK;
                } else {
                    cpu->reg[0].u32 = E_POINTER;
                }
                return;
            default:
                cpu->reg[0].u32 = E_NOTIMPL;
                return;
            }
        }

        if (method.kind == DirectShowInterfaceKind::BasicAudio) {
            switch (method.index) {
            case 7: // put_Volume
                graph.volume = static_cast<S32>(argument(cpu, 1));
                cpu->reg[0].u32 = S_OK;
                return;
            case 8: // get_Volume
                if (argument(cpu, 1)) {
                    memory->writed(
                        argument(cpu, 1),
                        static_cast<U32>(graph.volume));
                    cpu->reg[0].u32 = S_OK;
                } else {
                    cpu->reg[0].u32 = E_POINTER;
                }
                return;
            case 9: // put_Balance
                cpu->reg[0].u32 = S_OK;
                return;
            case 10: // get_Balance
                if (argument(cpu, 1)) {
                    memory->writed(argument(cpu, 1), 0);
                    cpu->reg[0].u32 = S_OK;
                } else {
                    cpu->reg[0].u32 = E_POINTER;
                }
                return;
            default:
                cpu->reg[0].u32 = E_NOTIMPL;
                return;
            }
        }

        switch (method.index) {
        case 7: // IMediaEvent::GetEventHandle
            if (argument(cpu, 1)) {
                memory->writed(argument(cpu, 1), 0);
            }
            cpu->reg[0].u32 = E_NOTIMPL;
            return;
        case 8: // IMediaEvent::GetEvent
            for (U32 index = 1; index <= 3; ++index) {
                if (argument(cpu, index)) {
                    memory->writed(argument(cpu, index), 0);
                }
            }
            cpu->reg[0].u32 = E_ABORT;
            return;
        case 9: // IMediaEvent::WaitForCompletion
            if (argument(cpu, 2)) {
                memory->writed(argument(cpu, 2), 0);
            }
            cpu->reg[0].u32 = S_FALSE;
            return;
        case 10: // CancelDefaultHandling
        case 11: // RestoreDefaultHandling
        case 12: // FreeEventParams
            cpu->reg[0].u32 = S_OK;
            return;
        default:
            cpu->reg[0].u32 = E_NOTIMPL;
            return;
        }
    }

    static void callbackDirectShowComMethod(CPU* cpu) {
        if (!activeSession) {
            cpu->thread->terminating = true;
            return;
        }
        U32 callbackIndex = cpu->peek32(0);
        auto found = activeSession->directShowComMethods.find(callbackIndex);
        if (found == activeSession->directShowComMethods.end()) {
            callbackUnresolvedImport(cpu);
            return;
        }
        std::string module;
        std::string symbol;
        SugarbombBridge::callbackName(callbackIndex, module, symbol);
        std::string api = "DIRECTSHOW!" + symbol;
        SugarbombRuntimeSession* session = current(cpu, api.c_str());
        if (session) {
            session->dispatchDirectShowComMethod(cpu, found->second);
        }
    }

    bool ensureDirectInputVtables() {
        if (directInputVtableAddress && directInputDeviceVtableAddress) {
            return true;
        }
        directInputVtableAddress = allocateGuestHeap(
            static_cast<U32>(directInputVtable.size() * sizeof(U32)),
            true);
        directInputDeviceVtableAddress = allocateGuestHeap(
            static_cast<U32>(directInputDeviceVtable.size() * sizeof(U32)),
            true);
        if (!directInputVtableAddress || !directInputDeviceVtableAddress) {
            return false;
        }
        for (U32 index = 0; index < directInputVtable.size(); ++index) {
            memory->writed(
                directInputVtableAddress + index * sizeof(U32),
                directInputVtable[index]);
        }
        for (U32 index = 0; index < directInputDeviceVtable.size(); ++index) {
            memory->writed(
                directInputDeviceVtableAddress + index * sizeof(U32),
                directInputDeviceVtable[index]);
        }
        return true;
    }

    U32 createDirectInputObject(DirectInputObjectKind kind, U32 deviceGuidData1 = 0) {
        if (!ensureDirectInputVtables()) {
            return 0;
        }
        U32 objectAddress = allocateGuestHeap(8, true);
        if (!objectAddress) {
            return 0;
        }
        DirectInputObject object;
        object.kind = kind;
        object.deviceGuidData1 = deviceGuidData1;
        directInputObjects[objectAddress] = object;
        memory->writed(
            objectAddress,
            kind == DirectInputObjectKind::Device
                ? directInputDeviceVtableAddress
                : directInputVtableAddress);
        memory->writed(objectAddress + 4, 1);
        return objectAddress;
    }

    U32 directInputDeviceType(const DirectInputObject& object) const {
        if (object.deviceGuidData1 == 0x6f1d2b60) {
            return 0x12; // DI8DEVTYPE_MOUSE
        }
        if (object.deviceGuidData1 == 0x6f1d2b61) {
            return 0x13; // DI8DEVTYPE_KEYBOARD
        }
        return 0x11; // DI8DEVTYPE_DEVICE
    }

    bool isDirectInputMouse(const DirectInputObject& object) const {
        return object.kind == DirectInputObjectKind::Device &&
            object.deviceGuidData1 == 0x6f1d2b60;
    }

    bool isDirectInputKeyboard(const DirectInputObject& object) const {
        return object.kind == DirectInputObjectKind::Device &&
            object.deviceGuidData1 == 0x6f1d2b61;
    }

    bool hasDirectInputForegroundPriority(
        const DirectInputObject& object) const {
        constexpr U32 DISCL_FOREGROUND = 0x00000004;
        if (!(object.cooperativeFlags & DISCL_FOREGROUND)) {
            return true;
        }
        U32 cooperativeTopLevel =
            topLevelGuestWindow(object.cooperativeWindow);
        U32 activeTopLevel = topLevelGuestWindow(activeWindow);
        if (cooperativeTopLevel &&
            activeTopLevel &&
            cooperativeTopLevel != activeTopLevel) {
            return false;
        }
        U32 targetTopLevel =
            cooperativeTopLevel ? cooperativeTopLevel : activeTopLevel;
        if (hostWindow.nativeHandle()) {
            return targetTopLevel &&
                hostWindow.isGuestWindowForeground(targetTopLevel);
        }
        return targetTopLevel != 0;
    }

    void loseForegroundDirectInputDevices(U32 guestHandle) {
        constexpr U32 DISCL_FOREGROUND = 0x00000004;
        U32 lostTopLevel = topLevelGuestWindow(guestHandle);
        for (auto& entry : directInputObjects) {
            DirectInputObject& object = entry.second;
            if (object.kind != DirectInputObjectKind::Device ||
                !(object.cooperativeFlags & DISCL_FOREGROUND)) {
                continue;
            }
            U32 cooperativeTopLevel =
                topLevelGuestWindow(object.cooperativeWindow);
            if (cooperativeTopLevel &&
                cooperativeTopLevel != lostTopLevel) {
                continue;
            }
            object.acquired = false;
            object.mouseDeltaX = 0;
            object.mouseDeltaY = 0;
            object.mouseWheelDelta = 0;
            object.events.clear();
        }
        updateHostDirectInputMouseCapture();
    }

    void loseExclusiveDirectInputMouse() {
        constexpr U32 DISCL_EXCLUSIVE = 0x00000001;
        directInputMouseButtons.fill(0);
        for (auto& entry : directInputObjects) {
            DirectInputObject& object = entry.second;
            if (!isDirectInputMouse(object) ||
                !(object.cooperativeFlags & DISCL_EXCLUSIVE)) {
                continue;
            }
            object.acquired = false;
            object.mouseDeltaX = 0;
            object.mouseDeltaY = 0;
            object.mouseWheelDelta = 0;
            object.events.clear();
        }
        updateHostDirectInputMouseCapture();
    }

    void updateHostDirectInputMouseCapture() {
        constexpr U32 DISCL_EXCLUSIVE = 0x00000001;
        bool capture = false;
        for (const auto& entry : directInputObjects) {
            const DirectInputObject& object = entry.second;
            if (isDirectInputMouse(object) &&
                object.acquired &&
                (object.cooperativeFlags & DISCL_EXCLUSIVE) &&
                hasDirectInputForegroundPriority(object)) {
                capture = true;
                break;
            }
        }
        hostWindow.setMouseCapture(capture);
    }

    void queueDirectInputEvent(
        DirectInputObject& object,
        U32 offset,
        U32 data,
        U32 timestamp) {
        if (!object.acquired) {
            return;
        }
        DirectInputDeviceEvent event;
        event.offset = offset;
        event.data = data;
        event.timestamp = timestamp;
        event.sequence = nextDirectInputSequence++;
        if (!nextDirectInputSequence) {
            nextDirectInputSequence = 1;
        }
        U32 capacity = object.bufferSize
            ? std::min<U32>(object.bufferSize, 4096)
            : 256;
        while (object.events.size() >= capacity) {
            object.events.pop_front();
        }
        object.events.push_back(event);
    }

    void clearDirectInputState(U32 timestamp) {
        for (U32 key = 0; key < directInputKeyboardState.size(); ++key) {
            if (!(directInputKeyboardState[key] & 0x80)) {
                continue;
            }
            directInputKeyboardState[key] = 0;
            for (auto& entry : directInputObjects) {
                if (isDirectInputKeyboard(entry.second)) {
                    queueDirectInputEvent(entry.second, key, 0, timestamp);
                }
            }
        }
        for (U32 button = 0; button < directInputMouseButtons.size(); ++button) {
            if (!(directInputMouseButtons[button] & 0x80)) {
                continue;
            }
            directInputMouseButtons[button] = 0;
            for (auto& entry : directInputObjects) {
                if (isDirectInputMouse(entry.second)) {
                    queueDirectInputEvent(
                        entry.second,
                        12 + button,
                        0,
                        timestamp);
                }
            }
        }
        directInputVirtualKeyState.fill(0);
        directInputVirtualKeyPressedSinceRead.fill(0);
        directInputMousePositionKnown = false;
    }

    U32 directInputScanCode(U32 virtualKey, U32 longParameter) const {
        U32 scanCode = (longParameter >> 16) & 0xff;
        if (longParameter & 0x01000000) {
            scanCode |= 0x80;
        }
        if (virtualKey == 0x13) { // VK_PAUSE / DIK_PAUSE
            return 0xc5;
        }
        if (virtualKey == 0x2c) { // VK_SNAPSHOT / DIK_SYSRQ
            return 0xb7;
        }
        return scanCode;
    }

    void updateDirectInputFromHostEvent(
        const SugarbombHostWindow::Event& event) {
        constexpr U32 WM_ACTIVATE_GUEST = 0x0006;
        constexpr U32 WM_SETFOCUS_GUEST = 0x0007;
        constexpr U32 WM_KILLFOCUS_GUEST = 0x0008;
        constexpr U32 WM_ACTIVATEAPP_GUEST = 0x001c;
        constexpr U32 WM_CANCELMODE_GUEST = 0x001f;
        constexpr U32 WM_CAPTURECHANGED_GUEST = 0x0215;
        constexpr U32 WM_KEYDOWN_GUEST = 0x0100;
        constexpr U32 WM_KEYUP_GUEST = 0x0101;
        constexpr U32 WM_SYSKEYDOWN_GUEST = 0x0104;
        constexpr U32 WM_SYSKEYUP_GUEST = 0x0105;
        constexpr U32 WM_MOUSEMOVE_GUEST = 0x0200;
        constexpr U32 WM_LBUTTONDOWN_GUEST = 0x0201;
        constexpr U32 WM_LBUTTONUP_GUEST = 0x0202;
        constexpr U32 WM_RBUTTONDOWN_GUEST = 0x0204;
        constexpr U32 WM_RBUTTONUP_GUEST = 0x0205;
        constexpr U32 WM_MBUTTONDOWN_GUEST = 0x0207;
        constexpr U32 WM_MBUTTONUP_GUEST = 0x0208;
        constexpr U32 WM_MOUSEWHEEL_GUEST = 0x020a;
        constexpr U32 WM_XBUTTONDOWN_GUEST = 0x020b;
        constexpr U32 WM_XBUTTONUP_GUEST = 0x020c;
        constexpr U32 WM_MOUSEHWHEEL_GUEST = 0x020e;

        if (event.relativeMouse) {
            directInputRawMouseAvailable = true;
            S32 deltaX = static_cast<S32>(event.wordParameter);
            S32 deltaY = static_cast<S32>(event.longParameter);
            if (++directInputRawMouseTraceCount <= 16) {
                printf(
                    "Sugarbomb DirectInput: raw mouse delta=(%d,%d)\n",
                    deltaX,
                    deltaY);
            }
            for (auto& entry : directInputObjects) {
                DirectInputObject& object = entry.second;
                if (!isDirectInputMouse(object) || !object.acquired) {
                    continue;
                }
                if (deltaX) {
                    object.mouseDeltaX += deltaX;
                    queueDirectInputEvent(
                        object,
                        0, // DIMOFS_X
                        static_cast<U32>(deltaX),
                        event.time);
                }
                if (deltaY) {
                    object.mouseDeltaY += deltaY;
                    queueDirectInputEvent(
                        object,
                        4, // DIMOFS_Y
                        static_cast<U32>(deltaY),
                        event.time);
                }
            }
            return;
        }

        if (event.message == WM_CANCELMODE_GUEST ||
            event.message == WM_CAPTURECHANGED_GUEST) {
            loseExclusiveDirectInputMouse();
            return;
        }

        bool focusLost =
            event.message == WM_KILLFOCUS_GUEST ||
            (event.message == WM_ACTIVATE_GUEST &&
             !(event.wordParameter & 0xffff)) ||
            (event.message == WM_ACTIVATEAPP_GUEST &&
             !event.wordParameter);
        if (focusLost) {
            clearDirectInputState(event.time);
            loseForegroundDirectInputDevices(event.guestHandle);
            return;
        }
        if (event.message == WM_SETFOCUS_GUEST ||
            (event.message == WM_ACTIVATE_GUEST &&
             (event.wordParameter & 0xffff)) ||
            (event.message == WM_ACTIVATEAPP_GUEST &&
             event.wordParameter)) {
            directInputMousePositionKnown = false;
            return;
        }

        if (event.message == WM_KEYDOWN_GUEST ||
            event.message == WM_KEYUP_GUEST ||
            event.message == WM_SYSKEYDOWN_GUEST ||
            event.message == WM_SYSKEYUP_GUEST) {
            bool pressed =
                event.message == WM_KEYDOWN_GUEST ||
                event.message == WM_SYSKEYDOWN_GUEST;
            U32 virtualKey = event.wordParameter & 0xff;
            if (virtualKey < directInputVirtualKeyState.size()) {
                if (pressed && !directInputVirtualKeyState[virtualKey]) {
                    directInputVirtualKeyPressedSinceRead[virtualKey] = 1;
                }
                directInputVirtualKeyState[virtualKey] =
                    pressed ? 0x80 : 0;
            }
            U32 scanCode =
                directInputScanCode(event.wordParameter, event.longParameter);
            if (scanCode >= directInputKeyboardState.size()) {
                return;
            }
            U8 state = pressed ? 0x80 : 0;
            if (directInputKeyboardState[scanCode] == state) {
                return;
            }
            directInputKeyboardState[scanCode] = state;
            if (++directInputHostEventTraceCount <= 32) {
                printf(
                    "Sugarbomb DirectInput: host keyboard DIK=0x%02X "
                    "state=0x%02X\n",
                    scanCode,
                    state);
            }
            for (auto& entry : directInputObjects) {
                if (isDirectInputKeyboard(entry.second)) {
                    queueDirectInputEvent(
                        entry.second,
                        scanCode,
                        state,
                        event.time);
                }
            }
            return;
        }

        if (event.message == WM_MOUSEMOVE_GUEST) {
            S32 x = static_cast<S16>(event.longParameter & 0xffff);
            S32 y = static_cast<S16>((event.longParameter >> 16) & 0xffff);
            if (directInputMousePositionKnown &&
                !directInputRawMouseAvailable) {
                S32 deltaX = x - directInputMouseX;
                S32 deltaY = y - directInputMouseY;
                for (auto& entry : directInputObjects) {
                    DirectInputObject& object = entry.second;
                    if (!isDirectInputMouse(object) || !object.acquired) {
                        continue;
                    }
                    if (deltaX) {
                        object.mouseDeltaX += deltaX;
                        queueDirectInputEvent(
                            object,
                            0, // DIMOFS_X
                            static_cast<U32>(deltaX),
                            event.time);
                    }
                    if (deltaY) {
                        object.mouseDeltaY += deltaY;
                        queueDirectInputEvent(
                            object,
                            4, // DIMOFS_Y
                            static_cast<U32>(deltaY),
                            event.time);
                    }
                }
            }
            directInputMouseX = x;
            directInputMouseY = y;
            directInputMousePositionKnown = true;
            return;
        }

        U32 button = std::numeric_limits<U32>::max();
        bool pressed = false;
        switch (event.message) {
        case WM_LBUTTONDOWN_GUEST:
            button = 0;
            pressed = true;
            break;
        case WM_LBUTTONUP_GUEST:
            button = 0;
            break;
        case WM_RBUTTONDOWN_GUEST:
            button = 1;
            pressed = true;
            break;
        case WM_RBUTTONUP_GUEST:
            button = 1;
            break;
        case WM_MBUTTONDOWN_GUEST:
            button = 2;
            pressed = true;
            break;
        case WM_MBUTTONUP_GUEST:
            button = 2;
            break;
        case WM_XBUTTONDOWN_GUEST:
        case WM_XBUTTONUP_GUEST:
            button = ((event.wordParameter >> 16) & 0xffff) == 1 ? 3 : 4;
            pressed = event.message == WM_XBUTTONDOWN_GUEST;
            break;
        default:
            break;
        }
        if (button < directInputMouseButtons.size()) {
            U8 state = pressed ? 0x80 : 0;
            if (directInputMouseButtons[button] == state) {
                return;
            }
            directInputMouseButtons[button] = state;
            for (auto& entry : directInputObjects) {
                if (isDirectInputMouse(entry.second)) {
                    queueDirectInputEvent(
                        entry.second,
                        12 + button,
                        state,
                        event.time);
                }
            }
            return;
        }

        if (event.message == WM_MOUSEWHEEL_GUEST ||
            event.message == WM_MOUSEHWHEEL_GUEST) {
            S32 delta = static_cast<S16>(
                (event.wordParameter >> 16) & 0xffff);
            for (auto& entry : directInputObjects) {
                DirectInputObject& object = entry.second;
                if (!isDirectInputMouse(object) || !object.acquired) {
                    continue;
                }
                U32 offset =
                    event.message == WM_MOUSEWHEEL_GUEST ? 8 : 0;
                if (event.message == WM_MOUSEWHEEL_GUEST) {
                    object.mouseWheelDelta += delta;
                } else {
                    object.mouseDeltaX += delta;
                }
                queueDirectInputEvent(
                    object,
                    offset,
                    static_cast<U32>(delta),
                    event.time);
            }
        }
    }

    U32 getAsyncKeyState(U32 virtualKey) {
        pumpHostMessages();
        if (virtualKey >= directInputVirtualKeyState.size()) {
            return 0;
        }
        U32 result =
            directInputVirtualKeyState[virtualKey] ? 0x8000 : 0;
        if (directInputVirtualKeyPressedSinceRead[virtualKey]) {
            result |= 1;
            directInputVirtualKeyPressedSinceRead[virtualKey] = 0;
        }
        return result;
    }

    void dispatchDirectInputComMethod(CPU* cpu, const DirectInputComMethod& method) {
        constexpr U32 DI_OK = 0;
        constexpr U32 DIERR_INVALIDPARAM = 0x80070057;
        constexpr U32 DIERR_NOTACQUIRED = 0x8007000c;
        constexpr U32 DIERR_OTHERAPPHASPRIO = 0x80070005;
        constexpr U32 E_POINTER = 0x80004003;

        U32 objectAddress = argument(cpu, 0);
        auto found = directInputObjects.find(objectAddress);
        if (found == directInputObjects.end() ||
            (method.device &&
             found->second.kind != DirectInputObjectKind::Device) ||
            (!method.device &&
             found->second.kind != DirectInputObjectKind::Interface)) {
            cpu->reg[0].u32 = E_POINTER;
            return;
        }
        DirectInputObject& object = found->second;

        if (method.index == 0) { // QueryInterface
            U32 resultAddress = argument(cpu, 2);
            if (!resultAddress) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            ++object.references;
            memory->writed(objectAddress + 4, object.references);
            memory->writed(resultAddress, objectAddress);
            cpu->reg[0].u32 = DI_OK;
            return;
        }
        if (method.index == 1) { // AddRef
            ++object.references;
            memory->writed(objectAddress + 4, object.references);
            cpu->reg[0].u32 = object.references;
            return;
        }
        if (method.index == 2) { // Release
            if (object.references) {
                --object.references;
            }
            if (!object.references &&
                object.kind == DirectInputObjectKind::Device) {
                object.acquired = false;
                object.events.clear();
                if (isDirectInputMouse(object)) {
                    updateHostDirectInputMouseCapture();
                }
            }
            memory->writed(objectAddress + 4, object.references);
            cpu->reg[0].u32 = object.references;
            return;
        }

        if (!method.device) {
            switch (method.index) {
            case 3: { // CreateDevice
                U32 guidAddress = argument(cpu, 1);
                U32 resultAddress = argument(cpu, 2);
                if (!guidAddress || !resultAddress) {
                    cpu->reg[0].u32 = E_POINTER;
                    return;
                }
                U32 guidData1 = memory->readd(guidAddress);
                U32 device = createDirectInputObject(
                    DirectInputObjectKind::Device,
                    guidData1);
                memory->writed(resultAddress, device);
                printf(
                    "Sugarbomb DirectInput: CreateDevice(GUID.Data1=0x%08X) -> 0x%08X\n",
                    guidData1,
                    device);
                cpu->reg[0].u32 = device ? DI_OK : 0x8007000e;
                return;
            }
            case 4: // EnumDevices
            case 6: // RunControlPanel
            case 7: // Initialize
            case 9: // EnumDevicesBySemantics
            case 10: // ConfigureDevices
                cpu->reg[0].u32 = DI_OK;
                return;
            case 5: // GetDeviceStatus
                cpu->reg[0].u32 = argument(cpu, 1) ? DI_OK : E_POINTER;
                return;
            case 8: // FindDevice
                cpu->reg[0].u32 = 0x80040154; // REGDB_E_CLASSNOTREG
                return;
            default:
                cpu->reg[0].u32 = DIERR_INVALIDPARAM;
                return;
            }
        }

        switch (method.index) {
        case 3: { // GetCapabilities
            U32 capabilities = argument(cpu, 1);
            if (!capabilities) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            U32 size = std::min<U32>(memory->readd(capabilities), 44);
            if (size < 24) {
                cpu->reg[0].u32 = DIERR_INVALIDPARAM;
                return;
            }
            memory->memset(capabilities, 0, size);
            memory->writed(capabilities, size);
            memory->writed(capabilities + 4, 1); // DIDC_ATTACHED
            memory->writed(capabilities + 8, directInputDeviceType(object));
            if (object.deviceGuidData1 == 0x6f1d2b60) {
                memory->writed(capabilities + 12, 3);
                memory->writed(capabilities + 16, 8);
            } else if (object.deviceGuidData1 == 0x6f1d2b61) {
                memory->writed(capabilities + 16, 256);
            }
            cpu->reg[0].u32 = DI_OK;
            return;
        }
        case 4: // EnumObjects
        case 5: // GetProperty
        case 16: // RunControlPanel
        case 17: // Initialize
        case 19: // EnumEffects
        case 22: // SendForceFeedbackCommand
        case 23: // EnumCreatedEffectObjects
        case 25: // Poll
        case 27: // EnumEffectsInFile
        case 28: // WriteEffectToFile
        case 29: // BuildActionMap
        case 30: // SetActionMap
            cpu->reg[0].u32 = DI_OK;
            return;
        case 6: { // SetProperty
            U32 property = argument(cpu, 1);
            U32 header = argument(cpu, 2);
            if (!header || !memory->canRead(header, 16)) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            if (property == 1 &&
                memory->readd(header) >= 20 &&
                memory->canRead(header, 20)) { // DIPROP_BUFFERSIZE
                object.bufferSize =
                    std::min<U32>(memory->readd(header + 16), 4096);
                while (object.events.size() > object.bufferSize) {
                    object.events.pop_front();
                }
            }
            cpu->reg[0].u32 = DI_OK;
            return;
        }
        case 7: { // Acquire
            pumpHostMessages();
            bool wasAcquired = object.acquired;
            if (!wasAcquired &&
                !hasDirectInputForegroundPriority(object)) {
                cpu->reg[0].u32 = DIERR_OTHERAPPHASPRIO;
                return;
            }
            object.acquired = true;
            if (!wasAcquired) {
                object.mouseDeltaX = 0;
                object.mouseDeltaY = 0;
                object.mouseWheelDelta = 0;
                object.events.clear();
                directInputMousePositionKnown = false;
                printf(
                    "Sugarbomb DirectInput: Acquire(%s 0x%08X)\n",
                    isDirectInputKeyboard(object) ? "keyboard" : "mouse",
                    objectAddress);
                if (isDirectInputMouse(object)) {
                    updateHostDirectInputMouseCapture();
                }
            }
            cpu->reg[0].u32 = wasAcquired ? 1 : DI_OK; // DI_NOEFFECT
            return;
        }
        case 8: { // Unacquire
            bool wasAcquired = object.acquired;
            object.acquired = false;
            if (wasAcquired) {
                object.mouseDeltaX = 0;
                object.mouseDeltaY = 0;
                object.mouseWheelDelta = 0;
                object.events.clear();
                printf(
                    "Sugarbomb DirectInput: Unacquire(%s 0x%08X)\n",
                    isDirectInputKeyboard(object) ? "keyboard" : "mouse",
                    objectAddress);
                if (isDirectInputMouse(object)) {
                    updateHostDirectInputMouseCapture();
                }
            }
            cpu->reg[0].u32 = wasAcquired ? DI_OK : 1; // DI_NOEFFECT
            return;
        }
        case 9: { // GetDeviceState
            U32 size = argument(cpu, 1);
            U32 destination = argument(cpu, 2);
            if (!destination ||
                !size ||
                size > 4096 ||
                !memory->canWrite(destination, size)) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            pumpHostMessages();
            if (!object.acquired) {
                cpu->reg[0].u32 = DIERR_NOTACQUIRED;
                return;
            }
            if (++directInputStateCallTraceCount <= 16) {
                printf(
                    "Sugarbomb DirectInput: GetDeviceState(%s 0x%08X, "
                    "size=%u, acquired=%u)\n",
                    isDirectInputKeyboard(object) ? "keyboard" : "mouse",
                    objectAddress,
                    size,
                    object.acquired ? 1 : 0);
            }
            memory->memset(destination, 0, size);
            if (isDirectInputKeyboard(object)) {
                memory->memcpy(
                    destination,
                    directInputKeyboardState.data(),
                    std::min<U32>(
                        size,
                        static_cast<U32>(directInputKeyboardState.size())));
            } else if (isDirectInputMouse(object)) {
                if (size >= 4) {
                    memory->writed(
                        destination,
                        static_cast<U32>(object.mouseDeltaX));
                }
                if (size >= 8) {
                    memory->writed(
                        destination + 4,
                        static_cast<U32>(object.mouseDeltaY));
                }
                if (size >= 12) {
                    memory->writed(
                        destination + 8,
                        static_cast<U32>(object.mouseWheelDelta));
                }
                U32 buttonBytes = size > 12
                    ? std::min<U32>(
                        size - 12,
                        static_cast<U32>(directInputMouseButtons.size()))
                    : 0;
                if (buttonBytes) {
                    memory->memcpy(
                        destination + 12,
                        directInputMouseButtons.data(),
                        buttonBytes);
                }
                object.mouseDeltaX = 0;
                object.mouseDeltaY = 0;
                object.mouseWheelDelta = 0;
            }
            cpu->reg[0].u32 = DI_OK;
            return;
        }
        case 10: { // GetDeviceData
            U32 elementSize = argument(cpu, 1);
            U32 destination = argument(cpu, 2);
            U32 elementCount = argument(cpu, 3);
            U32 flags = argument(cpu, 4);
            if (!elementCount ||
                !memory->canRead(elementCount, 4) ||
                !memory->canWrite(elementCount, 4)) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            if (elementSize < 16 || elementSize > 256) {
                cpu->reg[0].u32 = DIERR_INVALIDPARAM;
                return;
            }
            pumpHostMessages();
            if (!object.acquired) {
                memory->writed(elementCount, 0);
                cpu->reg[0].u32 = DIERR_NOTACQUIRED;
                return;
            }
            U32 requested = memory->readd(elementCount);
            U32 available = static_cast<U32>(object.events.size());
            U32 count = requested == 0xffffffff
                ? available
                : std::min<U32>(requested, available);
            if (++directInputDataCallTraceCount <= 16) {
                printf(
                    "Sugarbomb DirectInput: GetDeviceData(%s 0x%08X, "
                    "requested=%u, available=%u, acquired=%u)\n",
                    isDirectInputKeyboard(object) ? "keyboard" : "mouse",
                    objectAddress,
                    requested,
                    available,
                    object.acquired ? 1 : 0);
            }
            if (destination) {
                U64 destinationBytes =
                    static_cast<U64>(count) * elementSize;
                if (destinationBytes > std::numeric_limits<U32>::max() ||
                    !memory->canWrite(
                        destination,
                        static_cast<U32>(destinationBytes))) {
                    cpu->reg[0].u32 = E_POINTER;
                    return;
                }
                auto event = object.events.begin();
                for (U32 index = 0; index < count; ++index, ++event) {
                    U32 output = destination + index * elementSize;
                    memory->memset(output, 0, elementSize);
                    memory->writed(output, event->offset);
                    memory->writed(output + 4, event->data);
                    memory->writed(output + 8, event->timestamp);
                    memory->writed(output + 12, event->sequence);
                }
            }
            if (!(flags & 1)) { // DIGDD_PEEK
                for (U32 index = 0; index < count; ++index) {
                    object.events.pop_front();
                }
            }
            memory->writed(elementCount, count);
            if (count && ++directInputReadTraceCount <= 32) {
                printf(
                    "Sugarbomb DirectInput: GetDeviceData delivered %u "
                    "%s event(s), %zu buffered\n",
                    count,
                    isDirectInputKeyboard(object) ? "keyboard" : "mouse",
                    object.events.size());
            }
            cpu->reg[0].u32 = DI_OK;
            return;
        }
        case 11: { // SetDataFormat
            U32 format = argument(cpu, 1);
            if (!format || !memory->canRead(format, 24)) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            U32 structureSize = memory->readd(format);
            U32 objectSize = memory->readd(format + 4);
            U32 dataSize = memory->readd(format + 12);
            if (structureSize < 24 ||
                objectSize < 16 ||
                !dataSize ||
                dataSize > 4096) {
                cpu->reg[0].u32 = DIERR_INVALIDPARAM;
                return;
            }
            object.dataFormatSize = dataSize;
            cpu->reg[0].u32 = DI_OK;
            return;
        }
        case 12: // SetEventNotification
            object.eventHandle = argument(cpu, 1);
            cpu->reg[0].u32 = DI_OK;
            return;
        case 13: // SetCooperativeLevel
            object.cooperativeWindow = argument(cpu, 1);
            object.cooperativeFlags = argument(cpu, 2);
            printf(
                "Sugarbomb DirectInput: SetCooperativeLevel(%s 0x%08X, "
                "HWND=0x%08X, flags=0x%08X)\n",
                isDirectInputKeyboard(object) ? "keyboard" : "mouse",
                objectAddress,
                object.cooperativeWindow,
                object.cooperativeFlags);
            if (isDirectInputMouse(object) && object.acquired) {
                updateHostDirectInputMouseCapture();
            }
            cpu->reg[0].u32 = DI_OK;
            return;
        case 14: { // GetObjectInfo
            U32 info = argument(cpu, 1);
            if (!info) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            U32 size = std::min<U32>(memory->readd(info), 316);
            if (size >= 4) {
                memory->memset(info, 0, size);
                memory->writed(info, size);
            }
            cpu->reg[0].u32 = DI_OK;
            return;
        }
        case 15: { // GetDeviceInfo
            U32 info = argument(cpu, 1);
            if (!info) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            U32 size = std::min<U32>(memory->readd(info), 580);
            if (size < 40) {
                cpu->reg[0].u32 = DIERR_INVALIDPARAM;
                return;
            }
            memory->memset(info, 0, size);
            memory->writed(info, size);
            memory->writed(info + 36, directInputDeviceType(object));
            const char* name =
                object.deviceGuidData1 == 0x6f1d2b60
                ? "Sugarbomb Mouse"
                : (object.deviceGuidData1 == 0x6f1d2b61
                    ? "Sugarbomb Keyboard"
                    : "Sugarbomb Input Device");
            if (size > 40) {
                memory->strcpy(info + 40, name);
            }
            if (size > 300) {
                memory->strcpy(info + 300, name);
            }
            cpu->reg[0].u32 = DI_OK;
            return;
        }
        case 18: { // CreateEffect
            U32 resultAddress = argument(cpu, 3);
            if (resultAddress) {
                memory->writed(resultAddress, 0);
            }
            cpu->reg[0].u32 = 0x80004001; // E_NOTIMPL
            return;
        }
        case 20: // GetEffectInfo
        case 21: // GetForceFeedbackState
        case 24: // Escape
        case 26: // SendDeviceData
        case 31: // GetImageInfo
            cpu->reg[0].u32 = 0x80004001;
            return;
        default:
            cpu->reg[0].u32 = DIERR_INVALIDPARAM;
            return;
        }
    }

    static void callbackDirectInput8Create(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "DINPUT8!DirectInput8Create");
        if (!session) {
            return;
        }
        U32 version = argument(cpu, 1);
        U32 resultAddress = argument(cpu, 3);
        if (!resultAddress) {
            cpu->reg[0].u32 = 0x80004003; // E_POINTER
            return;
        }
        session->memory->writed(resultAddress, 0);
        if (version < DIRECTINPUT_VERSION) {
            cpu->reg[0].u32 = 0x80070057;
            return;
        }
        U32 directInput = session->createDirectInputObject(
            DirectInputObjectKind::Interface);
        session->memory->writed(resultAddress, directInput);
        printf(
            "Sugarbomb DirectInput: DirectInput8Create(version=0x%04X) -> 0x%08X\n",
            version,
            directInput);
        cpu->reg[0].u32 = directInput ? 0 : 0x8007000e;
    }

    static void callbackDirectInputComMethod(CPU* cpu) {
        if (!activeSession) {
            cpu->thread->terminating = true;
            return;
        }
        U32 callbackIndex = cpu->peek32(0);
        auto found = activeSession->directInputComMethods.find(callbackIndex);
        if (found == activeSession->directInputComMethods.end()) {
            callbackUnresolvedImport(cpu);
            return;
        }
        std::string module;
        std::string symbol;
        SugarbombBridge::callbackName(callbackIndex, module, symbol);
        std::string api = "DINPUT8!" + symbol;
        SugarbombRuntimeSession* session = current(cpu, api.c_str());
        if (session) {
            session->dispatchDirectInputComMethod(cpu, found->second);
        }
    }

    bool ensureDirectSoundVtables() {
        if (directSoundVtableAddress && directSoundBufferVtableAddress) {
            return true;
        }
        directSoundVtableAddress = allocateGuestHeap(
            static_cast<U32>(directSoundVtable.size() * sizeof(U32)),
            true);
        directSoundBufferVtableAddress = allocateGuestHeap(
            static_cast<U32>(directSoundBufferVtable.size() * sizeof(U32)),
            true);
        if (!directSoundVtableAddress || !directSoundBufferVtableAddress) {
            return false;
        }
        for (U32 index = 0; index < directSoundVtable.size(); ++index) {
            memory->writed(
                directSoundVtableAddress + index * sizeof(U32),
                directSoundVtable[index]);
        }
        for (U32 index = 0; index < directSoundBufferVtable.size(); ++index) {
            memory->writed(
                directSoundBufferVtableAddress + index * sizeof(U32),
                directSoundBufferVtable[index]);
        }
        return true;
    }

    U32 createDirectSoundObject(DirectSoundObjectKind kind, U32 flags = 0, U32 bufferBytes = 0) {
        if (!ensureDirectSoundVtables()) {
            return 0;
        }
        U32 objectAddress = allocateGuestHeap(8, true);
        if (!objectAddress) {
            return 0;
        }
        DirectSoundObject object;
        object.kind = kind;
        object.flags = flags;
        object.bufferBytes = bufferBytes;
        directSoundObjects[objectAddress] = object;
        memory->writed(
            objectAddress,
            kind == DirectSoundObjectKind::Buffer
                ? directSoundBufferVtableAddress
                : directSoundVtableAddress);
        memory->writed(objectAddress + 4, 1);
        return objectAddress;
    }

    void writeDefaultWaveFormat(U32 destination, U32 destinationSize) {
        if (!destination || destinationSize < 16) {
            return;
        }
        U32 size = std::min<U32>(destinationSize, 18);
        memory->memset(destination, 0, size);
        memory->writew(destination, 1); // WAVE_FORMAT_PCM
        memory->writew(destination + 2, 2);
        memory->writed(destination + 4, 44100);
        memory->writed(destination + 8, 176400);
        memory->writew(destination + 12, 4);
        memory->writew(destination + 14, 16);
        if (size >= 18) {
            memory->writew(destination + 16, 0);
        }
    }

    void dispatchDirectSoundComMethod(CPU* cpu, const DirectSoundComMethod& method) {
        constexpr U32 DS_OK = 0;
        constexpr U32 DSERR_INVALIDPARAM = 0x80070057;
        constexpr U32 E_POINTER = 0x80004003;

        U32 objectAddress = argument(cpu, 0);
        auto found = directSoundObjects.find(objectAddress);
        if (found == directSoundObjects.end() ||
            (method.buffer &&
             found->second.kind != DirectSoundObjectKind::Buffer) ||
            (!method.buffer &&
             found->second.kind != DirectSoundObjectKind::Interface)) {
            cpu->reg[0].u32 = E_POINTER;
            return;
        }
        DirectSoundObject& object = found->second;

        if (method.index == 0) { // QueryInterface
            U32 resultAddress = argument(cpu, 2);
            if (!resultAddress) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            ++object.references;
            memory->writed(objectAddress + 4, object.references);
            memory->writed(resultAddress, objectAddress);
            cpu->reg[0].u32 = DS_OK;
            return;
        }
        if (method.index == 1) { // AddRef
            ++object.references;
            memory->writed(objectAddress + 4, object.references);
            cpu->reg[0].u32 = object.references;
            return;
        }
        if (method.index == 2) { // Release
            if (object.references) {
                --object.references;
            }
            memory->writed(objectAddress + 4, object.references);
            cpu->reg[0].u32 = object.references;
            return;
        }

        if (!method.buffer) {
            switch (method.index) {
            case 3: { // CreateSoundBuffer
                U32 description = argument(cpu, 1);
                U32 resultAddress = argument(cpu, 2);
                if (!description || !resultAddress || memory->readd(description) < 20) {
                    cpu->reg[0].u32 = DSERR_INVALIDPARAM;
                    return;
                }
                U32 flags = memory->readd(description + 4);
                U32 bufferBytes = memory->readd(description + 8);
                U32 buffer = createDirectSoundObject(
                    DirectSoundObjectKind::Buffer,
                    flags,
                    bufferBytes);
                memory->writed(resultAddress, buffer);
                printf(
                    "Sugarbomb DirectSound: CreateSoundBuffer(flags=0x%08X, bytes=%u) -> 0x%08X\n",
                    flags,
                    bufferBytes,
                    buffer);
                cpu->reg[0].u32 = buffer ? DS_OK : 0x8007000e;
                return;
            }
            case 4: { // GetCaps
                U32 caps = argument(cpu, 1);
                if (!caps) {
                    cpu->reg[0].u32 = E_POINTER;
                    return;
                }
                U32 size = std::min<U32>(memory->readd(caps), 96);
                if (size < 4) {
                    cpu->reg[0].u32 = DSERR_INVALIDPARAM;
                    return;
                }
                memory->memset(caps, 0, size);
                memory->writed(caps, size);
                cpu->reg[0].u32 = DS_OK;
                return;
            }
            case 5: { // DuplicateSoundBuffer
                U32 sourceAddress = argument(cpu, 1);
                U32 resultAddress = argument(cpu, 2);
                auto source = directSoundObjects.find(sourceAddress);
                if (!resultAddress || source == directSoundObjects.end() ||
                    source->second.kind != DirectSoundObjectKind::Buffer) {
                    cpu->reg[0].u32 = DSERR_INVALIDPARAM;
                    return;
                }
                U32 duplicate = createDirectSoundObject(
                    DirectSoundObjectKind::Buffer,
                    source->second.flags,
                    source->second.bufferBytes);
                memory->writed(resultAddress, duplicate);
                cpu->reg[0].u32 = duplicate ? DS_OK : 0x8007000e;
                return;
            }
            case 6: // SetCooperativeLevel
            case 7: // Compact
            case 9: // SetSpeakerConfig
            case 10: // Initialize
                cpu->reg[0].u32 = DS_OK;
                return;
            case 8: { // GetSpeakerConfig
                U32 config = argument(cpu, 1);
                if (!config) {
                    cpu->reg[0].u32 = E_POINTER;
                    return;
                }
                memory->writed(config, 4); // DSSPEAKER_STEREO
                cpu->reg[0].u32 = DS_OK;
                return;
            }
            case 11: { // VerifyCertification
                U32 certified = argument(cpu, 1);
                if (!certified) {
                    cpu->reg[0].u32 = E_POINTER;
                    return;
                }
                memory->writed(certified, 0);
                cpu->reg[0].u32 = DS_OK;
                return;
            }
            default:
                cpu->reg[0].u32 = DSERR_INVALIDPARAM;
                return;
            }
        }

        switch (method.index) {
        case 3: { // GetCaps
            U32 caps = argument(cpu, 1);
            if (!caps) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            U32 size = std::min<U32>(memory->readd(caps), 20);
            if (size < 12) {
                cpu->reg[0].u32 = DSERR_INVALIDPARAM;
                return;
            }
            memory->memset(caps, 0, size);
            memory->writed(caps, size);
            memory->writed(caps + 4, object.flags);
            memory->writed(caps + 8, object.bufferBytes);
            cpu->reg[0].u32 = DS_OK;
            return;
        }
        case 4: { // GetCurrentPosition
            if (argument(cpu, 1)) {
                memory->writed(argument(cpu, 1), 0);
            }
            if (argument(cpu, 2)) {
                memory->writed(argument(cpu, 2), 0);
            }
            cpu->reg[0].u32 = DS_OK;
            return;
        }
        case 5: { // GetFormat
            U32 format = argument(cpu, 1);
            U32 size = argument(cpu, 2);
            U32 written = argument(cpu, 3);
            if (written) {
                memory->writed(written, 18);
            }
            if (format) {
                writeDefaultWaveFormat(format, size);
            }
            cpu->reg[0].u32 = DS_OK;
            return;
        }
        case 6: // GetVolume
            if (!argument(cpu, 1)) {
                cpu->reg[0].u32 = E_POINTER;
            } else {
                memory->writed(argument(cpu, 1), static_cast<U32>(object.volume));
                cpu->reg[0].u32 = DS_OK;
            }
            return;
        case 7: // GetPan
            if (!argument(cpu, 1)) {
                cpu->reg[0].u32 = E_POINTER;
            } else {
                memory->writed(argument(cpu, 1), static_cast<U32>(object.pan));
                cpu->reg[0].u32 = DS_OK;
            }
            return;
        case 8: // GetFrequency
            if (!argument(cpu, 1)) {
                cpu->reg[0].u32 = E_POINTER;
            } else {
                memory->writed(argument(cpu, 1), object.frequency);
                cpu->reg[0].u32 = DS_OK;
            }
            return;
        case 9: // GetStatus
            if (!argument(cpu, 1)) {
                cpu->reg[0].u32 = E_POINTER;
            } else {
                memory->writed(argument(cpu, 1), object.playing ? 1 : 0);
                cpu->reg[0].u32 = DS_OK;
            }
            return;
        case 10: // Initialize
        case 13: // SetCurrentPosition
        case 14: // SetFormat
        case 20: // Restore
            cpu->reg[0].u32 = DS_OK;
            return;
        case 11: { // Lock
            U32 offset = argument(cpu, 1);
            U32 bytes = argument(cpu, 2);
            U32 audio1 = argument(cpu, 3);
            U32 bytes1 = argument(cpu, 4);
            U32 audio2 = argument(cpu, 5);
            U32 bytes2 = argument(cpu, 6);
            U32 flags = argument(cpu, 7);
            if (!audio1 || !bytes1) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            if (!object.bufferBytes) {
                object.bufferBytes = 0x10000;
            }
            if (!object.storageAddress) {
                object.storageAddress = allocateGuestHeap(object.bufferBytes, true);
            }
            if (!object.storageAddress) {
                cpu->reg[0].u32 = 0x8007000e;
                return;
            }
            if (flags & 2) { // DSBLOCK_ENTIREBUFFER
                offset = 0;
                bytes = object.bufferBytes;
            }
            offset %= object.bufferBytes;
            bytes = std::min(bytes, object.bufferBytes);
            U32 firstBytes = std::min(bytes, object.bufferBytes - offset);
            memory->writed(audio1, object.storageAddress + offset);
            memory->writed(bytes1, firstBytes);
            if (audio2) {
                memory->writed(
                    audio2,
                    bytes > firstBytes ? object.storageAddress : 0);
            }
            if (bytes2) {
                memory->writed(bytes2, bytes - firstBytes);
            }
            cpu->reg[0].u32 = DS_OK;
            return;
        }
        case 12: // Play
            object.playing = true;
            cpu->reg[0].u32 = DS_OK;
            return;
        case 15: // SetVolume
            object.volume = static_cast<S32>(argument(cpu, 1));
            cpu->reg[0].u32 = DS_OK;
            return;
        case 16: // SetPan
            object.pan = static_cast<S32>(argument(cpu, 1));
            cpu->reg[0].u32 = DS_OK;
            return;
        case 17: // SetFrequency
            object.frequency = argument(cpu, 1) ? argument(cpu, 1) : 44100;
            cpu->reg[0].u32 = DS_OK;
            return;
        case 18: // Stop
            object.playing = false;
            cpu->reg[0].u32 = DS_OK;
            return;
        case 19: // Unlock
            cpu->reg[0].u32 = DS_OK;
            return;
        case 21: // SetFX
        case 22: // AcquireResources
            cpu->reg[0].u32 = 0x80004001; // E_NOTIMPL
            return;
        case 23: { // GetObjectInPath
            U32 resultAddress = argument(cpu, 4);
            if (resultAddress) {
                memory->writed(resultAddress, 0);
            }
            cpu->reg[0].u32 = 0x80004002; // E_NOINTERFACE
            return;
        }
        default:
            cpu->reg[0].u32 = DSERR_INVALIDPARAM;
            return;
        }
    }

    static void callbackDirectSoundCreate8(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "DSOUND!DirectSoundCreate8");
        if (!session) {
            return;
        }
        U32 resultAddress = argument(cpu, 1);
        if (!resultAddress) {
            cpu->reg[0].u32 = 0x80004003;
            return;
        }
        U32 directSound = session->createDirectSoundObject(
            DirectSoundObjectKind::Interface);
        session->memory->writed(resultAddress, directSound);
        printf(
            "Sugarbomb DirectSound: DirectSoundCreate8 -> 0x%08X\n",
            directSound);
        cpu->reg[0].u32 = directSound ? 0 : 0x8007000e;
    }

    static void callbackDirectSoundComMethod(CPU* cpu) {
        if (!activeSession) {
            cpu->thread->terminating = true;
            return;
        }
        U32 callbackIndex = cpu->peek32(0);
        auto found = activeSession->directSoundComMethods.find(callbackIndex);
        if (found == activeSession->directSoundComMethods.end()) {
            callbackUnresolvedImport(cpu);
            return;
        }
        std::string module;
        std::string symbol;
        SugarbombBridge::callbackName(callbackIndex, module, symbol);
        std::string api = "DSOUND!" + symbol;
        SugarbombRuntimeSession* session = current(cpu, api.c_str());
        if (session) {
            session->dispatchDirectSoundComMethod(cpu, found->second);
        }
    }

    bool readMmioBytes(U32 handle, U64 offset, U8* destination, U32 count, U32& bytesRead) {
        bytesRead = 0;
        auto state = mmioFiles.find(handle);
        if (state == mmioFiles.end()) {
            return false;
        }
        auto file = guestFiles.find(state->second.guestFileHandle);
        if (file == guestFiles.end()) {
            return false;
        }
        if (file->second.overlay) {
            if (offset >= file->second.overlay->bytes.size()) {
                return true;
            }
            bytesRead = static_cast<U32>(std::min<U64>(
                count,
                file->second.overlay->bytes.size() - offset));
            memcpy(
                destination,
                file->second.overlay->bytes.data() + offset,
                bytesRead);
            return true;
        }
        if (!file->second.input) {
            return false;
        }
        file->second.input->clear();
        file->second.input->seekg(static_cast<std::streamoff>(offset), std::ios::beg);
        file->second.input->read(
            reinterpret_cast<char*>(destination),
            static_cast<std::streamsize>(count));
        bytesRead = static_cast<U32>(file->second.input->gcount());
        return !file->second.input->bad();
    }

    U64 mmioFileSize(U32 handle) {
        auto state = mmioFiles.find(handle);
        if (state == mmioFiles.end()) {
            return 0;
        }
        auto file = guestFiles.find(state->second.guestFileHandle);
        if (file == guestFiles.end()) {
            return 0;
        }
        if (file->second.overlay) {
            return file->second.overlay->bytes.size();
        }
        if (!file->second.input) {
            return 0;
        }
        file->second.input->clear();
        file->second.input->seekg(0, std::ios::end);
        U64 size = static_cast<U64>(file->second.input->tellg());
        file->second.input->clear();
        return size;
    }

    static U32 readLittleEndianU32(const U8* bytes) {
        return static_cast<U32>(bytes[0]) |
            (static_cast<U32>(bytes[1]) << 8) |
            (static_cast<U32>(bytes[2]) << 16) |
            (static_cast<U32>(bytes[3]) << 24);
    }

    U32 openMmioFile(U32 filenameAddress) {
        if (!filenameAddress) {
            return 0;
        }
        U32 fileHandle = createGuestFile(
            readAnsi(filenameAddress),
            0x80000000,
            3);
        if (fileHandle == 0xffffffff) {
            return 0;
        }
        U32 handle = nextMmioHandle++;
        MmioFile state;
        state.guestFileHandle = fileHandle;
        mmioFiles[handle] = state;
        return handle;
    }

    S32 readMmioFile(U32 handle, U32 destination, U32 requested) {
        auto state = mmioFiles.find(handle);
        if (state == mmioFiles.end() || (!destination && requested)) {
            return -1;
        }
        std::vector<U8> buffer(requested);
        U32 bytesRead = 0;
        if (!readMmioBytes(
                handle,
                state->second.position,
                buffer.data(),
                requested,
                bytesRead)) {
            return -1;
        }
        if (bytesRead) {
            memory->memcpy(destination, buffer.data(), bytesRead);
        }
        state->second.position += bytesRead;
        return static_cast<S32>(bytesRead);
    }

    U32 descendMmio(U32 handle, U32 chunkInfo, U32 parentInfo, U32 flags) {
        constexpr U32 FOURCC_RIFF = 0x46464952;
        constexpr U32 FOURCC_LIST = 0x5453494c;
        constexpr U32 MMIO_FINDCHUNK = 0x10;
        constexpr U32 MMIO_FINDRIFF = 0x20;
        constexpr U32 MMIO_FINDLIST = 0x40;
        constexpr U32 MMIOERR_CHUNKNOTFOUND = 257;

        auto state = mmioFiles.find(handle);
        if (state == mmioFiles.end() || !chunkInfo) {
            return 5; // MMSYSERR_INVALHANDLE
        }
        U32 targetId = memory->readd(chunkInfo);
        U32 targetType = memory->readd(chunkInfo + 8);
        U64 limit = mmioFileSize(handle);
        if (parentInfo) {
            U32 parentId = memory->readd(parentInfo);
            U64 parentData = memory->readd(parentInfo + 12);
            U64 parentSize = memory->readd(parentInfo + 4);
            limit = std::min<U64>(
                limit,
                parentData + parentSize -
                    ((parentId == FOURCC_RIFF || parentId == FOURCC_LIST) ? 4 : 0));
        }

        U64 position = state->second.position;
        while (position + 8 <= limit) {
            U8 header[12] = {};
            U32 bytesRead = 0;
            if (!readMmioBytes(handle, position, header, sizeof(header), bytesRead) ||
                bytesRead < 8) {
                break;
            }
            U32 id = readLittleEndianU32(header);
            U32 size = readLittleEndianU32(header + 4);
            bool container = id == FOURCC_RIFF || id == FOURCC_LIST;
            U32 type = container && bytesRead >= 12
                ? readLittleEndianU32(header + 8)
                : 0;
            bool matches =
                (!(flags & (MMIO_FINDCHUNK | MMIO_FINDRIFF | MMIO_FINDLIST))) ||
                ((flags & MMIO_FINDCHUNK) && id == targetId) ||
                ((flags & MMIO_FINDRIFF) && id == FOURCC_RIFF && type == targetType) ||
                ((flags & MMIO_FINDLIST) && id == FOURCC_LIST && type == targetType);
            if (matches) {
                U32 dataOffset = static_cast<U32>(position + (container ? 12 : 8));
                memory->writed(chunkInfo, id);
                memory->writed(chunkInfo + 4, size);
                memory->writed(chunkInfo + 8, type);
                memory->writed(chunkInfo + 12, dataOffset);
                memory->writed(chunkInfo + 16, 0);
                state->second.position = dataOffset;
                return 0;
            }
            U64 next = position + 8 + size;
            position = (next + 1) & ~static_cast<U64>(1);
        }
        return MMIOERR_CHUNKNOTFOUND;
    }

    static void callbackTimeGetTime(CPU* cpu) {
        if (current(cpu, "WINMM!timeGetTime")) {
            cpu->reg[0].u32 = static_cast<U32>(KSystem::getMicroCounter() / 1000);
        }
    }

    static void callbackMmioOpenA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "WINMM!mmioOpenA");
        if (session) {
            cpu->reg[0].u32 = session->openMmioFile(argument(cpu, 0));
        }
    }

    static void callbackMmioClose(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "WINMM!mmioClose");
        if (!session) {
            return;
        }
        U32 handle = argument(cpu, 0);
        auto found = session->mmioFiles.find(handle);
        if (found == session->mmioFiles.end()) {
            cpu->reg[0].u32 = 5;
            return;
        }
        session->closeGuestFile(found->second.guestFileHandle);
        session->mmioFiles.erase(found);
        cpu->reg[0].u32 = 0;
    }

    static void callbackMmioRead(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "WINMM!mmioRead");
        if (session) {
            cpu->reg[0].u32 = static_cast<U32>(session->readMmioFile(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2)));
        }
    }

    static void callbackMmioDescend(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "WINMM!mmioDescend");
        if (session) {
            cpu->reg[0].u32 = session->descendMmio(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3));
        }
    }

    static void callbackMmioAscend(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "WINMM!mmioAscend");
        if (!session) {
            return;
        }
        auto found = session->mmioFiles.find(argument(cpu, 0));
        U32 chunkInfo = argument(cpu, 1);
        if (found == session->mmioFiles.end() || !chunkInfo) {
            cpu->reg[0].u32 = 5;
            return;
        }
        U32 id = session->memory->readd(chunkInfo);
        U64 size = session->memory->readd(chunkInfo + 4);
        U64 dataOffset = session->memory->readd(chunkInfo + 12);
        if (id == 0x46464952 || id == 0x5453494c) {
            size = size >= 4 ? size - 4 : 0;
        }
        found->second.position = (dataOffset + size + 1) & ~static_cast<U64>(1);
        cpu->reg[0].u32 = 0;
    }

    static void callbackMmioGetInfo(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "WINMM!mmioGetInfo");
        if (!session) {
            return;
        }
        U32 handle = argument(cpu, 0);
        U32 info = argument(cpu, 1);
        auto found = session->mmioFiles.find(handle);
        if (found == session->mmioFiles.end() || !info) {
            cpu->reg[0].u32 = 5;
            return;
        }
        session->memory->memset(info, 0, 72);
        session->memory->writed(
            info + 44,
            static_cast<U32>(found->second.position));
        session->memory->writed(info + 68, handle);
        cpu->reg[0].u32 = 0;
    }

    static void callbackMmioAdvance(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "WINMM!mmioAdvance");
        if (session) {
            cpu->reg[0].u32 =
                session->mmioFiles.find(argument(cpu, 0)) != session->mmioFiles.end()
                ? 0
                : 5;
        }
    }

    bool ensureDirect3DVtables() {
        if (direct3DVtableAddress &&
            direct3DDeviceVtableAddress &&
            direct3DSurfaceVtableAddress &&
            direct3DResourceVtableAddresses.size() ==
                direct3DResourceVtables.size()) {
            return true;
        }
        direct3DVtableAddress = allocateGuestHeap(
            static_cast<U32>(direct3DVtable.size() * sizeof(U32)),
            true);
        direct3DDeviceVtableAddress = allocateGuestHeap(
            static_cast<U32>(direct3DDeviceVtable.size() * sizeof(U32)),
            true);
        direct3DSurfaceVtableAddress = allocateGuestHeap(
            static_cast<U32>(direct3DSurfaceVtable.size() * sizeof(U32)),
            true);
        if (!direct3DVtableAddress ||
            !direct3DDeviceVtableAddress ||
            !direct3DSurfaceVtableAddress) {
            return false;
        }
        for (U32 index = 0; index < direct3DVtable.size(); ++index) {
            memory->writed(
                direct3DVtableAddress + index * sizeof(U32),
                direct3DVtable[index]);
        }
        for (U32 index = 0; index < direct3DDeviceVtable.size(); ++index) {
            memory->writed(
                direct3DDeviceVtableAddress + index * sizeof(U32),
                direct3DDeviceVtable[index]);
        }
        for (U32 index = 0; index < direct3DSurfaceVtable.size(); ++index) {
            memory->writed(
                direct3DSurfaceVtableAddress + index * sizeof(U32),
                direct3DSurfaceVtable[index]);
        }
        for (const auto& entry : direct3DResourceVtables) {
            U32 address = allocateGuestHeap(
                static_cast<U32>(entry.second.size() * sizeof(U32)),
                true);
            if (!address) {
                return false;
            }
            direct3DResourceVtableAddresses[entry.first] = address;
            for (U32 index = 0; index < entry.second.size(); ++index) {
                memory->writed(
                    address + index * sizeof(U32),
                    entry.second[index]);
            }
        }
        return true;
    }

    U32 createDirect3DObject(Direct3DObjectKind kind) {
        if (!ensureDirect3DVtables()) {
            return 0;
        }
        U32 objectAddress = allocateGuestHeap(8, true);
        if (!objectAddress) {
            return 0;
        }
        Direct3DObject object;
        object.kind = kind;
        direct3DObjects[objectAddress] = object;
        memory->writed(
            objectAddress,
            kind == Direct3DObjectKind::Device
                ? direct3DDeviceVtableAddress
                : direct3DVtableAddress);
        memory->writed(objectAddress + 4, 1);
        if (kind == Direct3DObjectKind::Interface) {
            direct3DInterfaceAddress = objectAddress;
        } else {
            direct3DDeviceAddress = objectAddress;
        }
        return objectAddress;
    }

    U32 createDirect3DSurface(
        U32 width,
        U32 height,
        U32 format,
        U32 usage = 0,
        U32 pool = 0,
        U32 multiSampleType = 0,
        U32 multiSampleQuality = 0) {
        if (!ensureDirect3DVtables()) {
            return 0;
        }
        U32 objectAddress = allocateGuestHeap(8, true);
        if (!objectAddress) {
            return 0;
        }
        Direct3DSurface surface;
        surface.width = width ? width : configuredDisplayDimension("iSize W", 1280);
        surface.height = height ? height : configuredDisplayDimension("iSize H", 720);
        surface.format = format ? format : 22;
        surface.usage = usage;
        surface.pool = pool;
        surface.multiSampleType = multiSampleType;
        surface.multiSampleQuality = multiSampleQuality;
        direct3DSurfaces[objectAddress] = surface;
        memory->writed(objectAddress, direct3DSurfaceVtableAddress);
        memory->writed(objectAddress + 4, 1);
        return objectAddress;
    }

    U32 ensureDirect3DBackBuffer() {
        U32& surface = direct3DBackBufferSurface;
        if (!surface) {
            surface = createDirect3DSurface(
                direct3DBackBufferWidth
                    ? direct3DBackBufferWidth
                    : configuredDisplayDimension("iSize W", 1280),
                direct3DBackBufferHeight
                    ? direct3DBackBufferHeight
                    : configuredDisplayDimension("iSize H", 720),
                direct3DBackBufferFormat
                    ? direct3DBackBufferFormat
                    : 22,
                1);
            hostDirect3D.registerBackBuffer(surface);
        }
        if (!direct3DRenderTargetSurface) {
            direct3DRenderTargetSurface = surface;
        }
        return surface;
    }

    U32 ensureDirect3DRenderTarget(bool depthStencil) {
        if (!depthStencil) {
            ensureDirect3DBackBuffer();
            return direct3DRenderTargetSurface;
        }
        U32& surface = direct3DDepthStencilSurface;
        if (!surface) {
            surface = createDirect3DSurface(
                direct3DBackBufferWidth
                    ? direct3DBackBufferWidth
                    : configuredDisplayDimension("iSize W", 1280),
                direct3DBackBufferHeight
                    ? direct3DBackBufferHeight
                    : configuredDisplayDimension("iSize H", 720),
                75,
                2);
            auto created = direct3DSurfaces.find(surface);
            if (created != direct3DSurfaces.end()) {
                hostDirect3D.createSurface(
                    surface,
                    created->second.width,
                    created->second.height,
                    created->second.format,
                    created->second.usage,
                    created->second.pool,
                    created->second.multiSampleType,
                    created->second.multiSampleQuality);
            }
        }
        return surface;
    }

    U32 createDirect3DResource(
        Direct3DResourceKind kind,
        U32 resourceType,
        U32 width = 1,
        U32 height = 1,
        U32 levels = 1,
        U32 format = 22,
        U32 usage = 0,
        U32 pool = 0,
        U32 length = 0) {
        if (!ensureDirect3DVtables()) {
            return 0;
        }
        auto vtable = direct3DResourceVtableAddresses.find(
            static_cast<U32>(kind));
        if (vtable == direct3DResourceVtableAddresses.end()) {
            return 0;
        }
        U32 objectAddress = allocateGuestHeap(8, true);
        if (!objectAddress) {
            return 0;
        }
        Direct3DResource resource;
        resource.kind = kind;
        resource.resourceType = resourceType;
        resource.width = width ? width : 1;
        resource.height = height ? height : 1;
        resource.levels = levels ? levels : 1;
        resource.format = format;
        resource.usage = usage;
        resource.pool = pool;
        resource.length = length;
        direct3DResources[objectAddress] = resource;
        memory->writed(objectAddress, vtable->second);
        memory->writed(objectAddress + 4, 1);
        if ((kind == Direct3DResourceKind::Texture ||
             kind == Direct3DResourceKind::CubeTexture) &&
            resourceType != 4) {
            hostDirect3D.createTexture(
                objectAddress,
                resource.width,
                resource.height,
                resource.levels,
                resource.usage,
                resource.format,
                resource.pool,
                kind == Direct3DResourceKind::CubeTexture);
        } else if (kind == Direct3DResourceKind::Buffer) {
            hostDirect3D.createBuffer(
                objectAddress,
                resource.length,
                resource.usage,
                resource.format,
                resource.pool,
                resourceType == 7);
        }
        return objectAddress;
    }

    std::string falloutPrefsPath() const {
        if (const char* userProfile = std::getenv("USERPROFILE")) {
            return (
                std::filesystem::path(userProfile) /
                "Documents" /
                "My Games" /
                "FalloutNV" /
                "FalloutPrefs.ini").string();
        }
        return (
            std::filesystem::path(imagePath).parent_path() /
            "FalloutPrefs.ini").string();
    }

    std::string configuredDirect3DDeviceName() {
        std::string result = profileValue(
            falloutPrefsPath(),
            "Display",
            "sD3DDevice",
            "Sugarbomb Virtual D3D9 Adapter");
        if (result.size() >= 2 && result.front() == '"' && result.back() == '"') {
            result = result.substr(1, result.size() - 2);
        }
        return result.empty() ? "Sugarbomb Virtual D3D9 Adapter" : result;
    }

    U32 configuredDisplayDimension(const char* key, U32 fallback) {
        std::string value = profileValue(
            falloutPrefsPath(),
            "Display",
            key,
            std::to_string(fallback));
        char* end = nullptr;
        unsigned long parsed = std::strtoul(value.c_str(), &end, 10);
        return end != value.c_str() && parsed && parsed <= 16384
            ? static_cast<U32>(parsed)
            : fallback;
    }

    void applyDirect3DPresentationParameters(
        U32 parameters,
        U32 focusWindow = 0) {
        U32 width = configuredDisplayDimension("iSize W", 1280);
        U32 height = configuredDisplayDimension("iSize H", 720);
        U32 format = 22;
        U32 deviceWindow = focusWindow;
        if (parameters && memory->canRead(parameters, 36)) {
            width = memory->readd(parameters);
            height = memory->readd(parameters + 4);
            format = memory->readd(parameters + 8);
            U32 configuredWindow = memory->readd(parameters + 28);
            if (configuredWindow) {
                deviceWindow = configuredWindow;
            }
        }
        direct3DBackBufferWidth =
            width ? width : configuredDisplayDimension("iSize W", 1280);
        direct3DBackBufferHeight =
            height ? height : configuredDisplayDimension("iSize H", 720);
        direct3DBackBufferFormat = format ? format : 22;
        if (guestWindows.count(deviceWindow)) {
            direct3DDeviceWindow = deviceWindow;
        }
        U32 presentationWindow = topLevelGuestWindow(
            direct3DDeviceWindow ? direct3DDeviceWindow : activeWindow);
        auto window = guestWindows.find(presentationWindow);
        if (window != guestWindows.end()) {
            window->second.width = static_cast<S32>(direct3DBackBufferWidth);
            window->second.height = static_cast<S32>(direct3DBackBufferHeight);
            syncHostWindow(window->second);
        }
    }

    void writeDirect3DDisplayMode(U32 destination) {
        if (!destination) {
            return;
        }
        memory->writed(destination, configuredDisplayDimension("iSize W", 1280));
        memory->writed(destination + 4, configuredDisplayDimension("iSize H", 720));
        memory->writed(destination + 8, 60);
        memory->writed(destination + 12, 22); // D3DFMT_X8R8G8B8
    }

    void writeDirect3DCaps(U32 destination) {
        if (!destination) {
            return;
        }
        memory->memset(destination, 0, 304);
        memory->writed(destination, 1); // D3DDEVTYPE_HAL
        memory->writed(destination + 8, 0x00020000);
        memory->writed(destination + 12, 0x20000000);
        memory->writed(destination + 20, 0x80000000);
        memory->writed(destination + 28, 0x0019a000);
        memory->writed(destination + 32, 0x000000f0);
        memory->writed(destination + 36, 0x07000000);
        memory->writed(destination + 60, 0x0000e000);
        memory->writed(destination + 88, 4096);
        memory->writed(destination + 92, 4096);
        memory->writed(destination + 96, 256);
        memory->writed(destination + 100, 8192);
        memory->writed(destination + 104, 4096);
        memory->writed(destination + 108, 16);
        memory->writed(destination + 112, 0x3f800000);
        memory->writed(destination + 144, 0x03ffffff);
        memory->writed(destination + 148, 8);
        memory->writed(destination + 152, 8);
        memory->writed(destination + 160, 8);
        memory->writed(destination + 164, 6);
        memory->writed(destination + 168, 4);
        memory->writed(destination + 172, 255);
        memory->writed(destination + 176, 0x42800000);
        memory->writed(destination + 180, 0x000fffff);
        memory->writed(destination + 184, 0x00ffffff);
        memory->writed(destination + 188, 16);
        memory->writed(destination + 192, 255);
        memory->writed(destination + 196, 0xfffe0300);
        memory->writed(destination + 200, 256);
        memory->writed(destination + 204, 0xffff0300);
        memory->writed(destination + 208, 0x3f800000);
        memory->writed(destination + 232, 1);
        memory->writed(destination + 236, 0x000003ff);
        memory->writed(destination + 240, 4);
        memory->writed(destination + 244, 0x03000300);
        memory->writed(destination + 248, 1);
        memory->writed(destination + 252, 24);
        memory->writed(destination + 256, 32);
        memory->writed(destination + 260, 4);
        memory->writed(destination + 264, 1);
        memory->writed(destination + 268, 24);
        memory->writed(destination + 272, 32);
        memory->writed(destination + 276, 4);
        memory->writed(destination + 280, 512);
        memory->writed(destination + 284, 0x03000300);
        memory->writed(destination + 288, 65535);
        memory->writed(destination + 292, 65535);
        memory->writed(destination + 296, 512);
        memory->writed(destination + 300, 512);
    }

    void dispatchDirect3DComMethod(CPU* cpu, const Direct3DComMethod& method) {
        constexpr U32 D3D_OK = 0;
        constexpr U32 D3DERR_INVALIDCALL = 0x8876086c;
        constexpr U32 D3DERR_NOTAVAILABLE = 0x8876086a;
        constexpr U32 E_POINTER = 0x80004003;

        U32 objectAddress = argument(cpu, 0);
        auto found = direct3DObjects.find(objectAddress);
        if (found == direct3DObjects.end() ||
            (method.device &&
             found->second.kind != Direct3DObjectKind::Device) ||
            (!method.device &&
             found->second.kind != Direct3DObjectKind::Interface)) {
            cpu->reg[0].u32 = E_POINTER;
            return;
        }
        Direct3DObject& object = found->second;
        if (method.index == 0) {
            U32 resultAddress = argument(cpu, 2);
            if (!resultAddress) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            ++object.references;
            memory->writed(objectAddress + 4, object.references);
            memory->writed(resultAddress, objectAddress);
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        if (method.index == 1) {
            ++object.references;
            memory->writed(objectAddress + 4, object.references);
            cpu->reg[0].u32 = object.references;
            return;
        }
        if (method.index == 2) {
            if (object.references) {
                --object.references;
            }
            memory->writed(objectAddress + 4, object.references);
            cpu->reg[0].u32 = object.references;
            return;
        }

        if (!method.device) {
            switch (method.index) {
            case 3: // RegisterSoftwareDevice
                cpu->reg[0].u32 = D3DERR_NOTAVAILABLE;
                return;
            case 4: // GetAdapterCount
                cpu->reg[0].u32 = 1;
                return;
            case 5: { // GetAdapterIdentifier
                U32 identifier = argument(cpu, 3);
                if (!identifier) {
                    cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                    return;
                }
                memory->memset(identifier, 0, 1100);
                memory->strcpy(identifier, "sugarbomb-d3d9");
                std::string description = configuredDirect3DDeviceName();
                memory->strcpy(identifier + 512, description.c_str());
                memory->strcpy(identifier + 1024, "\\\\.\\DISPLAY1");
                memory->writed(identifier + 1064, 0x1414);
                memory->writed(identifier + 1068, 0x0009);
                printf(
                    "Sugarbomb D3D9: adapter description \"%s\"\n",
                    description.c_str());
                cpu->reg[0].u32 = D3D_OK;
                return;
            }
            case 6: // GetAdapterModeCount
                cpu->reg[0].u32 = 1;
                return;
            case 7: // EnumAdapterModes
                if (argument(cpu, 3) != 0 || !argument(cpu, 4)) {
                    cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                } else {
                    writeDirect3DDisplayMode(argument(cpu, 4));
                    cpu->reg[0].u32 = D3D_OK;
                }
                return;
            case 8: // GetAdapterDisplayMode
                if (!argument(cpu, 2)) {
                    cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                } else {
                    writeDirect3DDisplayMode(argument(cpu, 2));
                    cpu->reg[0].u32 = D3D_OK;
                }
                return;
            case 9:  // CheckDeviceType
            case 10: // CheckDeviceFormat
            case 11: // CheckDeviceMultiSampleType
            case 12: // CheckDepthStencilMatch
            case 13: // CheckDeviceFormatConversion
                if (method.index == 11 && argument(cpu, 6)) {
                    memory->writed(argument(cpu, 6), 1);
                }
                cpu->reg[0].u32 = D3D_OK;
                return;
            case 14: // GetDeviceCaps
                if (!argument(cpu, 3)) {
                    cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                } else {
                    writeDirect3DCaps(argument(cpu, 3));
                    cpu->reg[0].u32 = D3D_OK;
                }
                return;
            case 15: // GetAdapterMonitor
                cpu->reg[0].u32 = activeWindow ? activeWindow : 0x57000100;
                return;
            case 16: { // CreateDevice
                U32 resultAddress = argument(cpu, 6);
                if (!resultAddress) {
                    cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                    return;
                }
                applyDirect3DPresentationParameters(
                    argument(cpu, 5),
                    argument(cpu, 3));
                if (!hostDirect3D.ready() &&
                    !hostDirect3D.initialize(
                        hostWindow.nativeHandle(),
                        direct3DBackBufferWidth,
                        direct3DBackBufferHeight)) {
                    fprintf(
                        stderr,
                        "Sugarbomb host D3D9: native device unavailable; "
                        "continuing with the software presentation fallback\n");
                }
                U32 device = createDirect3DObject(Direct3DObjectKind::Device);
                memory->writed(resultAddress, device);
                printf(
                    "Sugarbomb D3D9: CreateDevice(adapter=%u, "
                    "behavior=0x%08X, backbuffer=%ux%u) -> 0x%08X\n",
                    argument(cpu, 1),
                    argument(cpu, 4),
                    direct3DBackBufferWidth,
                    direct3DBackBufferHeight,
                    device);
                cpu->reg[0].u32 = device ? D3D_OK : 0x8007000e;
                return;
            }
            default:
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
        }

        switch (method.index) {
        case 3: // TestCooperativeLevel
        case 5: // EvictManagedResources
        case 20: // SetDialogBoxMode
        case 33: // GetFrontBufferData
        case 46: // MultiplyTransform
        case 49: // SetMaterial
        case 51: // SetLight
        case 53: // LightEnable
        case 55: // SetClipPlane
        case 60: // BeginStateBlock
        case 62: // SetClipStatus
        case 71: // SetPaletteEntries
        case 73: // SetCurrentTexturePalette
        case 77: // SetSoftwareVertexProcessing
        case 79: // SetNPatchMode
        case 83: // DrawPrimitiveUP
        case 84: // DrawIndexedPrimitiveUP
        case 85: // ProcessVertices
        case 115: // DrawRectPatch
        case 116: // DrawTriPatch
        case 117: // DeletePatch
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 30: { // UpdateSurface
            U8 sourceRectangle[16] = {};
            U8 destinationPoint[8] = {};
            const void* sourceRectangleValue = nullptr;
            const void* destinationPointValue = nullptr;
            if (argument(cpu, 2) &&
                memory->canRead(argument(cpu, 2), 16)) {
                memory->memcpy(
                    sourceRectangle,
                    argument(cpu, 2),
                    sizeof(sourceRectangle));
                sourceRectangleValue = sourceRectangle;
            }
            if (argument(cpu, 4) &&
                memory->canRead(argument(cpu, 4), 8)) {
                memory->memcpy(
                    destinationPoint,
                    argument(cpu, 4),
                    sizeof(destinationPoint));
                destinationPointValue = destinationPoint;
            }
            hostDirect3D.updateSurface(
                argument(cpu, 1),
                sourceRectangleValue,
                argument(cpu, 3),
                destinationPointValue);
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 31: // UpdateTexture
            hostDirect3D.updateTexture(
                argument(cpu, 1),
                argument(cpu, 2));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 32: // GetRenderTargetData
            hostDirect3D.getRenderTargetData(
                argument(cpu, 1),
                argument(cpu, 2));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 34: { // StretchRect
            U8 sourceRectangle[16] = {};
            U8 destinationRectangle[16] = {};
            const void* sourceRectangleValue = nullptr;
            const void* destinationRectangleValue = nullptr;
            if (argument(cpu, 2) &&
                memory->canRead(argument(cpu, 2), 16)) {
                memory->memcpy(
                    sourceRectangle,
                    argument(cpu, 2),
                    sizeof(sourceRectangle));
                sourceRectangleValue = sourceRectangle;
            }
            if (argument(cpu, 4) &&
                memory->canRead(argument(cpu, 4), 16)) {
                memory->memcpy(
                    destinationRectangle,
                    argument(cpu, 4),
                    sizeof(destinationRectangle));
                destinationRectangleValue = destinationRectangle;
            }
            hostDirect3D.stretchRect(
                argument(cpu, 1),
                sourceRectangleValue,
                argument(cpu, 3),
                destinationRectangleValue,
                argument(cpu, 5));
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 35: { // ColorFill
            U8 rectangle[16] = {};
            const void* rectangleValue = nullptr;
            if (argument(cpu, 2) &&
                memory->canRead(argument(cpu, 2), 16)) {
                memory->memcpy(
                    rectangle,
                    argument(cpu, 2),
                    sizeof(rectangle));
                rectangleValue = rectangle;
            }
            hostDirect3D.colorFill(
                argument(cpu, 1),
                rectangleValue,
                argument(cpu, 3));
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 16: { // Reset
            applyDirect3DPresentationParameters(argument(cpu, 1));
            hostDirect3D.reset(
                direct3DBackBufferWidth,
                direct3DBackBufferHeight);
            auto backBuffer =
                direct3DSurfaces.find(direct3DBackBufferSurface);
            if (backBuffer != direct3DSurfaces.end()) {
                backBuffer->second.width = direct3DBackBufferWidth;
                backBuffer->second.height = direct3DBackBufferHeight;
                backBuffer->second.format = direct3DBackBufferFormat;
                backBuffer->second.storageAddress = 0;
            }
            auto depthStencil =
                direct3DSurfaces.find(direct3DDepthStencilSurface);
            if (depthStencil != direct3DSurfaces.end()) {
                depthStencil->second.width = direct3DBackBufferWidth;
                depthStencil->second.height = direct3DBackBufferHeight;
                depthStencil->second.storageAddress = 0;
            }
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 17: // Present
            presentHostBackBuffer();
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 39: // SetDepthStencilSurface
            hostDirect3D.setDepthStencilSurface(argument(cpu, 1));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 41: // BeginScene
            hostDirect3D.beginScene();
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 42: // EndScene
            hostDirect3D.endScene();
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 44: { // SetTransform
            U32 matrixAddress = argument(cpu, 2);
            if (matrixAddress && memory->canRead(matrixAddress, 64)) {
                float matrix[16] = {};
                memory->memcpy(matrix, matrixAddress, sizeof(matrix));
                hostDirect3D.setTransform(
                    argument(cpu, 1),
                    matrix);
            }
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 47: { // SetViewport
            U32 viewportAddress = argument(cpu, 1);
            if (viewportAddress && memory->canRead(viewportAddress, 24)) {
                U8 viewport[24] = {};
                memory->memcpy(
                    viewport,
                    viewportAddress,
                    sizeof(viewport));
                hostDirect3D.setViewport(viewport);
            }
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 57: // SetRenderState
            hostDirect3D.setRenderState(
                argument(cpu, 1),
                argument(cpu, 2));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 65: // SetTexture
            hostDirect3D.setTexture(
                argument(cpu, 1),
                argument(cpu, 2));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 67: // SetTextureStageState
            hostDirect3D.setTextureStageState(
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 69: // SetSamplerState
            hostDirect3D.setSamplerState(
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 75: { // SetScissorRect
            U32 rectangleAddress = argument(cpu, 1);
            if (rectangleAddress && memory->canRead(rectangleAddress, 16)) {
                U8 rectangle[16] = {};
                memory->memcpy(
                    rectangle,
                    rectangleAddress,
                    sizeof(rectangle));
                hostDirect3D.setScissorRect(rectangle);
            }
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 81: // DrawPrimitive
            hostDirect3D.drawPrimitive(
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 82: // DrawIndexedPrimitive
            hostDirect3D.drawIndexedPrimitive(
                argument(cpu, 1),
                static_cast<S32>(argument(cpu, 2)),
                argument(cpu, 3),
                argument(cpu, 4),
                argument(cpu, 5),
                argument(cpu, 6));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 87: // SetVertexDeclaration
            hostDirect3D.setVertexDeclaration(argument(cpu, 1));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 89: // SetFVF
            hostDirect3D.setFvf(argument(cpu, 1));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 92: // SetVertexShader
            hostDirect3D.setVertexShader(argument(cpu, 1));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 94: // SetVertexShaderConstantF
        case 96: // SetVertexShaderConstantI
        case 98: { // SetVertexShaderConstantB
            U32 startRegister = argument(cpu, 1);
            U32 valuesAddress = argument(cpu, 2);
            U32 count = argument(cpu, 3);
            U32 componentCount = method.index == 98 ? 1 : 4;
            U64 byteCount64 =
                static_cast<U64>(count) * componentCount * sizeof(U32);
            if (valuesAddress &&
                byteCount64 <= 0x10000 &&
                memory->canRead(
                    valuesAddress,
                    static_cast<U32>(byteCount64))) {
                std::vector<U32> values(
                    static_cast<std::size_t>(count) * componentCount);
                memory->memcpy(
                    values.data(),
                    valuesAddress,
                    static_cast<U32>(byteCount64));
                if (method.index == 94) {
                    hostDirect3D.setVertexShaderConstantF(
                        startRegister,
                        reinterpret_cast<const float*>(values.data()),
                        count);
                } else if (method.index == 96) {
                    hostDirect3D.setVertexShaderConstantI(
                        startRegister,
                        reinterpret_cast<const S32*>(values.data()),
                        count);
                } else {
                    hostDirect3D.setVertexShaderConstantB(
                        startRegister,
                        reinterpret_cast<const S32*>(values.data()),
                        count);
                }
            }
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 100: // SetStreamSource
            hostDirect3D.setStreamSource(
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3),
                argument(cpu, 4));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 102: // SetStreamSourceFreq
            hostDirect3D.setStreamSourceFrequency(
                argument(cpu, 1),
                argument(cpu, 2));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 104: // SetIndices
            hostDirect3D.setIndices(argument(cpu, 1));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 107: // SetPixelShader
            hostDirect3D.setPixelShader(argument(cpu, 1));
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 109: // SetPixelShaderConstantF
        case 111: // SetPixelShaderConstantI
        case 113: { // SetPixelShaderConstantB
            U32 startRegister = argument(cpu, 1);
            U32 valuesAddress = argument(cpu, 2);
            U32 count = argument(cpu, 3);
            U32 componentCount = method.index == 113 ? 1 : 4;
            U64 byteCount64 =
                static_cast<U64>(count) * componentCount * sizeof(U32);
            if (valuesAddress &&
                byteCount64 <= 0x10000 &&
                memory->canRead(
                    valuesAddress,
                    static_cast<U32>(byteCount64))) {
                std::vector<U32> values(
                    static_cast<std::size_t>(count) * componentCount);
                memory->memcpy(
                    values.data(),
                    valuesAddress,
                    static_cast<U32>(byteCount64));
                if (method.index == 109) {
                    hostDirect3D.setPixelShaderConstantF(
                        startRegister,
                        reinterpret_cast<const float*>(values.data()),
                        count);
                } else if (method.index == 111) {
                    hostDirect3D.setPixelShaderConstantI(
                        startRegister,
                        reinterpret_cast<const S32*>(values.data()),
                        count);
                } else {
                    hostDirect3D.setPixelShaderConstantB(
                        startRegister,
                        reinterpret_cast<const S32*>(values.data()),
                        count);
                }
            }
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 37: { // SetRenderTarget
            if (argument(cpu, 1) == 0 &&
                direct3DSurfaces.count(argument(cpu, 2))) {
                direct3DRenderTargetSurface = argument(cpu, 2);
            }
            hostDirect3D.setRenderTarget(
                argument(cpu, 1),
                argument(cpu, 2));
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 43: { // Clear
            constexpr U32 D3DCLEAR_TARGET = 0x00000001;
            if (argument(cpu, 3) & D3DCLEAR_TARGET) {
                U32 renderTarget = ensureDirect3DRenderTarget(false);
                auto surface = direct3DSurfaces.find(renderTarget);
                if (surface != direct3DSurfaces.end()) {
                    clearDirect3DSurface(
                        surface->second,
                        argument(cpu, 4));
                }
            }
            std::vector<U8> rectangles;
            U32 rectangleCount = argument(cpu, 1);
            U32 rectangleAddress = argument(cpu, 2);
            if (rectangleCount &&
                rectangleCount <= 4096 &&
                rectangleAddress &&
                memory->canRead(rectangleAddress, rectangleCount * 16)) {
                rectangles.resize(rectangleCount * 16);
                memory->memcpy(
                    rectangles.data(),
                    rectangleAddress,
                    static_cast<U32>(rectangles.size()));
            } else {
                rectangleCount = 0;
            }
            U32 depthBits = argument(cpu, 5);
            float depth = 1.0f;
            memcpy(&depth, &depthBits, sizeof(depth));
            hostDirect3D.clear(
                rectangleCount,
                rectangles.empty() ? nullptr : rectangles.data(),
                argument(cpu, 3),
                argument(cpu, 4),
                depth,
                argument(cpu, 6));
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 4: // GetAvailableTextureMem
            cpu->reg[0].u32 = 512 * 1024 * 1024;
            return;
        case 6: { // GetDirect3D
            U32 result = argument(cpu, 1);
            if (!result || !direct3DInterfaceAddress) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            ++direct3DObjects[direct3DInterfaceAddress].references;
            memory->writed(result, direct3DInterfaceAddress);
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 7: // GetDeviceCaps
            if (!argument(cpu, 1)) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
            } else {
                writeDirect3DCaps(argument(cpu, 1));
                cpu->reg[0].u32 = D3D_OK;
            }
            return;
        case 8: // GetDisplayMode
            if (!argument(cpu, 2)) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
            } else {
                writeDirect3DDisplayMode(argument(cpu, 2));
                cpu->reg[0].u32 = D3D_OK;
            }
            return;
        case 9: { // GetCreationParameters
            U32 parameters = argument(cpu, 1);
            if (!parameters) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            memory->memset(parameters, 0, 16);
            memory->writed(parameters + 4, 1);
            memory->writed(parameters + 8, activeWindow);
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 10: // SetCursorProperties
        case 13: // CreateAdditionalSwapChain
        case 14: // GetSwapChain
            cpu->reg[0].u32 = D3DERR_NOTAVAILABLE;
            return;
        case 23: // CreateTexture
        case 24: // CreateVolumeTexture
        case 25: { // CreateCubeTexture
            Direct3DResourceKind kind =
                method.index == 25
                ? Direct3DResourceKind::CubeTexture
                : Direct3DResourceKind::Texture;
            U32 resourceType = method.index == 24 ? 4 : (method.index == 25 ? 5 : 3);
            U32 width = argument(cpu, 1);
            U32 height = method.index == 25 ? width : argument(cpu, 2);
            U32 levels = argument(cpu, method.index == 24 ? 4 : (method.index == 25 ? 2 : 3));
            U32 usage = argument(cpu, method.index == 24 ? 5 : (method.index == 25 ? 3 : 4));
            U32 format = argument(cpu, method.index == 24 ? 6 : (method.index == 25 ? 4 : 5));
            U32 pool = argument(cpu, method.index == 24 ? 7 : (method.index == 25 ? 5 : 6));
            U32 resultAddress = argument(cpu, method.index == 24 ? 8 : (method.index == 25 ? 6 : 7));
            if (!resultAddress) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            U32 resource = createDirect3DResource(
                kind,
                resourceType,
                width,
                height,
                levels,
                format,
                usage,
                pool);
            memory->writed(resultAddress, resource);
            cpu->reg[0].u32 = resource ? D3D_OK : 0x8007000e;
            return;
        }
        case 26: // CreateVertexBuffer
        case 27: { // CreateIndexBuffer
            U32 resultAddress = argument(cpu, 5);
            if (!resultAddress) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            U32 resource = createDirect3DResource(
                Direct3DResourceKind::Buffer,
                method.index == 26 ? 6 : 7,
                1,
                1,
                1,
                method.index == 27 ? argument(cpu, 3) : 0,
                argument(cpu, 2),
                argument(cpu, 4),
                argument(cpu, 1));
            memory->writed(resultAddress, resource);
            cpu->reg[0].u32 = resource ? D3D_OK : 0x8007000e;
            return;
        }
        case 59: // CreateStateBlock
        case 61: { // EndStateBlock
            U32 resultAddress = argument(cpu, method.index == 59 ? 2 : 1);
            if (!resultAddress) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            U32 resource = createDirect3DResource(
                Direct3DResourceKind::StateBlock,
                0);
            memory->writed(resultAddress, resource);
            cpu->reg[0].u32 = resource ? D3D_OK : 0x8007000e;
            return;
        }
        case 86: { // CreateVertexDeclaration
            U32 elementsAddress = argument(cpu, 1);
            U32 resultAddress = argument(cpu, 2);
            if (!elementsAddress || !resultAddress) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            U32 resource = createDirect3DResource(
                Direct3DResourceKind::Declaration,
                0);
            std::vector<U8> elements;
            for (U32 index = 0; index < 64; ++index) {
                U32 elementAddress = elementsAddress + index * 8;
                if (!memory->canRead(elementAddress, 8)) {
                    break;
                }
                std::size_t offset = elements.size();
                elements.resize(offset + 8);
                memory->memcpy(
                    elements.data() + offset,
                    elementAddress,
                    8);
                if (memory->readw(elementAddress) == 0x00ff &&
                    memory->readb(elementAddress + 4) == 17) {
                    break;
                }
            }
            if (resource && !elements.empty()) {
                hostDirect3D.createVertexDeclaration(
                    resource,
                    elements.data(),
                    elements.size());
            }
            memory->writed(resultAddress, resource);
            cpu->reg[0].u32 = resource ? D3D_OK : 0x8007000e;
            return;
        }
        case 91: // CreateVertexShader
        case 106: { // CreatePixelShader
            U32 bytecodeAddress = argument(cpu, 1);
            U32 resultAddress = argument(cpu, 2);
            if (!bytecodeAddress || !resultAddress) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            U32 resource = createDirect3DResource(
                Direct3DResourceKind::Shader,
                method.index == 91 ? 1 : 2);
            std::vector<U32> bytecode;
            for (U32 index = 0; index < 65536; ++index) {
                U32 tokenAddress = bytecodeAddress + index * 4;
                if (!memory->canRead(tokenAddress, 4)) {
                    break;
                }
                U32 token = memory->readd(tokenAddress);
                bytecode.push_back(token);
                if (token == 0x0000ffff) {
                    break;
                }
            }
            if (resource &&
                !bytecode.empty() &&
                bytecode.back() == 0x0000ffff) {
                hostDirect3D.createShader(
                    resource,
                    method.index == 106,
                    bytecode.data(),
                    bytecode.size());
            }
            memory->writed(resultAddress, resource);
            cpu->reg[0].u32 = resource ? D3D_OK : 0x8007000e;
            return;
        }
        case 118: { // CreateQuery
            U32 resultAddress = argument(cpu, 2);
            if (!resultAddress) {
                cpu->reg[0].u32 = D3D_OK;
                return;
            }
            U32 resource = createDirect3DResource(
                Direct3DResourceKind::Query,
                argument(cpu, 1));
            memory->writed(resultAddress, resource);
            cpu->reg[0].u32 = resource ? D3D_OK : 0x8007000e;
            return;
        }
        case 18: // GetBackBuffer
        case 38: // GetRenderTarget
        case 40: { // GetDepthStencilSurface
            U32 resultAddress =
                method.index == 18 ? argument(cpu, 4) :
                (method.index == 38 ? argument(cpu, 2) : argument(cpu, 1));
            if (!resultAddress) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            U32 surface =
                method.index == 18
                    ? ensureDirect3DBackBuffer()
                    : ensureDirect3DRenderTarget(method.index == 40);
            if (surface) {
                ++direct3DSurfaces[surface].references;
                memory->writed(surface + 4, direct3DSurfaces[surface].references);
            }
            memory->writed(resultAddress, surface);
            cpu->reg[0].u32 = surface ? D3D_OK : 0x8007000e;
            return;
        }
        case 28: // CreateRenderTarget
        case 29: // CreateDepthStencilSurface
        case 36: { // CreateOffscreenPlainSurface
            U32 width = argument(cpu, 1);
            U32 height = argument(cpu, 2);
            U32 format = argument(cpu, 3);
            U32 resultAddress =
                method.index == 36 ? argument(cpu, 6) : argument(cpu, 8);
            if (!resultAddress) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            U32 surface = createDirect3DSurface(
                width,
                height,
                format,
                method.index == 29 ? 2 : (method.index == 28 ? 1 : 0),
                method.index == 36 ? argument(cpu, 4) : 0,
                method.index == 36 ? 0 : argument(cpu, 4),
                method.index == 36 ? 0 : argument(cpu, 5));
            auto created = direct3DSurfaces.find(surface);
            if (created != direct3DSurfaces.end()) {
                hostDirect3D.createSurface(
                    surface,
                    created->second.width,
                    created->second.height,
                    created->second.format,
                    created->second.usage,
                    created->second.pool,
                    created->second.multiSampleType,
                    created->second.multiSampleQuality);
            }
            memory->writed(resultAddress, surface);
            cpu->reg[0].u32 = surface ? D3D_OK : 0x8007000e;
            return;
        }
        case 11: // SetCursorPosition
        case 21: // SetGammaRamp
            return;
        case 12: // ShowCursor
            cpu->reg[0].u32 = 0;
            return;
        case 15: // GetNumberOfSwapChains
            cpu->reg[0].u32 = 1;
            return;
        case 19: { // GetRasterStatus
            U32 status = argument(cpu, 2);
            if (status) {
                memory->memset(status, 0, 8);
            }
            cpu->reg[0].u32 = status ? D3D_OK : D3DERR_INVALIDCALL;
            return;
        }
        case 22: // GetGammaRamp
            if (argument(cpu, 2)) {
                memory->memset(argument(cpu, 2), 0, 1536);
            }
            return;
        case 45: // GetTransform
            if (argument(cpu, 2)) {
                memory->memset(argument(cpu, 2), 0, 64);
                memory->writed(argument(cpu, 2), 0x3f800000);
                memory->writed(argument(cpu, 2) + 20, 0x3f800000);
                memory->writed(argument(cpu, 2) + 40, 0x3f800000);
                memory->writed(argument(cpu, 2) + 60, 0x3f800000);
            }
            cpu->reg[0].u32 = argument(cpu, 2) ? D3D_OK : D3DERR_INVALIDCALL;
            return;
        case 48: // GetViewport
            if (argument(cpu, 1)) {
                memory->memset(argument(cpu, 1), 0, 24);
                memory->writed(argument(cpu, 1) + 8, 1280);
                memory->writed(argument(cpu, 1) + 12, 720);
                memory->writed(argument(cpu, 1) + 20, 0x3f800000);
            }
            cpu->reg[0].u32 = argument(cpu, 1) ? D3D_OK : D3DERR_INVALIDCALL;
            return;
        case 54: // GetLightEnable
        case 58: // GetRenderState
        case 66: // GetTextureStageState
        case 68: // GetSamplerState
        case 74: // GetCurrentTexturePalette
        case 90: // GetFVF
        case 103: // GetStreamSourceFreq
            {
                U32 outputIndex =
                    method.index == 74 || method.index == 90
                    ? 1
                    : (method.index == 54 || method.index == 58 ||
                               method.index == 103
                           ? 2
                           : 3);
                if (!argument(cpu, outputIndex)) {
                    cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                    return;
                }
                memory->writed(argument(cpu, outputIndex), 0);
                cpu->reg[0].u32 = D3D_OK;
                return;
            }
        case 70: // ValidateDevice
            if (argument(cpu, 1)) {
                memory->writed(argument(cpu, 1), 1);
            }
            cpu->reg[0].u32 = argument(cpu, 1) ? D3D_OK : D3DERR_INVALIDCALL;
            return;
        case 78: // GetSoftwareVertexProcessing
            cpu->reg[0].u32 = 0;
            return;
        default:
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
    }

    void dispatchDirect3DSurfaceMethod(CPU* cpu, U32 methodIndex) {
        constexpr U32 D3D_OK = 0;
        constexpr U32 D3DERR_INVALIDCALL = 0x8876086c;
        constexpr U32 D3DERR_NOTFOUND = 0x88760866;
        constexpr U32 E_POINTER = 0x80004003;
        constexpr U32 E_NOINTERFACE = 0x80004002;

        U32 objectAddress = argument(cpu, 0);
        auto found = direct3DSurfaces.find(objectAddress);
        if (found == direct3DSurfaces.end()) {
            cpu->reg[0].u32 = E_POINTER;
            return;
        }
        Direct3DSurface& surface = found->second;
        switch (methodIndex) {
        case 0: { // QueryInterface
            U32 resultAddress = argument(cpu, 2);
            if (!resultAddress) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            ++surface.references;
            memory->writed(objectAddress + 4, surface.references);
            memory->writed(resultAddress, objectAddress);
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 1: // AddRef
            ++surface.references;
            memory->writed(objectAddress + 4, surface.references);
            cpu->reg[0].u32 = surface.references;
            return;
        case 2: // Release
            if (surface.references) {
                --surface.references;
            }
            memory->writed(objectAddress + 4, surface.references);
            if (!surface.references) {
                hostDirect3D.releaseResource(objectAddress);
            }
            cpu->reg[0].u32 = surface.references;
            return;
        case 3: { // GetDevice
            U32 resultAddress = argument(cpu, 1);
            if (!resultAddress || !direct3DDeviceAddress) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            ++direct3DObjects[direct3DDeviceAddress].references;
            memory->writed(resultAddress, direct3DDeviceAddress);
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 4: // SetPrivateData
        case 6: // FreePrivateData
            cpu->reg[0].u32 = D3D_OK;
            return;
        case 5: // GetPrivateData
            cpu->reg[0].u32 = D3DERR_NOTFOUND;
            return;
        case 7: // SetPriority
        case 8: // GetPriority
            cpu->reg[0].u32 = 0;
            return;
        case 9: // PreLoad
            return;
        case 10: // GetType
            cpu->reg[0].u32 = 1; // D3DRTYPE_SURFACE
            return;
        case 11: { // GetContainer
            U32 resultAddress = argument(cpu, 2);
            if (resultAddress) {
                memory->writed(resultAddress, 0);
            }
            cpu->reg[0].u32 = E_NOINTERFACE;
            return;
        }
        case 12: { // GetDesc
            U32 description = argument(cpu, 1);
            if (!description) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            memory->writed(description, surface.format);
            memory->writed(description + 4, 1); // D3DRTYPE_SURFACE
            memory->writed(description + 8, surface.usage);
            memory->writed(description + 12, surface.pool);
            memory->writed(description + 16, surface.multiSampleType);
            memory->writed(description + 20, surface.multiSampleQuality);
            memory->writed(description + 24, surface.width);
            memory->writed(description + 28, surface.height);
            if (surfaceDescTraceCount < 16) {
                printf(
                    "Sugarbomb D3D9: Surface::GetDesc -> %ux%u format %u "
                    "(guest return 0x%08X)\n",
                    surface.width,
                    surface.height,
                    surface.format,
                    cpu->peek32(1));
                ++surfaceDescTraceCount;
            }
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 13: { // LockRect
            U32 lockedRect = argument(cpu, 1);
            if (!lockedRect) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            if (!ensureDirect3DSurfaceStorage(surface)) {
                cpu->reg[0].u32 = 0x8007000e;
                return;
            }
            U32 bits = surface.storageAddress;
            U32 rectangle = argument(cpu, 2);
            if (rectangle) {
                U32 left = memory->readd(rectangle);
                U32 top = memory->readd(rectangle + 4);
                if (left < surface.width && top < surface.height) {
                    U32 bytesPerPixel =
                        surface.width
                            ? surface.lockPitch / surface.width
                            : 0;
                    bits += top * surface.lockPitch +
                        left * bytesPerPixel;
                }
            }
            memory->writed(lockedRect, surface.lockPitch);
            memory->writed(lockedRect + 4, bits);
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 14: { // UnlockRect
            U32 byteCount = surface.lockPitch * surface.lockRows;
            if (surface.storageAddress &&
                byteCount &&
                memory->canRead(surface.storageAddress, byteCount)) {
                std::vector<U8> upload(byteCount);
                memory->memcpy(
                    upload.data(),
                    surface.storageAddress,
                    byteCount);
                if (surface.parentResource) {
                    hostDirect3D.uploadTexture(
                        surface.parentResource,
                        surface.parentFace,
                        surface.parentLevel,
                        upload.data(),
                        surface.lockPitch,
                        surface.lockRows);
                } else {
                    hostDirect3D.uploadSurface(
                        objectAddress,
                        upload.data(),
                        surface.lockPitch,
                        surface.width,
                        surface.lockRows);
                }
            }
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 15: // GetDC
            if (argument(cpu, 1)) {
                memory->writed(argument(cpu, 1), 0);
            }
            cpu->reg[0].u32 = 0x80004001;
            return;
        case 16: // ReleaseDC
            cpu->reg[0].u32 = D3D_OK;
            return;
        default:
            cpu->reg[0].u32 = D3DERR_INVALIDCALL;
            return;
        }
    }

    void dispatchDirect3DResourceMethod(
        CPU* cpu,
        const Direct3DResourceMethod& method) {
        constexpr U32 D3D_OK = 0;
        constexpr U32 D3DERR_INVALIDCALL = 0x8876086c;
        constexpr U32 D3DERR_NOTFOUND = 0x88760866;
        constexpr U32 E_POINTER = 0x80004003;

        U32 objectAddress = argument(cpu, 0);
        auto found = direct3DResources.find(objectAddress);
        if (found == direct3DResources.end() ||
            found->second.kind != method.kind) {
            cpu->reg[0].u32 = E_POINTER;
            return;
        }
        Direct3DResource& resource = found->second;
        switch (method.index) {
        case 0: { // QueryInterface
            U32 resultAddress = argument(cpu, 2);
            if (!resultAddress) {
                cpu->reg[0].u32 = E_POINTER;
                return;
            }
            ++resource.references;
            memory->writed(objectAddress + 4, resource.references);
            memory->writed(resultAddress, objectAddress);
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        case 1: // AddRef
            ++resource.references;
            memory->writed(objectAddress + 4, resource.references);
            cpu->reg[0].u32 = resource.references;
            return;
        case 2: // Release
            if (resource.references) {
                --resource.references;
            }
            memory->writed(objectAddress + 4, resource.references);
            if (!resource.references) {
                hostDirect3D.releaseResource(objectAddress);
            }
            cpu->reg[0].u32 = resource.references;
            return;
        case 3: { // GetDevice
            U32 resultAddress = argument(cpu, 1);
            if (!resultAddress || !direct3DDeviceAddress) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            ++direct3DObjects[direct3DDeviceAddress].references;
            memory->writed(resultAddress, direct3DDeviceAddress);
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        default:
            break;
        }

        if (resource.kind == Direct3DResourceKind::Texture ||
            resource.kind == Direct3DResourceKind::CubeTexture ||
            resource.kind == Direct3DResourceKind::Buffer) {
            switch (method.index) {
            case 4: // SetPrivateData
            case 6: // FreePrivateData
                cpu->reg[0].u32 = D3D_OK;
                return;
            case 5: // GetPrivateData
                cpu->reg[0].u32 = D3DERR_NOTFOUND;
                return;
            case 7: // SetPriority
            case 8: // GetPriority
                cpu->reg[0].u32 = 0;
                return;
            case 9: // PreLoad
                return;
            case 10: // GetType
                cpu->reg[0].u32 = resource.resourceType;
                return;
            default:
                break;
            }
        }

        if (resource.kind == Direct3DResourceKind::Texture ||
            resource.kind == Direct3DResourceKind::CubeTexture) {
            switch (method.index) {
            case 11: // SetLOD
            case 12: // GetLOD
                cpu->reg[0].u32 = 0;
                return;
            case 13: // GetLevelCount
                cpu->reg[0].u32 = resource.levels;
                return;
            case 14: // SetAutoGenFilterType
                cpu->reg[0].u32 = D3D_OK;
                return;
            case 15: // GetAutoGenFilterType
                cpu->reg[0].u32 = 2; // D3DTEXF_LINEAR
                return;
            case 16: // GenerateMipSubLevels
                return;
            case 17: { // GetLevelDesc
                U32 level = argument(cpu, 1);
                U32 description = argument(cpu, 2);
                if (!description || level >= resource.levels) {
                    cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                    return;
                }
                U32 width = std::max<U32>(1, resource.width >> level);
                U32 height = std::max<U32>(1, resource.height >> level);
                memory->memset(description, 0, 32);
                memory->writed(description, resource.format);
                memory->writed(description + 4, 1); // D3DRTYPE_SURFACE
                memory->writed(description + 8, resource.usage);
                memory->writed(description + 12, resource.pool);
                memory->writed(description + 24, width);
                memory->writed(description + 28, height);
                cpu->reg[0].u32 = D3D_OK;
                return;
            }
            case 18: { // GetSurfaceLevel / GetCubeMapSurface
                U32 level = argument(
                    cpu,
                    resource.kind == Direct3DResourceKind::CubeTexture ? 2 : 1);
                U32 resultAddress = argument(
                    cpu,
                    resource.kind == Direct3DResourceKind::CubeTexture ? 3 : 2);
                if (!resultAddress || level >= resource.levels) {
                    cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                    return;
                }
                U32 surface = createDirect3DSurface(
                    std::max<U32>(1, resource.width >> level),
                    std::max<U32>(1, resource.height >> level),
                    resource.format,
                    resource.usage,
                    resource.pool);
                auto created = direct3DSurfaces.find(surface);
                if (created != direct3DSurfaces.end()) {
                    created->second.parentResource = objectAddress;
                    created->second.parentFace =
                        resource.kind == Direct3DResourceKind::CubeTexture
                            ? argument(cpu, 1)
                            : 0;
                    created->second.parentLevel = level;
                    hostDirect3D.aliasTextureSurface(
                        surface,
                        objectAddress,
                        created->second.parentFace,
                        level);
                }
                memory->writed(resultAddress, surface);
                cpu->reg[0].u32 = surface ? D3D_OK : 0x8007000e;
                return;
            }
            case 19: { // LockRect
                bool cube =
                    resource.kind == Direct3DResourceKind::CubeTexture;
                U32 level = argument(cpu, cube ? 2 : 1);
                U32 lockedRect = argument(cpu, cube ? 3 : 2);
                U32 rectangle = argument(cpu, cube ? 4 : 3);
                if (!lockedRect || level >= resource.levels) {
                    cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                    return;
                }
                U32 width = std::max<U32>(1, resource.width >> level);
                U32 height = std::max<U32>(1, resource.height >> level);
                U32 basePitch = 0;
                U32 baseRows = 0;
                direct3DStorageLayout(
                    resource.format,
                    resource.width,
                    resource.height,
                    basePitch,
                    baseRows);
                direct3DStorageLayout(
                    resource.format,
                    width,
                    height,
                    resource.lockPitch,
                    resource.lockRows);
                U64 storageSize64 =
                    static_cast<U64>(basePitch) * baseRows;
                if (!resource.storageAddress &&
                    storageSize64 &&
                    storageSize64 <= 0x10000000) {
                    resource.storageAddress = allocateGuestHeap(
                        static_cast<U32>(storageSize64),
                        true);
                }
                if (!resource.storageAddress) {
                    cpu->reg[0].u32 = 0x8007000e;
                    return;
                }
                U32 bits = resource.storageAddress;
                if (rectangle) {
                    U32 left = memory->readd(rectangle);
                    U32 top = memory->readd(rectangle + 4);
                    if (left < width && top < height) {
                        U32 bytesPerPixel =
                            width ? resource.lockPitch / width : 0;
                        bits += top * resource.lockPitch +
                            left * bytesPerPixel;
                    }
                }
                resource.lockFace =
                    cube ? argument(cpu, 1) : 0;
                resource.lockLevel = level;
                memory->writed(lockedRect, resource.lockPitch);
                memory->writed(lockedRect + 4, bits);
                cpu->reg[0].u32 = D3D_OK;
                return;
            }
            case 20: { // UnlockRect
                U32 byteCount = resource.lockPitch * resource.lockRows;
                if (resource.storageAddress &&
                    byteCount &&
                    memory->canRead(resource.storageAddress, byteCount)) {
                    std::vector<U8> upload(byteCount);
                    memory->memcpy(
                        upload.data(),
                        resource.storageAddress,
                        byteCount);
                    hostDirect3D.uploadTexture(
                        objectAddress,
                        resource.lockFace,
                        resource.lockLevel,
                        upload.data(),
                        resource.lockPitch,
                        resource.lockRows);
                }
                cpu->reg[0].u32 = D3D_OK;
                return;
            }
            case 21: // AddDirtyRect
                cpu->reg[0].u32 = D3D_OK;
                return;
            default:
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
        }

        if (resource.kind == Direct3DResourceKind::Buffer) {
            switch (method.index) {
            case 11: { // Lock
                U32 offset = argument(cpu, 1);
                U32 size = argument(cpu, 2);
                U32 resultAddress = argument(cpu, 3);
                U32 capacity = resource.length ? resource.length : 4096;
                if (!resultAddress || offset > capacity ||
                    (size && size > capacity - offset)) {
                    cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                    return;
                }
                if (!resource.storageAddress) {
                    resource.storageAddress = allocateGuestHeap(capacity, true);
                }
                resource.lockOffset = offset;
                resource.lockSize = size ? size : capacity - offset;
                memory->writed(
                    resultAddress,
                    resource.storageAddress
                        ? resource.storageAddress + offset
                        : 0);
                cpu->reg[0].u32 =
                    resource.storageAddress ? D3D_OK : 0x8007000e;
                return;
            }
            case 12: { // Unlock
                if (resource.storageAddress &&
                    resource.lockSize &&
                    memory->canRead(
                        resource.storageAddress + resource.lockOffset,
                        resource.lockSize)) {
                    std::vector<U8> upload(resource.lockSize);
                    memory->memcpy(
                        upload.data(),
                        resource.storageAddress + resource.lockOffset,
                        resource.lockSize);
                    hostDirect3D.uploadBuffer(
                        objectAddress,
                        upload.data(),
                        resource.lockOffset,
                        resource.lockSize);
                }
                cpu->reg[0].u32 = D3D_OK;
                return;
            }
            case 13: { // GetDesc
                U32 description = argument(cpu, 1);
                if (!description) {
                    cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                    return;
                }
                memory->memset(description, 0, 24);
                memory->writed(description, resource.format);
                memory->writed(description + 4, resource.resourceType);
                memory->writed(description + 8, resource.usage);
                memory->writed(description + 12, resource.pool);
                memory->writed(description + 16, resource.length);
                cpu->reg[0].u32 = D3D_OK;
                return;
            }
            default:
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
        }

        if (resource.kind == Direct3DResourceKind::Declaration &&
            method.index == 4) {
            U32 countAddress = argument(cpu, 2);
            if (!countAddress) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            memory->writed(countAddress, 0);
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        if (resource.kind == Direct3DResourceKind::Shader &&
            method.index == 4) {
            U32 sizeAddress = argument(cpu, 2);
            if (!sizeAddress) {
                cpu->reg[0].u32 = D3DERR_INVALIDCALL;
                return;
            }
            memory->writed(sizeAddress, 0);
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        if (resource.kind == Direct3DResourceKind::StateBlock &&
            (method.index == 4 || method.index == 5)) {
            cpu->reg[0].u32 = D3D_OK;
            return;
        }
        if (resource.kind == Direct3DResourceKind::Query) {
            switch (method.index) {
            case 4: // GetType
                cpu->reg[0].u32 = resource.resourceType;
                return;
            case 5: // GetDataSize
                cpu->reg[0].u32 = 4;
                return;
            case 6: // Issue
                cpu->reg[0].u32 = D3D_OK;
                return;
            case 7: { // GetData
                U32 data = argument(cpu, 1);
                U32 size = argument(cpu, 2);
                if (data && size) {
                    memory->memset(data, 0, size);
                }
                cpu->reg[0].u32 = D3D_OK;
                return;
            }
            default:
                break;
            }
        }
        cpu->reg[0].u32 = D3DERR_INVALIDCALL;
    }

    static void callbackDirect3DCreate9(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "D3D9!Direct3DCreate9");
        if (!session) {
            return;
        }
        U32 sdkVersion = argument(cpu, 0);
        U32 direct3D = session->createDirect3DObject(
            Direct3DObjectKind::Interface);
        printf(
            "Sugarbomb D3D9: Direct3DCreate9(SDK=%u) -> 0x%08X\n",
            sdkVersion,
            direct3D);
        cpu->reg[0].u32 = direct3D;
    }

    static void callbackDirect3DComMethod(CPU* cpu) {
        if (!activeSession) {
            cpu->thread->terminating = true;
            return;
        }
        U32 callbackIndex = cpu->peek32(0);
        auto found = activeSession->direct3DComMethods.find(callbackIndex);
        if (found == activeSession->direct3DComMethods.end()) {
            callbackUnresolvedImport(cpu);
            return;
        }
        std::string module;
        std::string symbol;
        SugarbombBridge::callbackName(callbackIndex, module, symbol);
        std::string api = "D3D9!" + symbol;
        SugarbombRuntimeSession* session = current(cpu, api.c_str());
        if (session) {
            session->dispatchDirect3DComMethod(cpu, found->second);
        }
    }

    static void callbackDirect3DSurfaceMethod(CPU* cpu) {
        if (!activeSession) {
            cpu->thread->terminating = true;
            return;
        }
        U32 callbackIndex = cpu->peek32(0);
        auto found = activeSession->direct3DSurfaceMethods.find(callbackIndex);
        if (found == activeSession->direct3DSurfaceMethods.end()) {
            callbackUnresolvedImport(cpu);
            return;
        }
        std::string module;
        std::string symbol;
        SugarbombBridge::callbackName(callbackIndex, module, symbol);
        std::string api = "D3D9!" + symbol;
        SugarbombRuntimeSession* session = current(cpu, api.c_str());
        if (session) {
            session->dispatchDirect3DSurfaceMethod(cpu, found->second);
        }
    }

    static void callbackDirect3DResourceMethod(CPU* cpu) {
        if (!activeSession) {
            cpu->thread->terminating = true;
            return;
        }
        U32 callbackIndex = cpu->peek32(0);
        auto found = activeSession->direct3DResourceMethods.find(callbackIndex);
        if (found == activeSession->direct3DResourceMethods.end()) {
            callbackUnresolvedImport(cpu);
            return;
        }
        std::string module;
        std::string symbol;
        SugarbombBridge::callbackName(callbackIndex, module, symbol);
        std::string api = "D3D9!" + symbol;
        SugarbombRuntimeSession* session = current(cpu, api.c_str());
        if (session) {
            session->dispatchDirect3DResourceMethod(cpu, found->second);
        }
    }

    static void callbackXInputGetState(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "XINPUT1_3!XInputGetState");
        if (!session) {
            return;
        }
        U32 state = argument(cpu, 1);
        if (state) {
            session->memory->memset(state, 0, 16);
        }
        cpu->reg[0].u32 = 1167; // ERROR_DEVICE_NOT_CONNECTED
    }

    static void callbackXInputSetState(CPU* cpu) {
        if (current(cpu, "XINPUT1_3!XInputSetState")) {
            cpu->reg[0].u32 = 1167; // ERROR_DEVICE_NOT_CONNECTED
        }
    }

    static void callbackFalloutCompatibilityNoOp(CPU* cpu) {
        if (current(cpu, "FALLOUTNV!BootstrapCompatibilityNoOp")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackFalloutMemorySystemInitializeThread(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "FALLOUTNV!BootstrapMemorySystem::InitializeThread");
        if (!session) {
            return;
        }
        U32 router = argument(cpu, 0);
        if (!router ||
            !session->falloutBootstrapAllocator ||
            !session->memory->canWrite(router, 0x1c)) {
            cpu->reg[0].u32 = 0;
            return;
        }
        session->memory->writed(
            router + 0x10,
            session->falloutBootstrapAllocator);
        session->memory->writed(
            router + 0x14,
            session->falloutBootstrapAllocator);
        cpu->reg[0].u32 = router;
    }

    static void callbackFalloutAllocatorAllocate(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "FALLOUTNV!BootstrapAllocator::Allocate");
        if (!session) {
            return;
        }
        U32 size = argument(cpu, 0);
        cpu->reg[0].u32 =
            size && size <= 0x10000000
            ? session->allocateGuestHeap(size, false)
            : 0;
    }

    static void callbackFalloutAllocatorFree(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "FALLOUTNV!BootstrapAllocator::Free");
        if (!session) {
            return;
        }
        U32 address = argument(cpu, 0);
        auto found = session->heapAllocations.find(address);
        if (found != session->heapAllocations.end()) {
            session->freeGuestHeap(address);
        }
        cpu->reg[0].u32 = 0;
    }

    static void callbackD3DPerfSetOptions(CPU* cpu) {
        if (current(cpu, "D3D9!D3DPERF_SetOptions")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static float guestFloat(SugarbombRuntimeSession* session, U32 address) {
        U32 bits = session->memory->readd(address);
        float value = 0.0f;
        memcpy(&value, &bits, sizeof(value));
        return value;
    }

    static float argumentFloat(CPU* cpu, U32 index) {
        U32 bits = argument(cpu, index);
        float value = 0.0f;
        memcpy(&value, &bits, sizeof(value));
        return value;
    }

    static void writeGuestFloat(
        SugarbombRuntimeSession* session,
        U32 address,
        float value) {
        U32 bits = 0;
        memcpy(&bits, &value, sizeof(bits));
        session->memory->writed(address, bits);
    }

    static void readGuestMatrix(
        SugarbombRuntimeSession* session,
        U32 address,
        float result[16]) {
        for (U32 index = 0; index < 16; ++index) {
            result[index] = guestFloat(session, address + index * 4);
        }
    }

    static void writeGuestMatrix(
        SugarbombRuntimeSession* session,
        U32 address,
        const float value[16]) {
        for (U32 index = 0; index < 16; ++index) {
            writeGuestFloat(session, address + index * 4, value[index]);
        }
    }

    static void multiplyMatrix(
        const float left[16],
        const float right[16],
        float result[16]) {
        for (U32 row = 0; row < 4; ++row) {
            for (U32 column = 0; column < 4; ++column) {
                float value = 0.0f;
                for (U32 inner = 0; inner < 4; ++inner) {
                    value += left[row * 4 + inner] *
                        right[inner * 4 + column];
                }
                result[row * 4 + column] = value;
            }
        }
    }

    static void callbackD3DXMatrixMultiply(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "D3DX9!D3DXMatrixMultiply");
        if (!session) {
            return;
        }
        U32 destination = argument(cpu, 0);
        float left[16] = {};
        float right[16] = {};
        float result[16] = {};
        readGuestMatrix(session, argument(cpu, 1), left);
        readGuestMatrix(session, argument(cpu, 2), right);
        multiplyMatrix(left, right, result);
        writeGuestMatrix(session, destination, result);
        cpu->reg[0].u32 = destination;
    }

    static void callbackD3DXMatrixMultiplyTranspose(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "D3DX9!D3DXMatrixMultiplyTranspose");
        if (!session) {
            return;
        }
        U32 destination = argument(cpu, 0);
        float left[16] = {};
        float right[16] = {};
        float product[16] = {};
        float result[16] = {};
        readGuestMatrix(session, argument(cpu, 1), left);
        readGuestMatrix(session, argument(cpu, 2), right);
        multiplyMatrix(left, right, product);
        for (U32 row = 0; row < 4; ++row) {
            for (U32 column = 0; column < 4; ++column) {
                result[row * 4 + column] = product[column * 4 + row];
            }
        }
        writeGuestMatrix(session, destination, result);
        cpu->reg[0].u32 = destination;
    }

    static void callbackD3DXMatrixTranspose(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "D3DX9!D3DXMatrixTranspose");
        if (!session) {
            return;
        }
        U32 destination = argument(cpu, 0);
        float source[16] = {};
        float result[16] = {};
        readGuestMatrix(session, argument(cpu, 1), source);
        for (U32 row = 0; row < 4; ++row) {
            for (U32 column = 0; column < 4; ++column) {
                result[row * 4 + column] = source[column * 4 + row];
            }
        }
        writeGuestMatrix(session, destination, result);
        cpu->reg[0].u32 = destination;
    }

    static void callbackD3DXMatrixInverse(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "D3DX9!D3DXMatrixInverse");
        if (!session) {
            return;
        }
        U32 destination = argument(cpu, 0);
        float source[16] = {};
        float augmented[4][8] = {};
        readGuestMatrix(session, argument(cpu, 2), source);
        for (U32 row = 0; row < 4; ++row) {
            for (U32 column = 0; column < 4; ++column) {
                augmented[row][column] = source[row * 4 + column];
            }
            augmented[row][row + 4] = 1.0f;
        }
        float determinant = 1.0f;
        int sign = 1;
        for (U32 pivotColumn = 0; pivotColumn < 4; ++pivotColumn) {
            U32 pivotRow = pivotColumn;
            for (U32 row = pivotColumn + 1; row < 4; ++row) {
                if (std::fabs(augmented[row][pivotColumn]) >
                    std::fabs(augmented[pivotRow][pivotColumn])) {
                    pivotRow = row;
                }
            }
            float pivot = augmented[pivotRow][pivotColumn];
            if (std::fabs(pivot) < 1.0e-20f) {
                if (argument(cpu, 1)) {
                    writeGuestFloat(session, argument(cpu, 1), 0.0f);
                }
                cpu->reg[0].u32 = 0;
                return;
            }
            if (pivotRow != pivotColumn) {
                for (U32 column = 0; column < 8; ++column) {
                    std::swap(
                        augmented[pivotRow][column],
                        augmented[pivotColumn][column]);
                }
                sign = -sign;
            }
            determinant *= pivot;
            for (U32 column = 0; column < 8; ++column) {
                augmented[pivotColumn][column] /= pivot;
            }
            for (U32 row = 0; row < 4; ++row) {
                if (row == pivotColumn) {
                    continue;
                }
                float factor = augmented[row][pivotColumn];
                for (U32 column = 0; column < 8; ++column) {
                    augmented[row][column] -=
                        factor * augmented[pivotColumn][column];
                }
            }
        }
        float inverse[16] = {};
        for (U32 row = 0; row < 4; ++row) {
            for (U32 column = 0; column < 4; ++column) {
                inverse[row * 4 + column] = augmented[row][column + 4];
            }
        }
        if (argument(cpu, 1)) {
            writeGuestFloat(
                session,
                argument(cpu, 1),
                determinant * static_cast<float>(sign));
        }
        writeGuestMatrix(session, destination, inverse);
        cpu->reg[0].u32 = destination;
    }

    static void callbackD3DXMatrixRotationYawPitchRoll(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "D3DX9!D3DXMatrixRotationYawPitchRoll");
        if (!session) {
            return;
        }
        float yaw = argumentFloat(cpu, 1);
        float pitch = argumentFloat(cpu, 2);
        float roll = argumentFloat(cpu, 3);
        float yawMatrix[16] = {
            std::cos(yaw), 0.0f, -std::sin(yaw), 0.0f,
            0.0f, 1.0f, 0.0f, 0.0f,
            std::sin(yaw), 0.0f, std::cos(yaw), 0.0f,
            0.0f, 0.0f, 0.0f, 1.0f};
        float pitchMatrix[16] = {
            1.0f, 0.0f, 0.0f, 0.0f,
            0.0f, std::cos(pitch), std::sin(pitch), 0.0f,
            0.0f, -std::sin(pitch), std::cos(pitch), 0.0f,
            0.0f, 0.0f, 0.0f, 1.0f};
        float rollMatrix[16] = {
            std::cos(roll), std::sin(roll), 0.0f, 0.0f,
            -std::sin(roll), std::cos(roll), 0.0f, 0.0f,
            0.0f, 0.0f, 1.0f, 0.0f,
            0.0f, 0.0f, 0.0f, 1.0f};
        float intermediate[16] = {};
        float result[16] = {};
        multiplyMatrix(yawMatrix, pitchMatrix, intermediate);
        multiplyMatrix(intermediate, rollMatrix, result);
        writeGuestMatrix(session, argument(cpu, 0), result);
        cpu->reg[0].u32 = argument(cpu, 0);
    }

    static void transformGuestVector(
        SugarbombRuntimeSession* session,
        U32 destination,
        U32 sourceAddress,
        U32 matrixAddress,
        float sourceW,
        bool divideByW,
        U32 resultComponents) {
        float source[4] = {
            guestFloat(session, sourceAddress),
            guestFloat(session, sourceAddress + 4),
            guestFloat(session, sourceAddress + 8),
            sourceW};
        if (resultComponents == 4) {
            source[3] = guestFloat(session, sourceAddress + 12);
        }
        float matrix[16] = {};
        float result[4] = {};
        readGuestMatrix(session, matrixAddress, matrix);
        for (U32 column = 0; column < 4; ++column) {
            for (U32 row = 0; row < 4; ++row) {
                result[column] += source[row] * matrix[row * 4 + column];
            }
        }
        if (divideByW && std::fabs(result[3]) > 1.0e-20f) {
            result[0] /= result[3];
            result[1] /= result[3];
            result[2] /= result[3];
        }
        for (U32 index = 0; index < resultComponents; ++index) {
            writeGuestFloat(session, destination + index * 4, result[index]);
        }
    }

    static void callbackD3DXVec4Transform(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "D3DX9!D3DXVec4Transform");
        if (session) {
            transformGuestVector(
                session,
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                1.0f,
                false,
                4);
            cpu->reg[0].u32 = argument(cpu, 0);
        }
    }

    static void callbackD3DXVec3TransformCoord(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "D3DX9!D3DXVec3TransformCoord");
        if (session) {
            transformGuestVector(
                session,
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                1.0f,
                true,
                3);
            cpu->reg[0].u32 = argument(cpu, 0);
        }
    }

    static void callbackD3DXVec3TransformNormal(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "D3DX9!D3DXVec3TransformNormal");
        if (session) {
            transformGuestVector(
                session,
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                0.0f,
                false,
                3);
            cpu->reg[0].u32 = argument(cpu, 0);
        }
    }

    static void normalizeGuestVector(
        SugarbombRuntimeSession* session,
        U32 destination,
        U32 source,
        U32 components,
        U32 lengthComponents) {
        float value[4] = {};
        float lengthSquared = 0.0f;
        for (U32 index = 0; index < components; ++index) {
            value[index] = guestFloat(session, source + index * 4);
            if (index < lengthComponents) {
                lengthSquared += value[index] * value[index];
            }
        }
        float inverseLength = lengthSquared > 1.0e-30f
            ? 1.0f / std::sqrt(lengthSquared)
            : 0.0f;
        for (U32 index = 0; index < components; ++index) {
            writeGuestFloat(
                session,
                destination + index * 4,
                value[index] * inverseLength);
        }
    }

    static void callbackD3DXVec3Normalize(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "D3DX9!D3DXVec3Normalize");
        if (session) {
            normalizeGuestVector(
                session,
                argument(cpu, 0),
                argument(cpu, 1),
                3,
                3);
            cpu->reg[0].u32 = argument(cpu, 0);
        }
    }

    static void callbackD3DXPlaneTransform(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "D3DX9!D3DXPlaneTransform");
        if (session) {
            transformGuestVector(
                session,
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                1.0f,
                false,
                4);
            cpu->reg[0].u32 = argument(cpu, 0);
        }
    }

    static void callbackD3DXPlaneNormalize(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "D3DX9!D3DXPlaneNormalize");
        if (session) {
            normalizeGuestVector(
                session,
                argument(cpu, 0),
                argument(cpu, 1),
                4,
                3);
            cpu->reg[0].u32 = argument(cpu, 0);
        }
    }

    U32 direct3DShaderProfile(const char* profile, U32& cachedAddress) {
        if (!cachedAddress) {
            cachedAddress = allocateGuestHeap(
                static_cast<U32>(strlen(profile) + 1),
                true);
            if (cachedAddress) {
                memory->strcpy(cachedAddress, profile);
            }
        }
        return cachedAddress;
    }

    static void callbackD3DXGetVertexShaderProfile(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "D3DX9!D3DXGetVertexShaderProfile");
        if (session) {
            cpu->reg[0].u32 = session->direct3DShaderProfile(
                "vs_3_0",
                session->direct3DVertexProfileAddress);
        }
    }

    static void callbackD3DXGetPixelShaderProfile(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "D3DX9!D3DXGetPixelShaderProfile");
        if (session) {
            cpu->reg[0].u32 = session->direct3DShaderProfile(
                "ps_3_0",
                session->direct3DPixelProfileAddress);
        }
    }

    static void callbackD3DXLoadSurfaceFromSurface(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "D3DX9!D3DXLoadSurfaceFromSurface");
        if (!session) {
            return;
        }
        U8 destinationRectangle[16] = {};
        U8 sourceRectangle[16] = {};
        const void* destinationRectangleValue = nullptr;
        const void* sourceRectangleValue = nullptr;
        if (argument(cpu, 2) &&
            session->memory->canRead(argument(cpu, 2), 16)) {
            session->memory->memcpy(
                destinationRectangle,
                argument(cpu, 2),
                sizeof(destinationRectangle));
            destinationRectangleValue = destinationRectangle;
        }
        if (argument(cpu, 5) &&
            session->memory->canRead(argument(cpu, 5), 16)) {
            session->memory->memcpy(
                sourceRectangle,
                argument(cpu, 5),
                sizeof(sourceRectangle));
            sourceRectangleValue = sourceRectangle;
        }
        cpu->reg[0].u32 =
            session->hostDirect3D.loadSurfaceFromSurface(
                argument(cpu, 0),
                destinationRectangleValue,
                argument(cpu, 3),
                sourceRectangleValue,
                argument(cpu, 6),
                argument(cpu, 7))
            ? 0
            : 0x80004005;
    }

    static void callbackD3DXReturnSuccess(CPU* cpu) {
        if (current(cpu, "D3DX9!CompatibilitySuccess")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackD3DXReturnNotImplemented(CPU* cpu) {
        if (current(cpu, "D3DX9!NotImplemented")) {
            cpu->reg[0].u32 = 0x80004001;
        }
    }

    bool copyDirect3DImageBytes(
        U32 guestAddress,
        U32 byteCount,
        std::vector<U8>& bytes) {
        constexpr U32 MAX_IMAGE_BYTES = 256 * 1024 * 1024;
        if (!guestAddress ||
            !byteCount ||
            byteCount > MAX_IMAGE_BYTES ||
            !memory->canRead(guestAddress, byteCount)) {
            return false;
        }
        bytes.resize(byteCount);
        memory->memcpy(bytes.data(), guestAddress, byteCount);
        return true;
    }

    static void callbackD3DXGetImageInfoFromFileInMemory(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "D3DX9!D3DXGetImageInfoFromFileInMemory");
        if (!session) {
            return;
        }
        constexpr U32 E_FAIL = 0x80004005;
        U32 dataAddress = argument(cpu, 0);
        U32 byteCount = argument(cpu, 1);
        U32 outputAddress = argument(cpu, 2);
        if (!outputAddress ||
            !session->memory->canWrite(outputAddress, 28)) {
            cpu->reg[0].u32 = E_FAIL;
            return;
        }
        std::vector<U8> bytes;
        SugarbombHostD3DImageInfo info;
        if (!session->copyDirect3DImageBytes(
                dataAddress,
                byteCount,
                bytes) ||
            !session->hostDirect3D.getImageInfoFromMemory(
                bytes.data(),
                byteCount,
                info)) {
            cpu->reg[0].u32 = E_FAIL;
            return;
        }
        session->memory->writed(outputAddress + 0, info.width);
        session->memory->writed(outputAddress + 4, info.height);
        session->memory->writed(outputAddress + 8, info.depth);
        session->memory->writed(outputAddress + 12, info.mipLevels);
        session->memory->writed(outputAddress + 16, info.format);
        session->memory->writed(outputAddress + 20, info.resourceType);
        session->memory->writed(outputAddress + 24, info.fileFormat);
        cpu->reg[0].u32 = 0;
    }

    U32 createDirect3DTextureFromMemory(
        U32 dataAddress,
        U32 byteCount,
        U32 outputAddress,
        bool cube) {
        constexpr U32 E_FAIL = 0x80004005;
        constexpr U32 E_POINTER = 0x80004003;
        if (!outputAddress || !memory->canWrite(outputAddress, 4)) {
            return E_POINTER;
        }
        memory->writed(outputAddress, 0);
        std::vector<U8> bytes;
        SugarbombHostD3DImageInfo info;
        if (!copyDirect3DImageBytes(dataAddress, byteCount, bytes) ||
            !hostDirect3D.getImageInfoFromMemory(
                bytes.data(),
                byteCount,
                info)) {
            return E_FAIL;
        }
        U32 resource = createDirect3DResource(
            cube
                ? Direct3DResourceKind::CubeTexture
                : Direct3DResourceKind::Texture,
            cube ? 5 : 3,
            info.width,
            info.height,
            info.mipLevels,
            info.format,
            0,
            1);
        if (!resource ||
            !hostDirect3D.createTextureFromMemory(
                resource,
                bytes.data(),
                byteCount,
                cube)) {
            if (resource) {
                hostDirect3D.releaseResource(resource);
            }
            return E_FAIL;
        }
        memory->writed(outputAddress, resource);
        return 0;
    }

    static void callbackD3DXCreateTextureFromFileInMemory(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "D3DX9!D3DXCreateTextureFromFileInMemory");
        if (session) {
            cpu->reg[0].u32 = session->createDirect3DTextureFromMemory(
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3),
                false);
        }
    }

    static void callbackD3DXCreateCubeTextureFromFileInMemory(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "D3DX9!D3DXCreateCubeTextureFromFileInMemory");
        if (session) {
            cpu->reg[0].u32 = session->createDirect3DTextureFromMemory(
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3),
                true);
        }
    }

    static void callbackGetSystemTimeAsFileTime(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetSystemTimeAsFileTime");
        if (!session) {
            return;
        }
        U32 destination = argument(cpu, 0);
        U64 fileTime = KSystem::getSystemTimeAsMicroSeconds() * 10 + WINDOWS_TO_UNIX_EPOCH_100NS;
        session->memory->writeq(destination, fileTime);
    }

    static void callbackGetCurrentProcessId(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetCurrentProcessId");
        if (session) {
            cpu->reg[0].u32 = session->process->id;
        }
    }

    static void callbackGetCurrentProcess(CPU* cpu) {
        if (current(cpu, "KERNEL32!GetCurrentProcess")) {
            cpu->reg[0].u32 = 0xffffffff;
        }
    }

    static void callbackGetCurrentThreadId(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetCurrentThreadId");
        if (session) {
            cpu->reg[0].u32 = cpu->thread->id;
        }
    }

    static void callbackGetTickCount(CPU* cpu) {
        if (current(cpu, "KERNEL32!GetTickCount")) {
            cpu->reg[0].u32 = static_cast<U32>(KSystem::getMicroCounter() / 1000);
        }
    }

    static void callbackQueryPerformanceCounter(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!QueryPerformanceCounter");
        if (session) {
            session->memory->writeq(argument(cpu, 0), KSystem::getMicroCounter());
            cpu->reg[0].u32 = 1;
        }
    }

    static void callbackQueryPerformanceFrequency(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!QueryPerformanceFrequency");
        if (session) {
            session->memory->writeq(argument(cpu, 0), 1000000);
            cpu->reg[0].u32 = 1;
        }
    }

    static void callbackGetStartupInfoA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetStartupInfoA");
        if (session) {
            U32 startupInfo = argument(cpu, 0);
            session->memory->memset(startupInfo, 0, 68);
            session->memory->writed(startupInfo, 68);
        }
    }

    static void callbackGetCommandLineA(CPU* cpu) {
        if (current(cpu, "KERNEL32!GetCommandLineA")) {
            cpu->reg[0].u32 = ANSI_COMMAND_LINE;
        }
    }

    static void callbackGetLastError(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetLastError");
        if (session) {
            cpu->reg[0].u32 = session->memory->readd(cpu->seg[FS].address + 0x34);
        }
    }

    static void callbackSetLastError(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!SetLastError");
        if (session) {
            session->memory->writed(cpu->seg[FS].address + 0x34, argument(cpu, 0));
        }
    }

    static void callbackGetModuleHandleA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetModuleHandleA");
        if (session) {
            U32 moduleName = argument(cpu, 0);
            if (!moduleName) {
                cpu->reg[0].u32 = session->image.loadBase;
            } else {
                std::string name = session->readAnsi(moduleName);
                std::string key = session->guestModuleKey(name);
                if (key == "kernel32.dll") {
                    cpu->reg[0].u32 = KERNEL32_MODULE_HANDLE;
                } else if (key == "d3d9.dll") {
                    cpu->reg[0].u32 = D3D9_MODULE_HANDLE;
                } else {
                    cpu->reg[0].u32 =
                        session->guestModuleHandle(name);
                    if (!cpu->reg[0].u32) {
                        session->setLastError(126);
                    }
                }
            }
        }
    }

    static void callbackGetModuleHandleW(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetModuleHandleW");
        if (session) {
            U32 moduleName = argument(cpu, 0);
            if (!moduleName) {
                cpu->reg[0].u32 = session->image.loadBase;
            } else {
                std::string name = session->readWide(moduleName);
                std::string key = session->guestModuleKey(name);
                if (key == "kernel32.dll") {
                    cpu->reg[0].u32 = KERNEL32_MODULE_HANDLE;
                } else if (key == "d3d9.dll") {
                    cpu->reg[0].u32 = D3D9_MODULE_HANDLE;
                } else {
                    cpu->reg[0].u32 =
                        session->guestModuleHandle(name);
                    if (!cpu->reg[0].u32) {
                        session->setLastError(126);
                    }
                }
            }
        }
    }

    static void callbackGetModuleFileNameA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetModuleFileNameA");
        if (!session) {
            return;
        }
        U32 module = argument(cpu, 0);
        U32 buffer = argument(cpu, 1);
        U32 capacity = argument(cpu, 2);
        std::string path;
        if (!module || module == session->image.loadBase) {
            path = session->imagePath;
        } else {
            auto found = session->guestModules.find(module);
            if (found != session->guestModules.end()) {
                path = found->second.path;
            }
        }
        if (path.empty() || !buffer || !capacity) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 length = static_cast<U32>(path.size());
        U32 copied = std::min(length, capacity - 1);
        session->memory->memcpy(buffer, path.data(), copied);
        session->memory->writeb(buffer + copied, 0);
        cpu->reg[0].u32 = copied;
        if (copied != length) {
            session->setLastError(122); // ERROR_INSUFFICIENT_BUFFER
        }
    }

    static void callbackGetPrivateProfileIntA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetPrivateProfileIntA");
        if (session) {
            cpu->reg[0].u32 = session->getPrivateProfileInt(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3));
        }
    }

    static void callbackGetPrivateProfileStringA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetPrivateProfileStringA");
        if (session) {
            cpu->reg[0].u32 = session->getPrivateProfileString(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3),
                argument(cpu, 4),
                argument(cpu, 5));
        }
    }

    static void callbackWritePrivateProfileStringA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!WritePrivateProfileStringA");
        if (session) {
            cpu->reg[0].u32 = session->writePrivateProfileString(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3)) ? 1 : 0;
        }
    }

    static void callbackGetCurrentDirectoryA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetCurrentDirectoryA");
        if (session) {
            cpu->reg[0].u32 = session->getCurrentDirectory(
                argument(cpu, 0),
                argument(cpu, 1));
        }
    }

    static void callbackCreateDirectoryA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!CreateDirectoryA");
        if (session) {
            cpu->reg[0].u32 =
                session->createDirectory(
                    session->readAnsi(argument(cpu, 0), 32768))
                ? 1
                : 0;
        }
    }

    static void callbackCreateDirectoryW(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!CreateDirectoryW");
        if (session) {
            cpu->reg[0].u32 =
                session->createDirectory(
                    session->readWide(argument(cpu, 0), 32768))
                ? 1
                : 0;
        }
    }

    static void callbackCreateDirectoryExA(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!CreateDirectoryExA");
        if (session) {
            cpu->reg[0].u32 =
                session->createDirectory(
                    session->readAnsi(argument(cpu, 1), 32768))
                ? 1
                : 0;
        }
    }

    static void callbackCreateDirectoryExW(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!CreateDirectoryExW");
        if (session) {
            cpu->reg[0].u32 =
                session->createDirectory(
                    session->readWide(argument(cpu, 1), 32768))
                ? 1
                : 0;
        }
    }

    static void callbackDeleteFileA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!DeleteFileA");
        if (session) {
            cpu->reg[0].u32 =
                session->deleteFile(
                    session->readAnsi(argument(cpu, 0), 32768))
                ? 1
                : 0;
        }
    }

    static void callbackDeleteFileW(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!DeleteFileW");
        if (session) {
            cpu->reg[0].u32 =
                session->deleteFile(
                    session->readWide(argument(cpu, 0), 32768))
                ? 1
                : 0;
        }
    }

    static void callbackGetFileAttributesA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetFileAttributesA");
        if (session) {
            cpu->reg[0].u32 =
                session->getFileAttributes(
                    session->readAnsi(argument(cpu, 0), 32768));
        }
    }

    static void callbackGetFileAttributesW(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!GetFileAttributesW");
        if (session) {
            cpu->reg[0].u32 =
                session->getFileAttributes(
                    session->readWide(argument(cpu, 0), 32768));
        }
    }

    static void callbackGetFileAttributesExA(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!GetFileAttributesExA");
        if (session) {
            if (argument(cpu, 1) != 0) {
                session->setLastError(87);
                cpu->reg[0].u32 = 0;
            } else {
                cpu->reg[0].u32 =
                    session->writeFileAttributesEx(
                        session->readAnsi(argument(cpu, 0), 32768),
                        argument(cpu, 2))
                    ? 1
                    : 0;
            }
        }
    }

    static void callbackGetFileAttributesExW(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!GetFileAttributesExW");
        if (session) {
            if (argument(cpu, 1) != 0) {
                session->setLastError(87);
                cpu->reg[0].u32 = 0;
            } else {
                cpu->reg[0].u32 =
                    session->writeFileAttributesEx(
                        session->readWide(argument(cpu, 0), 32768),
                        argument(cpu, 2))
                    ? 1
                    : 0;
            }
        }
    }

    static void callbackCreateFileA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!CreateFileA");
        if (session) {
            cpu->reg[0].u32 = session->createGuestFile(
                session->readAnsi(argument(cpu, 0)),
                argument(cpu, 1),
                argument(cpu, 4));
        }
    }

    static void callbackCreateFileW(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!CreateFileW");
        if (session) {
            cpu->reg[0].u32 = session->createGuestFile(
                session->readWide(argument(cpu, 0)),
                argument(cpu, 1),
                argument(cpu, 4));
        }
    }

    static void callbackGetFileSize(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetFileSize");
        if (session) {
            U64 size = 0;
            if (!session->guestFileSize(argument(cpu, 0), size)) {
                cpu->reg[0].u32 = 0xffffffff;
                return;
            }
            if (argument(cpu, 1)) {
                session->memory->writed(argument(cpu, 1), static_cast<U32>(size >> 32));
            }
            cpu->reg[0].u32 = static_cast<U32>(size);
        }
    }

    static void callbackGetFileSizeEx(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetFileSizeEx");
        if (session) {
            U64 size = 0;
            U32 destination = argument(cpu, 1);
            if (!destination || !session->guestFileSize(argument(cpu, 0), size)) {
                cpu->reg[0].u32 = 0;
                return;
            }
            session->memory->writeq(destination, size);
            cpu->reg[0].u32 = 1;
        }
    }

    static void callbackSetFilePointer(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!SetFilePointer");
        if (session) {
            S64 distance = static_cast<S32>(argument(cpu, 1));
            U32 highAddress = argument(cpu, 2);
            if (highAddress) {
                distance |= static_cast<S64>(
                    static_cast<S32>(session->memory->readd(highAddress))) << 32;
            }
            U64 position = 0;
            if (!session->setGuestFilePointer(argument(cpu, 0), distance, argument(cpu, 3), position)) {
                cpu->reg[0].u32 = 0xffffffff;
                return;
            }
            if (highAddress) {
                session->memory->writed(highAddress, static_cast<U32>(position >> 32));
            }
            cpu->reg[0].u32 = static_cast<U32>(position);
        }
    }

    static void callbackSetFilePointerEx(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!SetFilePointerEx");
        if (session) {
            U64 rawDistance =
                static_cast<U64>(argument(cpu, 1)) |
                (static_cast<U64>(argument(cpu, 2)) << 32);
            U64 position = 0;
            if (!session->setGuestFilePointer(
                    argument(cpu, 0),
                    static_cast<S64>(rawDistance),
                    argument(cpu, 4),
                    position)) {
                cpu->reg[0].u32 = 0;
                return;
            }
            if (argument(cpu, 3)) {
                session->memory->writeq(argument(cpu, 3), position);
            }
            cpu->reg[0].u32 = 1;
        }
    }

    static void callbackSetEndOfFile(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!SetEndOfFile");
        if (session) {
            cpu->reg[0].u32 = session->setGuestEndOfFile(argument(cpu, 0)) ? 1 : 0;
        }
    }

    static void callbackFindFirstFileA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!FindFirstFileA");
        if (session) {
            cpu->reg[0].u32 = session->findFirstFile(argument(cpu, 0), argument(cpu, 1));
        }
    }

    static void callbackFindNextFileA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!FindNextFileA");
        if (session) {
            cpu->reg[0].u32 = session->findNextFile(argument(cpu, 0), argument(cpu, 1)) ? 1 : 0;
        }
    }

    static void callbackFindClose(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!FindClose");
        if (session) {
            cpu->reg[0].u32 = session->closeFindHandle(argument(cpu, 0)) ? 1 : 0;
        }
    }

    static void callbackCompareFileTime(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!CompareFileTime");
        if (session) {
            U64 first = session->memory->readq(argument(cpu, 0));
            U64 second = session->memory->readq(argument(cpu, 1));
            cpu->reg[0].u32 = first < second ? 0xffffffff : (first > second ? 1 : 0);
        }
    }

    static void callbackLstrcpyA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!lstrcpyA");
        if (session) {
            U32 destination = argument(cpu, 0);
            session->memory->strcpy(destination, session->readAnsi(argument(cpu, 1)).c_str());
            cpu->reg[0].u32 = destination;
        }
    }

    static void callbackLstrcatA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!lstrcatA");
        if (session) {
            U32 destination = argument(cpu, 0);
            std::string value = session->readAnsi(destination) + session->readAnsi(argument(cpu, 1));
            session->memory->strcpy(destination, value.c_str());
            cpu->reg[0].u32 = destination;
        }
    }

    static void callbackGetCommandLineW(CPU* cpu) {
        if (current(cpu, "KERNEL32!GetCommandLineW")) {
            cpu->reg[0].u32 = WIDE_COMMAND_LINE;
        }
    }

    static void callbackGetEnvironmentStringsA(CPU* cpu) {
        if (current(cpu, "KERNEL32!GetEnvironmentStringsA")) {
            cpu->reg[0].u32 = ANSI_ENVIRONMENT;
        }
    }

    static void callbackGetEnvironmentStringsW(CPU* cpu) {
        if (current(cpu, "KERNEL32!GetEnvironmentStringsW")) {
            cpu->reg[0].u32 = WIDE_ENVIRONMENT;
        }
    }

    static void callbackFreeEnvironmentStringsA(CPU* cpu) {
        if (current(cpu, "KERNEL32!FreeEnvironmentStringsA")) {
            cpu->reg[0].u32 = 1;
        }
    }

    static void callbackFreeEnvironmentStringsW(CPU* cpu) {
        if (current(cpu, "KERNEL32!FreeEnvironmentStringsW")) {
            cpu->reg[0].u32 = 1;
        }
    }

    static void callbackGetProcAddress(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetProcAddress");
        if (!session) {
            return;
        }
        U32 module = argument(cpu, 0);
        U32 nameAddress = argument(cpu, 1);
        U32 ordinal = nameAddress <= 0xffff ? nameAddress : 0;
        std::string name = ordinal
            ? "#" + std::to_string(ordinal)
            : session->readAnsi(nameAddress);
        if (module == D3D9_MODULE_HANDLE && name == "Direct3DCreate9") {
            printf(
                "Sugarbomb Win32 loader: GetProcAddress(D3D9.DLL, Direct3DCreate9) -> 0x%08X\n",
                session->direct3DCreate9Thunk);
            cpu->reg[0].u32 = session->direct3DCreate9Thunk;
            return;
        }
        U32 guestAddress = session->guestModuleProcAddress(
            module,
            ordinal ? std::string() : name,
            ordinal);
        if (guestAddress) {
            printf(
                "Sugarbomb Win32 loader: GetProcAddress("
                "0x%08X, %s) -> guest 0x%08X\n",
                module,
                name.c_str(),
                guestAddress);
            cpu->reg[0].u32 = guestAddress;
            return;
        }
        printf("Sugarbomb Win32 probe: GetProcAddress(0x%08X, %s) -> unavailable\n", module, name.c_str());
        session->setLastError(127); // ERROR_PROC_NOT_FOUND
        cpu->reg[0].u32 = 0;
    }

    static void callbackLoadLibraryA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!LoadLibraryA");
        if (session) {
            std::string name = session->readAnsi(argument(cpu, 0));
            std::string key = session->guestModuleKey(name);
            if (key == "kernel32.dll") {
                cpu->reg[0].u32 = KERNEL32_MODULE_HANDLE;
                return;
            }
            if (key == "d3d9.dll") {
                printf(
                    "Sugarbomb Win32 loader: LoadLibraryA(%s) -> 0x%08X\n",
                    name.c_str(),
                    D3D9_MODULE_HANDLE);
                cpu->reg[0].u32 = D3D9_MODULE_HANDLE;
                return;
            }
            U32 moduleHandle = 0;
            if (session->mapGuestModule(name, moduleHandle)) {
                cpu->reg[0].u32 = moduleHandle;
            } else {
                printf(
                    "Sugarbomb Win32 loader probe: LoadLibraryA(%s) "
                    "failed: %s\n",
                    name.c_str(),
                    session->error.c_str());
                session->setLastError(126);
                cpu->reg[0].u32 = 0;
            }
        }
    }

    static void callbackLoadLibraryExA(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!LoadLibraryExA");
        if (!session) {
            return;
        }
        std::string name = session->readAnsi(argument(cpu, 0));
        std::string key = session->guestModuleKey(name);
        if (key == "kernel32.dll") {
            cpu->reg[0].u32 = KERNEL32_MODULE_HANDLE;
            return;
        }
        if (key == "d3d9.dll") {
            cpu->reg[0].u32 = D3D9_MODULE_HANDLE;
            return;
        }
        U32 moduleHandle = 0;
        if (session->mapGuestModule(name, moduleHandle)) {
            cpu->reg[0].u32 = moduleHandle;
        } else {
            printf(
                "Sugarbomb Win32 loader probe: LoadLibraryExA(%s, "
                "flags=0x%08X) failed: %s\n",
                name.c_str(),
                argument(cpu, 2),
                session->error.c_str());
            session->setLastError(126);
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackFreeLibrary(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!FreeLibrary");
        if (!session) {
            return;
        }
        U32 moduleHandle = argument(cpu, 0);
        auto found = session->guestModules.find(moduleHandle);
        if (found != session->guestModules.end()) {
            if (found->second.references) {
                --found->second.references;
            }
            cpu->reg[0].u32 = 1;
        } else if (
            moduleHandle == KERNEL32_MODULE_HANDLE ||
            moduleHandle == D3D9_MODULE_HANDLE) {
            cpu->reg[0].u32 = 1;
        } else {
            session->setLastError(6); // ERROR_INVALID_HANDLE
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackTlsAlloc(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!TlsAlloc");
        if (!session) {
            return;
        }
        if (session->nextTlsIndex >= 64) {
            session->setLastError(8);
            cpu->reg[0].u32 = 0xffffffff;
            return;
        }
        cpu->reg[0].u32 = session->nextTlsIndex++;
    }

    static void callbackTlsGetValue(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!TlsGetValue");
        if (!session) {
            return;
        }
        U32 index = argument(cpu, 0);
        if (index >= 64) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        session->setLastError(0);
        U32 tlsArray = session->memory->readd(cpu->seg[FS].address + 0x2c);
        cpu->reg[0].u32 = session->memory->readd(tlsArray + index * 4);
    }

    static void callbackTlsSetValue(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!TlsSetValue");
        if (!session) {
            return;
        }
        U32 index = argument(cpu, 0);
        if (index >= 64) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 tlsArray = session->memory->readd(cpu->seg[FS].address + 0x2c);
        session->memory->writed(tlsArray + index * 4, argument(cpu, 1));
        cpu->reg[0].u32 = 1;
    }

    static void callbackTlsFree(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!TlsFree");
        if (!session) {
            return;
        }
        U32 index = argument(cpu, 0);
        if (index >= 64) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        for (auto& state : session->guestThreads) {
            session->memory->writed(state->tlsArray + index * 4, 0);
        }
        cpu->reg[0].u32 = 1;
    }

    static void callbackInitializeCriticalSection(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!InitializeCriticalSection");
        if (session) {
            session->initializeCriticalSection(argument(cpu, 0), 0);
        }
    }

    static void callbackInitializeCriticalSectionAndSpinCount(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!InitializeCriticalSectionAndSpinCount");
        if (session) {
            session->initializeCriticalSection(argument(cpu, 0), argument(cpu, 1));
            cpu->reg[0].u32 = 1;
        }
    }

    static void callbackDeleteCriticalSection(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!DeleteCriticalSection");
        if (session) {
            U32 address = argument(cpu, 0);
            session->criticalSections.erase(address);
            session->memory->memset(address, 0, 24);
        }
    }

    static void callbackEnterCriticalSection(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!EnterCriticalSection");
        if (session) {
            U32 address = argument(cpu, 0);
            if (!session->enterCriticalSection(address)) {
                GuestThreadState* state =
                    session->findGuestThread(cpu->thread->id);
                if (!state) {
                    session->setLastError(6);
                    return;
                }
                session->parkGuestThreadOnCriticalSection(*state, address);
            }
        }
    }

    static void callbackTryEnterCriticalSection(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!TryEnterCriticalSection");
        if (session) {
            cpu->reg[0].u32 = session->enterCriticalSection(argument(cpu, 0)) ? 1 : 0;
        }
    }

    static void callbackLeaveCriticalSection(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!LeaveCriticalSection");
        if (session) {
            session->leaveCriticalSection(argument(cpu, 0));
        }
    }

    static void acquireSrwLock(
        CPU* cpu,
        const char* api,
        bool exclusive) {
        SugarbombRuntimeSession* session = current(cpu, api);
        if (!session) {
            return;
        }
        U32 address = argument(cpu, 0);
        if (session->tryAcquireSrwLock(address, exclusive)) {
            return;
        }
        GuestThreadState* state =
            session->findGuestThread(cpu->thread->id);
        if (!state) {
            session->setLastError(6);
            return;
        }
        session->parkGuestThreadOnSrwLock(
            *state,
            address,
            exclusive);
    }

    static void callbackAcquireSrwLockExclusive(CPU* cpu) {
        acquireSrwLock(
            cpu,
            "KERNEL32!AcquireSRWLockExclusive",
            true);
    }

    static void callbackAcquireSrwLockShared(CPU* cpu) {
        acquireSrwLock(
            cpu,
            "KERNEL32!AcquireSRWLockShared",
            false);
    }

    static void callbackReleaseSrwLockExclusive(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!ReleaseSRWLockExclusive");
        if (session) {
            session->releaseSrwLock(argument(cpu, 0), true);
        }
    }

    static void callbackReleaseSrwLockShared(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!ReleaseSRWLockShared");
        if (session) {
            session->releaseSrwLock(argument(cpu, 0), false);
        }
    }

    static void tryAcquireSrwLock(
        CPU* cpu,
        const char* api,
        bool exclusive) {
        SugarbombRuntimeSession* session = current(cpu, api);
        if (session) {
            cpu->reg[0].u32 =
                session->tryAcquireSrwLock(
                    argument(cpu, 0),
                    exclusive)
                ? 1
                : 0;
        }
    }

    static void callbackTryAcquireSrwLockExclusive(CPU* cpu) {
        tryAcquireSrwLock(
            cpu,
            "KERNEL32!TryAcquireSRWLockExclusive",
            true);
    }

    static void callbackTryAcquireSrwLockShared(CPU* cpu) {
        tryAcquireSrwLock(
            cpu,
            "KERNEL32!TryAcquireSRWLockShared",
            false);
    }

    static void callbackSleepConditionVariableSrw(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!SleepConditionVariableSRW");
        if (!session) {
            return;
        }
        U32 conditionVariable = argument(cpu, 0);
        U32 lock = argument(cpu, 1);
        U32 timeout = argument(cpu, 2);
        U32 flags = argument(cpu, 3);
        if (!conditionVariable ||
            !session->memory->canWrite(conditionVariable, 4) ||
            flags & ~1U) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        bool exclusive = !(flags & 1);
        if (!session->releaseSrwLock(lock, exclusive)) {
            cpu->reg[0].u32 = 0;
            return;
        }
        GuestThreadState* state =
            session->findGuestThread(cpu->thread->id);
        if (!state) {
            session->setLastError(6);
            cpu->reg[0].u32 = 0;
            return;
        }
        cpu->reg[0].u32 = 1;
        session->parkGuestThreadOnConditionVariable(
            *state,
            conditionVariable,
            lock,
            exclusive,
            timeout);
    }

    static void callbackWakeConditionVariable(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!WakeConditionVariable");
        if (session) {
            session->wakeConditionVariable(
                argument(cpu, 0),
                false);
        }
    }

    static void callbackWakeAllConditionVariable(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!WakeAllConditionVariable");
        if (session) {
            session->wakeConditionVariable(
                argument(cpu, 0),
                true);
        }
    }

    static void callbackInterlockedExchange(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!InterlockedExchange");
        if (session) {
            U32 destination = argument(cpu, 0);
            U32 previous = session->memory->readd(destination);
            session->memory->writed(destination, argument(cpu, 1));
            cpu->reg[0].u32 = previous;
        }
    }

    static void callbackInterlockedCompareExchange(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!InterlockedCompareExchange");
        if (session) {
            U32 destination = argument(cpu, 0);
            U32 previous = session->memory->readd(destination);
            if (previous == argument(cpu, 2)) {
                session->memory->writed(destination, argument(cpu, 1));
            }
            cpu->reg[0].u32 = previous;
        }
    }

    static void callbackInterlockedIncrement(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!InterlockedIncrement");
        if (session) {
            U32 destination = argument(cpu, 0);
            U32 value = session->memory->readd(destination) + 1;
            session->memory->writed(destination, value);
            cpu->reg[0].u32 = value;
        }
    }

    static void callbackInterlockedDecrement(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!InterlockedDecrement");
        if (session) {
            U32 destination = argument(cpu, 0);
            U32 value = session->memory->readd(destination) - 1;
            session->memory->writed(destination, value);
            cpu->reg[0].u32 = value;
        }
    }

    static void callbackInterlockedExchangeAdd(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!InterlockedExchangeAdd");
        if (session) {
            U32 destination = argument(cpu, 0);
            U32 previous = session->memory->readd(destination);
            session->memory->writed(destination, previous + argument(cpu, 1));
            cpu->reg[0].u32 = previous;
        }
    }

    static void callbackGetStdHandle(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetStdHandle");
        if (!session) {
            return;
        }
        switch (argument(cpu, 0)) {
        case 0xfffffff6:
            cpu->reg[0].u32 = session->standardHandles[0];
            break;
        case 0xfffffff5:
            cpu->reg[0].u32 = session->standardHandles[1];
            break;
        case 0xfffffff4:
            cpu->reg[0].u32 = session->standardHandles[2];
            break;
        default:
            session->setLastError(87);
            cpu->reg[0].u32 = 0xffffffff;
            break;
        }
    }

    static void callbackSetStdHandle(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!SetStdHandle");
        if (!session) {
            return;
        }
        U32 slot = argument(cpu, 0);
        U32 handle = argument(cpu, 1);
        if (slot == 0xfffffff6) {
            session->standardHandles[0] = handle;
        } else if (slot == 0xfffffff5) {
            session->standardHandles[1] = handle;
        } else if (slot == 0xfffffff4) {
            session->standardHandles[2] = handle;
        } else {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        cpu->reg[0].u32 = 1;
    }

    static void callbackSetHandleCount(CPU* cpu) {
        if (current(cpu, "KERNEL32!SetHandleCount")) {
            cpu->reg[0].u32 = argument(cpu, 0);
        }
    }

    static void callbackGetFileType(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetFileType");
        if (session) {
            U32 handle = argument(cpu, 0);
            cpu->reg[0].u32 = session->isStandardHandle(handle)
                ? 2
                : (session->guestFiles.find(handle) != session->guestFiles.end() ? 1 : 0);
        }
    }

    static void callbackGetConsoleMode(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetConsoleMode");
        if (!session) {
            return;
        }
        U32 handle = argument(cpu, 0);
        U32 mode = argument(cpu, 1);
        if (!session->isStandardHandle(handle) || !mode) {
            session->setLastError(6);
            cpu->reg[0].u32 = 0;
            return;
        }
        session->memory->writed(mode, handle == session->standardHandles[0] ? 0x0007 : 0x0003);
        cpu->reg[0].u32 = 1;
    }

    static void callbackGetConsoleCP(CPU* cpu) {
        if (current(cpu, "KERNEL32!GetConsoleCP")) {
            cpu->reg[0].u32 = 437;
        }
    }

    static void callbackGetConsoleOutputCP(CPU* cpu) {
        if (current(cpu, "KERNEL32!GetConsoleOutputCP")) {
            cpu->reg[0].u32 = 437;
        }
    }

    static void callbackAreFileApisAnsi(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!AreFileApisANSI");
        if (session) {
            cpu->reg[0].u32 =
                session->fileApisAnsi ? 1 : 0;
        }
    }

    static void callbackSetFileApisToAnsi(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!SetFileApisToANSI");
        if (session) {
            session->fileApisAnsi = true;
        }
    }

    static void callbackSetFileApisToOem(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!SetFileApisToOEM");
        if (session) {
            session->fileApisAnsi = false;
        }
    }

    static void callbackGetACP(CPU* cpu) {
        if (current(cpu, "KERNEL32!GetACP")) {
            cpu->reg[0].u32 = 1252;
        }
    }

    static void callbackGetOEMCP(CPU* cpu) {
        if (current(cpu, "KERNEL32!GetOEMCP")) {
            cpu->reg[0].u32 = 437;
        }
    }

    static void callbackGetCPInfo(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetCPInfo");
        if (!session) {
            return;
        }
        U32 info = argument(cpu, 1);
        if (!info) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        session->memory->memset(info, 0, 20);
        session->memory->writed(info, 1);
        session->memory->writeb(info + 4, '?');
        cpu->reg[0].u32 = 1;
    }

    static void callbackIsValidCodePage(CPU* cpu) {
        if (current(cpu, "KERNEL32!IsValidCodePage")) {
            U32 codePage = argument(cpu, 0);
            cpu->reg[0].u32 = codePage == 0 || codePage == 1 ||
                codePage == 437 || codePage == 1252 || codePage == 65001;
        }
    }

    static void callbackWideCharToMultiByte(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!WideCharToMultiByte");
        if (!session) {
            return;
        }
        U32 source = argument(cpu, 2);
        S32 requestedCharacters = static_cast<S32>(argument(cpu, 3));
        U32 destination = argument(cpu, 4);
        U32 capacity = argument(cpu, 5);
        U32 usedDefaultCharacter = argument(cpu, 7);
        if (!source || !requestedCharacters) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 characters = requestedCharacters < 0
            ? static_cast<U32>(session->readWide(source).size()) + 1
            : static_cast<U32>(requestedCharacters);
        if (!destination || !capacity) {
            cpu->reg[0].u32 = characters;
            return;
        }
        if (capacity < characters) {
            session->setLastError(122);
            cpu->reg[0].u32 = 0;
            return;
        }
        bool usedDefault = false;
        for (U32 index = 0; index < characters; ++index) {
            U16 value = session->memory->readw(source + index * 2);
            if (value > 0xff) {
                value = '?';
                usedDefault = true;
            }
            session->memory->writeb(destination + index, static_cast<U8>(value));
        }
        if (usedDefaultCharacter) {
            session->memory->writed(usedDefaultCharacter, usedDefault ? 1 : 0);
        }
        cpu->reg[0].u32 = characters;
    }

    static void callbackMultiByteToWideChar(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!MultiByteToWideChar");
        if (!session) {
            return;
        }
        U32 source = argument(cpu, 2);
        S32 requestedBytes = static_cast<S32>(argument(cpu, 3));
        U32 destination = argument(cpu, 4);
        U32 capacity = argument(cpu, 5);
        if (!source || !requestedBytes) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 characters = requestedBytes < 0
            ? static_cast<U32>(session->readAnsi(source).size()) + 1
            : static_cast<U32>(requestedBytes);
        if (!destination || !capacity) {
            cpu->reg[0].u32 = characters;
            return;
        }
        if (capacity < characters) {
            session->setLastError(122);
            cpu->reg[0].u32 = 0;
            return;
        }
        for (U32 index = 0; index < characters; ++index) {
            session->memory->writew(destination + index * 2, session->memory->readb(source + index));
        }
        cpu->reg[0].u32 = characters;
    }

    static void callbackGetStringTypeW(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetStringTypeW");
        if (!session) {
            return;
        }
        U32 source = argument(cpu, 1);
        S32 requestedCharacters = static_cast<S32>(argument(cpu, 2));
        U32 destination = argument(cpu, 3);
        if (!source || !destination || !requestedCharacters) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 characters = requestedCharacters < 0
            ? static_cast<U32>(session->readWide(source).size()) + 1
            : static_cast<U32>(requestedCharacters);
        for (U32 index = 0; index < characters; ++index) {
            session->memory->writew(
                destination + index * 2,
                asciiCharacterType(session->memory->readw(source + index * 2)));
        }
        cpu->reg[0].u32 = 1;
    }

    static void callbackGetStringTypeA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetStringTypeA");
        if (!session) {
            return;
        }
        U32 source = argument(cpu, 2);
        S32 requestedBytes = static_cast<S32>(argument(cpu, 3));
        U32 destination = argument(cpu, 4);
        if (!source || !destination || !requestedBytes) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 characters = requestedBytes < 0
            ? static_cast<U32>(session->readAnsi(source).size()) + 1
            : static_cast<U32>(requestedBytes);
        for (U32 index = 0; index < characters; ++index) {
            session->memory->writew(
                destination + index * 2,
                asciiCharacterType(session->memory->readb(source + index)));
        }
        cpu->reg[0].u32 = 1;
    }

    static void callbackLCMapStringW(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!LCMapStringW");
        if (session) {
            cpu->reg[0].u32 = session->mapWideString(
                argument(cpu, 1),
                argument(cpu, 2),
                static_cast<S32>(argument(cpu, 3)),
                argument(cpu, 4),
                argument(cpu, 5));
        }
    }

    static void callbackLCMapStringA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!LCMapStringA");
        if (session) {
            cpu->reg[0].u32 = session->mapAnsiString(
                argument(cpu, 1),
                argument(cpu, 2),
                static_cast<S32>(argument(cpu, 3)),
                argument(cpu, 4),
                argument(cpu, 5));
        }
    }

    static void callbackSetUnhandledExceptionFilter(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!SetUnhandledExceptionFilter");
        if (session) {
            U32 previous = session->unhandledExceptionFilter;
            session->unhandledExceptionFilter = argument(cpu, 0);
            cpu->reg[0].u32 = previous;
        }
    }

    static void callbackUnhandledExceptionFilter(CPU* cpu) {
        if (current(cpu, "KERNEL32!UnhandledExceptionFilter")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackRaiseException(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!RaiseException");
        if (!session) {
            return;
        }
        U32 exceptionCode = argument(cpu, 0);
        U32 exceptionFlags = argument(cpu, 1);
        U32 argumentCount = argument(cpu, 2);
        U32 arguments = argument(cpu, 3);

        // MSVC's conventional debugger thread-name notification. It is benign
        // when no debugger consumes it, and Fallout uses it during worker setup.
        if (exceptionCode == 0x406d1388 && argumentCount >= 4 && arguments) {
            U32 type = session->memory->readd(arguments);
            U32 nameAddress = session->memory->readd(arguments + 4);
            U32 namedThreadId = session->memory->readd(arguments + 8);
            if (type == 0x1000 && nameAddress) {
                if (namedThreadId == 0xffffffff) {
                    namedThreadId = cpu->thread->id;
                }
                std::string name = session->readAnsi(nameAddress, 256);
                GuestThreadState* state = session->findGuestThread(namedThreadId);
                if (state) {
                    state->name = name;
                }
                printf(
                    "Sugarbomb Win32 thread: tid %u named \"%s\"\n",
                    namedThreadId,
                    name.c_str());
                return;
            }
        }

        fprintf(
            stderr,
            "Sugarbomb: stopped at unsupported guest RaiseException(code=0x%08X, flags=0x%08X, arguments=%u, tid=%u)\n",
            exceptionCode,
            exceptionFlags,
            argumentCount,
            cpu->thread->id);
        session->runtimeStopping = true;
        cpu->reg[0].u32 = exceptionCode;
        cpu->thread->terminating = true;
    }

    static void callbackIsDebuggerPresent(CPU* cpu) {
        if (current(cpu, "KERNEL32!IsDebuggerPresent")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackOutputDebugStringA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!OutputDebugStringA");
        if (session) {
            printf("FalloutNV debug: %s\n", session->readAnsi(argument(cpu, 0), 4096).c_str());
        }
    }

    static void callbackGlobalMemoryStatusEx(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GlobalMemoryStatusEx");
        if (!session) {
            return;
        }
        U32 status = argument(cpu, 0);
        if (!status || session->memory->readd(status) < 64) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        session->memory->writed(status + 4, 25);
        session->memory->writeq(status + 8, 8ULL * 1024 * 1024 * 1024);
        session->memory->writeq(status + 16, 6ULL * 1024 * 1024 * 1024);
        session->memory->writeq(status + 24, 16ULL * 1024 * 1024 * 1024);
        session->memory->writeq(status + 32, 14ULL * 1024 * 1024 * 1024);
        session->memory->writeq(status + 40, 0x7ffe0000ULL);
        session->memory->writeq(status + 48, 0x60000000ULL);
        session->memory->writeq(status + 56, 0);
        cpu->reg[0].u32 = 1;
    }

    static void callbackGlobalMemoryStatus(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GlobalMemoryStatus");
        if (!session) {
            return;
        }
        U32 status = argument(cpu, 0);
        if (!status) {
            return;
        }
        session->memory->writed(status + 0, 32);
        session->memory->writed(status + 4, 25);
        session->memory->writed(status + 8, 0xffffffff);
        session->memory->writed(status + 12, 0xffffffff);
        session->memory->writed(status + 16, 0xffffffff);
        session->memory->writed(status + 20, 0xffffffff);
        session->memory->writed(status + 24, 0x7ffe0000);
        session->memory->writed(status + 28, 0x60000000);
    }

    static void callbackGetSystemInfo(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetSystemInfo");
        if (!session) {
            return;
        }
        U32 info = argument(cpu, 0);
        session->memory->memset(info, 0, 36);
        session->memory->writew(info + 0, 0); // PROCESSOR_ARCHITECTURE_INTEL
        session->memory->writed(info + 4, K_PAGE_SIZE);
        session->memory->writed(info + 8, 0x00010000);
        session->memory->writed(info + 12, 0x7ffeffff);
        session->memory->writed(info + 16, 0x0000000f);
        session->memory->writed(info + 20, 4);
        session->memory->writed(info + 24, 586);
        session->memory->writed(info + 28, 0x00010000);
        session->memory->writew(info + 32, 6);
        session->memory->writew(info + 34, 0x3a09);
    }

    static void callbackIsProcessorFeaturePresent(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!IsProcessorFeaturePresent");
        if (!session) {
            return;
        }
        U32 feature = argument(cpu, 0);
        bool available = false;
        switch (feature) {
        case 2:  // PF_COMPARE_EXCHANGE_DOUBLE
        case 3:  // PF_MMX_INSTRUCTIONS_AVAILABLE
        case 6:  // PF_XMMI_INSTRUCTIONS_AVAILABLE
        case 8:  // PF_RDTSC_INSTRUCTION_AVAILABLE
        case 10: // PF_XMMI64_INSTRUCTIONS_AVAILABLE
            available = true;
            break;
        default:
            break;
        }
        cpu->reg[0].u32 = available ? 1 : 0;
        if (++session->processorFeatureTraceCount <= 16) {
            printf(
                "Sugarbomb Win32 CPU: "
                "IsProcessorFeaturePresent(%u) -> %u\n",
                feature,
                available ? 1 : 0);
        }
    }

    static bool validSListHeader(
        SugarbombRuntimeSession* session,
        U32 header) {
        return header &&
            !(header & 7) &&
            session->memory->canRead(header, 8) &&
            session->memory->canWrite(header, 8);
    }

    static void callbackInitializeSListHead(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!InitializeSListHead");
        if (!session) {
            return;
        }
        U32 header = argument(cpu, 0);
        if (!validSListHeader(session, header)) {
            session->setLastError(87);
            return;
        }
        session->memory->writeq(header, 0);
        printf(
            "Sugarbomb Win32 SList: initialized header 0x%08X\n",
            header);
    }

    static void callbackInterlockedPushEntrySList(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!InterlockedPushEntrySList");
        if (!session) {
            return;
        }
        U32 header = argument(cpu, 0);
        U32 entry = argument(cpu, 1);
        if (!validSListHeader(session, header) ||
            !entry ||
            !session->memory->canWrite(entry, 4)) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 previous = session->memory->readd(header);
        U16 depth = session->memory->readw(header + 4);
        U16 sequence = session->memory->readw(header + 6);
        session->memory->writed(entry, previous);
        session->memory->writed(header, entry);
        session->memory->writew(
            header + 4,
            static_cast<U16>(depth + 1));
        session->memory->writew(
            header + 6,
            static_cast<U16>(sequence + 1));
        cpu->reg[0].u32 = previous;
    }

    static void callbackInterlockedPopEntrySList(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!InterlockedPopEntrySList");
        if (!session) {
            return;
        }
        U32 header = argument(cpu, 0);
        if (!validSListHeader(session, header)) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 first = session->memory->readd(header);
        if (!first) {
            cpu->reg[0].u32 = 0;
            return;
        }
        if (!session->memory->canRead(first, 4)) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 next = session->memory->readd(first);
        U16 depth = session->memory->readw(header + 4);
        U16 sequence = session->memory->readw(header + 6);
        session->memory->writed(header, next);
        session->memory->writew(
            header + 4,
            depth ? static_cast<U16>(depth - 1) : 0);
        session->memory->writew(
            header + 6,
            static_cast<U16>(sequence + 1));
        cpu->reg[0].u32 = first;
    }

    static void callbackInterlockedFlushSList(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!InterlockedFlushSList");
        if (!session) {
            return;
        }
        U32 header = argument(cpu, 0);
        if (!validSListHeader(session, header)) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 first = session->memory->readd(header);
        U16 sequence = session->memory->readw(header + 6);
        session->memory->writed(header, 0);
        session->memory->writew(header + 4, 0);
        session->memory->writew(
            header + 6,
            static_cast<U16>(sequence + 1));
        cpu->reg[0].u32 = first;
    }

    static void callbackQueryDepthSList(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!QueryDepthSList");
        if (!session) {
            return;
        }
        U32 header = argument(cpu, 0);
        if (!validSListHeader(session, header)) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        cpu->reg[0].u32 =
            session->memory->readw(header + 4);
    }

    static void callbackInitializeOnExitTable(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_initialize_onexit_table");
        if (!session) {
            return;
        }
        U32 table = argument(cpu, 0);
        if (!table || !session->memory->canWrite(table, 12)) {
            cpu->reg[0].u32 = 22; // EINVAL
            return;
        }
        auto previous = session->onExitTables.find(table);
        if (previous != session->onExitTables.end()) {
            if (previous->second.owned) {
                session->freeGuestHeap(
                    previous->second.allocation);
            }
            session->onExitTables.erase(previous);
        }
        session->memory->memset(table, 0, 12);
        cpu->reg[0].u32 = 0;
        printf(
            "Sugarbomb UCRT: initialized on-exit table at 0x%08X\n",
            table);
    }

    static void callbackUcrtLocaleCodepage(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!___lc_codepage_func");
        if (!session) {
            return;
        }
        if (!session->ucrtLocaleCodepageAddress) {
            session->ucrtLocaleCodepageAddress =
                session->allocateGuestHeap(4, true);
            if (session->ucrtLocaleCodepageAddress) {
                session->memory->writed(
                    session->ucrtLocaleCodepageAddress,
                    1252);
            }
        }
        cpu->reg[0].u32 =
            session->ucrtLocaleCodepageAddress;
    }

    static void callbackRegisterOnExitFunction(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_register_onexit_function");
        if (!session) {
            return;
        }
        U32 table = argument(cpu, 0);
        U32 function = argument(cpu, 1);
        if (!table ||
            !function ||
            !session->memory->canWrite(table, 12) ||
            !session->memory->canRead(function, 1)) {
            cpu->reg[0].u32 = 22; // EINVAL
            return;
        }

        U32 first = session->memory->readd(table);
        U32 last = session->memory->readd(table + 4);
        U32 end = session->memory->readd(table + 8);
        GuestOnExitTable& tracked =
            session->onExitTables[table];
        if (!first && !last && !end) {
            tracked.capacity = 32;
            tracked.allocation = session->allocateGuestHeap(
                tracked.capacity * sizeof(U32),
                true);
            if (!tracked.allocation) {
                session->onExitTables.erase(table);
                cpu->reg[0].u32 = 12; // ENOMEM
                return;
            }
            tracked.owned = true;
            first = tracked.allocation;
            last = first;
            end = first + tracked.capacity * sizeof(U32);
        } else if (
            !first ||
            first > last ||
            last > end ||
            ((last - first) & 3) ||
            ((end - first) & 3) ||
            !session->memory->canRead(
                first,
                end - first)) {
            session->onExitTables.erase(table);
            cpu->reg[0].u32 = 22; // EINVAL
            return;
        } else if (!tracked.allocation) {
            tracked.allocation = first;
            tracked.capacity = (end - first) / sizeof(U32);
            tracked.owned = false;
        }

        if (last == end) {
            U32 used = (last - first) / sizeof(U32);
            U32 capacity = std::max<U32>(
                32,
                tracked.capacity);
            if (capacity > 0x10000) {
                cpu->reg[0].u32 = 12; // ENOMEM
                return;
            }
            U32 replacementCapacity = capacity * 2;
            U32 replacement = session->allocateGuestHeap(
                replacementCapacity * sizeof(U32),
                true);
            if (!replacement) {
                cpu->reg[0].u32 = 12; // ENOMEM
                return;
            }
            if (used) {
                session->memory->memcpy(
                    replacement,
                    first,
                    used * sizeof(U32));
            }
            if (tracked.owned &&
                tracked.allocation == first) {
                session->freeGuestHeap(first);
            }
            tracked.allocation = replacement;
            tracked.capacity = replacementCapacity;
            tracked.owned = true;
            first = replacement;
            last = replacement + used * sizeof(U32);
            end = replacement +
                replacementCapacity * sizeof(U32);
        }
        session->memory->writed(last, function);
        last += sizeof(U32);
        session->memory->writed(table, first);
        session->memory->writed(table + 4, last);
        session->memory->writed(table + 8, end);
        cpu->reg[0].u32 = 0;
        printf(
            "Sugarbomb UCRT: registered on-exit function "
            "0x%08X in table 0x%08X (%u entries)\n",
            function,
            table,
            static_cast<U32>(
                (last - first) / sizeof(U32)));
    }

    static void callbackConfigureNarrowArgv(CPU* cpu) {
        if (current(cpu, "UCRT!_configure_narrow_argv")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackInitializeNarrowEnvironment(CPU* cpu) {
        if (current(
                cpu,
                "UCRT!_initialize_narrow_environment")) {
            cpu->reg[0].u32 = 0;
        }
    }

    static void callbackInitTerm(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_initterm");
        if (session &&
            !session->beginGuestFunctionArray(
                cpu,
                argument(cpu, 0),
                argument(cpu, 1),
                false,
                "UCRT _initterm")) {
            fprintf(
                stderr,
                "Sugarbomb UCRT: _initterm failed: %s\n",
                session->error.c_str());
            session->runtimeStopping = true;
            cpu->thread->terminating = true;
        }
    }

    static void callbackInitTermE(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_initterm_e");
        if (session &&
            !session->beginGuestFunctionArray(
                cpu,
                argument(cpu, 0),
                argument(cpu, 1),
                true,
                "UCRT _initterm_e")) {
            fprintf(
                stderr,
                "Sugarbomb UCRT: _initterm_e failed: %s\n",
                session->error.c_str());
            session->runtimeStopping = true;
            cpu->thread->terminating = true;
        }
    }

    static void callbackUcrtMalloc(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!malloc");
        if (session) {
            cpu->reg[0].u32 =
                session->allocateGuestHeap(
                    argument(cpu, 0),
                    false);
        }
    }

    static void callbackUcrtFree(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!free");
        if (session) {
            session->freeGuestHeap(argument(cpu, 0));
        }
    }

    static void callbackUcrtRealloc(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!realloc");
        if (!session) {
            return;
        }
        U32 previous = argument(cpu, 0);
        U32 size = argument(cpu, 1);
        if (previous && !size) {
            session->freeGuestHeap(previous);
            cpu->reg[0].u32 = 0;
            return;
        }
        cpu->reg[0].u32 =
            session->reallocateGuestHeap(
                previous,
                size,
                false);
    }

    static void callbackUcrtMallocDebug(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_malloc_dbg");
        if (session) {
            cpu->reg[0].u32 =
                session->allocateGuestHeap(
                    argument(cpu, 0),
                    false);
        }
    }

    static void callbackUcrtCallocDebug(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_calloc_dbg");
        if (!session) {
            return;
        }
        U64 bytes =
            static_cast<U64>(argument(cpu, 0)) *
            argument(cpu, 1);
        if (bytes > std::numeric_limits<U32>::max()) {
            session->setLastError(8);
            cpu->reg[0].u32 = 0;
            return;
        }
        cpu->reg[0].u32 =
            session->allocateGuestHeap(
                static_cast<U32>(bytes),
                true);
    }

    static void callbackUcrtFreeDebug(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_free_dbg");
        if (session) {
            session->freeGuestHeap(argument(cpu, 0));
        }
    }

    static bool validateCrtMemory(
        SugarbombRuntimeSession* session,
        CPU* cpu,
        const char* operation,
        U32 destination,
        U32 source,
        U32 size,
        bool readSource) {
        if (!size) {
            return true;
        }
        if (!destination ||
            !session->memory->canWrite(destination, size) ||
            (readSource &&
             (!source ||
              !session->memory->canRead(source, size)))) {
            fprintf(
                stderr,
                "Sugarbomb CRT: %s received an invalid guest range "
                "(destination=0x%08X, source=0x%08X, size=%u)\n",
                operation,
                destination,
                source,
                size);
            session->runtimeStopping = true;
            cpu->thread->terminating = true;
            return false;
        }
        return true;
    }

    static void callbackCrtMemset(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "CRT!memset");
        if (!session) {
            return;
        }
        U32 destination = argument(cpu, 0);
        U32 size = argument(cpu, 2);
        if (!validateCrtMemory(
                session,
                cpu,
                "memset",
                destination,
                0,
                size,
                false)) {
            return;
        }
        if (size) {
            session->memory->memset(
                destination,
                static_cast<U8>(argument(cpu, 1)),
                size);
        }
        cpu->reg[0].u32 = destination;
    }

    static void callbackCrtMemcpy(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "CRT!memcpy");
        if (!session) {
            return;
        }
        U32 destination = argument(cpu, 0);
        U32 source = argument(cpu, 1);
        U32 size = argument(cpu, 2);
        if (!validateCrtMemory(
                session,
                cpu,
                "memcpy",
                destination,
                source,
                size,
                true)) {
            return;
        }
        if (size) {
            session->memory->memcpy(
                destination,
                source,
                size);
        }
        cpu->reg[0].u32 = destination;
    }

    static void callbackCrtMemmove(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "CRT!memmove");
        if (!session) {
            return;
        }
        U32 destination = argument(cpu, 0);
        U32 source = argument(cpu, 1);
        U32 size = argument(cpu, 2);
        if (!validateCrtMemory(
                session,
                cpu,
                "memmove",
                destination,
                source,
                size,
                true)) {
            return;
        }
        if (size) {
            // KMemory's guest-to-guest copy selects a direction and is
            // overlap-safe.
            session->memory->memcpy(
                destination,
                source,
                size);
        }
        cpu->reg[0].u32 = destination;
    }

    static void callbackCrtMemcmp(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "CRT!memcmp");
        if (!session) {
            return;
        }
        U32 left = argument(cpu, 0);
        U32 right = argument(cpu, 1);
        U32 size = argument(cpu, 2);
        if (size &&
            (!left ||
             !right ||
             !session->memory->canRead(left, size) ||
             !session->memory->canRead(right, size))) {
            fprintf(
                stderr,
                "Sugarbomb CRT: memcmp received an invalid guest "
                "range (left=0x%08X, right=0x%08X, size=%u)\n",
                left,
                right,
                size);
            session->runtimeStopping = true;
            cpu->thread->terminating = true;
            return;
        }
        S32 result = 0;
        for (U32 index = 0; index < size; ++index) {
            U8 leftByte =
                session->memory->readb(left + index);
            U8 rightByte =
                session->memory->readb(right + index);
            if (leftByte != rightByte) {
                result = static_cast<S32>(leftByte) -
                    static_cast<S32>(rightByte);
                break;
            }
        }
        cpu->reg[0].u32 = static_cast<U32>(result);
    }

    static void callbackCrtMemchr(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "CRT!memchr");
        if (!session) {
            return;
        }
        U32 source = argument(cpu, 0);
        U8 value = static_cast<U8>(argument(cpu, 1));
        U32 size = argument(cpu, 2);
        if (size &&
            (!source ||
             !session->memory->canRead(source, size))) {
            session->runtimeStopping = true;
            cpu->thread->terminating = true;
            return;
        }
        cpu->reg[0].u32 = 0;
        for (U32 index = 0; index < size; ++index) {
            if (session->memory->readb(source + index) == value) {
                cpu->reg[0].u32 = source + index;
                break;
            }
        }
    }

    static void callbackCrtStrchr(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "CRT!strchr");
        if (!session) {
            return;
        }
        U32 source = argument(cpu, 0);
        U8 value = static_cast<U8>(argument(cpu, 1));
        U32 length = 0;
        if (!session->guestCStringLength(source, length)) {
            session->runtimeStopping = true;
            cpu->thread->terminating = true;
            return;
        }
        cpu->reg[0].u32 = 0;
        for (U32 index = 0; index <= length; ++index) {
            if (session->memory->readb(source + index) == value) {
                cpu->reg[0].u32 = source + index;
                break;
            }
        }
    }

    static void callbackCrtStrrchr(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "CRT!strrchr");
        if (!session) {
            return;
        }
        U32 source = argument(cpu, 0);
        U8 value = static_cast<U8>(argument(cpu, 1));
        U32 length = 0;
        if (!session->guestCStringLength(source, length)) {
            session->runtimeStopping = true;
            cpu->thread->terminating = true;
            return;
        }
        cpu->reg[0].u32 = 0;
        for (U32 index = length + 1; index; --index) {
            U32 offset = index - 1;
            if (session->memory->readb(source + offset) == value) {
                cpu->reg[0].u32 = source + offset;
                break;
            }
        }
    }

    static void callbackCrtStrstr(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "CRT!strstr");
        if (!session) {
            return;
        }
        U32 haystack = argument(cpu, 0);
        U32 needle = argument(cpu, 1);
        U32 haystackLength = 0;
        U32 needleLength = 0;
        if (!session->guestCStringLength(
                haystack,
                haystackLength) ||
            !session->guestCStringLength(
                needle,
                needleLength)) {
            session->runtimeStopping = true;
            cpu->thread->terminating = true;
            return;
        }
        if (!needleLength) {
            cpu->reg[0].u32 = haystack;
            return;
        }
        cpu->reg[0].u32 = 0;
        if (needleLength > haystackLength) {
            return;
        }
        for (U32 index = 0;
             index <= haystackLength - needleLength;
             ++index) {
            bool equal = true;
            for (U32 character = 0;
                 character < needleLength;
                 ++character) {
                if (session->memory->readb(
                        haystack + index + character) !=
                    session->memory->readb(
                        needle + character)) {
                    equal = false;
                    break;
                }
            }
            if (equal) {
                cpu->reg[0].u32 = haystack + index;
                break;
            }
        }
    }

    static bool readGuestCrtString(
        SugarbombRuntimeSession* session,
        CPU* cpu,
        U32 address,
        std::string& value,
        U32& length) {
        if (!session->guestCStringLength(address, length)) {
            fprintf(
                stderr,
                "Sugarbomb UCRT: invalid string pointer "
                "0x%08X\n",
                address);
            session->runtimeStopping = true;
            cpu->thread->terminating = true;
            return false;
        }
        value = session->readAnsi(address, length + 1);
        return true;
    }

    static U8 asciiLower(U8 value) {
        return value >= 'A' && value <= 'Z'
            ? static_cast<U8>(value + ('a' - 'A'))
            : value;
    }

    static bool compareGuestCrtStrings(
        SugarbombRuntimeSession* session,
        CPU* cpu,
        U32 left,
        U32 right,
        U32 limit,
        bool limited,
        bool ignoreCase,
        S32& result) {
        result = 0;
        if (limited && !limit) {
            return true;
        }
        U32 index = 0;
        for (;;) {
            if (index >
                    std::numeric_limits<U32>::max() - left ||
                index >
                    std::numeric_limits<U32>::max() - right ||
                !session->memory->canRead(left + index, 1) ||
                !session->memory->canRead(right + index, 1)) {
                session->runtimeStopping = true;
                cpu->thread->terminating = true;
                return false;
            }
            U8 leftValue =
                session->memory->readb(left + index);
            U8 rightValue =
                session->memory->readb(right + index);
            U8 comparedLeft =
                ignoreCase ? asciiLower(leftValue) : leftValue;
            U8 comparedRight =
                ignoreCase ? asciiLower(rightValue) : rightValue;
            if (comparedLeft != comparedRight) {
                result =
                    static_cast<S32>(comparedLeft) -
                    static_cast<S32>(comparedRight);
                return true;
            }
            if (!leftValue) {
                return true;
            }
            ++index;
            if ((limited && index >= limit) ||
                index >= 16 * 1024 * 1024) {
                return true;
            }
        }
    }

    static void callbackUcrtStrdup(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_strdup");
        if (!session) {
            return;
        }
        U32 source = argument(cpu, 0);
        U32 length = 0;
        if (!session->guestCStringLength(source, length) ||
            length == std::numeric_limits<U32>::max()) {
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 destination =
            session->allocateGuestHeap(length + 1, false);
        if (destination) {
            session->memory->memcpy(
                destination,
                source,
                length + 1);
        }
        cpu->reg[0].u32 = destination;
    }

    static void callbackUcrtStrlen(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!strlen");
        if (!session) {
            return;
        }
        U32 length = 0;
        if (!session->guestCStringLength(
                argument(cpu, 0),
                length)) {
            session->runtimeStopping = true;
            cpu->thread->terminating = true;
            return;
        }
        cpu->reg[0].u32 = length;
    }

    static void callbackUcrtStringCompare(
        CPU* cpu,
        const char* api,
        bool limited,
        bool ignoreCase) {
        SugarbombRuntimeSession* session = current(cpu, api);
        if (!session) {
            return;
        }
        S32 result = 0;
        if (compareGuestCrtStrings(
                session,
                cpu,
                argument(cpu, 0),
                argument(cpu, 1),
                limited ? argument(cpu, 2) : 0,
                limited,
                ignoreCase,
                result)) {
            cpu->reg[0].u32 =
                static_cast<U32>(result);
        }
    }

    static void callbackUcrtStrcmp(CPU* cpu) {
        callbackUcrtStringCompare(
            cpu,
            "UCRT!strcmp",
            false,
            false);
    }

    static void callbackUcrtStrncmp(CPU* cpu) {
        callbackUcrtStringCompare(
            cpu,
            "UCRT!strncmp",
            true,
            false);
    }

    static void callbackUcrtStricmp(CPU* cpu) {
        callbackUcrtStringCompare(
            cpu,
            "UCRT!_stricmp",
            false,
            true);
    }

    static void callbackUcrtStrnicmp(CPU* cpu) {
        callbackUcrtStringCompare(
            cpu,
            "UCRT!_strnicmp",
            true,
            true);
    }

    static void callbackUcrtStrcpy(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!strcpy");
        if (!session) {
            return;
        }
        U32 destination = argument(cpu, 0);
        U32 source = argument(cpu, 1);
        U32 length = 0;
        if (!session->guestCStringLength(source, length) ||
            length == std::numeric_limits<U32>::max() ||
            !destination ||
            !session->memory->canWrite(
                destination,
                length + 1)) {
            session->runtimeStopping = true;
            cpu->thread->terminating = true;
            return;
        }
        session->memory->memcpy(
            destination,
            source,
            length + 1);
        cpu->reg[0].u32 = destination;
    }

    static U32 copyGuestCrtStringSecure(
        SugarbombRuntimeSession* session,
        U32 destination,
        U32 capacity,
        U32 source,
        bool append) {
        if (!destination ||
            !capacity ||
            !session->memory->canWrite(destination, capacity)) {
            return 22; // EINVAL
        }
        U32 sourceLength = 0;
        if (!session->guestCStringLength(
                source,
                sourceLength)) {
            session->memory->writeb(destination, 0);
            return 22;
        }
        U32 destinationLength = 0;
        if (append &&
            !session->guestCStringLength(
                destination,
                destinationLength,
                capacity)) {
            session->memory->writeb(destination, 0);
            return 22;
        }
        U64 required =
            static_cast<U64>(destinationLength) +
            sourceLength + 1;
        if (required > capacity) {
            session->memory->writeb(destination, 0);
            return 34; // ERANGE
        }
        session->memory->memcpy(
            destination + destinationLength,
            source,
            sourceLength + 1);
        return 0;
    }

    static void callbackUcrtStrcpyS(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!strcpy_s");
        if (session) {
            cpu->reg[0].u32 =
                copyGuestCrtStringSecure(
                    session,
                    argument(cpu, 0),
                    argument(cpu, 1),
                    argument(cpu, 2),
                    false);
        }
    }

    static void callbackUcrtStrcatS(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!strcat_s");
        if (session) {
            cpu->reg[0].u32 =
                copyGuestCrtStringSecure(
                    session,
                    argument(cpu, 0),
                    argument(cpu, 1),
                    argument(cpu, 2),
                    true);
        }
    }

    enum class UcrtCtypeOperation {
        IsLower,
        IsUpper,
        IsAlpha,
        IsDigit,
        IsAlnum,
        IsSpace,
        IsPunct,
        IsPrint,
        ToLower,
        ToUpper
    };

    static void callbackUcrtCtype(
        CPU* cpu,
        const char* api,
        UcrtCtypeOperation operation) {
        if (!current(cpu, api)) {
            return;
        }
        S32 input = static_cast<S32>(argument(cpu, 0));
        if (input == -1 ||
            input < 0 ||
            input > 255) {
            cpu->reg[0].u32 =
                static_cast<U32>(input);
            return;
        }
        U8 value = static_cast<U8>(input);
        bool lower = value >= 'a' && value <= 'z';
        bool upper = value >= 'A' && value <= 'Z';
        bool digit = value >= '0' && value <= '9';
        bool space =
            value == ' ' ||
            value == '\t' ||
            value == '\n' ||
            value == '\r' ||
            value == '\f' ||
            value == '\v';
        bool printable = value >= 0x20 && value <= 0x7e;
        switch (operation) {
        case UcrtCtypeOperation::IsLower:
            cpu->reg[0].u32 = lower;
            break;
        case UcrtCtypeOperation::IsUpper:
            cpu->reg[0].u32 = upper;
            break;
        case UcrtCtypeOperation::IsAlpha:
            cpu->reg[0].u32 = lower || upper;
            break;
        case UcrtCtypeOperation::IsDigit:
            cpu->reg[0].u32 = digit;
            break;
        case UcrtCtypeOperation::IsAlnum:
            cpu->reg[0].u32 = lower || upper || digit;
            break;
        case UcrtCtypeOperation::IsSpace:
            cpu->reg[0].u32 = space;
            break;
        case UcrtCtypeOperation::IsPunct:
            cpu->reg[0].u32 =
                printable &&
                !lower &&
                !upper &&
                !digit &&
                !space;
            break;
        case UcrtCtypeOperation::IsPrint:
            cpu->reg[0].u32 = printable;
            break;
        case UcrtCtypeOperation::ToLower:
            cpu->reg[0].u32 = upper
                ? value + ('a' - 'A')
                : value;
            break;
        case UcrtCtypeOperation::ToUpper:
            cpu->reg[0].u32 = lower
                ? value - ('a' - 'A')
                : value;
            break;
        }
    }

    static void callbackUcrtIsLower(CPU* cpu) {
        callbackUcrtCtype(
            cpu,
            "UCRT!islower",
            UcrtCtypeOperation::IsLower);
    }

    static void callbackUcrtIsUpper(CPU* cpu) {
        callbackUcrtCtype(
            cpu,
            "UCRT!isupper",
            UcrtCtypeOperation::IsUpper);
    }

    static void callbackUcrtIsAlpha(CPU* cpu) {
        callbackUcrtCtype(
            cpu,
            "UCRT!isalpha",
            UcrtCtypeOperation::IsAlpha);
    }

    static void callbackUcrtIsDigit(CPU* cpu) {
        callbackUcrtCtype(
            cpu,
            "UCRT!isdigit",
            UcrtCtypeOperation::IsDigit);
    }

    static void callbackUcrtIsAlnum(CPU* cpu) {
        callbackUcrtCtype(
            cpu,
            "UCRT!isalnum",
            UcrtCtypeOperation::IsAlnum);
    }

    static void callbackUcrtIsSpace(CPU* cpu) {
        callbackUcrtCtype(
            cpu,
            "UCRT!isspace",
            UcrtCtypeOperation::IsSpace);
    }

    static void callbackUcrtIsPunct(CPU* cpu) {
        callbackUcrtCtype(
            cpu,
            "UCRT!ispunct",
            UcrtCtypeOperation::IsPunct);
    }

    static void callbackUcrtIsPrint(CPU* cpu) {
        callbackUcrtCtype(
            cpu,
            "UCRT!isprint",
            UcrtCtypeOperation::IsPrint);
    }

    static void callbackUcrtToLower(CPU* cpu) {
        callbackUcrtCtype(
            cpu,
            "UCRT!tolower",
            UcrtCtypeOperation::ToLower);
    }

    static void callbackUcrtToUpper(CPU* cpu) {
        callbackUcrtCtype(
            cpu,
            "UCRT!toupper",
            UcrtCtypeOperation::ToUpper);
    }

    static bool prepareGuestNumberString(
        SugarbombRuntimeSession* session,
        CPU* cpu,
        U32 source,
        std::string& value) {
        U32 length = 0;
        return readGuestCrtString(
            session,
            cpu,
            source,
            value,
            length);
    }

    static void callbackUcrtParseInteger(
        CPU* cpu,
        const char* api,
        bool signedValue,
        bool wideResult) {
        SugarbombRuntimeSession* session = current(cpu, api);
        if (!session) {
            return;
        }
        U32 source = argument(cpu, 0);
        U32 endPointer = argument(cpu, 1);
        S32 base = static_cast<S32>(argument(cpu, 2));
        std::string value;
        if ((base != 0 && (base < 2 || base > 36)) ||
            !prepareGuestNumberString(
                session,
                cpu,
                source,
                value)) {
            session->setUcrtErrno(22);
            cpu->reg[0].u32 = 0;
            cpu->reg[2].u32 = 0;
            return;
        }
        errno = 0;
        char* end = nullptr;
        U64 parsed = signedValue
            ? static_cast<U64>(
                std::strtoll(value.c_str(), &end, base))
            : std::strtoull(value.c_str(), &end, base);
        U32 consumed = static_cast<U32>(
            end - value.c_str());
        if (endPointer) {
            if (!session->memory->canWrite(endPointer, 4)) {
                session->setUcrtErrno(22);
                cpu->reg[0].u32 = 0;
                cpu->reg[2].u32 = 0;
                return;
            }
            session->memory->writed(
                endPointer,
                source + consumed);
        }
        if (errno == ERANGE) {
            session->setUcrtErrno(34);
        }
        if (!wideResult) {
            if (signedValue) {
                S64 signedParsed = static_cast<S64>(parsed);
                if (signedParsed >
                        std::numeric_limits<S32>::max()) {
                    parsed = static_cast<U32>(
                        std::numeric_limits<S32>::max());
                    session->setUcrtErrno(34);
                } else if (
                    signedParsed <
                        std::numeric_limits<S32>::min()) {
                    parsed = static_cast<U32>(
                        std::numeric_limits<S32>::min());
                    session->setUcrtErrno(34);
                }
            } else if (
                parsed >
                    std::numeric_limits<U32>::max()) {
                parsed =
                    std::numeric_limits<U32>::max();
                session->setUcrtErrno(34);
            }
        }
        cpu->reg[0].u32 = static_cast<U32>(parsed);
        cpu->reg[2].u32 = wideResult
            ? static_cast<U32>(parsed >> 32)
            : 0;
    }

    static void callbackUcrtStrtol(CPU* cpu) {
        callbackUcrtParseInteger(
            cpu,
            "UCRT!strtol",
            true,
            false);
    }

    static void callbackUcrtStrtoll(CPU* cpu) {
        callbackUcrtParseInteger(
            cpu,
            "UCRT!strtoll",
            true,
            true);
    }

    static void callbackUcrtStrtoul(CPU* cpu) {
        callbackUcrtParseInteger(
            cpu,
            "UCRT!strtoul",
            false,
            false);
    }

    static void callbackUcrtParseDouble(
        CPU* cpu,
        const char* api,
        bool hasEndPointer) {
        SugarbombRuntimeSession* session = current(cpu, api);
        if (!session) {
            return;
        }
        U32 source = argument(cpu, 0);
        std::string value;
        if (!prepareGuestNumberString(
                session,
                cpu,
                source,
                value)) {
            returnGuestDouble(cpu, 0.0);
            return;
        }
        errno = 0;
        char* end = nullptr;
        double parsed =
            std::strtod(value.c_str(), &end);
        if (hasEndPointer) {
            U32 endPointer = argument(cpu, 1);
            if (endPointer) {
                if (!session->memory->canWrite(
                        endPointer,
                        4)) {
                    session->setUcrtErrno(22);
                    returnGuestDouble(cpu, 0.0);
                    return;
                }
                session->memory->writed(
                    endPointer,
                    source + static_cast<U32>(
                        end - value.c_str()));
            }
        }
        if (errno == ERANGE) {
            session->setUcrtErrno(34);
        }
        returnGuestDouble(cpu, parsed);
    }

    static void callbackUcrtStrtod(CPU* cpu) {
        callbackUcrtParseDouble(
            cpu,
            "UCRT!strtod",
            true);
    }

    static void callbackUcrtAtof(CPU* cpu) {
        callbackUcrtParseDouble(
            cpu,
            "UCRT!atof",
            false);
    }

    static void callbackUcrtAtoi(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!atoi");
        if (!session) {
            return;
        }
        std::string value;
        if (!prepareGuestNumberString(
                session,
                cpu,
                argument(cpu, 0),
                value)) {
            cpu->reg[0].u32 = 0;
            return;
        }
        cpu->reg[0].u32 = static_cast<U32>(
            static_cast<S32>(
                std::strtoll(
                    value.c_str(),
                    nullptr,
                    10)));
    }

    static void callbackUcrtErrno(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_errno");
        if (session) {
            cpu->reg[0].u32 =
                session->ensureUcrtErrno();
        }
    }

    static bool readGuestPrintfFormat(
        SugarbombRuntimeSession* session,
        U32 address,
        bool wide,
        std::string& format) {
        if (wide) {
            return session->readGuestWideString(
                address,
                format);
        }
        U32 length = 0;
        if (!session->guestCStringLength(
                address,
                length,
                1024 * 1024)) {
            return false;
        }
        format = session->readAnsi(address, length + 1);
        return true;
    }

    static void callbackUcrtCommonVsprintf(
        CPU* cpu,
        const char* api,
        bool secure,
        bool wide) {
        SugarbombRuntimeSession* session = current(cpu, api);
        if (!session) {
            return;
        }
        U32 destination = argument(cpu, 2);
        U32 capacity = argument(cpu, 3);
        U32 formatAddress = argument(cpu, 4);
        U32 vaList = argument(cpu, 6);
        std::string format;
        std::string output;
        bool success =
            destination &&
            capacity &&
            readGuestPrintfFormat(
                session,
                formatAddress,
                wide,
                format) &&
            session->formatGuestPrintf(
                format,
                vaList,
                wide,
                output);
        if (success) {
            U64 requiredUnits =
                static_cast<U64>(output.size()) + 1;
            U64 requiredBytes =
                requiredUnits * (wide ? 2 : 1);
            success =
                (!secure || requiredUnits <= capacity) &&
                requiredUnits <= capacity &&
                requiredBytes <=
                    std::numeric_limits<U32>::max() &&
                session->memory->canWrite(
                    destination,
                    static_cast<U32>(requiredBytes));
        }
        if (!success) {
            if (destination &&
                session->memory->canWrite(
                    destination,
                    wide ? 2 : 1)) {
                if (wide) {
                    session->memory->writew(destination, 0);
                } else {
                    session->memory->writeb(destination, 0);
                }
            }
            session->setLastError(87);
            cpu->reg[0].u32 = 0xffffffff;
            return;
        }
        if (wide) {
            for (U32 index = 0;
                 index < output.size();
                 ++index) {
                session->memory->writew(
                    destination + index * 2,
                    static_cast<U8>(output[index]));
            }
            session->memory->writew(
                destination +
                    static_cast<U32>(output.size()) * 2,
                0);
        } else {
            if (!output.empty()) {
                session->memory->memcpy(
                    destination,
                    output.data(),
                    static_cast<U32>(output.size()));
            }
            session->memory->writeb(
                destination +
                    static_cast<U32>(output.size()),
                0);
        }
        if (++session->printfTraceCount <= 24) {
            printf(
                "Sugarbomb UCRT printf: \"%s\" -> \"%s\"\n",
                format.c_str(),
                output.c_str());
        }
        cpu->reg[0].u32 =
            static_cast<U32>(output.size());
    }

    static void callbackUcrtStdioCommonVsprintfS(CPU* cpu) {
        callbackUcrtCommonVsprintf(
            cpu,
            "UCRT!__stdio_common_vsprintf_s",
            true,
            false);
    }

    static void callbackUcrtStdioCommonVsprintf(CPU* cpu) {
        callbackUcrtCommonVsprintf(
            cpu,
            "UCRT!__stdio_common_vsprintf",
            false,
            false);
    }

    static void callbackUcrtStdioCommonVswprintf(CPU* cpu) {
        callbackUcrtCommonVsprintf(
            cpu,
            "UCRT!__stdio_common_vswprintf",
            false,
            true);
    }

    static void callbackUcrtCommonVfprintf(
        CPU* cpu,
        const char* api) {
        SugarbombRuntimeSession* session = current(cpu, api);
        if (!session) {
            return;
        }
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 2));
        std::string format;
        std::string output;
        if (!stream ||
            !readGuestPrintfFormat(
                session,
                argument(cpu, 3),
                false,
                format) ||
            !session->formatGuestPrintf(
                format,
                argument(cpu, 5),
                false,
                output) ||
            session->writeHostToGuestCFile(
                *stream,
                output) != output.size()) {
            cpu->reg[0].u32 = 0xffffffff;
            return;
        }
        if (++session->printfTraceCount <= 24) {
            printf(
                "Sugarbomb UCRT fprintf: \"%s\" -> \"%s\"\n",
                format.c_str(),
                output.c_str());
        }
        cpu->reg[0].u32 =
            static_cast<U32>(output.size());
    }

    static void callbackUcrtStdioCommonVfprintfS(CPU* cpu) {
        callbackUcrtCommonVfprintf(
            cpu,
            "UCRT!__stdio_common_vfprintf_s");
    }

    static void callbackUcrtStdioCommonVfprintf(CPU* cpu) {
        callbackUcrtCommonVfprintf(
            cpu,
            "UCRT!__stdio_common_vfprintf");
    }

    static void callbackUcrtStdioCommonVsscanf(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!__stdio_common_vsscanf");
        if (!session) {
            return;
        }
        U32 source = argument(cpu, 2);
        U32 sourceLimit = argument(cpu, 3);
        U32 sourceLength = 0;
        bool sourceValid = source != 0;
        if (sourceValid &&
            sourceLimit == 0xffffffff) {
            sourceValid = session->guestCStringLength(
                source,
                sourceLength,
                16 * 1024 * 1024);
        } else if (sourceValid) {
            while (sourceLength < sourceLimit &&
                   sourceLength < 16 * 1024 * 1024) {
                if (source >
                        std::numeric_limits<U32>::max() -
                            sourceLength ||
                    !session->memory->canRead(
                        source + sourceLength,
                        1)) {
                    sourceValid = false;
                    break;
                }
                if (!session->memory->readb(
                        source + sourceLength)) {
                    break;
                }
                ++sourceLength;
            }
            if (sourceLength == 16 * 1024 * 1024 &&
                sourceLength < sourceLimit) {
                sourceValid = false;
            }
        }
        std::string format;
        std::string input;
        S32 result = -1;
        if (sourceValid &&
            readGuestPrintfFormat(
                session,
                argument(cpu, 4),
                false,
                format)) {
            input = session->readAnsi(
                source,
                sourceLength + 1);
            session->formatGuestScanf(
                input,
                format,
                argument(cpu, 6),
                result);
        }
        if (++session->printfTraceCount <= 24) {
            printf(
                "Sugarbomb UCRT scanf: \"%s\" <- \"%s\" "
                "(%d assignment%s)\n",
                format.c_str(),
                input.c_str(),
                result,
                result == 1 ? "" : "s");
        }
        cpu->reg[0].u32 = static_cast<U32>(result);
    }

    static void callbackUcrtFsopen(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_fsopen");
        if (session) {
            cpu->reg[0].u32 = session->openGuestCFile(
                session->readAnsi(argument(cpu, 0), 4096),
                session->readAnsi(argument(cpu, 1), 64));
        }
    }

    static void callbackUcrtFopenS(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!fopen_s");
        if (!session) {
            return;
        }
        U32 destination = argument(cpu, 0);
        if (!destination ||
            !session->memory->canWrite(destination, 4)) {
            cpu->reg[0].u32 = 22; // EINVAL
            return;
        }
        U32 stream = session->openGuestCFile(
            session->readAnsi(argument(cpu, 1), 4096),
            session->readAnsi(argument(cpu, 2), 64));
        session->memory->writed(destination, stream);
        cpu->reg[0].u32 = stream ? 0 : 2; // ENOENT
    }

    static void callbackUcrtFclose(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!fclose");
        if (session) {
            cpu->reg[0].u32 =
                session->closeGuestCFile(argument(cpu, 0))
                ? 0
                : 0xffffffff;
        }
    }

    static void callbackUcrtFread(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!fread");
        if (!session) {
            return;
        }
        U32 elementSize = argument(cpu, 1);
        U32 elementCount = argument(cpu, 2);
        U64 requested =
            static_cast<U64>(elementSize) * elementCount;
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 3));
        if (!elementSize ||
            !elementCount) {
            cpu->reg[0].u32 = 0;
            return;
        }
        if (!stream ||
            requested > std::numeric_limits<U32>::max()) {
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 bytes = session->readGuestCFile(
            *stream,
            argument(cpu, 0),
            static_cast<U32>(requested));
        cpu->reg[0].u32 = bytes / elementSize;
    }

    static void callbackUcrtFwrite(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!fwrite");
        if (!session) {
            return;
        }
        U32 elementSize = argument(cpu, 1);
        U32 elementCount = argument(cpu, 2);
        U64 requested =
            static_cast<U64>(elementSize) * elementCount;
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 3));
        if (!elementSize ||
            !elementCount) {
            cpu->reg[0].u32 = 0;
            return;
        }
        if (!stream ||
            requested > std::numeric_limits<U32>::max()) {
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 bytes = session->writeGuestCFile(
            *stream,
            argument(cpu, 0),
            static_cast<U32>(requested));
        cpu->reg[0].u32 = bytes / elementSize;
    }

    static void callbackUcrtFgetc(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!fgetc");
        if (!session) {
            return;
        }
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 0));
        cpu->reg[0].u32 = stream
            ? static_cast<U32>(
                session->readGuestCFileByte(*stream))
            : 0xffffffff;
    }

    static void callbackUcrtFputc(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!fputc");
        if (!session) {
            return;
        }
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 1));
        U8 value = static_cast<U8>(argument(cpu, 0));
        cpu->reg[0].u32 =
            stream &&
            session->writeGuestCFileByte(*stream, value)
            ? value
            : 0xffffffff;
    }

    static void callbackUcrtFputs(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!fputs");
        if (!session) {
            return;
        }
        U32 source = argument(cpu, 0);
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 1));
        U32 length = 0;
        if (!stream ||
            !session->guestCStringLength(source, length)) {
            cpu->reg[0].u32 = 0xffffffff;
            return;
        }
        cpu->reg[0].u32 =
            session->writeGuestCFile(
                *stream,
                source,
                length) == length
            ? 0
            : 0xffffffff;
    }

    static void callbackUcrtFflush(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!fflush");
        if (!session) {
            return;
        }
        U32 streamAddress = argument(cpu, 0);
        if (!streamAddress) {
            fflush(stdout);
            fflush(stderr);
            cpu->reg[0].u32 = 0;
            return;
        }
        cpu->reg[0].u32 =
            session->findGuestCFile(streamAddress)
            ? 0
            : 0xffffffff;
    }

    static void callbackUcrtFseeki64(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_fseeki64");
        if (!session) {
            return;
        }
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 0));
        if (!stream || stream->standardIndex >= 0) {
            cpu->reg[0].u32 = 0xffffffff;
            return;
        }
        U64 rawDistance =
            static_cast<U64>(argument(cpu, 1)) |
            (static_cast<U64>(argument(cpu, 2)) << 32);
        U64 position = 0;
        bool success = session->setGuestFilePointer(
            stream->guestFileHandle,
            static_cast<S64>(rawDistance),
            argument(cpu, 3),
            position);
        if (success) {
            stream->endOfFile = false;
            stream->ungot = -1;
        }
        cpu->reg[0].u32 =
            success ? 0 : 0xffffffff;
    }

    static void callbackUcrtFgetpos(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!fgetpos");
        if (!session) {
            return;
        }
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 0));
        U32 destination = argument(cpu, 1);
        auto file = stream
            ? session->guestFiles.find(stream->guestFileHandle)
            : session->guestFiles.end();
        if (!stream ||
            file == session->guestFiles.end() ||
            !destination ||
            !session->memory->canWrite(destination, 8)) {
            cpu->reg[0].u32 = 0xffffffff;
            return;
        }
        session->memory->writeq(
            destination,
            file->second.position);
        cpu->reg[0].u32 = 0;
    }

    static void callbackUcrtFsetpos(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!fsetpos");
        if (!session) {
            return;
        }
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 0));
        U32 source = argument(cpu, 1);
        if (!stream ||
            stream->standardIndex >= 0 ||
            !source ||
            !session->memory->canRead(source, 8)) {
            cpu->reg[0].u32 = 0xffffffff;
            return;
        }
        U64 position = 0;
        U64 raw = session->memory->readq(source);
        bool success =
            raw <= static_cast<U64>(
                std::numeric_limits<S64>::max()) &&
            session->setGuestFilePointer(
                stream->guestFileHandle,
                static_cast<S64>(raw),
                0,
                position);
        if (success) {
            stream->endOfFile = false;
            stream->ungot = -1;
        }
        cpu->reg[0].u32 =
            success ? 0 : 0xffffffff;
    }

    static void callbackUcrtSetvbuf(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!setvbuf");
        if (!session) {
            return;
        }
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 0));
        if (!stream ||
            !session->memory->canWrite(
                stream->objectAddress,
                12)) {
            cpu->reg[0].u32 = 0xffffffff;
            return;
        }
        session->memory->memset(
            stream->objectAddress,
            0,
            12);
        cpu->reg[0].u32 = 0;
    }

    static void callbackUcrtUngetc(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!ungetc");
        if (!session) {
            return;
        }
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 1));
        U32 character = argument(cpu, 0);
        if (!stream ||
            character == 0xffffffff ||
            stream->ungot >= 0) {
            cpu->reg[0].u32 = 0xffffffff;
            return;
        }
        stream->ungot = static_cast<U8>(character);
        stream->endOfFile = false;
        cpu->reg[0].u32 =
            static_cast<U8>(character);
    }

    static void callbackUcrtLockFile(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_lock_file");
        if (!session) {
            return;
        }
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 0));
        if (!stream) {
            return;
        }
        if (!session->enterCriticalSection(
                stream->lockAddress)) {
            GuestThreadState* state =
                session->findGuestThread(cpu->thread->id);
            if (state) {
                session->parkGuestThreadOnCriticalSection(
                    *state,
                    stream->lockAddress);
            }
        }
    }

    static void callbackUcrtUnlockFile(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_unlock_file");
        if (!session) {
            return;
        }
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 0));
        if (stream) {
            session->leaveCriticalSection(
                stream->lockAddress);
        }
    }

    static void callbackUcrtGetStreamBufferPointers(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!_get_stream_buffer_pointers");
        if (!session) {
            return;
        }
        GuestCFile* stream =
            session->findGuestCFile(argument(cpu, 0));
        U32 base = argument(cpu, 1);
        U32 current = argument(cpu, 2);
        U32 count = argument(cpu, 3);
        if (!stream ||
            !base ||
            !current ||
            !count ||
            !session->memory->canWrite(base, 4) ||
            !session->memory->canWrite(current, 4) ||
            !session->memory->canWrite(count, 4)) {
            return;
        }
        session->memory->writed(
            base,
            stream->objectAddress);
        session->memory->writed(
            current,
            stream->objectAddress + 4);
        session->memory->writed(
            count,
            stream->objectAddress + 8);
    }

    static void callbackUcrtIobFunction(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "UCRT!__acrt_iob_func");
        if (session) {
            cpu->reg[0].u32 =
                session->standardGuestCFile(
                    argument(cpu, 0));
        }
    }

    U32 msvcpLockAddress(U32 kind) {
        auto found = msvcpLockAddresses.find(kind);
        if (found != msvcpLockAddresses.end()) {
            return found->second;
        }
        U32 address = allocateGuestHeap(24, true);
        if (!address) {
            return 0;
        }
        initializeCriticalSection(address, 0);
        msvcpLockAddresses[kind] = address;
        return address;
    }

    static void callbackMsvcpLockitConstruct(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "MSVCP140!_Lockit::_Lockit");
        if (!session) {
            return;
        }
        U32 object = cpu->reg[1].u32; // this in ECX
        U32 kind = argument(cpu, 0);
        U32 lock = session->msvcpLockAddress(kind);
        if (!object ||
            !lock ||
            !session->memory->canWrite(object, 4)) {
            session->setLastError(8);
            session->runtimeStopping = true;
            cpu->thread->terminating = true;
            return;
        }
        session->memory->writed(object, kind);
        session->msvcpLockitObjects[object] = kind;
        if (!session->enterCriticalSection(lock)) {
            GuestThreadState* state =
                session->findGuestThread(cpu->thread->id);
            if (!state) {
                session->runtimeStopping = true;
                cpu->thread->terminating = true;
                return;
            }
            session->parkGuestThreadOnCriticalSection(
                *state,
                lock);
        }
        cpu->reg[0].u32 = object;
    }

    static void callbackMsvcpLockitDestruct(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "MSVCP140!_Lockit::~_Lockit");
        if (!session) {
            return;
        }
        U32 object = cpu->reg[1].u32; // this in ECX
        auto instance =
            session->msvcpLockitObjects.find(object);
        if (instance == session->msvcpLockitObjects.end()) {
            return;
        }
        auto lock =
            session->msvcpLockAddresses.find(
                instance->second);
        if (lock != session->msvcpLockAddresses.end()) {
            session->leaveCriticalSection(lock->second);
        }
        session->msvcpLockitObjects.erase(instance);
    }

    static void callbackVirtualAlloc(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!VirtualAlloc");
        if (session) {
            ++session->virtualAllocCallCount;
            if (session->virtualAllocCallCount <= 20) {
                printf(
                    "Sugarbomb Win32 memory: VirtualAlloc(address=0x%08X, size=0x%08X, type=0x%08X, protect=0x%08X)\n",
                    argument(cpu, 0),
                    argument(cpu, 1),
                    argument(cpu, 2),
                    argument(cpu, 3));
            } else if (session->virtualAllocCallCount == 21) {
                printf("Sugarbomb Win32 memory: suppressing repetitive VirtualAlloc trace lines\n");
            }
            U32 address = argument(cpu, 0);
            U32 size = argument(cpu, 1);
            U32 allocationType = argument(cpu, 2);
            U32 protection = argument(cpu, 3);
            cpu->reg[0].u32 =
                session->virtualAlloc(address, size, allocationType, protection);
            if (!cpu->reg[0].u32) {
                ++session->virtualAllocFailureTraceCount;
                if (!address || session->virtualAllocFailureTraceCount <= 16) {
                    fprintf(
                        stderr,
                        "Sugarbomb Win32 memory: VirtualAlloc FAILED (address=0x%08X, size=0x%08X, type=0x%08X, protect=0x%08X, next=0x%08X)\n",
                        address,
                        size,
                        allocationType,
                        protection,
                        session->nextVirtualAddress);
                } else if (session->virtualAllocFailureTraceCount == 17) {
                    fprintf(stderr, "Sugarbomb Win32 memory: suppressing expected fixed-address VirtualAlloc probe failures\n");
                }
            }
        }
    }

    static void callbackVirtualFree(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!VirtualFree");
        if (session) {
            cpu->reg[0].u32 = session->virtualFree(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2)) ? 1 : 0;
        }
    }

    static void callbackVirtualProtect(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!VirtualProtect");
        if (session) {
            cpu->reg[0].u32 =
                session->virtualProtect(
                    argument(cpu, 0),
                    argument(cpu, 1),
                    argument(cpu, 2),
                    argument(cpu, 3))
                ? 1
                : 0;
        }
    }

    static void callbackVirtualQuery(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!VirtualQuery");
        if (session) {
            cpu->reg[0].u32 = session->virtualQuery(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2));
        }
    }

    static void callbackFlushInstructionCache(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "KERNEL32!FlushInstructionCache");
        if (session) {
            const U32 processHandle = argument(cpu, 0);
            const U32 baseAddress = argument(cpu, 1);
            const U32 size = argument(cpu, 2);
            if (++session->flushInstructionCacheTraceCount <= 16) {
                printf(
                    "Sugarbomb Win32 memory: FlushInstructionCache("
                    "0x%08X, 0x%08X, 0x%08X)\n",
                    processHandle,
                    baseAddress,
                    size);
            }

            // Guest writes already invalidate BoxedWine's translated code through
            // the memory write path. Clearing the complete operation cache here
            // would release the translated block that is executing this callback.
            cpu->reg[0].u32 = 1;
        }
    }

    static void callbackCreateSemaphoreA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!CreateSemaphoreA");
        if (session) {
            cpu->reg[0].u32 = session->createSemaphore(
                static_cast<S32>(argument(cpu, 1)),
                static_cast<S32>(argument(cpu, 2)),
                argument(cpu, 3));
        }
    }

    static void callbackReleaseSemaphore(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!ReleaseSemaphore");
        if (session) {
            cpu->reg[0].u32 = session->releaseSemaphore(
                argument(cpu, 0),
                static_cast<S32>(argument(cpu, 1)),
                argument(cpu, 2)) ? 1 : 0;
        }
    }

    static void callbackCreateEventA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!CreateEventA");
        if (session) {
            cpu->reg[0].u32 = session->createEvent(
                argument(cpu, 1) != 0,
                argument(cpu, 2) != 0,
                argument(cpu, 3));
        }
    }

    static void callbackSetEvent(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!SetEvent");
        if (session) {
            cpu->reg[0].u32 = session->setEvent(argument(cpu, 0), true) ? 1 : 0;
        }
    }

    static void callbackResetEvent(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!ResetEvent");
        if (session) {
            cpu->reg[0].u32 = session->setEvent(argument(cpu, 0), false) ? 1 : 0;
        }
    }

    static void callbackCreateMutexA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!CreateMutexA");
        if (session) {
            cpu->reg[0].u32 = session->createMutex(
                argument(cpu, 1) != 0,
                argument(cpu, 2));
        }
    }

    static void callbackReleaseMutex(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!ReleaseMutex");
        if (session) {
            cpu->reg[0].u32 = session->releaseMutex(argument(cpu, 0)) ? 1 : 0;
        }
    }

    static void callbackWaitForSingleObject(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!WaitForSingleObject");
        if (session) {
            cpu->reg[0].u32 = session->waitForSingleObject(
                argument(cpu, 0),
                argument(cpu, 1));
        }
    }

    static void callbackWaitForMultipleObjects(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!WaitForMultipleObjects");
        if (session) {
            cpu->reg[0].u32 = session->waitForMultipleObjects(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2) != 0,
                argument(cpu, 3));
        }
    }

    static void callbackSleep(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!Sleep");
        if (session) {
            session->sleepGuestThread(cpu, argument(cpu, 0));
        }
    }

    static void callbackCreateThread(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!CreateThread");
        if (session) {
            cpu->reg[0].u32 = session->createGuestThread(
                cpu,
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3),
                argument(cpu, 4),
                argument(cpu, 5));
        }
    }

    static void callbackResumeThread(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!ResumeThread");
        if (session) {
            cpu->reg[0].u32 = session->changeThreadSuspendCount(argument(cpu, 0), false);
        }
    }

    static void callbackSuspendThread(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!SuspendThread");
        if (session) {
            cpu->reg[0].u32 = session->changeThreadSuspendCount(argument(cpu, 0), true);
        }
    }

    static void callbackExitThread(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!ExitThread");
        if (session) {
            session->completeCurrentGuestThread(cpu, argument(cpu, 0));
        }
    }

    static void callbackGetExitCodeThread(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetExitCodeThread");
        if (session) {
            cpu->reg[0].u32 = session->getGuestThreadExitCode(
                argument(cpu, 0),
                argument(cpu, 1)) ? 1 : 0;
        }
    }

    static void callbackGetCurrentThread(CPU* cpu) {
        if (current(cpu, "KERNEL32!GetCurrentThread")) {
            cpu->reg[0].u32 = CURRENT_THREAD_PSEUDO_HANDLE;
        }
    }

    static void callbackSetThreadPriority(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!SetThreadPriority");
        if (session) {
            cpu->reg[0].u32 = session->isGuestThreadHandle(argument(cpu, 0), cpu) ? 1 : 0;
        }
    }

    static void callbackSetThreadIdealProcessor(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!SetThreadIdealProcessor");
        if (session) {
            if (session->isGuestThreadHandle(argument(cpu, 0), cpu)) {
                cpu->reg[0].u32 = 0;
            } else {
                cpu->reg[0].u32 = 0xffffffff;
            }
        }
    }

    static void callbackWriteFile(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!WriteFile");
        if (session) {
            U32 handle = argument(cpu, 0);
            if (session->isStandardHandle(handle)) {
                cpu->reg[0].u32 = session->writeGuestOutput(
                    handle,
                    argument(cpu, 1),
                    argument(cpu, 2),
                    argument(cpu, 3),
                    false) ? 1 : 0;
            } else {
                cpu->reg[0].u32 = session->writeGuestFile(
                    handle,
                    argument(cpu, 1),
                    argument(cpu, 2),
                    argument(cpu, 3)) ? 1 : 0;
            }
        }
    }

    static void callbackWriteConsoleA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!WriteConsoleA");
        if (session) {
            cpu->reg[0].u32 = session->writeGuestOutput(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3),
                false) ? 1 : 0;
        }
    }

    static void callbackWriteConsoleW(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!WriteConsoleW");
        if (session) {
            cpu->reg[0].u32 = session->writeGuestOutput(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3),
                true) ? 1 : 0;
        }
    }

    static void callbackReadFile(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!ReadFile");
        if (!session) {
            return;
        }
        U32 bytesRead = argument(cpu, 3);
        U32 handle = argument(cpu, 0);
        if (session->isStandardHandle(handle)) {
            if (bytesRead) {
                session->memory->writed(bytesRead, 0);
            }
            cpu->reg[0].u32 = 1;
        } else {
            cpu->reg[0].u32 = session->readGuestFile(
                handle,
                argument(cpu, 1),
                argument(cpu, 2),
                bytesRead) ? 1 : 0;
        }
        if (!cpu->reg[0].u32) {
            session->setLastError(6);
        }
    }

    static void callbackFlushFileBuffers(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!FlushFileBuffers");
        if (session) {
            fflush(stdout);
            fflush(stderr);
            U32 handle = argument(cpu, 0);
            cpu->reg[0].u32 =
                (session->isStandardHandle(handle) ||
                 session->guestFiles.find(handle) != session->guestFiles.end()) ? 1 : 0;
        }
    }

    static void callbackCloseHandle(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!CloseHandle");
        if (session) {
            U32 handle = argument(cpu, 0);
            cpu->reg[0].u32 =
                (session->isStandardHandle(handle) ||
                 session->closeGuestFile(handle) ||
                 session->closeKernelHandle(handle)) ? 1 : 0;
            if (!cpu->reg[0].u32) {
                session->setLastError(6);
            }
        }
    }

    static void callbackHeapCreate(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!HeapCreate");
        if (session) {
            cpu->reg[0].u32 = session->nextHeapHandle++;
        }
    }

    static void callbackGetProcessHeap(CPU* cpu) {
        if (current(cpu, "KERNEL32!GetProcessHeap")) {
            cpu->reg[0].u32 = PROCESS_HEAP_HANDLE;
        }
    }

    static void callbackHeapAlloc(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!HeapAlloc");
        if (session) {
            U32 flags = argument(cpu, 1);
            U32 size = argument(cpu, 2);
            cpu->reg[0].u32 = session->allocateGuestHeap(size, (flags & HEAP_ZERO_MEMORY) != 0);
        }
    }

    static void callbackHeapReAlloc(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!HeapReAlloc");
        if (session) {
            U32 flags = argument(cpu, 1);
            U32 previous = argument(cpu, 2);
            U32 size = argument(cpu, 3);
            cpu->reg[0].u32 = session->reallocateGuestHeap(
                previous,
                size,
                (flags & HEAP_ZERO_MEMORY) != 0);
        }
    }

    static void callbackHeapFree(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!HeapFree");
        if (session) {
            U32 address = argument(cpu, 2);
            cpu->reg[0].u32 = session->freeGuestHeap(address) ? 1 : 0;
        }
    }

    static void callbackHeapSize(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!HeapSize");
        if (session) {
            auto allocation = session->heapAllocations.find(argument(cpu, 2));
            cpu->reg[0].u32 = allocation == session->heapAllocations.end()
                ? 0xffffffff
                : allocation->second.requestedSize;
        }
    }

    static void callbackLocalFree(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!LocalFree");
        if (session) {
            U32 address = argument(cpu, 0);
            cpu->reg[0].u32 =
                (!address || session->freeGuestHeap(address)) ? 0 : address;
        }
    }

    static void callbackExitProcess(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!ExitProcess");
        if (session) {
            session->exitCode = argument(cpu, 0);
            session->runtimeStopping = true;
            printf("Sugarbomb: guest requested ExitProcess(%u)\n", session->exitCode);
            for (auto& state : session->guestThreads) {
                if (state->thread) {
                    state->thread->terminating = true;
                }
            }
        }
        cpu->thread->terminating = true;
    }

    static void callbackEntryPointReturn(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "SUGARBOMB!ExeEntryPointReturn");
        if (session) {
            printf("Sugarbomb: PE32 executable entry point returned EAX=0x%08X\n", cpu->reg[0].u32);
            session->runtimeStopping = true;
        }
        cpu->thread->terminating = true;
    }

    static void callbackThreadEntryPointReturn(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "SUGARBOMB!ThreadEntryPointReturn");
        if (session) {
            session->completeCurrentGuestThread(cpu, cpu->reg[0].u32);
        }
    }

    static void callbackGuestWndProcReturn(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(cpu, "SUGARBOMB!GuestWndProcReturn");
        if (session) {
            session->completeGuestWndProcDispatch(cpu);
        }
    }

    static void callbackGuestModuleInitializerReturn(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(
                cpu,
                "SUGARBOMB!GuestModuleInitializerReturn");
        if (session) {
            session->completeGuestModuleInitializer(cpu);
        }
    }

    static void callbackGuestFunctionArrayReturn(CPU* cpu) {
        SugarbombRuntimeSession* session =
            current(
                cpu,
                "SUGARBOMB!GuestFunctionArrayReturn");
        if (session) {
            session->completeGuestFunctionArray(cpu);
        }
    }

    static void callbackUnresolvedImport(CPU* cpu) {
        std::string module;
        std::string symbol;
        U32 callbackIndex = cpu->peek32(0);
        SugarbombBridge::callbackName(callbackIndex, module, symbol);
        if (activeSession) {
            ++activeSession->nativeCallCount;
            activeSession->stoppedAtUnresolvedImport = true;
            activeSession->runtimeStopping = true;
        }
        fprintf(
            stderr,
            "Sugarbomb: stopped at unresolved Win32 import %s!%s "
            "(callback %u, tid %u, return=0x%08X, "
            "args=[0x%08X,0x%08X,0x%08X,0x%08X,"
            "0x%08X,0x%08X,0x%08X,0x%08X])\n",
            module.c_str(),
            symbol.c_str(),
            callbackIndex,
            cpu->thread->id,
            cpu->peek32(1),
            cpu->peek32(2),
            cpu->peek32(3),
            cpu->peek32(4),
            cpu->peek32(5),
            cpu->peek32(6),
            cpu->peek32(7),
            cpu->peek32(8),
            cpu->peek32(9));
        cpu->reg[0].u32 = 0xc0000139; // STATUS_ENTRYPOINT_NOT_FOUND
        cpu->thread->terminating = true;
    }

    struct VirtualFileContent {
        std::vector<U8> bytes;
    };

    struct GuestFile {
        std::filesystem::path path;
        std::unique_ptr<std::ifstream> input;
        std::shared_ptr<VirtualFileContent> overlay;
        U64 position = 0;
        U64 size = 0;
        bool readable = false;
        bool writable = false;
    };

    struct GuestCFile {
        U32 guestFileHandle = 0;
        U32 objectAddress = 0;
        U32 lockAddress = 0;
        S32 standardIndex = -1;
        S32 ungot = -1;
        bool endOfFile = false;
        bool error = false;
    };

    struct FindState {
        std::vector<std::filesystem::path> entries;
        std::size_t nextIndex = 0;
    };

    static bool wildcardMatch(const std::string& patternValue, const std::string& textValue) {
        std::string pattern = lowerAscii(patternValue);
        std::string text = lowerAscii(textValue);
        std::size_t patternIndex = 0;
        std::size_t textIndex = 0;
        std::size_t starIndex = std::string::npos;
        std::size_t retryTextIndex = 0;
        while (textIndex < text.size()) {
            if (patternIndex < pattern.size() &&
                (pattern[patternIndex] == '?' || pattern[patternIndex] == text[textIndex])) {
                ++patternIndex;
                ++textIndex;
            } else if (patternIndex < pattern.size() && pattern[patternIndex] == '*') {
                starIndex = patternIndex++;
                retryTextIndex = textIndex;
            } else if (starIndex != std::string::npos) {
                patternIndex = starIndex + 1;
                textIndex = ++retryTextIndex;
            } else {
                return false;
            }
        }
        while (patternIndex < pattern.size() && pattern[patternIndex] == '*') {
            ++patternIndex;
        }
        return patternIndex == pattern.size();
    }

    U32 createGuestFile(const std::string& guestPath, U32 desiredAccess, U32 disposition) {
        if (guestPath.empty()) {
            setLastError(87);
            return 0xffffffff;
        }
        std::filesystem::path path = resolveGuestPath(guestPath);
        std::string normalized = lowerAscii(path.string());
        auto overlay = virtualFileContents.find(normalized);
        bool hostExists = std::filesystem::is_regular_file(path) &&
            virtualDeletedFiles.find(normalized) == virtualDeletedFiles.end();
        bool exists = overlay != virtualFileContents.end() || hostExists;
        bool readable = (desiredAccess & 0x80000000) != 0 || desiredAccess == 0;
        bool writable = (desiredAccess & 0x40000000) != 0;
        bool createEmpty = false;
        switch (disposition) {
        case 1: // CREATE_NEW
            if (exists) {
                setLastError(80);
                return 0xffffffff;
            }
            createEmpty = true;
            break;
        case 2: // CREATE_ALWAYS
            createEmpty = true;
            break;
        case 3: // OPEN_EXISTING
            if (!exists) {
                setLastError(2);
                return 0xffffffff;
            }
            break;
        case 4: // OPEN_ALWAYS
            createEmpty = !exists;
            break;
        case 5: // TRUNCATE_EXISTING
            if (!exists || !writable) {
                setLastError(!exists ? 2 : 5);
                return 0xffffffff;
            }
            createEmpty = true;
            break;
        default:
            setLastError(87);
            return 0xffffffff;
        }

        GuestFile file;
        file.path = path;
        file.readable = readable;
        file.writable = writable;
        if (createEmpty || writable || overlay != virtualFileContents.end()) {
            std::shared_ptr<VirtualFileContent> content;
            if (overlay != virtualFileContents.end() && !createEmpty) {
                content = overlay->second;
            } else {
                content = std::make_shared<VirtualFileContent>();
                if (hostExists && !createEmpty) {
                    std::ifstream input(path, std::ios::binary);
                    input.seekg(0, std::ios::end);
                    std::streamoff length = input.tellg();
                    input.seekg(0, std::ios::beg);
                    if (length > 0) {
                        content->bytes.resize(static_cast<std::size_t>(length));
                        input.read(
                            reinterpret_cast<char*>(content->bytes.data()),
                            static_cast<std::streamsize>(content->bytes.size()));
                    }
                }
                virtualFileContents[normalized] = content;
            }
            file.overlay = content;
            file.size = content->bytes.size();
            virtualDeletedFiles.erase(normalized);
        } else {
            file.input.reset(new std::ifstream(path, std::ios::binary));
            if (!*file.input) {
                setLastError(2);
                return 0xffffffff;
            }
            file.input->seekg(0, std::ios::end);
            std::streamoff length = file.input->tellg();
            file.input->seekg(0, std::ios::beg);
            file.size = length > 0 ? static_cast<U64>(length) : 0;
        }
        U32 handle = nextGuestFileHandle++;
        guestFiles[handle] = std::move(file);
        if (++fileOpenTraceCount <= 20) {
            printf(
                "Sugarbomb Win32 file: CreateFile(%s, access=0x%08X, disposition=%u) -> 0x%08X\n",
                path.string().c_str(),
                desiredAccess,
                disposition,
                handle);
        }
        return handle;
    }

    bool readGuestFile(U32 handle, U32 destination, U32 requested, U32 bytesReadAddress) {
        auto found = guestFiles.find(handle);
        if (found == guestFiles.end() || !found->second.readable ||
            (requested && !memory->canWrite(destination, requested))) {
            setLastError(found == guestFiles.end() ? 6 : 5);
            return false;
        }
        GuestFile& file = found->second;
        U64 available = file.position < file.size ? file.size - file.position : 0;
        U32 count = static_cast<U32>(std::min<U64>(available, requested));
        if (count) {
            if (file.overlay) {
                memory->memcpy(
                    destination,
                    file.overlay->bytes.data() + static_cast<std::size_t>(file.position),
                    count);
            } else {
                std::vector<U8> buffer(count);
                file.input->clear();
                file.input->seekg(static_cast<std::streamoff>(file.position), std::ios::beg);
                file.input->read(reinterpret_cast<char*>(buffer.data()), count);
                count = static_cast<U32>(file.input->gcount());
                if (count) {
                    memory->memcpy(destination, buffer.data(), count);
                }
            }
            file.position += count;
        }
        if (bytesReadAddress) {
            memory->writed(bytesReadAddress, count);
        }
        return true;
    }

    bool writeGuestFile(U32 handle, U32 source, U32 requested, U32 bytesWrittenAddress) {
        auto found = guestFiles.find(handle);
        if (found == guestFiles.end() || !found->second.writable ||
            !found->second.overlay || (requested && !memory->canRead(source, requested))) {
            setLastError(found == guestFiles.end() ? 6 : 5);
            return false;
        }
        GuestFile& file = found->second;
        U64 end = file.position + requested;
        if (end > static_cast<U64>(std::numeric_limits<std::size_t>::max())) {
            setLastError(8);
            return false;
        }
        if (end > file.overlay->bytes.size()) {
            file.overlay->bytes.resize(static_cast<std::size_t>(end), 0);
        }
        for (U32 index = 0; index < requested; ++index) {
            file.overlay->bytes[static_cast<std::size_t>(file.position) + index] =
                memory->readb(source + index);
        }
        file.position = end;
        file.size = std::max(file.size, end);
        if (bytesWrittenAddress) {
            memory->writed(bytesWrittenAddress, requested);
        }
        return true;
    }

    bool guestFileSize(U32 handle, U64& size) {
        auto found = guestFiles.find(handle);
        if (found == guestFiles.end()) {
            setLastError(6);
            return false;
        }
        size = found->second.size;
        return true;
    }

    bool setGuestFilePointer(U32 handle, S64 distance, U32 method, U64& position) {
        auto found = guestFiles.find(handle);
        if (found == guestFiles.end() || method > 2) {
            setLastError(found == guestFiles.end() ? 6 : 87);
            return false;
        }
        GuestFile& file = found->second;
        S64 origin = method == 0
            ? 0
            : (method == 1 ? static_cast<S64>(file.position) : static_cast<S64>(file.size));
        if ((distance < 0 && origin < -distance) ||
            (distance > 0 && origin > std::numeric_limits<S64>::max() - distance)) {
            setLastError(131);
            return false;
        }
        S64 result = origin + distance;
        if (result < 0) {
            setLastError(131);
            return false;
        }
        file.position = static_cast<U64>(result);
        position = file.position;
        return true;
    }

    bool setGuestEndOfFile(U32 handle) {
        auto found = guestFiles.find(handle);
        if (found == guestFiles.end() || !found->second.writable || !found->second.overlay) {
            setLastError(found == guestFiles.end() ? 6 : 5);
            return false;
        }
        GuestFile& file = found->second;
        file.overlay->bytes.resize(static_cast<std::size_t>(file.position), 0);
        file.size = file.position;
        return true;
    }

    bool closeGuestFile(U32 handle) {
        auto file = guestFiles.find(handle);
        if (file != guestFiles.end()) {
            guestFiles.erase(file);
            return true;
        }
        return false;
    }

    GuestCFile* findGuestCFile(U32 stream) {
        auto found = guestCFiles.find(stream);
        return found == guestCFiles.end()
            ? nullptr
            : &found->second;
    }

    U32 createGuestCFileObject(
        U32 guestFileHandle,
        S32 standardIndex) {
        U32 object = allocateGuestHeap(64, true);
        U32 lock = allocateGuestHeap(24, true);
        if (!object || !lock) {
            if (object) {
                freeGuestHeap(object);
            }
            if (lock) {
                freeGuestHeap(lock);
            }
            if (guestFileHandle) {
                closeGuestFile(guestFileHandle);
            }
            return 0;
        }
        initializeCriticalSection(lock, 0);
        GuestCFile stream;
        stream.guestFileHandle = guestFileHandle;
        stream.objectAddress = object;
        stream.lockAddress = lock;
        stream.standardIndex = standardIndex;
        guestCFiles[object] = stream;
        memory->writed(object + 12, guestFileHandle);
        return object;
    }

    U32 openGuestCFile(
        const std::string& guestPath,
        const std::string& mode) {
        if (guestPath.empty() || mode.empty()) {
            setLastError(87);
            return 0;
        }
        bool update = mode.find('+') != std::string::npos;
        bool exclusive = mode.find('x') != std::string::npos;
        bool append = mode[0] == 'a';
        U32 desiredAccess = 0;
        U32 disposition = 0;
        switch (mode[0]) {
        case 'r':
            desiredAccess =
                0x80000000 | (update ? 0x40000000 : 0);
            disposition = 3; // OPEN_EXISTING
            break;
        case 'w':
            desiredAccess =
                0x40000000 | (update ? 0x80000000 : 0);
            disposition = exclusive ? 1 : 2;
            break;
        case 'a':
            desiredAccess =
                0x40000000 | (update ? 0x80000000 : 0);
            disposition = exclusive ? 1 : 4;
            break;
        default:
            setLastError(87);
            return 0;
        }
        U32 handle = createGuestFile(
            guestPath,
            desiredAccess,
            disposition);
        if (handle == 0xffffffff) {
            return 0;
        }
        if (append) {
            U64 position = 0;
            if (!setGuestFilePointer(handle, 0, 2, position)) {
                closeGuestFile(handle);
                return 0;
            }
        }
        U32 stream = createGuestCFileObject(handle, -1);
        if (stream) {
            printf(
                "Sugarbomb UCRT file: fopen(%s, %s) -> 0x%08X\n",
                guestPath.c_str(),
                mode.c_str(),
                stream);
        }
        return stream;
    }

    U32 standardGuestCFile(U32 index) {
        if (index >= 3) {
            setLastError(87);
            return 0;
        }
        if (!standardCFiles[index]) {
            standardCFiles[index] =
                createGuestCFileObject(
                    0,
                    static_cast<S32>(index));
        }
        return standardCFiles[index];
    }

    U32 readGuestCFile(
        GuestCFile& stream,
        U32 destination,
        U32 requested) {
        if (!requested) {
            return 0;
        }
        if (!destination ||
            !memory->canWrite(destination, requested) ||
            stream.standardIndex >= 0) {
            stream.endOfFile = true;
            return 0;
        }
        U32 total = 0;
        if (stream.ungot >= 0) {
            memory->writeb(
                destination,
                static_cast<U8>(stream.ungot));
            stream.ungot = -1;
            ++total;
        }
        auto file =
            guestFiles.find(stream.guestFileHandle);
        if (file == guestFiles.end()) {
            stream.error = true;
            return total;
        }
        U64 before = file->second.position;
        if (total < requested &&
            !readGuestFile(
                stream.guestFileHandle,
                destination + total,
                requested - total,
                0)) {
            stream.error = true;
            return total;
        }
        file = guestFiles.find(stream.guestFileHandle);
        if (file != guestFiles.end()) {
            total += static_cast<U32>(
                file->second.position - before);
        }
        stream.endOfFile = total < requested;
        return total;
    }

    U32 writeGuestCFile(
        GuestCFile& stream,
        U32 source,
        U32 requested) {
        if (!requested) {
            return 0;
        }
        if (!source ||
            !memory->canRead(source, requested)) {
            stream.error = true;
            return 0;
        }
        if (stream.standardIndex >= 0) {
            FILE* output =
                stream.standardIndex == 2 ? stderr : stdout;
            for (U32 index = 0; index < requested; ++index) {
                fputc(memory->readb(source + index), output);
            }
            fflush(output);
            return requested;
        }
        if (!writeGuestFile(
                stream.guestFileHandle,
                source,
                requested,
                0)) {
            stream.error = true;
            return 0;
        }
        return requested;
    }

    U32 writeHostToGuestCFile(
        GuestCFile& stream,
        const std::string& source) {
        if (source.empty()) {
            return 0;
        }
        if (stream.standardIndex >= 0) {
            FILE* output =
                stream.standardIndex == 2 ? stderr : stdout;
            std::size_t written = std::fwrite(
                source.data(),
                1,
                source.size(),
                output);
            std::fflush(output);
            if (written != source.size()) {
                stream.error = true;
            }
            return static_cast<U32>(written);
        }
        auto found = guestFiles.find(stream.guestFileHandle);
        if (found == guestFiles.end() ||
            !found->second.writable ||
            !found->second.overlay) {
            stream.error = true;
            return 0;
        }
        GuestFile& file = found->second;
        U64 end = file.position + source.size();
        if (end >
            static_cast<U64>(
                std::numeric_limits<std::size_t>::max())) {
            stream.error = true;
            return 0;
        }
        if (end > file.overlay->bytes.size()) {
            file.overlay->bytes.resize(
                static_cast<std::size_t>(end),
                0);
        }
        std::copy(
            source.begin(),
            source.end(),
            file.overlay->bytes.begin() +
                static_cast<std::size_t>(file.position));
        file.position = end;
        file.size = std::max(file.size, end);
        return static_cast<U32>(source.size());
    }

    S32 readGuestCFileByte(GuestCFile& stream) {
        if (stream.ungot >= 0) {
            S32 value = stream.ungot;
            stream.ungot = -1;
            stream.endOfFile = false;
            return value;
        }
        if (stream.standardIndex >= 0) {
            stream.endOfFile = true;
            return -1;
        }
        auto found = guestFiles.find(stream.guestFileHandle);
        if (found == guestFiles.end() ||
            !found->second.readable) {
            stream.error = true;
            return -1;
        }
        GuestFile& file = found->second;
        if (file.position >= file.size) {
            stream.endOfFile = true;
            return -1;
        }
        U8 value = 0;
        if (file.overlay) {
            value = file.overlay->bytes[
                static_cast<std::size_t>(file.position)];
        } else {
            file.input->clear();
            file.input->seekg(
                static_cast<std::streamoff>(file.position),
                std::ios::beg);
            char byte = 0;
            file.input->read(&byte, 1);
            if (file.input->gcount() != 1) {
                stream.endOfFile = true;
                return -1;
            }
            value = static_cast<U8>(byte);
        }
        ++file.position;
        stream.endOfFile = false;
        return value;
    }

    bool writeGuestCFileByte(
        GuestCFile& stream,
        U8 value) {
        if (stream.standardIndex >= 0) {
            FILE* output =
                stream.standardIndex == 2 ? stderr : stdout;
            fputc(value, output);
            return true;
        }
        auto found = guestFiles.find(stream.guestFileHandle);
        if (found == guestFiles.end() ||
            !found->second.writable ||
            !found->second.overlay) {
            stream.error = true;
            return false;
        }
        GuestFile& file = found->second;
        if (file.position >= file.overlay->bytes.size()) {
            file.overlay->bytes.resize(
                static_cast<std::size_t>(file.position) + 1,
                0);
        }
        file.overlay->bytes[
            static_cast<std::size_t>(file.position++)] = value;
        file.size = std::max(file.size, file.position);
        return true;
    }

    bool closeGuestCFile(U32 streamAddress) {
        auto found = guestCFiles.find(streamAddress);
        if (found == guestCFiles.end()) {
            return false;
        }
        GuestCFile stream = found->second;
        guestCFiles.erase(found);
        if (stream.standardIndex >= 0 &&
            stream.standardIndex < 3) {
            standardCFiles[stream.standardIndex] = 0;
        }
        if (stream.guestFileHandle) {
            closeGuestFile(stream.guestFileHandle);
        }
        criticalSections.erase(stream.lockAddress);
        freeGuestHeap(stream.lockAddress);
        freeGuestHeap(stream.objectAddress);
        return true;
    }

    bool writeFindData(U32 destination, const std::filesystem::path& path) {
        if (!destination || !memory->canWrite(destination, 320)) {
            setLastError(87);
            return false;
        }
        memory->memset(destination, 0, 320);
        std::error_code ec;
        bool directory = std::filesystem::is_directory(path, ec);
        memory->writed(destination, directory ? 0x10 : 0x20);
        U64 size = directory ? 0 : std::filesystem::file_size(path, ec);
        if (ec) {
            size = 0;
        }
        memory->writed(destination + 28, static_cast<U32>(size >> 32));
        memory->writed(destination + 32, static_cast<U32>(size));
        std::string name = path.filename().string();
        if (name.size() >= 260) {
            name.resize(259);
        }
        memory->strcpy(destination + 44, name.c_str());
        return true;
    }

    U32 findFirstFile(U32 patternAddress, U32 destination) {
        if (!patternAddress) {
            setLastError(87);
            return 0xffffffff;
        }
        std::filesystem::path patternPath = resolveGuestPath(readAnsi(patternAddress));
        std::filesystem::path directory = patternPath.parent_path();
        std::string pattern = patternPath.filename().string();
        FindState state;
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(directory, ec)) {
            std::string normalized = lowerAscii(entry.path().string());
            if (virtualDeletedFiles.find(normalized) == virtualDeletedFiles.end() &&
                wildcardMatch(pattern, entry.path().filename().string())) {
                state.entries.push_back(entry.path());
            }
        }
        std::sort(state.entries.begin(), state.entries.end());
        if (state.entries.empty()) {
            setLastError(2);
            return 0xffffffff;
        }
        if (!writeFindData(destination, state.entries[0])) {
            return 0xffffffff;
        }
        state.nextIndex = 1;
        U32 handle = nextGuestFindHandle++;
        findStates[handle] = std::move(state);
        return handle;
    }

    bool findNextFile(U32 handle, U32 destination) {
        auto found = findStates.find(handle);
        if (found == findStates.end()) {
            setLastError(6);
            return false;
        }
        if (found->second.nextIndex >= found->second.entries.size()) {
            setLastError(18);
            return false;
        }
        return writeFindData(
            destination,
            found->second.entries[found->second.nextIndex++]);
    }

    bool closeFindHandle(U32 handle) {
        return findStates.erase(handle) != 0;
    }

    struct IniDocument {
        bool loaded = false;
        std::unordered_map<std::string, std::unordered_map<std::string, std::string>> sections;
    };

    static std::string trimAscii(const std::string& value) {
        std::size_t first = 0;
        while (first < value.size() && std::isspace(static_cast<unsigned char>(value[first]))) {
            ++first;
        }
        std::size_t last = value.size();
        while (last > first && std::isspace(static_cast<unsigned char>(value[last - 1]))) {
            --last;
        }
        return value.substr(first, last - first);
    }

    std::filesystem::path resolveGuestPath(const std::string& guestPath) const {
        std::filesystem::path path(guestPath);
        if (path.is_relative()) {
            path = std::filesystem::path(imagePath).parent_path() / path;
        }
        return path.lexically_normal();
    }

    IniDocument& loadIniDocument(const std::string& guestPath) {
        std::filesystem::path path = resolveGuestPath(guestPath);
        std::string cacheKey = lowerAscii(path.string());
        IniDocument& document = iniDocuments[cacheKey];
        if (document.loaded) {
            return document;
        }
        document.loaded = true;
        std::ifstream input(path);
        bool opened = input.is_open();
        std::string section;
        std::string line;
        while (std::getline(input, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            std::string trimmed = trimAscii(line);
            if (trimmed.empty() || trimmed[0] == ';' || trimmed[0] == '#') {
                continue;
            }
            if (trimmed.front() == '[' && trimmed.back() == ']') {
                section = lowerAscii(trimAscii(trimmed.substr(1, trimmed.size() - 2)));
                continue;
            }
            std::size_t separator = trimmed.find('=');
            if (separator == std::string::npos) {
                continue;
            }
            std::string key = lowerAscii(trimAscii(trimmed.substr(0, separator)));
            std::string value = trimAscii(trimmed.substr(separator + 1));
            document.sections[section][key] = value;
        }
        if (!opened && profileTraceCount < 12) {
            printf("Sugarbomb Win32 profile: %s is not present; defaults remain active\n", path.string().c_str());
        }
        return document;
    }

    std::string profileValue(
        const std::string& file,
        const std::string& section,
        const std::string& key,
        const std::string& defaultValue) {
        std::string normalizedSection = lowerAscii(section);
        std::string normalizedKey = lowerAscii(key);
        std::string overrideKey =
            lowerAscii(resolveGuestPath(file).string()) + "\n" + normalizedSection + "\n" + normalizedKey;
        auto overrideValue = profileOverrides.find(overrideKey);
        if (overrideValue != profileOverrides.end()) {
            return overrideValue->second;
        }
        IniDocument& document = loadIniDocument(file);
        auto foundSection = document.sections.find(normalizedSection);
        if (foundSection == document.sections.end()) {
            return defaultValue;
        }
        auto foundValue = foundSection->second.find(normalizedKey);
        return foundValue == foundSection->second.end() ? defaultValue : foundValue->second;
    }

    U32 getPrivateProfileInt(U32 sectionAddress, U32 keyAddress, U32 defaultValue, U32 fileAddress) {
        if (!sectionAddress || !keyAddress || !fileAddress) {
            return defaultValue;
        }
        std::string section = readAnsi(sectionAddress);
        std::string key = readAnsi(keyAddress);
        std::string file = readAnsi(fileAddress);
        std::string value = profileValue(file, section, key, std::to_string(defaultValue));
        char* end = nullptr;
        long parsed = std::strtol(value.c_str(), &end, 0);
        U32 result = end == value.c_str() ? defaultValue : static_cast<U32>(parsed);
        if (++profileTraceCount <= 12) {
            printf(
                "Sugarbomb Win32 profile: [%s] %s=%u from %s\n",
                section.c_str(),
                key.c_str(),
                result,
                file.c_str());
        }
        return result;
    }

    U32 copyProfileResult(U32 destination, U32 capacity, const std::string& value) {
        if (!destination || !capacity) {
            return 0;
        }
        U32 copied = std::min<U32>(static_cast<U32>(value.size()), capacity - 1);
        if (copied) {
            memory->memcpy(destination, value.data(), copied);
        }
        memory->writeb(destination + copied, 0);
        return copied;
    }

    U32 getPrivateProfileString(
        U32 sectionAddress,
        U32 keyAddress,
        U32 defaultAddress,
        U32 destination,
        U32 capacity,
        U32 fileAddress) {
        if (!destination || !capacity || !fileAddress) {
            return 0;
        }
        std::string file = readAnsi(fileAddress);
        if (!sectionAddress || !keyAddress) {
            memory->writeb(destination, 0);
            if (capacity > 1) {
                memory->writeb(destination + 1, 0);
            }
            return 0;
        }
        std::string section = readAnsi(sectionAddress);
        std::string key = readAnsi(keyAddress);
        std::string fallback = defaultAddress ? readAnsi(defaultAddress) : "";
        std::string value = profileValue(file, section, key, fallback);
        if (++profileTraceCount <= 12) {
            printf(
                "Sugarbomb Win32 profile: [%s] %s=%s from %s\n",
                section.c_str(),
                key.c_str(),
                value.c_str(),
                file.c_str());
        }
        return copyProfileResult(destination, capacity, value);
    }

    bool writePrivateProfileString(
        U32 sectionAddress,
        U32 keyAddress,
        U32 valueAddress,
        U32 fileAddress) {
        if (!sectionAddress || !keyAddress || !fileAddress) {
            setLastError(87);
            return false;
        }
        std::string file = readAnsi(fileAddress);
        std::string overrideKey =
            lowerAscii(resolveGuestPath(file).string()) + "\n" +
            lowerAscii(readAnsi(sectionAddress)) + "\n" +
            lowerAscii(readAnsi(keyAddress));
        if (valueAddress) {
            profileOverrides[overrideKey] = readAnsi(valueAddress);
        } else {
            profileOverrides.erase(overrideKey);
        }
        return true;
    }

    U32 getCurrentDirectory(U32 capacity, U32 destination) {
        std::string directory = std::filesystem::path(imagePath).parent_path().string();
        if (!capacity || capacity <= directory.size()) {
            return static_cast<U32>(directory.size() + 1);
        }
        if (!destination || !memory->canWrite(destination, static_cast<U32>(directory.size() + 1))) {
            setLastError(87);
            return 0;
        }
        memory->strcpy(destination, directory.c_str());
        return static_cast<U32>(directory.size());
    }

    U32 commandLineToArgv(U32 commandLineAddress, U32 countAddress) {
        if (!commandLineAddress || !countAddress || !memory->canWrite(countAddress, 4)) {
            setLastError(87);
            return 0;
        }
        std::string command = readWide(commandLineAddress, 32768);
        std::vector<std::string> arguments;
        std::string currentArgument;
        bool quoted = false;
        for (std::size_t index = 0; index <= command.size(); ++index) {
            char value = index < command.size() ? command[index] : '\0';
            if (value == '"') {
                quoted = !quoted;
            } else if (!value || (!quoted && std::isspace(static_cast<unsigned char>(value)))) {
                if (!currentArgument.empty()) {
                    arguments.push_back(currentArgument);
                    currentArgument.clear();
                }
                if (!value) {
                    break;
                }
            } else {
                currentArgument.push_back(value);
            }
        }
        if (arguments.empty()) {
            arguments.push_back(imagePath);
        }
        U32 pointerBytes = static_cast<U32>((arguments.size() + 1) * 4);
        U32 stringBytes = 0;
        for (const std::string& argumentValue : arguments) {
            stringBytes += static_cast<U32>((argumentValue.size() + 1) * 2);
        }
        U32 allocation = allocateGuestHeap(pointerBytes + stringBytes, true);
        if (!allocation) {
            return 0;
        }
        U32 stringAddress = allocation + pointerBytes;
        for (U32 index = 0; index < arguments.size(); ++index) {
            memory->writed(allocation + index * 4, stringAddress);
            for (U32 character = 0; character < arguments[index].size(); ++character) {
                memory->writew(stringAddress + character * 2, arguments[index][character]);
            }
            memory->writew(stringAddress + static_cast<U32>(arguments[index].size()) * 2, 0);
            stringAddress += static_cast<U32>((arguments[index].size() + 1) * 2);
        }
        memory->writed(countAddress, static_cast<U32>(arguments.size()));
        return allocation;
    }

    bool createDirectory(const std::string& guestPath) {
        if (guestPath.empty()) {
            setLastError(87);
            return false;
        }
        std::filesystem::path path =
            resolveGuestPath(guestPath);
        std::string normalized =
            lowerAscii(path.string());
        if (virtualDirectories.find(normalized) !=
                virtualDirectories.end() ||
            std::filesystem::is_directory(path)) {
            setLastError(183); // ERROR_ALREADY_EXISTS
            return false;
        }
        virtualDirectories.insert(normalized);
        printf(
            "Sugarbomb Win32 directory overlay: "
            "CreateDirectory(%s)\n",
            path.string().c_str());
        return true;
    }

    bool deleteFile(const std::string& guestPath) {
        if (guestPath.empty()) {
            setLastError(87);
            return false;
        }
        std::filesystem::path path =
            resolveGuestPath(guestPath);
        std::string normalized = lowerAscii(path.string());
        bool exists =
            virtualFileContents.find(normalized) != virtualFileContents.end() ||
            (std::filesystem::is_regular_file(path) &&
             virtualDeletedFiles.find(normalized) == virtualDeletedFiles.end());
        if (!exists) {
            setLastError(2);
            return false;
        }
        virtualFileContents.erase(normalized);
        virtualDeletedFiles.insert(normalized);
        printf("Sugarbomb Win32 file overlay: DeleteFileA(%s)\n", path.string().c_str());
        return true;
    }

    U32 getFileAttributes(const std::string& guestPath) {
        if (guestPath.empty()) {
            setLastError(87);
            return 0xffffffff;
        }
        std::filesystem::path path =
            resolveGuestPath(guestPath);
        std::string normalized = lowerAscii(path.string());
        U32 attributes = 0xffffffff;
        if (virtualDirectories.find(normalized) != virtualDirectories.end() ||
            std::filesystem::is_directory(path)) {
            attributes = 0x10;
        } else if (virtualDeletedFiles.find(normalized) == virtualDeletedFiles.end() &&
                   (virtualFileContents.find(normalized) != virtualFileContents.end() ||
                    std::filesystem::is_regular_file(path))) {
            attributes = 0x20;
        } else {
            setLastError(2);
        }
        if (++fileAttributeTraceCount <= 16) {
            printf(
                "Sugarbomb Win32 file: GetFileAttributes(%s) -> 0x%08X\n",
                path.string().c_str(),
                attributes);
        }
        return attributes;
    }

    bool writeFileAttributesEx(
        const std::string& guestPath,
        U32 destination) {
        if (!destination ||
            !memory->canWrite(destination, 36)) {
            setLastError(87);
            return false;
        }
        U32 attributes = getFileAttributes(guestPath);
        if (attributes == 0xffffffff) {
            return false;
        }
        std::filesystem::path path =
            resolveGuestPath(guestPath);
        std::string normalized =
            lowerAscii(path.string());
        U64 size = 0;
        auto overlay =
            virtualFileContents.find(normalized);
        if (overlay != virtualFileContents.end()) {
            size = overlay->second->bytes.size();
        } else if (attributes != 0x10) {
            std::error_code fileError;
            size = std::filesystem::file_size(
                path,
                fileError);
            if (fileError) {
                size = 0;
            }
        }
        memory->memset(destination, 0, 36);
        memory->writed(destination, attributes);
        memory->writed(
            destination + 28,
            static_cast<U32>(size >> 32));
        memory->writed(
            destination + 32,
            static_cast<U32>(size));
        return true;
    }

    struct HeapAllocation {
        U32 requestedSize = 0;
        U32 mappedSize = 0;
    };

    static U16 asciiCharacterType(U16 character) {
        U16 type = 0;
        if (character >= 'A' && character <= 'Z') {
            type |= 0x0001 | 0x0100;
        }
        if (character >= 'a' && character <= 'z') {
            type |= 0x0002 | 0x0100;
        }
        if (character >= '0' && character <= '9') {
            type |= 0x0004;
        }
        if (character == ' ' || (character >= 9 && character <= 13)) {
            type |= 0x0008;
        }
        if (character == ' ' || character == '\t') {
            type |= 0x0040;
        }
        if (character < 0x20 || character == 0x7f) {
            type |= 0x0020;
        }
        if ((character >= '!' && character <= '/') ||
            (character >= ':' && character <= '@') ||
            (character >= '[' && character <= '`') ||
            (character >= '{' && character <= '~')) {
            type |= 0x0010;
        }
        if ((character >= '0' && character <= '9') ||
            (character >= 'A' && character <= 'F') ||
            (character >= 'a' && character <= 'f')) {
            type |= 0x0080;
        }
        return type;
    }

    U32 mapWideString(U32 flags, U32 source, S32 requestedCharacters, U32 destination, U32 capacity) {
        if (!source || !requestedCharacters) {
            setLastError(87);
            return 0;
        }
        U32 characters = requestedCharacters < 0
            ? static_cast<U32>(readWide(source).size()) + 1
            : static_cast<U32>(requestedCharacters);
        if (!destination || !capacity) {
            return characters;
        }
        if (capacity < characters) {
            setLastError(122);
            return 0;
        }
        for (U32 index = 0; index < characters; ++index) {
            U16 value = memory->readw(source + index * 2);
            if ((flags & 0x00000100) && value >= 'A' && value <= 'Z') {
                value += 'a' - 'A';
            } else if ((flags & 0x00000200) && value >= 'a' && value <= 'z') {
                value -= 'a' - 'A';
            }
            memory->writew(destination + index * 2, value);
        }
        return characters;
    }

    U32 mapAnsiString(U32 flags, U32 source, S32 requestedBytes, U32 destination, U32 capacity) {
        if (!source || !requestedBytes) {
            setLastError(87);
            return 0;
        }
        U32 characters = requestedBytes < 0
            ? static_cast<U32>(readAnsi(source).size()) + 1
            : static_cast<U32>(requestedBytes);
        if (!destination || !capacity) {
            return characters;
        }
        if (capacity < characters) {
            setLastError(122);
            return 0;
        }
        for (U32 index = 0; index < characters; ++index) {
            U8 value = memory->readb(source + index);
            if ((flags & 0x00000100) && value >= 'A' && value <= 'Z') {
                value += 'a' - 'A';
            } else if ((flags & 0x00000200) && value >= 'a' && value <= 'z') {
                value -= 'a' - 'A';
            }
            memory->writeb(destination + index, value);
        }
        return characters;
    }

    struct CriticalSectionState {
        U32 ownerThread = 0;
        U32 recursionCount = 0;
        U32 spinCount = 0;
    };

    struct SlimReaderWriterLockState {
        U32 exclusiveOwner = 0;
        U32 sharedCount = 0;
    };

    struct VirtualRegion {
        U32 base = 0;
        U32 size = 0;
        U32 allocationProtection = 0;
        U32 protection = 0;
        U32 state = 0;
        std::vector<std::pair<U32, U32>> committedRanges;
    };

    std::string readGuestWindowIdentifier(U32 value) {
        if (!value) {
            return "";
        }
        if (value <= 0xffff) {
            return "#" + std::to_string(value);
        }
        return readAnsi(value);
    }

    void writeAnsiBounded(U32 destination, U32 capacity, const std::string& value) {
        if (!capacity || !memory->canWrite(destination, capacity)) {
            return;
        }
        U32 length = std::min<U32>(static_cast<U32>(value.size()), capacity - 1);
        for (U32 index = 0; index < length; ++index) {
            memory->writeb(destination + index, value[index]);
        }
        memory->writeb(destination + length, 0);
    }

    void enqueueGuestMessage(
        U32 window,
        U32 message,
        U32 wordParameter = 0,
        U32 longParameter = 0,
        U32 time = 0,
        S32 pointX = 0,
        S32 pointY = 0) {
        U32 threadId = currentGuestThreadId();
        if (window) {
            auto found = guestWindows.find(window);
            if (found == guestWindows.end()) {
                return;
            }
            threadId = found->second.ownerThreadId;
        }
        GuestMessage queued;
        queued.threadId = threadId;
        queued.window = window;
        queued.message = message;
        queued.wordParameter = wordParameter;
        queued.longParameter = longParameter;
        queued.time = time ? time : KSystem::getMilliesSinceStart();
        queued.pointX = pointX;
        queued.pointY = pointY;

        constexpr U32 WM_MOUSEMOVE_GUEST = 0x0200;
        if (message == WM_MOUSEMOVE_GUEST && !guestMessageQueue.empty()) {
            GuestMessage& previous = guestMessageQueue.back();
            if (previous.threadId == queued.threadId &&
                previous.window == queued.window &&
                previous.message == queued.message) {
                previous = queued;
                return;
            }
        }
        constexpr std::size_t MAX_QUEUED_GUEST_MESSAGES = 4096;
        if (guestMessageQueue.size() >= MAX_QUEUED_GUEST_MESSAGES) {
            guestMessageQueue.pop_front();
        }
        guestMessageQueue.push_back(queued);
    }

    void queueGuestWindowSize(U32 handle) {
        auto found = guestWindows.find(handle);
        if (found == guestWindows.end()) {
            return;
        }
        U32 width = static_cast<U32>(
            std::min<S32>(0xffff, std::max<S32>(0, found->second.width)));
        U32 height = static_cast<U32>(
            std::min<S32>(0xffff, std::max<S32>(0, found->second.height)));
        enqueueGuestMessage(
            handle,
            0x0005, // WM_SIZE
            0, // SIZE_RESTORED
            width | (height << 16));
    }

    bool isGuestChildWindow(const GuestWindow& window) const {
        return window.parent != 0 ||
            (window.style & 0x40000000) != 0; // WS_CHILD
    }

    U32 topLevelGuestWindow(U32 handle) const {
        U32 currentHandle = handle;
        for (U32 depth = 0; currentHandle && depth < 32; ++depth) {
            auto found = guestWindows.find(currentHandle);
            if (found == guestWindows.end()) {
                return 0;
            }
            if (!found->second.parent) {
                return currentHandle;
            }
            currentHandle = found->second.parent;
        }
        return 0;
    }

    void queueGuestWindowVisibility(U32 handle, bool visible) {
        auto found = guestWindows.find(handle);
        if (found == guestWindows.end()) {
            return;
        }
        bool childWindow = isGuestChildWindow(found->second);
        bool synthesizeActivation =
            !childWindow && !hostWindow.nativeHandle();
        if (visible) {
            enqueueGuestMessage(handle, 0x0018, 1, 0); // WM_SHOWWINDOW
            if (synthesizeActivation) {
                enqueueGuestMessage(handle, 0x001c, 1, 0); // WM_ACTIVATEAPP
                enqueueGuestMessage(handle, 0x0006, 1, 0); // WM_ACTIVATE / WA_ACTIVE
                enqueueGuestMessage(handle, 0x0007, 0, 0); // WM_SETFOCUS
            }
            queueGuestWindowSize(handle);
            enqueueGuestMessage(handle, 0x000f, 0, 0); // WM_PAINT
        } else {
            if (synthesizeActivation) {
                enqueueGuestMessage(handle, 0x0008, 0, 0); // WM_KILLFOCUS
                enqueueGuestMessage(handle, 0x0006, 0, 0); // WM_ACTIVATE / WA_INACTIVE
                enqueueGuestMessage(handle, 0x001c, 0, 0); // WM_ACTIVATEAPP
            }
            enqueueGuestMessage(handle, 0x0018, 0, 0); // WM_SHOWWINDOW
        }
    }

    bool guestMessageMatches(
        const GuestMessage& message,
        U32 threadId,
        U32 windowFilter,
        U32 minimumMessage,
        U32 maximumMessage) const {
        if (message.threadId != threadId) {
            return false;
        }
        if (windowFilter == 0xffffffff) {
            if (message.window) {
                return false;
            }
        } else if (windowFilter && message.window != windowFilter) {
            return false;
        }
        return (!minimumMessage && !maximumMessage) ||
            (message.message >= minimumMessage &&
             message.message <= maximumMessage);
    }

    void writeGuestMessage(U32 destination, const GuestMessage& message) {
        memory->writed(destination, message.window);
        memory->writed(destination + 4, message.message);
        memory->writed(destination + 8, message.wordParameter);
        memory->writed(destination + 12, message.longParameter);
        memory->writed(destination + 16, message.time);
        memory->writed(destination + 20, static_cast<U32>(message.pointX));
        memory->writed(destination + 24, static_cast<U32>(message.pointY));
    }

    bool peekGuestMessage(
        CPU* guestCpu,
        U32 destination,
        U32 windowFilter,
        U32 minimumMessage,
        U32 maximumMessage,
        U32 removeFlags) {
        if (!destination || !memory->canWrite(destination, 28)) {
            setLastError(87);
            return false;
        }
        pumpHostMessages();
        U32 threadId = guestCpu->thread->id;
        auto found = std::find_if(
            guestMessageQueue.begin(),
            guestMessageQueue.end(),
            [&](const GuestMessage& message) {
                return guestMessageMatches(
                    message,
                    threadId,
                    windowFilter,
                    minimumMessage,
                    maximumMessage);
            });
        if (found == guestMessageQueue.end()) {
            memory->memset(destination, 0, 28);
            return false;
        }
        GuestMessage message = *found;
        writeGuestMessage(destination, message);
        if (removeFlags & 0x0001) { // PM_REMOVE
            guestMessageQueue.erase(found);
        }
        if (++guestMessageTraceCount <= 32) {
            printf(
                "Sugarbomb Win32 USER32: PeekMessageA -> "
                "HWND 0x%08X, message 0x%04X%s\n",
                message.window,
                message.message,
                (removeFlags & 0x0001) ? " (removed)" : "");
        }
        return true;
    }

    bool dispatchGuestMessage(CPU* guestCpu, U32 messageAddress) {
        if (!messageAddress || !memory->canRead(messageAddress, 28)) {
            setLastError(87);
            guestCpu->reg[0].u32 = 0;
            return false;
        }
        return dispatchGuestWindowProcedure(
            guestCpu,
            memory->readd(messageAddress),
            memory->readd(messageAddress + 4),
            memory->readd(messageAddress + 8),
            memory->readd(messageAddress + 12));
    }

    bool dispatchGuestWindowProcedure(
        CPU* guestCpu,
        U32 window,
        U32 message,
        U32 wordParameter,
        U32 longParameter) {
        guestCpu->reg[0].u32 = 0;
        auto found = guestWindows.find(window);
        if (found == guestWindows.end()) {
            if (window) {
                setLastError(1400);
            }
            return false;
        }
        const GuestWindowClass* windowClass =
            findGuestWindowClass(found->second.className);
        if (!windowClass || !windowClass->windowProcedure) {
            return false;
        }

        U32 originalStackPointer = guestCpu->reg[4].u32;
        U32 frameStackPointer =
            (originalStackPointer & guestCpu->stackNotMask) |
            ((originalStackPointer - 20) & guestCpu->stackMask);
        U32 frameAddress =
            guestCpu->seg[SS].address +
            (frameStackPointer & guestCpu->stackMask);
        if (!memory->canWrite(frameAddress, 20)) {
            setLastError(8);
            return false;
        }

        PendingWndProcDispatch pending;
        pending.nativeThunkStackPointer = originalStackPointer;
        pending.nativeThunkResumeEip = guestCpu->eip.u32 + 2;
        pending.window = window;
        pending.message = message;
        pendingWndProcDispatches[guestCpu->thread->id].push_back(pending);

        guestCpu->push32(longParameter);
        guestCpu->push32(wordParameter);
        guestCpu->push32(message);
        guestCpu->push32(window);
        guestCpu->push32(wndProcReturnThunk);
        guestCpu->eip.u32 = windowClass->windowProcedure;
        guestCpu->nextOp = nullptr;
        if (++wndProcDispatchTraceCount <= 32) {
            printf(
                "Sugarbomb Win32 USER32: dispatch message 0x%04X "
                "to guest WndProc 0x%08X for HWND 0x%08X\n",
                message,
                windowClass->windowProcedure,
                window);
        }
        return true;
    }

    void completeGuestWndProcDispatch(CPU* guestCpu) {
        U32 threadId = guestCpu->thread->id;
        auto found = pendingWndProcDispatches.find(threadId);
        if (found == pendingWndProcDispatches.end() ||
            found->second.empty()) {
            fprintf(
                stderr,
                "Sugarbomb Win32 USER32: guest WndProc return "
                "without a pending dispatch on thread %u\n",
                threadId);
            guestCpu->thread->terminating = true;
            runtimeStopping = true;
            return;
        }
        PendingWndProcDispatch pending = found->second.back();
        found->second.pop_back();
        if (found->second.empty()) {
            pendingWndProcDispatches.erase(found);
        }
        U32 result = guestCpu->reg[0].u32;
        guestCpu->reg[4].u32 = pending.nativeThunkStackPointer;
        guestCpu->eip.u32 = pending.nativeThunkResumeEip;
        guestCpu->nextOp = nullptr;
        if (wndProcDispatchTraceCount <= 32) {
            printf(
                "Sugarbomb Win32 USER32: guest WndProc returned "
                "0x%08X for message 0x%04X\n",
                result,
                pending.message);
        }
    }

    U32 registerGuestWindowClass(U32 classAddress) {
        if (!classAddress || !memory->canRead(classAddress, 40)) {
            setLastError(87);
            return 0;
        }
        GuestWindowClass windowClass;
        windowClass.style = memory->readd(classAddress);
        windowClass.windowProcedure = memory->readd(classAddress + 4);
        windowClass.instance = memory->readd(classAddress + 16);
        windowClass.icon = memory->readd(classAddress + 20);
        windowClass.cursor = memory->readd(classAddress + 24);
        windowClass.background = memory->readd(classAddress + 28);
        windowClass.name = readGuestWindowIdentifier(memory->readd(classAddress + 36));
        if (windowClass.name.empty()) {
            setLastError(87);
            return 0;
        }

        std::string key = lowerAscii(windowClass.name);
        auto existing = guestWindowClasses.find(key);
        if (existing != guestWindowClasses.end()) {
            setLastError(1410); // ERROR_CLASS_ALREADY_EXISTS
            return 0;
        }
        windowClass.atom = nextWindowAtom++;
        U32 atom = windowClass.atom;
        guestWindowClasses[key] = windowClass;
        printf(
            "Sugarbomb Win32 USER32: RegisterClassA(%s, wndproc=0x%08X) -> atom %u\n",
            windowClass.name.c_str(),
            windowClass.windowProcedure,
            atom);
        return atom;
    }

    const GuestWindowClass* findGuestWindowClass(const std::string& identifier) const {
        if (!identifier.empty() && identifier[0] == '#') {
            U32 atom = static_cast<U32>(std::strtoul(identifier.c_str() + 1, nullptr, 10));
            for (const auto& entry : guestWindowClasses) {
                if (entry.second.atom == atom) {
                    return &entry.second;
                }
            }
            return nullptr;
        }
        auto found = guestWindowClasses.find(lowerAscii(identifier));
        return found == guestWindowClasses.end() ? nullptr : &found->second;
    }

    U32 createGuestWindow(
        U32 extendedStyle,
        U32 classIdentifier,
        U32 titleAddress,
        U32 style,
        S32 x,
        S32 y,
        S32 width,
        S32 height,
        U32 parent,
        U32 instance) {
        std::string className = readGuestWindowIdentifier(classIdentifier);
        const GuestWindowClass* windowClass = findGuestWindowClass(className);
        if (!windowClass) {
            setLastError(1407); // ERROR_CANNOT_FIND_WND_CLASS
            return 0;
        }

        GuestWindow window;
        window.handle = nextWindowHandle++;
        window.ownerThreadId = currentGuestThreadId();
        window.extendedStyle = extendedStyle;
        window.style = style;
        window.instance = instance ? instance : windowClass->instance;
        window.parent = parent;
        window.x = x == static_cast<S32>(0x80000000) ? 0 : x;
        window.y = y == static_cast<S32>(0x80000000) ? 0 : y;
        window.width = width <= 0 || width == static_cast<S32>(0x80000000) ? 1280 : width;
        window.height = height <= 0 || height == static_cast<S32>(0x80000000) ? 720 : height;
        window.visible = (style & 0x10000000) != 0; // WS_VISIBLE
        window.className = windowClass->name;
        window.title = titleAddress ? readAnsi(titleAddress) : "";
        U32 handle = window.handle;
        guestWindows[handle] = window;
        syncHostWindow(guestWindows[handle]);
        if (!isGuestChildWindow(window) &&
            !hostWindow.nativeHandle()) {
            activeWindow = handle;
        }
        if (window.visible) {
            queueGuestWindowVisibility(handle, true);
        } else {
            queueGuestWindowSize(handle);
        }
        printf(
            "Sugarbomb Win32 USER32: CreateWindowExA("
            "%s, %s, style=0x%08X, parent=0x%08X, "
            "%dx%d, visible=%u) -> 0x%08X\n",
            window.className.c_str(),
            window.title.c_str(),
            window.style,
            window.parent,
            window.width,
            window.height,
            window.visible ? 1 : 0,
            handle);
        return handle;
    }

    bool destroyGuestWindow(U32 handle) {
        auto found = guestWindows.find(handle);
        if (found == guestWindows.end()) {
            setLastError(1400); // ERROR_INVALID_WINDOW_HANDLE
            return false;
        }
        destroyHostWindowForGuest(handle);
        guestWindows.erase(found);
        if (activeWindow == handle) {
            activeWindow = 0;
        }
        return true;
    }

    bool showGuestWindow(U32 handle, U32 command) {
        auto found = guestWindows.find(handle);
        if (found == guestWindows.end()) {
            setLastError(1400);
            return false;
        }
        bool wasVisible = found->second.visible;
        found->second.visible = command != 0;
        syncHostWindow(found->second);
        if (found->second.visible &&
            !isGuestChildWindow(found->second) &&
            !hostWindow.nativeHandle()) {
            activeWindow = handle;
        }
        if (wasVisible != found->second.visible) {
            queueGuestWindowVisibility(handle, found->second.visible);
        }
        return wasVisible;
    }

    bool updateGuestWindow(U32 handle) {
        if (!guestWindows.count(handle)) {
            setLastError(1400);
            return false;
        }
        enqueueGuestMessage(handle, 0x000f, 0, 0); // WM_PAINT
        return true;
    }

    U32 guestWindowWithNativeState(
        NativeWindowState state) const {
        U32 topLevel = topLevelGuestWindow(activeWindow);
        if (!hostWindow.nativeHandle()) {
            return topLevel;
        }
        if (!topLevel) {
            return 0;
        }
        bool ownsState = false;
        switch (state) {
        case NativeWindowState::Active:
            ownsState =
                hostWindow.isGuestWindowActive(topLevel);
            break;
        case NativeWindowState::Focused:
            ownsState =
                hostWindow.isGuestWindowFocused(topLevel);
            break;
        case NativeWindowState::Foreground:
            ownsState =
                hostWindow.isGuestWindowForeground(topLevel);
            break;
        }
        return ownsState ? topLevel : 0;
    }

    bool setActiveGuestWindow(U32 handle) {
        if (!handle) {
            if (hostWindow.nativeHandle()) {
                return hostWindow.setActiveGuestWindow(0);
            }
            activeWindow = 0;
            return true;
        }
        U32 topLevel = topLevelGuestWindow(handle);
        if (!topLevel || !guestWindows.count(topLevel)) {
            setLastError(1400);
            return false;
        }
        if (hostWindow.nativeHandle()) {
            return hostWindow.setActiveGuestWindow(topLevel);
        }
        return activateGuestWindow(topLevel);
    }

    bool focusGuestWindow(U32 handle) {
        if (!handle) {
            if (hostWindow.nativeHandle()) {
                return hostWindow.focusGuestWindow(0);
            }
            activeWindow = 0;
            return true;
        }
        U32 topLevel = topLevelGuestWindow(handle);
        if (!topLevel || !guestWindows.count(topLevel)) {
            setLastError(1400);
            return false;
        }
        if (hostWindow.nativeHandle()) {
            return hostWindow.focusGuestWindow(topLevel);
        }
        return activateGuestWindow(topLevel);
    }

    bool activateGuestWindow(U32 handle) {
        U32 topLevel = topLevelGuestWindow(handle);
        auto found = guestWindows.find(topLevel);
        if (found == guestWindows.end()) {
            setLastError(1400);
            return false;
        }
        handle = topLevel;
        if (hostWindow.nativeHandle()) {
            return hostWindow.activateGuestWindow(handle);
        }
        U32 previous = activeWindow;
        if (previous && previous != handle && guestWindows.count(previous)) {
            enqueueGuestMessage(previous, 0x0008, handle, 0); // WM_KILLFOCUS
            enqueueGuestMessage(previous, 0x0006, 0, handle); // WA_INACTIVE
        }
        activeWindow = handle;
        if (previous != handle) {
            enqueueGuestMessage(handle, 0x001c, 1, 0); // WM_ACTIVATEAPP
            enqueueGuestMessage(handle, 0x0006, 1, previous); // WA_ACTIVE
            enqueueGuestMessage(handle, 0x0007, previous, 0); // WM_SETFOCUS
        }
        return true;
    }

    bool writeGuestClientRect(U32 handle, U32 rectangle) {
        auto found = guestWindows.find(handle);
        if (found == guestWindows.end() || !rectangle || !memory->canWrite(rectangle, 16)) {
            setLastError(found == guestWindows.end() ? 1400 : 87);
            return false;
        }
        memory->writed(rectangle, 0);
        memory->writed(rectangle + 4, 0);
        memory->writed(rectangle + 8, static_cast<U32>(found->second.width));
        memory->writed(rectangle + 12, static_cast<U32>(found->second.height));
        return true;
    }

    bool setGuestWindowPosition(
        U32 handle,
        S32 x,
        S32 y,
        S32 width,
        S32 height,
        U32 flags) {
        auto found = guestWindows.find(handle);
        if (found == guestWindows.end()) {
            setLastError(1400);
            return false;
        }
        S32 previousWidth = found->second.width;
        S32 previousHeight = found->second.height;
        bool wasVisible = found->second.visible;
        if (!(flags & 0x0002)) { // SWP_NOMOVE
            found->second.x = x;
            found->second.y = y;
        }
        if (!(flags & 0x0001)) { // SWP_NOSIZE
            found->second.width = std::max<S32>(1, width);
            found->second.height = std::max<S32>(1, height);
        }
        if (flags & 0x0040) { // SWP_SHOWWINDOW
            found->second.visible = true;
        }
        if (flags & 0x0080) { // SWP_HIDEWINDOW
            found->second.visible = false;
        }
        syncHostWindow(found->second);
        if (previousWidth != found->second.width ||
            previousHeight != found->second.height) {
            queueGuestWindowSize(handle);
        }
        if (wasVisible != found->second.visible) {
            if (found->second.visible &&
                !isGuestChildWindow(found->second) &&
                !hostWindow.nativeHandle()) {
                activeWindow = handle;
            }
            queueGuestWindowVisibility(handle, found->second.visible);
        }
        return true;
    }

    U32 findGuestWindow(const std::string& className, const std::string& title) const {
        for (const auto& entry : guestWindows) {
            const GuestWindow& window = entry.second;
            if ((!className.empty() && lowerAscii(window.className) != lowerAscii(className)) ||
                (!title.empty() && window.title != title)) {
                continue;
            }
            return entry.first;
        }
        return 0;
    }

    bool setGuestWindowText(U32 handle, U32 textAddress) {
        auto found = guestWindows.find(handle);
        if (found == guestWindows.end()) {
            setLastError(1400);
            return false;
        }
        found->second.title = textAddress ? readAnsi(textAddress) : "";
        syncHostWindow(found->second);
        return true;
    }

    U32 copyGuestWindowString(U32 handle, U32 destination, U32 capacity, bool className) {
        auto found = guestWindows.find(handle);
        if (found == guestWindows.end() || !destination || !capacity ||
            !memory->canWrite(destination, capacity)) {
            setLastError(found == guestWindows.end() ? 1400 : 87);
            return 0;
        }
        const std::string& value = className ? found->second.className : found->second.title;
        U32 copied = std::min<U32>(static_cast<U32>(value.size()), capacity - 1);
        writeAnsiBounded(destination, capacity, value);
        return copied;
    }

    U32 getGuestWindowLong(U32 handle, S32 index) {
        auto found = guestWindows.find(handle);
        if (found == guestWindows.end()) {
            setLastError(1400);
            return 0;
        }
        const GuestWindow& window = found->second;
        const GuestWindowClass* windowClass = findGuestWindowClass(window.className);
        switch (index) {
        case -4: return windowClass ? windowClass->windowProcedure : 0; // GWL_WNDPROC
        case -6: return window.instance; // GWL_HINSTANCE
        case -8: return window.parent; // GWL_HWNDPARENT
        case -16: return window.style; // GWL_STYLE
        case -20: return window.extendedStyle; // GWL_EXSTYLE
        default: return 0;
        }
    }

    U32 getGuestClassLong(U32 handle, S32 index) {
        auto window = guestWindows.find(handle);
        if (window == guestWindows.end()) {
            setLastError(1400);
            return 0;
        }
        const GuestWindowClass* windowClass = findGuestWindowClass(window->second.className);
        if (!windowClass) {
            return 0;
        }
        switch (index) {
        case -12: return windowClass->cursor; // GCL_HCURSOR
        case -14:
        case -34: return windowClass->icon; // GCL_HICON / GCL_HICONSM
        case -10: return windowClass->background; // GCL_HBRBACKGROUND
        case -26: return windowClass->style; // GCL_STYLE
        default: return 0;
        }
    }

    bool writeGuestDisplayDevice(U32 deviceIndex, U32 destination) {
        if (deviceIndex != 0 || !destination || !memory->canRead(destination, 4)) {
            return false;
        }
        U32 size = memory->readd(destination);
        if (size < 168 || !memory->canWrite(destination, size)) {
            setLastError(87);
            return false;
        }
        memory->memset(destination, 0, size);
        memory->writed(destination, size);
        writeAnsiBounded(destination + 4, std::min<U32>(32, size - 4), "\\\\.\\DISPLAY1");
        if (size > 36) {
            writeAnsiBounded(
                destination + 36,
                std::min<U32>(128, size - 36),
                "Sugarbomb 64-bit Virtual Display");
        }
        if (size >= 168) {
            memory->writed(destination + 164, 0x00000005); // ACTIVE | PRIMARY_DEVICE
        }
        return true;
    }

    enum class KernelObjectType {
        Semaphore,
        Event,
        Mutex,
        Thread
    };

    struct KernelObject {
        KernelObjectType type = KernelObjectType::Event;
        S32 count = 0;
        S32 maximumCount = 0;
        bool manualReset = false;
        bool signaled = false;
        U32 ownerThread = 0;
        U32 recursionCount = 0;
        U32 threadId = 0;
        U32 exitCode = STILL_ACTIVE;
        std::string name;
    };

    U32 currentGuestThreadId() const {
        return activeCpu && activeCpu->thread ? activeCpu->thread->id : thread->id;
    }

    bool initializeGuestThreadCpu(
        GuestThreadState& state,
        U32 startAddress,
        U32 parameter) {
        KThread* guestThread = state.thread;
        struct user_desc teb = {};
        teb.entry_number = TLS_ENTRY_START_INDEX;
        teb.base_addr = state.tebAddress;
        teb.limit = 0xfffff;
        teb.seg_32bit = 1;
        teb.contents = 0;
        teb.read_exec_only = 0;
        teb.limit_in_pages = 1;
        teb.seg_not_present = 0;
        teb.useable = 1;
        guestThread->setTLS(&teb);

        CPU* guestCpu = guestThread->cpu;
        guestCpu->reset();
#ifdef BOXEDWINE_JIT
        // KProcess owns the generated lazy-flag helpers. CPU::reset clears the
        // per-CPU table, so a newly initialized Win32 thread must inherit it
        // before entering code blocks that another thread already compiled.
        memcpy(
            guestCpu->calculateCF,
            guestThread->process->calculateCF,
            sizeof(guestCpu->calculateCF));
#endif
        guestCpu->setSegment(CS, BOXEDWINE_VISIBLE_USER_CODE_SELECTOR);
        guestCpu->setSegment(SS, BOXEDWINE_VISIBLE_USER_DATA_SELECTOR);
        guestCpu->setSegment(DS, BOXEDWINE_VISIBLE_USER_DATA_SELECTOR);
        guestCpu->setSegment(ES, BOXEDWINE_VISIBLE_USER_DATA_SELECTOR);
        guestCpu->setSegment(FS, WINDOWS_TEB_SELECTOR);
        guestCpu->setSegment(GS, 0);

        U32 stackTop = state.stackBase + state.stackSize;
        U32 stackPointer = stackTop - 8;
        memory->writed(stackPointer, threadReturnThunk);
        memory->writed(stackPointer + 4, parameter);
        guestCpu->reg[4].u32 = stackPointer;
        guestCpu->eip.u32 = startAddress;
        guestCpu->nextOp = nullptr;
        return true;
    }

    U32 createGuestThread(
        CPU* callerCpu,
        U32 requestedStackSize,
        U32 startAddress,
        U32 parameter,
        U32 creationFlags,
        U32 threadIdAddress) {
        if (!startAddress || !memory->canRead(startAddress, 1) ||
            (threadIdAddress && !memory->canWrite(threadIdAddress, 4))) {
            setLastError(87);
            return 0;
        }

        U32 stackSize = requestedStackSize
            ? K_ROUND_UP_TO_PAGE(requestedStackSize)
            : STACK_SIZE;
        stackSize = std::max<U32>(stackSize, 0x00010000);
        if (stackSize > nextChildStackTop ||
            nextChildStackTop - stackSize < THUNK_BASE + THUNK_SIZE ||
            nextChildEnvironmentBase < CHILD_ENV_SIZE) {
            setLastError(8);
            return 0;
        }
        U32 stackBase = nextChildStackTop - stackSize;
        U32 environmentBase = nextChildEnvironmentBase;

        KThread* guestThread = process->createThread();
        if (memory->mmap(
                guestThread,
                stackBase,
                stackSize,
                K_PROT_READ | K_PROT_WRITE,
                K_MAP_FIXED | K_MAP_PRIVATE | K_MAP_ANONYMOUS,
                -1,
                0) != stackBase) {
            process->deleteThread(guestThread);
            setLastError(8);
            return 0;
        }
        if (memory->mmap(
                guestThread,
                environmentBase,
                CHILD_ENV_SIZE,
                K_PROT_READ | K_PROT_WRITE,
                K_MAP_FIXED | K_MAP_PRIVATE | K_MAP_ANONYMOUS,
                -1,
                0) != environmentBase) {
            memory->unmap(stackBase, stackSize);
            process->deleteThread(guestThread);
            setLastError(8);
            return 0;
        }
        memory->memset(stackBase, 0, stackSize);
        memory->memset(environmentBase, 0, CHILD_ENV_SIZE);

        std::unique_ptr<GuestThreadState> state(new GuestThreadState());
        state->thread = guestThread;
        state->stackBase = stackBase;
        state->stackSize = stackSize;
        state->environmentBase = environmentBase;
        state->tlsArray = environmentBase + CHILD_TLS_ARRAY_OFFSET;
        state->tebAddress = environmentBase + CHILD_TEB_OFFSET;
        state->suspendCount = (creationFlags & CREATE_SUSPENDED) ? 1 : 0;

        U32 stackTop = stackBase + stackSize;
        memory->writed(state->tebAddress + 0x00, 0xffffffff);
        memory->writed(state->tebAddress + 0x04, stackTop);
        memory->writed(state->tebAddress + 0x08, stackBase);
        memory->writed(state->tebAddress + 0x18, state->tebAddress);
        memory->writed(state->tebAddress + 0x20, process->id);
        memory->writed(state->tebAddress + 0x24, guestThread->id);
        memory->writed(state->tebAddress + 0x2c, state->tlsArray);
        memory->writed(state->tebAddress + 0x30, PEB_ADDRESS);
        memory->writed(state->tebAddress + 0x34, 0);
        if (!initializeThreadStaticTls(*state)) {
            for (U32 block : state->staticTlsBlocks) {
                freeGuestHeap(block);
            }
            memory->unmap(environmentBase, CHILD_ENV_SIZE);
            memory->unmap(stackBase, stackSize);
            process->deleteThread(guestThread);
            setLastError(8);
            return 0;
        }
        initializeGuestThreadCpu(*state, startAddress, parameter);

        KernelObject object;
        object.type = KernelObjectType::Thread;
        object.threadId = guestThread->id;
        U32 handle = addKernelObject(object);
        state->handle = handle;
        guestThreads.push_back(std::move(state));
        nextChildStackTop = stackBase;
        nextChildEnvironmentBase -= CHILD_ENV_SIZE;
        if (threadIdAddress) {
            memory->writed(threadIdAddress, guestThread->id);
        }
        printf(
            "Sugarbomb Win32 thread: CreateThread(start=0x%08X, parameter=0x%08X, flags=0x%08X) -> handle 0x%08X, tid %u\n",
            startAddress,
            parameter,
            creationFlags,
            handle,
            guestThread->id);
        activeCpu = callerCpu;
        return handle;
    }

    GuestThreadState* guestThreadFromHandle(U32 handle, CPU* callerCpu) {
        if (handle == CURRENT_THREAD_PSEUDO_HANDLE) {
            return callerCpu ? findGuestThread(callerCpu->thread->id) : nullptr;
        }
        auto object = kernelObjects.find(handle);
        if (object == kernelObjects.end() || object->second.type != KernelObjectType::Thread) {
            return nullptr;
        }
        return findGuestThread(object->second.threadId);
    }

    bool isGuestThreadHandle(U32 handle, CPU* callerCpu) {
        if (guestThreadFromHandle(handle, callerCpu)) {
            return true;
        }
        setLastError(6);
        return false;
    }

    U32 changeThreadSuspendCount(U32 handle, bool suspend) {
        GuestThreadState* state = guestThreadFromHandle(handle, activeCpu);
        if (!state || state->completed) {
            setLastError(6);
            return 0xffffffff;
        }
        U32 previous = state->suspendCount;
        if (suspend) {
            if (state->suspendCount == 0x7f) {
                setLastError(87);
                return 0xffffffff;
            }
            ++state->suspendCount;
        } else if (state->suspendCount) {
            --state->suspendCount;
        }
        return previous;
    }

    void completeGuestThread(GuestThreadState& state, U32 code) {
        state.exitCode = code;
        state.completed = true;
        state.thread->terminating = true;
        for (auto& entry : kernelObjects) {
            if (entry.second.type == KernelObjectType::Thread &&
                entry.second.threadId == state.thread->id) {
                entry.second.exitCode = code;
                entry.second.signaled = true;
            }
        }
        printf("Sugarbomb Win32 thread: tid %u exited with code %u\n", state.thread->id, code);
    }

    void completeCurrentGuestThread(CPU* guestCpu, U32 code) {
        GuestThreadState* state = findGuestThread(guestCpu->thread->id);
        if (state) {
            completeGuestThread(*state, code);
        } else {
            guestCpu->thread->terminating = true;
        }
    }

    bool getGuestThreadExitCode(U32 handle, U32 destination) {
        GuestThreadState* state = guestThreadFromHandle(handle, activeCpu);
        if (!state || !destination || !memory->canWrite(destination, 4)) {
            setLastError(state ? 87 : 6);
            return false;
        }
        memory->writed(destination, state->completed ? state->exitCode : STILL_ACTIVE);
        return true;
    }

    void sleepGuestThread(CPU* guestCpu, U32 milliseconds) {
        if (!milliseconds) {
            return;
        }
        GuestThreadState* state = guestCpu ? findGuestThread(guestCpu->thread->id) : nullptr;
        if (!state) {
            return;
        }
        state->waitKind = GuestWaitKind::Sleep;
        state->waitHandles.clear();
        state->waitAll = false;
        state->waitDeadline =
            milliseconds == 0xffffffff
            ? std::numeric_limits<U64>::max()
            : KSystem::getMicroCounter() + static_cast<U64>(milliseconds) * 1000;
    }

    U32 createSemaphore(S32 initialCount, S32 maximumCount, U32 nameAddress) {
        if (maximumCount <= 0 || initialCount < 0 || initialCount > maximumCount) {
            setLastError(87);
            return 0;
        }
        std::string name = nameAddress ? lowerAscii(readAnsi(nameAddress)) : "";
        U32 existing = findNamedKernelObject(name, KernelObjectType::Semaphore);
        if (existing) {
            setLastError(183); // ERROR_ALREADY_EXISTS
            return existing;
        }
        KernelObject object;
        object.type = KernelObjectType::Semaphore;
        object.count = initialCount;
        object.maximumCount = maximumCount;
        object.name = name;
        return addKernelObject(object);
    }

    bool releaseSemaphore(U32 handle, S32 releaseCount, U32 previousCountAddress) {
        auto found = kernelObjects.find(handle);
        if (found == kernelObjects.end() ||
            found->second.type != KernelObjectType::Semaphore ||
            releaseCount <= 0 ||
            releaseCount > found->second.maximumCount - found->second.count) {
            setLastError(87);
            return false;
        }
        if (previousCountAddress) {
            memory->writed(previousCountAddress, static_cast<U32>(found->second.count));
        }
        found->second.count += releaseCount;
        return true;
    }

    U32 createEvent(bool manualReset, bool initialState, U32 nameAddress) {
        std::string name = nameAddress ? lowerAscii(readAnsi(nameAddress)) : "";
        U32 existing = findNamedKernelObject(name, KernelObjectType::Event);
        if (existing) {
            setLastError(183);
            return existing;
        }
        KernelObject object;
        object.type = KernelObjectType::Event;
        object.manualReset = manualReset;
        object.signaled = initialState;
        object.name = name;
        return addKernelObject(object);
    }

    bool setEvent(U32 handle, bool signaled) {
        auto found = kernelObjects.find(handle);
        if (found == kernelObjects.end() || found->second.type != KernelObjectType::Event) {
            setLastError(6);
            return false;
        }
        found->second.signaled = signaled;
        return true;
    }

    U32 createMutex(bool initialOwner, U32 nameAddress) {
        std::string name = nameAddress ? lowerAscii(readAnsi(nameAddress)) : "";
        U32 existing = findNamedKernelObject(name, KernelObjectType::Mutex);
        if (existing) {
            setLastError(183);
            return existing;
        }
        KernelObject object;
        object.type = KernelObjectType::Mutex;
        object.name = name;
        if (initialOwner) {
            object.ownerThread = currentGuestThreadId();
            object.recursionCount = 1;
        }
        return addKernelObject(object);
    }

    bool releaseMutex(U32 handle) {
        auto found = kernelObjects.find(handle);
        if (found == kernelObjects.end() ||
            found->second.type != KernelObjectType::Mutex ||
            found->second.ownerThread != currentGuestThreadId() ||
            !found->second.recursionCount) {
            setLastError(288);
            return false;
        }
        --found->second.recursionCount;
        if (!found->second.recursionCount) {
            found->second.ownerThread = 0;
        }
        return true;
    }

    U32 waitForSingleObject(U32 handle, U32 timeout) {
        auto found = kernelObjects.find(handle);
        if (found == kernelObjects.end()) {
            setLastError(6);
            return 0xffffffff; // WAIT_FAILED
        }
        U32 threadId = currentGuestThreadId();
        if (kernelObjectIsSignaled(found->second, threadId)) {
            acquireKernelObject(found->second, threadId);
            return 0; // WAIT_OBJECT_0
        }
        if (!timeout) {
            return 258; // WAIT_TIMEOUT
        }

        GuestThreadState* state = activeCpu ? findGuestThread(activeCpu->thread->id) : nullptr;
        if (!state) {
            setLastError(6);
            return 0xffffffff;
        }
        parkGuestThread(*state, {handle}, false, timeout);
        return 258; // Placeholder until the scheduler writes the actual result into EAX.
    }

    U32 waitForMultipleObjects(U32 count, U32 handlesAddress, bool waitAll, U32 timeout) {
        if (!count || count > 64 || !memory->canRead(handlesAddress, count * 4)) {
            setLastError(87);
            return 0xffffffff;
        }
        std::vector<U32> handles;
        handles.reserve(count);
        for (U32 index = 0; index < count; ++index) {
            U32 handle = memory->readd(handlesAddress + index * 4);
            auto found = kernelObjects.find(handle);
            if (found == kernelObjects.end()) {
                setLastError(6);
                return 0xffffffff;
            }
            handles.push_back(handle);
        }

        GuestThreadState* state = activeCpu ? findGuestThread(activeCpu->thread->id) : nullptr;
        if (!state) {
            setLastError(6);
            return 0xffffffff;
        }
        state->waitHandles = handles;
        state->waitAll = waitAll;
        U32 result = tryAcquireGuestWait(*state);
        state->waitHandles.clear();
        state->waitAll = false;
        if (result != 258 || !timeout) {
            return result;
        }
        parkGuestThread(*state, handles, waitAll, timeout);
        return 258; // Placeholder until the scheduler writes the actual result into EAX.
    }

    U32 addKernelObject(const KernelObject& object) {
        U32 handle = nextKernelHandle++;
        kernelObjects[handle] = object;
        if (!object.name.empty()) {
            namedKernelObjects[object.name] = handle;
        }
        return handle;
    }

    U32 findNamedKernelObject(const std::string& name, KernelObjectType type) {
        if (name.empty()) {
            return 0;
        }
        auto named = namedKernelObjects.find(name);
        if (named == namedKernelObjects.end()) {
            return 0;
        }
        auto object = kernelObjects.find(named->second);
        if (object == kernelObjects.end() || object->second.type != type) {
            setLastError(6);
            return 0;
        }
        return named->second;
    }

    bool kernelObjectIsSignaled(const KernelObject& object, U32 threadId) const {
        switch (object.type) {
        case KernelObjectType::Semaphore:
            return object.count > 0;
        case KernelObjectType::Event:
            return object.signaled;
        case KernelObjectType::Mutex:
            return !object.ownerThread || object.ownerThread == threadId;
        case KernelObjectType::Thread:
            return object.signaled;
        }
        return false;
    }

    void printGuestCpuDetails(const GuestThreadState& state) const {
        if (state.completed || !state.thread || !state.thread->cpu) {
            return;
        }
        CPU* stateCpu = state.thread->cpu;
        U32 stackPointer = stateCpu->reg[4].u32;
        U32 stackAddress =
            stateCpu->seg[SS].address +
            (stackPointer & stateCpu->stackMask);
        fprintf(stderr, "      ESP=0x%08X", stackPointer);
        constexpr U32 STACK_WORDS = 6;
        if (memory->canRead(stackAddress, STACK_WORDS * sizeof(U32))) {
            fprintf(stderr, " stack:");
            for (U32 index = 0; index < STACK_WORDS; ++index) {
                fprintf(
                    stderr,
                    " 0x%08X",
                    memory->readd(stackAddress + index * sizeof(U32)));
            }
        }
        fprintf(stderr, "\n");
    }

    void printGuestWaitDetails(const GuestThreadState& state) const {
        if (state.waitKind == GuestWaitKind::Sleep) {
            U64 now = KSystem::getMicroCounter();
            fprintf(
                stderr,
                "      sleep deadline=%llu now=%llu remaining_ms=%lld\n",
                static_cast<unsigned long long>(state.waitDeadline),
                static_cast<unsigned long long>(now),
                state.waitDeadline == std::numeric_limits<U64>::max()
                    ? -1LL
                    : static_cast<long long>(
                        state.waitDeadline > now
                            ? (state.waitDeadline - now) / 1000
                            : 0));
            return;
        }
        if (state.waitKind != GuestWaitKind::KernelObjects) {
            return;
        }
        static const char* typeNames[] = {
            "semaphore",
            "event",
            "mutex",
            "thread",
        };
        fprintf(
            stderr,
            "      waitAll=%u deadline=%llu handles:",
            state.waitAll ? 1 : 0,
            static_cast<unsigned long long>(state.waitDeadline));
        for (U32 handle : state.waitHandles) {
            auto object = kernelObjects.find(handle);
            if (object == kernelObjects.end()) {
                fprintf(stderr, " 0x%08X(invalid)", handle);
                continue;
            }
            const KernelObject& value = object->second;
            fprintf(
                stderr,
                " 0x%08X(%s,signaled=%u,count=%d,tid=%u%s%s)",
                handle,
                typeNames[static_cast<U32>(value.type)],
                kernelObjectIsSignaled(
                    value,
                    state.thread ? state.thread->id : 0)
                    ? 1
                    : 0,
                value.count,
                value.threadId,
                value.name.empty() ? "" : ",name=",
                value.name.empty() ? "" : value.name.c_str());
        }
        fprintf(stderr, "\n");
    }

    void acquireKernelObject(KernelObject& object, U32 threadId) {
        switch (object.type) {
        case KernelObjectType::Semaphore:
            --object.count;
            break;
        case KernelObjectType::Event:
            if (!object.manualReset) {
                object.signaled = false;
            }
            break;
        case KernelObjectType::Mutex:
            object.ownerThread = threadId;
            ++object.recursionCount;
            break;
        case KernelObjectType::Thread:
            break;
        }
    }

    void parkGuestThread(
        GuestThreadState& state,
        const std::vector<U32>& handles,
        bool waitAll,
        U32 timeout) {
        state.waitKind = GuestWaitKind::KernelObjects;
        state.waitHandles = handles;
        state.waitAll = waitAll;
        state.waitDeadline =
            timeout == 0xffffffff
            ? std::numeric_limits<U64>::max()
            : KSystem::getMicroCounter() + static_cast<U64>(timeout) * 1000;
        if (waitTraceCount < 24) {
            printf(
                "Sugarbomb scheduler: parked tid %u on %zu handle%s%s\n",
                state.thread->id,
                handles.size(),
                handles.size() == 1 ? "" : "s",
                timeout == 0xffffffff ? " (infinite)" : "");
            ++waitTraceCount;
        }
    }

    void parkGuestThreadOnCriticalSection(
        GuestThreadState& state,
        U32 address) {
        state.waitKind = GuestWaitKind::CriticalSection;
        state.waitCriticalSectionAddress = address;
        state.waitDeadline = std::numeric_limits<U64>::max();
        if (waitTraceCount < 24) {
            printf(
                "Sugarbomb scheduler: parked tid %u on critical section 0x%08X\n",
                state.thread->id,
                address);
            ++waitTraceCount;
        }
    }

    void parkGuestThreadOnSrwLock(
        GuestThreadState& state,
        U32 address,
        bool exclusive) {
        state.waitKind = GuestWaitKind::SlimReaderWriterLock;
        state.waitSlimReaderWriterLockAddress = address;
        state.waitSlimReaderWriterLockExclusive = exclusive;
        state.waitDeadline = std::numeric_limits<U64>::max();
        if (waitTraceCount < 24) {
            printf(
                "Sugarbomb scheduler: parked tid %u on %s "
                "SRW lock 0x%08X\n",
                state.thread->id,
                exclusive ? "exclusive" : "shared",
                address);
            ++waitTraceCount;
        }
    }

    void parkGuestThreadOnConditionVariable(
        GuestThreadState& state,
        U32 conditionVariable,
        U32 lock,
        bool exclusive,
        U32 timeout) {
        state.waitKind = GuestWaitKind::ConditionVariable;
        state.waitConditionVariableAddress = conditionVariable;
        state.waitConditionVariableSignaled = false;
        state.waitSlimReaderWriterLockAddress = lock;
        state.waitSlimReaderWriterLockExclusive = exclusive;
        state.waitDeadline =
            timeout == 0xffffffff
            ? std::numeric_limits<U64>::max()
            : KSystem::getMicroCounter() +
                static_cast<U64>(timeout) * 1000;
        if (waitTraceCount < 24) {
            printf(
                "Sugarbomb scheduler: parked tid %u on condition "
                "variable 0x%08X with %s SRW lock 0x%08X\n",
                state.thread->id,
                conditionVariable,
                exclusive ? "exclusive" : "shared",
                lock);
            ++waitTraceCount;
        }
    }

    void wakeConditionVariable(U32 address, bool all) {
        if (!address || !memory->canWrite(address, 4)) {
            setLastError(87);
            return;
        }
        for (auto& state : guestThreads) {
            if (state->completed ||
                state->waitKind !=
                    GuestWaitKind::ConditionVariable ||
                state->waitConditionVariableAddress != address) {
                continue;
            }
            state->waitConditionVariableSignaled = true;
            if (!all) {
                break;
            }
        }
    }

    U32 tryAcquireGuestWait(GuestThreadState& state) {
        U32 threadId = state.thread->id;
        if (state.waitAll) {
            for (U32 handle : state.waitHandles) {
                auto object = kernelObjects.find(handle);
                if (object == kernelObjects.end()) {
                    setThreadLastError(state, 6);
                    return 0xffffffff; // WAIT_FAILED
                }
                if (!kernelObjectIsSignaled(object->second, threadId)) {
                    return 258; // WAIT_TIMEOUT, also used internally as "not ready".
                }
            }
            for (U32 handle : state.waitHandles) {
                acquireKernelObject(kernelObjects.find(handle)->second, threadId);
            }
            return 0; // WAIT_OBJECT_0
        }

        for (U32 index = 0; index < state.waitHandles.size(); ++index) {
            auto object = kernelObjects.find(state.waitHandles[index]);
            if (object == kernelObjects.end()) {
                setThreadLastError(state, 6);
                return 0xffffffff;
            }
            if (kernelObjectIsSignaled(object->second, threadId)) {
                acquireKernelObject(object->second, threadId);
                return index; // WAIT_OBJECT_0 + index
            }
        }
        return 258;
    }

    void refreshWaitingGuestThreads() {
        U64 now = KSystem::getMicroCounter();
        for (auto& state : guestThreads) {
            if (state->completed || !state->thread || state->waitKind == GuestWaitKind::None) {
                continue;
            }

            U32 result = 0;
            bool wake = false;
            if (state->waitKind == GuestWaitKind::Sleep) {
                wake = now >= state->waitDeadline;
            } else if (state->waitKind == GuestWaitKind::CriticalSection) {
                U32 address = state->waitCriticalSectionAddress;
                auto criticalSection = criticalSections.find(address);
                if (criticalSection == criticalSections.end() ||
                    !criticalSection->second.ownerThread ||
                    criticalSection->second.ownerThread == state->thread->id) {
                    CPU* previousCpu = activeCpu;
                    activeCpu = state->thread->cpu;
                    wake = enterCriticalSection(address);
                    activeCpu = previousCpu;
                }
            } else if (
                state->waitKind ==
                GuestWaitKind::SlimReaderWriterLock) {
                CPU* previousCpu = activeCpu;
                activeCpu = state->thread->cpu;
                wake = tryAcquireSrwLock(
                    state->waitSlimReaderWriterLockAddress,
                    state->waitSlimReaderWriterLockExclusive);
                activeCpu = previousCpu;
            } else if (
                state->waitKind ==
                GuestWaitKind::ConditionVariable) {
                bool timedOut =
                    !state->waitConditionVariableSignaled &&
                    state->waitDeadline !=
                        std::numeric_limits<U64>::max() &&
                    now >= state->waitDeadline;
                if (state->waitConditionVariableSignaled ||
                    timedOut) {
                    CPU* previousCpu = activeCpu;
                    activeCpu = state->thread->cpu;
                    wake = tryAcquireSrwLock(
                        state->waitSlimReaderWriterLockAddress,
                        state->waitSlimReaderWriterLockExclusive);
                    activeCpu = previousCpu;
                    if (wake) {
                        result = timedOut ? 0 : 1;
                        if (timedOut) {
                            setThreadLastError(
                                *state,
                                1460); // ERROR_TIMEOUT
                        }
                    }
                }
            } else {
                result = tryAcquireGuestWait(*state);
                wake = result != 258;
                if (!wake &&
                    state->waitDeadline != std::numeric_limits<U64>::max() &&
                    now >= state->waitDeadline) {
                    result = 258; // WAIT_TIMEOUT
                    wake = true;
                }
            }
            if (!wake) {
                continue;
            }

            state->thread->cpu->reg[0].u32 = result;
            state->waitKind = GuestWaitKind::None;
            state->waitHandles.clear();
            state->waitAll = false;
            state->waitDeadline = 0;
            state->waitCriticalSectionAddress = 0;
            state->waitSlimReaderWriterLockAddress = 0;
            state->waitSlimReaderWriterLockExclusive = false;
            state->waitConditionVariableAddress = 0;
            state->waitConditionVariableSignaled = false;
            if (waitTraceCount < 24) {
                printf(
                    "Sugarbomb scheduler: woke tid %u with result 0x%08X\n",
                    state->thread->id,
                    result);
                ++waitTraceCount;
            }
        }
    }

    bool closeKernelHandle(U32 handle) {
        auto found = kernelObjects.find(handle);
        if (found == kernelObjects.end()) {
            return false;
        }
        if (!found->second.name.empty()) {
            namedKernelObjects.erase(found->second.name);
        }
        kernelObjects.erase(found);
        return true;
    }

    static U32 windowsProtectionToGuest(U32 protection) {
        switch (protection & 0xff) {
        case 0x01:
            return K_PROT_NONE;
        case 0x02:
            return K_PROT_READ;
        case 0x04:
        case 0x08:
            return K_PROT_READ | K_PROT_WRITE;
        case 0x10:
            return K_PROT_EXEC;
        case 0x20:
            return K_PROT_READ | K_PROT_EXEC;
        case 0x40:
        case 0x80:
            return K_PROT_READ | K_PROT_WRITE | K_PROT_EXEC;
        default:
            return K_PROT_NONE;
        }
    }

    U32 findFreeVirtualBase(U32 roundedSize) const {
        auto scanFrom = [&](U32 requestedStart) -> U32 {
            U64 candidate =
                (static_cast<U64>(requestedStart) + 0xffff) &
                ~static_cast<U64>(0xffff);
            while (candidate >= GUEST_VIRTUAL_BASE &&
                   candidate <= GUEST_VIRTUAL_LIMIT &&
                   static_cast<U64>(roundedSize) <=
                       static_cast<U64>(GUEST_VIRTUAL_LIMIT) - candidate) {
                bool overlaps = false;
                U64 nextCandidate = candidate;
                const U64 candidateEnd = candidate + roundedSize;
                for (const auto& entry : virtualRegions) {
                    const U64 existingBase = entry.second.base;
                    const U64 existingEnd = existingBase + entry.second.size;
                    if (candidate < existingEnd && candidateEnd > existingBase) {
                        overlaps = true;
                        nextCandidate = std::max(
                            nextCandidate,
                            (existingEnd + 0xffff) &
                                ~static_cast<U64>(0xffff));
                    }
                }
                if (!overlaps &&
                    guestRangeIsFree(
                        static_cast<U32>(candidate),
                        roundedSize)) {
                    return static_cast<U32>(candidate);
                }
                if (!overlaps) {
                    overlaps = true;
                    nextCandidate = candidate + 0x10000;
                }
                if (nextCandidate <= candidate) {
                    return 0;
                }
                candidate = nextCandidate;
            }
            return 0;
        };

        U32 base = scanFrom(nextVirtualAddress);
        if (!base && nextVirtualAddress != GUEST_VIRTUAL_BASE) {
            base = scanFrom(GUEST_VIRTUAL_BASE);
        }
        return base;
    }

    static U32 peSectionWindowsProtection(
        U32 characteristics) {
        bool execute =
            (characteristics & 0x20000000) != 0;
        bool read =
            (characteristics & 0x40000000) != 0;
        bool write =
            (characteristics & 0x80000000) != 0;
        if (execute) {
            if (write) {
                return 0x40; // PAGE_EXECUTE_READWRITE
            }
            if (read) {
                return 0x20; // PAGE_EXECUTE_READ
            }
            return 0x10; // PAGE_EXECUTE
        }
        if (write) {
            return 0x04; // PAGE_READWRITE
        }
        if (read) {
            return 0x02; // PAGE_READONLY
        }
        return 0x01; // PAGE_NOACCESS
    }

    static U32 peImageProtectionAt(
        const Pe32MappedImage& mapped,
        U32 address) {
        U64 imageEnd =
            static_cast<U64>(mapped.loadBase) +
            mapped.info.sizeOfImage;
        if (address < mapped.loadBase ||
            address >= imageEnd) {
            return 0;
        }
        if (address <
            static_cast<U64>(mapped.loadBase) +
                mapped.info.sizeOfHeaders) {
            return 0x02;
        }
        U32 rva = address - mapped.loadBase;
        for (const Pe32SectionInfo& section :
             mapped.info.sections) {
            U32 span = std::max(
                section.virtualSize,
                section.rawDataSize);
            if (rva >= section.virtualAddress &&
                static_cast<U64>(rva) <
                    static_cast<U64>(
                        section.virtualAddress) +
                        span) {
                return peSectionWindowsProtection(
                    section.characteristics);
            }
        }
        return 0x02;
    }

    U32 virtualProtectionAt(U32 address) const {
        U32 page = address & ~K_PAGE_MASK;
        auto overridden = pageProtections.find(page);
        if (overridden != pageProtections.end()) {
            return overridden->second;
        }
        for (const auto& entry : virtualRegions) {
            const VirtualRegion& region = entry.second;
            if (address >= region.base &&
                static_cast<U64>(address) <
                    static_cast<U64>(region.base) +
                        region.size) {
                return region.protection;
            }
        }
        U32 imageProtection =
            peImageProtectionAt(image, address);
        if (imageProtection) {
            return imageProtection;
        }
        for (const auto& entry : guestModules) {
            imageProtection = peImageProtectionAt(
                entry.second.image,
                address);
            if (imageProtection) {
                return imageProtection;
            }
        }
        for (const auto& entry : heapAllocations) {
            if (address >= entry.first &&
                static_cast<U64>(address) <
                    static_cast<U64>(entry.first) +
                        entry.second.mappedSize) {
                return 0x04;
            }
        }
        if ((address >= STACK_BASE &&
             address < STACK_TOP) ||
            (address >= ENV_BASE &&
             address < ENV_BASE + ENV_SIZE)) {
            return 0x04;
        }
        if (address >= THUNK_BASE &&
            address < THUNK_BASE + THUNK_SIZE) {
            return 0x20;
        }
        return memory->canRead(address, 1)
            ? 0x04
            : 0;
    }

    bool virtualProtect(
        U32 address,
        U32 size,
        U32 protection,
        U32 previousProtectionAddress) {
        U32 baseProtection = protection & 0xff;
        if (!address ||
            !size ||
            !previousProtectionAddress ||
            !memory->canWrite(
                previousProtectionAddress,
                4) ||
            (baseProtection != 0x01 &&
             baseProtection != 0x02 &&
             baseProtection != 0x04 &&
             baseProtection != 0x08 &&
             baseProtection != 0x10 &&
             baseProtection != 0x20 &&
             baseProtection != 0x40 &&
             baseProtection != 0x80)) {
            setLastError(87);
            return false;
        }
        U64 requestedEnd =
            static_cast<U64>(address) + size;
        if (requestedEnd >
            static_cast<U64>(
                std::numeric_limits<U32>::max()) + 1) {
            setLastError(487);
            return false;
        }
        U32 alignedBase = address & ~K_PAGE_MASK;
        U64 alignedEnd64 =
            (requestedEnd + K_PAGE_MASK) &
            ~static_cast<U64>(K_PAGE_MASK);
        if (alignedEnd64 <= alignedBase ||
            alignedEnd64 >
                static_cast<U64>(
                    std::numeric_limits<U32>::max()) + 1) {
            setLastError(487);
            return false;
        }
        U32 oldProtection =
            virtualProtectionAt(address);
        if (!oldProtection) {
            setLastError(487);
            return false;
        }
        U64 alignedSize64 = alignedEnd64 - alignedBase;
        if (alignedSize64 >
            std::numeric_limits<U32>::max()) {
            setLastError(487);
            return false;
        }
        U32 alignedSize = static_cast<U32>(alignedSize64);
        if (memory->mprotect(
                thread,
                alignedBase,
                alignedSize,
                windowsProtectionToGuest(protection)) != 0) {
            setLastError(487);
            return false;
        }
        for (U64 page = alignedBase;
             page < alignedEnd64;
             page += K_PAGE_SIZE) {
            pageProtections[
                static_cast<U32>(page)] = protection;
        }
        memory->writed(
            previousProtectionAddress,
            oldProtection);
        if (++virtualProtectTraceCount <= 24) {
            printf(
                "Sugarbomb Win32 memory: VirtualProtect("
                "0x%08X, 0x%08X, 0x%08X) old=0x%08X\n",
                address,
                size,
                protection,
                oldProtection);
        }
        return true;
    }

    U32 virtualAlloc(U32 requestedAddress, U32 requestedSize, U32 allocationType, U32 protection) {
        if (!requestedSize || !(allocationType & (0x1000 | 0x2000))) {
            setLastError(87);
            return 0;
        }
        U64 roundedSize64 = (static_cast<U64>(requestedSize) + K_PAGE_MASK) & ~static_cast<U64>(K_PAGE_MASK);
        if (roundedSize64 > 0xffffffff) {
            setLastError(8);
            return 0;
        }
        U32 roundedSize = static_cast<U32>(roundedSize64);
        U32 base = requestedAddress
            ? requestedAddress & ~K_PAGE_MASK
            : findFreeVirtualBase(roundedSize);
        if (!base) {
            setLastError(8);
            return 0;
        }

        auto containing = findVirtualRegion(base);
        if (requestedAddress && containing) {
            if ((allocationType & 0x2000) ||
                static_cast<U64>(base) + roundedSize >
                    static_cast<U64>(containing->base) + containing->size) {
                setLastError(487); // ERROR_INVALID_ADDRESS
                return 0;
            }
            U32 guestProtection = windowsProtectionToGuest(protection);
            if (memory->canRead(base, 1)) {
                if (memory->mprotect(thread, base, roundedSize, guestProtection) != 0) {
                    setLastError(487);
                    return 0;
                }
            } else if (memory->mmap(
                    thread,
                    base,
                    roundedSize,
                    guestProtection,
                    K_MAP_FIXED | K_MAP_PRIVATE | K_MAP_ANONYMOUS,
                    -1,
                    0) != base) {
                setLastError(8);
                return 0;
            }
            containing->protection = protection;
            containing->state = 0x1000; // MEM_COMMIT
            containing->committedRanges.push_back(std::make_pair(base, roundedSize));
            return base;
        }

        if (base < GUEST_VIRTUAL_BASE || base > GUEST_VIRTUAL_LIMIT ||
            roundedSize > GUEST_VIRTUAL_LIMIT - base) {
            setLastError(8);
            return 0;
        }
        for (const auto& entry : virtualRegions) {
            U64 requestedEnd = static_cast<U64>(base) + roundedSize;
            U64 existingEnd = static_cast<U64>(entry.second.base) + entry.second.size;
            if (base < existingEnd && requestedEnd > entry.second.base) {
                setLastError(487);
                return 0;
            }
        }
        if (!guestRangeIsFree(base, roundedSize)) {
            setLastError(487);
            return 0;
        }
        if (allocationType & 0x1000) {
            U32 guestProtection = windowsProtectionToGuest(protection);
            if (memory->mmap(
                    thread,
                    base,
                    roundedSize,
                    guestProtection,
                    K_MAP_FIXED | K_MAP_PRIVATE | K_MAP_ANONYMOUS,
                    -1,
                    0) != base) {
                setLastError(8);
                return 0;
            }
        }
        VirtualRegion region;
        region.base = base;
        region.size = roundedSize;
        region.allocationProtection = protection;
        region.protection = (allocationType & 0x1000) ? protection : 0;
        region.state = (allocationType & 0x1000) ? 0x1000 : 0x2000;
        if (allocationType & 0x1000) {
            region.committedRanges.push_back(std::make_pair(base, roundedSize));
        }
        virtualRegions[base] = region;
        if (!requestedAddress) {
            nextVirtualAddress = base + roundedSize;
        }
        return base;
    }

    bool virtualFree(U32 address, U32 size, U32 freeType) {
        VirtualRegion* region = findVirtualRegion(address);
        if (!region) {
            setLastError(487);
            return false;
        }
        if (freeType & 0x8000) { // MEM_RELEASE
            if (address != region->base || size) {
                setLastError(87);
                return false;
            }
            U32 base = region->base;
            for (const auto& range : region->committedRanges) {
                memory->unmap(range.first, range.second);
            }
            virtualRegions.erase(base);
            return true;
        }
        if (freeType & 0x4000) { // MEM_DECOMMIT
            U32 decommitSize = size ? K_ROUND_UP_TO_PAGE(size) : region->size;
            if (memory->unmap(address & ~K_PAGE_MASK, decommitSize) != 0) {
                setLastError(487);
                return false;
            }
            region->state = 0x2000;
            region->protection = 0;
            return true;
        }
        setLastError(87);
        return false;
    }

    U32 virtualQuery(U32 address, U32 information, U32 length) {
        if (!information || length < 28) {
            setLastError(87);
            return 0;
        }
        VirtualRegion* region = findVirtualRegion(address);
        if (!region) {
            memory->memset(information, 0, 28);
            U32 base = address & ~K_PAGE_MASK;
            memory->writed(information + 0, base);
            memory->writed(information + 12, K_PAGE_SIZE);
            memory->writed(information + 16, 0x10000); // MEM_FREE
            return 28;
        }
        memory->writed(information + 0, region->base);
        memory->writed(information + 4, region->base);
        memory->writed(information + 8, region->allocationProtection);
        memory->writed(information + 12, region->size);
        memory->writed(information + 16, region->state);
        memory->writed(information + 20, region->protection);
        memory->writed(information + 24, 0x20000); // MEM_PRIVATE
        return 28;
    }

    VirtualRegion* findVirtualRegion(U32 address) {
        for (auto& entry : virtualRegions) {
            U64 end = static_cast<U64>(entry.second.base) + entry.second.size;
            if (address >= entry.second.base && address < end) {
                return &entry.second;
            }
        }
        return nullptr;
    }

    void initializeCriticalSection(U32 address, U32 spinCount) {
        CriticalSectionState state;
        state.spinCount = spinCount;
        criticalSections[address] = state;
        memory->memset(address, 0, 24);
        memory->writed(address + 4, 0xffffffff);
        memory->writed(address + 20, spinCount);
    }

    bool enterCriticalSection(U32 address) {
        auto found = criticalSections.find(address);
        if (found == criticalSections.end()) {
            initializeCriticalSection(address, 0);
            found = criticalSections.find(address);
        }
        CriticalSectionState& state = found->second;
        if (state.ownerThread && state.ownerThread != currentGuestThreadId()) {
            return false;
        }
        state.ownerThread = currentGuestThreadId();
        ++state.recursionCount;
        memory->writed(address + 4, state.recursionCount - 1);
        memory->writed(address + 8, state.recursionCount);
        memory->writed(address + 12, state.ownerThread);
        return true;
    }

    void leaveCriticalSection(U32 address) {
        auto found = criticalSections.find(address);
        if (found == criticalSections.end() ||
            found->second.ownerThread != currentGuestThreadId() ||
            !found->second.recursionCount) {
            setLastError(288); // ERROR_NOT_OWNER
            return;
        }
        CriticalSectionState& state = found->second;
        --state.recursionCount;
        if (!state.recursionCount) {
            state.ownerThread = 0;
            memory->writed(address + 4, 0xffffffff);
        } else {
            memory->writed(address + 4, state.recursionCount - 1);
        }
        memory->writed(address + 8, state.recursionCount);
        memory->writed(address + 12, state.ownerThread);
    }

    void writeSrwLockState(
        U32 address,
        const SlimReaderWriterLockState& state) {
        U32 value = 0;
        if (state.exclusiveOwner) {
            value = (state.exclusiveOwner << 2) | 1;
        } else if (state.sharedCount) {
            value = (state.sharedCount << 4) | 2;
        }
        memory->writed(address, value);
    }

    bool tryAcquireSrwLock(U32 address, bool exclusive) {
        if (!address || !memory->canWrite(address, 4)) {
            setLastError(87);
            return false;
        }
        SlimReaderWriterLockState& state =
            slimReaderWriterLocks[address];
        if (exclusive) {
            if (state.exclusiveOwner || state.sharedCount) {
                return false;
            }
            state.exclusiveOwner = currentGuestThreadId();
        } else {
            if (state.exclusiveOwner ||
                state.sharedCount ==
                    std::numeric_limits<U32>::max()) {
                return false;
            }
            ++state.sharedCount;
        }
        writeSrwLockState(address, state);
        return true;
    }

    bool releaseSrwLock(U32 address, bool exclusive) {
        auto found = slimReaderWriterLocks.find(address);
        if (!address ||
            !memory->canWrite(address, 4) ||
            found == slimReaderWriterLocks.end()) {
            setLastError(288); // ERROR_NOT_OWNER
            return false;
        }
        SlimReaderWriterLockState& state = found->second;
        if (exclusive) {
            if (state.exclusiveOwner != currentGuestThreadId()) {
                setLastError(288);
                return false;
            }
            state.exclusiveOwner = 0;
        } else {
            if (!state.sharedCount || state.exclusiveOwner) {
                setLastError(288);
                return false;
            }
            --state.sharedCount;
        }
        writeSrwLockState(address, state);
        if (!state.exclusiveOwner && !state.sharedCount) {
            slimReaderWriterLocks.erase(found);
        }
        return true;
    }

    U32 allocateGuestHeap(U32 requestedSize, bool zeroMemory) {
        U32 logicalSize = requestedSize ? requestedSize : 1;
        if (logicalSize > 0xfffff000) {
            setLastError(8); // ERROR_NOT_ENOUGH_MEMORY
            return 0;
        }
        U32 mappedSize = K_ROUND_UP_TO_PAGE(logicalSize);
        if (nextHeapAddress > GUEST_HEAP_LIMIT ||
            mappedSize > GUEST_HEAP_LIMIT - nextHeapAddress) {
            setLastError(8);
            return 0;
        }
        U32 address = nextHeapAddress;
        if (memory->mmap(
                thread,
                address,
                mappedSize,
                K_PROT_READ | K_PROT_WRITE,
                K_MAP_FIXED | K_MAP_PRIVATE | K_MAP_ANONYMOUS,
                -1,
                0) != address) {
            setLastError(8);
            return 0;
        }
        nextHeapAddress += mappedSize;
        HeapAllocation allocation;
        allocation.requestedSize = requestedSize;
        allocation.mappedSize = mappedSize;
        heapAllocations[address] = allocation;
        if (zeroMemory) {
            memory->memset(address, 0, logicalSize);
        }
        return address;
    }

    U32 reallocateGuestHeap(U32 previous, U32 requestedSize, bool zeroMemory) {
        if (!previous) {
            return allocateGuestHeap(requestedSize, zeroMemory);
        }
        auto found = heapAllocations.find(previous);
        if (found == heapAllocations.end()) {
            setLastError(87); // ERROR_INVALID_PARAMETER
            return 0;
        }
        U32 oldSize = found->second.requestedSize;
        U32 replacement = allocateGuestHeap(requestedSize, false);
        if (!replacement) {
            return 0;
        }
        U32 copySize = std::min(oldSize, requestedSize);
        if (copySize) {
            memory->memcpy(replacement, previous, copySize);
        }
        if (zeroMemory && requestedSize > oldSize) {
            memory->memset(replacement + oldSize, 0, requestedSize - oldSize);
        }
        freeGuestHeap(previous);
        return replacement;
    }

    bool freeGuestHeap(U32 address) {
        if (!address) {
            return true;
        }
        auto found = heapAllocations.find(address);
        if (found == heapAllocations.end()) {
            setLastError(87);
            return false;
        }
        memory->unmap(address, found->second.mappedSize);
        heapAllocations.erase(found);
        return true;
    }

    U32 ensureUcrtErrno() {
        if (!ucrtErrnoAddress) {
            ucrtErrnoAddress =
                allocateGuestHeap(4, true);
        }
        return ucrtErrnoAddress;
    }

    void setUcrtErrno(U32 value) {
        U32 address = ensureUcrtErrno();
        if (address) {
            memory->writed(address, value);
        }
    }

    void setLastError(U32 errorCode) {
        U32 tebAddress = activeCpu ? activeCpu->seg[FS].address : TEB_ADDRESS;
        memory->writed(tebAddress + 0x34, errorCode);
    }

    void setThreadLastError(const GuestThreadState& state, U32 errorCode) {
        memory->writed(state.tebAddress + 0x34, errorCode);
    }

    bool isStandardHandle(U32 handle) const {
        return handle == standardHandles[0] ||
            handle == standardHandles[1] ||
            handle == standardHandles[2];
    }

    bool writeGuestOutput(U32 handle, U32 buffer, U32 length, U32 bytesWritten, bool wide) {
        const U64 byteLength =
            wide ? static_cast<U64>(length) * 2 : length;
        if (!isStandardHandle(handle) ||
            byteLength > std::numeric_limits<U32>::max() ||
            !memory->canRead(
                buffer,
                static_cast<U32>(byteLength)) ||
            (bytesWritten &&
             !memory->canWrite(bytesWritten, 4))) {
            setLastError(6);
            return false;
        }
        FILE* output = handle == standardHandles[2] ? stderr : stdout;
        if (wide) {
            for (U32 index = 0; index < length; ++index) {
                U16 character = memory->readw(buffer + index * 2);
                fputc(character <= 0x7f ? static_cast<char>(character) : '?', output);
            }
        } else {
            for (U32 index = 0; index < length; ++index) {
                fputc(memory->readb(buffer + index), output);
            }
        }
        fflush(output);
        if (bytesWritten) {
            memory->writed(bytesWritten, length);
        }
        return true;
    }

    bool guestCStringLength(
        U32 address,
        U32& length,
        U32 limit = 16 * 1024 * 1024) {
        length = 0;
        if (!address) {
            return false;
        }
        for (U32 index = 0; index < limit; ++index) {
            if (index >
                    std::numeric_limits<U32>::max() - address ||
                !memory->canRead(address + index, 1)) {
                return false;
            }
            if (!memory->readb(address + index)) {
                length = index;
                return true;
            }
        }
        return false;
    }

    std::string readAnsi(U32 address, U32 limit = 512) {
        std::string result;
        for (U32 index = 0;
             index < limit &&
             index <= std::numeric_limits<U32>::max() - address &&
             memory->canRead(address + index, 1);
             ++index) {
            U8 value = memory->readb(address + index);
            if (!value) {
                break;
            }
            result.push_back(static_cast<char>(value));
        }
        return result;
    }

    std::string readWide(U32 address, U32 limit = 512) {
        std::string result;
        for (U32 index = 0; index < limit; ++index) {
            const U64 characterAddress =
                static_cast<U64>(address) +
                static_cast<U64>(index) * 2;
            if (characterAddress >
                    std::numeric_limits<U32>::max() - 1ULL ||
                !memory->canRead(
                    static_cast<U32>(characterAddress),
                    2)) {
                break;
            }
            U16 value = memory->readw(
                static_cast<U32>(characterAddress));
            if (!value) {
                break;
            }
            result.push_back(value <= 0x7f ? static_cast<char>(value) : '?');
        }
        return result;
    }

    std::string imagePath;
    std::string commandLine;
    std::string error;
    KProcessPtr process;
    KThread* thread = nullptr;
    KMemory* memory = nullptr;
    CPU* cpu = nullptr;
    CPU* activeCpu = nullptr;
    Pe32MappedImage image;
    std::unordered_map<U32, GuestModule> guestModules;
    std::unordered_map<std::string, U32> guestModuleHandles;
    std::vector<U32> guestModuleLoadOrder;
    std::vector<GuestModuleInitializer> guestModuleInitializers;
    std::size_t guestModuleInitializerIndex = 0;
    U32 nextGuestModuleBase = 0x18000000;
    SugarbombThunkArena thunks;
    U32 entryReturnThunk = 0;
    U32 threadReturnThunk = 0;
    U32 wndProcReturnThunk = 0;
    U32 moduleInitializerReturnThunk = 0;
    U32 guestFunctionArrayReturnThunk = 0;
    std::vector<StaticTlsTemplate> staticTlsTemplates;
    U32 nativeCallCount = 0;
    U64 runSlices = 0;
    U32 lastGuestEip = 0;
    U32 exitCode = 0;
    U32 unhandledExceptionFilter = 0;
    U32 virtualAllocCallCount = 0;
    U32 virtualAllocFailureTraceCount = 0;
    U32 systemMetricsCallCount = 0;
    U32 profileTraceCount = 0;
    U32 fileAttributeTraceCount = 0;
    U32 fileOpenTraceCount = 0;
    U32 waitTraceCount = 0;
    U32 surfaceDescTraceCount = 0;
    U32 guestMessageTraceCount = 0;
    U32 wndProcDispatchTraceCount = 0;
    U32 nextKernelHandle = 0x53000000;
    U32 nextGuestFileHandle = GUEST_FILE_HANDLE_BASE;
    U32 nextGuestFindHandle = GUEST_FIND_HANDLE_BASE;
    U32 nextMmioHandle = MMIO_HANDLE_BASE;
    U32 nextRegistryHandle = 0x56000000;
    U32 nextWindowHandle = 0x57000100;
    U32 nextWindowAtom = 1;
    U32 activeWindow = 0;
    U32 direct3DDeviceWindow = 0;
    U32 directInputVtableAddress = 0;
    U32 directInputDeviceVtableAddress = 0;
    U32 directSoundVtableAddress = 0;
    U32 directSoundBufferVtableAddress = 0;
    U32 direct3DCreate9Thunk = 0;
    U32 direct3DVtableAddress = 0;
    U32 direct3DDeviceVtableAddress = 0;
    U32 direct3DSurfaceVtableAddress = 0;
    U32 direct3DInterfaceAddress = 0;
    U32 direct3DDeviceAddress = 0;
    U32 direct3DBackBufferSurface = 0;
    U32 direct3DRenderTargetSurface = 0;
    U32 direct3DDepthStencilSurface = 0;
    U32 direct3DBackBufferWidth = 0;
    U32 direct3DBackBufferHeight = 0;
    U32 direct3DBackBufferFormat = 22;
    U32 direct3DLastClearColor = 0xff000000;
    U32 direct3DVertexProfileAddress = 0;
    U32 direct3DPixelProfileAddress = 0;
    SugarbombHostD3D9 hostDirect3D;
    SugarbombHostWindow hostWindow;
    std::vector<U32> hostPresentPixels;
    bool hostFrameCaptured = false;
    U32 guestPresentCount = 0;
    U32 nextHeapHandle = PROCESS_HEAP_HANDLE + 1;
    U32 nextHeapAddress = GUEST_HEAP_BASE;
    U32 nextVirtualAddress = GUEST_VIRTUAL_BASE;
    U32 nextTlsIndex = 0;
    bool staticTlsInitialized = false;
    U32 ucrtLocaleCodepageAddress = 0;
    U32 ucrtErrnoAddress = 0;
    U32 nextChildStackTop = CHILD_STACK_FIRST_TOP;
    U32 nextChildEnvironmentBase = CHILD_ENV_FIRST_BASE;
    S32 cursorDisplayCount = 0;
    bool mouseButtonsSwapped = false;
    bool fileApisAnsi = true;
    U32 standardHandles[3] = {STDIN_GUEST_HANDLE, STDOUT_GUEST_HANDLE, STDERR_GUEST_HANDLE};
    std::unordered_map<U32, HeapAllocation> heapAllocations;
    std::unordered_map<U32, CriticalSectionState> criticalSections;
    std::unordered_map<U32, SlimReaderWriterLockState>
        slimReaderWriterLocks;
    std::unordered_map<U32, U32> msvcpLockAddresses;
    std::unordered_map<U32, U32> msvcpLockitObjects;
    std::unordered_map<U32, VirtualRegion> virtualRegions;
    std::unordered_map<U32, U32> pageProtections;
    std::unordered_map<U32, KernelObject> kernelObjects;
    std::unordered_map<std::string, U32> namedKernelObjects;
    std::unordered_map<std::string, U32> nativeApiCounts;
    std::unordered_map<U32, GuestOnExitTable> onExitTables;
    std::unordered_map<std::string, IniDocument> iniDocuments;
    std::unordered_map<std::string, std::string> profileOverrides;
    std::unordered_map<U32, GuestFile> guestFiles;
    std::unordered_map<U32, GuestCFile> guestCFiles;
    U32 standardCFiles[3] = {};
    std::unordered_map<U32, FindState> findStates;
    std::unordered_map<U32, MmioFile> mmioFiles;
    std::unordered_map<U32, std::string> registryKeys;
    std::unordered_map<std::string, GuestWindowClass> guestWindowClasses;
    std::unordered_map<U32, GuestWindow> guestWindows;
    std::deque<GuestMessage> guestMessageQueue;
    std::unordered_map<U32, std::vector<PendingWndProcDispatch>>
        pendingWndProcDispatches;
    std::unordered_map<
        U32,
        std::vector<PendingGuestFunctionArray>>
        pendingGuestFunctionArrays;
    std::unordered_map<U32, DirectInputObject> directInputObjects;
    std::unordered_map<U32, DirectInputComMethod> directInputComMethods;
    std::vector<U32> directInputVtable;
    std::vector<U32> directInputDeviceVtable;
    std::array<U8, 256> directInputKeyboardState = {};
    std::array<U8, 256> directInputVirtualKeyState = {};
    std::array<U8, 256> directInputVirtualKeyPressedSinceRead = {};
    std::array<U8, 8> directInputMouseButtons = {};
    S32 directInputMouseX = 0;
    S32 directInputMouseY = 0;
    bool directInputMousePositionKnown = false;
    bool directInputRawMouseAvailable = false;
    U32 nextDirectInputSequence = 1;
    U32 directInputHostEventTraceCount = 0;
    U32 directInputRawMouseTraceCount = 0;
    U32 directInputReadTraceCount = 0;
    U32 directInputStateCallTraceCount = 0;
    U32 directInputDataCallTraceCount = 0;
    U32 processorFeatureTraceCount = 0;
    U32 virtualProtectTraceCount = 0;
    U32 flushInstructionCacheTraceCount = 0;
    U32 guestFunctionArrayDispatchTraceCount = 0;
    U32 printfTraceCount = 0;
    std::unordered_map<U32, DirectSoundObject> directSoundObjects;
    std::unordered_map<U32, DirectSoundComMethod> directSoundComMethods;
    std::vector<U32> directSoundVtable;
    std::vector<U32> directSoundBufferVtable;
    std::unordered_map<U32, DirectShowGraph> directShowGraphs;
    std::unordered_map<U32, DirectShowInterface> directShowInterfaces;
    std::unordered_map<U32, DirectShowComMethod> directShowComMethods;
    std::unordered_map<U32, std::vector<U32>> directShowVtables;
    std::unordered_map<U32, U32> directShowVtableAddresses;
    U32 directShowVtableBlock = 0;
    std::unordered_map<U32, BinkMovie> binkMovies;
    std::unordered_map<U32, Direct3DObject> direct3DObjects;
    std::unordered_map<U32, Direct3DComMethod> direct3DComMethods;
    std::vector<U32> direct3DVtable;
    std::vector<U32> direct3DDeviceVtable;
    std::unordered_map<U32, Direct3DSurface> direct3DSurfaces;
    std::vector<U32> direct3DClearPixels;
    std::unordered_map<U32, U32> direct3DSurfaceMethods;
    std::vector<U32> direct3DSurfaceVtable;
    std::unordered_map<U32, Direct3DResource> direct3DResources;
    std::unordered_map<U32, Direct3DResourceMethod> direct3DResourceMethods;
    std::unordered_map<U32, std::vector<U32>> direct3DResourceVtables;
    std::unordered_map<U32, U32> direct3DResourceVtableAddresses;
    std::vector<U32> falloutMemorySystemVtable;
    std::vector<U32> falloutAllocatorVtable;
    U32 falloutBootstrapMemorySystem = 0;
    U32 falloutBootstrapAllocator = 0;
    std::unordered_map<std::string, std::shared_ptr<VirtualFileContent>> virtualFileContents;
    std::unordered_set<std::string> virtualDirectories;
    std::unordered_set<std::string> virtualDeletedFiles;
    std::vector<std::unique_ptr<GuestThreadState>> guestThreads;
    bool runtimeStopping = false;
    bool stoppedAtUnresolvedImport = false;
};

} // namespace

int SugarbombRuntime::run(const char* imagePath) {
    SugarbombRuntimeSession session;
    return session.run(imagePath);
}
