/*
 *  Copyright (C) 2026  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "sugarbombhostd3d9.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <unordered_map>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <d3d9.h>
#endif

#ifdef _WIN32
struct D3DXImageInfoCompat {
    UINT width;
    UINT height;
    UINT depth;
    UINT mipLevels;
    D3DFORMAT format;
    D3DRESOURCETYPE resourceType;
    UINT fileFormat;
};

using D3DXGetImageInfoFromFileInMemoryProc =
    HRESULT (WINAPI*)(LPCVOID, UINT, D3DXImageInfoCompat*);
using D3DXCreateTextureFromFileInMemoryProc =
    HRESULT (WINAPI*)(
        IDirect3DDevice9*,
        LPCVOID,
        UINT,
        IDirect3DTexture9**);
using D3DXCreateCubeTextureFromFileInMemoryProc =
    HRESULT (WINAPI*)(
        IDirect3DDevice9*,
        LPCVOID,
        UINT,
        IDirect3DCubeTexture9**);
using D3DXSaveSurfaceToFileAProc =
    HRESULT (WINAPI*)(
        const char*,
        int,
        IDirect3DSurface9*,
        const PALETTEENTRY*,
        const RECT*);
using D3DXLoadSurfaceFromSurfaceProc =
    HRESULT (WINAPI*)(
        IDirect3DSurface9*,
        const PALETTEENTRY*,
        const RECT*,
        IDirect3DSurface9*,
        const PALETTEENTRY*,
        const RECT*,
        DWORD,
        D3DCOLOR);

struct SugarbombD3DFormatBridge {
    std::uint32_t guestFormat = 0;
    D3DFORMAT nativeFormat = D3DFMT_UNKNOWN;
};
#endif

struct SugarbombHostD3D9::Impl {
#ifdef _WIN32
    HWND window = nullptr;
    IDirect3D9* direct3D = nullptr;
    IDirect3DDevice9* device = nullptr;
    HMODULE d3dxModule = nullptr;
    D3DXGetImageInfoFromFileInMemoryProc getImageInfo = nullptr;
    D3DXCreateTextureFromFileInMemoryProc createTextureFromMemory = nullptr;
    D3DXCreateCubeTextureFromFileInMemoryProc
        createCubeTextureFromMemory = nullptr;
    D3DXSaveSurfaceToFileAProc saveSurfaceToFile = nullptr;
    D3DXLoadSurfaceFromSurfaceProc loadSurfaceFromSurface = nullptr;
    D3DPRESENT_PARAMETERS presentation = {};
    std::unordered_map<std::uint32_t, IDirect3DSurface9*> surfaces;
    std::unordered_map<std::uint32_t, IDirect3DTexture9*> textures;
    std::unordered_map<std::uint32_t, IDirect3DCubeTexture9*> cubeTextures;
    std::unordered_map<std::uint32_t, SugarbombD3DFormatBridge>
        translatedSurfaceFormats;
    std::unordered_map<std::uint32_t, SugarbombD3DFormatBridge>
        translatedTextureFormats;
    std::unordered_map<std::uint32_t, IDirect3DVertexBuffer9*> vertexBuffers;
    std::unordered_map<std::uint32_t, IDirect3DIndexBuffer9*> indexBuffers;
    std::unordered_map<std::uint32_t, IDirect3DVertexDeclaration9*> declarations;
    std::unordered_map<std::uint32_t, IDirect3DVertexShader9*> vertexShaders;
    std::unordered_map<std::uint32_t, IDirect3DPixelShader9*> pixelShaders;
#endif
    std::uint32_t presentCount = 0;
    std::uint32_t failureCount = 0;
};

#ifdef _WIN32

namespace {

template <typename T>
void releaseObject(T*& object) {
    if (object) {
        object->Release();
        object = nullptr;
    }
}

bool ensureDirect3DInterface(SugarbombHostD3D9::Impl* impl) {
    if (!impl) {
        return false;
    }
    if (impl->direct3D) {
        return true;
    }
    impl->direct3D = Direct3DCreate9(D3D_SDK_VERSION);
    if (!impl->direct3D) {
        std::fprintf(
            stderr,
            "Sugarbomb host D3D9: Direct3DCreate9 returned null\n");
        return false;
    }
    return true;
}

template <typename T>
void releaseMap(std::unordered_map<std::uint32_t, T*>& objects) {
    for (auto& entry : objects) {
        releaseObject(entry.second);
    }
    objects.clear();
}

bool reportFailure(
    SugarbombHostD3D9::Impl* impl,
    const char* operation,
    HRESULT result) {
    if (FAILED(result) && impl->failureCount < 64) {
        std::fprintf(
            stderr,
            "Sugarbomb host D3D9: %s failed with HRESULT 0x%08lX\n",
            operation,
            static_cast<unsigned long>(result));
        ++impl->failureCount;
    }
    return SUCCEEDED(result);
}

SugarbombD3DFormatBridge bridgeTextureFormat(
    std::uint32_t guestFormat) {
    SugarbombD3DFormatBridge bridge;
    bridge.guestFormat = guestFormat;
    bridge.nativeFormat = static_cast<D3DFORMAT>(guestFormat);
    if (bridge.nativeFormat == D3DFMT_R8G8B8) {
        bridge.nativeFormat = D3DFMT_X8R8G8B8;
    }
    return bridge;
}

bool expandsRgb24(const SugarbombD3DFormatBridge* bridge) {
    return bridge &&
        bridge->guestFormat == D3DFMT_R8G8B8 &&
        bridge->nativeFormat == D3DFMT_X8R8G8B8;
}

const SugarbombD3DFormatBridge* findFormatBridge(
    const std::unordered_map<
        std::uint32_t,
        SugarbombD3DFormatBridge>& formats,
    std::uint32_t key) {
    auto found = formats.find(key);
    return found == formats.end() ? nullptr : &found->second;
}

std::uint32_t surfaceRowCount(
    D3DFORMAT format,
    std::uint32_t height) {
    switch (format) {
    case D3DFMT_DXT1:
    case D3DFMT_DXT2:
    case D3DFMT_DXT3:
    case D3DFMT_DXT4:
    case D3DFMT_DXT5:
        return std::max<std::uint32_t>(1, (height + 3) / 4);
    default:
        return height;
    }
}

bool uploadSurfacePixels(
    SugarbombHostD3D9::Impl* impl,
    IDirect3DSurface9* destination,
    const void* pixels,
    std::uint32_t sourcePitch,
    std::uint32_t rowCount,
    const SugarbombD3DFormatBridge* formatBridge,
    const char* operation) {
    if (!impl || !impl->device || !destination ||
        !pixels || !sourcePitch || !rowCount) {
        return false;
    }

    D3DSURFACE_DESC description = {};
    HRESULT result = destination->GetDesc(&description);
    if (!reportFailure(impl, operation, result)) {
        return false;
    }

    IDirect3DSurface9* staging = nullptr;
    IDirect3DSurface9* writable = destination;
    const bool needsStaging =
        description.Pool == D3DPOOL_DEFAULT &&
        !(description.Usage & D3DUSAGE_DYNAMIC);
    if (needsStaging) {
        result = impl->device->CreateOffscreenPlainSurface(
            description.Width,
            description.Height,
            description.Format,
            D3DPOOL_SYSTEMMEM,
            &staging,
            nullptr);
        if (!reportFailure(impl, operation, result)) {
            return false;
        }
        writable = staging;
    }

    D3DLOCKED_RECT locked = {};
    result = writable->LockRect(&locked, nullptr, 0);
    if (!reportFailure(impl, operation, result)) {
        releaseObject(staging);
        return false;
    }
    const std::uint32_t targetPitch =
        static_cast<std::uint32_t>(std::abs(locked.Pitch));
    const std::uint32_t rows =
        std::min<std::uint32_t>(
            rowCount,
            surfaceRowCount(
                description.Format,
                description.Height));
    const auto* source =
        static_cast<const unsigned char*>(pixels);
    auto* target =
        static_cast<unsigned char*>(locked.pBits);
    for (std::uint32_t row = 0; row < rows; ++row) {
        if (expandsRgb24(formatBridge)) {
            const std::uint32_t pixelsInSource = sourcePitch / 3;
            const std::uint32_t pixelsInTarget = targetPitch / 4;
            const std::uint32_t pixelsToCopy =
                std::min<std::uint32_t>(
                    description.Width,
                    std::min(pixelsInSource, pixelsInTarget));
            for (std::uint32_t pixel = 0;
                 pixel < pixelsToCopy;
                 ++pixel) {
                target[pixel * 4] = source[pixel * 3];
                target[pixel * 4 + 1] = source[pixel * 3 + 1];
                target[pixel * 4 + 2] = source[pixel * 3 + 2];
                target[pixel * 4 + 3] = 0xff;
            }
        } else {
            const std::uint32_t copyBytes =
                std::min<std::uint32_t>(sourcePitch, targetPitch);
            std::memcpy(target, source, copyBytes);
        }
        source += sourcePitch;
        target += locked.Pitch;
    }
    result = writable->UnlockRect();
    if (!reportFailure(impl, operation, result)) {
        releaseObject(staging);
        return false;
    }

    if (needsStaging) {
        result = impl->device->UpdateSurface(
            staging,
            nullptr,
            destination,
            nullptr);
        releaseObject(staging);
        if (!reportFailure(impl, operation, result)) {
            return false;
        }
    }
    return true;
}

template <typename T>
T* findObject(
    const std::unordered_map<std::uint32_t, T*>& objects,
    std::uint32_t key) {
    auto found = objects.find(key);
    return found == objects.end() ? nullptr : found->second;
}

IDirect3DBaseTexture9* findTexture(
    SugarbombHostD3D9::Impl* impl,
    std::uint32_t key) {
    if (!key) {
        return nullptr;
    }
    if (IDirect3DTexture9* texture = findObject(impl->textures, key)) {
        return texture;
    }
    return findObject(impl->cubeTextures, key);
}

void releaseDeviceResources(SugarbombHostD3D9::Impl* impl) {
    releaseMap(impl->surfaces);
    releaseMap(impl->textures);
    releaseMap(impl->cubeTextures);
    impl->translatedSurfaceFormats.clear();
    impl->translatedTextureFormats.clear();
    releaseMap(impl->vertexBuffers);
    releaseMap(impl->indexBuffers);
    releaseMap(impl->declarations);
    releaseMap(impl->vertexShaders);
    releaseMap(impl->pixelShaders);
}

} // namespace

#endif

SugarbombHostD3D9::SugarbombHostD3D9() : impl(new Impl()) {
}

SugarbombHostD3D9::~SugarbombHostD3D9() {
    shutdown();
    delete impl;
}

bool SugarbombHostD3D9::queryAdapterIdentifier(
    std::uint32_t adapter,
    std::uint32_t flags,
    void* destination,
    std::size_t byteCount) {
#ifdef _WIN32
    constexpr std::size_t IDENTIFIER_BYTES =
        offsetof(D3DADAPTER_IDENTIFIER9, WHQLLevel) +
        sizeof(DWORD);
    static_assert(IDENTIFIER_BYTES == 1100);
    if (!destination ||
        byteCount < IDENTIFIER_BYTES ||
        !ensureDirect3DInterface(impl)) {
        return false;
    }
    D3DADAPTER_IDENTIFIER9 identifier = {};
    const HRESULT result = impl->direct3D->GetAdapterIdentifier(
        adapter,
        flags,
        &identifier);
    if (!reportFailure(impl, "GetAdapterIdentifier", result)) {
        return false;
    }
    std::memcpy(
        destination,
        &identifier,
        IDENTIFIER_BYTES);
    return true;
#else
    (void)adapter;
    (void)flags;
    (void)destination;
    (void)byteCount;
    return false;
#endif
}

bool SugarbombHostD3D9::queryDeviceCaps(
    std::uint32_t adapter,
    std::uint32_t deviceType,
    void* destination,
    std::size_t byteCount) {
#ifdef _WIN32
    static_assert(sizeof(D3DCAPS9) == 304);
    if (!destination ||
        byteCount < sizeof(D3DCAPS9) ||
        !ensureDirect3DInterface(impl)) {
        return false;
    }
    D3DCAPS9 caps = {};
    const HRESULT result = impl->direct3D->GetDeviceCaps(
        adapter,
        static_cast<D3DDEVTYPE>(deviceType),
        &caps);
    if (!reportFailure(impl, "GetDeviceCaps", result)) {
        return false;
    }
    std::memcpy(destination, &caps, sizeof(caps));
    return true;
#else
    (void)adapter;
    (void)deviceType;
    (void)destination;
    (void)byteCount;
    return false;
#endif
}

bool SugarbombHostD3D9::initialize(
    std::uintptr_t nativeWindow,
    std::uint32_t width,
    std::uint32_t height) {
#ifdef _WIN32
    if (impl->device) {
        return true;
    }
    impl->window = reinterpret_cast<HWND>(nativeWindow);
    if (!impl->window) {
        return false;
    }
    if (!ensureDirect3DInterface(impl)) {
        return false;
    }
    impl->presentation = {};
    impl->presentation.BackBufferWidth = std::max<std::uint32_t>(1, width);
    impl->presentation.BackBufferHeight = std::max<std::uint32_t>(1, height);
    impl->presentation.BackBufferFormat = D3DFMT_X8R8G8B8;
    impl->presentation.BackBufferCount = 1;
    impl->presentation.MultiSampleType = D3DMULTISAMPLE_NONE;
    impl->presentation.SwapEffect = D3DSWAPEFFECT_DISCARD;
    impl->presentation.hDeviceWindow = impl->window;
    impl->presentation.Windowed = TRUE;
    impl->presentation.EnableAutoDepthStencil = FALSE;
    impl->presentation.PresentationInterval = D3DPRESENT_INTERVAL_IMMEDIATE;

    constexpr DWORD hardwareFlags =
        D3DCREATE_HARDWARE_VERTEXPROCESSING |
        D3DCREATE_MULTITHREADED |
        D3DCREATE_FPU_PRESERVE;
    HRESULT result = impl->direct3D->CreateDevice(
        D3DADAPTER_DEFAULT,
        D3DDEVTYPE_HAL,
        impl->window,
        hardwareFlags,
        &impl->presentation,
        &impl->device);
    if (FAILED(result)) {
        constexpr DWORD softwareFlags =
            D3DCREATE_SOFTWARE_VERTEXPROCESSING |
            D3DCREATE_MULTITHREADED |
            D3DCREATE_FPU_PRESERVE;
        result = impl->direct3D->CreateDevice(
            D3DADAPTER_DEFAULT,
            D3DDEVTYPE_HAL,
            impl->window,
            softwareFlags,
            &impl->presentation,
            &impl->device);
    }
    if (!reportFailure(impl, "CreateDevice", result)) {
        return false;
    }
    impl->d3dxModule = LoadLibraryA("d3dx9_38.dll");
    if (impl->d3dxModule) {
        impl->getImageInfo =
            reinterpret_cast<D3DXGetImageInfoFromFileInMemoryProc>(
                GetProcAddress(
                    impl->d3dxModule,
                    "D3DXGetImageInfoFromFileInMemory"));
        impl->createTextureFromMemory =
            reinterpret_cast<D3DXCreateTextureFromFileInMemoryProc>(
                GetProcAddress(
                    impl->d3dxModule,
                    "D3DXCreateTextureFromFileInMemory"));
        impl->createCubeTextureFromMemory =
            reinterpret_cast<D3DXCreateCubeTextureFromFileInMemoryProc>(
                GetProcAddress(
                    impl->d3dxModule,
                    "D3DXCreateCubeTextureFromFileInMemory"));
        impl->saveSurfaceToFile =
            reinterpret_cast<D3DXSaveSurfaceToFileAProc>(
                GetProcAddress(
                    impl->d3dxModule,
                    "D3DXSaveSurfaceToFileA"));
        impl->loadSurfaceFromSurface =
            reinterpret_cast<D3DXLoadSurfaceFromSurfaceProc>(
                GetProcAddress(
                    impl->d3dxModule,
                    "D3DXLoadSurfaceFromSurface"));
    }
    std::printf(
        "Sugarbomb host D3D9: created 64-bit device for %ux%u guest output\n",
        impl->presentation.BackBufferWidth,
        impl->presentation.BackBufferHeight);
    return true;
#else
    (void)nativeWindow;
    (void)width;
    (void)height;
    return false;
#endif
}

bool SugarbombHostD3D9::reset(
    std::uint32_t width,
    std::uint32_t height) {
#ifdef _WIN32
    if (!impl->device) {
        return false;
    }
    releaseDeviceResources(impl);
    impl->presentation.BackBufferWidth = std::max<std::uint32_t>(1, width);
    impl->presentation.BackBufferHeight = std::max<std::uint32_t>(1, height);
    return reportFailure(
        impl,
        "Reset",
        impl->device->Reset(&impl->presentation));
#else
    (void)width;
    (void)height;
    return false;
#endif
}

bool SugarbombHostD3D9::ready() const {
#ifdef _WIN32
    return impl->device != nullptr;
#else
    return false;
#endif
}

void SugarbombHostD3D9::shutdown() {
#ifdef _WIN32
    releaseDeviceResources(impl);
    releaseObject(impl->device);
    releaseObject(impl->direct3D);
    if (impl->d3dxModule) {
        FreeLibrary(impl->d3dxModule);
        impl->d3dxModule = nullptr;
    }
    impl->getImageInfo = nullptr;
    impl->createTextureFromMemory = nullptr;
    impl->createCubeTextureFromMemory = nullptr;
    impl->saveSurfaceToFile = nullptr;
    impl->loadSurfaceFromSurface = nullptr;
    impl->window = nullptr;
#endif
}

bool SugarbombHostD3D9::registerBackBuffer(std::uint32_t guestKey) {
#ifdef _WIN32
    if (!impl->device || !guestKey) {
        return false;
    }
    releaseResource(guestKey);
    IDirect3DSurface9* surface = nullptr;
    HRESULT result = impl->device->GetBackBuffer(
        0,
        0,
        D3DBACKBUFFER_TYPE_MONO,
        &surface);
    if (!reportFailure(impl, "GetBackBuffer", result)) {
        return false;
    }
    impl->surfaces[guestKey] = surface;
    return true;
#else
    (void)guestKey;
    return false;
#endif
}

bool SugarbombHostD3D9::createSurface(
    std::uint32_t guestKey,
    std::uint32_t width,
    std::uint32_t height,
    std::uint32_t format,
    std::uint32_t usage,
    std::uint32_t pool,
    std::uint32_t multiSampleType,
    std::uint32_t multiSampleQuality) {
#ifdef _WIN32
    if (!impl->device || !guestKey || !width || !height) {
        return false;
    }
    releaseResource(guestKey);
    const SugarbombD3DFormatBridge formatBridge =
        bridgeTextureFormat(format);
    IDirect3DSurface9* surface = nullptr;
    HRESULT result = D3DERR_INVALIDCALL;
    if (usage & D3DUSAGE_DEPTHSTENCIL) {
        result = impl->device->CreateDepthStencilSurface(
            width,
            height,
            formatBridge.nativeFormat,
            static_cast<D3DMULTISAMPLE_TYPE>(multiSampleType),
            multiSampleQuality,
            TRUE,
            &surface,
            nullptr);
    } else if (usage & D3DUSAGE_RENDERTARGET) {
        result = impl->device->CreateRenderTarget(
            width,
            height,
            formatBridge.nativeFormat,
            static_cast<D3DMULTISAMPLE_TYPE>(multiSampleType),
            multiSampleQuality,
            FALSE,
            &surface,
            nullptr);
    } else {
        result = impl->device->CreateOffscreenPlainSurface(
            width,
            height,
            formatBridge.nativeFormat,
            static_cast<D3DPOOL>(pool),
            &surface,
            nullptr);
    }
    if (!reportFailure(impl, "CreateSurface", result)) {
        return false;
    }
    impl->surfaces[guestKey] = surface;
    if (formatBridge.guestFormat != formatBridge.nativeFormat) {
        impl->translatedSurfaceFormats[guestKey] = formatBridge;
    }
    return true;
#else
    (void)guestKey;
    (void)width;
    (void)height;
    (void)format;
    (void)usage;
    (void)pool;
    (void)multiSampleType;
    (void)multiSampleQuality;
    return false;
#endif
}

bool SugarbombHostD3D9::aliasTextureSurface(
    std::uint32_t surfaceKey,
    std::uint32_t textureKey,
    std::uint32_t face,
    std::uint32_t level) {
#ifdef _WIN32
    if (!impl->device || !surfaceKey) {
        return false;
    }
    releaseResource(surfaceKey);
    IDirect3DSurface9* surface = nullptr;
    HRESULT result = D3DERR_INVALIDCALL;
    if (IDirect3DTexture9* texture =
            findObject(impl->textures, textureKey)) {
        result = texture->GetSurfaceLevel(level, &surface);
    } else if (IDirect3DCubeTexture9* texture =
                   findObject(impl->cubeTextures, textureKey)) {
        result = texture->GetCubeMapSurface(
            static_cast<D3DCUBEMAP_FACES>(face),
            level,
            &surface);
    }
    if (!reportFailure(impl, "GetTextureSurface", result)) {
        return false;
    }
    impl->surfaces[surfaceKey] = surface;
    const SugarbombD3DFormatBridge* formatBridge =
        findFormatBridge(impl->translatedTextureFormats, textureKey);
    if (formatBridge) {
        impl->translatedSurfaceFormats[surfaceKey] = *formatBridge;
    }
    return true;
#else
    (void)surfaceKey;
    (void)textureKey;
    (void)face;
    (void)level;
    return false;
#endif
}

bool SugarbombHostD3D9::createTexture(
    std::uint32_t guestKey,
    std::uint32_t width,
    std::uint32_t height,
    std::uint32_t levels,
    std::uint32_t usage,
    std::uint32_t format,
    std::uint32_t pool,
    bool cube,
    std::uint32_t* nativeResult) {
#ifdef _WIN32
    if (nativeResult) {
        *nativeResult = static_cast<std::uint32_t>(D3DERR_INVALIDCALL);
    }
    if (!impl->device || !guestKey || !width || !height) {
        return false;
    }
    releaseResource(guestKey);
    const SugarbombD3DFormatBridge formatBridge =
        bridgeTextureFormat(format);
    if (cube) {
        IDirect3DCubeTexture9* texture = nullptr;
        HRESULT result = impl->device->CreateCubeTexture(
            width,
            levels,
            usage,
            formatBridge.nativeFormat,
            static_cast<D3DPOOL>(pool),
            &texture,
            nullptr);
        if (nativeResult) {
            *nativeResult = static_cast<std::uint32_t>(result);
        }
        char operation[256] = {};
        std::snprintf(
            operation,
            sizeof(operation),
            "CreateCubeTexture(key=0x%08X edge=%u levels=%u "
            "usage=0x%08X format=0x%08X nativeFormat=0x%08X pool=%u)",
            guestKey,
            width,
            levels,
            usage,
            format,
            static_cast<std::uint32_t>(formatBridge.nativeFormat),
            pool);
        if (!reportFailure(impl, operation, result)) {
            return false;
        }
        impl->cubeTextures[guestKey] = texture;
        if (formatBridge.guestFormat != formatBridge.nativeFormat) {
            impl->translatedTextureFormats[guestKey] = formatBridge;
        }
        return true;
    }
    IDirect3DTexture9* texture = nullptr;
    HRESULT result = impl->device->CreateTexture(
        width,
        height,
        levels,
        usage,
        formatBridge.nativeFormat,
        static_cast<D3DPOOL>(pool),
        &texture,
        nullptr);
    if (nativeResult) {
        *nativeResult = static_cast<std::uint32_t>(result);
    }
    char operation[256] = {};
    std::snprintf(
        operation,
        sizeof(operation),
        "CreateTexture(key=0x%08X size=%ux%u levels=%u "
        "usage=0x%08X format=0x%08X nativeFormat=0x%08X pool=%u)",
        guestKey,
        width,
        height,
        levels,
        usage,
        format,
        static_cast<std::uint32_t>(formatBridge.nativeFormat),
        pool);
    if (!reportFailure(impl, operation, result)) {
        return false;
    }
    impl->textures[guestKey] = texture;
    if (formatBridge.guestFormat != formatBridge.nativeFormat) {
        impl->translatedTextureFormats[guestKey] = formatBridge;
    }
    return true;
#else
    (void)guestKey;
    (void)width;
    (void)height;
    (void)levels;
    (void)usage;
    (void)format;
    (void)pool;
    (void)cube;
    if (nativeResult) {
        *nativeResult = 0x8876086c;
    }
    return false;
#endif
}

bool SugarbombHostD3D9::createBuffer(
    std::uint32_t guestKey,
    std::uint32_t length,
    std::uint32_t usage,
    std::uint32_t format,
    std::uint32_t pool,
    bool indexBuffer,
    std::uint32_t* nativeResult) {
#ifdef _WIN32
    if (nativeResult) {
        *nativeResult = static_cast<std::uint32_t>(D3DERR_INVALIDCALL);
    }
    if (!impl->device || !guestKey || !length) {
        return false;
    }
    releaseResource(guestKey);
    if (indexBuffer) {
        IDirect3DIndexBuffer9* buffer = nullptr;
        HRESULT result = impl->device->CreateIndexBuffer(
            length,
            usage,
            static_cast<D3DFORMAT>(format),
            static_cast<D3DPOOL>(pool),
            &buffer,
            nullptr);
        if (nativeResult) {
            *nativeResult = static_cast<std::uint32_t>(result);
        }
        if (!reportFailure(impl, "CreateIndexBuffer", result)) {
            return false;
        }
        impl->indexBuffers[guestKey] = buffer;
        return true;
    }
    IDirect3DVertexBuffer9* buffer = nullptr;
    HRESULT result = impl->device->CreateVertexBuffer(
        length,
        usage,
        0,
        static_cast<D3DPOOL>(pool),
        &buffer,
        nullptr);
    if (nativeResult) {
        *nativeResult = static_cast<std::uint32_t>(result);
    }
    if (!reportFailure(impl, "CreateVertexBuffer", result)) {
        return false;
    }
    impl->vertexBuffers[guestKey] = buffer;
    return true;
#else
    (void)guestKey;
    (void)length;
    (void)usage;
    (void)format;
    (void)pool;
    (void)indexBuffer;
    if (nativeResult) {
        *nativeResult = 0x8876086c;
    }
    return false;
#endif
}

bool SugarbombHostD3D9::createVertexDeclaration(
    std::uint32_t guestKey,
    const void* elements,
    std::size_t byteCount) {
#ifdef _WIN32
    if (!impl->device || !guestKey || !elements ||
        byteCount < sizeof(D3DVERTEXELEMENT9)) {
        return false;
    }
    releaseResource(guestKey);
    IDirect3DVertexDeclaration9* declaration = nullptr;
    HRESULT result = impl->device->CreateVertexDeclaration(
        static_cast<const D3DVERTEXELEMENT9*>(elements),
        &declaration);
    if (!reportFailure(impl, "CreateVertexDeclaration", result)) {
        return false;
    }
    impl->declarations[guestKey] = declaration;
    return true;
#else
    (void)guestKey;
    (void)elements;
    (void)byteCount;
    return false;
#endif
}

bool SugarbombHostD3D9::createShader(
    std::uint32_t guestKey,
    bool pixelShader,
    const std::uint32_t* bytecode,
    std::size_t dwordCount) {
#ifdef _WIN32
    if (!impl->device || !guestKey || !bytecode || dwordCount < 2) {
        return false;
    }
    releaseResource(guestKey);
    if (pixelShader) {
        IDirect3DPixelShader9* shader = nullptr;
        HRESULT result = impl->device->CreatePixelShader(
            reinterpret_cast<const DWORD*>(bytecode),
            &shader);
        if (!reportFailure(impl, "CreatePixelShader", result)) {
            return false;
        }
        impl->pixelShaders[guestKey] = shader;
        return true;
    }
    IDirect3DVertexShader9* shader = nullptr;
    HRESULT result = impl->device->CreateVertexShader(
        reinterpret_cast<const DWORD*>(bytecode),
        &shader);
    if (!reportFailure(impl, "CreateVertexShader", result)) {
        return false;
    }
    impl->vertexShaders[guestKey] = shader;
    return true;
#else
    (void)guestKey;
    (void)pixelShader;
    (void)bytecode;
    (void)dwordCount;
    return false;
#endif
}

bool SugarbombHostD3D9::getImageInfoFromMemory(
    const void* bytes,
    std::uint32_t byteCount,
    SugarbombHostD3DImageInfo& info) {
#ifdef _WIN32
    if (!impl->getImageInfo || !bytes || !byteCount) {
        return false;
    }
    D3DXImageInfoCompat nativeInfo = {};
    HRESULT result = impl->getImageInfo(
        bytes,
        byteCount,
        &nativeInfo);
    if (!reportFailure(impl, "D3DXGetImageInfoFromFileInMemory", result)) {
        return false;
    }
    info.width = nativeInfo.width;
    info.height = nativeInfo.height;
    info.depth = nativeInfo.depth;
    info.mipLevels = nativeInfo.mipLevels;
    info.format = static_cast<std::uint32_t>(nativeInfo.format);
    info.resourceType =
        static_cast<std::uint32_t>(nativeInfo.resourceType);
    info.fileFormat = nativeInfo.fileFormat;
    return true;
#else
    (void)bytes;
    (void)byteCount;
    (void)info;
    return false;
#endif
}

bool SugarbombHostD3D9::createTextureFromMemory(
    std::uint32_t guestKey,
    const void* bytes,
    std::uint32_t byteCount,
    bool cube) {
#ifdef _WIN32
    if (!impl->device || !guestKey || !bytes || !byteCount) {
        return false;
    }
    releaseResource(guestKey);
    if (cube) {
        if (!impl->createCubeTextureFromMemory) {
            return false;
        }
        IDirect3DCubeTexture9* texture = nullptr;
        HRESULT result = impl->createCubeTextureFromMemory(
            impl->device,
            bytes,
            byteCount,
            &texture);
        if (!reportFailure(
                impl,
                "D3DXCreateCubeTextureFromFileInMemory",
                result)) {
            return false;
        }
        impl->cubeTextures[guestKey] = texture;
        return true;
    }
    if (!impl->createTextureFromMemory) {
        return false;
    }
    IDirect3DTexture9* texture = nullptr;
    HRESULT result = impl->createTextureFromMemory(
        impl->device,
        bytes,
        byteCount,
        &texture);
    if (!reportFailure(
            impl,
            "D3DXCreateTextureFromFileInMemory",
            result)) {
        return false;
    }
    impl->textures[guestKey] = texture;
    return true;
#else
    (void)guestKey;
    (void)bytes;
    (void)byteCount;
    (void)cube;
    return false;
#endif
}

bool SugarbombHostD3D9::captureRenderTarget(const char* path) {
#ifdef _WIN32
    if (!impl->device ||
        !impl->saveSurfaceToFile ||
        !path ||
        !*path) {
        return false;
    }
    IDirect3DSurface9* renderTarget = nullptr;
    HRESULT result = impl->device->GetRenderTarget(0, &renderTarget);
    if (!reportFailure(impl, "GetRenderTarget(capture)", result)) {
        return false;
    }
    constexpr int D3DXIFF_PNG = 3;
    result = impl->saveSurfaceToFile(
        path,
        D3DXIFF_PNG,
        renderTarget,
        nullptr,
        nullptr);
    releaseObject(renderTarget);
    if (!reportFailure(impl, "D3DXSaveSurfaceToFileA", result)) {
        return false;
    }
    std::printf(
        "Sugarbomb host D3D9: captured translated render target to %s\n",
        path);
    return true;
#else
    (void)path;
    return false;
#endif
}

bool SugarbombHostD3D9::captureBackBuffer(const char* path) {
#ifdef _WIN32
    if (!impl->device ||
        !impl->saveSurfaceToFile ||
        !path ||
        !*path) {
        return false;
    }
    IDirect3DSurface9* backBuffer = nullptr;
    HRESULT result = impl->device->GetBackBuffer(
        0,
        0,
        D3DBACKBUFFER_TYPE_MONO,
        &backBuffer);
    if (!reportFailure(impl, "GetBackBuffer(capture)", result)) {
        return false;
    }
    constexpr int D3DXIFF_PNG = 3;
    result = impl->saveSurfaceToFile(
        path,
        D3DXIFF_PNG,
        backBuffer,
        nullptr,
        nullptr);
    releaseObject(backBuffer);
    if (!reportFailure(impl, "D3DXSaveSurfaceToFileA(backbuffer)", result)) {
        return false;
    }
    std::printf(
        "Sugarbomb host D3D9: captured translated backbuffer to %s\n",
        path);
    return true;
#else
    (void)path;
    return false;
#endif
}

void SugarbombHostD3D9::releaseResource(std::uint32_t guestKey) {
#ifdef _WIN32
    impl->translatedSurfaceFormats.erase(guestKey);
    impl->translatedTextureFormats.erase(guestKey);
#define RELEASE_GUEST_OBJECT(objects) \
    do { \
        auto found = impl->objects.find(guestKey); \
        if (found != impl->objects.end()) { \
            releaseObject(found->second); \
            impl->objects.erase(found); \
            return; \
        } \
    } while (false)
    RELEASE_GUEST_OBJECT(surfaces);
    RELEASE_GUEST_OBJECT(textures);
    RELEASE_GUEST_OBJECT(cubeTextures);
    RELEASE_GUEST_OBJECT(vertexBuffers);
    RELEASE_GUEST_OBJECT(indexBuffers);
    RELEASE_GUEST_OBJECT(declarations);
    RELEASE_GUEST_OBJECT(vertexShaders);
    RELEASE_GUEST_OBJECT(pixelShaders);
#undef RELEASE_GUEST_OBJECT
#else
    (void)guestKey;
#endif
}

bool SugarbombHostD3D9::uploadSurface(
    std::uint32_t guestKey,
    const void* pixels,
    std::uint32_t sourcePitch,
    std::uint32_t width,
    std::uint32_t height) {
#ifdef _WIN32
    IDirect3DSurface9* surface = findObject(impl->surfaces, guestKey);
    if (!surface || !pixels || !sourcePitch || !width || !height) {
        return false;
    }
    char operation[192] = {};
    std::snprintf(
        operation,
        sizeof(operation),
        "upload surface(key=0x%08X size=%ux%u pitch=%u rows=%u)",
        guestKey,
        width,
        height,
        sourcePitch,
        height);
    return uploadSurfacePixels(
        impl,
        surface,
        pixels,
        sourcePitch,
        height,
        findFormatBridge(impl->translatedSurfaceFormats, guestKey),
        operation);
#else
    (void)guestKey;
    (void)pixels;
    (void)sourcePitch;
    (void)width;
    (void)height;
    return false;
#endif
}

bool SugarbombHostD3D9::uploadTexture(
    std::uint32_t guestKey,
    std::uint32_t face,
    std::uint32_t level,
    const void* pixels,
    std::uint32_t sourcePitch,
    std::uint32_t rowCount) {
#ifdef _WIN32
    if (!pixels || !sourcePitch || !rowCount) {
        return false;
    }
    HRESULT result = D3DERR_INVALIDCALL;
    IDirect3DSurface9* surface = nullptr;
    IDirect3DTexture9* texture = findObject(impl->textures, guestKey);
    IDirect3DCubeTexture9* cubeTexture =
        findObject(impl->cubeTextures, guestKey);
    if (texture) {
        result = texture->GetSurfaceLevel(level, &surface);
    } else if (cubeTexture) {
        result = cubeTexture->GetCubeMapSurface(
            static_cast<D3DCUBEMAP_FACES>(face),
            level,
            &surface);
    }
    char operation[224] = {};
    std::snprintf(
        operation,
        sizeof(operation),
        "upload texture(key=0x%08X face=%u level=%u "
        "pitch=%u rows=%u)",
        guestKey,
        face,
        level,
        sourcePitch,
        rowCount);
    if (!reportFailure(impl, operation, result)) {
        return false;
    }
    const bool uploaded = uploadSurfacePixels(
        impl,
        surface,
        pixels,
        sourcePitch,
        rowCount,
        findFormatBridge(impl->translatedTextureFormats, guestKey),
        operation);
    releaseObject(surface);
    return uploaded;
#else
    (void)guestKey;
    (void)face;
    (void)level;
    (void)pixels;
    (void)sourcePitch;
    (void)rowCount;
    return false;
#endif
}

bool SugarbombHostD3D9::uploadBuffer(
    std::uint32_t guestKey,
    const void* bytes,
    std::uint32_t offset,
    std::uint32_t byteCount) {
#ifdef _WIN32
    if (!bytes || !byteCount) {
        return false;
    }
    void* destination = nullptr;
    HRESULT result = D3DERR_INVALIDCALL;
    IDirect3DVertexBuffer9* vertexBuffer =
        findObject(impl->vertexBuffers, guestKey);
    IDirect3DIndexBuffer9* indexBuffer =
        findObject(impl->indexBuffers, guestKey);
    if (vertexBuffer) {
        result = vertexBuffer->Lock(
            offset,
            byteCount,
            &destination,
            0);
    } else if (indexBuffer) {
        result = indexBuffer->Lock(
            offset,
            byteCount,
            &destination,
            0);
    }
    if (!reportFailure(impl, "Buffer::Lock", result)) {
        return false;
    }
    std::memcpy(destination, bytes, byteCount);
    if (vertexBuffer) {
        vertexBuffer->Unlock();
    } else {
        indexBuffer->Unlock();
    }
    return true;
#else
    (void)guestKey;
    (void)bytes;
    (void)offset;
    (void)byteCount;
    return false;
#endif
}

bool SugarbombHostD3D9::updateSurface(
    std::uint32_t sourceKey,
    const void* sourceRectangle,
    std::uint32_t destinationKey,
    const void* destinationPoint) {
#ifdef _WIN32
    IDirect3DSurface9* source =
        findObject(impl->surfaces, sourceKey);
    IDirect3DSurface9* destination =
        findObject(impl->surfaces, destinationKey);
    return impl->device &&
        source &&
        destination &&
        reportFailure(
            impl,
            "UpdateSurface",
            impl->device->UpdateSurface(
                source,
                static_cast<const RECT*>(sourceRectangle),
                destination,
                static_cast<const POINT*>(destinationPoint)));
#else
    (void)sourceKey;
    (void)sourceRectangle;
    (void)destinationKey;
    (void)destinationPoint;
    return false;
#endif
}

bool SugarbombHostD3D9::updateTexture(
    std::uint32_t sourceKey,
    std::uint32_t destinationKey) {
#ifdef _WIN32
    IDirect3DBaseTexture9* source =
        findObject(impl->textures, sourceKey);
    IDirect3DBaseTexture9* destination =
        findObject(impl->textures, destinationKey);
    if (!source || !destination) {
        source = findObject(impl->cubeTextures, sourceKey);
        destination = findObject(impl->cubeTextures, destinationKey);
    }
    return impl->device &&
        source &&
        destination &&
        reportFailure(
            impl,
            "UpdateTexture",
            impl->device->UpdateTexture(source, destination));
#else
    (void)sourceKey;
    (void)destinationKey;
    return false;
#endif
}

bool SugarbombHostD3D9::getRenderTargetData(
    std::uint32_t sourceKey,
    std::uint32_t destinationKey) {
#ifdef _WIN32
    IDirect3DSurface9* source =
        findObject(impl->surfaces, sourceKey);
    IDirect3DSurface9* destination =
        findObject(impl->surfaces, destinationKey);
    return impl->device &&
        source &&
        destination &&
        reportFailure(
            impl,
            "GetRenderTargetData",
            impl->device->GetRenderTargetData(source, destination));
#else
    (void)sourceKey;
    (void)destinationKey;
    return false;
#endif
}

bool SugarbombHostD3D9::stretchRect(
    std::uint32_t sourceKey,
    const void* sourceRectangle,
    std::uint32_t destinationKey,
    const void* destinationRectangle,
    std::uint32_t filter) {
#ifdef _WIN32
    IDirect3DSurface9* source =
        findObject(impl->surfaces, sourceKey);
    IDirect3DSurface9* destination =
        findObject(impl->surfaces, destinationKey);
    return impl->device &&
        source &&
        destination &&
        reportFailure(
            impl,
            "StretchRect",
            impl->device->StretchRect(
                source,
                static_cast<const RECT*>(sourceRectangle),
                destination,
                static_cast<const RECT*>(destinationRectangle),
                static_cast<D3DTEXTUREFILTERTYPE>(filter)));
#else
    (void)sourceKey;
    (void)sourceRectangle;
    (void)destinationKey;
    (void)destinationRectangle;
    (void)filter;
    return false;
#endif
}

bool SugarbombHostD3D9::colorFill(
    std::uint32_t surfaceKey,
    const void* rectangle,
    std::uint32_t color) {
#ifdef _WIN32
    IDirect3DSurface9* surface =
        findObject(impl->surfaces, surfaceKey);
    return impl->device &&
        surface &&
        reportFailure(
            impl,
            "ColorFill",
            impl->device->ColorFill(
                surface,
                static_cast<const RECT*>(rectangle),
                color));
#else
    (void)surfaceKey;
    (void)rectangle;
    (void)color;
    return false;
#endif
}

bool SugarbombHostD3D9::loadSurfaceFromSurface(
    std::uint32_t destinationKey,
    const void* destinationRectangle,
    std::uint32_t sourceKey,
    const void* sourceRectangle,
    std::uint32_t filter,
    std::uint32_t colorKey) {
#ifdef _WIN32
    IDirect3DSurface9* source =
        findObject(impl->surfaces, sourceKey);
    IDirect3DSurface9* destination =
        findObject(impl->surfaces, destinationKey);
    return impl->loadSurfaceFromSurface &&
        source &&
        destination &&
        reportFailure(
            impl,
            "D3DXLoadSurfaceFromSurface",
            impl->loadSurfaceFromSurface(
                destination,
                nullptr,
                static_cast<const RECT*>(destinationRectangle),
                source,
                nullptr,
                static_cast<const RECT*>(sourceRectangle),
                filter,
                colorKey));
#else
    (void)destinationKey;
    (void)destinationRectangle;
    (void)sourceKey;
    (void)sourceRectangle;
    (void)filter;
    (void)colorKey;
    return false;
#endif
}

bool SugarbombHostD3D9::beginScene() {
#ifdef _WIN32
    return impl->device &&
        reportFailure(impl, "BeginScene", impl->device->BeginScene());
#else
    return false;
#endif
}

bool SugarbombHostD3D9::endScene() {
#ifdef _WIN32
    return impl->device &&
        reportFailure(impl, "EndScene", impl->device->EndScene());
#else
    return false;
#endif
}

bool SugarbombHostD3D9::clear(
    std::uint32_t count,
    const void* rectangles,
    std::uint32_t flags,
    std::uint32_t color,
    float depth,
    std::uint32_t stencil) {
#ifdef _WIN32
    return impl->device &&
        reportFailure(
            impl,
            "Clear",
            impl->device->Clear(
                count,
                static_cast<const D3DRECT*>(rectangles),
                flags,
                color,
                depth,
                stencil));
#else
    (void)count;
    (void)rectangles;
    (void)flags;
    (void)color;
    (void)depth;
    (void)stencil;
    return false;
#endif
}

bool SugarbombHostD3D9::present() {
#ifdef _WIN32
    if (!impl->device ||
        !reportFailure(
            impl,
            "Present",
            impl->device->Present(nullptr, nullptr, nullptr, nullptr))) {
        return false;
    }
    ++impl->presentCount;
    if (impl->presentCount == 1) {
        std::printf(
            "Sugarbomb host D3D9: first translated frame presented\n");
    }
    return true;
#else
    return false;
#endif
}

bool SugarbombHostD3D9::setCursorProperties(
    std::uint32_t hotX,
    std::uint32_t hotY,
    std::uint32_t surfaceKey) {
#ifdef _WIN32
    IDirect3DSurface9* surface =
        findObject(impl->surfaces, surfaceKey);
    return impl->device &&
        surface &&
        reportFailure(
            impl,
            "SetCursorProperties",
            impl->device->SetCursorProperties(hotX, hotY, surface));
#else
    (void)hotX;
    (void)hotY;
    (void)surfaceKey;
    return false;
#endif
}

void SugarbombHostD3D9::setCursorPosition(
    std::int32_t screenX,
    std::int32_t screenY,
    std::uint32_t flags) {
#ifdef _WIN32
    if (impl->device) {
        impl->device->SetCursorPosition(screenX, screenY, flags);
    }
#else
    (void)screenX;
    (void)screenY;
    (void)flags;
#endif
}

bool SugarbombHostD3D9::showCursor(bool visible) {
#ifdef _WIN32
    return impl->device &&
        impl->device->ShowCursor(visible ? TRUE : FALSE) != FALSE;
#else
    (void)visible;
    return false;
#endif
}

bool SugarbombHostD3D9::setRenderTarget(
    std::uint32_t index,
    std::uint32_t surfaceKey) {
#ifdef _WIN32
    IDirect3DSurface9* surface =
        surfaceKey ? findObject(impl->surfaces, surfaceKey) : nullptr;
    return impl->device &&
        (!surfaceKey || surface) &&
        reportFailure(
            impl,
            "SetRenderTarget",
            impl->device->SetRenderTarget(index, surface));
#else
    (void)index;
    (void)surfaceKey;
    return false;
#endif
}

bool SugarbombHostD3D9::setDepthStencilSurface(std::uint32_t surfaceKey) {
#ifdef _WIN32
    IDirect3DSurface9* surface =
        surfaceKey ? findObject(impl->surfaces, surfaceKey) : nullptr;
    return impl->device &&
        (!surfaceKey || surface) &&
        reportFailure(
            impl,
            "SetDepthStencilSurface",
            impl->device->SetDepthStencilSurface(surface));
#else
    (void)surfaceKey;
    return false;
#endif
}

bool SugarbombHostD3D9::setViewport(const void* viewport) {
#ifdef _WIN32
    return impl->device && viewport &&
        reportFailure(
            impl,
            "SetViewport",
            impl->device->SetViewport(
                static_cast<const D3DVIEWPORT9*>(viewport)));
#else
    (void)viewport;
    return false;
#endif
}

bool SugarbombHostD3D9::setTransform(
    std::uint32_t state,
    const float* matrix) {
#ifdef _WIN32
    return impl->device && matrix &&
        reportFailure(
            impl,
            "SetTransform",
            impl->device->SetTransform(
                static_cast<D3DTRANSFORMSTATETYPE>(state),
                reinterpret_cast<const D3DMATRIX*>(matrix)));
#else
    (void)state;
    (void)matrix;
    return false;
#endif
}

bool SugarbombHostD3D9::setRenderState(
    std::uint32_t state,
    std::uint32_t value) {
#ifdef _WIN32
    return impl->device &&
        reportFailure(
            impl,
            "SetRenderState",
            impl->device->SetRenderState(
                static_cast<D3DRENDERSTATETYPE>(state),
                value));
#else
    (void)state;
    (void)value;
    return false;
#endif
}

bool SugarbombHostD3D9::setTexture(
    std::uint32_t stage,
    std::uint32_t textureKey) {
#ifdef _WIN32
    IDirect3DBaseTexture9* texture = findTexture(impl, textureKey);
    return impl->device &&
        (!textureKey || texture) &&
        reportFailure(
            impl,
            "SetTexture",
            impl->device->SetTexture(stage, texture));
#else
    (void)stage;
    (void)textureKey;
    return false;
#endif
}

bool SugarbombHostD3D9::setTextureStageState(
    std::uint32_t stage,
    std::uint32_t state,
    std::uint32_t value) {
#ifdef _WIN32
    return impl->device &&
        reportFailure(
            impl,
            "SetTextureStageState",
            impl->device->SetTextureStageState(
                stage,
                static_cast<D3DTEXTURESTAGESTATETYPE>(state),
                value));
#else
    (void)stage;
    (void)state;
    (void)value;
    return false;
#endif
}

bool SugarbombHostD3D9::setSamplerState(
    std::uint32_t sampler,
    std::uint32_t state,
    std::uint32_t value) {
#ifdef _WIN32
    return impl->device &&
        reportFailure(
            impl,
            "SetSamplerState",
            impl->device->SetSamplerState(
                sampler,
                static_cast<D3DSAMPLERSTATETYPE>(state),
                value));
#else
    (void)sampler;
    (void)state;
    (void)value;
    return false;
#endif
}

bool SugarbombHostD3D9::setScissorRect(const void* rectangle) {
#ifdef _WIN32
    return impl->device && rectangle &&
        reportFailure(
            impl,
            "SetScissorRect",
            impl->device->SetScissorRect(
                static_cast<const RECT*>(rectangle)));
#else
    (void)rectangle;
    return false;
#endif
}

bool SugarbombHostD3D9::setVertexDeclaration(std::uint32_t guestKey) {
#ifdef _WIN32
    IDirect3DVertexDeclaration9* declaration =
        guestKey ? findObject(impl->declarations, guestKey) : nullptr;
    return impl->device &&
        (!guestKey || declaration) &&
        reportFailure(
            impl,
            "SetVertexDeclaration",
            impl->device->SetVertexDeclaration(declaration));
#else
    (void)guestKey;
    return false;
#endif
}

bool SugarbombHostD3D9::setFvf(std::uint32_t fvf) {
#ifdef _WIN32
    return impl->device &&
        reportFailure(impl, "SetFVF", impl->device->SetFVF(fvf));
#else
    (void)fvf;
    return false;
#endif
}

bool SugarbombHostD3D9::setVertexShader(std::uint32_t guestKey) {
#ifdef _WIN32
    IDirect3DVertexShader9* shader =
        guestKey ? findObject(impl->vertexShaders, guestKey) : nullptr;
    return impl->device &&
        (!guestKey || shader) &&
        reportFailure(
            impl,
            "SetVertexShader",
            impl->device->SetVertexShader(shader));
#else
    (void)guestKey;
    return false;
#endif
}

bool SugarbombHostD3D9::setPixelShader(std::uint32_t guestKey) {
#ifdef _WIN32
    IDirect3DPixelShader9* shader =
        guestKey ? findObject(impl->pixelShaders, guestKey) : nullptr;
    return impl->device &&
        (!guestKey || shader) &&
        reportFailure(
            impl,
            "SetPixelShader",
            impl->device->SetPixelShader(shader));
#else
    (void)guestKey;
    return false;
#endif
}

#define DEFINE_SHADER_CONSTANT_METHOD(methodName, nativeName, valueType) \
    bool SugarbombHostD3D9::methodName( \
        std::uint32_t startRegister, \
        const valueType* values, \
        std::uint32_t count) { \
    /* The platform guard keeps D3D headers out of non-Windows builds. */ \
    (void)startRegister; \
    (void)values; \
    (void)count; \
    /* body supplied below */ \
    return false; \
    }

#ifdef _WIN32

bool SugarbombHostD3D9::setVertexShaderConstantF(
    std::uint32_t startRegister,
    const float* values,
    std::uint32_t vectorCount) {
    return impl->device && values &&
        reportFailure(
            impl,
            "SetVertexShaderConstantF",
            impl->device->SetVertexShaderConstantF(
                startRegister,
                values,
                vectorCount));
}

bool SugarbombHostD3D9::setVertexShaderConstantI(
    std::uint32_t startRegister,
    const std::int32_t* values,
    std::uint32_t vectorCount) {
    return impl->device && values &&
        reportFailure(
            impl,
            "SetVertexShaderConstantI",
            impl->device->SetVertexShaderConstantI(
                startRegister,
                reinterpret_cast<const int*>(values),
                vectorCount));
}

bool SugarbombHostD3D9::setVertexShaderConstantB(
    std::uint32_t startRegister,
    const std::int32_t* values,
    std::uint32_t valueCount) {
    return impl->device && values &&
        reportFailure(
            impl,
            "SetVertexShaderConstantB",
            impl->device->SetVertexShaderConstantB(
                startRegister,
                reinterpret_cast<const BOOL*>(values),
                valueCount));
}

bool SugarbombHostD3D9::setPixelShaderConstantF(
    std::uint32_t startRegister,
    const float* values,
    std::uint32_t vectorCount) {
    return impl->device && values &&
        reportFailure(
            impl,
            "SetPixelShaderConstantF",
            impl->device->SetPixelShaderConstantF(
                startRegister,
                values,
                vectorCount));
}

bool SugarbombHostD3D9::setPixelShaderConstantI(
    std::uint32_t startRegister,
    const std::int32_t* values,
    std::uint32_t vectorCount) {
    return impl->device && values &&
        reportFailure(
            impl,
            "SetPixelShaderConstantI",
            impl->device->SetPixelShaderConstantI(
                startRegister,
                reinterpret_cast<const int*>(values),
                vectorCount));
}

bool SugarbombHostD3D9::setPixelShaderConstantB(
    std::uint32_t startRegister,
    const std::int32_t* values,
    std::uint32_t valueCount) {
    return impl->device && values &&
        reportFailure(
            impl,
            "SetPixelShaderConstantB",
            impl->device->SetPixelShaderConstantB(
                startRegister,
                reinterpret_cast<const BOOL*>(values),
                valueCount));
}

#else

DEFINE_SHADER_CONSTANT_METHOD(setVertexShaderConstantF, unused, float)
DEFINE_SHADER_CONSTANT_METHOD(setVertexShaderConstantI, unused, std::int32_t)
DEFINE_SHADER_CONSTANT_METHOD(setVertexShaderConstantB, unused, std::int32_t)
DEFINE_SHADER_CONSTANT_METHOD(setPixelShaderConstantF, unused, float)
DEFINE_SHADER_CONSTANT_METHOD(setPixelShaderConstantI, unused, std::int32_t)
DEFINE_SHADER_CONSTANT_METHOD(setPixelShaderConstantB, unused, std::int32_t)

#endif

#undef DEFINE_SHADER_CONSTANT_METHOD

bool SugarbombHostD3D9::setStreamSource(
    std::uint32_t stream,
    std::uint32_t bufferKey,
    std::uint32_t offset,
    std::uint32_t stride) {
#ifdef _WIN32
    IDirect3DVertexBuffer9* buffer =
        bufferKey ? findObject(impl->vertexBuffers, bufferKey) : nullptr;
    return impl->device &&
        (!bufferKey || buffer) &&
        reportFailure(
            impl,
            "SetStreamSource",
            impl->device->SetStreamSource(
                stream,
                buffer,
                offset,
                stride));
#else
    (void)stream;
    (void)bufferKey;
    (void)offset;
    (void)stride;
    return false;
#endif
}

bool SugarbombHostD3D9::setStreamSourceFrequency(
    std::uint32_t stream,
    std::uint32_t setting) {
#ifdef _WIN32
    return impl->device &&
        reportFailure(
            impl,
            "SetStreamSourceFreq",
            impl->device->SetStreamSourceFreq(stream, setting));
#else
    (void)stream;
    (void)setting;
    return false;
#endif
}

bool SugarbombHostD3D9::setIndices(std::uint32_t bufferKey) {
#ifdef _WIN32
    IDirect3DIndexBuffer9* buffer =
        bufferKey ? findObject(impl->indexBuffers, bufferKey) : nullptr;
    return impl->device &&
        (!bufferKey || buffer) &&
        reportFailure(
            impl,
            "SetIndices",
            impl->device->SetIndices(buffer));
#else
    (void)bufferKey;
    return false;
#endif
}

bool SugarbombHostD3D9::drawPrimitive(
    std::uint32_t primitiveType,
    std::uint32_t startVertex,
    std::uint32_t primitiveCount) {
#ifdef _WIN32
    return impl->device &&
        reportFailure(
            impl,
            "DrawPrimitive",
            impl->device->DrawPrimitive(
                static_cast<D3DPRIMITIVETYPE>(primitiveType),
                startVertex,
                primitiveCount));
#else
    (void)primitiveType;
    (void)startVertex;
    (void)primitiveCount;
    return false;
#endif
}

bool SugarbombHostD3D9::drawIndexedPrimitive(
    std::uint32_t primitiveType,
    std::int32_t baseVertexIndex,
    std::uint32_t minimumVertexIndex,
    std::uint32_t vertexCount,
    std::uint32_t startIndex,
    std::uint32_t primitiveCount) {
#ifdef _WIN32
    return impl->device &&
        reportFailure(
            impl,
            "DrawIndexedPrimitive",
            impl->device->DrawIndexedPrimitive(
                static_cast<D3DPRIMITIVETYPE>(primitiveType),
                baseVertexIndex,
                minimumVertexIndex,
                vertexCount,
                startIndex,
                primitiveCount));
#else
    (void)primitiveType;
    (void)baseVertexIndex;
    (void)minimumVertexIndex;
    (void)vertexCount;
    (void)startIndex;
    (void)primitiveCount;
    return false;
#endif
}
