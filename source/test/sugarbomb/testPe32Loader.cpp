/*
 *  Copyright (C) 2026  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "boxedwine.h"

#ifdef __TEST

#include "pe32loader.h"
#include "sugarbombbridge.h"
#include "../../sugarbomb/sugarbombhostd3d9.h"
#include "../../sugarbomb/sugarbombhostwindow.h"
#include "../cpu/testCPU.h"
#include "testPe32Loader.h"

#include <algorithm>

#ifdef _WIN32
#include <Windows.h>
#endif

namespace {

constexpr U32 TEST_IMAGE_BASE = 0x00400000;
constexpr U32 TEST_RELOCATED_BASE = 0x00600000;
constexpr U32 TEST_ENTRY_RVA = 0x00001000;
constexpr U32 TEST_ENTRY_RESULT = 0x12345678;
constexpr U32 TEST_BRIDGE_RESULT = 0x53425547;
constexpr U32 TEST_BRIDGE_SKIPPED_RESULT = 0x0badc0de;
constexpr U32 TEST_BRIDGE_TRANSFER_RESULT = 0x74726170;
constexpr U32 TEST_BRIDGE_TRANSFER_TARGET = 15;
constexpr U32 TEST_IMPORT_ADDRESS = 0x70001000;
constexpr U32 TEST_THUNK_BASE = 0x60000000;

void writeU16(std::vector<U8>& bytes, size_t offset, U16 value) {
    bytes[offset] = static_cast<U8>(value);
    bytes[offset + 1] = static_cast<U8>(value >> 8);
}

void writeU32(std::vector<U8>& bytes, size_t offset, U32 value) {
    bytes[offset] = static_cast<U8>(value);
    bytes[offset + 1] = static_cast<U8>(value >> 8);
    bytes[offset + 2] = static_cast<U8>(value >> 16);
    bytes[offset + 3] = static_cast<U8>(value >> 24);
}

void writeString(std::vector<U8>& bytes, size_t offset, const char* value) {
    while (*value) {
        bytes[offset++] = static_cast<U8>(*value++);
    }
    bytes[offset] = 0;
}

std::vector<U8> createTestPe32() {
    std::vector<U8> bytes(0x600, 0);
    writeU16(bytes, 0, 0x5a4d);
    writeU32(bytes, 0x3c, 0x80);

    const size_t pe = 0x80;
    writeU32(bytes, pe, 0x00004550);
    writeU16(bytes, pe + 4, 0x014c);
    writeU16(bytes, pe + 6, 2);
    writeU32(bytes, pe + 8, 0x12345678);
    writeU16(bytes, pe + 20, 0x00e0);
    writeU16(bytes, pe + 22, 0x0102);

    const size_t optional = pe + 24;
    writeU16(bytes, optional, 0x010b);
    writeU32(bytes, optional + 16, TEST_ENTRY_RVA);
    writeU32(bytes, optional + 20, 0x1000);
    writeU32(bytes, optional + 24, 0x2000);
    writeU32(bytes, optional + 28, TEST_IMAGE_BASE);
    writeU32(bytes, optional + 32, 0x1000);
    writeU32(bytes, optional + 36, 0x200);
    writeU32(bytes, optional + 56, 0x3000);
    writeU32(bytes, optional + 60, 0x200);
    writeU16(bytes, optional + 68, 3);
    writeU32(bytes, optional + 92, 16);
    writeU32(bytes, optional + 96, 0x2100);
    writeU32(bytes, optional + 100, 0x80);
    writeU32(bytes, optional + 104, 0x2000);
    writeU32(bytes, optional + 108, 0x28);
    writeU32(bytes, optional + 136, 0x20a0);
    writeU32(bytes, optional + 140, 12);
    writeU32(bytes, optional + 168, 0x2080);
    writeU32(bytes, optional + 172, 24);

    const size_t textSection = optional + 0xe0;
    writeString(bytes, textSection, ".text");
    writeU32(bytes, textSection + 8, 0x100);
    writeU32(bytes, textSection + 12, 0x1000);
    writeU32(bytes, textSection + 16, 0x200);
    writeU32(bytes, textSection + 20, 0x200);
    writeU32(bytes, textSection + 36, 0xe0000020);

    const size_t importSection = textSection + 40;
    writeString(bytes, importSection, ".idata");
    writeU32(bytes, importSection + 8, 0x200);
    writeU32(bytes, importSection + 12, 0x2000);
    writeU32(bytes, importSection + 16, 0x200);
    writeU32(bytes, importSection + 20, 0x400);
    writeU32(bytes, importSection + 36, 0xc0000040);

    bytes[0x200] = 0xb8; // mov eax, TEST_ENTRY_RESULT
    writeU32(bytes, 0x201, TEST_ENTRY_RESULT);
    bytes[0x205] = 0xcd; // test-only end interrupt
    bytes[0x206] = 0x97;
    writeU32(bytes, 0x208, TEST_IMAGE_BASE + 0x2000);

    writeU32(bytes, 0x400, 0x2040);
    writeU32(bytes, 0x40c, 0x2060);
    writeU32(bytes, 0x410, 0x2050);
    writeU32(bytes, 0x440, 0x2070);
    writeU32(bytes, 0x450, 0x2070);
    writeString(bytes, 0x460, "KERNEL32.dll");
    writeU16(bytes, 0x470, 0);
    writeString(bytes, 0x472, "ExitProcess");
    writeU32(bytes, 0x4a0, 0x1000);
    writeU32(bytes, 0x4a4, 12);
    writeU16(bytes, 0x4a8, 0x3008);
    writeU16(bytes, 0x4aa, 0);

    writeU32(bytes, 0x50c, 0x2140);
    writeU32(bytes, 0x510, 1);
    writeU32(bytes, 0x514, 2);
    writeU32(bytes, 0x518, 1);
    writeU32(bytes, 0x51c, 0x2128);
    writeU32(bytes, 0x520, 0x2130);
    writeU32(bytes, 0x524, 0x2138);
    writeU32(bytes, 0x528, 0x1000);
    writeU32(bytes, 0x52c, 0x2160);
    writeU32(bytes, 0x530, 0x2150);
    writeU16(bytes, 0x538, 0);
    writeString(bytes, 0x540, "fixture.dll");
    writeString(bytes, 0x550, "FixtureExport");
    writeString(bytes, 0x560, "KERNEL32.ExitProcess");
    return bytes;
}

void testBridgeCallback(CPU* cpu) {
    cpu->reg[0].u32 = TEST_BRIDGE_RESULT;
}

void testBridgeControlTransferCallback(CPU* cpu) {
    cpu->eip.u32 = TEST_BRIDGE_TRANSFER_TARGET;
}

bool resolveTestImport(
    void* context,
    const Pe32ImportModule& module,
    const Pe32ImportSymbol& symbol,
    U32& guestAddress) {
    bool* resolved = static_cast<bool*>(context);
    if (module.name != "KERNEL32.dll" || symbol.name != "ExitProcess") {
        return false;
    }
    *resolved = true;
    guestAddress = TEST_IMPORT_ADDRESS;
    return true;
}

} // namespace

void testPe32LoaderRejectsInvalidImage() {
    std::vector<U8> invalid(64, 0);
    Pe32ImageInfo info;
    std::string error;
    if (Pe32Loader::inspect(invalid, info, error)) {
        testFail("invalid PE32 image was accepted");
    }
    if (error.empty()) {
        testFail("invalid PE32 image did not report an error");
    }
}

void testPe32LoaderMapsAndExecutesImage() {
    std::vector<U8> bytes = createTestPe32();
    Pe32ImageInfo inspected;
    std::string error;
    if (!Pe32Loader::inspect(bytes, inspected, error)) {
        testFail("synthetic PE32 inspection failed: %s", error.c_str());
        return;
    }
    if (inspected.imageBase != TEST_IMAGE_BASE ||
        inspected.entryPoint() != TEST_IMAGE_BASE + TEST_ENTRY_RVA ||
        inspected.sections.size() != 2 ||
        inspected.exportDirectoryRva != 0x2100 ||
        inspected.exportModuleName != "fixture.dll" ||
        inspected.exports.size() != 2 ||
        inspected.imports.size() != 1 ||
        inspected.tlsDirectoryRva != 0x2080 ||
        inspected.tlsDirectorySize != 24 ||
        inspected.imports[0].name != "KERNEL32.dll" ||
        inspected.imports[0].symbols.size() != 1 ||
        inspected.imports[0].symbols[0].name != "ExitProcess") {
        testFail("synthetic PE32 metadata was parsed incorrectly");
        return;
    }
    const Pe32ExportSymbol* namedExport =
        inspected.findExport("FixtureExport");
    const Pe32ExportSymbol* forwardedExport =
        inspected.findExport(2);
    if (!namedExport ||
        namedExport->ordinal != 1 ||
        namedExport->rva != TEST_ENTRY_RVA ||
        namedExport->forwarded() ||
        !forwardedExport ||
        forwardedExport->name.size() ||
        forwardedExport->rva != 0x2160 ||
        forwardedExport->forwarder != "KERNEL32.ExitProcess") {
        testFail("synthetic PE32 exports were parsed incorrectly");
        return;
    }

    TestContext& context = testContext();
    Pe32MappedImage image;
    bool importResolved = false;
    if (!Pe32Loader::mapImageWithImports(
            context.thread,
            bytes,
            0,
            resolveTestImport,
            &importResolved,
            image,
            error)) {
        testFail("synthetic PE32 mapping failed: %s", error.c_str());
        return;
    }
    if (context.memory->readb(image.entryPoint) != 0xb8 ||
        !importResolved ||
        context.memory->readd(TEST_IMAGE_BASE + 0x2050) != TEST_IMPORT_ADDRESS) {
        testFail("PE32 entry point or bound import was not mapped");
        return;
    }
    Pe32MappedImage collidingImage;
    if (Pe32Loader::mapImage(
            context.thread,
            bytes,
            collidingImage,
            error) ||
        context.memory->readb(image.entryPoint) != 0xb8) {
        testFail(
            "PE32 preferred-base collision replaced an existing guest image");
        return;
    }

    CPU* cpu = context.cpu;
    cpu->seg[CS].address = 0;
    cpu->seg[CS].value = BOXEDWINE_INTERNAL_USER_CODE_SELECTOR;
    cpu->eip.u32 = image.entryPoint;
    cpu->nextOp = nullptr;
    context.memory->clearOpCache();
    cpu->nextOp = cpu->getNextOp();
    do {
        cpu->run();
    } while (!cpu->nextOp || cpu->nextOp->inst != TestEnd);

    if (cpu->reg[0].u32 != TEST_ENTRY_RESULT) {
        testFail("mapped PE32 x86 entry point did not execute");
    }

    Pe32MappedImage relocatedImage;
    if (!Pe32Loader::mapImageAt(context.thread, bytes, TEST_RELOCATED_BASE, relocatedImage, error)) {
        testFail("synthetic PE32 relocation failed: %s", error.c_str());
        return;
    }
    if (relocatedImage.loadBase != TEST_RELOCATED_BASE ||
        relocatedImage.entryPoint != TEST_RELOCATED_BASE + TEST_ENTRY_RVA ||
        context.memory->readd(TEST_RELOCATED_BASE + 0x1008) != TEST_RELOCATED_BASE + 0x2000) {
        testFail("PE32 HIGHLOW relocation was not applied correctly");
    }
}

void testSugarbombThunkArena() {
    SugarbombBridge::clearForTests();
    TestContext& context = testContext();
    SugarbombThunkArena arena;
    std::string error;
    if (!arena.initialize(context.thread, TEST_THUNK_BASE, K_PAGE_SIZE, error)) {
        testFail("Sugarbomb thunk arena initialization failed: %s", error.c_str());
        return;
    }

    U32 callbackIndex = SugarbombBridge::registerCallback(
        "KERNEL32.dll",
        "ThunkArenaTest",
        testBridgeCallback);
    U32 thunkAddress = 0;
    if (!arena.createThunk(callbackIndex, 8, thunkAddress, error) ||
        thunkAddress != TEST_THUNK_BASE ||
        arena.thunkCount() != 1 ||
        context.memory->readb(thunkAddress) != 0x68 ||
        context.memory->readd(thunkAddress + 1) != callbackIndex ||
        context.memory->readb(thunkAddress + 5) != 0xcd ||
        context.memory->readb(thunkAddress + 6) != 0x9c ||
        context.memory->readb(thunkAddress + 10) != 0xc2 ||
        context.memory->readw(thunkAddress + 11) != 8) {
        testFail("Sugarbomb stdcall thunk bytes were generated incorrectly");
    }

    std::string module;
    std::string symbol;
    if (!SugarbombBridge::callbackName(callbackIndex, module, symbol) ||
        module != "KERNEL32.dll" ||
        symbol != "ThunkArenaTest") {
        testFail("Sugarbomb callback registry did not retain the import name");
    }
    if (!arena.finalize(error) || context.memory->canWrite(TEST_THUNK_BASE, 1)) {
        testFail("Sugarbomb thunk arena did not become read/execute-only: %s", error.c_str());
    }
    U32 dynamicCallback = SugarbombBridge::registerCallback(
        "KERNEL32.dll",
        "DynamicThunkTest",
        testBridgeCallback);
    U32 dynamicThunk = 0;
    if (!arena.beginUpdate(error) ||
        !arena.createThunk(
            dynamicCallback,
            4,
            dynamicThunk,
            error) ||
        dynamicThunk != TEST_THUNK_BASE + 16 ||
        !arena.finalize(error) ||
        context.memory->canWrite(TEST_THUNK_BASE, 1)) {
        testFail(
            "Sugarbomb thunk arena could not add a dynamic DLL thunk: %s",
            error.c_str());
    }

    context.memory->unmap(TEST_THUNK_BASE, K_PAGE_SIZE);
    SugarbombBridge::clearForTests();
}

void testSugarbombNativeBridge() {
    SugarbombBridge::clearForTests();
    U32 callbackIndex = SugarbombBridge::registerCallback("kernel32", "SugarbombTest", testBridgeCallback);

    testNewInstruction(0);
    testPushCode8(0x68); // push callback index
    testPushCode32(callbackIndex);
    testPushCode8(0xcd); // Sugarbomb native trap
    testPushCode8(0x9c);
    testPushCode8(0x83); // add esp, 4
    testPushCode8(0xc4);
    testPushCode8(0x04);
    testRunCPU();

    if (testContext().cpu->reg[0].u32 != TEST_BRIDGE_RESULT) {
        testFail("Sugarbomb guest-to-native callback did not execute");
    }
    SugarbombBridge::clearForTests();
}

void testSugarbombNativeBridgeControlTransfer() {
    SugarbombBridge::clearForTests();
    U32 callbackIndex = SugarbombBridge::registerCallback(
        "user32",
        "GuestControlTransferTest",
        testBridgeControlTransferCallback);

    testNewInstruction(0);
    testPushCode8(0x68); // push callback index
    testPushCode32(callbackIndex);
    testPushCode8(0xcd); // Sugarbomb native trap
    testPushCode8(0x9c);
    testPushCode8(0x83); // add esp, 4 (must be skipped by the redirect)
    testPushCode8(0xc4);
    testPushCode8(0x04);
    testPushCode8(0xb8); // mov eax, TEST_BRIDGE_SKIPPED_RESULT
    testPushCode32(TEST_BRIDGE_SKIPPED_RESULT);
    testPushCode8(0xb8); // redirected target: mov eax, TEST_BRIDGE_TRANSFER_RESULT
    testPushCode32(TEST_BRIDGE_TRANSFER_RESULT);
    testRunCPU();

    if (testContext().cpu->reg[0].u32 != TEST_BRIDGE_TRANSFER_RESULT) {
        testFail("Sugarbomb callback did not transfer control to the requested guest EIP");
    }
    SugarbombBridge::clearForTests();
}

void testSugarbombHostWindowLifecycle() {
#ifdef _WIN32
    constexpr std::uint32_t GUEST_WINDOW = 0x57000100;
    SugarbombHostWindow window;
    window.syncGuestWindow(
        GUEST_WINDOW,
        "Sugarbomb hidden host-window test",
        0,
        0,
        320,
        200,
        false,
        SW_HIDE);
    if (!window.nativeHandle()) {
        testFail(
            "Sugarbomb native host window was not created on its UI thread");
        return;
    }

    window.setCursorVisible(false);
    window.setCursorVisible(true);
    std::vector<SugarbombHostWindow::Event> events;
    if (!window.pumpMessages(&events)) {
        testFail(
            "Sugarbomb hidden native host window closed unexpectedly");
    }

    HWND nativeWindow =
        reinterpret_cast<HWND>(window.nativeHandle());
    {
        SugarbombHostD3D9 renderer;
        std::vector<U8> adapterIdentifier(1100);
        if (!renderer.queryAdapterIdentifier(
                0,
                0,
                adapterIdentifier.data(),
                adapterIdentifier.size()) ||
            !adapterIdentifier[0] ||
            !adapterIdentifier[512]) {
            testFail(
                "Sugarbomb could not query the native D3D9 adapter "
                "identity before device creation");
        }
        std::vector<U8> caps(304);
        U32 maxVertexShaderInstructions = 0;
        if (!renderer.queryDeviceCaps(
                0,
                1,
                caps.data(),
                caps.size())) {
            testFail(
                "Sugarbomb could not query native D3D9 device caps "
                "before device creation");
        } else {
            std::memcpy(
                &maxVertexShaderInstructions,
                caps.data() + 280,
                sizeof(maxVertexShaderInstructions));
            if (!maxVertexShaderInstructions) {
                testFail(
                    "Sugarbomb native D3D9 caps reported no vertex "
                    "shader instruction capacity");
            }
        }
        if (renderer.initialize(
                window.nativeHandle(),
                320,
                200)) {
            constexpr U32 TEST_TEXTURE = 0x57001000;
            constexpr U32 TEST_RGB24_TEXTURE = 0x57002000;
            constexpr U32 TEST_TEXTURE_SIZE = 16;
            constexpr U32 D3DFMT_A8R8G8B8 = 21;
            constexpr U32 D3DFMT_R8G8B8 = 20;
            constexpr U32 D3DPOOL_DEFAULT = 0;
            U32 nativeResult = 0;
            if (!renderer.createTexture(
                    TEST_TEXTURE,
                    TEST_TEXTURE_SIZE,
                    TEST_TEXTURE_SIZE,
                    1,
                    0,
                    D3DFMT_A8R8G8B8,
                    D3DPOOL_DEFAULT,
                    false,
                    &nativeResult)) {
                testFail(
                    "Sugarbomb could not create a default-pool native "
                    "texture for staged upload validation");
            } else {
                std::vector<U32> pixels(
                    TEST_TEXTURE_SIZE * TEST_TEXTURE_SIZE,
                    0xff4a7f32);
                if (!renderer.uploadTexture(
                        TEST_TEXTURE,
                        0,
                        0,
                        pixels.data(),
                        TEST_TEXTURE_SIZE * sizeof(U32),
                        TEST_TEXTURE_SIZE)) {
                    testFail(
                        "Sugarbomb could not stage a guest CPU upload "
                        "into a default-pool native texture");
                }
            }
            nativeResult = 0;
            if (!renderer.createTexture(
                    TEST_RGB24_TEXTURE,
                    TEST_TEXTURE_SIZE,
                    TEST_TEXTURE_SIZE,
                    1,
                    0,
                    D3DFMT_R8G8B8,
                    D3DPOOL_DEFAULT,
                    false,
                    &nativeResult)) {
                testFail(
                    "Sugarbomb could not bridge a guest RGB24 texture "
                    "to a supported native format");
            } else {
                std::vector<U8> pixels(
                    TEST_TEXTURE_SIZE * TEST_TEXTURE_SIZE * 3);
                for (std::size_t offset = 0;
                     offset < pixels.size();
                     offset += 3) {
                    pixels[offset] = 0x32;
                    pixels[offset + 1] = 0x7f;
                    pixels[offset + 2] = 0x4a;
                }
                if (!renderer.uploadTexture(
                        TEST_RGB24_TEXTURE,
                        0,
                        0,
                        pixels.data(),
                        TEST_TEXTURE_SIZE * 3,
                        TEST_TEXTURE_SIZE)) {
                    testFail(
                        "Sugarbomb could not expand a guest RGB24 "
                        "upload into its native 32-bit texture");
                }
            }
        }
    }
    if (!MoveWindow(
            nativeWindow,
            0,
            0,
            240,
            160,
            FALSE)) {
        testFail(
            "Sugarbomb native host window could not be resized for "
            "coordinate validation");
    } else {
        RECT client = {};
        if (!GetClientRect(nativeWindow, &client) ||
            client.right <= 0 ||
            client.bottom <= 0) {
            testFail(
                "Sugarbomb native host window did not report a valid "
                "resized client area");
        } else {
            const S32 nativeX = client.right / 3;
            const S32 nativeY = client.bottom / 4;
            const S32 expectedGuestX =
                nativeX * 320 / client.right;
            const S32 expectedGuestY =
                nativeY * 200 / client.bottom;
            SendMessageA(
                nativeWindow,
                WM_MOUSEMOVE,
                0,
                MAKELPARAM(nativeX, nativeY));
            events.clear();
            window.pumpMessages(&events);
            auto mouseMove = std::find_if(
                events.begin(),
                events.end(),
                [](const SugarbombHostWindow::Event& event) {
                    return event.message == WM_MOUSEMOVE;
                });
            if (mouseMove == events.end()) {
                testFail(
                    "Sugarbomb native mouse move was not forwarded to "
                    "the guest event queue");
            } else {
                const S32 guestX =
                    static_cast<S16>(
                        mouseMove->longParameter & 0xffff);
                const S32 guestY =
                    static_cast<S16>(
                        (mouseMove->longParameter >> 16) & 0xffff);
                if (guestX != expectedGuestX ||
                    guestY != expectedGuestY) {
                    testFail(
                        "Sugarbomb native mouse coordinates were not "
                        "scaled into guest client space");
                }
            }
            S32 screenX = 0;
            S32 screenY = 0;
            POINT roundTrip = {};
            if (!window.guestClientToScreen(
                    expectedGuestX,
                    expectedGuestY,
                    screenX,
                    screenY)) {
                testFail(
                    "Sugarbomb guest client coordinates could not be "
                    "mapped into native screen space");
            } else {
                roundTrip.x = screenX;
                roundTrip.y = screenY;
                if (!ScreenToClient(nativeWindow, &roundTrip) ||
                    std::abs(roundTrip.x - nativeX) > 1 ||
                    std::abs(roundTrip.y - nativeY) > 1) {
                    testFail(
                        "Sugarbomb guest-to-screen cursor mapping did "
                        "not invert native-to-guest mouse scaling");
                }
            }
        }
    }
    window.destroyGuestWindow(GUEST_WINDOW);
    if (window.nativeHandle()) {
        testFail(
            "Sugarbomb native host window UI thread did not shut down");
    }
#endif
}

#endif
