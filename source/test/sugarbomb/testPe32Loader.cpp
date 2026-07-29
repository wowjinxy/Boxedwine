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
#include "../cpu/testCPU.h"
#include "testPe32Loader.h"

namespace {

constexpr U32 TEST_IMAGE_BASE = 0x00400000;
constexpr U32 TEST_RELOCATED_BASE = 0x00600000;
constexpr U32 TEST_ENTRY_RVA = 0x00001000;
constexpr U32 TEST_ENTRY_RESULT = 0x12345678;
constexpr U32 TEST_BRIDGE_RESULT = 0x53425547;
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
    return bytes;
}

void testBridgeCallback(CPU* cpu) {
    cpu->reg[0].u32 = TEST_BRIDGE_RESULT;
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
        inspected.imports.size() != 1 ||
        inspected.tlsDirectoryRva != 0x2080 ||
        inspected.tlsDirectorySize != 24 ||
        inspected.imports[0].name != "KERNEL32.dll" ||
        inspected.imports[0].symbols.size() != 1 ||
        inspected.imports[0].symbols[0].name != "ExitProcess") {
        testFail("synthetic PE32 metadata was parsed incorrectly");
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

#endif
