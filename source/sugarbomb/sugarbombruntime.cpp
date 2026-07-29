/*
 *  Copyright (C) 2026  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#include "boxedwine.h"
#include "pe32loader.h"
#include "sugarbombbridge.h"
#include "sugarbombruntime.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <string>
#include <unordered_map>

#ifdef BOXEDWINE_HOST_EXCEPTIONS
void platformInitExceptionHandling();
#endif

namespace {

constexpr U32 THUNK_BASE = 0x60000000;
constexpr U32 THUNK_SIZE = 0x00100000;
constexpr U32 STACK_BASE = 0x6f800000;
constexpr U32 STACK_SIZE = 0x00800000;
constexpr U32 STACK_TOP = STACK_BASE + STACK_SIZE;
constexpr U32 ENV_BASE = 0x7ffd8000;
constexpr U32 ENV_SIZE = 0x00008000;
constexpr U32 ANSI_COMMAND_LINE = 0x7ffd8000;
constexpr U32 WIDE_IMAGE_PATH = 0x7ffd8800;
constexpr U32 WIDE_COMMAND_LINE = 0x7ffd9000;
constexpr U32 TLS_ARRAY = 0x7ffda000;
constexpr U32 STATIC_TLS_DATA = 0x7ffda400;
constexpr U32 STATIC_TLS_CAPACITY = 0x00000c00;
constexpr U32 ANSI_ENVIRONMENT = 0x7ffdb000;
constexpr U32 WIDE_ENVIRONMENT = 0x7ffdb400;
constexpr U32 PROCESS_PARAMETERS = 0x7ffdc000;
constexpr U32 PEB_LDR_DATA = 0x7ffdd000;
constexpr U32 TEB_ADDRESS = 0x7ffde000;
constexpr U32 PEB_ADDRESS = 0x7ffdf000;
constexpr U32 WINDOWS_TEB_SELECTOR = (TLS_ENTRY_START_INDEX << 3) | 3;
constexpr U64 WINDOWS_TO_UNIX_EPOCH_100NS = 116444736000000000ULL;
constexpr U32 MAX_RUN_SLICES = 2000000;
constexpr U32 PROCESS_HEAP_HANDLE = 0x50000000;
constexpr U32 KERNEL32_MODULE_HANDLE = 0x51000000;
constexpr U32 STDIN_GUEST_HANDLE = 0x52000000;
constexpr U32 STDOUT_GUEST_HANDLE = 0x52000001;
constexpr U32 STDERR_GUEST_HANDLE = 0x52000002;
constexpr U32 GUEST_HEAP_BASE = 0x20000000;
constexpr U32 GUEST_HEAP_LIMIT = 0x50000000;
constexpr U32 GUEST_VIRTUAL_BASE = 0x02000000;
constexpr U32 GUEST_VIRTUAL_LIMIT = 0x1f000000;
constexpr U32 HEAP_ZERO_MEMORY = 0x00000008;

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

        U32 exitCallback = SugarbombBridge::registerCallback(
            "sugarbomb",
            "ExeEntryPointReturn",
            callbackEntryPointReturn);
        if (!thunks.createThunk(exitCallback, 0, entryReturnThunk, error) ||
            !thunks.finalize(error)) {
            fprintf(stderr, "Sugarbomb could not finalize native thunks: %s\n", error.c_str());
            return false;
        }

        if (!initializeStaticTls()) {
            fprintf(stderr, "Sugarbomb could not initialize PE static TLS: %s\n", error.c_str());
            return false;
        }
        initializeWindowsEnvironment();
        initializeCpu();
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

    bool initializeStaticTls() {
        if (!image.info.tlsDirectoryRva || image.info.tlsDirectorySize < 24) {
            return true;
        }
        U32 directory = image.loadBase + image.info.tlsDirectoryRva;
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
        if (!indexAddress || totalSize > STATIC_TLS_CAPACITY ||
            (rawSize && !memory->canRead(rawStart, rawSize))) {
            error = "PE TLS template does not fit the bootstrap TLS storage";
            return false;
        }

        memory->writed(indexAddress, 0);
        memory->writed(TLS_ARRAY, STATIC_TLS_DATA);
        if (rawSize) {
            memory->memcpy(STATIC_TLS_DATA, rawStart, rawSize);
        }
        if (zeroFillSize) {
            memory->memset(STATIC_TLS_DATA + rawSize, 0, zeroFillSize);
        }
        nextTlsIndex = 1;

        U32 callbackCount = 0;
        if (callbacksAddress) {
            while (callbackCount < 1024 && memory->canRead(callbacksAddress + callbackCount * 4, 4)) {
                U32 callback = memory->readd(callbacksAddress + callbackCount * 4);
                if (!callback) {
                    break;
                }
                ++callbackCount;
            }
        }
        printf(
            "Sugarbomb: initialized PE static TLS slot 0 (%u template bytes, %u zero-fill bytes, %u callbacks)\n",
            rawSize,
            zeroFillSize,
            callbackCount);
        return true;
    }

    bool execute() {
        printf("Sugarbomb: entering FalloutNV.exe as an x86 guest in the %zu-bit host\n", sizeof(void*) * 8);
        U32 slices = 0;
        while (!thread->terminating && slices < MAX_RUN_SLICES) {
            cpu->run();
            ++slices;
        }
        if (slices == MAX_RUN_SLICES) {
            fprintf(stderr, "Sugarbomb stopped after the bootstrap execution budget was exhausted\n");
            return false;
        }
        printf(
            "Sugarbomb: guest stopped after %u CPU slices and %u native API calls at EIP=0x%08X\n",
            slices,
            nativeCallCount,
            cpu->getEipAddress());
        return true;
    }

    void cleanup() {
        if (thread && process) {
            KThread::setCurrentThread(nullptr);
            process->deleteThread(thread);
            thread = nullptr;
            cpu = nullptr;
            memory = nullptr;
        }
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

    void findNativeCallback(
        const std::string& module,
        const std::string& symbol,
        SugarbombNativeCallback& callback,
        U16& stackCleanupBytes) {
        if (module != "kernel32.dll" && module != "kernelbase.dll") {
            return;
        }
        if (symbol == "GetSystemTimeAsFileTime") {
            callback = callbackGetSystemTimeAsFileTime;
            stackCleanupBytes = 4;
        } else if (symbol == "GetCurrentProcessId") {
            callback = callbackGetCurrentProcessId;
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
        } else if (symbol == "GetConsoleCP") {
            callback = callbackGetConsoleCP;
        } else if (symbol == "GetConsoleOutputCP") {
            callback = callbackGetConsoleOutputCP;
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
        } else if (symbol == "SetUnhandledExceptionFilter") {
            callback = callbackSetUnhandledExceptionFilter;
            stackCleanupBytes = 4;
        } else if (symbol == "UnhandledExceptionFilter") {
            callback = callbackUnhandledExceptionFilter;
            stackCleanupBytes = 4;
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
        } else if (symbol == "VirtualAlloc") {
            callback = callbackVirtualAlloc;
            stackCleanupBytes = 16;
        } else if (symbol == "VirtualFree") {
            callback = callbackVirtualFree;
            stackCleanupBytes = 12;
        } else if (symbol == "VirtualQuery") {
            callback = callbackVirtualQuery;
            stackCleanupBytes = 12;
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
        } else if (symbol == "ExitProcess") {
            callback = callbackExitProcess;
            stackCleanupBytes = 4;
        }
    }

    static SugarbombRuntimeSession* current(CPU* cpu, const char* api) {
        if (!activeSession) {
            if (cpu) {
                cpu->thread->terminating = true;
            }
            kwarn_fmt("Sugarbomb API %s called without an active runtime", api);
            return nullptr;
        }
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

    static void callbackGetCurrentThreadId(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetCurrentThreadId");
        if (session) {
            cpu->reg[0].u32 = session->thread->id;
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
            cpu->reg[0].u32 = session->memory->readd(TEB_ADDRESS + 0x34);
        }
    }

    static void callbackSetLastError(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!SetLastError");
        if (session) {
            session->memory->writed(TEB_ADDRESS + 0x34, argument(cpu, 0));
        }
    }

    static void callbackGetModuleHandleA(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetModuleHandleA");
        if (session) {
            U32 moduleName = argument(cpu, 0);
            if (!moduleName) {
                cpu->reg[0].u32 = session->image.loadBase;
            } else if (lowerAscii(session->readAnsi(moduleName)) == "kernel32.dll") {
                cpu->reg[0].u32 = KERNEL32_MODULE_HANDLE;
            } else {
                cpu->reg[0].u32 = 0;
                session->setLastError(126); // ERROR_MOD_NOT_FOUND
            }
        }
    }

    static void callbackGetModuleHandleW(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!GetModuleHandleW");
        if (session) {
            U32 moduleName = argument(cpu, 0);
            if (!moduleName) {
                cpu->reg[0].u32 = session->image.loadBase;
            } else if (lowerAscii(session->readWide(moduleName)) == "kernel32.dll") {
                cpu->reg[0].u32 = KERNEL32_MODULE_HANDLE;
            } else {
                cpu->reg[0].u32 = 0;
                session->setLastError(126);
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
        if ((module && module != session->image.loadBase) || !buffer || !capacity) {
            session->setLastError(87);
            cpu->reg[0].u32 = 0;
            return;
        }
        U32 length = static_cast<U32>(session->imagePath.size());
        U32 copied = std::min(length, capacity - 1);
        session->memory->memcpy(buffer, session->imagePath.data(), copied);
        session->memory->writeb(buffer + copied, 0);
        cpu->reg[0].u32 = copied;
        if (copied != length) {
            session->setLastError(122); // ERROR_INSUFFICIENT_BUFFER
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
        std::string name = nameAddress <= 0xffff
            ? "#" + std::to_string(nameAddress)
            : session->readAnsi(nameAddress);
        printf("Sugarbomb Win32 probe: GetProcAddress(0x%08X, %s) -> unavailable\n", module, name.c_str());
        session->setLastError(127); // ERROR_PROC_NOT_FOUND
        cpu->reg[0].u32 = 0;
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
        cpu->reg[0].u32 = session->memory->readd(TLS_ARRAY + index * 4);
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
        session->memory->writed(TLS_ARRAY + index * 4, argument(cpu, 1));
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
        session->memory->writed(TLS_ARRAY + index * 4, 0);
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
            session->enterCriticalSection(argument(cpu, 0));
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
            cpu->reg[0].u32 = session->isStandardHandle(argument(cpu, 0)) ? 2 : 0;
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
            cpu->reg[0].u32 = session->virtualAlloc(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3));
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

    static void callbackVirtualQuery(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!VirtualQuery");
        if (session) {
            cpu->reg[0].u32 = session->virtualQuery(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2));
        }
    }

    static void callbackWriteFile(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!WriteFile");
        if (session) {
            cpu->reg[0].u32 = session->writeGuestOutput(
                argument(cpu, 0),
                argument(cpu, 1),
                argument(cpu, 2),
                argument(cpu, 3),
                false) ? 1 : 0;
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
        if (bytesRead) {
            session->memory->writed(bytesRead, 0);
        }
        cpu->reg[0].u32 = session->isStandardHandle(argument(cpu, 0)) ? 1 : 0;
        if (!cpu->reg[0].u32) {
            session->setLastError(6);
        }
    }

    static void callbackFlushFileBuffers(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!FlushFileBuffers");
        if (session) {
            fflush(stdout);
            fflush(stderr);
            cpu->reg[0].u32 = session->isStandardHandle(argument(cpu, 0)) ? 1 : 0;
        }
    }

    static void callbackCloseHandle(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!CloseHandle");
        if (session) {
            cpu->reg[0].u32 = session->isStandardHandle(argument(cpu, 0)) ? 1 : 0;
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

    static void callbackExitProcess(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "KERNEL32!ExitProcess");
        if (session) {
            session->exitCode = argument(cpu, 0);
            printf("Sugarbomb: guest requested ExitProcess(%u)\n", session->exitCode);
        }
        cpu->thread->terminating = true;
    }

    static void callbackEntryPointReturn(CPU* cpu) {
        SugarbombRuntimeSession* session = current(cpu, "SUGARBOMB!ExeEntryPointReturn");
        if (session) {
            printf("Sugarbomb: PE32 executable entry point returned EAX=0x%08X\n", cpu->reg[0].u32);
        }
        cpu->thread->terminating = true;
    }

    static void callbackUnresolvedImport(CPU* cpu) {
        std::string module;
        std::string symbol;
        U32 callbackIndex = cpu->peek32(0);
        SugarbombBridge::callbackName(callbackIndex, module, symbol);
        if (activeSession) {
            ++activeSession->nativeCallCount;
            activeSession->stoppedAtUnresolvedImport = true;
        }
        fprintf(
            stderr,
            "Sugarbomb: stopped at unresolved Win32 import %s!%s (callback %u)\n",
            module.c_str(),
            symbol.c_str(),
            callbackIndex);
        cpu->reg[0].u32 = 0xc0000139; // STATUS_ENTRYPOINT_NOT_FOUND
        cpu->thread->terminating = true;
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

    struct VirtualRegion {
        U32 base = 0;
        U32 size = 0;
        U32 allocationProtection = 0;
        U32 protection = 0;
        U32 state = 0;
        std::vector<std::pair<U32, U32>> committedRanges;
    };

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
            : (nextVirtualAddress + 0xffff) & 0xffff0000;

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
        if (state.ownerThread && state.ownerThread != thread->id) {
            return false;
        }
        state.ownerThread = thread->id;
        ++state.recursionCount;
        memory->writed(address + 4, state.recursionCount - 1);
        memory->writed(address + 8, state.recursionCount);
        memory->writed(address + 12, state.ownerThread);
        return true;
    }

    void leaveCriticalSection(U32 address) {
        auto found = criticalSections.find(address);
        if (found == criticalSections.end() ||
            found->second.ownerThread != thread->id ||
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

    void setLastError(U32 errorCode) {
        memory->writed(TEB_ADDRESS + 0x34, errorCode);
    }

    bool isStandardHandle(U32 handle) const {
        return handle == standardHandles[0] ||
            handle == standardHandles[1] ||
            handle == standardHandles[2];
    }

    bool writeGuestOutput(U32 handle, U32 buffer, U32 length, U32 bytesWritten, bool wide) {
        if (!isStandardHandle(handle) || !memory->canRead(buffer, wide ? length * 2 : length)) {
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

    std::string readAnsi(U32 address, U32 limit = 512) {
        std::string result;
        for (U32 index = 0; index < limit && memory->canRead(address + index, 1); ++index) {
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
        for (U32 index = 0; index < limit && memory->canRead(address + index * 2, 2); ++index) {
            U16 value = memory->readw(address + index * 2);
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
    Pe32MappedImage image;
    SugarbombThunkArena thunks;
    U32 entryReturnThunk = 0;
    U32 nativeCallCount = 0;
    U32 exitCode = 0;
    U32 unhandledExceptionFilter = 0;
    U32 virtualAllocCallCount = 0;
    U32 nextHeapHandle = PROCESS_HEAP_HANDLE + 1;
    U32 nextHeapAddress = GUEST_HEAP_BASE;
    U32 nextVirtualAddress = GUEST_VIRTUAL_BASE;
    U32 nextTlsIndex = 0;
    U32 standardHandles[3] = {STDIN_GUEST_HANDLE, STDOUT_GUEST_HANDLE, STDERR_GUEST_HANDLE};
    std::unordered_map<U32, HeapAllocation> heapAllocations;
    std::unordered_map<U32, CriticalSectionState> criticalSections;
    std::unordered_map<U32, VirtualRegion> virtualRegions;
    std::unordered_map<std::string, U32> nativeApiCounts;
    bool stoppedAtUnresolvedImport = false;
};

} // namespace

int SugarbombRuntime::run(const char* imagePath) {
    SugarbombRuntimeSession session;
    return session.run(imagePath);
}
