/*
 *  Copyright (C) 2012-2025  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "boxedwine.h"

#include "startupArgs.h"
#ifndef BOXEDWINE_DISABLE_UI
#include "../ui/mainui.h"
#include "../ui/data/boxedwineData.h"
#include "../ui/data/globalSettings.h"
#endif
#include "knativesystem.h"
#include "pe32loader.h"
#include "sugarbombruntime.h"

#ifdef BOXEDWINE_MSVC
#include <Windows.h>
#endif

#ifndef __TEST

U32 gensrc;

#ifdef GENERATE_SOURCE
void writeSource();
#endif

#ifdef BOXEDWINE_MSVC
static void configureSugarbombHostProcess() {
    // Fallout's client dimensions are physical game pixels. Opt the native
    // host into modern DPI handling before it creates any HWND so Windows
    // does not turn a 1920x1080 backbuffer into a 3840x2160 client at 200%.
    using SetProcessDpiAwarenessContextProc =
        BOOL(WINAPI*)(HANDLE);
    HMODULE user32 = GetModuleHandleA("user32.dll");
    auto setProcessDpiAwarenessContext =
        user32
        ? reinterpret_cast<SetProcessDpiAwarenessContextProc>(
              GetProcAddress(
                  user32,
                  "SetProcessDpiAwarenessContext"))
        : nullptr;
    constexpr std::intptr_t DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2_VALUE =
        -4;
    if (setProcessDpiAwarenessContext &&
        setProcessDpiAwarenessContext(
            reinterpret_cast<HANDLE>(
                DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2_VALUE))) {
        return;
    }
    SetProcessDPIAware();
}
#endif

int boxedmain(int argc, const char **argv) {
    if (argc == 3 && strcmp(argv[1], "--sugarbomb-run") == 0) {
#ifdef BOXEDWINE_MSVC
        configureSugarbombHostProcess();
#endif
        return SugarbombRuntime::run(argv[2]);
    }

    const bool inspectSugarbombPe = argc == 3 && (
        strcmp(argv[1], "--sugarbomb-pe-info") == 0 ||
        strcmp(argv[1], "--sugarbomb-pe-imports") == 0 ||
        strcmp(argv[1], "--sugarbomb-pe-exports") == 0);
    if (inspectSugarbombPe) {
        const bool listImports = strcmp(argv[1], "--sugarbomb-pe-imports") == 0;
        const bool listExports = strcmp(argv[1], "--sugarbomb-pe-exports") == 0;
        std::vector<U8> bytes;
        Pe32ImageInfo info;
        std::string error;
        if (!Pe32Loader::readFile(argv[2], bytes, error) || !Pe32Loader::inspect(bytes, info, error)) {
            fprintf(stderr, "Sugarbomb PE32 inspection failed: %s\n", error.c_str());
            return 1;
        }

        printf("Format: PE32/i386\n");
        printf("Image base: 0x%08X\n", info.imageBase);
        printf("Entry point: 0x%08X (RVA 0x%08X)\n", info.entryPoint(), info.entryPointRva);
        printf("Image size: 0x%08X\n", info.sizeOfImage);
        printf("Sections: %zu\n", info.sections.size());
        for (const Pe32SectionInfo& section : info.sections) {
            printf("  %-8s RVA=0x%08X VSIZE=0x%08X RAW=0x%08X FLAGS=0x%08X\n",
                section.name.c_str(),
                section.virtualAddress,
                section.virtualSize,
                section.rawDataSize,
                section.characteristics);
        }
        printf("Exports: %zu symbols from %s\n",
            info.exports.size(),
            info.exportModuleName.empty()
                ? "<unnamed>"
                : info.exportModuleName.c_str());
        if (listExports) {
            for (const Pe32ExportSymbol& symbol : info.exports) {
                if (symbol.forwarded()) {
                    printf("  ORD=%u RVA=0x%08X %-32s -> %s\n",
                        symbol.ordinal,
                        symbol.rva,
                        symbol.name.empty() ? "<ordinal-only>" : symbol.name.c_str(),
                        symbol.forwarder.c_str());
                } else {
                    printf("  ORD=%u ADDR=0x%08X RVA=0x%08X %s\n",
                        symbol.ordinal,
                        info.imageBase + symbol.rva,
                        symbol.rva,
                        symbol.name.empty() ? "<ordinal-only>" : symbol.name.c_str());
                }
            }
        }
        printf("Imports: %zu modules, %zu symbols\n", info.imports.size(), info.importSymbolCount());
        for (const Pe32ImportModule& module : info.imports) {
            printf("  %s: %zu\n", module.name.c_str(), module.symbols.size());
            if (listImports) {
                for (const Pe32ImportSymbol& symbol : module.symbols) {
                    if (symbol.byOrdinal) {
                        printf("    IAT=0x%08X RVA=0x%08X #%u\n",
                            info.imageBase + symbol.iatRva,
                            symbol.iatRva,
                            symbol.ordinal);
                    } else {
                        printf("    IAT=0x%08X RVA=0x%08X %s\n",
                            info.imageBase + symbol.iatRva,
                            symbol.iatRva,
                            symbol.name.c_str());
                    }
                }
            }
        }
        printf("Base relocations: RVA=0x%08X SIZE=0x%08X\n",
            info.baseRelocationDirectoryRva,
            info.baseRelocationDirectorySize);
        printf("TLS directory: RVA=0x%08X SIZE=0x%08X\n",
            info.tlsDirectoryRva,
            info.tlsDirectorySize);
        return 0;
    }

    StartUpArgs startupArgs;

    klog("Starting ...");
#if defined(__MACH__)
    std::vector<BString> lines;
    std::vector<const char*> args;
    BString dataPath = KNativeSystem::getLocalDirectory();
    BString argsPath = dataPath.stringByApppendingPath("args.txt");
    readLinesFromFile(argsPath, lines);
    Fs::deleteNativeFile(argsPath);
    if (lines.size()) {
        KSystem::showWindowTimestamp = dataPath.stringByApppendingPath(lines[0]+".txt");
        U32 createdTime = lines[0].toInt();
        U32 now = (U32)(KSystem::getSystemTimeAsMicroSeconds() / 100000);
        if (createdTime + 10 > now) {
            args.push_back(argv[0]);
            
            for (int i=1;i<(int)lines.size();i++) {
                args.push_back(lines[i].c_str());
            }
            argc = (int)args.size();
            argv = args.data();
        }
    }
#endif
    KSystem::startMicroCounter();
    KSystem::exePath = BString::copy(argv[0]);
    if (KSystem::exePath.contains("\\")) {
        KSystem::exePath = KSystem::exePath.substr(0, KSystem::exePath.lastIndexOf('\\')+1);
    } else {
        KSystem::exePath = KSystem::exePath.substr(0, KSystem::exePath.lastIndexOf('/')+1);
    }
    if (argc == 1) {
        if (!startupArgs.loadDefaultResource(argv[0])) {
            return 1;
        }
        
    } else if (!startupArgs.parseStartupArgs(argc, argv)) {
        return 1;
    }
    
#ifdef BOXEDWINE_MSVC
#ifdef BOXEDWINE_DISABLE_UI    
    if (startupArgs.dpiAware) {
        SetProcessDPIAware();
    }
#else
    if (startupArgs.shouldStartUI() || startupArgs.dpiAware) {
        SetProcessDPIAware();
    }
#endif
#endif

#ifdef _DEBUG
    U32 cpuCount = Platform::getCpuCount();
    if (cpuCount==1) {
        klog_fmt("%d MHz CPU detected", Platform::getCpuFreqMHz());
    } else {
        klog_fmt("%dx %d MHz CPUs detected", cpuCount, Platform::getCpuFreqMHz());
    }
#endif

    Platform::init();
    // currently to fake sound, we really need to play it and just silence it right before it goes to speaker, 
    // this way the timing of the callback to get the audio from wine are correct.  Without this timing, things can hange.
    if (!KNativeSystem::init(startupArgs.videoOption, true/* startupArgs.soundEnabled */)) {
        return 1;
    }
#ifndef BOXEDWINE_DISABLE_UI
    BoxedwineData::init(argc, argv);
#endif
    if (!startupArgs.shouldStartUI()) {
        if (!startupArgs.apply()) {
            return 1;
        }
    } else {
#ifndef BOXEDWINE_DISABLE_UI

#ifdef BOXEDWINE_MSVC
        if (StartUpArgs::uiType == UI_TYPE_UNSET) {
#ifdef BOXEDWINE_IMGUI_DX9
            StartUpArgs::uiType = UI_TYPE_DX9;
#else
            StartUpArgs::uiType = UI_TYPE_OPENGL;
#endif
        }
#else
        if (StartUpArgs::uiType == UI_TYPE_UNSET) {
            StartUpArgs::uiType = UI_TYPE_OPENGL;
        }
#endif
        while (true) {
            if (GlobalSettings::keepUIRunning) {
                GlobalSettings::keepUIRunning();
                GlobalSettings::keepUIRunning = nullptr;
                if (!uiContinue()) {
                    break;
                }
            } else {
                if (!uiShow(GlobalSettings::getExePath() + Fs::nativePathSeperator)) {
                    break;
                }
            }
            if (GlobalSettings::restartUI) {
                GlobalSettings::restartUI = false;
                if (GlobalSettings::reinit) {
                    GlobalSettings::reinit = false;
                    GlobalSettings::init(argc, argv);
                } else {
                    GlobalSettings::startUp();
                }
                continue;
            }
            BoxedwineData::startApp();
            GlobalSettings::startUpArgs.readyToLaunch = false;

            KNativeSystem::preReturnToUI();
            if (!GlobalSettings::keepUIRunning) {
                GlobalSettings::startUp(); // we we come back in after launching a game, we will need to create icons, like the demo icons
            }
        }
#endif
    }              

    klog("Boxedwine shutdown");
    KNativeSystem::cleanup();
    return BOXEDWINE_RECORDER_QUIT();
}

#endif
