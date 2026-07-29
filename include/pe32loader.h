/*
 *  Copyright (C) 2026  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifndef __PE32_LOADER_H__
#define __PE32_LOADER_H__

#include <cstddef>
#include <string>
#include <vector>

class KThread;

struct Pe32SectionInfo {
    std::string name;
    U32 virtualAddress = 0;
    U32 virtualSize = 0;
    U32 rawDataOffset = 0;
    U32 rawDataSize = 0;
    U32 characteristics = 0;
};

struct Pe32ImportSymbol {
    std::string name;
    U16 hint = 0;
    U16 ordinal = 0;
    U32 iatRva = 0;
    bool byOrdinal = false;
};

struct Pe32ImportModule {
    std::string name;
    std::vector<Pe32ImportSymbol> symbols;
};

struct Pe32ImageInfo {
    U16 machine = 0;
    U16 characteristics = 0;
    U32 timestamp = 0;
    U32 imageBase = 0;
    U32 entryPointRva = 0;
    U32 sizeOfImage = 0;
    U32 sizeOfHeaders = 0;
    U32 sectionAlignment = 0;
    U32 fileAlignment = 0;
    U32 importDirectoryRva = 0;
    U32 importDirectorySize = 0;
    U32 baseRelocationDirectoryRva = 0;
    U32 baseRelocationDirectorySize = 0;
    std::vector<Pe32SectionInfo> sections;
    std::vector<Pe32ImportModule> imports;

    U32 entryPoint() const {
        return imageBase + entryPointRva;
    }

    size_t importSymbolCount() const;
};

struct Pe32MappedImage {
    Pe32ImageInfo info;
    U32 loadBase = 0;
    U32 entryPoint = 0;
};

typedef bool (*Pe32ImportResolver)(
    void* context,
    const Pe32ImportModule& module,
    const Pe32ImportSymbol& symbol,
    U32& guestAddress);

class Pe32Loader {
public:
    static bool readFile(const char* path, std::vector<U8>& bytes, std::string& error);
    static bool inspect(const std::vector<U8>& bytes, Pe32ImageInfo& info, std::string& error);
    static bool mapImage(KThread* thread, const std::vector<U8>& bytes, Pe32MappedImage& image, std::string& error);
    static bool mapImageAt(KThread* thread, const std::vector<U8>& bytes, U32 loadBase, Pe32MappedImage& image, std::string& error);
    static bool mapImageWithImports(
        KThread* thread,
        const std::vector<U8>& bytes,
        U32 loadBase,
        Pe32ImportResolver resolver,
        void* resolverContext,
        Pe32MappedImage& image,
        std::string& error);
};

#endif
