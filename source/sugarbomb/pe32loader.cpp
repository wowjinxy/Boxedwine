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

#include <fstream>
#include <limits>

namespace {

constexpr U16 PE32_MACHINE_I386 = 0x014c;
constexpr U16 PE32_OPTIONAL_MAGIC = 0x010b;
constexpr U32 PE_SIGNATURE = 0x00004550;
constexpr U32 PE_ORDINAL_FLAG32 = 0x80000000;
constexpr U16 PE_RELOCATION_ABSOLUTE = 0;
constexpr U16 PE_RELOCATION_HIGHLOW = 3;

constexpr U32 PE_SECTION_MEM_EXECUTE = 0x20000000;
constexpr U32 PE_SECTION_MEM_READ = 0x40000000;
constexpr U32 PE_SECTION_MEM_WRITE = 0x80000000;

bool hasRange(size_t offset, size_t length, size_t total) {
    return offset <= total && length <= total - offset;
}

bool addFitsU32(U32 left, U32 right, U32& result) {
    if (left > std::numeric_limits<U32>::max() - right) {
        return false;
    }
    result = left + right;
    return true;
}

bool readU16(const std::vector<U8>& bytes, size_t offset, U16& value) {
    if (!hasRange(offset, 2, bytes.size())) {
        return false;
    }
    value = static_cast<U16>(bytes[offset]) |
        static_cast<U16>(static_cast<U16>(bytes[offset + 1]) << 8);
    return true;
}

bool readU32(const std::vector<U8>& bytes, size_t offset, U32& value) {
    if (!hasRange(offset, 4, bytes.size())) {
        return false;
    }
    value = static_cast<U32>(bytes[offset]) |
        (static_cast<U32>(bytes[offset + 1]) << 8) |
        (static_cast<U32>(bytes[offset + 2]) << 16) |
        (static_cast<U32>(bytes[offset + 3]) << 24);
    return true;
}

bool readCString(const std::vector<U8>& bytes, size_t offset, std::string& value) {
    if (offset >= bytes.size()) {
        return false;
    }
    constexpr size_t MAX_STRING_LENGTH = 4096;
    size_t end = offset;
    while (end < bytes.size() && end - offset < MAX_STRING_LENGTH && bytes[end]) {
        ++end;
    }
    if (end >= bytes.size() || end - offset == MAX_STRING_LENGTH) {
        return false;
    }
    value.assign(reinterpret_cast<const char*>(&bytes[offset]), end - offset);
    return true;
}

bool rvaToFileOffset(const Pe32ImageInfo& info, const std::vector<U8>& bytes, U32 rva, size_t length, size_t& offset) {
    if (rva < info.sizeOfHeaders) {
        offset = static_cast<size_t>(rva);
        return hasRange(offset, length, bytes.size());
    }

    for (const Pe32SectionInfo& section : info.sections) {
        U32 span = std::max(section.virtualSize, section.rawDataSize);
        U32 sectionEnd = 0;
        if (!addFitsU32(section.virtualAddress, span, sectionEnd)) {
            continue;
        }
        if (rva < section.virtualAddress || rva >= sectionEnd) {
            continue;
        }

        U32 delta = rva - section.virtualAddress;
        if (delta > section.rawDataSize || length > static_cast<size_t>(section.rawDataSize - delta)) {
            return false;
        }
        offset = static_cast<size_t>(section.rawDataOffset) + delta;
        return hasRange(offset, length, bytes.size());
    }
    return false;
}

bool readRvaCString(const Pe32ImageInfo& info, const std::vector<U8>& bytes, U32 rva, std::string& value) {
    size_t offset = 0;
    if (!rvaToFileOffset(info, bytes, rva, 1, offset)) {
        return false;
    }
    return readCString(bytes, offset, value);
}

bool parseImports(const std::vector<U8>& bytes, Pe32ImageInfo& info, std::string& error) {
    if (!info.importDirectoryRva || !info.importDirectorySize) {
        return true;
    }

    constexpr U32 IMPORT_DESCRIPTOR_SIZE = 20;
    constexpr U32 MAX_IMPORT_MODULES = 4096;
    constexpr U32 MAX_IMPORT_SYMBOLS_PER_MODULE = 65536;
    U32 descriptorRva = info.importDirectoryRva;

    for (U32 moduleIndex = 0; moduleIndex < MAX_IMPORT_MODULES; ++moduleIndex) {
        size_t descriptorOffset = 0;
        if (!rvaToFileOffset(info, bytes, descriptorRva, IMPORT_DESCRIPTOR_SIZE, descriptorOffset)) {
            error = "PE32 import descriptor is outside the file";
            return false;
        }

        U32 originalFirstThunk = 0;
        U32 timeDateStamp = 0;
        U32 forwarderChain = 0;
        U32 nameRva = 0;
        U32 firstThunk = 0;
        readU32(bytes, descriptorOffset, originalFirstThunk);
        readU32(bytes, descriptorOffset + 4, timeDateStamp);
        readU32(bytes, descriptorOffset + 8, forwarderChain);
        readU32(bytes, descriptorOffset + 12, nameRva);
        readU32(bytes, descriptorOffset + 16, firstThunk);

        if (!originalFirstThunk && !timeDateStamp && !forwarderChain && !nameRva && !firstThunk) {
            return true;
        }

        Pe32ImportModule module;
        if (!nameRva || !readRvaCString(info, bytes, nameRva, module.name)) {
            error = "PE32 import module name is invalid";
            return false;
        }

        U32 lookupTableRva = originalFirstThunk ? originalFirstThunk : firstThunk;
        bool symbolTableTerminated = false;
        for (U32 symbolIndex = 0; symbolIndex < MAX_IMPORT_SYMBOLS_PER_MODULE; ++symbolIndex) {
            U32 thunkEntryRva = 0;
            if (!addFitsU32(lookupTableRva, symbolIndex * 4, thunkEntryRva)) {
                error = "PE32 import lookup table overflows the guest address space";
                return false;
            }
            size_t thunkOffset = 0;
            if (!rvaToFileOffset(info, bytes, thunkEntryRva, 4, thunkOffset)) {
                error = "PE32 import lookup entry is outside the file";
                return false;
            }

            U32 thunkValue = 0;
            readU32(bytes, thunkOffset, thunkValue);
            if (!thunkValue) {
                symbolTableTerminated = true;
                break;
            }

            Pe32ImportSymbol symbol;
            if (!addFitsU32(firstThunk, symbolIndex * 4, symbol.iatRva)) {
                error = "PE32 import address table overflows the guest address space";
                return false;
            }

            if (thunkValue & PE_ORDINAL_FLAG32) {
                symbol.byOrdinal = true;
                symbol.ordinal = static_cast<U16>(thunkValue & 0xffff);
            } else {
                size_t nameOffset = 0;
                if (!rvaToFileOffset(info, bytes, thunkValue, 3, nameOffset) ||
                    !readU16(bytes, nameOffset, symbol.hint) ||
                    !readCString(bytes, nameOffset + 2, symbol.name)) {
                    error = "PE32 imported symbol name is invalid";
                    return false;
                }
            }
            module.symbols.push_back(symbol);
        }
        if (!symbolTableTerminated) {
            error = "PE32 import lookup table is not terminated";
            return false;
        }
        info.imports.push_back(module);

        if (!addFitsU32(descriptorRva, IMPORT_DESCRIPTOR_SIZE, descriptorRva)) {
            error = "PE32 import descriptor table overflows the guest address space";
            return false;
        }
    }

    error = "PE32 import descriptor table is not terminated";
    return false;
}

U32 sectionProtection(const Pe32SectionInfo& section) {
    U32 protection = 0;
    if (section.characteristics & PE_SECTION_MEM_READ) {
        protection |= K_PROT_READ;
    }
    if (section.characteristics & PE_SECTION_MEM_WRITE) {
        protection |= K_PROT_WRITE;
    }
    if (section.characteristics & PE_SECTION_MEM_EXECUTE) {
        protection |= K_PROT_EXEC;
    }
    return protection ? protection : K_PROT_READ;
}

bool applyBaseRelocations(
    KThread* thread,
    const std::vector<U8>& bytes,
    const Pe32ImageInfo& info,
    U32 loadBase,
    std::string& error) {
    if (loadBase == info.imageBase) {
        return true;
    }
    if (!info.baseRelocationDirectoryRva || !info.baseRelocationDirectorySize) {
        error = "PE32 image cannot be loaded away from its preferred base because it has no relocation table";
        return false;
    }

    U32 relocationEnd = 0;
    if (!addFitsU32(info.baseRelocationDirectoryRva, info.baseRelocationDirectorySize, relocationEnd)) {
        error = "PE32 relocation directory overflows the guest address space";
        return false;
    }

    U32 cursor = info.baseRelocationDirectoryRva;
    const U32 delta = loadBase - info.imageBase;
    while (cursor < relocationEnd) {
        if (relocationEnd - cursor < 8) {
            error = "PE32 relocation block header is truncated";
            return false;
        }

        size_t blockOffset = 0;
        U32 pageRva = 0;
        U32 blockSize = 0;
        if (!rvaToFileOffset(info, bytes, cursor, 8, blockOffset) ||
            !readU32(bytes, blockOffset, pageRva) ||
            !readU32(bytes, blockOffset + 4, blockSize)) {
            error = "PE32 relocation block is outside the file";
            return false;
        }
        if (!pageRva && !blockSize) {
            break;
        }
        if (blockSize < 8 || (blockSize & 1) || blockSize > relocationEnd - cursor) {
            error = "PE32 relocation block has an invalid size";
            return false;
        }

        const U32 entryCount = (blockSize - 8) / 2;
        for (U32 entryIndex = 0; entryIndex < entryCount; ++entryIndex) {
            size_t entryOffset = 0;
            U16 entry = 0;
            const U32 entryRva = cursor + 8 + entryIndex * 2;
            if (!rvaToFileOffset(info, bytes, entryRva, 2, entryOffset) ||
                !readU16(bytes, entryOffset, entry)) {
                error = "PE32 relocation entry is outside the file";
                return false;
            }

            const U16 type = entry >> 12;
            if (type == PE_RELOCATION_ABSOLUTE) {
                continue;
            }
            if (type != PE_RELOCATION_HIGHLOW) {
                error = "PE32 relocation table contains an unsupported relocation type";
                return false;
            }

            U32 targetRva = 0;
            if (!addFitsU32(pageRva, entry & 0x0fff, targetRva) ||
                targetRva > info.sizeOfImage - 4) {
                error = "PE32 relocation target is outside the mapped image";
                return false;
            }
            const U32 target = loadBase + targetRva;
            thread->memory->writed(target, thread->memory->readd(target) + delta);
        }

        cursor += blockSize;
    }
    return true;
}

bool bindImports(
    KThread* thread,
    const Pe32MappedImage& image,
    Pe32ImportResolver resolver,
    void* resolverContext,
    std::string& error) {
    if (!resolver) {
        return true;
    }

    for (const Pe32ImportModule& module : image.info.imports) {
        for (const Pe32ImportSymbol& symbol : module.symbols) {
            if (symbol.iatRva > image.info.sizeOfImage - 4) {
                error = "PE32 import address table entry is outside the mapped image";
                return false;
            }

            U32 guestAddress = 0;
            if (!resolver(resolverContext, module, symbol, guestAddress) || !guestAddress) {
                error = "Unable to resolve PE32 import " + module.name + "!";
                error += symbol.byOrdinal ? ("#" + std::to_string(symbol.ordinal)) : symbol.name;
                return false;
            }
            thread->memory->writed(image.loadBase + symbol.iatRva, guestAddress);
        }
    }
    return true;
}

} // namespace

size_t Pe32ImageInfo::importSymbolCount() const {
    size_t result = 0;
    for (const Pe32ImportModule& module : imports) {
        result += module.symbols.size();
    }
    return result;
}

bool Pe32Loader::readFile(const char* path, std::vector<U8>& bytes, std::string& error) {
    bytes.clear();
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) {
        error = "Unable to open PE32 file";
        return false;
    }

    std::streamoff length = input.tellg();
    if (length <= 0 || static_cast<U64>(length) > std::numeric_limits<U32>::max()) {
        error = "PE32 file has an unsupported size";
        return false;
    }
    input.seekg(0, std::ios::beg);
    bytes.resize(static_cast<size_t>(length));
    if (!input.read(reinterpret_cast<char*>(bytes.data()), length)) {
        bytes.clear();
        error = "Unable to read the complete PE32 file";
        return false;
    }
    return true;
}

bool Pe32Loader::inspect(const std::vector<U8>& bytes, Pe32ImageInfo& info, std::string& error) {
    info = Pe32ImageInfo();
    error.clear();

    U16 dosMagic = 0;
    U32 peOffset = 0;
    if (!readU16(bytes, 0, dosMagic) || dosMagic != 0x5a4d || !readU32(bytes, 0x3c, peOffset)) {
        error = "File is not an MZ executable";
        return false;
    }

    U32 signature = 0;
    if (!readU32(bytes, peOffset, signature) || signature != PE_SIGNATURE) {
        error = "File does not contain a PE signature";
        return false;
    }

    size_t fileHeaderOffset = static_cast<size_t>(peOffset) + 4;
    U16 sectionCount = 0;
    U16 optionalHeaderSize = 0;
    if (!readU16(bytes, fileHeaderOffset, info.machine) ||
        !readU16(bytes, fileHeaderOffset + 2, sectionCount) ||
        !readU32(bytes, fileHeaderOffset + 4, info.timestamp) ||
        !readU16(bytes, fileHeaderOffset + 16, optionalHeaderSize) ||
        !readU16(bytes, fileHeaderOffset + 18, info.characteristics)) {
        error = "PE32 COFF header is truncated";
        return false;
    }
    if (info.machine != PE32_MACHINE_I386) {
        error = "PE image is not an i386 executable";
        return false;
    }
    if (!sectionCount || sectionCount > 96) {
        error = "PE32 section count is invalid";
        return false;
    }

    size_t optionalHeaderOffset = fileHeaderOffset + 20;
    U16 optionalMagic = 0;
    if (optionalHeaderSize < 96 ||
        !hasRange(optionalHeaderOffset, optionalHeaderSize, bytes.size()) ||
        !readU16(bytes, optionalHeaderOffset, optionalMagic) ||
        optionalMagic != PE32_OPTIONAL_MAGIC) {
        error = "PE optional header is not PE32";
        return false;
    }

    U32 numberOfDataDirectories = 0;
    if (!readU32(bytes, optionalHeaderOffset + 16, info.entryPointRva) ||
        !readU32(bytes, optionalHeaderOffset + 28, info.imageBase) ||
        !readU32(bytes, optionalHeaderOffset + 32, info.sectionAlignment) ||
        !readU32(bytes, optionalHeaderOffset + 36, info.fileAlignment) ||
        !readU32(bytes, optionalHeaderOffset + 56, info.sizeOfImage) ||
        !readU32(bytes, optionalHeaderOffset + 60, info.sizeOfHeaders) ||
        !readU32(bytes, optionalHeaderOffset + 92, numberOfDataDirectories)) {
        error = "PE32 optional header is truncated";
        return false;
    }

    U32 imageEnd = 0;
    if (!info.imageBase || info.sizeOfImage < 4 || !info.sizeOfHeaders ||
        info.sizeOfHeaders > info.sizeOfImage ||
        info.sizeOfHeaders > bytes.size() ||
        !addFitsU32(info.imageBase, info.sizeOfImage, imageEnd) ||
        info.entryPointRva >= info.sizeOfImage) {
        error = "PE32 image address range is invalid";
        return false;
    }

    if (numberOfDataDirectories > 1 && optionalHeaderSize >= 112) {
        readU32(bytes, optionalHeaderOffset + 104, info.importDirectoryRva);
        readU32(bytes, optionalHeaderOffset + 108, info.importDirectorySize);
    }
    if (numberOfDataDirectories > 5 && optionalHeaderSize >= 144) {
        readU32(bytes, optionalHeaderOffset + 136, info.baseRelocationDirectoryRva);
        readU32(bytes, optionalHeaderOffset + 140, info.baseRelocationDirectorySize);
    }
    if (numberOfDataDirectories > 9 && optionalHeaderSize >= 176) {
        readU32(bytes, optionalHeaderOffset + 168, info.tlsDirectoryRva);
        readU32(bytes, optionalHeaderOffset + 172, info.tlsDirectorySize);
    }

    size_t sectionTableOffset = optionalHeaderOffset + optionalHeaderSize;
    if (!hasRange(sectionTableOffset, static_cast<size_t>(sectionCount) * 40, bytes.size())) {
        error = "PE32 section table is truncated";
        return false;
    }

    for (U16 index = 0; index < sectionCount; ++index) {
        size_t sectionOffset = sectionTableOffset + static_cast<size_t>(index) * 40;
        Pe32SectionInfo section;
        size_t nameLength = 0;
        while (nameLength < 8 && bytes[sectionOffset + nameLength]) {
            ++nameLength;
        }
        section.name.assign(reinterpret_cast<const char*>(&bytes[sectionOffset]), nameLength);
        readU32(bytes, sectionOffset + 8, section.virtualSize);
        readU32(bytes, sectionOffset + 12, section.virtualAddress);
        readU32(bytes, sectionOffset + 16, section.rawDataSize);
        readU32(bytes, sectionOffset + 20, section.rawDataOffset);
        readU32(bytes, sectionOffset + 36, section.characteristics);

        U32 virtualSpan = std::max(section.virtualSize, section.rawDataSize);
        U32 virtualEnd = 0;
        if (!addFitsU32(section.virtualAddress, virtualSpan, virtualEnd) ||
            virtualEnd > info.sizeOfImage ||
            (section.rawDataSize && !hasRange(section.rawDataOffset, section.rawDataSize, bytes.size()))) {
            error = "PE32 section range is invalid";
            return false;
        }
        info.sections.push_back(section);
    }

    return parseImports(bytes, info, error);
}

bool Pe32Loader::mapImage(KThread* thread, const std::vector<U8>& bytes, Pe32MappedImage& image, std::string& error) {
    return mapImageWithImports(thread, bytes, 0, nullptr, nullptr, image, error);
}

bool Pe32Loader::mapImageAt(
    KThread* thread,
    const std::vector<U8>& bytes,
    U32 loadBase,
    Pe32MappedImage& image,
    std::string& error) {
    return mapImageWithImports(thread, bytes, loadBase, nullptr, nullptr, image, error);
}

bool Pe32Loader::mapImageWithImports(
    KThread* thread,
    const std::vector<U8>& bytes,
    U32 loadBase,
    Pe32ImportResolver resolver,
    void* resolverContext,
    Pe32MappedImage& image,
    std::string& error) {
    image = Pe32MappedImage();
    if (!thread || !thread->memory) {
        error = "PE32 loader requires a guest thread and memory space";
        return false;
    }
    if (!inspect(bytes, image.info, error)) {
        return false;
    }
    if (!loadBase) {
        loadBase = image.info.imageBase;
    }
    U32 imageEnd = 0;
    if (!addFitsU32(loadBase, image.info.sizeOfImage, imageEnd)) {
        error = "Requested PE32 load address overflows the guest address space";
        return false;
    }

    U32 mapped = thread->memory->mmap(
        thread,
        loadBase,
        image.info.sizeOfImage,
        K_PROT_READ | K_PROT_WRITE | K_PROT_EXEC,
        K_MAP_FIXED | K_MAP_PRIVATE | K_MAP_ANONYMOUS,
        -1,
        0);
    if (mapped != loadBase) {
        error = "Unable to reserve the requested PE32 guest image range";
        return false;
    }

    thread->memory->memset(loadBase, 0, image.info.sizeOfImage);
    U32 headerBytes = std::min<U32>(image.info.sizeOfHeaders, static_cast<U32>(bytes.size()));
    thread->memory->memcpy(loadBase, bytes.data(), headerBytes);

    for (const Pe32SectionInfo& section : image.info.sections) {
        if (section.rawDataSize) {
            thread->memory->memcpy(
                loadBase + section.virtualAddress,
                bytes.data() + section.rawDataOffset,
                section.rawDataSize);
        }
    }

    if (!applyBaseRelocations(thread, bytes, image.info, loadBase, error)) {
        thread->memory->unmap(loadBase, image.info.sizeOfImage);
        return false;
    }

    image.loadBase = loadBase;
    image.entryPoint = loadBase + image.info.entryPointRva;
    if (!bindImports(thread, image, resolver, resolverContext, error)) {
        thread->memory->unmap(loadBase, image.info.sizeOfImage);
        image = Pe32MappedImage();
        return false;
    }

    U32 headerProtectionSize = K_ROUND_UP_TO_PAGE(image.info.sizeOfHeaders);
    if (thread->memory->mprotect(thread, loadBase, headerProtectionSize, K_PROT_READ) != 0) {
        thread->memory->unmap(loadBase, image.info.sizeOfImage);
        error = "Unable to apply PE32 header memory protection";
        return false;
    }

    for (const Pe32SectionInfo& section : image.info.sections) {
        U32 span = std::max(section.virtualSize, section.rawDataSize);
        if (!span) {
            continue;
        }
        U32 address = loadBase + section.virtualAddress;
        U32 alignedAddress = address & ~K_PAGE_MASK;
        U32 alignmentPrefix = address - alignedAddress;
        U32 protectedLength = K_ROUND_UP_TO_PAGE(span + alignmentPrefix);
        if (thread->memory->mprotect(thread, alignedAddress, protectedLength, sectionProtection(section)) != 0) {
            thread->memory->unmap(loadBase, image.info.sizeOfImage);
            error = "Unable to apply PE32 section memory protection";
            return false;
        }
    }

    return true;
}
