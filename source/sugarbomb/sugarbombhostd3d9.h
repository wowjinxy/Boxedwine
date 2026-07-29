/*
 *  Copyright (C) 2026  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifndef SUGARBOMB_HOST_D3D9_H
#define SUGARBOMB_HOST_D3D9_H

#include <cstddef>
#include <cstdint>

struct SugarbombHostD3DImageInfo {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::uint32_t depth = 0;
    std::uint32_t mipLevels = 0;
    std::uint32_t format = 0;
    std::uint32_t resourceType = 0;
    std::uint32_t fileFormat = 0;
};

class SugarbombHostD3D9 {
public:
    struct Impl;

    SugarbombHostD3D9();
    ~SugarbombHostD3D9();

    SugarbombHostD3D9(const SugarbombHostD3D9&) = delete;
    SugarbombHostD3D9& operator=(const SugarbombHostD3D9&) = delete;

    bool initialize(
        std::uintptr_t nativeWindow,
        std::uint32_t width,
        std::uint32_t height);
    bool reset(std::uint32_t width, std::uint32_t height);
    bool ready() const;
    void shutdown();

    bool registerBackBuffer(std::uint32_t guestKey);
    bool createSurface(
        std::uint32_t guestKey,
        std::uint32_t width,
        std::uint32_t height,
        std::uint32_t format,
        std::uint32_t usage,
        std::uint32_t pool,
        std::uint32_t multiSampleType,
        std::uint32_t multiSampleQuality);
    bool aliasTextureSurface(
        std::uint32_t surfaceKey,
        std::uint32_t textureKey,
        std::uint32_t face,
        std::uint32_t level);
    bool createTexture(
        std::uint32_t guestKey,
        std::uint32_t width,
        std::uint32_t height,
        std::uint32_t levels,
        std::uint32_t usage,
        std::uint32_t format,
        std::uint32_t pool,
        bool cube);
    bool createBuffer(
        std::uint32_t guestKey,
        std::uint32_t length,
        std::uint32_t usage,
        std::uint32_t format,
        std::uint32_t pool,
        bool indexBuffer);
    bool createVertexDeclaration(
        std::uint32_t guestKey,
        const void* elements,
        std::size_t byteCount);
    bool createShader(
        std::uint32_t guestKey,
        bool pixelShader,
        const std::uint32_t* bytecode,
        std::size_t dwordCount);
    bool getImageInfoFromMemory(
        const void* bytes,
        std::uint32_t byteCount,
        SugarbombHostD3DImageInfo& info);
    bool createTextureFromMemory(
        std::uint32_t guestKey,
        const void* bytes,
        std::uint32_t byteCount,
        bool cube);
    bool captureRenderTarget(const char* path);
    bool captureBackBuffer(const char* path);
    void releaseResource(std::uint32_t guestKey);

    bool uploadSurface(
        std::uint32_t guestKey,
        const void* pixels,
        std::uint32_t sourcePitch,
        std::uint32_t width,
        std::uint32_t height);
    bool uploadTexture(
        std::uint32_t guestKey,
        std::uint32_t face,
        std::uint32_t level,
        const void* pixels,
        std::uint32_t sourcePitch,
        std::uint32_t rowCount);
    bool uploadBuffer(
        std::uint32_t guestKey,
        const void* bytes,
        std::uint32_t offset,
        std::uint32_t byteCount);
    bool updateSurface(
        std::uint32_t sourceKey,
        const void* sourceRectangle,
        std::uint32_t destinationKey,
        const void* destinationPoint);
    bool updateTexture(
        std::uint32_t sourceKey,
        std::uint32_t destinationKey);
    bool getRenderTargetData(
        std::uint32_t sourceKey,
        std::uint32_t destinationKey);
    bool stretchRect(
        std::uint32_t sourceKey,
        const void* sourceRectangle,
        std::uint32_t destinationKey,
        const void* destinationRectangle,
        std::uint32_t filter);
    bool colorFill(
        std::uint32_t surfaceKey,
        const void* rectangle,
        std::uint32_t color);
    bool loadSurfaceFromSurface(
        std::uint32_t destinationKey,
        const void* destinationRectangle,
        std::uint32_t sourceKey,
        const void* sourceRectangle,
        std::uint32_t filter,
        std::uint32_t colorKey);

    bool beginScene();
    bool endScene();
    bool clear(
        std::uint32_t count,
        const void* rectangles,
        std::uint32_t flags,
        std::uint32_t color,
        float depth,
        std::uint32_t stencil);
    bool present();
    bool setRenderTarget(std::uint32_t index, std::uint32_t surfaceKey);
    bool setDepthStencilSurface(std::uint32_t surfaceKey);
    bool setViewport(const void* viewport);
    bool setTransform(std::uint32_t state, const float* matrix);
    bool setRenderState(std::uint32_t state, std::uint32_t value);
    bool setTexture(std::uint32_t stage, std::uint32_t textureKey);
    bool setTextureStageState(
        std::uint32_t stage,
        std::uint32_t state,
        std::uint32_t value);
    bool setSamplerState(
        std::uint32_t sampler,
        std::uint32_t state,
        std::uint32_t value);
    bool setScissorRect(const void* rectangle);
    bool setVertexDeclaration(std::uint32_t guestKey);
    bool setFvf(std::uint32_t fvf);
    bool setVertexShader(std::uint32_t guestKey);
    bool setPixelShader(std::uint32_t guestKey);
    bool setVertexShaderConstantF(
        std::uint32_t startRegister,
        const float* values,
        std::uint32_t vectorCount);
    bool setVertexShaderConstantI(
        std::uint32_t startRegister,
        const std::int32_t* values,
        std::uint32_t vectorCount);
    bool setVertexShaderConstantB(
        std::uint32_t startRegister,
        const std::int32_t* values,
        std::uint32_t valueCount);
    bool setPixelShaderConstantF(
        std::uint32_t startRegister,
        const float* values,
        std::uint32_t vectorCount);
    bool setPixelShaderConstantI(
        std::uint32_t startRegister,
        const std::int32_t* values,
        std::uint32_t vectorCount);
    bool setPixelShaderConstantB(
        std::uint32_t startRegister,
        const std::int32_t* values,
        std::uint32_t valueCount);
    bool setStreamSource(
        std::uint32_t stream,
        std::uint32_t bufferKey,
        std::uint32_t offset,
        std::uint32_t stride);
    bool setStreamSourceFrequency(
        std::uint32_t stream,
        std::uint32_t setting);
    bool setIndices(std::uint32_t bufferKey);
    bool drawPrimitive(
        std::uint32_t primitiveType,
        std::uint32_t startVertex,
        std::uint32_t primitiveCount);
    bool drawIndexedPrimitive(
        std::uint32_t primitiveType,
        std::int32_t baseVertexIndex,
        std::uint32_t minimumVertexIndex,
        std::uint32_t vertexCount,
        std::uint32_t startIndex,
        std::uint32_t primitiveCount);

private:
    Impl* impl;
};

#endif
