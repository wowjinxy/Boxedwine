/*
 *  Copyright (C) 2026  The BoxedWine Team
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifndef __TEST_PE32_LOADER_H__
#define __TEST_PE32_LOADER_H__

void testPe32LoaderRejectsInvalidImage();
void testPe32LoaderMapsAndExecutesImage();
void testSugarbombThunkArena();
void testSugarbombNativeBridge();
void testSugarbombNativeBridgeControlTransfer();

#endif
