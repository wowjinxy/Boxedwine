# Sugarbomb direct Win32 guest

This branch is a proof of a Wine-free execution path for Fallout: New Vegas,
NVSE, and other 32-bit Windows programs. It keeps BoxedWine's x86 decoder/JIT,
soft MMU, and scheduler, but replaces the Linux-plus-Wine userland with a PE32
loader and a purpose-built Win32 high-level emulation (HLE) layer.

The normal BoxedWine runtime still exists on this branch. The Sugarbomb path is
additive while its Win32 coverage is being built.

## Execution target

The primary guest executable is **FalloutNV.exe 1.4.0.525**. Sugarbomb maps it
at `0x00400000`, builds its Windows process environment, binds its imports, and
starts its PE entry point.

`nvse_1_4.dll` is not the execution target. It is the xNVSE runtime DLL for the
FalloutNV 1.4 executable and is mapped into the same guest process afterward.
Sugarbomb owns that loading step, so the deployed path does not run
`nvse_loader.exe`.

## Verified milestone

The Windows x64 host builds with Visual Studio 2022 and runs a synthetic PE32
image directly in its emulated 32-bit address space. Focused tests verify:

- invalid PE images are rejected;
- PE32 headers, sections, imports, and protection flags are parsed;
- the image is mapped at its preferred 32-bit base and its x86 entry point runs;
- a resolver binds imported symbols to supplied guest thunk addresses before
  final section protections are applied;
- `IMAGE_REL_BASED_HIGHLOW` relocations allow DLLs with colliding preferred
  bases to be mapped elsewhere;
- an x86 guest can call a registered 64-bit C++ function through `INT 9Ch`.

The PE inspector also parses the primary executable and its optional extension
modules without Wine:

| Module | Preferred base | Image size | Imports |
| --- | ---: | ---: | ---: |
| `FalloutNV.exe` (unpacked 1.4.0.525) | `0x00400000` | `0x0107B000` | 17 modules / 280 symbols |
| `nvse_loader.exe` | `0x00400000` | `0x0002B000` | 11 modules / 87 symbols |
| xNVSE 6.4.8 `nvse_1_4.dll` (Release) | `0x10000000` | `0x00159000` | 13 modules / 264 symbols |
| `ZeGaryHax.dll` | `0x10000000` | `0x001E8000` | 11 modules / 234 symbols |

`nvse_1_4.dll` names the DLL selected for the FalloutNV 1.4 game runtime; it
does not mean NVSE version 1.4. The validated Release DLL reports file/product
version 6.4.8.

The xNVSE and plugin DLLs above demonstrate why base relocation support is
required: both prefer `0x10000000`.

## Architecture

```text
64-bit Windows process
|
+-- Sugarbomb host
|   +-- renderer, audio, input, filesystem, networking
|   +-- native object store (64-bit pointers never enter guest memory)
|   +-- Win32 HLE callback registry
|
+-- BoxedWine x86 CPU/JIT and soft MMU
    +-- 4 GiB guest address model (32-bit pointers remain exact)
    +-- FalloutNV.exe at 0x00400000
    +-- relocated PE32 DLLs
    +-- NVSE and NVSE plugins
    +-- guest import stubs -> INT 9Ch -> 64-bit callbacks
```

Guest structures, vtables, patch sites, and absolute NVSE addresses remain
32-bit values. Native host objects live in ordinary 64-bit memory and are
referred to by validated 32-bit handles. A guest pointer is never cast to a
host pointer.

`INT 9Ch` follows the callback convention BoxedWine already uses for OpenGL,
Vulkan, and X11 traps. The callback index is at the top of the guest stack.
The next layer will generate import stubs with the appropriate `stdcall`,
`cdecl`, or COM cleanup behavior and patch their addresses into each PE IAT.

## Why the NVSE loader executable is unnecessary

Sugarbomb can own startup:

1. map `FalloutNV.exe`;
2. bind its imports to Win32 HLE and native subsystem stubs;
3. map the matching NVSE runtime DLL;
4. reproduce the small amount of loader initialization NVSE expects;
5. discover and map `Data/NVSE/Plugins/*.dll`;
6. call each DLL entry point and NVSE Query/Load export in guest context.

That removes Wine and `nvse_loader.exe` from the deployed runtime. The existing
loader remains useful as documentation and a behavioral oracle.

## Win32 coverage plan

PE loading is the foundation, not the whole Windows contract. Implement APIs in
dependency order and validate each group with small guest fixtures:

1. **Process core:** PEB/TEB, TLS, virtual memory, heap, thread/event/critical
   section primitives, timing, exceptions, module lookup, files, paths, and
   Unicode conversion.
2. **NVSE bootstrap:** DLL exports, import binding, CRT entry points, plugin
   enumeration, `DllMain`, and NVSE messaging/interfaces.
3. **Window and input:** USER32, raw input, DirectInput 8, XInput, cursor and
   message-loop behavior.
4. **Rendering:** D3D9 and the required D3DX9 surface, translated directly to
   Sugarbomb's renderer.
5. **Audio/video:** DirectSound, WinMM, and Bink integration.
6. **Services:** COM, registry, sockets, shell helpers, and the small Steam API
   surface the game actually exercises.

Implement calls from traces and import/use-site evidence rather than attempting
all of Win32. Unsupported imports should fail deterministically with the module,
symbol, guest call site, and argument snapshot.

## Build and inspect

From the repository root:

```powershell
.\tools\sugarbomb\build-win64.ps1 -Configuration Test
.\project\msvc\BoxedWine\x64\Test\BoxedWine.exe 0 3 1

.\tools\sugarbomb\build-win64.ps1 -Configuration Release
.\tools\sugarbomb\inspect-pe32.ps1 'D:\path\to\FalloutNV.exe'
.\tools\sugarbomb\inspect-pe32.ps1 'D:\path\to\FalloutNV.exe' -Imports
```

The Visual Studio project currently targets the newer v145 toolset upstream.
The build helper explicitly selects the installed v143 toolset from Visual
Studio 2022.

## Non-goals

- Loading 32-bit Windows system DLLs into the 64-bit host process.
- Passing native pointers through 32-bit guest fields.
- Reproducing every Windows version quirk before the game needs it.
- Depending on a Wine filesystem or a separate Wine process.
