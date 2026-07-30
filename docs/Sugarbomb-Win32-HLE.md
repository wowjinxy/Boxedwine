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

The Windows x64 host now enters the original FalloutNV 1.4.0.525 executable at
`0x00ECC4DB` without Wine and continues through engine startup. A 30-second
diagnostic run executes about 17.2 million guest CPU slices and 9.9 million
bridged native calls without an unresolved import or guest page fault. During
that run Fallout:

- opens the base BSA archives and enumerates installed ESM/NAM content;
- registers both game windows and creates a real D3D9 device owned by the
  64-bit host;
- drains a thread-owned USER32 queue and calls its registered 32-bit WndProc at
  `0x0086A0A0` for show, activation, focus, size, paint, and native host mouse
  messages;
- creates textures, cube textures, render targets, depth surfaces, shaders,
  declarations, and vertex/index buffers while retaining 32-bit guest COM
  identities;
- decodes 96 texture images through the native x64 D3DX9 runtime, completes
  roughly 600 translated indexed draws, and runs about 300 complete
  `BeginScene`/`EndScene`/`Present` cycles;
- initializes DirectInput 8, XInput, DirectSound 8, WinMM, and COM;
- constructs a DirectShow filter graph for `MainTitle.mp3`, renders its source
  filter, queries media position, sets volume, runs, and pauses playback;
- initializes Bink sound support and creates its `MoviePlayer` guest thread;
- launches archive, task-manager, background-clone, and additional engine
  worker threads using guest-visible kernel synchronization objects.

At the end of the diagnostic window the main thread is sleeping on its normal
frame-timer path while worker threads are parked on kernel-object waits.
Fallout's 32-bit guest `HWND` remains an integer in guest memory, while its
corresponding native `HWND` and every native D3D pointer remain private to the
64-bit host.

The renderer checkpoint is no longer synthetic. Sugarbomb translates
Fallout's render targets, surfaces, textures, texture locks, vertex/index
buffers, declarations, shader bytecode, constants, render/sampler state, and
draw calls to a native x64 `IDirect3DDevice9`. It also forwards the surface-copy
operations used by the engine and can capture the active render target or
swap-chain backbuffer for deterministic diagnostics. A verified 1920x1080
backbuffer capture contains Fallout's fully rendered Obsidian Entertainment
startup splash. Audio output, video decoding, raw/DirectInput event fidelity,
and enough remaining Win32 behavior to reach an interactive menu are still
incomplete, so this is not yet a playable build.

The runtime currently builds:

- an 8 MiB 32-bit guest stack;
- a minimal Windows PEB, TEB, process-parameters block, and `FS` TLS segment;
- the executable's static PE TLS slot and 708-byte `.tls` template;
- dynamic TLS slots, process/CRT heaps, and logical `VirtualAlloc` reservations;
- a read/execute-only import-thunk arena at `0x60000000`;
- a cooperative x86 guest scheduler with suspended/runnable/completed thread
  states, timed sleeps, and semaphore/event/mutex/thread waits;
- filesystem, profile/INI, registry, Shell32, USER32, GDI32, input, audio,
  DirectShow, synthetic Bink, and a broad D3D9/D3DX compatibility surface;
- a per-thread 32-bit `MSG` queue, creation-time window lifecycle messages, and
  translation of native keyboard, character, mouse, and focus events;
- initial Kernel32 timing, process, heap, locale, console, exception, atomic,
  critical-section, memory-status, and virtual-memory services;
- version-keyed Fallout 1.4 bootstrap objects for two startup-order races: the
  Bink manager and Havok memory system. The Havok bridge initializes the
  game's per-thread memory router and allocates from the tracked 32-bit guest
  heap backed by the 64-bit host.

Large `MEM_RESERVE` calls remain logical until committed, so Fallout can see its
normal 32-bit address layout without forcing the 64-bit host to back every
reserved guest page. In the verified trace it reserves 200 MiB and 64 MiB
arenas, then commits only the ranges it touches.

Focused tests verify:

- invalid PE images are rejected;
- PE32 headers, sections, imports, and protection flags are parsed;
- the image is mapped at its preferred 32-bit base and its x86 entry point runs;
- a resolver binds imported symbols to supplied guest thunk addresses before
  final section protections are applied;
- `IMAGE_REL_BASED_HIGHLOW` relocations allow DLLs with colliding preferred
  bases to be mapped elsewhere;
- PE TLS-directory metadata is retained for loader initialization;
- stdcall import thunks contain the correct callback and stack-cleanup operands,
  preserve their module/symbol diagnostics, and become read/execute-only;
- an x86 guest can call a registered 64-bit C++ function through `INT 9Ch`;
- a native callback can redirect the x86 CPU to a requested guest EIP, which is
  the control-transfer primitive used to enter guest callback functions.

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
Sugarbomb generates 16-byte guest stubs with the appropriate `stdcall` cleanup
and patches their addresses into the PE IAT. Unsupported calls stop at a named
`module!symbol` boundary instead of jumping through an unresolved host pointer.
Callbacks may also redirect the emulated EIP. USER32 uses that path to construct
a 32-bit stdcall WndProc frame, enter Fallout's registered procedure, and return
through a Sugarbomb thunk that restores the interrupted import frame. Pending
returns are stacked per guest thread, so nested guest dispatch remains valid.

On Windows x64 JIT builds, the direct runtime also installs BoxedWine's vectored
host-exception handler. Guest page faults are therefore translated back into
the emulated CPU instead of escaping as native access violations.

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

1. **Process core:** PEB/TEB, static and dynamic TLS, virtual memory, heap,
   timing, exceptions, module lookup, console handles, Unicode conversion,
   critical sections, kernel objects, guest threads, and cooperative waits.
2. **NVSE bootstrap:** DLL exports, import binding, CRT entry points, plugin
   enumeration, `DllMain`, and NVSE messaging/interfaces.
3. **Window and input:** USER32, raw input, DirectInput 8, XInput, cursor and
   message-loop behavior. The guest/native HWND bridge and host message pump
   create visible output. `PeekMessageA`, `DispatchMessageA`, and `SendMessageA`
   now deliver lifecycle plus native keyboard/mouse/focus events to Fallout's
   guest WndProc. Remaining work includes raw input, richer cursor/capture
   behavior, and feeding real device state/events through DirectInput and
   XInput.
4. **Rendering:** D3D9 and the required D3DX9 surface, translated directly to
   Sugarbomb's renderer. The guest COM/resource model, native presentation
   window, x64 D3D9 resource/state/shader/draw translation, D3DX image decoding,
   and surface-copy paths are in place. Remaining work includes less common
   resource methods, volume textures, D3DX shader helpers, reset/lost-device
   edge cases, and frame-by-frame validation beyond the startup splash.
5. **Audio/video:** DirectSound, WinMM, DirectShow, and Bink integration. The
   current facades preserve guest contracts and timing but do not decode or
   emit media yet.
6. **Services:** COM, registry, sockets, shell helpers, and the small Steam API
   surface the game actually exercises.

Implement calls from traces and import/use-site evidence rather than attempting
all of Win32. Unsupported imports should fail deterministically with the module,
symbol, guest call site, and argument snapshot.

## Build and inspect

From the repository root:

```powershell
.\tools\sugarbomb\build-win64.ps1 -Configuration Test
.\project\msvc\BoxedWine\x64\Test\BoxedWine.exe 0 5 1

.\tools\sugarbomb\build-win64.ps1 -Configuration Release
.\tools\sugarbomb\inspect-pe32.ps1 'D:\path\to\FalloutNV.exe'
.\tools\sugarbomb\inspect-pe32.ps1 'D:\path\to\FalloutNV.exe' -Imports
.\project\msvc\BoxedWine\x64\Release\BoxedWine.exe --sugarbomb-run 'D:\path\to\FalloutNV.exe'
```

For deterministic diagnostics, the runtime accepts optional environment
variables. They do not change the guest ABI:

```powershell
$env:SUGARBOMB_MAX_RUN_SLICES = '2600000'
$env:SUGARBOMB_MAX_RUN_MILLISECONDS = '20000'
$env:SUGARBOMB_NO_HOST_WINDOW = '1' # optional for unattended runs
$env:SUGARBOMB_CAPTURE_FRAME = 'D:\captures\fallout-present.png'
$env:SUGARBOMB_CAPTURE_AFTER_PRESENTS = '100'
$env:SUGARBOMB_CAPTURE_FINAL_FRAME = 'D:\captures\fallout-final-target.png'
$env:SUGARBOMB_CAPTURE_FINAL_BACKBUFFER = 'D:\captures\fallout-final-backbuffer.png'
```

When either diagnostic budget expires, Sugarbomb prints every guest thread's
state/EIP, kernel-wait details, the busiest bridged APIs, and selected graphics
milestones. Renderer captures are written by the native D3DX9 path and therefore
do not depend on desktop focus or screen-compositor capture behavior.

The Visual Studio project currently targets the newer v145 toolset upstream.
The build helper explicitly selects the installed v143 toolset from Visual
Studio 2022.

## Non-goals

- Loading 32-bit Windows system DLLs into the 64-bit host process.
- Passing native pointers through 32-bit guest fields.
- Reproducing every Windows version quirk before the game needs it.
- Depending on a Wine filesystem or a separate Wine process.

## Current boundary

This is an executable compatibility-layer checkpoint, not a playable build.
Fallout now survives the previously missing kernel-object, guest-thread,
USER32, D3D9, audio, DirectShow, Bink, and startup-order singleton boundaries.
The 64-bit host owns the window and real D3D9 objects, translates Fallout's
32-bit graphics workload, delivers host and lifecycle messages through
Fallout's own 32-bit WndProc, and produces a correctly textured startup splash
without exposing native pointers to the guest. The next major work is to find
the remaining post-splash state gate, finish the D3D9/D3DX, input, and media
behaviors needed to reach the interactive menu, persist remaining virtual-file
operations, and load `nvse_1_4.dll` plus NVSE plugins in the same guest process.
