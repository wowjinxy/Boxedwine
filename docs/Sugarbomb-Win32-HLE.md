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

The retail Steam executable is CEG-packed on disk. Sugarbomb recognizes that
exact image identity and selects a verified unpacked 1.4.0.525 sidecar for the
bytes it maps, while retaining the user-supplied `FalloutNV.exe` path in the
guest command line, process parameters, module filename, working directory,
and filesystem view. It rejects an unverified sidecar instead of executing
packed bytes as x86 code.

`nvse_1_4.dll` is not the execution target. It is the xNVSE runtime DLL for the
FalloutNV 1.4 executable and is staged in the same guest process. Sugarbomb
hooks Fallout's CRT-to-WinMain call at `0x00ECC46B`, loads xNVSE there through
Fallout's own `LoadLibraryA` IAT, and then tail-jumps to the original WinMain at
`0x0086A850`. Sugarbomb therefore owns the loading step without running
`nvse_loader.exe`, while preserving the initialization order expected by the
game and its plugins.

## Verified milestone

The Windows x64 host now enters the original FalloutNV 1.4.0.525 executable at
`0x00ECC4DB` without Wine and continues through the intro to the fully rendered
main menu. A 90-second diagnostic run completes 7,917 native D3D9 presentation
cycles and 116,768 translated indexed draws without an unresolved import, guest
page fault, or host D3D failure. During that run Fallout:

- opens the base BSA archives and enumerates installed ESM/NAM content;
- registers both game windows and creates a real D3D9 device owned by the
  64-bit host;
- drains a thread-owned USER32 queue and calls its registered 32-bit WndProc at
  `0x0086A0A0` for show, activation, focus, size, paint, and native host mouse
  messages;
- creates textures, cube textures, render targets, depth surfaces, shaders,
  declarations, and vertex/index buffers while retaining 32-bit guest COM
  identities;
- decodes 135 texture images through the native x64 D3DX9 runtime, completes
  116,768 translated indexed draws, and runs 7,917 complete
  `BeginScene`/`EndScene`/`Present` cycles;
- initializes DirectInput 8, XInput, DirectSound 8, WinMM, and COM;
- constructs a DirectShow filter graph for `MainTitle.mp3`, renders its source
  filter, queries media position, sets volume, runs, and pauses playback;
- initializes Bink sound support and creates its `MoviePlayer` guest thread;
- launches archive, task-manager, background-clone, and additional engine
  worker threads using guest-visible kernel synchronization objects.

The same trace drains 8,891 `PeekMessageA` calls, dispatches 1,283 messages
through Fallout's original guest WndProc, and observes all 1,283 guest returns.
At the end of the diagnostic window the main thread remains runnable while
worker threads are parked on their normal kernel-object waits. Fallout's 32-bit
guest `HWND` remains an integer in guest memory, while its corresponding native
`HWND` and every native D3D pointer remain private to the 64-bit host.

The presentation surface is now an ordinary top-level Windows application
window, owned by a dedicated native UI thread and message loop. It has a normal
title bar, taskbar and Alt-Tab presence, and Windows controls its foreground
and focus state. A visible 3840x2160 validation reached the main menu, accepted
two extended Down-arrow scan-code events through the foreground native `HWND`,
reported the corresponding DirectInput `DIK_DOWN` (`0xD0`) press/release
records, and visibly advanced the Fallout menu highlight from no selection to
`Continue` and then `New`. Focus changes caused by desktop capture were also
released and reacquired normally rather than being forced by the runtime.

The staged xNVSE 6.4.8 runtime now initializes automatically at Fallout's real
WinMain boundary. A bounded headless smoke run completes both PE TLS callbacks,
the DLL entry point, all 909 UCRT initializer calls, and 79 exit-handler
registrations. xNVSE reads `Data/NVSE/nvse_config.ini`, identifies and patches
the Fallout image, discovers a configured `mlf.dll` plugin, validates it with
ImageHlp, maps and relocates it, runs its CRT/DllMain, resolves
`NVSEPlugin_Query` and `NVSEPlugin_Load`, and reports `MLF` version 3 loaded
correctly. Fallout then continues through archive/plugin discovery, window and
DirectInput creation, audio and DirectShow setup, D3D9 device/resource creation,
and seven complete presentation cycles in a 1.5-million-slice run. The former
R6030 “CRT not initialized” failure is gone because plugin Load now occurs after
Fallout's executable CRT startup. No Wine process, `nvse_loader.exe`, unresolved
import, or host crash is involved.

Dynamic guest DLL placement now treats logical `MEM_RESERVE` regions as
occupied even when their pages have not been committed. This prevents an NVSE
plugin from being placed in a hole that Fallout later commits from one of its
large reserved arenas. With that rule, MLF relocates to
`0x18800000-0x18807000` instead of overlapping the arena at `0x18000000`.
The guest heap also coalesces and reuses freed page ranges instead of consuming
a fresh page-aligned address for every small CRT allocation. A 210-second
headless Fallout+xNVSE+MLF smoke run completed 156,422,420 CPU slices,
148,437,498 native API calls, and 21,588 D3D9 presents, stopping only at the
configured wall-clock budget. Across 144,134 allocations it reused 17,712
freed ranges and kept its high-water address at `0x44E52000`, well below the
`0x5F000000` heap boundary. It exercised guest-only
`RtlCaptureStackBackTrace` without an unresolved import, guest page fault, or
allocation failure. The debug-UCRT `_callnewh` no-handler path is implemented
as the ABI-correct fallback but was not needed during the verified run.

The renderer checkpoint is no longer synthetic. Sugarbomb translates
Fallout's render targets, surfaces, textures, texture locks, vertex/index
buffers, declarations, shader bytecode, constants, render/sampler state, and
draw calls to a native x64 `IDirect3DDevice9`. It also forwards the surface-copy
operations used by the engine and can capture the active render target or
swap-chain backbuffer for deterministic diagnostics. A verified 1920x1080
backbuffer capture contains Fallout's fully rendered main menu with the logo,
Sunset Sarsaparilla sign, cursor, and all seven menu entries. Cursor-coordinate
and menu-action validation, audio output, and video decoding are still
incomplete, so the visible menu is not yet a playable build.

The runtime currently builds:

- an 8 MiB 32-bit guest stack;
- a minimal Windows PEB, TEB, process-parameters block, and `FS` TLS segment;
- per-module, per-thread static PE TLS, including Fallout's 708-byte template
  and xNVSE's 20,746-byte template plus its two process-attach callbacks;
- dynamic TLS slots, reusable/coalescing process and CRT heaps, and logical
  `VirtualAlloc` reservations;
- a read/execute-only import-thunk arena at `0x60000000`;
- a guest DLL registry with collision-safe preferred-base mapping, HIGHLOW
  relocation, logical-reservation-aware placement, name/ordinal export lookup,
  incremental import thunks, and Kernel32 module APIs;
- automatic staging of `nvse_1_4.dll` beside Fallout at its preferred
  `0x10000000` base, with `StartNVSE` discovered from the real export table and
  automatic TLS/PE-entry initialization from an xNVSE-compatible hook at
  Fallout's CRT-to-WinMain boundary;
- dynamic PE32 DLL process initialization for both newly mapped and prestaged
  modules, including nested `LoadLibrary` calls, TLS callbacks, CRT/DllMain,
  relocation, exports, and return to the interrupted guest import thunk;
- an optional `SUGARBOMB_NVSE_PLUGIN_PATHS` filesystem overlay that exposes
  selected DLLs or plugin directories through `Data/NVSE/Plugins` without
  copying files into the game installation;
- a cooperative x86 guest scheduler with suspended/runnable/completed thread
  states, timed sleeps, and semaphore/event/mutex/thread waits;
- filesystem, profile/INI, registry, Shell32, USER32, GDI32, input, audio,
  DirectShow, synthetic Bink, and a broad D3D9/D3DX compatibility surface;
- a per-thread 32-bit `MSG` queue, creation-time window lifecycle messages, and
  translation of native keyboard, character, mouse, and focus events;
- distinct top-level and child-window activation semantics, preserving
  Fallout's top-level active `HWND` while its child device window owns D3D9
  presentation;
- native foreground/focus ownership for normal application runs, with
  activation loss and reacquisition forwarded to Fallout instead of synthesized
  by the guest runtime;
- host-backed DirectInput keyboard and mouse state, relative axes, wheel and
  button state, buffered `DIDEVICEOBJECTDATA`, and idempotent device
  acquire/unacquire behavior, including foreground cooperative-level loss and
  reacquisition across native focus changes;
- native raw-mouse deltas, exclusive foreground capture and clipping, and
  guest-driven host cursor visibility, with legacy `WM_MOUSEMOVE` retained as a
  registration fallback;
- initial Kernel32 timing, process, heap, locale, console, exception, atomic,
  critical-section, memory-status, and virtual-memory services;
- the UCRT/MSVCP surface exercised by xNVSE startup, including initializer and
  on-exit tables, guest `FILE*` streams, formatting/scanning, locale, string,
  character-classification, parsing, math, heap, SRW-lock, and condition-variable
  operations, plus the no-handler `_callnewh` contract;
- guest-only `RtlCaptureStackBackTrace`/`CaptureStackBackTrace`, which returns
  validated 32-bit guest return addresses without exposing host stack pointers;
- executable-page protection tracking for xNVSE patching. Guest memory writes
  synchronously invalidate translated code, so Win32
  `FlushInstructionCache` does not destroy the block currently returning
  through the native callback bridge;
- version-keyed Fallout 1.4 bootstrap objects for two startup-order races: the
  Bink manager and Havok memory system. The Havok bridge initializes the
  game's per-thread memory router and allocates from the tracked 32-bit guest
  heap backed by the 64-bit host.

Large `MEM_RESERVE` calls remain logical until committed, so Fallout can see its
normal 32-bit address layout without forcing the 64-bit host to back every
reserved guest page. In the verified trace it reserves 200 MiB and 64 MiB
arenas, then commits only the ranges it touches. Dynamic DLL allocation checks
both committed pages and these logical reservations before choosing a base.

Focused tests verify:

- invalid PE images are rejected;
- PE32 headers, sections, imports, exports, forwarded exports, and protection
  flags are parsed;
- the image is mapped at its preferred 32-bit base and its x86 entry point runs;
- a resolver binds imported symbols to supplied guest thunk addresses before
  final section protections are applied;
- `IMAGE_REL_BASED_HIGHLOW` relocations allow DLLs with colliding preferred
  bases to be mapped elsewhere;
- PE TLS-directory metadata is retained for loader initialization;
- stdcall import thunks contain the correct callback and stack-cleanup operands,
  preserve their module/symbol diagnostics, become read/execute-only, and can
  reopen as a batch for dynamically mapped DLL imports before returning to RX;
- an x86 guest can call a registered 64-bit C++ function through `INT 9Ch`;
- a native callback can redirect the x86 CPU to a requested guest EIP, which is
  the control-transfer primitive used to enter guest callback functions.

The PE inspector also parses the primary executable and its optional extension
modules without Wine:

| Module | Preferred base | Image size | Imports |
| --- | ---: | ---: | ---: |
| `FalloutNV.exe` (unpacked 1.4.0.525) | `0x00400000` | `0x0107B000` | 17 modules / 280 symbols |
| `nvse_loader.exe` | `0x00400000` | `0x0002B000` | 11 modules / 87 symbols |
| xNVSE 6.4.8 `nvse_1_4.dll` (current staged build) | `0x10000000` | `0x00752000` | 8 modules / 362 symbols |
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
The D3D device window is retained separately from USER32's active window:
creating or presenting through a `WS_CHILD` window does not steal activation
from its top-level ancestor.

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
2. **NVSE bootstrap:** DLL export parsing, import binding, module lookup,
   preferred-base staging, per-module/per-thread static TLS, CRT startup, TLS
   callbacks, and the real DLL entry point are implemented. The staged xNVSE
   runtime initializes automatically after Fallout's CRT and before WinMain.
   xNVSE can discover, validate, map, initialize, Query, and Load a real plugin;
   `FNV Mod Limit Fix` version 3 is the current verified fixture. Remaining work
   includes broader plugin coverage plus the NVSE messaging and optional
   interface contracts those plugins exercise.
3. **Window and input:** USER32, raw input, DirectInput 8, XInput, cursor and
   message-loop behavior. Fallout's mapped top-level `HWND` now belongs to a
   dedicated native UI thread with an independent Windows message loop, so the
   desktop window remains responsive while the x86 guest translates or blocks.
   `PeekMessageA`, `DispatchMessageA`, and `SendMessageA` deliver lifecycle plus
   native keyboard/mouse/focus events to Fallout's guest WndProc. Startup uses
   ordinary `ShowWindow` behavior rather than forcing foreground ownership.
   Native activation, clicking, and Alt-Tab are authoritative, and guest calls
   to `GetForegroundWindow`, `GetActiveWindow`, `GetFocus`, `SetActiveWindow`,
   `SetFocus`, and `SetForegroundWindow` are reflected through the real window.
   The same host event stream feeds keyboard and mouse DirectInput state plus
   buffered menu events. Raw mouse motion and exclusive foreground capture
   follow the native window lifecycle; focus loss, capture revocation, and
   cancel-mode transitions release ownership so Fallout can reacquire it
   normally. Deterministic native keyboard navigation through the main menu is
   verified. Remaining work includes cursor-coordinate/click validation and
   XInput device state.
4. **Rendering:** D3D9 and the required D3DX9 surface, translated directly to
   Sugarbomb's renderer. The guest COM/resource model, native presentation
   window, x64 D3D9 resource/state/shader/draw translation, D3DX image decoding,
   and surface-copy paths are in place. Remaining work includes less common
   resource methods, volume textures, D3DX shader helpers, reset/lost-device
   edge cases, and frame-by-frame validation beyond the main menu.
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
.\project\msvc\BoxedWine\x64\Test\BoxedWine.exe 0 6 1

.\tools\sugarbomb\build-win64.ps1 -Configuration Release
.\tools\sugarbomb\inspect-pe32.ps1 'D:\path\to\FalloutNV.exe'
.\tools\sugarbomb\inspect-pe32.ps1 'D:\path\to\FalloutNV.exe' -Imports
.\tools\sugarbomb\inspect-pe32.ps1 'D:\path\to\nvse_1_4.dll' -Exports
.\project\msvc\BoxedWine\x64\Release\BoxedWine.exe --sugarbomb-run 'D:\path\to\FalloutNV.exe'
```

Ordinary launches run until the guest exits or the native window is closed.
For deterministic diagnostics, the runtime accepts optional environment
variables that impose explicit execution or wall-clock budgets. They do not
change the guest ABI:

```powershell
$env:SUGARBOMB_MAX_RUN_SLICES = '2600000'
$env:SUGARBOMB_MAX_RUN_MILLISECONDS = '20000'
$env:SUGARBOMB_NO_HOST_WINDOW = '1' # optional for unattended runs
$env:SUGARBOMB_FALLOUT_UNPACKED_IMAGE = 'D:\path\to\verified\FalloutNV.unpacked.exe'
$env:SUGARBOMB_NVSE_PLUGIN_PATHS = 'D:\mods\PluginA.dll;D:\mods\NVSE\Plugins'
$env:SUGARBOMB_DISABLE_NVSE = '1' # optional diagnostic opt-out
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
Fallout's own 32-bit WndProc, and reaches the correctly textured main menu
without exposing native pointers to the guest. xNVSE now initializes through
its real static-TLS and DLL-entry sequence at the same CRT boundary used by the
xNVSE loader, patches the same guest Fallout image, and loads a real NVSE plugin
before the game continues. The next major work is to verify deterministic menu
click interaction and gameplay transition through the native-focus/DirectInput
path, persist remaining virtual-file operations, and expand plugin/API coverage
from additional real NVSE workloads.
