# Palette limit patch: specification

Applies to the software rasterizer DLLs of Star Trek: Birth of the Federation (1.0.3):
`mpr555.dll`, `mpr555m.dll`, `mpr555p.dll`, `mpr555pm.dll` and the four `mpr565*` equivalents
(555 / 565 are the two pixel formats; the `m` / `p` / `pm` suffixes are build variants). All 8 get the same patch.

The patch is applied to the original binaries by `palgrow.py`. `listings/` has the exact
before/after disassembly of every changed location.

## 1. Problem

The renderer keeps the loaded texture palettes in a fixed table of **128 records** per device
state block. Handle 0 means "no palette", so 127 palettes are usable. Every texture (GIF) in
`stbof.res` has its own 256 colour palette, so a game with more than 127 textures overruns the table.
The original allocator has no "table full" check, so the 128th request writes behind the table.

## 2. Data layout

### Palette record (0x418 bytes, unchanged)

| Offset | Size | Meaning |
|-------:|-----:|---------|
| 0x00 | 4 | data pointer |
| 0x04 | 4 | driver key |
| 0x08 | 4 | state |
| 0x0C | 4 | version |
| 0x10 | 4 | cache version tag |
| 0x14 | 4 | cache node list |
| 0x18 | 0x400 | converted palette cache (256 x 4 bytes), written when a texture is bound and read by the span renderers |

The cache is why the record stride can't be shrunk: records would overlap their neighbours' caches.
(An earlier attempt did exactly that and crashed.)

### Device state block (stride changes)

There are 8 state blocks, one per device slot, in a `.bss` array.

| Offset in block | Original | Patched |
|----------------:|----------|---------|
| 0x34 | palette record table, 128 records | palette record table, **N** records |
| 0x20C34 | first field behind the table (default texture, texture list, flags, callbacks, node pool, ...) | same fields at **+0xE5400** |
| block stride | 0x424F0 | 0x1278F0 |

With the default N = 1024:

- table end moves from `0x34 + 128*0x418 = 0x20C34` to `0x34 + 1024*0x418`
- `DELTA = (N - 128) * 0x418 = 0xE5400`
- `NEW_STRIDE = 0x424F0 + DELTA = 0x1278F0` (must be a multiple of 16)
- the 8 slot array needs `8 * 0x1278F0 = 0x93C780` bytes (about 9.7 MB of address space)

Handles 1..127 map to the same record offsets as before, so existing behaviour is unchanged.
Handles 128..N-1 are new.

## 3. Changes

### 3.1 Fields behind the table

Every memory operand with a displacement in the range `[0x20C34, 0x424F0 + 0x10)` addressed through a
state block pointer gets `+DELTA`. The tool checks that every such instruction has a 32 bit
displacement. In `mpr555.dll`: 48 displacements and 2 `add reg, 0x20CD4` immediates. Any other
immediate in that range makes the tool stop (`unclassified immediate`) rather than guess.

### 3.2 Slot stride

- The init loop's `add reg, 0x424F0` becomes `add reg, NEW_STRIDE`.
- The compiler computed `slot * 0x424F0` with `shl` / `lea` / `sub` chains. Each chain is replaced
  by one `imul reg, reg, NEW_STRIDE` (6 bytes) and the remaining instructions become `nop`.
  Variants: a chain with a final `shl 4`, one without, the interleaved double chain in the
  context-create routine (two slot multiples at once), and the same in the `p` builds.
- All chain patterns are matched exactly. If a pattern is not found the expected number of
  times, the tool aborts.

### 3.3 Absolute references into the array

The array base (`0x100841E0` in `mpr555.dll`) is found from the slot init loop. Every `.reloc`
entry of type HIGHLOW that points into the old array is re-pointed to the new section, with `+DELTA`
for fields behind the table. 22 references in `mpr555.dll`. A reference that points into the
16 bytes just before the old table end would be ambiguous, and the tool refuses it. Because
this goes through `.reloc`, the patched DLL works at any load address (tested rebased).

### 3.4 Table length constants

| Where | Original | Patched |
|-------|----------|---------|
| new-palette search loop | `mov esi,1; ... cmp esi,0x80; jb` (30 bytes, no exit when full) | counts down from N-1, leaves through the allocator's existing failure path, so request N returns handle 0 |
| free-all loop bound | `cmp esi, 0x20C00` | `cmp esi, N*0x418` |
| key-reset loop count | `mov ecx, 0x7F` | `mov ecx, N-1` |
| evict wrap | `cmp ebp, 0x80` | `cmp ebp, N` |
| table clear (`rep stosd`) | `mov ecx, 0x8300` dwords | `N*0x418/4` dwords |

New-palette search, after patching:

```
xor esi, esi ; inc esi          ; handle = 1
lea eax, [ebx + 0x44C]          ; record 1
mov ecx, N-1
L: cmp dword ptr [eax], 0
   je  found
   inc esi
   add eax, 0x418
   dec ecx
   jnz L
   jmp fail                      ; returns 0 = "no palette"
```

### 3.5 New section

A section `.pal` is added after the last section: virtual size `8 * NEW_STRIDE`, raw size 0 (no
file size cost), flags `0xC0000080` (uninitialised data, readable, writable). The
section count, `SizeOfImage` are updated and the PE checksum is set to 0. The header slot after the
section table must be empty, otherwise the tool aborts.

## 4. Limits

| Item | Value |
|------|-------|
| Usable palettes | 1023 (handles 1..1023) |
| Behaviour above that | allocation returns 0 instead of overwriting memory |
| Extra memory | about 9.7 MB (zero filled `.pal`, mapped on load) |
| Different N | `python3 palgrow.py in.dll out.dll N`; the stride must stay a multiple of 16 |

Ultimate Editor mirrors this with `PaletteList.MAX_PALETTES = 1023`. Without the patched DLLs the
original limit of 127 still applies in game.

## 5. Safety checks in the tool

The tool aborts instead of writing a partial patch when:

- the old bytes at a patch site differ from what was expected (`Patch.set` asserts them)
- the array base, the allocator failure exit or the context-create chain is not found exactly once
- the number of simple chains is not 3 or 4
- an unclassified immediate in the field range is found
- there's no room for another section header

## 6. Verification

- `rig.py` runs the original and the patched DLL in an emulator (Unicorn) and compares them, including the
  limit case: request N must return 0. See the script for exactly what it exercises.
- Rebased test at load address `0x05140000`, as seen in a user crash dump.
- Rebuilding `mpr555.dll` from the original gives a byte identical file to the one shipped in the patcher.
- In game: 77 models / 132 ship records and a palette list with about 1024 textures ran correctly.
- `palette_stress.lst` (299 palettes) from the earlier release as an in-game test.

## 7. Related: the trek.exe ship model patch

`ShipModelPatcher` also moves the ship model table of `trek.exe` (73 entries + TMP, 48 bytes each,
VA `0x5919FC`) into a new section `.mdl` with 512 entries + TMP and a 21 byte code cave:

- three code sites are checked against the original bytes first: VA `0x4A28AE` (`mov ecx, table`),
  `0x4A2880` (`mov eax, TMP`) and `0x4A28C6` (the loop `inc ebx; add ecx,30h; cmp ebx,49h; jb`)
- the table and TMP addresses are rewritten, the loop jumps to the cave which compares against the new count
  and jumps back or out
- unused slots are filled with name `FF FF FF FF`, so they never match

Apply it after any other exe edits. UE reads the table from the `.mdl` section afterwards, not from
the old file offset.
