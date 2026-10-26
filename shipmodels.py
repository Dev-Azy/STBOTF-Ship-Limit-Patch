#!/usr/bin/env python3
"""
shipmodels.py - move trek.exe's ship-model table (74 x 48 bytes, VA 0x5919FC) into its own PE section and
raise its capacity (default 512 entries).

What the game does (ui\\tactical\\sfx.cpp, VA 0x4A2110):  it takes the ship model's file name, builds a
3-character key (first 3 chars upper-cased, '_' -> NUL; so "H1_" style names collapse to e.g. "H1"), calls the
lookup routine at 0x4A2890 which scans the table for an entry whose 4-byte name matches the key and returns
the 48-byte entry, which is copied to [ship_ctx+0x140]  (scale, phaser hard-points, ...).  When nothing
matches, the TMP entry (getter 0x4A2880) is used.

Original limits: 73 searchable entries (the loop bound is the imm8 0x49) + TMP, and the table is followed
directly by other variables, so it could not grow in place.

Patch
  * new section .mdl (R/W/X):  [capacity x 48 byte entries][TMP entry][code cave]
      - entries 0..72 are copies of the original ones; unused slots have name FF FF FF FF (never matches)
  * 0x4A28AE  mov ecx,0x5919FC          -> new table base      (existing relocation entry stays valid)
  * 0x4A2881  mov eax,0x5927AC (TMP)    -> new TMP address     (existing relocation entry stays valid)
  * 0x4A28C6  inc ebx/add ecx,0x30/cmp ebx,0x49/jb  -> jmp to a cave that does the same with cmp ebx,capacity
Everything else in the exe is untouched.  The old table memory stays in place but is no longer used.

usage:  shipmodels.py patch  trek.exe  out.exe [capacity]
        shipmodels.py add    patched.exe out.exe NAME CLONE_NAME [scale]   # new entry = copy of CLONE_NAME (+ new scale)
        shipmodels.py list   trek.exe                      # dump the (patched or original) table
"""
import sys, struct
import pefile

ORIG_SIZE = 1781248
ENTRY = 0x30
OLD_TABLE, OLD_TMP, OLD_COUNT = 0x5919FC, 0x5927AC, 73
SITE_BASE, SITE_TMP, SITE_LOOP, LOOP_BACK, LOOP_EXIT = 0x4A28AE, 0x4A2881, 0x4A28C6, 0x4A28B9, 0x4A28CF


def align(v, a):
    return (v + a - 1) // a * a


def v2o(pe, va):
    r = va - pe.OPTIONAL_HEADER.ImageBase
    for s in pe.sections:
        if s.VirtualAddress <= r < s.VirtualAddress + s.SizeOfRawData:
            return s.PointerToRawData + r - s.VirtualAddress
    raise ValueError(hex(va))


def patch(data, capacity=512):
    assert len(data) == ORIG_SIZE, 'not the expected trek.exe (v1.0.3, %d bytes)' % ORIG_SIZE
    pe = pefile.PE(data=data)
    base = pe.OPTIONAL_HEADER.ImageBase
    d = bytearray(data)
    o = v2o(pe, OLD_TABLE)
    assert d[o:o + 4] == b'CH1\0' and d[v2o(pe, OLD_TMP):v2o(pe, OLD_TMP) + 4] == b'TMP\0', 'table not where expected'
    # code sites must match exactly
    exp = {SITE_BASE: bytes.fromhex('b9fc195900'), SITE_TMP - 1: bytes.fromhex('b8ac275900'),
           SITE_LOOP: bytes.fromhex('4383c1308 3fb4972ea'.replace(' ', ''))}
    for va, b in exp.items():
        assert bytes(d[v2o(pe, va):v2o(pe, va) + len(b)]) == b, 'unexpected code at %x' % va
    assert capacity >= 74
    nsec = pe.FILE_HEADER.NumberOfSections
    sec_tab = pe.DOS_HEADER.e_lfanew + 24 + pe.FILE_HEADER.SizeOfOptionalHeader
    assert bytes(d[sec_tab + nsec * 40: sec_tab + nsec * 40 + 40]) == b'\0' * 40
    last = pe.sections[-1]
    sa, fa = pe.OPTIONAL_HEADER.SectionAlignment, pe.OPTIONAL_HEADER.FileAlignment
    new_rva = align(last.VirtualAddress + max(last.Misc_VirtualSize, last.SizeOfRawData), sa)
    new_off = align(len(d), fa)
    new_va = base + new_rva

    tab_va = new_va
    tmp_va = tab_va + capacity * ENTRY
    cave_va = tmp_va + ENTRY
    cave_va = (cave_va + 15) & ~15
    sec = bytearray()
    for i in range(capacity):
        if i < OLD_COUNT:
            sec += d[o + i * ENTRY:o + (i + 1) * ENTRY]
        else:
            sec += b'\xff\xff\xff\xff' + b'\0' * (ENTRY - 4)
    sec += d[v2o(pe, OLD_TMP):v2o(pe, OLD_TMP) + ENTRY]
    sec += b'\0' * (cave_va - (tab_va + len(sec)))
    cave_off = len(sec)
    # cave:  inc ebx ; add ecx,0x30 ; cmp ebx,capacity ; jb LOOP_BACK ; jmp LOOP_EXIT
    c = bytearray(b'\x43\x83\xc1\x30\x81\xfb' + struct.pack('<I', capacity))
    here = cave_va + len(c)
    c += b'\x0f\x82' + struct.pack('<i', LOOP_BACK - (here + 6))
    here = cave_va + len(c)
    c += b'\xe9' + struct.pack('<i', LOOP_EXIT - (here + 5))
    sec += c
    vsize = len(sec)
    raw = align(vsize, fa)
    sec += b'\0' * (raw - vsize)

    # --- patch code
    p = v2o(pe, SITE_BASE); d[p + 1:p + 5] = struct.pack('<I', tab_va)
    p = v2o(pe, SITE_TMP);  d[p:p + 4] = struct.pack('<I', tmp_va)
    p = v2o(pe, SITE_LOOP)
    d[p:p + 9] = b'\xe9' + struct.pack('<i', cave_va - (SITE_LOOP + 5)) + b'\x90' * 4
    # --- section header + PE fields
    hdr = struct.pack('<8sIIIIIIHHI', b'.mdl\0\0\0\0', vsize, new_rva, raw, new_off, 0, 0, 0, 0, 0xE0000060)
    d[sec_tab + nsec * 40: sec_tab + nsec * 40 + 40] = hdr
    struct.pack_into('<H', d, pe.DOS_HEADER.e_lfanew + 6, nsec + 1)
    oh = pe.DOS_HEADER.e_lfanew + 24
    struct.pack_into('<I', d, oh + 56, align(new_rva + vsize, sa))            # SizeOfImage
    isz = struct.unpack_from('<I', d, oh + 8)[0]
    struct.pack_into('<I', d, oh + 8, isz + raw)                              # SizeOfInitializedData
    d += b'\0' * (new_off - len(d))
    d += sec
    return bytes(d), dict(table=hex(tab_va), tmp=hex(tmp_va), cave=hex(cave_va), capacity=capacity,
                          section=(hex(new_rva), hex(vsize)))


def listing(data):
    pe = pefile.PE(data=data)
    base = pe.OPTIONAL_HEADER.ImageBase
    names = [s.Name.rstrip(b'\0') for s in pe.sections]
    if b'.mdl' in names:
        s = pe.sections[names.index(b'.mdl')]
        tab = s.PointerToRawData
        n = 0
        while True:
            e = data[tab + n * ENTRY: tab + (n + 1) * ENTRY]
            if e[:4] == b'\xff\xff\xff\xff' or n * ENTRY >= s.Misc_VirtualSize:
                break
            n += 1
        print('patched exe: %d used entries' % n)
    else:
        tab, n = v2o(pe, OLD_TABLE), OLD_COUNT
    for i in range(n):
        e = data[tab + i * ENTRY: tab + (i + 1) * ENTRY]
        print('%3d %-4s scale=%.3f %s' % (i, e[:4].rstrip(b'\0').decode('latin1'), struct.unpack_from('<f', e, 0x1c)[0], e[4:].hex(' ')))


def add_entry(data, name, clone, scale=None):
    pe = pefile.PE(data=data)
    names = [s.Name.rstrip(b'\0') for s in pe.sections]
    assert b'.mdl' in names, 'run "patch" first'
    s = pe.sections[names.index(b'.mdl')]
    tab = s.PointerToRawData
    cap = (s.Misc_VirtualSize - ENTRY - 0x40) // ENTRY
    ents = [bytes(data[tab + i * ENTRY: tab + (i + 1) * ENTRY]) for i in range(cap + 1)]
    key = lambda b: b[:4].split(b'\0')[0]
    nm, cl = name.encode().upper(), clone.encode().upper()
    assert 1 <= len(nm) <= 3, 'name must be 1-3 characters (the game keys on the first 3)'
    src = [e for e in ents if key(e) == cl]
    assert src, 'clone entry %s not found' % clone
    assert not [e for e in ents if key(e) == nm], 'name already exists'
    free = next(i for i, e in enumerate(ents) if e[:4] == b'\xff\xff\xff\xff')
    e = bytearray(src[0]); e[:4] = nm + b'\0' * (4 - len(nm))
    if scale is not None:
        struct.pack_into('<f', e, 0x1c, scale)
    d = bytearray(data); d[tab + free * ENTRY: tab + (free + 1) * ENTRY] = e
    return bytes(d), free


if __name__ == '__main__':
    if len(sys.argv) >= 3 and sys.argv[1] == 'list':
        listing(open(sys.argv[2], 'rb').read())
    elif len(sys.argv) >= 4 and sys.argv[1] == 'patch':
        cap = int(sys.argv[4]) if len(sys.argv) > 4 else 512
        out, info = patch(open(sys.argv[2], 'rb').read(), cap)
        open(sys.argv[3], 'wb').write(out)
        print('wrote', sys.argv[3], info)
    elif len(sys.argv) >= 6 and sys.argv[1] == 'add':
        out, slot = add_entry(open(sys.argv[2], 'rb').read(), sys.argv[4], sys.argv[5],
                              float(sys.argv[6]) if len(sys.argv) > 6 else None)
        open(sys.argv[3], 'wb').write(out)
        print('added %s as slot %d -> %s' % (sys.argv[4].upper(), slot, sys.argv[3]))
    else:
        print(__doc__)
