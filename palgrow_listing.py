#!/usr/bin/env python3
"""
palgrow_listing.py - human readable change listing of the palette fix.

  python3 palgrow_listing.py ORIGINAL.dll [records] > mpr555_changes.txt

Runs palgrow.build() on the original DLL and prints every changed location as before/after
disassembly (x86-32, Intel syntax), plus header / section / data changes.
Needs palgrow.py next to it, plus pefile and capstone.
"""
import sys, struct
import pefile, capstone
import palgrow

GAP = 24       # changed spots closer than this many bytes are shown as one block


def main():
    src = open(sys.argv[1], 'rb').read()
    N = int(sys.argv[2]) if len(sys.argv) > 2 else palgrow.N_DEFAULT
    out, st, log = palgrow.build(src, N)
    pe = pefile.PE(data=src)
    base = pe.OPTIONAL_HEADER.ImageBase
    text = pe.sections[0]
    t0, t1 = text.PointerToRawData, text.PointerToRawData + text.Misc_VirtualSize
    t_va = base + text.VirtualAddress

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.skipdata = True
    ins = list(md.disasm(src[t0:t1], t_va))          # same linear sweep palgrow used
    starts = [i.address - t_va for i in ins]
    import bisect

    def ins_start(rel):                               # start of the instruction containing rel
        return starts[bisect.bisect_right(starts, rel) - 1]

    diff = [o for o in range(min(len(src), len(out))) if src[o] != out[o]]
    in_text = [o for o in diff if t0 <= o < t1]
    other = [o for o in diff if not (t0 <= o < t1)]

    P = print
    P('BotF software rasterizer - palette limit fix: change listing')
    P('=' * 64)
    P('input   : %s (%d bytes)' % (__import__('os').path.basename(sys.argv[1]), len(src)))
    P('records : %d (handles 1..%d), original 128 (1..127)' % (N, N - 1))
    P('image   : base 0x%X, .text VA 0x%X' % (base, t_va))
    P('')
    P('Summary of patched pattern kinds')
    P('-' * 64)
    for k, v in st.items():
        P('  %-20s %s' % (k, v))
    P('')
    P('Constants:  record 0x418 bytes (unchanged), old state stride 0x%X, new stride 0x%X' %
      (palgrow.OLD_STRIDE, palgrow.OLD_STRIDE + (N - 128) * palgrow.REC))
    P('            fields behind the table move up by 0x%X (= (%d-128)*0x418)' % ((N - 128) * palgrow.REC, N))
    P('')

    # ---- code changes
    blocks = []
    for o in in_text:
        r = o - t0
        if blocks and r - blocks[-1][1] <= GAP:
            blocks[-1][1] = r
        else:
            blocks.append([r, r])
    labels = {}
    for what, off in log:
        labels.setdefault(off, []).append(what)

    P('Pattern kinds')
    P('  field disp / imm : state-block field behind the palette table, offset + 0x%X' % ((N - 128) * palgrow.REC))
    P('  chain imul/nop   : slot*0x424F0 multiply (shl/lea chain) replaced by one imul with the new stride, rest nop')
    P('  slot stride loop : per-slot step of the init loop, new stride')
    P('  new-scan loop    : free-palette search, now N-1 entries with a "table full" exit (returns 0)')
    P('  free-all bound / key-reset count / evict wrap / table clear : loop limits 128 -> N')
    P('')
    P('Code changes in .text  (%d blocks, %d bytes changed)' % (len(blocks), len(in_text)))
    P('-' * 64)
    for n, (a, b) in enumerate(blocks, 1):
        a0, b0 = a, b
        a = ins_start(a)
        b = ins_start(b)
        b = b + next(i.size for i in ins if i.address - t_va == b)
        import re
        what = sorted({re.sub(r' [0-9a-f]{6,}$', '', w) for off, ws in labels.items() if t0 + a0 - 16 <= off <= t0 + b0 for w in ws})
        if not what:
            what = ['absolute address re-pointed (.reloc entry)']
        P('[%d] VA 0x%X  file 0x%X  (%d bytes)   %s' % (n, t_va + a, t0 + a, b - a, '; '.join(what)))
        for title, data in (('before', src), ('after ', out)):
            P('   ' + title)
            nops = []
            def flush():
                if nops:
                    P('     %08X  %-22s nop x%d' % (nops[0], '90', len(nops)))
                    nops.clear()
            for i in md.disasm(data[t0 + a:t0 + b], t_va + a):
                if i.mnemonic == 'nop' and i.size == 1:
                    nops.append(i.address)
                    continue
                flush()
                P('     %08X  %-22s %s %s' % (i.address, i.bytes.hex(' '), i.mnemonic, i.op_str))
            flush()
        P('')

    # ---- everything else (headers, section table, data, relocated pointers)
    P('Changes outside .text  (%d bytes)' % len(other))
    P('-' * 64)
    sec = lambda o: next((s.Name.rstrip(b'\0').decode() for s in pe.sections
                          if s.PointerToRawData <= o < s.PointerToRawData + s.SizeOfRawData), 'header')
    seen = set()
    for o in other:
        w = o & ~3
        if w in seen:
            continue
        seen.add(w)
        P('  file 0x%06X  [%-6s]  %s -> %s' % (w, sec(w), src[w:w + 4].hex(' '), out[w:w + 4].hex(' ')))
    P('')
    P('New section .pal: zero filled, no file data, holds the 8 device state blocks')
    P('  (section header added after the last one, NumberOfSections +1, SizeOfImage grown, checksum cleared)')


main()
