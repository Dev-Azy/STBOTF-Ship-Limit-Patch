#!/usr/bin/env python3
"""
palgrow.py - lift the 127-palette limit of the BotF software rasterizers
(mpr555*.dll / mpr565*.dll) WITHOUT touching the palette record layout.

Why the first attempt crashed
-----------------------------
A palette record is 0x418 bytes:  +0 data ptr, +4 driver key, +8 state, +0xC version,
+0x10 cache version tag, +0x14 cache node list, +0x18 .. +0x417 = a LIVE 256-entry
(0x400 byte) colour-converted palette cache, written by the texture bind routines
(0x10014C60 copies into rec+0x18, 0x10015260/0x154A0 return rec+0x18 / node+0x18 to the
span renderers).  Shrinking the stride to 0x20 made neighbouring records overlap this cache.

What this tool does instead
---------------------------
The per-device "state block" (stride 0x424F0, 8 of them, in .bss) holds
    +0x34 .. +0x20C33   128 palette records
    +0x20C34 ..         default texture / texture list / flags / callbacks / node pool ...
The tool keeps the record format 100% unchanged and simply makes the table longer:
  * record cap 128 -> N (default 1024)
  * every state field behind the table moves up by DELTA = (N-128)*0x418
  * the state stride grows by DELTA, the 8-slot array moves to a new zero-filled
    .bss-like section (.pal) appended to the PE (no file-size cost)
  * every absolute reference into the array is re-pointed (found through .reloc,
    so the list is complete), every 'index*0x424F0' multiply is rewritten.
Handles 1..127 behave exactly as before, 128..N-1 are new.
"""
import sys, re, struct
import pefile, capstone
from capstone.x86 import *

N_DEFAULT = 1024
OLD_STRIDE = 0x424F0
OLD_N = 128
REC = 0x418
TABLE_OFF = 0x34
TAIL_OFF = TABLE_OFF + OLD_N * REC            # 0x20C34 first field behind the table
OLD_ARRAY_RVA = 0x841E0
NSLOTS = 8

REGNUM = {X86_REG_EAX: 0, X86_REG_ECX: 1, X86_REG_EDX: 2, X86_REG_EBX: 3,
          X86_REG_ESP: 4, X86_REG_EBP: 5, X86_REG_ESI: 6, X86_REG_EDI: 7}


class Patch:
    def __init__(self, data):
        self.data = bytearray(data)
        self.log = []

    def set(self, off, old, new, what):
        assert len(old) == len(new), what
        assert bytes(self.data[off:off + len(old)]) == old, (what, hex(off))
        self.data[off:off + len(new)] = new
        self.log.append((what, off))


def build(src_bytes, N=N_DEFAULT, verbose=False):
    DELTA = (N - OLD_N) * REC
    NEW_STRIDE = OLD_STRIDE + DELTA
    assert NEW_STRIDE % 16 == 0
    P = Patch(src_bytes)
    pe = pefile.PE(data=src_bytes)
    base = pe.OPTIONAL_HEADER.ImageBase
    text = pe.sections[0]
    assert text.Name.startswith(b'.text')
    t_off, t_va, t_sz = text.PointerToRawData, base + text.VirtualAddress, text.Misc_VirtualSize
    OLD = None

    def va2off(va):
        return pe.get_offset_from_rva(va - base)

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.skipdata = True
    md.detail = True
    ins = [i for i in md.disasm(bytes(src_bytes[t_off:t_off + t_sz]), t_va)]
    stats = {}

    def cnt(k):
        stats[k] = stats.get(k, 0) + 1

    # array base: the slot-init loop is  mov reg, ARRAY+4 ; mov ecx, 8 ; ... add reg, 0x424F0
    for q, i in enumerate(ins):
        if i.mnemonic == 'add' and len(i.operands) == 2 and i.operands[1].type == X86_OP_IMM and i.operands[1].imm == OLD_STRIDE \
                and i.operands[0].type == X86_OP_REG:
            r = i.operands[0].reg
            for p in range(q - 1, max(q - 20, 0), -1):
                j = ins[p]
                if j.mnemonic == 'mov' and j.operands[0].type == X86_OP_REG and j.operands[0].reg == r and j.operands[1].type == X86_OP_IMM:
                    OLD = j.operands[1].imm - 4
                    break
            break
    assert OLD is not None, 'array base not found'
    stats['array_base'] = hex(OLD)
    for i in ins:
        if i.mnemonic.startswith('.'):
            continue
        for op in i.operands:
            if op.type == X86_OP_MEM and op.mem.base != 0 and TAIL_OFF <= op.mem.disp < OLD_STRIDE + 0x10:
                assert i.disp_size == 4, hex(i.address)
                o = va2off(i.address) + i.disp_offset
                old = bytes(P.data[o:o + 4])
                P.set(o, old, struct.pack('<I', op.mem.disp + DELTA), 'field disp %x' % i.address)
                cnt('field_disp')
            elif op.type == X86_OP_IMM and i.mnemonic == 'add' and op.imm == 0x20CD4:
                o = va2off(i.address) + i.imm_offset
                P.set(o, struct.pack('<I', 0x20CD4), struct.pack('<I', 0x20CD4 + DELTA), 'field imm %x' % i.address)
                cnt('field_imm')
            elif op.type == X86_OP_IMM and i.mnemonic == 'add' and op.imm == OLD_STRIDE:
                o = va2off(i.address) + i.imm_offset
                P.set(o, struct.pack('<I', OLD_STRIDE), struct.pack('<I', NEW_STRIDE), 'slot stride loop %x' % i.address)
                cnt('stride_loop')
            elif (op.type == X86_OP_IMM and TAIL_OFF - 0x40 <= op.imm < OLD_STRIDE + 0x10
                  and i.mnemonic in ('add', 'sub', 'mov', 'lea', 'cmp') and op.imm not in (0x20C00,)):
                raise SystemExit('unclassified immediate %s %s at %x' % (i.mnemonic, i.op_str, i.address))

    # ---------------------------------------------------------------- 2. array chains  i*0x424F0
    def regs(o):
        return REGNUM[o.reg] if o.type == X86_OP_REG else None

    from capstone import CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET
    n = len(ins)

    def accessed(i):
        r, w = i.regs_access()
        return set(r), set(w)

    def is_ctl(i):
        return any(g in (CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET) for g in i.groups)

    def find_next(j, pred, limit=14):
        """first index >= j matching pred, skipping only straight-line instructions"""
        for q in range(j, min(j + limit, n)):
            if ins[q].mnemonic.startswith('.') or is_ctl(ins[q]):
                return None
            if pred(ins[q]):
                return q
        return None

    def is_shl(i, r, imm):
        return (i.mnemonic == 'shl' and len(i.operands) == 2 and i.operands[0].type == X86_OP_REG
                and (r is None or i.operands[0].reg == r) and i.operands[1].type == X86_OP_IMM and i.operands[1].imm == imm)

    k = 0
    while k < n - 6:
        e0 = ins[k]
        if not is_shl(e0, None, 5):
            k += 1
            continue
        R1 = e0.operands[0].reg
        q1 = find_next(k + 1, lambda i: i.mnemonic == 'add' and i.operands[0].type == X86_OP_REG and i.operands[0].reg == R1
                       and i.operands[1].type == X86_OP_REG and i.operands[1].reg != R1, 8)
        if q1 is None:
            k += 1; continue
        R0 = ins[q1].operands[1].reg
        def lea_ok(i, idx, scale, base):
            if i.mnemonic != 'lea' or i.operands[0].type != X86_OP_REG: return False
            m = i.operands[1].mem
            return m.base == base and m.index == idx and m.scale == scale and m.disp == 0
        q2 = find_next(q1 + 1, lambda i: lea_ok(i, R1, 8, R0), 8)
        if q2 is None: k += 1; continue
        R2 = ins[q2].operands[0].reg
        q3 = find_next(q2 + 1, lambda i: lea_ok(i, R2, 4, R0), 8)
        if q3 is None: k += 1; continue
        R3 = ins[q3].operands[0].reg
        q4 = find_next(q3 + 1, lambda i: is_shl(i, R3, 4), 8)
        if q4 is None: k += 1; continue
        q5 = find_next(q4 + 1, lambda i: i.mnemonic == 'sub' and i.operands[0].type == X86_OP_REG and i.operands[0].reg == R3
                       and i.operands[1].type == X86_OP_REG and i.operands[1].reg == R0, 8)
        if q5 is None: k += 1; continue
        chain = [k, q1, q2, q3, q4, q5]
        q6 = find_next(q5 + 1, lambda i: is_shl(i, R3, 4), 3)
        final_shl = q6 is not None and all(
            not (accessed(ins[x])[0] | accessed(ins[x])[1]) & {R3} for x in range(q5 + 1, q6))
        if final_shl:
            chain.append(q6)
        # skipped instructions must not touch the chain registers (R0 may be read)
        for x in range(k, chain[-1] + 1):
            if x in chain: continue
            r, w = accessed(ins[x])
            if (r | w) & {R1, R2, R3} or w & {R0}:
                break
        else:
            mult = NEW_STRIDE if final_shl else NEW_STRIDE // 16
            code = b'\x69' + bytes([0xC0 | (REGNUM[R3] << 3) | REGNUM[R0]]) + struct.pack('<I', mult)
            # all chain elements become nops; the 6-byte imul goes into the longest run of
            # adjacent chain-element bytes (skipped instructions in between are left untouched)
            for x in chain:
                o = va2off(ins[x].address)
                P.set(o, bytes(P.data[o:o + ins[x].size]), b'\x90' * ins[x].size, 'chain nop %x' % ins[x].address)
            runs, cur = [], [ins[chain[0]].address, ins[chain[0]].address + ins[chain[0]].size]
            for x in chain[1:]:
                if ins[x].address == cur[1]:
                    cur[1] = ins[x].address + ins[x].size
                else:
                    runs.append(cur); cur = [ins[x].address, ins[x].address + ins[x].size]
            runs.append(cur)
            run = max(runs, key=lambda r: r[1] - r[0])
            assert run[1] - run[0] >= 6, 'no room for imul at %x' % ins[k].address
            o = va2off(run[0])
            P.set(o, bytes(P.data[o:o + 6]), code, 'chain imul %x' % ins[k].address)
            cnt('chain_final_shl' if final_shl else 'chain_noshl')
            k = chain[-1] + 1
            continue
        k += 1

    # interleaved double chain (context create): locate through its two relocated slot refs
    # original block:  mov eax,ebx; mov edx,ebx; shl eax,5; add eax,ebx; push 0x148; shl edx,5; lea ecx,[ebx+eax*8]; add edx,ebx
    #                  lea eax,[ebx+ecx*4]; lea ecx,[ebx+edx*8]; shl eax,4; sub eax,ebx; lea edx,[ebx+ecx*4]; shl eax,4; shl edx,4
    # -> eax = i*S ; edx = i*S/16 + i   (the following 'sub edx,ebx' then yields i*S/16)
    pat = re.compile(
        rb'\x8b\xc3\x8b\xd3\xc1\xe0\x05\x03\xc3\x68\x48\x01\x00\x00\xc1\xe2\x05\x8d\x0c\xc3\x03\xd3'
        rb'\x8d\x04\x8b\x8d\x0c\xd3\xc1\xe0\x04\x2b\xc3\x8d\x14\x8b\xc1\xe0\x04\xc1\xe2\x04', re.S)
    # (register encodings are verified by an exact-match; if a variant differs the tool refuses)
    found = list(pat.finditer(src_bytes, t_off, t_off + t_sz))
    for m in found:
        old = m.group(0)
        new = b'\x68\x48\x01\x00\x00' + b'\x69\xc3' + struct.pack('<I', NEW_STRIDE) + \
              b'\x69\xd3' + struct.pack('<I', NEW_STRIDE // 16 + 1)
        new += b'\x90' * (len(old) - len(new))
        P.set(m.start(), old, new, 'interleaved chain')
        cnt('chain_interleaved')
    # 'p' builds schedule the same two chains differently: eax = i*S, edx = 1061*i followed (after the
    # relocated 'mov ecx,[eax+...]') by  shl edx,4 ; sub edx,ebx   ->  edx = ((S/16+1)/16)*i first
    pat_p = re.compile(
        rb'\x8b\xc3\xc1\xe0\x05\x03\xc3\x8d\x0c\xc3\x8b\xd3\xc1\xe2\x05\x03\xd3\x8d\x04\x8b\x8d\x0c\xd3'
        rb'\xc1\xe0\x04\x2b\xc3\xc1\xe0\x04\x8d\x14\x8b(?=\x8b\x88.{4}\xc1\xe2\x04\x2b\xd3)', re.S)
    assert (NEW_STRIDE // 16 + 1) % 16 == 0
    for m in pat_p.finditer(src_bytes, t_off, t_off + t_sz):
        old = m.group(0)
        new = b'\x69\xc3' + struct.pack('<I', NEW_STRIDE) + b'\x69\xd3' + struct.pack('<I', (NEW_STRIDE // 16 + 1) // 16)
        new += b'\x90' * (len(old) - len(new))
        P.set(m.start(), old, new, 'interleaved chain (p)')
        cnt('chain_interleaved_p')
    if stats.get('chain_interleaved', 0) + stats.get('chain_interleaved_p', 0) != 1:
        raise SystemExit('context-create chain not found exactly once')
    if stats.get('chain_final_shl', 0) + stats.get('chain_noshl', 0) not in (3, 4):
        raise SystemExit('unexpected number of simple chains')

    # ---------------------------------------------------------------- 3. table length constants
    def sub_const(name, rx, fix, count):
        rxc = re.compile(rx, re.S)
        ms = list(rxc.finditer(src_bytes, t_off, t_off + t_sz))
        if count is not None and len(ms) != count:
            raise SystemExit('%s matched %d times (expected %d)' % (name, len(ms), count))
        for m in ms:
            old = m.group(0)
            new = fix(bytearray(old))
            P.set(m.start(), old, bytes(new), name)
            cnt(name)
        return len(ms)

    # New-palette scan.  Original (30 bytes):
    #   mov esi,1 ; lea eax,[ebx+0x44c] ; L: cmp [eax],0 ; je found ; inc esi ; add eax,0x418 ; cmp esi,0x80 ; jb L ; found:
    # Original has NO "table full" exit (the 128th request writes behind the table).  Rewritten in place with a
    # down-counter and an exit to the allocator's existing failure path (returns handle 0 = "no palette"):
    #   xor esi,esi ; inc esi ; lea eax,[ebx+0x44c] ; mov ecx,N-1 ; L: cmp [eax],0 ; je found ;
    #   inc esi ; add eax,0x418 ; dec ecx ; jnz L ; jmp fail ; found:
    scan_rx = re.compile(rb'\xbe\x01\x00\x00\x00\x8d\x83\x4c\x04\x00\x00\x83\x38\x00\x74\x0e\x46\x05\x18\x04\x00\x00\x81\xfe\x80\x00\x00\x00\x72\xed', re.S)
    ms = list(scan_rx.finditer(src_bytes, t_off, t_off + t_sz))
    if len(ms) != 1:
        raise SystemExit('new-scan loop matched %d times' % len(ms))
    m = ms[0]
    fail_rx = re.compile(rb'\x33\xf6\x5f\x8b\xc6', re.S)          # xor esi,esi ; pop edi ; mov eax,esi   (malloc-failed exit)
    fm = fail_rx.search(src_bytes, m.end(), m.end() + 0x60)
    assert fm, 'allocator failure exit not found'
    jmp_pos = m.start() + 28
    rel = fm.start() - (jmp_pos + 2)
    assert -128 <= rel < 128
    new = (b'\x33\xf6\x46' + b'\x8d\x83\x4c\x04\x00\x00' + b'\xb9' + struct.pack('<I', N - 1) +
           b'\x83\x38\x00' + b'\x74\x0b' + b'\x46' + b'\x05\x18\x04\x00\x00' + b'\x49' + b'\x75\xf2' +
           b'\xeb' + struct.pack('<b', rel))
    assert len(new) == 30
    P.set(m.start(), m.group(0), new, 'new-scan loop (with full check)')
    cnt('new-scan cap')

    def f_free(b):
        i = b.index(b'\x81\xfe\x00\x0c\x02\x00'); b[i + 2:i + 6] = struct.pack('<I', N * REC); return b
    sub_const('free-all bound',
              rb'\xbe\x18\x04\x00\x00.{3}\x8b\x44.\x3c\x85\xc0\x74.\x8b.\x8b.\xe8.{4}\x81\xc6\x18\x04\x00\x00\x43\x81\xfe\x00\x0c\x02\x00\x72.',
              f_free, 1)

    def f_key(b):
        i = b.index(b'\xb9\x7f\x00\x00\x00'); b[i + 1:i + 5] = struct.pack('<I', N - 1); return b
    c = sub_const('key-reset count',
                  rb'\xb9\x7f\x00\x00\x00\x05\x50\x04\x00\x00\xc7\x00\xff\xff\xff\x7f\x05\x18\x04\x00\x00\x49\x75.', f_key, None)
    c += sub_const('key-reset count (p)',
                   rb'\x05\x50\x04\x00\x00\xb9\x7f\x00\x00\x00\xc7\x00\xff\xff\xff\x7f\x05\x18\x04\x00\x00\x49\x75.', f_key, None)
    if c != 1:
        raise SystemExit('key reset loop count %d != 1' % c)

    def f_wrap(b):
        b[3:7] = struct.pack('<I', N); return b
    sub_const('evict wrap', rb'\x45\x81\xfd\x80\x00\x00\x00\x72\x05\xbd\x01\x00\x00\x00', f_wrap, 1)

    def f_clr(b):
        b[1:5] = struct.pack('<I', N * REC // 4); return b
    c = sub_const('table clear', rb'\xb9\x00\x83\x00\x00\x33\xc0\x8d\x7e\x34\xf3\xab', f_clr, None)
    c += sub_const('table clear (p)', rb'\x33\xc0\xb9\x00\x83\x00\x00\x8d\x7e\x34(?:\x6a\x20)?\xf3\xab', lambda b: f_clr(b[2:]) and b, None) if False else 0
    if c == 0:
        def f_clr2(b):
            b[3:7] = struct.pack('<I', N * REC // 4); return b
        c += sub_const('table clear (p)', rb'\x33\xc0\xb9\x00\x83\x00\x00\x8d\x7e\x34\x6a\x20\xf3\xab', f_clr2, None)
    if c != 1:
        raise SystemExit('table clear sites %d != 1' % c)

    # ---------------------------------------------------------------- 4. new section for the slot array
    opt = pe.OPTIONAL_HEADER
    sa = opt.SectionAlignment
    last = pe.sections[-1]
    new_rva = (last.VirtualAddress + max(last.Misc_VirtualSize, last.SizeOfRawData) + sa - 1) & ~(sa - 1)
    new_size = NSLOTS * NEW_STRIDE
    new_va = base + new_rva
    nsec = pe.FILE_HEADER.NumberOfSections
    sec_table = pe.DOS_HEADER.e_lfanew + 24 + pe.FILE_HEADER.SizeOfOptionalHeader
    hdr_end = sec_table + (nsec + 1) * 40
    first_raw = min(s.PointerToRawData for s in pe.sections if s.PointerToRawData)
    assert hdr_end <= first_raw, 'no room for a section header'
    assert bytes(P.data[sec_table + nsec * 40: sec_table + (nsec + 1) * 40]) == b'\0' * 40, 'header slot not empty'
    hdr = struct.pack('<8sIIIIIIHHI', b'.pal\0\0\0\0', new_size, new_rva, 0, 0, 0, 0, 0, 0, 0xC0000080)
    P.data[sec_table + nsec * 40: sec_table + (nsec + 1) * 40] = hdr
    struct.pack_into('<H', P.data, pe.DOS_HEADER.e_lfanew + 6, nsec + 1)
    size_of_image = (new_rva + new_size + sa - 1) & ~(sa - 1)
    struct.pack_into('<I', P.data, pe.DOS_HEADER.e_lfanew + 24 + 56, size_of_image)
    # checksum -> 0
    struct.pack_into('<I', P.data, pe.DOS_HEADER.e_lfanew + 24 + 64, 0)

    # ---------------------------------------------------------------- 5. re-point every absolute reference into the array
    moved = 0
    for blk in pe.DIRECTORY_ENTRY_BASERELOC:
        for e in blk.entries:
            if e.type != 3:
                continue
            o = pe.get_offset_from_rva(e.rva)
            v = struct.unpack_from('<I', src_bytes, o)[0]
            if OLD <= v < OLD + NSLOTS * OLD_STRIDE:
                slot, off = divmod(v - OLD, OLD_STRIDE)
                nv = new_va + slot * NEW_STRIDE + off + (DELTA if off >= TAIL_OFF - 0x10 else 0)
                # a reference at off in [TAIL_OFF-0x10, TAIL_OFF) would be ambiguous: refuse
                assert not (TAIL_OFF - 0x10 <= off < TAIL_OFF), hex(v)
                struct.pack_into('<I', P.data, o, nv)
                moved += 1
    stats['abs_refs_moved'] = moved
    stats['new_section'] = (hex(new_rva), hex(new_size))
    return bytes(P.data), stats, P.log


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(__doc__); sys.exit(1)
    N = int(sys.argv[3]) if len(sys.argv) > 3 else N_DEFAULT
    out, st, _log = build(open(sys.argv[1], 'rb').read(), N)
    _pe = pefile.PE(data=out)
    _pe.OPTIONAL_HEADER.CHECKSUM = 0
    out = _pe.write()
    open(sys.argv[2], 'wb').write(out)
    print(sys.argv[1], '->', sys.argv[2], st)
