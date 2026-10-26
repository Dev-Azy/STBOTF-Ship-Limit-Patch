import struct, re, random, hashlib, sys
import pefile
from unicorn import *
from unicorn.x86_const import *

HEAP = 0x70000000
STUB = 0x50000000
STACK = 0x30100000
RET = 0x40000000
CTXB = 0x20000000

import os
REF = os.environ.get('MPR555_ORIG', 'mpr555.dll')   # original mpr555.dll, used only to locate function entry points
FN555 = {'new': 0x100185e0, 'free': 0x100186f0, 'freeall': 0x10018770, 'attach': 0x10018b90, 'load': 0x10018c10,
         'stinit': 0x10018c60, 'pool': 0x10015160, 'texc': 0x10018540, 'bind': 0x10015260}
_ref = open(REF, 'rb').read()


def locate(raw, pe):
    """function entry RVAs by signature (taken from mpr555 original)"""
    t = pe.sections[0]
    code = raw[t.PointerToRawData:t.PointerToRawData + t.Misc_VirtualSize]
    out = {}
    for k, a in FN555.items():
        o = 0x400 + (a - 0x10001000)
        sig = _ref[o:o + 10]
        ms = [m.start() for m in re.finditer(re.escape(sig), code)]
        out[k] = (t.VirtualAddress + ms[0]) if len(ms) == 1 else None
    extra = {'attach': rb'\x8b\x44\x24\x04\x8b\x49\x60\x56\x8b\xf0\xc1\xe6\x06',
             'load': rb'\x8b\xc2\xc1\xe0\x06\x53\x8b\xd9',
             'free': rb'\x53\x8b\xda\x55\x8b\xc3\xc1\xe0\x06\x56',
             'stinit': rb'\x56\x8b\xf1\x57\x33\xc0\xb9\x00\x83'}
    for k, rx in extra.items():
        if out.get(k) is None:
            ms = [m.start() for m in re.finditer(rx, code, re.S)]
            assert len(ms) == 1, (k, len(ms))
            out[k] = t.VirtualAddress + ms[0]
    if out.get('texc') is None:
        o = out['stinit'] - t.VirtualAddress
        m = re.search(rb'\x8b\xce\xe8(....)', code[o:o + 0x40], re.S)
        rel = struct.unpack('<i', m.group(1))[0]
        out['texc'] = out['stinit'] + m.end() + rel
    return out


class Rig:
    def __init__(self, path, base=None, data=None, loc=None):
        self.raw = open(path, 'rb').read() if data is None else data
        self.pe = pefile.PE(data=self.raw)
        pre = self.pe.OPTIONAL_HEADER.ImageBase
        self.base = base or pre
        self.mu = mu = Uc(UC_ARCH_X86, UC_MODE_32)
        size = (self.pe.OPTIONAL_HEADER.SizeOfImage + 0xfff) & ~0xfff
        mu.mem_map(self.base, size)
        img = bytearray(size)
        img[:self.pe.OPTIONAL_HEADER.SizeOfHeaders] = self.raw[:self.pe.OPTIONAL_HEADER.SizeOfHeaders]
        for s in self.pe.sections:
            if s.SizeOfRawData:
                img[s.VirtualAddress:s.VirtualAddress + s.SizeOfRawData] = self.raw[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData]
        delta = self.base - pre
        if delta:
            for blk in self.pe.DIRECTORY_ENTRY_BASERELOC:
                for e in blk.entries:
                    if e.type == 3:
                        v = struct.unpack_from('<I', img, e.rva)[0]
                        struct.pack_into('<I', img, e.rva, (v + delta) & 0xffffffff)
        mu.mem_write(self.base, bytes(img))
        mu.mem_map(STUB, 0x10000)
        mu.mem_map(HEAP, 0x8000000)
        mu.mem_map(CTXB, 0x10000)
        mu.mem_map(STACK - 0x100000, 0x100000)
        mu.mem_map(RET, 0x1000)
        self.heap = HEAP
        self.stubs = {}
        self.nmalloc = 0
        self.freed = []
        self.fail_malloc_after = None
        for name, fn in (('malloc', self._malloc), ('free', self._free), ('calloc', self._calloc)):
            self._stub(name, fn)
        mu.hook_add(UC_HOOK_CODE, self._hook)
        lr = open(loc, 'rb').read() if loc else self.raw
        self.fn = {k: (self.base + v if v else None) for k, v in locate(lr, pefile.PE(data=lr)).items()}
        self.ctx = CTXB
        # array base = new section start or old bss address
        self.mu.mem_write(self.ctx, b'\0' * 0x100)

    def _stub(self, name, fn):
        for e in self.pe.DIRECTORY_ENTRY_IMPORT:
            for i in e.imports:
                if i.name and i.name.decode() == name:
                    a = STUB + 0x10 * (len(self.stubs) + 1)
                    self.stubs[a] = fn
                    self.mu.mem_write(self.base + i.address - self.pe.OPTIONAL_HEADER.ImageBase, struct.pack('<I', a))

    def _hook(self, mu, addr, size, _):
        if addr in self.stubs:
            self.stubs[addr](mu)
            ret = struct.unpack('<I', mu.mem_read(mu.reg_read(UC_X86_REG_ESP), 4))[0]
            mu.reg_write(UC_X86_REG_ESP, mu.reg_read(UC_X86_REG_ESP) + 4)
            mu.reg_write(UC_X86_REG_EIP, ret)
        elif addr == RET:
            mu.emu_stop()

    def _arg(self, mu, n):
        return struct.unpack('<I', mu.mem_read(mu.reg_read(UC_X86_REG_ESP) + 4 + 4 * n, 4))[0]

    def _malloc(self, mu):
        n = self._arg(mu, 0)
        self.nmalloc += 1
        p = self.heap
        self.heap += (n + 31) & ~15
        mu.reg_write(UC_X86_REG_EAX, p)

    def _calloc(self, mu):
        n = self._arg(mu, 0) * self._arg(mu, 1)
        p = self.heap
        self.heap += (n + 31) & ~15
        mu.reg_write(UC_X86_REG_EAX, p)

    def _free(self, mu):
        self.freed.append(self._arg(mu, 0))

    def rd(self, a, n=4):
        return bytes(self.mu.mem_read(a, n))

    def rd32(self, a):
        return struct.unpack('<I', self.rd(a))[0]

    def wr32(self, a, v):
        self.mu.mem_write(a, struct.pack('<I', v & 0xffffffff))

    def call(self, addr, ecx=0, edx=0, args=(), maxi=5_000_000):
        mu = self.mu
        sp = STACK - 0x1000
        for a in reversed(args):
            sp -= 4
            mu.mem_write(sp, struct.pack('<I', a & 0xffffffff))
        sp -= 4
        mu.mem_write(sp, struct.pack('<I', RET))
        mu.reg_write(UC_X86_REG_ESP, sp)
        mu.reg_write(UC_X86_REG_ECX, ecx)
        mu.reg_write(UC_X86_REG_EDX, edx)
        mu.reg_write(UC_X86_REG_EAX, 0)
        mu.emu_start(addr, RET, count=maxi)
        return mu.reg_read(UC_X86_REG_EAX)



# ------------------------------------------------------------------ scenario
SRC = HEAP + 0x7000000
SENT = 0xAB


def pal_data(seed):
    rnd = random.Random(seed)
    return b''.join(struct.pack('<I', 0xFF000000 | rnd.getrandbits(24)) for _ in range(256))


def slot0(r):
    for s in r.pe.sections:
        if s.Name.startswith(b'.pal'):
            return r.base + s.VirtualAddress, 0x1278f0, 0x20c34 + 0xe5400
    m = re.search(rb'\xb8(....)\xb9\x08\x00\x00\x00\x89', r.raw, re.S)
    v = struct.unpack('<I', m.group(1))[0] - 4
    return v - r.pe.OPTIONAL_HEADER.ImageBase + r.base, 0x424f0, 0x20c34


class Scn:
    def __init__(self, path, base=None, loc=None):
        self.r = r = Rig(path, base, loc=loc)
        self.slot, self.S, self.tail = slot0(r)
        bss = [s for s in r.pe.sections if s.Name.startswith(b'.bss')][0]
        D = bss.VirtualAddress - 0x1b000
        pre = r.pe.OPTIONAL_HEADER.ImageBase
        rnd = random.Random(5)
        a = r.base + 0x3d6e0 + D
        r.mu.mem_write(a, bytes(rnd.getrandbits(8) for _ in range(0x42000)))
        # neighbour slot sentinel
        self.neigh = self.slot + self.S
        r.mu.mem_write(self.neigh, bytes([SENT]) * 0x2000)
        r.wr32(r.ctx + 0x60, self.slot)
        r.wr32(r.ctx + 0x50, HEAP + 0x7f00000)
        r.call(r.fn['pool'], ecx=self.slot)
        r.call(r.fn['stinit'], ecx=self.slot)
        self.tex = {}

    def new_pal(self, seed):
        r = self.r
        h = r.call(r.fn['new'], ecx=r.ctx)
        if h:
            r.mu.mem_write(SRC, pal_data(seed))
            r.call(r.fn['load'], ecx=r.ctx, edx=h, args=(0, 0, 256, SRC))
        return h

    def bind(self, h, color):
        r = self.r
        if h not in self.tex:
            t = r.call(r.fn['texc'], ecx=self.slot, edx=0, args=(0x10, 0x20))
            r.call(r.fn['attach'], ecx=r.ctx, edx=t, args=(h,))
            self.tex[h] = t
        r.wr32(r.ctx + 0x24, self.tex[h])
        p = r.call(r.fn['bind'], ecx=r.ctx, edx=color)
        return r.rd(p, 0x200)

    def state_fields(self):
        r = self.r
        return [r.rd32(self.slot + self.tail + o) for o in (0, 4, 8)]

    def neighbour_ok(self):
        return self.r.rd(self.neigh, 0x2000) == bytes([SENT]) * 0x2000


COLORS = (0x00123456, 0x00ABCDEF, 0x00000000, 0x00F8F8F8)


def conv_set(sc, h):
    return [sc.bind(h, c) for c in COLORS] + [sc.bind(h, COLORS[0])]


if __name__ == '__main__':
    import glob
    orig, patched = sys.argv[1], sys.argv[2]
    so = Scn(orig)
    ref = {}
    for seed in range(1, 121):
        h = so.new_pal(seed)
        assert h == seed, (h, seed)
        ref[seed] = conv_set(so, h)
    assert any(any(b) for b in ref[1]), 'conversion output is all zero: test would be vacuous'
    print('orig : 120 palettes ok, neighbour intact:', so.neighbour_ok())
    base = int(sys.argv[3], 16) if len(sys.argv) > 3 else None
    sp = Scn(patched, base, loc=orig)
    f0 = sp.state_fields()
    bad = 0
    top = 0
    for i in range(1, 1100):
        seed = (i - 1) % 120 + 1
        h = sp.new_pal(seed)
        if h == 0:
            print('patched: New returned 0 (table full) at request', i)
            break
        assert h == i, (h, i)
        top = h
        if i <= 130 or i % 97 == 0 or i > 1015:
            got = conv_set(sp, h)
            if got != ref[seed]:
                bad += 1
                print('MISMATCH handle', h)
    print('patched: highest handle', top, 'mismatches', bad)
    print('patched: default texture ptr kept:', f0[0] == sp.state_fields()[0], 'list head sane:', sp.state_fields()[1] not in (0, 0x7fffffff),
          'neighbour intact:', sp.neighbour_ok())
    # re-bind early handles after thousands of allocations (cache / eviction state)
    again = all(conv_set(sp, h) == ref[h] for h in (1, 31, 32, 33, 64, 120))
    print('patched: early handles still convert identically:', again)
    # free-all then reuse
    sp.r.call(sp.r.fn['freeall'], ecx=sp.r.ctx)
    h = sp.r.call(sp.r.fn['new'], ecx=sp.r.ctx)
    print('patched: after free-all New ->', h, 'default texture ptr kept:', f0[0] == sp.state_fields()[0], 'neighbour:', sp.neighbour_ok())
