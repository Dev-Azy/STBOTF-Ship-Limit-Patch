import sys, struct
import pefile
from unicorn import *
from unicorn.x86_const import *
sys.path.insert(0, '.')
import shipmodels as sm

RET = 0x10000000
def load(data):
    pe = pefile.PE(data=data)
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    size = (pe.OPTIONAL_HEADER.SizeOfImage + 0xfff) & ~0xfff
    mu.mem_map(0x400000, size)
    mu.mem_write(0x400000, data[:pe.OPTIONAL_HEADER.SizeOfHeaders])
    for s in pe.sections:
        if s.SizeOfRawData:
            mu.mem_write(0x400000 + s.VirtualAddress, data[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData])
    mu.mem_map(0x30000000, 0x100000)   # stack + scratch
    mu.mem_map(RET, 0x1000)
    mu.hook_add(UC_HOOK_CODE, lambda m, a, s, u: m.emu_stop() if a == RET else None)
    return mu

def lookup(mu, name: bytes):
    mu.mem_write(0x30080000, name + b'\0' * 8)
    sp = 0x300F0000
    mu.mem_write(sp - 4, struct.pack('<I', RET))
    mu.reg_write(UC_X86_REG_ESP, sp - 4)
    mu.reg_write(UC_X86_REG_EAX, 0x30080000)
    mu.emu_start(0x4A2890, RET, count=200000)
    return mu.reg_read(UC_X86_REG_EAX)

def getter(mu):
    mu.mem_write(0x300F0000 - 4, struct.pack('<I', RET))
    mu.reg_write(UC_X86_REG_ESP, 0x300F0000 - 4)
    mu.emu_start(0x4A2880, RET, count=100)
    return mu.reg_read(UC_X86_REG_EAX)

if __name__ == '__main__':
    orig = open(sys.argv[1], 'rb').read()
    pat = open(sys.argv[2], 'rb').read()
    pe = pefile.PE(data=orig)
    o = sm.v2o(pe, sm.OLD_TABLE)
    names = [orig[o + i * 48:o + i * 48 + 4].rstrip(b'\0') for i in range(74)]
    probes = [n for n in names[:73]] + [n.lower() for n in names[:10]] + [b'H1_', b'CH1_', b'xyz', b'ZZ9', b'', b'TMP', b'___', b'H1_xyz', b'CS_', b'M01_']
    # extra: add three entries to the PATCHED image (slots 80, 300, 511) by writing into section data
    pp = pefile.PE(data=pat)
    mdl = [s for s in pp.sections if s.Name.startswith(b'.mdl')][0]
    buf = bytearray(pat)
    ent = bytearray(orig[o + 7 * 48:o + 8 * 48])       # clone 'CO'
    for slot, nm in ((80, b'ZA1'), (300, b'ZB2'), (511, b'ZC3')):
        e = bytearray(ent); e[:4] = nm + b'\0'; e[0x1c:0x20] = struct.pack('<f', 2.5 + slot)
        buf[mdl.PointerToRawData + slot * 48: mdl.PointerToRawData + (slot + 1) * 48] = e
    pat2 = bytes(buf)
    mo, mp = load(orig), load(pat2)
    def key_entry(mu, base, name):
        a = lookup(mu, name)
        return None if a == 0 else bytes(mu.mem_read(a, 48))
    bad = 0
    for nm in probes:
        a, b = key_entry(mo, 0, nm), key_entry(mp, 0, nm)
        if a != b:
            bad += 1; print('DIFF', nm, a and a[:8], b and b[:8])
    print('probes compared:', len(probes), 'differences:', bad)
    # TMP getter returns same bytes
    print('TMP getter equal:', bytes(mo.mem_read(getter(mo), 48)) == bytes(mp.mem_read(getter(mp), 48)))
    for nm, slot in ((b'ZA1', 80), (b'ZB2', 300), (b'ZC3', 511), (b'za1', 80)):
        e = key_entry(mp, 0, nm)
        print(nm, 'found' if e else 'MISSING', e and struct.unpack_from('<f', e, 0x1c)[0], 'expected', 2.5 + slot)
    print('unknown name -> returns 0 (caller then uses TMP):', key_entry(mp, 0, b'QQQ'))
