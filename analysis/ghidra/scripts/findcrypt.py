# Ghidra headless script: detect cryptographic constants
# Inspired by py-findcrypt-ghidra (AllsafeCyberSecurity)
# https://github.com/AllsafeCyberSecurity/py-findcrypt-ghidra

from ghidra.program.model.mem import MemoryAccessException
import json, os, struct

# Subset of crypto constants (S-boxes, round constants)
CRYPTO_SIGNATURES = [
    {'name': 'AES_SBOX',       'sig': bytes([0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5])},
    {'name': 'AES_INV_SBOX',   'sig': bytes([0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38])},
    {'name': 'DES_IPERM',      'sig': bytes([0x3a,0x32,0x2a,0x22,0x1a,0x12,0x0a,0x02])},
    {'name': 'RC4_INIT_CHECK', 'sig': b'expand 32-byte k'},
    {'name': 'MD5_INIT',       'sig': struct.pack('<IIII', 0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476)},
    {'name': 'SHA1_INIT',      'sig': struct.pack('>IIIII', 0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0)},
    {'name': 'SHA256_K0',      'sig': struct.pack('>II', 0x428a2f98,0x71374491)},
    {'name': 'CHACHA20_CONST', 'sig': b'expa'},
    {'name': 'MIRAI_XOR_KEY',  'sig': bytes([0xDE,0xAD,0xBE,0xEF])},  # Mirai C2 XOR
]

memory = currentProgram.getMemory()
results = []

for cs in CRYPTO_SIGNATURES:
    sig = cs['sig']
    addr = currentProgram.getMinAddress()
    while True:
        found = memory.findBytes(addr, sig, None, True, monitor)
        if found is None:
            break
        results.append({'name': cs['name'], 'address': str(found)})
        print('[FindCrypt] {} at {}'.format(cs['name'], found))
        try:
            addr = found.add(1)
        except Exception:
            break

out_path = os.path.join(
    str(currentProgram.getDomainFile().getParent().getPathname()),
    'findcrypt.json'
)
with open(out_path, 'w') as f:
    json.dump(results, f, indent=2)
print('FindCrypt: {} hits'.format(len(results)))
