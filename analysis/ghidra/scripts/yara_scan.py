# Ghidra headless script: dump raw bytes and run YARA rules
# Requires: yara-python available on the Ghidra JVM Python path (via ghidra_bridge)
# or run YARA externally on the raw binary after export.
#
# This script dumps the first loadable segment to a temp file
# so external YARA can be run on it.

import os, tempfile

memory = currentProgram.getMemory()
blocks = [b for b in memory.getBlocks() if b.isLoaded() and b.isInitialized()]

if not blocks:
    print('No loaded/initialized memory blocks found')
else:
    # dump largest block (usually .text or main ELF segment)
    block = sorted(blocks, key=lambda b: -b.getSize())[0]
    data  = bytearray(block.getSize())
    block.getBytes(block.getStart(), data, 0, len(data))

    out_path = os.path.join(
        str(currentProgram.getDomainFile().getParent().getPathname()),
        'main_segment.bin'
    )
    with open(out_path, 'wb') as f:
        f.write(bytes(data))
    print('Dumped {} bytes from {} to {}'.format(len(data), block.getName(), out_path))
    print('Run: yara -r analysis/yara/ {}'.format(out_path))
