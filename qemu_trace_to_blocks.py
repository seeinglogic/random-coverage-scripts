#!/usr/bin/python3

'''
Translate the output from qemu-users "-d in_out" logging
into "module+offset" instruction trace.
'''

import os
import sys
from pathlib import Path

USAGE = f'{sys.argv[0]} ASM_TRACE HEX_BASE_ADDR [OUTFILE]'

def convert_coverage(in_file: str, module_base: int, out_file: str):
    addrs_seen = set()
    with open(in_file) as f:
        for line in f:
            # Record all addresses, don't trust their blocks
            if line.startswith('0x'):
                cur_addr = int(line.split(':')[0], 16)
                addrs_seen.add(cur_addr)
    
    # Better spend time doing this check than time trying to debug what happened
    for addr in addrs_seen:
        if addr < module_base:
            print(f'[!] Address lower than module base: 0x{addr:x} < 0x{module_base:x}')
            exit(2)

    module = Path(in_file).stem
    with open(out_file, 'w') as f:
        offsets_seen = [addr - module_base for addr in addrs_seen]
        for offset in offsets_seen:
            f.write(f'{module}+{offset:x}\n')


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(USAGE)
        exit(2)

    in_file = sys.argv[1]
    if not os.path.exists(in_file):
        print(f'[!] Input file "{in_file}" not found')
        exit(2)

    module_base = int(sys.argv[2], 16)

    if len(sys.argv) >= 4:
        out_file = sys.argv[3]
    else:
        in_path = Path(in_file)
        out_file = in_path.stem + '.modcov'

    in_size = os.path.getsize(in_file)
    if in_size == 0:
        print(f'[!] Input file "{in_file}" is empty')
        exit(2)

    convert_coverage(in_file, module_base, out_file)
    
    out_size = os.path.getsize(out_file)
    print(f'[+] Read {in_size} bytes from {in_file}, wrote {out_size} bytes to {out_file}')

