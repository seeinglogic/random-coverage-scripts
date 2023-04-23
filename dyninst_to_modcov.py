#!/usr/bin/python3

'''
Convert output from DynInst's codeCoverage example
(https://github.com/dyninst/examples/tree/master/codeCoverage)
and its basic block (`-b`) logging into a "module+offset" instruction trace.

Need to capture stdout and feed that file as input to this script.
'''

import os
import sys
from pathlib import Path

USAGE = f'{sys.argv[0]} COVERAGE_OUTPUT_FILE HEX_BASE_ADDR [OUTFILE]'

def convert_coverage(in_file: str, module_base: int, out_file: str):

    addrs_seen = set()

    '''
    Output looks like:
 ************************** Basic Block Coverage ************************* 

 (__do_global_dtors_aux, gcc-testcc)
 	    1 : 0x10e0    
 	    1 : 0x10ed    
 	    1 : 0x10fb    
 	    1 : 0x1107
    '''
    in_basic_block_section = False
    with open(in_file) as f:
        for line in f:
            if not in_basic_block_section:
                if line.startswith(' ************************** Basic Block Coverage'):
                    in_basic_block_section = True
            else:
                # Want lines like the following
 	            #  	    1 : 0x1251    
                parts = line.split(':')
                if len(parts) == 2:
                    block_addr = int(parts[1].strip(), 16)
                    addrs_seen.add(block_addr)
    
    # Better to spend time checking than time trying to debug what happened
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

