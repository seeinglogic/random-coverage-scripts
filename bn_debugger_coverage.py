#!/usr/bin/python3

'''
Proof-of-concept headless script for getting block coverage
via Binary Ninja's built-in debugger (tested on version 3.3.3996)

Author: @seeinglogic
'''

from typing import Set
import os
import sys
import time
from pathlib import Path

import binaryninja
from binaryninja.debugger import (
    DebuggerController, ModuleNameAndOffset, DebugStopReason
)


USAGE = f'{sys.argv[0]} TARGET [OUTFILE]'


def run_target_for_coverage(bv: binaryninja.BinaryView) -> Set[int]:
    module_name = Path(bv.file.original_filename).name
    module_size = bv.end - bv.start
    block_offsets = set(b.start - bv.start for b in bv.basic_blocks)
    print(f'[*] Setting {len(block_offsets)} breakpoints, one for each block...')

    dbg = DebuggerController(bv)
    dbg.launch()

    module = next(m for m in dbg.modules if Path(m.name).name == module_name)
    module_base = module.address
    module_ceil = module_base + module_size

    #print(f'[DBG] Setting breakpoints...')
    start = time.time()
    for offset in block_offsets:
        mod_offset = ModuleNameAndOffset(
            bv.file.filename,
            offset
        )
        dbg.add_breakpoint(mod_offset)
    duration = time.time() - start
    #print(f'[DBG] Took {duration:.02f} seconds')

    print(f'[*] Starting to run "{bv.file.original_filename}" for coverage...')
    offsets_covered = set()
    while True:
        reason = dbg.go_and_wait()
        if reason == DebugStopReason.Breakpoint:
            stop_addr = dbg.ip
            dbg.delete_breakpoint(stop_addr)
            if module_base <= stop_addr < module_ceil:
                offsets_covered.add(stop_addr - module_base)
        else:
            reason_name = next(str(r) for r in DebugStopReason if r == reason)
            print(f'[*] Stopped for reason {reason_name}" ({reason}), finishing coverage...')
            break

    return offsets_covered


def write_module_offset_file(filename: str, module_name: str, offsets_covered: Set[int]):
    with open(filename, 'w') as f:
        for offset in offsets_covered:
            f.write(f'{module_name}+{offset:x}\n')


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(USAGE)
        exit(2)
    
    target = sys.argv[1]
    if not os.path.exists(target):
        print(f'[!] Target file "{target}" not found')
        exit(2)

    target_path = Path(target)
    out_file = target_path.stem + '.modcov'
    if len(sys.argv) > 2:
        out_file = sys.argv[2]

    print(f'[*] Loading binary view of "{target}"...')
    bv = binaryninja.load(target)

    start = time.time()
    offsets_covered = run_target_for_coverage(bv)
    duration = time.time() - start
    print(f'[*] Gathered coverage from "{target}" in {duration:.02f} seconds')

    write_module_offset_file(out_file, target_path.name, offsets_covered)
    out_size = os.path.getsize(out_file)
    if out_size:
        print(f'[+] Wrote {len(offsets_covered)} offsets to "{out_file}"')
    else:
        print(f'[!] Failed to write coverage to "{out_file}"')

