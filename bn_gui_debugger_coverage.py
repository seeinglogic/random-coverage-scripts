'''
A version that's easier to cut-and-paste into the Python Console in the GUI.
...In case you're a barbarian like me who doesn't always use snippets
(don't tell ;) )

Just cut and paste this whole thing and then do: run_target_for_coverage(bv)

Tested on a few Ubuntu 22.04 binaries. Just remember it's going to be a lot
faster if you run the headless version; this one's just for fun.
'''

from typing import Set
from pathlib import Path
import time
import binaryninja
from binaryninja.debugger import (
    DebuggerController, ModuleNameAndOffset, DebugStopReason
)

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
    print(f'[DBG] Setting breakpoints...')
    start = time.time()
    for offset in block_offsets:
        mod_offset = ModuleNameAndOffset(
            bv.file.filename,
            offset
        )
        dbg.add_breakpoint(mod_offset)
    duration = time.time() - start
    print(f'[DBG] Took {duration:.02f} seconds')
    print(f'[*] Starting to run "{bv.file.original_filename}" for coverage...')
    start = time.time()
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
    duration = time.time() - start
    print(f'[DBG] Took {duration:.02f} seconds')
    return offsets_covered
