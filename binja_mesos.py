'''
Uses Binary Ninja to generate a Mesos file from specified target

Author: @seeinglogic
'''

import os
import sys
import struct
import binaryninja
from pathlib import Path


USAGE = f'{sys.argv[0]} TARGET [OUTPUT_FILE]'
if len(sys.argv) not in [2,3]:
    print(USAGE)
    exit(1)

input_file = sys.argv[1]

# input_name is 'notepad.exe' from 'notepad.exe_bdd4adcd_38000'
# which is saved in the mesos file
last_dot = input_file.rfind('.')
extension = input_file[last_dot:last_dot+4]
input_name = Path(input_file).stem + extension

if len(sys.argv) == 3:
    output_filename = sys.argv[2]
else:
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    output_filename = os.path.join(cur_dir, f'{input_name}.meso')


print(f'Loading file "{input_file}" ({input_name=})...')
sys.stdout.flush()
with binaryninja.load(input_file) as bv:
    print("Analysis done, generating meso file...")
    sys.stdout.flush()

    image_base = bv.start

    tmp_filename = output_filename + ".tmp"
    with open(tmp_filename, "wb") as fd:
        # Write record type 0 (module)
        # unsigned 16-bit module name length
        fd.write(struct.pack("<BH", 0, len(input_name)))
        # And module name
        fd.write(input_name.encode())

        for cur_func in bv.functions:
            # mangled names might need different handling?
            func_name = cur_func.symbol.short_name

            # Write record type 1 (function)
            # Write unsigned 16-bit function name length and function name
            fd.write(struct.pack("<BH", 1, len(func_name)) + func_name.encode())

            # Write unsigned 64-bit offset of the function WRT the module base
            fd.write(struct.pack("<Q", cur_func.start - image_base))

            blockoffs = bytearray()
            for block in cur_func:
                blockoffs += struct.pack("<i", block.start - cur_func.start)

            # Unsigned 32-bit number of blocks, followed by block offsets
            fd.write(struct.pack("<I", len(blockoffs) // 4))
            fd.write(blockoffs)

    # Rename .tmp file to actual name
    if os.path.exists(output_filename):
        os.unlink(output_filename)
        print(f'NOTE: deleted existing file "{output_filename}"')
    os.rename(tmp_filename, output_filename)

    print(f'Generated meso file: {output_filename}')
