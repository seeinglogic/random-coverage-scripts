# Scripts to get block coverage from a binary

Here's a handful of scripts/tools to get block coverage information from a binary.

1. Scriptable debugger
  - [Headless Binary Ninja Script](./bn_debugger_coverage.py)
  - [Binary Ninja script](./binja_mesos.py) for [Mesos](https://github.com/gamozolabs/mesos)
2. TTD debugger
  - See [0vercl0k's script](https://github.com/0vercl0k/windbg-scripts/tree/master/codecov) for WinDbg
3. Emulator
  - [Script](./qemu_trace_to_blocks.py) to parse QEMU's `-d in_asm` debug output
4. Dynamic Binary Instrumentation (DBI)
  - [Script](https://github.com/ForAllSecure/bncov/blob/master/dr_block_coverage.py) for DynamoRIO's [drcov](https://dynamorio.org/page_drcov.html)
5. Static rewriting
  - [Script to parse](./dyninst_to_modcov.py) DynInst's [codeCoverage example](https://github.com/dyninst/examples/tree/master/codeCoverage)
