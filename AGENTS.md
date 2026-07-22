# AGENTS.md

## Overview
GDB/Pwndbg plugin (not a standalone app). Two scripts cover the pipeline: export renamed functions from IDA Pro, import them into GDB for `func_name+offset` display.

## Prerequisites
- **pwndbg** (GDB plugin framework) — must be sourced in GDB before this script
- **pwntools** `checksec` utility — used for PIE detection (`GDB-Import-Script.py:56`)
- IDA Pro with `idautils`, `idaapi`, `idc` — only for the export script

## Files & entrypoints
- `IDA-Outport-Script.py` — IDA Pro script to export functions to `.rename` file. Run via File → Script File in IDA.
- `GDB-Import-Script.py` — GDB plugin loaded via `source`. Registers commands: `rename_import`, `rename_save`, `rename_load`, `rename_list`, `rename_delete`, `rename_uninstall`.
- `.rename` — default output/input file for symbol data (line format: `addr name` or `start end name` or `addr name #bp`)

## Key workflow
1. In IDA: run `IDA-Outport-Script.py` after renaming functions → produces `.rename` file
2. In GDB: `source GDB-Import-Script.py`, then `rename_import ./.rename`
3. `rename_save` persists in-session renames; `rename_load` reloads them
4. `rename_uninstall` removes the symbol hook

## Architecture notes
- The GDB script **monkey-patches** `pwndbg.aglib.symbol.resolve_addr` to intercept symbol resolution and inject renamed symbols. This is the core mechanism.
- The import uses a fallback chain for pwndbg version compatibility: `pwndbg.aglib.symbol` (2025.02.19+) → `pwndbg.gdblib.symbol` (2024.x) → `pwndbg.symbol` (legacy).
- In pwndbg 2025.02.19+, the old `symbol.get` API was replaced by `symbol.resolve_addr`. The `pwndbg.gdblib.proc` and `pwndbg.gdblib.elf` modules no longer exist in newer versions.
- PIE-aware: uses `piebase` (pwndbg) + `checksec` (pwntools) to rebase addresses. Results are cached in globals.
- The IDA script filters out `sub_*` prefix functions (auto-generated names).

## No build/test/CI
No build system, no tests, no CI, no linter config. Changes are verified manually in GDB with pwndbg.
