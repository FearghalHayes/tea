# AGENTS.md

This file provides guidance to agents when working with code in this repository.

- Build: `zig build`
- Test: `zig build test`
- Stack: Zig compatibility layer for running Linux ELFs on Windows.
- Core: Syscall shimming, ELF loading, and fork() emulation via COW.
- Naming: Syscall handlers MUST use `sys_` prefix (e.g., `sys_read`).
