const std = @import("std");
const elf = std.elf;
const windows = std.os.windows;

// Windows NT definitions
const MEM_COMMIT = 0x00001000;
const MEM_RESERVE = 0x00002000;
const PAGE_EXECUTE_READWRITE = 0x40;
const PAGE_READWRITE = 0x04;
const PAGE_READONLY = 0x02;

// Linux Auxiliary Vector types
const AT_NULL = 0;
const AT_PHDR = 3;
const AT_PHENT = 4;
const AT_PHNUM = 5;
const AT_PAGESZ = 6;
const AT_BASE = 7;
const AT_FLAGS = 8;
const AT_ENTRY = 9;
const AT_UID = 11;
const AT_EUID = 12;
const AT_GID = 13;
const AT_EGID = 14;
const AT_PLATFORM = 15;
const AT_HWCAP = 16;
const AT_CLKTCK = 17;
const AT_SECURE = 23;
const AT_RANDOM = 25;
const AT_EXECFN = 31;
const AT_SYSINFO_EHDR = 33;

extern "kernel32" fn VirtualAlloc(
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) callconv(.c) ?*anyopaque;

extern "kernel32" fn GetLastError() callconv(.c) u32;
extern "kernel32" fn FlushInstructionCache(
    hProcess: windows.HANDLE,
    lpBaseAddress: ?*anyopaque,
    dwSize: usize,
) callconv(.c) windows.BOOL;

pub const ExecutionContext = struct {
    entry: usize,
    stack: usize,
    brk: usize,
};

pub const ElfLoader = struct {
    allocator: std.mem.Allocator,
    args: []const []const u8 = &[_][]const u8{},
    arg_addrs: []usize = &[_]usize{},

    pub fn init(allocator: std.mem.Allocator) ElfLoader {
        return .{
            .allocator = allocator,
        };
    }

    pub fn load(self: *ElfLoader, path: []const u8, args: []const []const u8) !ExecutionContext {
        self.args = args;
        self.arg_addrs = try self.allocator.alloc(usize, args.len);
        // We don't defer free because we need these for setupInitialStack,
        // and the loader instance lives long enough. Actually main can free them.

        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        var ehdr: elf.Elf64_Ehdr = undefined;
        try file.seekTo(0);
        if (try file.readAll(std.mem.asBytes(&ehdr)) < @sizeOf(elf.Elf64_Ehdr)) return error.InvalidElfHeader;

        if (!std.mem.eql(u8, ehdr.e_ident[0..4], elf.MAGIC)) return error.NotElf;
        if (ehdr.e_ident[elf.EI_CLASS] != elf.ELFCLASS64) return error.NotElf64;

        var min_vaddr: usize = std.math.maxInt(usize);
        var max_vaddr: usize = 0;
        var phdr_addr: usize = 0;

        // First pass: find range and PHDR
        var phdr_idx: u16 = 0;
        while (phdr_idx < ehdr.e_phnum) : (phdr_idx += 1) {
            var phdr: elf.Elf64_Phdr = undefined;
            try file.seekTo(ehdr.e_phoff + phdr_idx * ehdr.e_phentsize);
            if (try file.readAll(std.mem.asBytes(&phdr)) < ehdr.e_phentsize) return error.InvalidPhdr;

            if (phdr.p_type == elf.PT_PHDR) {
                phdr_addr = phdr.p_vaddr;
            }

            if (phdr.p_type == elf.PT_LOAD) {
                if (phdr.p_vaddr < min_vaddr) min_vaddr = phdr.p_vaddr;
                if (phdr.p_vaddr + phdr.p_memsz > max_vaddr) max_vaddr = phdr.p_vaddr + phdr.p_memsz;
            }
        }

        if (min_vaddr == std.math.maxInt(usize)) return error.NoLoadableSegments;

        // Reserve the entire range
        var load_base: usize = 0;
        if (min_vaddr < 0x400000) {
            load_base = 0x400000;
        }

        const aligned_min = (min_vaddr + load_base) & ~@as(usize, 0xFFFF);
        const aligned_max = (max_vaddr + load_base + 0xFFFF) & ~@as(usize, 0xFFFF);
        const total_size = aligned_max - aligned_min;

        const reserved_ptr = VirtualAlloc(
            @ptrFromInt(aligned_min),
            total_size,
            MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        if (reserved_ptr) |ptr| {
            if (min_vaddr < 0x400000) load_base = @intFromPtr(ptr) - min_vaddr;
        }

        // Second pass: load segments
        phdr_idx = 0;
        while (phdr_idx < ehdr.e_phnum) : (phdr_idx += 1) {
            var phdr: elf.Elf64_Phdr = undefined;
            try file.seekTo(ehdr.e_phoff + phdr_idx * ehdr.e_phentsize);
            if (try file.readAll(std.mem.asBytes(&phdr)) < ehdr.e_phentsize) return error.InvalidPhdr;

            if (phdr.p_type == elf.PT_LOAD) {
                const vaddr = phdr.p_vaddr;
                const memsz = phdr.p_memsz;
                const filesz = phdr.p_filesz;
                const offset = phdr.p_offset;

                const aligned_vaddr = (vaddr + load_base) & ~@as(usize, 0xFFF);
                const offset_in_page = (vaddr + load_base) & 0xFFF;
                const aligned_memsz = (memsz + offset_in_page + 0xFFF) & ~@as(usize, 0xFFF);

                const ptr = VirtualAlloc(
                    @ptrFromInt(aligned_vaddr),
                    aligned_memsz,
                    MEM_COMMIT,
                    PAGE_EXECUTE_READWRITE,
                ) orelse {
                    std.debug.print("TEA: VirtualAlloc (COMMIT) failed for 0x{x} with error {d}\n", .{ aligned_vaddr, GetLastError() });
                    return error.MemoryAllocationFailed;
                };

                const segment_ptr = @as([*]u8, @ptrCast(ptr)) + offset_in_page;
                try file.seekTo(offset);
                const bytes_read = try file.readAll(segment_ptr[0..filesz]);
                if (bytes_read != filesz) return error.IncompleteRead;

                self.patchSyscalls(segment_ptr[0..filesz]);
                _ = FlushInstructionCache(windows.kernel32.GetCurrentProcess(), ptr, aligned_memsz);

                if (memsz > filesz) {
                    @memset(segment_ptr[filesz..memsz], 0);
                }
            }
        }

        const relocated_phdr = (if (phdr_addr != 0) phdr_addr else min_vaddr + ehdr.e_phoff) + load_base;

        // Setup vDSO
        const vdso_ptr = VirtualAlloc(
            null,
            4096,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        ) orelse return error.MemoryAllocationFailed;

        const vdso_image = [_]u8{
            0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };
        @memcpy(@as([*]u8, @ptrCast(vdso_ptr))[0..vdso_image.len], &vdso_image);

        // Setup stack
        const stack_size = 8 * 1024 * 1024;
        const stack_ptr = VirtualAlloc(
            null,
            stack_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) orelse return error.StackAllocationFailed;

        const stack_top = @intFromPtr(stack_ptr) + stack_size;
        const relocated_entry = ehdr.e_entry + load_base;
        const initial_rsp = try self.setupInitialStack(stack_top, path, ehdr, relocated_phdr, relocated_entry, @intFromPtr(vdso_ptr));

        return ExecutionContext{
            .entry = relocated_entry,
            .stack = initial_rsp,
            .brk = (max_vaddr + load_base + 0xFFF) & ~@as(usize, 0xFFF),
        };
    }

    fn setupInitialStack(self: *ElfLoader, stack_top: usize, path: []const u8, ehdr: elf.Elf64_Ehdr, phdr_addr: usize, entry_addr: usize, vdso_addr: usize) !usize {
        var rsp = stack_top;

        // Data area for strings
        const path_len = path.len + 1;

        // Push execfn string
        rsp -= (path_len + 15) & ~@as(usize, 15);
        const execfn_addr = rsp;
        const execfn_ptr = @as([*]u8, @ptrFromInt(rsp));
        @memcpy(execfn_ptr[0..path.len], path);
        for (execfn_ptr[0..path.len]) |*c| {
            if (c.* == '\\') c.* = '/';
        }
        execfn_ptr[path.len] = 0;

        // Push arguments strings
        for (self.args, 0..) |arg, i| {
            const arg_len = arg.len + 1;
            rsp -= (arg_len + 15) & ~@as(usize, 15);
            self.arg_addrs[i] = rsp;
            const arg_ptr = @as([*]u8, @ptrFromInt(rsp));
            @memcpy(arg_ptr[0..arg.len], arg);
            // Normalize argv[0] to use forward slashes for Linux compatibility (e.g., BusyBox)
            if (i == 0) {
                for (arg_ptr[0..arg.len]) |*c| {
                    if (c.* == '\\') c.* = '/';
                }
            }
            arg_ptr[arg.len] = 0;
        }

        // Random bytes for AT_RANDOM
        rsp -= 16;
        @as(*[16]u8, @ptrFromInt(rsp)).* = [_]u8{0x42} ** 16;
        const random_ptr = rsp;

        // Platform string
        rsp -= 16;
        @as([*]u8, @ptrFromInt(rsp))[0..7].* = "x86_64\x00".*;
        const platform_ptr = rsp;

        // AuxV entries
        const aux_entries = [_][2]usize{
            .{ AT_PHDR, phdr_addr },
            .{ AT_PHENT, ehdr.e_phentsize },
            .{ AT_PHNUM, ehdr.e_phnum },
            .{ AT_PAGESZ, 4096 },
            .{ AT_BASE, 0 },
            .{ AT_FLAGS, 0 },
            .{ AT_ENTRY, entry_addr },
            .{ AT_UID, 1000 },
            .{ AT_EUID, 1000 },
            .{ AT_GID, 1000 },
            .{ AT_EGID, 1000 },
            .{ AT_HWCAP, 0 },
            .{ AT_CLKTCK, 100 },
            .{ AT_RANDOM, random_ptr },
            .{ AT_PLATFORM, platform_ptr },
            .{ AT_SECURE, 0 },
            .{ AT_EXECFN, execfn_addr },
            .{ AT_SYSINFO_EHDR, vdso_addr },
            .{ AT_NULL, 0 },
        };

        rsp &= ~@as(usize, 15);

        for (0..aux_entries.len) |i| {
            const entry = aux_entries[aux_entries.len - 1 - i];
            rsp -= 8;
            @as(*usize, @ptrFromInt(rsp)).* = entry[1];
            rsp -= 8;
            @as(*usize, @ptrFromInt(rsp)).* = entry[0];
        }

        rsp -= 8;
        @as(*usize, @ptrFromInt(rsp)).* = 0; // envp end

        // argv
        rsp -= 8;
        @as(*usize, @ptrFromInt(rsp)).* = 0; // argv end
        // Push arguments in reverse
        var arg_idx: usize = self.args.len;
        while (arg_idx > 0) {
            arg_idx -= 1;
            rsp -= 8;
            @as(*usize, @ptrFromInt(rsp)).* = self.arg_addrs[arg_idx];
        }

        rsp -= 8;
        @as(*usize, @ptrFromInt(rsp)).* = self.args.len; // argc

        return rsp;
    }

    fn patchSyscalls(self: *ElfLoader, data: []u8) void {
        _ = self;
        var i: usize = 0;
        while (i + 1 < data.len) {
            if (data[i] == 0x0F and data[i + 1] == 0x05) {
                data[i + 1] = 0x0B;
                i += 2;
                continue;
            }
            if (data[i] == 0xCD and data[i + 1] == 0x80) {
                data[i] = 0x0F;
                data[i + 1] = 0x0B;
                i += 2;
                continue;
            }
            i += 1;
        }
    }
};
