const std = @import("std");
const windows = std.os.windows;
const syscall = @import("syscall.zig");

const NTSTATUS = i32;
const STATUS_SUCCESS = 0;
const SECTION_ALL_ACCESS = 0xF001F;
const SEC_COMMIT = 0x08000000;
const ViewUnmap = 2;

// Linux Memory Protection Constants
pub const PROT_NONE = 0x0;
pub const PROT_READ = 0x1;
pub const PROT_WRITE = 0x2;
pub const PROT_EXEC = 0x4;

// Linux mmap Flags
pub const MAP_SHARED = 0x01;
pub const MAP_PRIVATE = 0x02;
pub const MAP_FIXED = 0x10;
pub const MAP_ANONYMOUS = 0x20;

// Windows Constants
const MEM_COMMIT = 0x1000;
const MEM_RESERVE = 0x2000;
const MEM_RELEASE = 0x8000;
const PAGE_NOACCESS = 0x01;
const PAGE_READONLY = 0x02;
const PAGE_READWRITE = 0x04;
const PAGE_WRITECOPY = 0x08;
const PAGE_EXECUTE = 0x10;
const PAGE_EXECUTE_READ = 0x20;
const PAGE_EXECUTE_READWRITE = 0x40;
const PAGE_EXECUTE_WRITECOPY = 0x80;

extern "ntdll" fn NtCreateSection(
    SectionHandle: *windows.HANDLE,
    DesiredAccess: windows.ACCESS_MASK,
    ObjectAttributes: ?*anyopaque,
    MaximumSize: ?*const windows.LARGE_INTEGER,
    SectionPageProtection: windows.ULONG,
    AllocationAttributes: windows.ULONG,
    FileHandle: ?windows.HANDLE,
) callconv(.c) NTSTATUS;

extern "ntdll" fn NtMapViewOfSection(
    SectionHandle: windows.HANDLE,
    ProcessHandle: windows.HANDLE,
    BaseAddress: *?*anyopaque,
    ZeroBits: windows.ULONG_PTR,
    CommitSize: windows.SIZE_T,
    SectionOffset: ?*const windows.LARGE_INTEGER,
    ViewSize: *windows.SIZE_T,
    InheritDisposition: u32,
    AllocationType: windows.ULONG,
    Win32Protect: windows.ULONG,
) callconv(.c) NTSTATUS;

extern "ntdll" fn NtUnmapViewOfSection(
    ProcessHandle: windows.HANDLE,
    BaseAddress: ?*anyopaque,
) callconv(.c) NTSTATUS;

extern "kernel32" fn VirtualAlloc(
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flAllocationType: u32,
    flProtect: u32,
) callconv(.c) ?*anyopaque;

extern "kernel32" fn VirtualFree(
    lpAddress: ?*anyopaque,
    dwSize: usize,
    dwFreeType: u32,
) callconv(.c) i32;

extern "kernel32" fn VirtualProtect(
    lpAddress: ?*anyopaque,
    dwSize: usize,
    flNewProtect: u32,
    lpflOldProtect: *u32,
) callconv(.c) i32;

extern "kernel32" fn CloseHandle(
    hObject: windows.HANDLE,
) callconv(.c) i32;

extern "kernel32" fn GetCurrentProcess() callconv(.c) windows.HANDLE;

pub const MappingInfo = struct {
    addr: usize,
    length: usize,
    prot: i32,
    flags: i32,
    fd: i32,
    offset: usize,
};

pub var manager: MmapManager = undefined;

pub const MmapManager = struct {
    allocator: std.mem.Allocator,
    mappings: std.AutoHashMap(usize, MappingInfo),
    brk_current: usize,
    brk_start: usize,

    pub fn init(allocator: std.mem.Allocator, initial_brk: usize) !void {
        manager = .{
            .allocator = allocator,
            .mappings = std.AutoHashMap(usize, MappingInfo).init(allocator),
            .brk_current = initial_brk,
            .brk_start = initial_brk,
        };
    }

    pub fn translateProtection(prot: i32) u32 {
        const r = (prot & PROT_READ) != 0;
        const w = (prot & PROT_WRITE) != 0;
        const x = (prot & PROT_EXEC) != 0;

        if (x) {
            if (w) return PAGE_EXECUTE_READWRITE;
            if (r) return PAGE_EXECUTE_READ;
            return PAGE_EXECUTE;
        } else {
            if (w) return PAGE_READWRITE;
            if (r) return PAGE_READONLY;
            return PAGE_NOACCESS;
        }
    }
};

pub fn sys_mmap(addr: usize, length: usize, prot: i32, flags: i32, fd: i32, offset: usize) syscall.SyscallResult {
    const win_prot = MmapManager.translateProtection(prot);

    var final_addr: usize = addr;

    if (flags & MAP_ANONYMOUS != 0) {
        const ptr = VirtualAlloc(
            if (addr != 0) @ptrFromInt(addr) else null,
            length,
            MEM_COMMIT | MEM_RESERVE,
            win_prot,
        ) orelse {
            return .{ .errno = 12 }; // ENOMEM
        };
        final_addr = @intFromPtr(ptr);
    } else {
        const file_handle: windows.HANDLE = @ptrFromInt(@as(usize, @intCast(fd)));

        var section_handle: windows.HANDLE = undefined;
        const status = NtCreateSection(
            &section_handle,
            SECTION_ALL_ACCESS,
            null,
            null,
            win_prot,
            SEC_COMMIT,
            file_handle,
        );

        if (status != STATUS_SUCCESS) {
            return .{ .errno = 22 }; // EINVAL
        }
        defer _ = CloseHandle(section_handle);

        var base: ?*anyopaque = if (addr != 0) @ptrFromInt(addr) else null;
        var view_size: usize = length;
        var offset_large: windows.LARGE_INTEGER = @bitCast(@as(u64, offset));

        const map_status = NtMapViewOfSection(
            section_handle,
            GetCurrentProcess(),
            &base,
            0,
            0,
            &offset_large,
            &view_size,
            ViewUnmap,
            0,
            win_prot,
        );

        if (map_status != STATUS_SUCCESS) {
            return .{ .errno = 12 }; // ENOMEM
        }
        final_addr = @intFromPtr(base);
    }

    manager.mappings.put(final_addr, .{
        .addr = final_addr,
        .length = length,
        .prot = prot,
        .flags = flags,
        .fd = fd,
        .offset = offset,
    }) catch return .{ .errno = 12 };

    return .{ .value = final_addr };
}

pub fn sys_munmap(addr: usize, length: usize) syscall.SyscallResult {
    _ = length;
    if (manager.mappings.get(addr)) |info| {
        if (info.flags & MAP_ANONYMOUS != 0) {
            if (VirtualFree(@ptrFromInt(info.addr), 0, MEM_RELEASE) == 0) {
                const status = NtUnmapViewOfSection(GetCurrentProcess(), @ptrFromInt(info.addr));
                if (status != STATUS_SUCCESS) {
                    return .{ .errno = 22 }; // EINVAL
                }
            }
        } else {
            const status = NtUnmapViewOfSection(GetCurrentProcess(), @ptrFromInt(info.addr));
            if (status != STATUS_SUCCESS) {
                return .{ .errno = 22 }; // EINVAL
            }
        }
        _ = manager.mappings.remove(addr);
        return .{ .value = 0 };
    }
    const status = NtUnmapViewOfSection(GetCurrentProcess(), @ptrFromInt(addr));
    if (status == STATUS_SUCCESS) return .{ .value = 0 };

    return .{ .errno = 22 }; // EINVAL
}

pub fn sys_mprotect(addr: usize, length: usize, prot: i32) syscall.SyscallResult {
    const win_prot = MmapManager.translateProtection(prot);
    var old_prot: u32 = undefined;

    if (VirtualProtect(@ptrFromInt(addr), length, win_prot, &old_prot) == 0) {
        return .{ .errno = 12 }; // ENOMEM
    }

    if (manager.mappings.getPtr(addr)) |info| {
        info.prot = prot;
    }

    return .{ .value = 0 };
}

pub fn sys_brk(brk: usize) syscall.SyscallResult {
    if (brk == 0 or brk < manager.brk_start) {
        return .{ .value = manager.brk_current };
    }

    if (brk > manager.brk_current) {
        const size_to_alloc = brk - manager.brk_current;
        const ptr = VirtualAlloc(
            @ptrFromInt(manager.brk_current),
            size_to_alloc,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) orelse {
            return .{ .value = manager.brk_current };
        };
        manager.brk_current = @intFromPtr(ptr) + size_to_alloc;
    } else if (brk < manager.brk_current) {
        manager.brk_current = brk;
    }

    return .{ .value = manager.brk_current };
}

test "Memory protection translation" {
    try std.testing.expectEqual(@as(u32, PAGE_NOACCESS), MmapManager.translateProtection(PROT_NONE));
    try std.testing.expectEqual(@as(u32, PAGE_READONLY), MmapManager.translateProtection(PROT_READ));
    try std.testing.expectEqual(@as(u32, PAGE_READWRITE), MmapManager.translateProtection(PROT_READ | PROT_WRITE));
    try std.testing.expectEqual(@as(u32, PAGE_EXECUTE_READ), MmapManager.translateProtection(PROT_READ | PROT_EXEC));
    try std.testing.expectEqual(@as(u32, PAGE_EXECUTE_READWRITE), MmapManager.translateProtection(PROT_READ | PROT_WRITE | PROT_EXEC));
}

test "MmapManager brk" {
    const allocator = std.testing.allocator;
    // Use a higher address that is less likely to be taken
    const base_addr: usize = 0x70000000;
    try MmapManager.init(allocator, base_addr);
    defer manager.mappings.deinit();

    // Initial brk
    var res = sys_brk(0);
    try std.testing.expectEqual(base_addr, res.value);

    // Increase brk
    const next_brk = base_addr + 0x1000;
    res = sys_brk(next_brk);
    // VirtualAlloc might not give us the exact address if it's already taken,
    // but in this high range it's likely it will.
    // If it fails, it returns the old brk.
    if (res.value == base_addr) {
        std.debug.print("TEA: Warning: VirtualAlloc failed in brk test at 0x{x}\n", .{base_addr});
    } else {
        try std.testing.expectEqual(next_brk, res.value);
        try std.testing.expect(manager.brk_current == next_brk);
    }

    // Decrease brk
    const lower_brk = base_addr + 0x500;
    res = sys_brk(lower_brk);
    try std.testing.expectEqual(lower_brk, res.value);
    try std.testing.expect(manager.brk_current == lower_brk);
}
