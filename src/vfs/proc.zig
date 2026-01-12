const std = @import("std");
const windows = std.os.windows;

pub const ProcFile = enum {
    maps,
    cpuinfo,
    exe,
    meminfo,
};

pub fn read(file: ProcFile, buf: []u8) !usize {
    return switch (file) {
        .maps => try generateMapsFile(buf),
        .cpuinfo => try generateCpuInfo(buf),
        .exe => try getExecutablePath(buf),
        .meminfo => try generateMemInfo(buf),
    };
}

fn generateMapsFile(buf: []u8) !usize {
    var stream = std.io.fixedBufferStream(buf);
    const writer = stream.writer();

    var addr: usize = 0;
    // Walk through the address space
    while (addr < 0x7FFFFFFFFFFF) {
        var mbi: windows.MEMORY_BASIC_INFORMATION = undefined;
        const result = windows.kernel32.VirtualQuery(@ptrFromInt(addr), &mbi, @sizeOf(windows.MEMORY_BASIC_INFORMATION));

        if (result == 0) break;

        if (mbi.State == windows.MEM_COMMIT) {
            const prot = formatProtection(mbi.Protect);
            try writer.print("{x:0>12}-{x:0>12} {s} {x:0>8} 00:00 0", .{
                @intFromPtr(mbi.BaseAddress),
                @intFromPtr(mbi.BaseAddress) + mbi.RegionSize,
                prot,
                0, // offset
            });

            // Add basic names for common regions
            const start = @intFromPtr(mbi.BaseAddress);
            if (start >= 0x400000 and start < 0x800000) {
                try writer.print(" [exe]", .{});
            } else if (start >= 0x7FFFF0000000) {
                try writer.print(" [stack]", .{});
            }

            try writer.writeByte('\n');
        }

        addr = @intFromPtr(mbi.BaseAddress) + mbi.RegionSize;
    }

    return stream.pos;
}

fn formatProtection(protect: u32) [4]u8 {
    var res = [_]u8{ '-', '-', '-', 'p' };
    if (protect & (windows.PAGE_READONLY | windows.PAGE_READWRITE | windows.PAGE_EXECUTE_READ | windows.PAGE_EXECUTE_READWRITE) != 0) res[0] = 'r';
    if (protect & (windows.PAGE_READWRITE | windows.PAGE_EXECUTE_READWRITE | windows.PAGE_WRITECOPY | windows.PAGE_EXECUTE_WRITECOPY) != 0) res[1] = 'w';
    if (protect & (windows.PAGE_EXECUTE | windows.PAGE_EXECUTE_READ | windows.PAGE_EXECUTE_READWRITE | windows.PAGE_EXECUTE_WRITECOPY) != 0) res[2] = 'x';
    return res;
}

fn generateCpuInfo(buf: []u8) !usize {
    const content =
        \\processor       : 0
        \\vendor_id       : GenuineIntel
        \\cpu family      : 6
        \\model           : 158
        \\model name      : Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz
        \\stepping        : 10
        \\cpu MHz         : 2208.000
        \\cache size      : 9216 KB
        \\
    ;
    const len = @min(buf.len, content.len);
    @memcpy(buf[0..len], content[0..len]);
    return len;
}

pub var guest_exe_path: []const u8 = "";

fn getExecutablePath(buf: []u8) !usize {
    if (guest_exe_path.len > 0) {
        const len = @min(buf.len, guest_exe_path.len);
        @memcpy(buf[0..len], guest_exe_path[0..len]);
        return len;
    }

    var wbuf: [260]u16 = undefined;
    const len = windows.kernel32.GetModuleFileNameW(null, &wbuf, wbuf.len);
    if (len == 0) return error.Unexpected;

    // Convert UTF-16 to UTF-8
    const utf8_len = try std.unicode.utf16LeToUtf8(buf, wbuf[0..len]);
    return utf8_len;
}

fn generateMemInfo(buf: []u8) !usize {
    const content =
        \\MemTotal:        16384000 kB
        \\MemFree:          8192000 kB
        \\MemAvailable:     8192000 kB
        \\
    ;
    const len = @min(buf.len, content.len);
    @memcpy(buf[0..len], content[0..len]);
    return len;
}
