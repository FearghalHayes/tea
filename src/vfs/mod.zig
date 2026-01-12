const std = @import("std");
const windows = std.os.windows;
const proc = @import("proc.zig");

const WIN32_FILE_ATTRIBUTE_DATA = extern struct {
    dwFileAttributes: u32,
    ftCreationTime: windows.FILETIME,
    ftLastAccessTime: windows.FILETIME,
    ftLastWriteTime: windows.FILETIME,
    nFileSizeHigh: u32,
    nFileSizeLow: u32,
};

const BY_HANDLE_FILE_INFORMATION = extern struct {
    dwFileAttributes: u32,
    ftCreationTime: windows.FILETIME,
    ftLastAccessTime: windows.FILETIME,
    ftLastWriteTime: windows.FILETIME,
    dwVolumeSerialNumber: u32,
    nFileSizeHigh: u32,
    nFileSizeLow: u32,
    nNumberOfLinks: u32,
    nFileIndexHigh: u32,
    nFileIndexLow: u32,
};

const WIN32_FIND_DATAW = extern struct {
    dwFileAttributes: u32,
    ftCreationTime: windows.FILETIME,
    ftLastAccessTime: windows.FILETIME,
    ftLastWriteTime: windows.FILETIME,
    nFileSizeHigh: u32,
    nFileSizeLow: u32,
    dwReserved0: u32,
    dwReserved1: u32,
    cFileName: [260]u16,
    cAlternateFileName: [14]u16,
};

extern "kernel32" fn GetFileAttributesExW(
    lpFileName: windows.LPCWSTR,
    fInfoLevelId: u32,
    lpFileInformation: *WIN32_FILE_ATTRIBUTE_DATA,
) callconv(.c) windows.BOOL;

extern "kernel32" fn GetFileInformationByHandle(
    hFile: windows.HANDLE,
    lpFileInformation: *BY_HANDLE_FILE_INFORMATION,
) callconv(.c) windows.BOOL;

extern "kernel32" fn FindFirstFileW(
    lpFileName: windows.LPCWSTR,
    lpFindFileData: *WIN32_FIND_DATAW,
) callconv(.c) windows.HANDLE;

extern "kernel32" fn FindNextFileW(
    hFindFile: windows.HANDLE,
    lpFindFileData: *WIN32_FIND_DATAW,
) callconv(.c) windows.BOOL;

extern "kernel32" fn FindClose(
    hFindFile: windows.HANDLE,
) callconv(.c) windows.BOOL;

pub const Vfs = struct {
    allocator: std.mem.Allocator,
    mount_table: std.StringHashMap([]const u8),
    cwd: []const u8,

    pub fn init(allocator: std.mem.Allocator) !Vfs {
        var self = Vfs{
            .allocator = allocator,
            .mount_table = std.StringHashMap([]const u8).init(allocator),
            .cwd = try allocator.dupe(u8, "/"),
        };

        // Default mounts
        try self.mount_table.put("/", "C:\\");

        if (std.process.getEnvVarOwned(allocator, "USERPROFILE")) |path| {
            try self.mount_table.put("/home", path);
        } else |_| {
            // Fallback if USERPROFILE is not set
            try self.mount_table.put("/home", "C:\\Users");
        }

        return self;
    }

    pub fn deinit(self: *Vfs) void {
        var iter = self.mount_table.iterator();
        while (iter.next()) |entry| {
            if (std.mem.eql(u8, entry.key_ptr.*, "/home")) {
                self.allocator.free(entry.value_ptr.*);
            }
        }
        self.mount_table.deinit();
        self.allocator.free(self.cwd);
    }

    pub const PathResult = union(enum) {
        windows_path: []const u8,
        proc_file: proc.ProcFile,
        invalid,
    };

    pub fn translatePath(self: *Vfs, linux_path: []const u8) !PathResult {
        if (linux_path.len == 0) return .invalid;

        var full_path: []const u8 = undefined;
        var allocated_full_path = false;
        if (linux_path[0] == '/') {
            full_path = linux_path;
        } else {
            // Absolute path from relative
            if (std.mem.eql(u8, self.cwd, "/")) {
                full_path = try std.fmt.allocPrint(self.allocator, "/{s}", .{linux_path});
            } else {
                full_path = try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ self.cwd, linux_path });
            }
            allocated_full_path = true;
        }
        defer if (allocated_full_path) self.allocator.free(full_path);

        // Handle /proc
        if (std.mem.startsWith(u8, full_path, "/proc/")) {
            const sub = full_path["/proc/".len..];
            if (std.mem.eql(u8, sub, "self/maps") or std.mem.eql(u8, sub, "maps")) {
                return .{ .proc_file = .maps };
            } else if (std.mem.eql(u8, sub, "cpuinfo")) {
                return .{ .proc_file = .cpuinfo };
            } else if (std.mem.eql(u8, sub, "self/exe")) {
                return .{ .proc_file = .exe };
            } else if (std.mem.eql(u8, sub, "meminfo")) {
                return .{ .proc_file = .meminfo };
            }
        }

        // Longest prefix match for mount table
        var best_match_key: []const u8 = "";
        var best_match_val: []const u8 = "";

        var iter = self.mount_table.iterator();
        while (iter.next()) |entry| {
            if (std.mem.startsWith(u8, full_path, entry.key_ptr.*)) {
                if (entry.key_ptr.len > best_match_key.len) {
                    best_match_key = entry.key_ptr.*;
                    best_match_val = entry.value_ptr.*;
                }
            }
        }

        if (best_match_key.len > 0) {
            const remaining = full_path[best_match_key.len..];
            // Replace forward slashes with backslashes
            var win_path = try self.allocator.alloc(u8, best_match_val.len + remaining.len);
            @memcpy(win_path[0..best_match_val.len], best_match_val);
            var i: usize = 0;
            while (i < remaining.len) : (i += 1) {
                win_path[best_match_val.len + i] = if (remaining[i] == '/') '\\' else remaining[i];
            }
            return .{ .windows_path = win_path };
        }

        return .invalid;
    }
};

pub var vfs_instance: ?Vfs = null;
pub var fd_table: ?std.AutoHashMap(i32, FileDescriptor) = null;
var next_fd: i32 = 3; // 0, 1, 2 are stdin, stdout, stderr

pub const FileDescriptor = struct {
    inner: union(enum) {
        windows_handle: windows.HANDLE,
        proc_file: proc.ProcFile,
    },
    path: ?[]const u8 = null, // Linux path, stored for directories
    offset: u64 = 0,
};

pub fn initVfs(allocator: std.mem.Allocator) !void {
    vfs_instance = try Vfs.init(allocator);
    fd_table = std.AutoHashMap(i32, FileDescriptor).init(allocator);

    // Setup standard FDs
    try fd_table.?.put(0, .{ .inner = .{ .windows_handle = windows.GetStdHandle(windows.STD_INPUT_HANDLE) catch windows.INVALID_HANDLE_VALUE } });
    try fd_table.?.put(1, .{ .inner = .{ .windows_handle = windows.GetStdHandle(windows.STD_OUTPUT_HANDLE) catch windows.INVALID_HANDLE_VALUE } });
    try fd_table.?.put(2, .{ .inner = .{ .windows_handle = windows.GetStdHandle(windows.STD_ERROR_HANDLE) catch windows.INVALID_HANDLE_VALUE } });
}

pub fn sys_open(path_ptr: usize, flags: i32, mode: i32) !i32 {
    _ = mode;
    const path = std.mem.span(@as([*:0]const u8, @ptrFromInt(path_ptr)));

    if (vfs_instance) |*vfs| {
        const result = try vfs.translatePath(path);
        switch (result) {
            .windows_path => |win_path| {
                defer vfs.allocator.free(win_path);
                // Convert flags from Linux to Windows
                const access: u32 = if (flags & 3 == 0) windows.GENERIC_READ else if (flags & 3 == 1) windows.GENERIC_WRITE else windows.GENERIC_READ | windows.GENERIC_WRITE;

                const O_DIRECTORY = 0x10000;
                const O_CREAT = 0x40;
                const is_dir_requested = (flags & O_DIRECTORY != 0);

                const create_disposition: u32 = if (flags & O_CREAT != 0) windows.OPEN_ALWAYS else windows.OPEN_EXISTING;

                // Convert win_path to UTF-16
                var win_path_w: [260]u16 = undefined;
                const len = try std.unicode.utf8ToUtf16Le(&win_path_w, win_path);
                win_path_w[len] = 0;

                const handle = windows.kernel32.CreateFileW(
                    @as(windows.LPCWSTR, @ptrCast(&win_path_w)),
                    access,
                    windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE,
                    null,
                    create_disposition,
                    windows.FILE_ATTRIBUTE_NORMAL | 0x02000000, // Always use FILE_FLAG_BACKUP_SEMANTICS
                    null,
                );

                if (handle == windows.INVALID_HANDLE_VALUE) {
                    return error.FileNotFound;
                }

                // Check if it's actually a directory
                var info: BY_HANDLE_FILE_INFORMATION = undefined;
                if (GetFileInformationByHandle(handle, &info) != 0) {
                    const actual_is_dir = (info.dwFileAttributes & 0x10 != 0);
                    if (is_dir_requested and !actual_is_dir) {
                        _ = windows.CloseHandle(handle);
                        return error.NotADirectory;
                    }

                    const fd = next_fd;
                    next_fd += 1;
                    try fd_table.?.put(fd, .{
                        .inner = .{ .windows_handle = handle },
                        .path = if (actual_is_dir) try vfs.allocator.dupe(u8, path) else null,
                    });
                    return fd;
                } else {
                    _ = windows.CloseHandle(handle);
                    return error.ReadError;
                }
            },
            .proc_file => |pf| {
                const fd = next_fd;
                next_fd += 1;
                try fd_table.?.put(fd, .{ .inner = .{ .proc_file = pf } });
                return fd;
            },
            .invalid => return error.FileNotFound,
        }
    }
    return error.VfsNotInitialized;
}

pub fn sys_read(fd: i32, buf_ptr: usize, count: usize) !usize {
    const buf = @as([*]u8, @ptrFromInt(buf_ptr))[0..count];

    if (fd_table) |*table| {
        if (table.get(fd)) |file| {
            switch (file.inner) {
                .windows_handle => |handle| {
                    var bytes_read: u32 = 0;
                    if (windows.kernel32.ReadFile(handle, buf.ptr, @intCast(count), &bytes_read, null) == 0) {
                        return error.ReadError;
                    }
                    return bytes_read;
                },
                .proc_file => |pf| {
                    return try proc.read(pf, buf);
                },
            }
        }
    }
    return error.BadFileDescriptor;
}

pub fn sys_write(fd: i32, buf_ptr: usize, count: usize) !usize {
    const buf = @as([*]u8, @ptrFromInt(buf_ptr))[0..count];

    if (fd_table) |*table| {
        if (table.get(fd)) |file| {
            switch (file.inner) {
                .windows_handle => |handle| {
                    var bytes_written: u32 = 0;
                    if (windows.kernel32.WriteFile(handle, buf.ptr, @intCast(count), &bytes_written, null) == 0) {
                        const err = windows.kernel32.GetLastError();
                        if (err == .ACCESS_DENIED or err == .INVALID_HANDLE or err == .NO_DATA) {
                            return count; // Lie to Busybox
                        }
                        return error.WriteError;
                    }
                    return bytes_written;
                },
                .proc_file => return error.PermissionDenied,
            }
        }
    }
    return error.BadFileDescriptor;
}

pub fn sys_close(fd: i32) !void {
    if (fd_table) |*table| {
        if (table.fetchRemove(fd)) |entry| {
            if (entry.value.path) |p| {
                if (vfs_instance) |vfs| vfs.allocator.free(p);
            }
            switch (entry.value.inner) {
                .windows_handle => |handle| {
                    _ = windows.CloseHandle(handle);
                },
                .proc_file => {},
            }
        } else {
            return error.BadFileDescriptor;
        }
    } else {
        return error.VfsNotInitialized;
    }
}

pub const Dirent = extern struct {
    ino: u64,
    off: u64,
    reclen: u16,
    name: [256]u8,
};

pub const Dirent64 = extern struct {
    ino: u64,
    off: i64,
    reclen: u16,
    type: u8,
    name: [256]u8,
};

pub const Stat = extern struct {
    dev: u64,
    ino: u64,
    nlink: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    __pad0: u32,
    rdev: u64,
    size: i64,
    blksize: i64,
    blocks: i64,
    atime: i64,
    atime_nsec: i64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
    __unused: [3]i64,
};

pub fn sys_stat(path_ptr: usize, stat_ptr: usize) !void {
    const path = std.mem.span(@as([*:0]const u8, @ptrFromInt(path_ptr)));
    if (vfs_instance) |*vfs| {
        const result = try vfs.translatePath(path);
        switch (result) {
            .windows_path => |win_path| {
                defer vfs.allocator.free(win_path);
                var win_path_w: [260]u16 = undefined;
                const len = try std.unicode.utf8ToUtf16Le(&win_path_w, win_path);
                win_path_w[len] = 0;

                var data: WIN32_FILE_ATTRIBUTE_DATA = undefined;
                if (GetFileAttributesExW(@as(windows.LPCWSTR, @ptrCast(&win_path_w)), 0, &data) == 0) {
                    return error.FileNotFound;
                }

                var stat: Stat = undefined;
                @memset(std.mem.asBytes(&stat), 0);
                stat.size = @as(i64, @intCast(data.nFileSizeLow)) | (@as(i64, @intCast(data.nFileSizeHigh)) << 32);
                stat.mode = 0o100644;
                if (data.dwFileAttributes & 0x00000010 != 0) {
                    stat.mode = 0o040755;
                }
                stat.ino = 1;
                stat.nlink = 1;
                stat.uid = 1000;
                stat.gid = 1000;
                stat.blksize = 4096;
                stat.blocks = @divTrunc(stat.size + 511, 512);
                @memcpy(@as([*]u8, @ptrFromInt(stat_ptr))[0..@sizeOf(Stat)], std.mem.asBytes(&stat));
            },
            .proc_file => {
                var stat: Stat = undefined;
                @memset(std.mem.asBytes(&stat), 0);
                stat.mode = 0o100444;
                stat.size = 4096;
                stat.uid = 1000;
                stat.gid = 1000;
                @memcpy(@as([*]u8, @ptrFromInt(stat_ptr))[0..@sizeOf(Stat)], std.mem.asBytes(&stat));
            },
            .invalid => return error.FileNotFound,
        }
    }
}

pub fn sys_getdents(fd: i32, dirp_ptr: usize, count: usize) !usize {
    if (fd_table) |*table| {
        if (table.getPtr(fd)) |file| {
            if (file.path) |linux_path| {
                const dirp = @as([*]u8, @ptrFromInt(dirp_ptr))[0..count];
                var offset: usize = 0;

                if (vfs_instance) |*vfs| {
                    const res = try vfs.translatePath(linux_path);
                    switch (res) {
                        .windows_path => |win_path| {
                            defer vfs.allocator.free(win_path);
                            const search_path = try std.fmt.allocPrint(vfs.allocator, "{s}\\*", .{win_path});
                            defer vfs.allocator.free(search_path);

                            var search_path_w: [260]u16 = undefined;
                            const len = try std.unicode.utf8ToUtf16Le(&search_path_w, search_path);
                            search_path_w[len] = 0;

                            var find_data: WIN32_FIND_DATAW = undefined;
                            const hFind = FindFirstFileW(@ptrCast(&search_path_w), &find_data);
                            if (hFind == windows.INVALID_HANDLE_VALUE) return 0;
                            defer _ = FindClose(hFind);

                            var current_index: u64 = 0;
                            while (true) {
                                if (current_index >= file.offset) {
                                    var name_buf: [260]u8 = undefined;
                                    const name_len = try std.unicode.utf16LeToUtf8(&name_buf, std.mem.span(@as([*:0]u16, @ptrCast(&find_data.cFileName))));
                                    const name = name_buf[0..name_len];

                                    const reclen = std.mem.alignForward(usize, 18 + name.len + 1, 8);
                                    if (offset + reclen > count) break;

                                    const d = dirp[offset..];
                                    std.mem.writeInt(u64, d[0..8], current_index + 100, .little);
                                    std.mem.writeInt(u64, d[8..16], current_index + 1, .little);
                                    std.mem.writeInt(u16, d[16..18], @as(u16, @intCast(reclen)), .little);
                                    @memcpy(d[18 .. 18 + name.len], name);
                                    d[18 + name.len] = 0;
                                    d[offset + reclen - 1] = if (find_data.dwFileAttributes & 0x10 != 0) @as(u8, 4) else @as(u8, 8);

                                    offset += reclen;
                                    file.offset += 1;
                                }

                                if (FindNextFileW(hFind, &find_data) == 0) break;
                                current_index += 1;
                            }
                            return offset;
                        },
                        else => return 0,
                    }
                }
            }
        }
    }
    return error.BadFileDescriptor;
}

pub fn sys_getdents64(fd: i32, dirp_ptr: usize, count: usize) !usize {
    if (fd_table) |*table| {
        if (table.getPtr(fd)) |file| {
            if (file.path) |linux_path| {
                const dirp = @as([*]u8, @ptrFromInt(dirp_ptr))[0..count];
                var offset: usize = 0;

                if (vfs_instance) |*vfs| {
                    const res = try vfs.translatePath(linux_path);
                    switch (res) {
                        .windows_path => |win_path| {
                            defer vfs.allocator.free(win_path);
                            const search_path = try std.fmt.allocPrint(vfs.allocator, "{s}\\*", .{win_path});
                            defer vfs.allocator.free(search_path);

                            var search_path_w: [260]u16 = undefined;
                            const len = try std.unicode.utf8ToUtf16Le(&search_path_w, search_path);
                            search_path_w[len] = 0;

                            var find_data: WIN32_FIND_DATAW = undefined;
                            const hFind = FindFirstFileW(@ptrCast(&search_path_w), &find_data);
                            if (hFind == windows.INVALID_HANDLE_VALUE) return 0;
                            defer _ = FindClose(hFind);

                            var current_index: u64 = 0;
                            while (true) {
                                if (current_index >= file.offset) {
                                    var name_buf: [260]u8 = undefined;
                                    const name_len = try std.unicode.utf16LeToUtf8(&name_buf, std.mem.span(@as([*:0]u16, @ptrCast(&find_data.cFileName))));
                                    const name = name_buf[0..name_len];

                                    const reclen = std.mem.alignForward(usize, 19 + name.len + 1, 8);
                                    if (offset + reclen > count) break;

                                    const d = dirp[offset..];
                                    std.mem.writeInt(u64, d[0..8], current_index + 100, .little);
                                    std.mem.writeInt(u64, d[8..16], current_index + 1, .little);
                                    std.mem.writeInt(u16, d[16..18], @as(u16, @intCast(reclen)), .little);
                                    d[18] = if (find_data.dwFileAttributes & 0x10 != 0) @as(u8, 4) else @as(u8, 8);
                                    @memcpy(d[19 .. 19 + name.len], name);
                                    d[19 + name.len] = 0;

                                    offset += reclen;
                                    file.offset += 1;
                                }

                                if (FindNextFileW(hFind, &find_data) == 0) break;
                                current_index += 1;
                            }
                            return offset;
                        },
                        else => return 0,
                    }
                }
            }
        }
    }
    return error.BadFileDescriptor;
}

pub fn sys_lseek(fd: i32, offset: i64, whence: i32) !usize {
    if (fd_table) |*table| {
        if (table.get(fd)) |file| {
            switch (file.inner) {
                .windows_handle => |handle| {
                    const method: u32 = switch (whence) {
                        0 => windows.FILE_BEGIN,
                        1 => windows.FILE_CURRENT,
                        2 => windows.FILE_END,
                        else => return error.InvalidArgument,
                    };
                    var new_pos: windows.LARGE_INTEGER = undefined;
                    if (windows.kernel32.SetFilePointerEx(handle, @bitCast(offset), &new_pos, method) == 0) {
                        return error.LseekError;
                    }
                    return @as(usize, @bitCast(new_pos));
                },
                .proc_file => return 0,
            }
        }
    }
    return error.BadFileDescriptor;
}

pub fn sys_dup2(oldfd: i32, newfd: i32) !void {
    if (fd_table) |*table| {
        if (table.get(oldfd)) |file| {
            if (table.get(newfd)) |_| {
                try sys_close(newfd);
            }

            var new_file = file;
            switch (file.inner) {
                .windows_handle => |handle| {
                    var duplicated_handle: windows.HANDLE = undefined;
                    const current_process = windows.kernel32.GetCurrentProcess();
                    if (windows.kernel32.DuplicateHandle(
                        current_process,
                        handle,
                        current_process,
                        &duplicated_handle,
                        0,
                        windows.TRUE,
                        0x00000002, // DUPLICATE_SAME_ACCESS
                    ) == 0) {
                        return error.DuplicateHandleFailed;
                    }
                    new_file.inner = .{ .windows_handle = duplicated_handle };
                },
                .proc_file => {},
            }

            if (file.path) |p| {
                if (vfs_instance) |vfs| new_file.path = try vfs.allocator.dupe(u8, p);
            }
            try table.put(newfd, new_file);
            return;
        }
    }
    return error.BadFileDescriptor;
}

const Iovec = extern struct {
    base: usize,
    len: usize,
};

pub fn sys_writev(fd: i32, iov_ptr: usize, iovcnt: i32) !usize {
    if (fd_table) |*table| {
        if (table.get(fd)) |file| {
            switch (file.inner) {
                .windows_handle => |handle| {
                    const iovecs = @as([*]const Iovec, @ptrFromInt(iov_ptr))[0..@intCast(iovcnt)];
                    var total_written: usize = 0;
                    for (iovecs) |iov| {
                        var bytes_written: u32 = 0;
                        if (windows.kernel32.WriteFile(handle, @as([*]const u8, @ptrFromInt(iov.base)), @intCast(iov.len), &bytes_written, null) == 0) {
                            if (total_written > 0) return total_written;
                            return error.WriteError;
                        }
                        total_written += bytes_written;
                        if (bytes_written < iov.len) break;
                    }
                    return total_written;
                },
                .proc_file => return error.PermissionDenied,
            }
        }
    }
    return error.BadFileDescriptor;
}

pub fn sys_fstatfs(fd: i32, buf_ptr: usize) !void {
    _ = fd;
    _ = buf_ptr;
}

pub fn sys_fstat(fd: i32, stat_ptr: usize) !void {
    if (fd_table) |*table| {
        if (table.get(fd)) |file| {
            switch (file.inner) {
                .windows_handle => |handle| {
                    var info: BY_HANDLE_FILE_INFORMATION = undefined;
                    if (GetFileInformationByHandle(handle, &info) == 0) {
                        return error.ReadError;
                    }

                    var stat: Stat = undefined;
                    @memset(std.mem.asBytes(&stat), 0);
                    stat.size = @as(i64, @intCast(info.nFileSizeLow)) | (@as(i64, @intCast(info.nFileSizeHigh)) << 32);
                    stat.mode = 0o100644;
                    if (info.dwFileAttributes & 0x10 != 0) stat.mode = 0o040755;
                    stat.uid = 1000;
                    stat.gid = 1000;
                    stat.ino = (@as(u64, info.nFileIndexHigh) << 32) | info.nFileIndexLow;
                    stat.nlink = info.nNumberOfLinks;
                    stat.blksize = 4096;
                    stat.blocks = @divTrunc(stat.size + 511, 512);
                    @memcpy(@as([*]u8, @ptrFromInt(stat_ptr))[0..@sizeOf(Stat)], std.mem.asBytes(&stat));
                },
                .proc_file => {
                    var stat: Stat = undefined;
                    @memset(std.mem.asBytes(&stat), 0);
                    stat.mode = 0o100444;
                    stat.size = 4096;
                    @memcpy(@as([*]u8, @ptrFromInt(stat_ptr))[0..@sizeOf(Stat)], std.mem.asBytes(&stat));
                },
            }
            return;
        }
    }
    return error.BadFileDescriptor;
}

pub fn sys_getcwd(buf_ptr: usize, size: usize) !usize {
    if (vfs_instance) |vfs| {
        if (vfs.cwd.len + 1 > size) return error.NameTooLong;
        @memcpy(@as([*]u8, @ptrFromInt(buf_ptr))[0..vfs.cwd.len], vfs.cwd);
        @as([*]u8, @ptrFromInt(buf_ptr))[vfs.cwd.len] = 0;
        return vfs.cwd.len + 1;
    }
    return error.VfsNotInitialized;
}
