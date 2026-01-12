const std = @import("std");
const windows = std.os.windows;
const signal = @import("signal.zig");
const thread = @import("thread.zig");

// Windows definitions
const EXCEPTION_ACCESS_VIOLATION = 0xC0000005;
const EXCEPTION_ILLEGAL_INSTRUCTION = 0xC000001D;
const EXCEPTION_CONTINUE_EXECUTION = -1;
const EXCEPTION_CONTINUE_SEARCH = 0;

const PVECTORED_EXCEPTION_HANDLER = *const fn (ExceptionInfo: *EXCEPTION_POINTERS) callconv(.c) i32;

const MEMORY_BASIC_INFORMATION = extern struct {
    BaseAddress: ?*anyopaque,
    AllocationBase: ?*anyopaque,
    AllocationProtect: u32,
    PartitionId: u16,
    RegionSize: usize,
    State: u32,
    Protect: u32,
    Type: u32,
};

const PAGE_NOACCESS = 0x01;
const PAGE_READONLY = 0x02;
const PAGE_READWRITE = 0x04;
const PAGE_WRITECOPY = 0x08;
const PAGE_EXECUTE = 0x10;
const PAGE_EXECUTE_READ = 0x20;
const PAGE_EXECUTE_READWRITE = 0x40;
const PAGE_EXECUTE_WRITECOPY = 0x80;
const MEM_COMMIT = 0x1000;

extern "kernel32" fn VirtualQuery(
    lpAddress: ?*const anyopaque,
    lpBuffer: *MEMORY_BASIC_INFORMATION,
    dwLength: usize,
) usize;

const EXCEPTION_RECORD = extern struct {
    ExceptionCode: u32,
    ExceptionFlags: u32,
    ExceptionRecord: ?*EXCEPTION_RECORD,
    ExceptionAddress: ?*anyopaque,
    NumberParameters: u32,
    ExceptionInformation: [15]usize,
};

const EXCEPTION_POINTERS = extern struct {
    ExceptionRecord: *EXCEPTION_RECORD,
    ContextRecord: *windows.CONTEXT,
};

extern "kernel32" fn AddVectoredExceptionHandler(
    First: u32,
    Handler: PVECTORED_EXCEPTION_HANDLER,
) ?*anyopaque;

pub const SyscallResult = struct {
    value: usize = 0,
    errno: i32 = 0,
};

pub const SyscallContext = extern struct {
    // Platform specific registers
    rax: usize,
    rdi: usize,
    rsi: usize,
    rdx: usize,
    r10: usize,
    r8: usize,
    r9: usize,
};

pub const signal_frame = extern struct {
    pretcode: usize,
    info: signal.siginfo_t,
    uc_context: [1024]u8, // Placeholder for ucontext_t
};

pub fn init() !void {
    if (AddVectoredExceptionHandler(1, vehHandler)) |_| {
        std.debug.print("TEA: Initializing Syscall Interception (VEH)... OK\n", .{});
    } else {
        return error.VehRegistrationFailed;
    }
}

fn vehHandler(info: *EXCEPTION_POINTERS) callconv(.c) i32 {
    const record = info.ExceptionRecord;
    const context = info.ContextRecord;

    const is_patched_syscall = if (record.ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) blk: {
        var mbi: MEMORY_BASIC_INFORMATION = undefined;
        if (VirtualQuery(@ptrFromInt(context.Rip), &mbi, @sizeOf(MEMORY_BASIC_INFORMATION)) != 0) {
            if (mbi.State == MEM_COMMIT and (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0) {
                const rip: [*]u8 = @ptrFromInt(context.Rip);
                // We expect ud2 (0x0F 0x0B) which we use to replace syscall (0x0F 0x05)
                break :blk (rip[0] == 0x0F and rip[1] == 0x0B);
            }
        }
        break :blk false;
    } else false;

    if (record.ExceptionCode != 0x406D1388 and !is_patched_syscall) { // Ignore thread name and handled syscalls
        var fs_base: usize = 0;
        asm volatile ("rdfsbase %[fs]"
            : [fs] "=r" (fs_base),
        );
        std.debug.print("TEA: Exception 0x{x} at RIP=0x{x}, Addr=0x{x}, FS_BASE=0x{x}\n", .{ record.ExceptionCode, info.ContextRecord.Rip, record.ExceptionInformation[1], fs_base });
    }

    const thread_ctx = thread.getCurrentThreadContext() orelse return EXCEPTION_CONTINUE_SEARCH;

    if (record.ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION) {
        // Check if this is the initial jump to guest
        if (thread_ctx.initial_entry != 0) {
            const entry = thread_ctx.initial_entry;
            const stack = thread_ctx.initial_stack;
            thread_ctx.initial_entry = 0; // Only once

            context.Rip = entry;
            context.Rsp = stack;
            // Clear registers for guest
            context.Rax = 0;
            context.Rbx = 0;
            context.Rcx = 0;
            context.Rdx = 0;
            context.Rsi = 0;
            context.Rdi = 0;
            context.Rbp = 0;
            context.R8 = 0;
            context.R9 = 0;
            context.R10 = 0;
            context.R11 = 0;
            context.R12 = 0;
            context.R13 = 0;
            context.R14 = 0;
            context.R15 = 0;
            // Ensure flags are sane (especially DF=0)
            context.EFlags = 0x202;

            if (thread_ctx.fs_base != 0) {
                asm volatile ("wrfsbase %[addr]"
                    :
                    : [addr] "r" (thread_ctx.fs_base),
                );
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        }

        if (is_patched_syscall) {
            var ctx = SyscallContext{
                .rax = context.Rax,
                .rdi = context.Rdi,
                .rsi = context.Rsi,
                .rdx = context.Rdx,
                .r10 = context.R10,
                .r8 = context.R8,
                .r9 = context.R9,
            };

            const res = dispatch(&ctx);

            if (res.errno != 0) {
                const neg_errno = -@as(i64, res.errno);
                context.Rax = @bitCast(neg_errno);
            } else {
                context.Rax = res.value;
            }
            context.Rip += 2; // Move past ud2

            if (thread_ctx.fs_base != 0) {
                asm volatile ("wrfsbase %[addr]"
                    :
                    : [addr] "r" (thread_ctx.fs_base),
                );
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    // Handle signals
    if (signal.translateException(record.ExceptionCode)) |sig| {
        const sa = thread_ctx.signal_handlers[sig];
        if (sa.handler != 0 and sa.handler != 1) { // Not SIG_DFL (0) or SIG_IGN (1)
            std.debug.print("TEA: Redirecting to signal handler for signal {d} at 0x{x}\n", .{ sig, sa.handler });

            // Basic stack frame setup
            // Linux x86_64: handler(sig, siginfo, ucontext)
            // For now, we only support basic handler call.

            // Align stack
            var rsp = context.Rsp;
            rsp -= 128; // Red zone

            // The alignment should be (RSP - sizeof(signal_frame)) & ~0xF
            rsp -= @sizeOf(signal_frame);
            rsp &= ~@as(u64, 15);

            // Set up registers for the call
            context.Rdi = sig;
            context.Rsi = 0; // siginfo placeholder
            context.Rdx = 0; // ucontext placeholder

            // Set return address to restorer if provided
            if (sa.restorer != 0) {
                var mbi: MEMORY_BASIC_INFORMATION = undefined;
                if (VirtualQuery(@ptrFromInt(rsp), &mbi, @sizeOf(MEMORY_BASIC_INFORMATION)) != 0) {
                    if (mbi.State == MEM_COMMIT and (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)) != 0) {
                        const stack: *u64 = @ptrFromInt(rsp);
                        stack.* = sa.restorer;
                    }
                }
            }

            context.Rip = sa.handler;
            context.Rsp = rsp;

            if (thread_ctx.fs_base != 0) {
                asm volatile ("wrfsbase %[addr]"
                    :
                    : [addr] "r" (thread_ctx.fs_base),
                );
            }

            return EXCEPTION_CONTINUE_EXECUTION;
        } else if (sa.handler == 1) { // SIG_IGN
            if (thread_ctx.fs_base != 0) {
                asm volatile ("wrfsbase %[addr]"
                    :
                    : [addr] "r" (thread_ctx.fs_base),
                );
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

const SyscallHandler = *const fn (*SyscallContext) SyscallResult;

fn wrap_sys_read(ctx: *SyscallContext) SyscallResult {
    return sys_read(ctx.rdi, ctx.rsi, ctx.rdx);
}
fn wrap_sys_write(ctx: *SyscallContext) SyscallResult {
    return sys_write(ctx.rdi, ctx.rsi, ctx.rdx);
}
fn wrap_sys_open(ctx: *SyscallContext) SyscallResult {
    return sys_open(ctx.rdi, @bitCast(@as(u32, @truncate(ctx.rsi))), @bitCast(@as(u32, @truncate(ctx.rdx))));
}
fn wrap_sys_close(ctx: *SyscallContext) SyscallResult {
    return sys_close(ctx.rdi);
}
fn wrap_sys_mmap(ctx: *SyscallContext) SyscallResult {
    const memory = @import("memory.zig");
    return memory.sys_mmap(ctx.rdi, ctx.rsi, @bitCast(@as(u32, @truncate(ctx.rdx))), @bitCast(@as(u32, @truncate(ctx.r10))), @bitCast(@as(u32, @truncate(ctx.r8))), ctx.r9);
}
fn wrap_sys_mprotect(ctx: *SyscallContext) SyscallResult {
    const memory = @import("memory.zig");
    return memory.sys_mprotect(ctx.rdi, ctx.rsi, @bitCast(@as(u32, @truncate(ctx.rdx))));
}
fn wrap_sys_munmap(ctx: *SyscallContext) SyscallResult {
    const memory = @import("memory.zig");
    return memory.sys_munmap(ctx.rdi, ctx.rsi);
}
fn wrap_sys_brk(ctx: *SyscallContext) SyscallResult {
    const memory = @import("memory.zig");
    return memory.sys_brk(ctx.rdi);
}
fn wrap_sys_rt_sigaction(ctx: *SyscallContext) SyscallResult {
    return signal.sys_rt_sigaction(ctx.rdi, ctx.rsi, ctx.rdx, ctx.r10);
}
fn wrap_sys_rt_sigprocmask(ctx: *SyscallContext) SyscallResult {
    return signal.sys_rt_sigprocmask(ctx.rdi, ctx.rsi, ctx.rdx, ctx.r10);
}
fn wrap_sys_clone(ctx: *SyscallContext) SyscallResult {
    return thread.sys_clone(ctx.rdi, ctx.rsi, ctx.rdx, ctx.r10, ctx.r8, ctx);
}
fn wrap_sys_gettid(ctx: *SyscallContext) SyscallResult {
    _ = ctx;
    return thread.sys_gettid();
}
fn wrap_sys_futex(ctx: *SyscallContext) SyscallResult {
    return thread.sys_futex(ctx.rdi, @bitCast(@as(u32, @truncate(ctx.rsi))), @bitCast(@as(u32, @truncate(ctx.rdx))), ctx.r10, ctx.r8, @bitCast(@as(u32, @truncate(ctx.r9))));
}
fn wrap_sys_set_tid_address(ctx: *SyscallContext) SyscallResult {
    return thread.sys_set_tid_address(ctx.rdi);
}
fn wrap_sys_arch_prctl(ctx: *SyscallContext) SyscallResult {
    return thread.sys_arch_prctl(@as(i32, @bitCast(@as(u32, @truncate(ctx.rdi)))), ctx.rsi);
}
fn wrap_sys_exit(ctx: *SyscallContext) SyscallResult {
    sys_exit(ctx.rdi);
}
fn wrap_sys_uname(ctx: *SyscallContext) SyscallResult {
    return sys_uname(ctx.rdi);
}
fn wrap_sys_getpid(ctx: *SyscallContext) SyscallResult {
    _ = ctx;
    return sys_getpid();
}
fn wrap_sys_getppid(ctx: *SyscallContext) SyscallResult {
    _ = ctx;
    return sys_getppid();
}
fn wrap_sys_getuid(ctx: *SyscallContext) SyscallResult {
    _ = ctx;
    return sys_getuid();
}
fn wrap_sys_getgid(ctx: *SyscallContext) SyscallResult {
    _ = ctx;
    return sys_getgid();
}
fn wrap_sys_setuid(ctx: *SyscallContext) SyscallResult {
    _ = ctx;
    return .{ .value = 0 };
}
fn wrap_sys_setgid(ctx: *SyscallContext) SyscallResult {
    _ = ctx;
    return .{ .value = 0 };
}
fn wrap_sys_geteuid(ctx: *SyscallContext) SyscallResult {
    _ = ctx;
    return sys_geteuid();
}
fn wrap_sys_getegid(ctx: *SyscallContext) SyscallResult {
    _ = ctx;
    return sys_getegid();
}
fn wrap_sys_getresuid(ctx: *SyscallContext) SyscallResult {
    if (ctx.rdi != 0) {
        std.mem.writeInt(u32, @as(*[4]u8, @ptrFromInt(ctx.rdi)), 1000, .little);
    }
    if (ctx.rsi != 0) {
        std.mem.writeInt(u32, @as(*[4]u8, @ptrFromInt(ctx.rsi)), 1000, .little);
    }
    if (ctx.rdx != 0) {
        std.mem.writeInt(u32, @as(*[4]u8, @ptrFromInt(ctx.rdx)), 1000, .little);
    }
    return .{ .value = 0 };
}
fn wrap_sys_getresgid(ctx: *SyscallContext) SyscallResult {
    if (ctx.rdi != 0) {
        std.mem.writeInt(u32, @as(*[4]u8, @ptrFromInt(ctx.rdi)), 1000, .little);
    }
    if (ctx.rsi != 0) {
        std.mem.writeInt(u32, @as(*[4]u8, @ptrFromInt(ctx.rsi)), 1000, .little);
    }
    if (ctx.rdx != 0) {
        std.mem.writeInt(u32, @as(*[4]u8, @ptrFromInt(ctx.rdx)), 1000, .little);
    }
    return .{ .value = 0 };
}
fn wrap_sys_lseek(ctx: *SyscallContext) SyscallResult {
    const vfs = @import("../vfs/mod.zig");
    const res = vfs.sys_lseek(@as(i32, @bitCast(@as(u32, @truncate(ctx.rdi)))), @as(i64, @bitCast(ctx.rsi)), @as(i32, @bitCast(@as(u32, @truncate(ctx.rdx))))) catch |err| {
        std.debug.print("TEA: sys_lseek failed: {any}\n", .{err});
        return .{ .errno = 9 }; // EBADF
    };
    return .{ .value = res };
}
fn wrap_sys_sendto(ctx: *SyscallContext) SyscallResult {
    return .{ .value = ctx.rdx };
}
fn wrap_sys_writev(ctx: *SyscallContext) SyscallResult {
    const vfs = @import("../vfs/mod.zig");
    const bytes_written = vfs.sys_writev(@as(i32, @bitCast(@as(u32, @truncate(ctx.rdi)))), ctx.rsi, @as(i32, @bitCast(@as(u32, @truncate(ctx.rdx))))) catch |err| {
        std.debug.print("TEA: sys_writev failed: {any}\n", .{err});
        return .{ .errno = 9 }; // EBADF
    };
    return .{ .value = bytes_written };
}
fn wrap_sys_ioctl(ctx: *SyscallContext) SyscallResult {
    return sys_ioctl(ctx.rdi, ctx.rsi, ctx.rdx);
}
fn wrap_sys_fstatfs(ctx: *SyscallContext) SyscallResult {
    const vfs = @import("../vfs/mod.zig");
    vfs.sys_fstatfs(@as(i32, @bitCast(@as(u32, @truncate(ctx.rdi)))), ctx.rsi) catch |err| {
        std.debug.print("TEA: sys_fstatfs failed: {any}\n", .{err});
        return .{ .errno = 9 }; // EBADF
    };
    return .{ .value = 0 };
}
fn wrap_sys_fcntl(ctx: *SyscallContext) SyscallResult {
    return sys_fcntl(ctx.rdi, ctx.rsi, ctx.rdx);
}
fn wrap_sys_getdents64(ctx: *SyscallContext) SyscallResult {
    return sys_getdents64(ctx.rdi, ctx.rsi, ctx.rdx);
}
fn wrap_sys_stat(ctx: *SyscallContext) SyscallResult {
    return sys_stat(ctx.rdi, ctx.rsi);
}
fn wrap_sys_fstat(ctx: *SyscallContext) SyscallResult {
    return sys_fstat(ctx.rdi, ctx.rsi);
}
fn wrap_sys_lstat(ctx: *SyscallContext) SyscallResult {
    return sys_lstat(ctx.rdi, ctx.rsi);
}
fn wrap_sys_access(ctx: *SyscallContext) SyscallResult {
    _ = ctx;
    return .{ .value = 0 }; // Stub: always success
}
fn wrap_sys_dup2(ctx: *SyscallContext) SyscallResult {
    return sys_dup2(ctx.rdi, ctx.rsi);
}
fn wrap_sys_exit_group(ctx: *SyscallContext) SyscallResult {
    sys_exit(ctx.rdi);
}
fn wrap_sys_getdents(ctx: *SyscallContext) SyscallResult {
    return sys_getdents(ctx.rdi, ctx.rsi, ctx.rdx);
}
fn wrap_sys_getcwd(ctx: *SyscallContext) SyscallResult {
    const vfs = @import("../vfs/mod.zig");
    const res = vfs.sys_getcwd(ctx.rdi, ctx.rsi) catch |err| {
        std.debug.print("TEA: sys_getcwd failed: {any}\n", .{err});
        return .{ .errno = 34 }; // ERANGE
    };
    return .{ .value = res };
}
fn wrap_sys_clock_gettime(ctx: *SyscallContext) SyscallResult {
    if (ctx.rsi != 0) {
        const now = std.time.nanoTimestamp();
        const sec: i64 = @intCast(@divTrunc(now, std.time.ns_per_s));
        const nsec: i64 = @intCast(@rem(now, std.time.ns_per_s));
        std.mem.writeInt(i64, @as(*[8]u8, @ptrFromInt(ctx.rsi)), sec, .little);
        std.mem.writeInt(i64, @as(*[8]u8, @ptrFromInt(ctx.rsi + 8)), nsec, .little);
    }
    return .{ .value = 0 };
}

const syscall_table = blk: {
    var table = [_]?SyscallHandler{null} ** 512;
    table[0] = wrap_sys_read;
    table[1] = wrap_sys_write;
    table[2] = wrap_sys_open;
    table[2] = wrap_sys_open;
    table[3] = wrap_sys_close;
    table[4] = wrap_sys_stat;
    table[5] = wrap_sys_fstat;
    table[6] = wrap_sys_lstat;
    table[8] = wrap_sys_lseek;
    table[9] = wrap_sys_mmap;
    table[10] = wrap_sys_mprotect;
    table[11] = wrap_sys_munmap;
    table[12] = wrap_sys_brk;
    table[13] = wrap_sys_rt_sigaction;
    table[14] = wrap_sys_rt_sigprocmask;
    table[16] = wrap_sys_ioctl;
    table[20] = wrap_sys_writev;
    table[21] = wrap_sys_access;
    table[33] = wrap_sys_dup2;
    table[39] = wrap_sys_getpid;
    table[44] = wrap_sys_sendto;
    table[56] = wrap_sys_clone;
    table[60] = wrap_sys_exit;
    table[63] = wrap_sys_uname;
    table[72] = wrap_sys_fcntl;
    table[78] = wrap_sys_getdents;
    table[79] = wrap_sys_getcwd;
    table[102] = wrap_sys_getuid;
    table[104] = wrap_sys_getgid;
    table[105] = wrap_sys_setuid;
    table[106] = wrap_sys_setgid;
    table[107] = wrap_sys_geteuid;
    table[108] = wrap_sys_getegid;
    table[117] = wrap_sys_getresuid;
    table[119] = wrap_sys_getresgid;
    table[158] = wrap_sys_arch_prctl;
    table[186] = wrap_sys_gettid;
    table[202] = wrap_sys_futex;
    table[217] = wrap_sys_getdents64;
    table[218] = wrap_sys_set_tid_address;
    table[228] = wrap_sys_clock_gettime;
    table[262] = wrap_sys_fstatfs;
    table[231] = wrap_sys_exit_group;
    break :blk table;
};

pub fn dispatch(ctx: *SyscallContext) SyscallResult {
    if (ctx.rax < syscall_table.len) {
        if (syscall_table[ctx.rax]) |handler| {
            std.debug.print("TEA: Syscall {d} (RAX: 0x{x}, RDI: 0x{x}, RSI: 0x{x}, RDX: 0x{x}, R10: 0x{x})\n", .{ ctx.rax, ctx.rax, ctx.rdi, ctx.rsi, ctx.rdx, ctx.r10 });
            const res = handler(ctx);
            std.debug.print("TEA: Syscall {d} returns 0x{x} (errno {d})\n", .{ ctx.rax, res.value, res.errno });
            return res;
        }
    }
    std.debug.print("TEA: Unhandled syscall {d} (RDI: 0x{x}, RSI: 0x{x}, RDX: 0x{x}, R10: 0x{x}, R8: 0x{x}, R9: 0x{x})\n", .{
        ctx.rax, ctx.rdi, ctx.rsi, ctx.rdx, ctx.r10, ctx.r8, ctx.r9,
    });
    return .{ .errno = 38 }; // ENOSYS
}

fn sys_getdents64(fd: usize, dirp: usize, count: usize) SyscallResult {
    const vfs = @import("../vfs/mod.zig");
    const res = vfs.sys_getdents64(@as(i32, @bitCast(@as(u32, @truncate(fd)))), dirp, count) catch |err| {
        std.debug.print("TEA: sys_getdents64(fd={d}) failed: {any}\n", .{ @as(i32, @bitCast(@as(u32, @truncate(fd)))), err });
        return .{ .errno = 9 }; // EBADF
    };
    return .{ .value = res };
}

fn sys_open(path_ptr: usize, flags: i32, mode: i32) SyscallResult {
    const vfs = @import("../vfs/mod.zig");
    const fd = vfs.sys_open(path_ptr, flags, mode) catch |err| {
        std.debug.print("TEA: sys_open failed: {any}\n", .{err});
        if (err == error.FileNotFound) return .{ .errno = 2 };
        return .{ .errno = 13 }; // EACCES or other
    };
    return .{ .value = @intCast(fd) };
}

fn sys_read(fd: usize, buf: usize, count: usize) SyscallResult {
    const vfs = @import("../vfs/mod.zig");
    const bytes_read = vfs.sys_read(@as(i32, @bitCast(@as(u32, @truncate(fd)))), buf, count) catch |err| {
        std.debug.print("TEA: sys_read failed: {any}\n", .{err});
        return .{ .errno = 9 }; // EBADF
    };
    return .{ .value = bytes_read };
}

fn sys_write(fd: usize, buf: usize, count: usize) SyscallResult {
    const vfs = @import("../vfs/mod.zig");
    const bytes_written = vfs.sys_write(@as(i32, @bitCast(@as(u32, @truncate(fd)))), buf, count) catch |err| {
        std.debug.print("TEA: sys_write failed: {any}\n", .{err});
        return .{ .errno = 9 }; // EBADF
    };
    return .{ .value = bytes_written };
}

fn sys_close(fd: usize) SyscallResult {
    const vfs = @import("../vfs/mod.zig");
    vfs.sys_close(@as(i32, @bitCast(@as(u32, @truncate(fd))))) catch |err| {
        std.debug.print("TEA: sys_close failed: {any}\n", .{err});
        return .{ .errno = 9 }; // EBADF
    };
    return .{ .value = 0 };
}

fn sys_exit(code: usize) noreturn {
    windows.kernel32.ExitProcess(@as(u32, @truncate(code)));
}

fn sys_uname(buf: usize) SyscallResult {
    const utsname = @as([*]u8, @ptrFromInt(buf));
    @memset(utsname[0 .. 65 * 6], 0);
    @memcpy(utsname[0..5], "Linux");
    @memcpy(utsname[65..74], "tea-guest");
    @memcpy(utsname[130..136], "5.15.0");
    const version = "#1 SMP TEA-RT 2026";
    @memcpy(utsname[195 .. 195 + version.len], version);
    @memcpy(utsname[260..266], "x86_64");
    return .{ .value = 0 };
}

fn sys_getpid() SyscallResult {
    return .{ .value = 1000 };
}
fn sys_getppid() SyscallResult {
    return .{ .value = 999 };
}
fn sys_getuid() SyscallResult {
    return .{ .value = 0 };
}
fn sys_getgid() SyscallResult {
    return .{ .value = 0 };
}
fn sys_geteuid() SyscallResult {
    return .{ .value = 0 };
}
fn sys_getegid() SyscallResult {
    return .{ .value = 0 };
}

fn sys_ioctl(fd: usize, request: usize, arg: usize) SyscallResult {
    _ = fd;
    // Stub for TIOCGWINSZ
    if (request == 0x5413) {
        if (arg != 0) {
            std.mem.writeInt(u16, @as(*[2]u8, @ptrFromInt(arg)), 24, .little);
            std.mem.writeInt(u16, @as(*[2]u8, @ptrFromInt(arg + 2)), 80, .little);
        }
        return .{ .value = 0 };
    }
    return .{ .value = 0 };
}

fn sys_fcntl(fd: usize, cmd: usize, arg: usize) SyscallResult {
    _ = fd;
    _ = cmd;
    _ = arg;
    return .{ .value = 0 };
}

fn sys_stat(path_ptr: usize, stat_ptr: usize) SyscallResult {
    const vfs = @import("../vfs/mod.zig");
    vfs.sys_stat(path_ptr, stat_ptr) catch return .{ .errno = 2 }; // ENOENT
    return .{ .value = 0 };
}

fn sys_lstat(path_ptr: usize, stat_ptr: usize) SyscallResult {
    return sys_stat(path_ptr, stat_ptr); // Stub: lstat same as stat
}

fn sys_fstat(fd: usize, stat_ptr: usize) SyscallResult {
    const vfs = @import("../vfs/mod.zig");
    vfs.sys_fstat(@as(i32, @bitCast(@as(u32, @truncate(fd)))), stat_ptr) catch return .{ .errno = 9 }; // EBADF
    return .{ .value = 0 };
}

fn sys_dup2(oldfd: usize, newfd: usize) SyscallResult {
    const vfs = @import("../vfs/mod.zig");
    vfs.sys_dup2(@as(i32, @bitCast(@as(u32, @truncate(oldfd)))), @as(i32, @bitCast(@as(u32, @truncate(newfd))))) catch return .{ .errno = 9 }; // EBADF
    return .{ .value = newfd };
}

fn sys_getdents(fd: usize, dirp: usize, count: usize) SyscallResult {
    const vfs = @import("../vfs/mod.zig");
    const res = vfs.sys_getdents(@as(i32, @bitCast(@as(u32, @truncate(fd)))), dirp, count) catch |err| {
        std.debug.print("TEA: sys_getdents failed: {any}\n", .{err});
        return .{ .errno = 9 }; // EBADF
    };
    return .{ .value = res };
}
