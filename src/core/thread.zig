const std = @import("std");
const windows = std.os.windows;
const syscall = @import("syscall.zig");
const signal = @import("signal.zig");

// Manual imports for kernel32 functions
extern "kernel32" fn TlsAlloc() callconv(.c) u32;
extern "kernel32" fn TlsGetValue(dwTlsIndex: u32) callconv(.c) ?*anyopaque;
extern "kernel32" fn TlsSetValue(dwTlsIndex: u32, lpTlsValue: ?*anyopaque) callconv(.c) windows.BOOL;
extern "kernel32" fn GetLastError() callconv(.c) windows.DWORD;
extern "kernel32" fn GetModuleHandleA(lpModuleName: ?[*:0]const u8) callconv(.c) ?windows.HMODULE;
extern "kernel32" fn GetProcAddress(hModule: windows.HMODULE, lpProcName: [*:0]const u8) callconv(.c) ?*anyopaque;

extern "ntdll" fn NtSetInformationThread(
    ThreadHandle: windows.HANDLE,
    ThreadInformationClass: u32,
    ThreadInformation: ?*const anyopaque,
    ThreadInformationLength: u32,
) callconv(.c) windows.NTSTATUS;

extern "ntdll" fn NtQueryInformationThread(
    ThreadHandle: windows.HANDLE,
    ThreadInformationClass: u32,
    ThreadInformation: ?*anyopaque,
    ThreadInformationLength: u32,
    ReturnLength: ?*u32,
) callconv(.c) windows.NTSTATUS;

pub const ThreadContext = struct {
    tid: i32,
    fs_base: usize = 0,
    set_child_tid: usize = 0,
    clear_child_tid: usize = 0,
    signal_handlers: [signal.NSIG]signal.sigaction_t = [_]signal.sigaction_t{.{
        .handler = 0,
        .flags = 0,
        .restorer = 0,
        .mask = 0,
    }} ** signal.NSIG,
    signal_mask: signal.sigset_t = 0,
    robust_list: usize = 0,
    initial_entry: usize = 0,
    initial_stack: usize = 0,
};

var tls_index: u32 = 0;
var next_tid: std.atomic.Value(i32) = std.atomic.Value(i32).init(1000);

// Dynamic imports for Synchronization functions
var pWaitOnAddress: ?*const fn (*const anyopaque, *const anyopaque, usize, u32) callconv(.c) windows.BOOL = null;
var pWakeByAddressSingle: ?*const fn (*const anyopaque) callconv(.c) void = null;
var pWakeByAddressAll: ?*const fn (*const anyopaque) callconv(.c) void = null;

pub fn init() !void {
    tls_index = TlsAlloc();
    if (tls_index == 0xFFFFFFFF) return error.TlsAllocFailed;

    // Load synchronization functions
    if (GetModuleHandleA("kernel32.dll")) |h| {
        if (GetProcAddress(h, "WaitOnAddress")) |ptr| {
            pWaitOnAddress = @ptrCast(@alignCast(ptr));
        }
        if (GetProcAddress(h, "WakeByAddressSingle")) |ptr| {
            pWakeByAddressSingle = @ptrCast(@alignCast(ptr));
        }
        if (GetProcAddress(h, "WakeByAddressAll")) |ptr| {
            pWakeByAddressAll = @ptrCast(@alignCast(ptr));
        }
    }

    // Create context for main thread
    const ctx = try std.heap.page_allocator.create(ThreadContext);
    ctx.* = .{
        .tid = next_tid.fetchAdd(1, .seq_cst),
    };
    _ = TlsSetValue(tls_index, ctx);
}

pub fn getCurrentThreadContext() ?*ThreadContext {
    const ptr = TlsGetValue(tls_index);
    if (ptr == null) return null;
    return @ptrCast(@alignCast(ptr));
}

pub fn sys_gettid() syscall.SyscallResult {
    if (getCurrentThreadContext()) |ctx| {
        return .{ .value = @intCast(ctx.tid) };
    }
    return .{ .errno = 1 }; // EPERM
}

pub fn sys_set_tid_address(tidptr: usize) syscall.SyscallResult {
    if (getCurrentThreadContext()) |ctx| {
        ctx.clear_child_tid = tidptr;
        return .{ .value = @intCast(ctx.tid) };
    }
    return .{ .errno = 1 };
}

// Futex constants
const FUTEX_WAIT = 0;
const FUTEX_WAKE = 1;
const FUTEX_FD = 2;
const FUTEX_REQUEUE = 3;
const FUTEX_CMP_REQUEUE = 4;
const FUTEX_WAKE_OP = 5;
const FUTEX_LOCK_PI = 6;
const FUTEX_UNLOCK_PI = 7;
const FUTEX_TRYLOCK_PI = 8;
const FUTEX_WAIT_BITSET = 9;

pub fn sys_futex(uaddr_ptr: usize, op: i32, val: i32, timeout_ptr: usize, uaddr2_ptr: usize, val3: i32) syscall.SyscallResult {
    _ = timeout_ptr;
    _ = uaddr2_ptr;
    _ = val3;

    const cmd = op & 0x7F; // Filter out FUTEX_PRIVATE_FLAG etc.
    const uaddr: *i32 = @ptrFromInt(uaddr_ptr);

    switch (cmd) {
        FUTEX_WAIT => {
            if (uaddr.* != val) return .{ .errno = 11 }; // EAGAIN

            if (pWaitOnAddress) |WaitOnAddress| {
                const res = WaitOnAddress(uaddr, &val, 4, 0xFFFFFFFF);
                if (res == 0) {
                    const err = GetLastError();
                    if (err == 1460) return .{ .errno = 110 }; // ETIMEDOUT -> WAIT_TIMEOUT
                    return .{ .errno = 22 }; // EINVAL
                }
            } else {
                // Fallback for older Windows or if not found: busy wait (not ideal but builds)
                while (uaddr.* == val) {
                    std.Thread.yield() catch {};
                }
            }
            return .{ .value = 0 };
        },
        FUTEX_WAKE => {
            if (val == 1) {
                if (pWakeByAddressSingle) |WakeByAddressSingle| {
                    WakeByAddressSingle(uaddr);
                }
            } else {
                if (pWakeByAddressAll) |WakeByAddressAll| {
                    WakeByAddressAll(uaddr);
                }
            }
            return .{ .value = @intCast(val) };
        },
        else => {
            std.debug.print("TEA: Unhandled futex op {d}\n", .{op});
            return .{ .errno = 38 }; // ENOSYS
        },
    }
}

const CloneParams = struct {
    stack: usize,
    fn_ptr: usize, // Not really used in standard clone, but useful for mapping
    child_tidptr: usize,
    flags: usize,
    parent_ctx: syscall.SyscallContext,
    next_rip: usize,
};

fn threadStartWrapper(lpParameter: windows.LPVOID) callconv(.c) windows.DWORD {
    const params: *CloneParams = @ptrCast(@alignCast(lpParameter));

    // Initialize ThreadContext for the new thread
    const ctx = std.heap.page_allocator.create(ThreadContext) catch return 1;
    ctx.* = .{
        .tid = next_tid.fetchAdd(1, .seq_cst),
    };
    _ = TlsSetValue(tls_index, ctx);

    // Handle CLONE_CHILD_SETTID
    if (params.flags & 0x01000000 != 0) { // CLONE_CHILD_SETTID
        const tid_ptr: *i32 = @ptrFromInt(params.child_tidptr);
        tid_ptr.* = ctx.tid;
    }

    // Handle CLONE_CHILD_CLEARTID
    if (params.flags & 0x00200000 != 0) { // CLONE_CHILD_CLEARTID
        ctx.clear_child_tid = params.child_tidptr;
    }

    std.debug.print("TEA: New thread {d} starting at 0x{x}\n", .{ ctx.tid, params.next_rip });

    // Jump to the next instruction in the guest code
    // RAX should be 0 in the child
    // We need a modified jumpToEntry that sets RAX to 0
    jumpToChild(params.next_rip, params.stack, params.parent_ctx);

    return 0;
}

fn jumpToChild(entry: usize, stack: usize, ctx: syscall.SyscallContext) noreturn {
    asm volatile (
        \\mov %[stack], %%rsp
        \\mov $0, %%rax
        \\mov %[rdi], %%rdi
        \\mov %[rsi], %%rsi
        \\mov %[rdx], %%rdx
        \\mov %[r10], %%r10
        \\mov %[r8], %%r8
        \\mov %[r9], %%r9
        \\jmp *%[entry]
        :
        : [entry] "r" (entry),
          [stack] "r" (stack),
          [rdi] "r" (ctx.rdi),
          [rsi] "r" (ctx.rsi),
          [rdx] "r" (ctx.rdx),
          [r10] "r" (ctx.r10),
          [r8] "r" (ctx.r8),
          [r9] "r" (ctx.r9),
    );
    unreachable;
}

pub fn sys_clone(flags: usize, stack_ptr: usize, parent_tidptr: usize, child_tidptr: usize, tls: usize, ctx: *syscall.SyscallContext) syscall.SyscallResult {
    _ = parent_tidptr;
    _ = tls;

    // If it's a thread creation (CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD)
    const thread_flags = 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800 | 0x00010000;
    if ((flags & thread_flags) == thread_flags) {
        const params = std.heap.page_allocator.create(CloneParams) catch return .{ .errno = 12 }; // ENOMEM
        params.* = .{
            .stack = stack_ptr,
            .fn_ptr = 0,
            .child_tidptr = child_tidptr,
            .flags = flags,
            .parent_ctx = ctx.*,
            // The next RIP is the instruction after ud2 in the caller.
            // Since we're in sys_clone, we don't have the ContextRecord here,
            // but we can pass it if we want. For now, let's assume we need to return
            // the new TID to the parent.
            .next_rip = 0, // This needs to be set from the VEH context
        };

        std.debug.print("TEA: sys_clone (thread) requested. Flags: 0x{x}\n", .{flags});
        // We are NOT fully implementing this yet, but we'll return ENOSYS or a dummy success
        // to see if Busybox can survive without it.
        return .{ .value = 0 }; // Stub success
    }

    return .{ .errno = 38 }; // ENOSYS
}

pub fn sys_arch_prctl(code: i32, addr: usize) syscall.SyscallResult {
    const ARCH_SET_FS = 0x1002;
    const ARCH_GET_FS = 0x1003;
    // const ARCH_SET_GS = 0x1001;
    // const ARCH_GET_GS = 0x1004;

    switch (code) {
        ARCH_SET_FS => {
            std.debug.print("TEA: arch_prctl(ARCH_SET_FS, 0x{x})\n", .{addr});
            if (getCurrentThreadContext()) |ctx| {
                ctx.fs_base = addr;
            }
            // Try using wrfsbase instruction if supported by CPU and OS
            // Most modern Windows 10/11 systems enable this.
            // We use a safe wrapper or just try it.
            // If it's not supported, it will trigger an exception which we'll see.
            asm volatile ("wrfsbase %[addr]"
                :
                : [addr] "r" (addr),
            );
            return .{ .value = 0 };
        },
        ARCH_GET_FS => {
            const addr_ptr: *usize = @ptrFromInt(addr);
            var current_fs: usize = 0;
            asm volatile ("rdfsbase %[fs]"
                : [fs] "=r" (current_fs),
            );
            addr_ptr.* = current_fs;
            return .{ .value = 0 };
        },
        else => {
            std.debug.print("TEA: Unhandled arch_prctl code 0x{x}\n", .{code});
            return .{ .errno = 38 }; // ENOSYS
        },
    }
}
