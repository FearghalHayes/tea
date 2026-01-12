const std = @import("std");
const windows = std.os.windows;
const syscall = @import("syscall.zig");

// Linux Signal Constants
pub const SIGHUP = 1;
pub const SIGINT = 2;
pub const SIGQUIT = 3;
pub const SIGILL = 4;
pub const SIGTRAP = 5;
pub const SIGABRT = 6;
pub const SIGIOT = 6;
pub const SIGBUS = 7;
pub const SIGFPE = 8;
pub const SIGKILL = 9;
pub const SIGUSR1 = 10;
pub const SIGSEGV = 11;
pub const SIGUSR2 = 12;
pub const SIGPIPE = 13;
pub const SIGALRM = 14;
pub const SIGTERM = 15;
pub const SIGSTKFLT = 16;
pub const SIGCHLD = 17;
pub const SIGCONT = 18;
pub const SIGSTOP = 19;
pub const SIGTSTP = 20;
pub const SIGTTIN = 21;
pub const SIGTTOU = 22;
pub const SIGURG = 23;
pub const SIGXCPU = 24;
pub const SIGXFSZ = 25;
pub const SIGVTALRM = 26;
pub const SIGPROF = 27;
pub const SIGWINCH = 28;
pub const SIGIO = 29;
pub const SIGPOLL = SIGIO;
pub const SIGPWR = 30;
pub const SIGSYS = 31;
pub const SIGUNUSED = 31;

pub const NSIG = 64;

// sigaction flags
pub const SA_NOCLDSTOP = 0x00000001;
pub const SA_NOCLDWAIT = 0x00000002;
pub const SA_SIGINFO = 0x00000004;
pub const SA_ONSTACK = 0x08000000;
pub const SA_RESTART = 0x10000000;
pub const SA_NODEFER = 0x40000000;
pub const SA_RESETHAND = 0x80000000;
pub const SA_RESTORER = 0x04000000;

pub const SIG_BLOCK = 0;
pub const SIG_UNBLOCK = 1;
pub const SIG_SETMASK = 2;

pub const sigset_t = u64;

pub const sigaction_t = extern struct {
    handler: usize,
    flags: usize,
    restorer: usize,
    mask: sigset_t,
};

pub const siginfo_t = extern struct {
    signo: i32,
    errno: i32,
    code: i32,
    _pad: i32,
    // Add more fields if needed for specific signals
    union_data: [112]u8, // Enough for most siginfo_t
};

// Mapping between Windows exceptions and Linux signals
pub fn translateException(code: u32) ?u32 {
    return switch (code) {
        0xC0000005 => SIGSEGV, // EXCEPTION_ACCESS_VIOLATION
        0xC000001D => SIGILL, // EXCEPTION_ILLEGAL_INSTRUCTION
        0xC000008D => SIGFPE, // EXCEPTION_FLT_DIVIDE_BY_ZERO
        0xC0000094 => SIGFPE, // EXCEPTION_INT_DIVIDE_BY_ZERO
        0x80000003 => SIGTRAP, // EXCEPTION_BREAKPOINT
        0x80000004 => SIGTRAP, // EXCEPTION_SINGLE_STEP
        0xC00000FD => SIGSEGV, // EXCEPTION_STACK_OVERFLOW
        else => null,
    };
}

pub fn sys_rt_sigaction(signum: usize, act_ptr: usize, oldact_ptr: usize, sigsetsize: usize) syscall.SyscallResult {
    const thread = @import("thread.zig");
    const thread_ctx = thread.getCurrentThreadContext() orelse return .{ .errno = 1 }; // EPERM or something

    if (signum >= NSIG or signum == 0) return .{ .errno = 22 }; // EINVAL
    if (sigsetsize != @sizeOf(sigset_t)) return .{ .errno = 22 }; // EINVAL

    if (oldact_ptr != 0) {
        const oldact: *sigaction_t = @ptrFromInt(oldact_ptr);
        oldact.* = thread_ctx.signal_handlers[signum];
    }

    if (act_ptr != 0) {
        const act: *sigaction_t = @ptrFromInt(act_ptr);
        // SIGKILL and SIGSTOP cannot be caught or ignored
        if (signum == SIGKILL or signum == SIGSTOP) return .{ .errno = 22 };
        thread_ctx.signal_handlers[signum] = act.*;
    }

    return .{ .value = 0 };
}

pub fn sys_rt_sigprocmask(how: usize, set_ptr: usize, oldset_ptr: usize, sigsetsize: usize) syscall.SyscallResult {
    const thread = @import("thread.zig");
    const thread_ctx = thread.getCurrentThreadContext() orelse return .{ .errno = 1 };

    if (sigsetsize != @sizeOf(sigset_t)) return .{ .errno = 22 };

    if (oldset_ptr != 0) {
        const oldset: *sigset_t = @ptrFromInt(oldset_ptr);
        oldset.* = thread_ctx.signal_mask;
    }

    if (set_ptr != 0) {
        const set: *sigset_t = @ptrFromInt(set_ptr);
        switch (how) {
            SIG_BLOCK => thread_ctx.signal_mask |= set.*,
            SIG_UNBLOCK => thread_ctx.signal_mask &= ~set.*,
            SIG_SETMASK => thread_ctx.signal_mask = set.*,
            else => return .{ .errno = 22 },
        }
        // SIGKILL and SIGSTOP cannot be blocked
        thread_ctx.signal_mask &= ~(@as(u64, 1) << (SIGKILL - 1));
        thread_ctx.signal_mask &= ~(@as(u64, 1) << (SIGSTOP - 1));
    }

    return .{ .value = 0 };
}
