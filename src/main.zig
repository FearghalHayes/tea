const std = @import("std");
const loader = @import("core/loader.zig");
const syscall = @import("core/syscall.zig");
const thread = @import("core/thread.zig");
const arch = @import("arch/x86_64.zig");
const memory = @import("core/memory.zig");
const vfs = @import("vfs/mod.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        std.debug.print("Usage: tea <linux_binary> [args...]\n", .{});
        return;
    }

    const binary_path = args[1];

    std.debug.print("TEA: Loading {s}...\n", .{binary_path});

    // Initialize syscall interception
    try syscall.init();

    // Initialize Threading (TLS)
    try thread.init();

    // Initialize VFS
    try vfs.initVfs(allocator);

    // Set guest executable path for /proc/self/exe
    const proc = @import("vfs/proc.zig");
    proc.guest_exe_path = binary_path;

    // Load ELF
    var elf_loader = loader.ElfLoader.init(allocator);
    const ctx = try elf_loader.load(binary_path, args[1..]);

    // Initialize Memory Manager
    try memory.MmapManager.init(allocator, ctx.brk);

    std.debug.print("TEA: Starting execution at 0x{x} with stack at 0x{x}\n", .{ ctx.entry, ctx.stack });

    if (thread.getCurrentThreadContext()) |tctx| {
        tctx.initial_entry = ctx.entry;
        tctx.initial_stack = ctx.stack;
    }

    // Jump to entry point
    arch.jumpToEntry(ctx.entry, ctx.stack);
}

test {
    _ = @import("core/loader.zig");
    _ = @import("core/syscall.zig");
    _ = @import("core/memory.zig");
    _ = @import("vfs/mod.zig");
}
