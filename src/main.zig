const std = @import("std");
const config = @import("config");
const loader = @import("core/loader.zig");
const syscall = @import("core/syscall.zig");
const thread = @import("core/thread.zig");
const arch = @import("arch/x86_64.zig");
const memory = @import("core/memory.zig");
const vfs = @import("vfs/mod.zig");

var runtime_log_level: std.log.Level = if (config.verbose_logging) .debug else .info;

pub const std_options: std.Options = .{
    .log_level = .debug, // Allow all levels through to our logFn
    .logFn = myLogFn,
};

pub fn myLogFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(level) > @intFromEnum(runtime_log_level)) return;

    const scope_str = @tagName(scope);
    const level_str = @tagName(level);

    const prefix = "[" ++ level_str ++ "] (" ++ scope_str ++ "): ";

    // Using std.debug.print here which handles its own locking in recent Zig versions.
    std.debug.print(prefix ++ format ++ "\n", args);
}

pub fn main() !void {
    // Check TEA_LOG environment variable
    if (std.process.getEnvVarOwned(std.heap.page_allocator, "TEA_LOG")) |tea_log| {
        defer std.heap.page_allocator.free(tea_log);
        if (std.mem.eql(u8, tea_log, "debug")) {
            runtime_log_level = .debug;
        } else if (std.mem.eql(u8, tea_log, "info")) {
            runtime_log_level = .info;
        } else if (std.mem.eql(u8, tea_log, "warn")) {
            runtime_log_level = .warn;
        } else if (std.mem.eql(u8, tea_log, "error")) {
            runtime_log_level = .err;
        }
    } else |_| {}

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

    const log = std.log.scoped(.loader);
    log.info("TEA: Loading {s}...", .{binary_path});

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

    log.info("TEA: Starting execution at 0x{x:0>16} with stack at 0x{x:0>16}", .{ ctx.entry, ctx.stack });

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
