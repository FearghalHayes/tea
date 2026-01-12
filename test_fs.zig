const std = @import("std");

pub fn main() !void {
    const addr: usize = 0x12345678;
    asm volatile ("wrfsbase %[addr]"
        :
        : [addr] "r" (addr),
    );

    var read_back: usize = 0;
    asm volatile ("rdfsbase %[read_back]"
        : [read_back] "=r" (read_back),
    );

    std.debug.print("Set FS base to 0x{x}, read back 0x{x}\n", .{ addr, read_back });
}
