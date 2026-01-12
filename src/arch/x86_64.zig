const std = @import("std");

pub fn jumpToEntry(entry: usize, stack: usize) noreturn {
    _ = entry;
    _ = stack;
    asm volatile ("ud2");
    unreachable;
}
