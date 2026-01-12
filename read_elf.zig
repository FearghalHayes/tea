const std = @import("std");
const elf = std.elf;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) return;
    const path = args[1];
    const target_rip: usize = if (args.len > 2) try std.fmt.parseInt(usize, args[2], 0) else 0;

    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var ehdr: elf.Elf64_Ehdr = undefined;
    _ = try file.readAll(std.mem.asBytes(&ehdr));

    std.debug.print("Entry: 0x{x}\n", .{ehdr.e_entry});

    var phdr_idx: u16 = 0;
    while (phdr_idx < ehdr.e_phnum) : (phdr_idx += 1) {
        var phdr: elf.Elf64_Phdr = undefined;
        try file.seekTo(ehdr.e_phoff + phdr_idx * ehdr.e_phentsize);
        _ = try file.readAll(std.mem.asBytes(&phdr));

        if (phdr.p_type == elf.PT_LOAD) {
            std.debug.print("LOAD: vaddr=0x{x}, filesz=0x{x}, offset=0x{x}\n", .{ phdr.p_vaddr, phdr.p_filesz, phdr.p_offset });
            if (target_rip >= phdr.p_vaddr and target_rip < phdr.p_vaddr + phdr.p_memsz) {
                const offset_in_segment = target_rip - phdr.p_vaddr;
                const file_offset = phdr.p_offset + offset_in_segment;
                std.debug.print("Target RIP 0x{x} found at file offset 0x{x}\n", .{ target_rip, file_offset });

                if (offset_in_segment < phdr.p_filesz) {
                    var bytes: [16]u8 = undefined;
                    try file.seekTo(file_offset);
                    const read = try file.readAll(&bytes);
                    std.debug.print("Bytes at 0x{x}: ", .{target_rip});
                    for (bytes[0..read]) |b| {
                        std.debug.print("{x:0>2} ", .{b});
                    }
                    std.debug.print("\n", .{});
                } else {
                    std.debug.print("Target RIP is in BSS area\n", .{});
                }
            }
        }
    }
}
