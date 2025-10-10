const std = @import("std");
const usrstd = @import("usrstd");

const shell_bin = @embedFile("shell.bin");

extern var __kernel_base: anyopaque;
extern var __bss: anyopaque;
extern var __bss_end: anyopaque;
extern var __stack_top: anyopaque;
extern var __free_ram: anyopaque;
extern var __free_ram_end: anyopaque;

var processes: [8]Process = .{Process{}} ** 8;
var current_proc: *Process = undefined;
var idle_proc: *Process = undefined;

export fn boot() linksection(".text.boot") callconv(.naked) noreturn {
    asm volatile (
        \\mv sp, %[stack_top]
        \\j %[main]
        :
        : [stack_top] "r" (&__stack_top),
          [main] "X" (&main),
    );
}

pub fn main() void {
    const bss_len = @intFromPtr(&__bss_end) - @intFromPtr(&__bss);
    const bss = @as([*]u8, @ptrCast(&__bss))[0..bss_len];
    @memset(bss, 0);

    writeCsr("stvec", @intFromPtr(&kernelEntry));

    const free_ram_len = @intFromPtr(&__free_ram_end) - @intFromPtr(&__free_ram);
    const free_ram = @as([*]u8, @ptrCast(&__free_ram))[0..free_ram_len];
    var fba: std.heap.FixedBufferAllocator = .init(free_ram);
    const allocator = fba.allocator();

    const blk = virtio.Blk.init(allocator) catch |err| std.debug.panic("Blk.init error: {t}", .{err});
    var buf: [virtio.sector_size]u8 = undefined;
    blk.readSector(&buf, 0);
    print("sector 0 original content: {s}\n", .{buf});
    const new_start = "wrote this...";
    @memcpy(buf[0..new_start.len], new_start);
    blk.writeSector(&buf, 0);
    print("sector 0 new content: {s}\n", .{buf});

    idle_proc = .create(allocator, &.{});
    idle_proc.pid = 0;
    current_proc = idle_proc;

    const shell: *Process = Process.create(allocator, shell_bin);
    print("starting process: pid={} sp=0x{x} state={t}\n", .{ shell.pid, shell.sp, shell.state });

    yield();
    @panic("switched to idle process");
}

fn kernelEntry() align(4) callconv(.naked) void {
    asm volatile (
        \\csrrw sp, sscratch, sp
        \\addi sp, sp, -4 * 31
        \\sw ra, 4 * 0(sp)
        \\sw gp, 4 * 1(sp)
        \\sw tp, 4 * 2(sp)
        \\sw t0, 4 * 3(sp)
        \\sw t1, 4 * 4(sp)
        \\sw t2, 4 * 5(sp)
        \\sw t3, 4 * 6(sp)
        \\sw t4, 4 * 7(sp)
        \\sw t5, 4 * 8(sp)
        \\sw t6, 4 * 9(sp)
        \\sw a0, 4 * 10(sp)
        \\sw a1, 4 * 11(sp)
        \\sw a2, 4 * 12(sp)
        \\sw a3, 4 * 13(sp)
        \\sw a4, 4 * 14(sp)
        \\sw a5, 4 * 15(sp)
        \\sw a6, 4 * 16(sp)
        \\sw a7, 4 * 17(sp)
        \\sw s0, 4 * 18(sp)
        \\sw s1, 4 * 19(sp)
        \\sw s2, 4 * 20(sp)
        \\sw s3, 4 * 21(sp)
        \\sw s4, 4 * 22(sp)
        \\sw s5, 4 * 23(sp)
        \\sw s6, 4 * 24(sp)
        \\sw s7, 4 * 25(sp)
        \\sw s8, 4 * 26(sp)
        \\sw s9, 4 * 27(sp)
        \\sw s10, 4 * 28(sp)
        \\sw s11, 4 * 29(sp)
        \\
        \\csrr a0, sscratch
        \\sw a0, 4 * 30(sp)
        \\
        \\addi a0, sp, 4 * 31
        \\csrw sscratch, a0
        \\
        \\mv a0, sp
        \\call %[handleTrap]
        \\
        \\lw ra, 4 * 0(sp)
        \\lw gp, 4 * 1(sp)
        \\lw tp, 4 * 2(sp)
        \\lw t0, 4 * 3(sp)
        \\lw t1, 4 * 4(sp)
        \\lw t2, 4 * 5(sp)
        \\lw t3, 4 * 6(sp)
        \\lw t4, 4 * 7(sp)
        \\lw t5, 4 * 8(sp)
        \\lw t6, 4 * 9(sp)
        \\lw a0, 4 * 10(sp)
        \\lw a1, 4 * 11(sp)
        \\lw a2, 4 * 12(sp)
        \\lw a3, 4 * 13(sp)
        \\lw a4, 4 * 14(sp)
        \\lw a5, 4 * 15(sp)
        \\lw a6, 4 * 16(sp)
        \\lw a7, 4 * 17(sp)
        \\lw s0, 4 * 18(sp)
        \\lw s1, 4 * 19(sp)
        \\lw s2, 4 * 20(sp)
        \\lw s3, 4 * 21(sp)
        \\lw s4, 4 * 22(sp)
        \\lw s5, 4 * 23(sp)
        \\lw s6, 4 * 24(sp)
        \\lw s7, 4 * 25(sp)
        \\lw s8, 4 * 26(sp)
        \\lw s9, 4 * 27(sp)
        \\lw s10, 4 * 28(sp)
        \\lw s11, 4 * 29(sp)
        \\lw sp, 4 * 30(sp)
        \\sret
        :
        : [handleTrap] "X" (&handleTrap),
    );
}

const TrapFrame = extern struct {
    ra: usize,
    gp: usize,
    tp: usize,
    t0: usize,
    t1: usize,
    t2: usize,
    t3: usize,
    t4: usize,
    t5: usize,
    t6: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
    a6: usize,
    a7: usize,
    s0: usize,
    s1: usize,
    s2: usize,
    s3: usize,
    s4: usize,
    s5: usize,
    s6: usize,
    s7: usize,
    s8: usize,
    s9: usize,
    s10: usize,
    s11: usize,
    sp: usize,
};

fn readCsr(comptime regname: []const u8) usize {
    return asm volatile ("csrr %[ret], " ++ regname
        : [ret] "=r" (-> usize),
    );
}

fn writeCsr(comptime regname: []const u8, val: usize) void {
    asm volatile ("csrw " ++ regname ++ ", %[val]"
        :
        : [val] "r" (val),
    );
}

// tf will sometimes point to address 0 when building in debug mode
// if callconv(.c) is not used
// i assume zig by default doesn't enforce a0 being used for the first arg?
fn handleTrap(tf: *TrapFrame) callconv(.c) void {
    const scause = readCsr("scause");
    const stval = readCsr("stval");
    const user_pc = readCsr("sepc");
    if (scause == 8) { // syscall
        const num = std.enums.fromInt(usrstd.sys.SysNum, tf.a3) orelse
            std.debug.panic("unimplemented syscall a3={}", .{tf.a3});

        switch (num) {
            .putc => _ = sbi.call(.{ .eid = .putc, .a0 = tf.a0 }),
            .getc => while (true) {
                const ret = sbi.call(.{ .eid = .getc });
                if (ret.err >= 0) {
                    tf.a0 = @bitCast(ret.err);
                    break;
                } else yield();
            },
            .exit => {
                print("process {} exited\n", .{current_proc.pid});
                current_proc.state = .exited;
                yield();
                std.debug.panic("failed to exit from process {}", .{current_proc.pid});
            },
        }
        // move to after ecall instruction in user bin
        writeCsr("sepc", user_pc + 4);
    } else {
        const scause_str = switch (scause) {
            0 => "instruction address misaligned",
            1 => "instruction access fault",
            2 => "illegal instruction",
            3 => "breakpoint",
            4 => "load address misaligned",
            5 => "load access fault",
            6 => "store/AMO address misaligned",
            7 => "store/AMO access fault",
            8 => "environment call from U-mode or VU-mode",
            9 => "environment call from HS-mode",
            10 => "environment call from VS-mode",
            11 => "environment call from M-mode",
            12 => "instruction page fault",
            13 => "load page fault",
            15 => "store/AMO page fault",
            20 => "instruction guest-page fault",
            21 => "load guest-page fault",
            22 => "virtual instruction",
            23 => "store/AMO guest-page fault",
            else => "",
        };
        std.debug.panic("unexpected trap scause={x}, stval={x}, sepc={x}\ncause: {s}", .{
            scause,
            stval,
            user_pc,
            scause_str,
        });
    }
}

const Process = struct {
    pid: usize = undefined,
    state: enum { unused, runnable, exited } = .unused,
    sp: usize = undefined,
    page_table: PageTable = undefined,
    stack: [8192]u8 align(4) = undefined,

    fn create(allocator: std.mem.Allocator, bin_image: []const u8) *Process {
        const idx = for (0..processes.len) |i| {
            if (processes[i].state == .unused) break i;
        } else @panic("no unused process slots");

        const proc = &processes[idx];

        proc.page_table = .init(allocator);
        proc.page_table.mapKernelPages(allocator);
        proc.page_table.mapPage(allocator, virtio.blk_paddr, virtio.blk_paddr, .rw);
        proc.page_table.mapUserImage(allocator, bin_image);

        const stack: []u32 = @ptrCast(&proc.stack);
        @memset(stack[stack.len - 12 ..], 0); // init s0...s11;
        stack[stack.len - 13] = @intFromPtr(&userEntry); // set return address
        proc.pid = idx + 1;
        proc.state = .runnable;
        proc.sp = @intFromPtr(&stack[stack.len - 13]);

        return proc;
    }
};

fn userEntry() callconv(.naked) void {
    const SPIE = 1 << 5; // something to do with interrupts (won't be used though)
    asm volatile (
        \\csrw sepc, %[sepc]
        \\csrw sstatus, %[sstatus]
        \\sret
        :
        : [sepc] "r" (PageTable.user_bin_base),
          [sstatus] "r" (SPIE),
    );
}

fn yield() void {
    const next: *Process = for (0..processes.len) |i| {
        const proc: *Process = &processes[(current_proc.pid + i) % processes.len];
        if (proc.state == .runnable and proc.pid != 0) break proc;
    } else idle_proc;
    if (current_proc == next) return;

    const prev: *Process = current_proc;
    current_proc = next;

    asm volatile (
        \\sfence.vma
        \\csrw satp, %[satp]
        \\sfence.vma
        \\
        \\csrw sscratch, %[sscratch]
        \\
        \\mv a0, %[prev_sp]
        \\mv a1, %[next_sp]
        \\jal %[switchContext]
        :
        : [satp] "r" (PageTable.satp_sv32 | (@intFromPtr(next.page_table.table1) / PageTable.page_size)),
          [sscratch] "r" (@intFromPtr(&next.stack) + next.stack.len),
          [prev_sp] "r" (&prev.sp),
          [next_sp] "r" (&next.sp),
          [switchContext] "X" (&switchContext),
        : .{ .x1 = true }); // x1 is ra, clobbered by jal
}

fn switchContext() callconv(.naked) void {
    asm volatile (
        \\addi sp, sp, -4 * 13
        \\sw ra, 4 * 0(sp)
        \\sw s0, 4 * 1(sp)
        \\sw s1, 4 * 2(sp)
        \\sw s2, 4 * 3(sp)
        \\sw s3, 4 * 4(sp)
        \\sw s4, 4 * 5(sp)
        \\sw s5, 4 * 6(sp)
        \\sw s6, 4 * 7(sp)
        \\sw s7, 4 * 8(sp)
        \\sw s8, 4 * 9(sp)
        \\sw s9, 4 * 10(sp)
        \\sw s10, 4 * 11(sp)
        \\sw s11, 4 * 12(sp)
        \\
        \\sw sp, (a0)
        \\lw sp, (a1)
        \\
        \\lw ra, 4 * 0(sp)
        \\lw s0, 4 * 1(sp)
        \\lw s1, 4 * 2(sp)
        \\lw s2, 4 * 3(sp)
        \\lw s3, 4 * 4(sp)
        \\lw s4, 4 * 5(sp)
        \\lw s5, 4 * 6(sp)
        \\lw s6, 4 * 7(sp)
        \\lw s7, 4 * 8(sp)
        \\lw s8, 4 * 9(sp)
        \\lw s9, 4 * 10(sp)
        \\lw s10, 4 * 11(sp)
        \\lw s11, 4 * 12(sp)
        \\addi sp, sp, 4 * 13
        \\ret
    );
}

const PageTable = struct {
    table1: [*]Page,
    const page_size = 4096;
    const satp_sv32 = 1 << 31;
    const Page = packed struct(u32) {
        flags: Flags,
        page_num: u22,
    };

    const Flags = packed struct(u10) {
        valid: bool = false,
        read: bool = false,
        write: bool = false,
        execute: bool = false,
        user: bool = false,
        reserved: u5 = 0,

        const rw: Flags = .{ .read = true, .write = true };
        const rwx: Flags = .{ .read = true, .write = true, .execute = true };
        const urwx: Flags = .{ .user = true, .read = true, .write = true, .execute = true };
    };

    fn init(allocator: std.mem.Allocator) PageTable {
        const table = allocator.alignedAlloc(Page, .fromByteUnits(page_size), page_size / 4) catch @panic("OOM");
        for (table) |*p| p.flags = .{ .valid = false };
        return .{ .table1 = table.ptr };
    }
    fn mapKernelPages(pt: PageTable, allocator: std.mem.Allocator) void {
        var paddr = @intFromPtr(&__kernel_base);
        while (paddr < @intFromPtr(&__free_ram_end)) : (paddr += page_size) {
            pt.mapPage(allocator, paddr, paddr, .rwx);
        }
    }

    const user_bin_base = 0x1000000;

    fn mapUserImage(pt: PageTable, allocator: std.mem.Allocator, image: []const u8) void {
        var off: usize = 0;
        while (off < image.len) : (off += page_size) {
            const page = allocator.alignedAlloc(u8, .fromByteUnits(page_size), page_size) catch @panic("OOM");

            const to_copy = image[off..][0..@min(page_size, image.len - off)];
            @memcpy(page[0..to_copy.len], to_copy);

            pt.mapPage(allocator, user_bin_base + off, @intFromPtr(page.ptr), .urwx);
        }
    }

    fn mapPage(pt: PageTable, allocator: std.mem.Allocator, vaddr: usize, paddr: usize, flags: Flags) void {
        if (!std.mem.isAligned(vaddr, page_size)) std.debug.panic("unaligned vaddr {x}", .{vaddr});
        if (!std.mem.isAligned(paddr, page_size)) std.debug.panic("unaligned paddr {x}", .{paddr});

        const vpn1 = (vaddr >> 22) & 0b11111_11111;
        if (!pt.table1[vpn1].flags.valid) {
            const pt_paddr = (allocator.alignedAlloc(u8, .fromByteUnits(page_size), page_size) catch @panic("OOM")).ptr;
            pt.table1[vpn1].flags = .{ .valid = true };
            pt.table1[vpn1].page_num = @intCast(@intFromPtr(pt_paddr) / page_size);
        }
        const vpn0 = (vaddr >> 12) & 0b11111_11111;
        const table0: [*]Page = @ptrFromInt(@as(usize, pt.table1[vpn1].page_num) * page_size);
        table0[vpn0].flags = flags;
        table0[vpn0].flags.valid = true;
        table0[vpn0].page_num = @intCast(paddr / page_size);
    }
};

pub const panic = std.debug.FullPanic(struct {
    fn panicFn(msg: []const u8, first_trace_addr: ?usize) noreturn {
        const addr = first_trace_addr orelse @returnAddress();
        print("panic at 0x{x}: {s}\n", .{ addr, msg });
        while (true) {}
    }
}.panicFn);

fn print(comptime fmt: []const u8, args: anytype) void {
    var w = sbi.writer(&.{});
    w.interface.print(fmt, args) catch return;
}

const sbi = struct {
    const Eid = enum(usize) { // extension id
        putc = 1,
        getc = 2,
    };

    const CallParams = struct {
        a0: usize = 0,
        a1: usize = 0,
        a2: usize = 0,
        a3: usize = 0,
        a4: usize = 0,
        a5: usize = 0,
        fid: usize = 0,
        eid: Eid,
    };
    const Ret = struct {
        err: isize,
        val: isize,
    };

    fn call(cp: CallParams) Ret {
        var err: isize = 0;
        var val: isize = 0;
        asm volatile ("ecall"
            : [err] "={a0}" (err),
              [val] "={a1}" (val),
            : [a0] "{a0}" (cp.a0),
              [a1] "{a1}" (cp.a1),
              [a2] "{a2}" (cp.a2),
              [a3] "{a3}" (cp.a3),
              [a4] "{a4}" (cp.a4),
              [a5] "{a5}" (cp.a5),
              [fid] "{a6}" (cp.fid),
              [eid] "{a7}" (@intFromEnum(cp.eid)),
            : .{ .memory = true });

        return .{ .err = err, .val = val };
    }

    fn write(bytes: []const u8) error{WriteFailed}!void {
        for (bytes) |b| {
            const ret = call(.{ .eid = .putc, .a0 = b });
            if (ret.err != 0) return error.WriteFailed;
        }
    }

    fn writer(buf: []u8) Writer {
        return .init(buf);
    }
    const Writer = struct {
        interface: std.Io.Writer,

        fn init(buf: []u8) Writer {
            return .{ .interface = .{
                .buffer = buf,
                .vtable = &.{ .drain = drain },
            } };
        }

        fn drain(io_w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const buffered = io_w.buffered();
            if (buffered.len != 0) {
                try write(buffered);
                return io_w.consume(buffered.len);
            }
            for (data[0 .. data.len - 1]) |buf| {
                if (buf.len == 0) continue;
                try write(buf);
                return io_w.consume(buf.len);
            }
            const pattern = data[data.len - 1];
            if (pattern.len == 0 or splat == 0) return 0;
            try write(pattern);
            return io_w.consume(pattern.len);
        }
    };
};

const virtio = struct {
    const sector_size = 512;
    const device_blk = 2;
    const blk_paddr = 0x10001000;

    const Blk = struct {
        capacity: u64,
        req_paddr: usize,
        req: *Request,
        vq: *Virtqueue,

        const Request = extern struct {
            dir: enum(u32) { in = 0, out = 1 } align(1),
            _reserved: u32 align(1),
            sector: u64 align(1),
            data: [sector_size]u8 align(1),
            status: u8 align(1),
        };

        pub fn init(allocator: std.mem.Allocator) !Blk {
            if (reg.magic.* != 0x74726976) return error.InvalidMagic;
            if (reg.version.* != 1) return error.InvalidVersion;
            if (reg.device_id.* != device_blk) return error.InvalidId;

            reg.device_status.* = .reset;
            reg.device_status.set(.ack);
            reg.device_status.set(.driver);
            reg.device_status.set(.feat_ok); //skip negotiation of features

            const vq: *Virtqueue = .init(allocator, 0);

            reg.device_status.* = .{ .driver_ok = true };

            const capacity = sector_size * reg.device_config.*;
            print("virtio-blk: capacity is {} bytes\n", .{capacity});

            const alignment: std.mem.Alignment = comptime .fromByteUnits(PageTable.page_size);
            const num_bytes = alignment.forward(@sizeOf(Request));
            const paddr_slice = allocator.alignedAlloc(u8, alignment, num_bytes) catch @panic("OOM");
            const paddr = @intFromPtr(paddr_slice.ptr);
            @memset(paddr_slice, 0); // init req to all 0

            return .{ .capacity = capacity, .req_paddr = paddr, .req = @ptrFromInt(paddr), .vq = vq };
        }

        pub fn readSector(blk: Blk, buf: *[sector_size]u8, sector: usize) void {
            readOrWriteSector(blk, buf, sector, false);
        }

        pub fn writeSector(blk: Blk, buf: *[sector_size]u8, sector: usize) void {
            readOrWriteSector(blk, buf, sector, true);
        }

        fn readOrWriteSector(blk: Blk, buf: *[sector_size]u8, sector: usize, is_write: bool) void {
            if (sector >= blk.capacity / sector_size) {
                return print("virtio: tried to access sector={}, but capacity is {}\n", .{ sector, blk.capacity / sector_size });
            }
            blk.req.sector = sector;
            blk.req.dir = if (is_write) .out else .in;
            if (is_write) @memcpy(&blk.req.data, buf);

            blk.vq.descs[0] = .{
                .addr = blk.req_paddr,
                .len = @sizeOf(u32) * 2 + @sizeOf(u64),
                .flags = .{ .next = true },
                .next = 1,
            };
            blk.vq.descs[1] = .{
                .addr = blk.req_paddr + @offsetOf(Request, "data"),
                .len = sector_size,
                .flags = .{ .next = true, .write = !is_write }, //writable by device if driver is reading
                .next = 2,
            };
            blk.vq.descs[2] = .{
                .addr = blk.req_paddr + @offsetOf(Request, "status"),
                .len = @sizeOf(u8),
                .flags = .{ .write = true },
                .next = 0,
            };

            blk.vq.kick(0);
            while (blk.vq.isBusy()) {}
            if (blk.req.status != 0) {
                return print("virtio: failed to access sector={} status={}\n", .{ sector, blk.req.status });
            }
            if (!is_write) @memcpy(buf, &blk.req.data);
        }
    };

    const reg = struct {
        const magic: *volatile u32 = @ptrFromInt(0x00 + blk_paddr);
        const version: *volatile u32 = @ptrFromInt(0x04 + blk_paddr);
        const device_id: *volatile u32 = @ptrFromInt(0x08 + blk_paddr);
        const queue_sel: *volatile u32 = @ptrFromInt(0x30 + blk_paddr);
        const queue_num_max: *volatile u32 = @ptrFromInt(0x34 + blk_paddr);
        const queue_num: *volatile u32 = @ptrFromInt(0x38 + blk_paddr);
        const queue_align: *volatile u32 = @ptrFromInt(0x3c + blk_paddr);
        const queue_pfn: *volatile u32 = @ptrFromInt(0x40 + blk_paddr);
        const queue_ready: *volatile u32 = @ptrFromInt(0x44 + blk_paddr);
        const queue_notify: *volatile u32 = @ptrFromInt(0x50 + blk_paddr);
        const device_status: *volatile DeviceStatus = @ptrFromInt(0x70 + blk_paddr);
        const device_config: *volatile u64 = @ptrFromInt(0x100 + blk_paddr);
    };

    const DeviceStatus = packed struct(u32) {
        ack: bool = false,
        driver: bool = false,
        driver_ok: bool = false,
        feat_ok: bool = false,
        _unused: u28 = 0,

        pub const reset: DeviceStatus = .{};
        // cannot set bitfields of volatile pointers to packed structs directly,
        // the entire value has to be set atomically, so use this function
        // see last part of https://ziglang.org/documentation/0.15.1/#packed-struct
        pub fn set(ds: *volatile DeviceStatus, comptime field_tag: std.meta.FieldEnum(DeviceStatus)) void {
            var prev = ds.*;
            @field(prev, @tagName(field_tag)) = true;
            ds.* = prev;
        }
    };

    const Virtqueue = extern struct {
        descs: [entry_num]Descriptor align(1),
        avail: AvailRing align(1),
        used: UsedRing align(PageTable.page_size),
        queue_index: u32 align(1),
        used_index: *volatile u16 align(1),
        last_used_index: u16 align(1),

        const entry_num = 16;

        const Descriptor = extern struct {
            addr: u64 align(1),
            len: u32 align(1),
            flags: Flags align(1),
            next: u16 align(1),

            const Flags = packed struct(u16) {
                next: bool = false,
                write: bool = false,
                _unused: u14 = 0,
            };
        };

        const AvailRing = extern struct {
            flags: Flags align(1),
            index: u16 align(1),
            ring: [entry_num]u16 align(1),

            const Flags = packed struct(u16) {
                no_interrupt: bool = false,
                _unused: u15 = 0,
            };
        };

        const UsedRing = extern struct {
            flags: u16 align(1),
            index: u16 align(1),
            ring: [entry_num]Entry align(1),

            const Entry = extern struct {
                id: u32 align(1),
                len: u32 align(1),
            };
        };

        pub fn init(allocator: std.mem.Allocator, index: u32) *Virtqueue {
            const alignment: std.mem.Alignment = comptime .fromByteUnits(PageTable.page_size);
            const num_bytes = alignment.forward(@sizeOf(Virtqueue));
            const paddr_slice = allocator.alignedAlloc(u8, alignment, num_bytes) catch @panic("OOM");
            const paddr = @intFromPtr(paddr_slice.ptr);
            const vq: *Virtqueue = @ptrCast(paddr_slice.ptr);
            @memset(paddr_slice, 0); // initialize entire vq to 0

            vq.queue_index = index;
            vq.used_index = @ptrCast(&vq.used.index);

            reg.queue_sel.* = index;
            reg.queue_num.* = entry_num;
            reg.queue_align.* = 0;
            reg.queue_pfn.* = paddr;
            return vq;
        }

        pub fn kick(vq: *Virtqueue, desc_index: u16) void {
            vq.avail.ring[vq.avail.index % entry_num] = desc_index;
            vq.avail.index +%= 1;
            // __sync_syncronize() was here in the book, don't know why
            // this might be the same?
            asm volatile ("fence" ::: .{ .memory = true });
            reg.queue_notify.* = vq.queue_index;
            vq.last_used_index +%= 1;
        }
        pub fn isBusy(vq: *const Virtqueue) bool {
            return vq.last_used_index != vq.used_index.*;
        }
    };
};
