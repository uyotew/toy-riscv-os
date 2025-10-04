const std = @import("std");

extern var __kernel_base: anyopaque;
extern var __bss: anyopaque;
extern var __bss_end: anyopaque;
extern var __stack_top: anyopaque;
extern var __free_ram: anyopaque;
extern var __free_ram_end: anyopaque;

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

    writeCsr("stvec", @intFromPtr(&enterKernel));

    const free_ram_len = @intFromPtr(&__free_ram_end) - @intFromPtr(&__free_ram);
    const free_ram = @as([*]u8, @ptrCast(&__free_ram))[0..free_ram_len];
    var fba: std.heap.FixedBufferAllocator = .init(free_ram);
    const allocator = fba.allocator();

    idle_proc = .create(allocator, 0);
    idle_proc.pid = 0;
    current_proc = idle_proc;

    proc1 = .create(allocator, @intFromPtr(&proc1Entry));
    proc2 = .create(allocator, @intFromPtr(&proc2Entry));

    yield();
    @panic("switched to idle process");
}

var processes: [8]Process = .{Process{}} ** 8;
var current_proc: *Process = undefined;
var idle_proc: *Process = undefined;

var proc1: *Process = undefined;
var proc2: *Process = undefined;

fn yield() void {
    const next: *Process = for (0..processes.len) |i| {
        const proc: *Process = &processes[(current_proc.pid + i) % processes.len];
        if (proc.state == .runnable and proc.pid != 0) break proc;
    } else return;
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

fn proc1Entry() void {
    while (true) {
        yield();
        debug.print("1", .{});
    }
}
fn proc2Entry() void {
    while (true) {
        yield();
        debug.print("2", .{});
    }
}

const Process = struct {
    pid: usize = undefined,
    state: enum { unused, runnable } = .unused,
    sp: usize = undefined,
    page_table: PageTable = undefined,
    stack: [8192]u8 = undefined,

    fn create(allocator: std.mem.Allocator, pc: usize) *Process {
        const idx = for (0..processes.len) |i| {
            if (processes[i].state == .unused) break i;
        } else @panic("no unused process slots");

        const proc = &processes[idx];

        proc.page_table = .init(allocator);
        @memset(proc.stack[proc.stack.len - 4 * 12 ..], 0); // set s0..11 'registers' on stack to 0
        proc.stack[proc.stack.len - 4 * 13 ..][0..4].* = std.mem.toBytes(pc); // set ra to pc
        proc.pid = idx + 1;
        proc.state = .runnable;
        proc.sp = @intFromPtr(&proc.stack[proc.stack.len - 4 * 13]);

        return proc;
    }
};

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
    };

    fn init(allocator: std.mem.Allocator) PageTable {
        const table = allocator.alignedAlloc(Page, .fromByteUnits(page_size), page_size) catch @panic("OOM");
        for (table) |*p| p.flags = .{};
        var pt: PageTable = .{ .table1 = table.ptr };

        var paddr = @intFromPtr(&__kernel_base);
        while (paddr < @intFromPtr(&__free_ram_end)) : (paddr += page_size) {
            const flags: Flags = .{ .read = true, .write = true, .execute = true };
            pt.mapPage(allocator, paddr, paddr, flags);
        }
        return pt;
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

fn enterKernel() align(4) callconv(.naked) void {
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

fn handleTrap(_: *TrapFrame) void {
    const scause = readCsr("scause");
    const stval = readCsr("stval");
    const user_pc = readCsr("sepc");
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

const TrapFrame = packed struct {
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

fn halt() noreturn {
    while (true) {} // can this be while (true) asm volatile ("wfi"); instead
}
pub const panic = std.debug.FullPanic(struct {
    fn panicFn(msg: []const u8, first_trace_addr: ?usize) noreturn {
        const addr = first_trace_addr orelse @returnAddress();
        var w = sbi.writer(&.{});
        w.interface.print("panic at 0x{x}: {s}\n", .{ addr, msg }) catch {};
        halt();
    }
}.panicFn);

const debug = struct {
    fn print(comptime fmt: []const u8, args: anytype) void {
        var w = sbi.writer(&.{});
        w.interface.print(fmt, args) catch return;
    }
};

const sbi = struct {
    const Eid = enum(usize) { // extension id
        dbcn = 0x4442434E, // debug console?
    };
    const fid = struct { // function id
        const dbcn = struct {
            const write = 0x0;
            const read = 0x1;
            const write_byte = 0x2;
        };
    };

    const ReturnCode = enum(isize) {
        SUCCESS = 0,
        FAILED = -1,
        NOT_SUPPORTED = -2,
        INVALID_PARAM = -3,
        DENIED = -4,
        INVALID_ADDRESS = -5,
        ALREADY_AVAILABLE = -6,
        ALREADY_STARTED = -7,
        ALREADY_STOPPED = -8,
        NO_SHMEM = -9,
        INVALID_STATE = -10,
        BAD_RANGE = -11,
        TIMEOUT = -12,
        IO = -13,
        DENIED_LOCKED = -14,

        fn toError(rc: ReturnCode) Error!void {
            return switch (rc) {
                .SUCCESS => {},
                .FAILED => error.Failed,
                .NOT_SUPPORTED => error.NotSupported,
                .INVALID_PARAM => error.InvalidParam,
                .DENIED => error.Denied,
                .INVALID_ADDRESS => error.InvalidAddress,
                .ALREADY_AVAILABLE => error.AlreadyAvailable,
                .ALREADY_STARTED => error.AlreadyStarted,
                .ALREADY_STOPPED => error.AlreadyStopped,
                .NO_SHMEM => error.NoShmem,
                .INVALID_STATE => error.InvalidState,
                .BAD_RANGE => error.BadRange,
                .TIMEOUT => error.Timeout,
                .IO => error.Io,
                .DENIED_LOCKED => error.DeniedLocked,
            };
        }
    };
    const Error = error{
        Failed,
        NotSupported,
        InvalidParam,
        Denied,
        InvalidAddress,
        AlreadyAvailable,
        AlreadyStarted,
        AlreadyStopped,
        NoShmem,
        InvalidState,
        BadRange,
        Timeout,
        Io,
        DeniedLocked,
    };

    const CallParams = struct {
        a0: usize = 0,
        a1: usize = 0,
        a2: usize = 0,
        a3: usize = 0,
        a4: usize = 0,
        a5: usize = 0,
        fid: usize,
        eid: Eid,
    };
    const Ret = struct {
        err: ReturnCode,
        val: usize,
    };

    fn call(cp: CallParams) Ret {
        var err: isize = 0;
        var val: usize = 0;
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

        return .{ .err = @enumFromInt(err), .val = val };
    }

    fn write(bytes: []const u8) Error!usize {
        const res = call(.{
            .eid = .dbcn,
            .fid = fid.dbcn.write,
            .a0 = bytes.len,
            .a1 = @intFromPtr(bytes.ptr),
        });
        try res.err.toError();
        return res.val;
    }

    fn writer(buf: []u8) Writer {
        return .init(buf);
    }
    const Writer = struct {
        err: ?Error = null,
        interface: std.Io.Writer,

        fn init(buf: []u8) Writer {
            return .{ .interface = .{
                .buffer = buf,
                .vtable = &.{ .drain = drain },
            } };
        }

        fn drain(io_w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const w: *Writer = @alignCast(@fieldParentPtr("interface", io_w));
            const buffered = io_w.buffered();
            if (buffered.len != 0) {
                const n = write(buffered) catch |err| {
                    w.err = err;
                    return error.WriteFailed;
                };
                return io_w.consume(n);
            }
            for (data[0 .. data.len - 1]) |buf| {
                if (buf.len == 0) continue;
                const n = write(buf) catch |err| {
                    w.err = err;
                    return error.WriteFailed;
                };
                return io_w.consume(n);
            }
            const pattern = data[data.len - 1];
            if (pattern.len == 0 or splat == 0) return 0;
            const n = write(pattern) catch |err| {
                w.err = err;
                return error.WriteFailed;
            };
            return io_w.consume(n);
        }
    };
};
