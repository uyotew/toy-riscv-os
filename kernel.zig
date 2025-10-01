// https://operating-system-in-1000-lines.vercel.app/en/
// maybe also add interrupt handling??

const std = @import("std");

extern var __stack_top: anyopaque;
extern var __bss_start: anyopaque;
extern var __bss_end: anyopaque;

var write_buf: [1024]u8 = undefined;

export fn boot() linksection(".text.boot") callconv(.naked) noreturn {
    asm volatile (
        \\mv sp, %[stack_top]
        \\j kernelMain
        \\
        :
        : [stack_top] "r" (&__stack_top),
    );
}

export fn kernelMain() void {
    const bss_len = @intFromPtr(&__bss_end) - @intFromPtr(&__bss_start);
    const bss = @as([*]u8, @ptrCast(&__bss_start))[0..bss_len];
    @memset(bss, 0);

    var conw = sbi.writer(&write_buf);
    conw.interface.print("hello {s}!\n", .{"world"}) catch {};
    conw.interface.flush() catch {};

    while (true) asm volatile ("wfi");
}

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
            if (pattern.len == 1) {
                const buf = io_w.buffer[0..@min(io_w.buffer.len - 1, splat)];
                @memset(buf, pattern[0]);
                const n = write(buf) catch |err| {
                    w.err = err;
                    return error.WriteFailed;
                };
                return io_w.consume(n);
            } else {
                const n = write(pattern) catch |err| {
                    w.err = err;
                    return error.WriteFailed;
                };
                return io_w.consume(n);
            }
        }
    };
};
