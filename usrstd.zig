const root = @import("root");
const std = @import("std");

extern var __stack_top: anyopaque;

export fn start() linksection(".text.start") callconv(.naked) noreturn {
    asm volatile (
        \\mv sp, %[stack_top]
        \\call %[main]
        \\call %[exit]
        :
        : [stack_top] "r" (&__stack_top),
          [main] "X" (&root.main),
          [exit] "X" (&exit),
    );
}

pub fn exit() noreturn {
    sys.exit();
}

pub const sys = struct {
    pub const SysNum = enum(usize) {
        putc = 0,
        getc = 1,
        exit = 2,
        read_file = 3,
        write_file = 4,
    };
    pub fn syscall(num: SysNum, arg0: usize, arg1: usize, arg2: usize) isize {
        return asm volatile ("ecall"
            : [ret] "={a0}" (-> isize),
            : [a0] "{a0}" (arg0),
              [a1] "{a1}" (arg1),
              [a2] "{a2}" (arg2),
              [a3] "{a3}" (@intFromEnum(num)),
            : .{ .memory = true });
    }

    pub fn putc(ch: u8) void {
        _ = syscall(.putc, ch, 0, 0);
    }
    pub fn getc() isize {
        return syscall(.getc, 0, 0, 0);
    }
    pub fn exit() noreturn {
        _ = syscall(.exit, 0, 0, 0);
        while (true) {} // should not be reached
    }
    pub fn readFile(filename: [*:0]const u8, buf: []u8) isize {
        return syscall(.read_file, @intFromPtr(filename), @intFromPtr(buf.ptr), buf.len);
    }
    pub fn writeFile(filename: [*:0]const u8, data: []const u8) isize {
        return syscall(.write_file, @intFromPtr(filename), @intFromPtr(data.ptr), data.len);
    }
};

pub const fs = struct {
    pub const readFile = sys.readFile;
    pub const writeFile = sys.writeFile;
};

pub const console = struct {
    pub fn print(comptime fmt: []const u8, args: anytype) void {
        var w = writer(&.{});
        w.interface.print(fmt, args) catch unreachable;
    }

    pub fn write(buf: []const u8) void {
        for (buf) |b| sys.putc(b);
    }

    pub fn writeByte(b: u8) void {
        sys.putc(b);
    }

    pub fn readByte() u8 {
        return @intCast(sys.getc());
    }

    pub fn writer(buf: []u8) Writer {
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
                write(buffered);
                return io_w.consume(buffered.len);
            }
            for (data[0 .. data.len - 1]) |buf| {
                if (buf.len == 0) continue;
                write(buf);
                return io_w.consume(buf.len);
            }
            const pattern = data[data.len - 1];
            if (pattern.len == 0 or splat == 0) return 0;
            write(pattern);
            return io_w.consume(pattern.len);
        }
    };
};
