const root = @import("root");

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

fn exit() noreturn {
    while (true) {}
}

pub const sys = struct {
    pub const SysNum = enum(usize) {
        putc = 0,
        getc = 1,
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
};

pub fn write(buf: []const u8) void {
    for (buf) |b| sys.putc(b);
}

// blocking version of sys.getc
pub fn getByte() u8 {
    var res: isize = -1;
    while (res < 0) res = sys.getc();
    return @intCast(res);
}
