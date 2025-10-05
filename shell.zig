const usrstd = @import("usrstd");
const std = @import("std");
const console = usrstd.console;
comptime {
    _ = usrstd; // makes sure usrstd.start is exported
}
// set panic function to avoid 'illegal instruction' happening when defaultPanic is called
pub const panic = std.debug.FullPanic(struct {
    fn panicFn(msg: []const u8, first_trace_addr: ?usize) noreturn {
        const addr = first_trace_addr orelse @returnAddress();
        console.print("panic at 0x{x}: {s}\n", .{ addr, msg });
        while (true) {}
    }
}.panicFn);

pub fn main() void {
    var buf: [128]u8 = undefined;
    prompt: while (true) {
        console.write("> ");
        var buf_len: usize = 0;
        while (true) : (buf_len += 1) {
            const b = console.readByte();
            console.writeByte(b);
            if (buf_len >= buf.len) {
                console.write("\nerror: command line too long\n");
                continue :prompt;
            }
            if (b == '\r') {
                console.writeByte('\n');
                break;
            } else buf[buf_len] = b;
        }

        if (std.mem.eql(u8, buf[0..buf_len], "exit")) {
            usrstd.exit();
        } else {
            console.print("unknown command: {s}\n", .{buf[0..buf_len]});
        }
    }
}
