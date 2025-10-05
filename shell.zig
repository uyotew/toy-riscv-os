const usrstd = @import("usrstd");
const std = @import("std");
comptime {
    _ = usrstd; // make sure std.start is exported
}
// set panic function to avoid 'illegal instruction' happening when defaultPanic is called
pub const panic = std.debug.FullPanic(struct {
    fn panicFn(msg: []const u8, first_trace_addr: ?usize) noreturn {
        _ = first_trace_addr orelse @returnAddress();
        _ = usrstd.write(msg);
        _ = usrstd.write("\n");
        while (true) {}
    }
}.panicFn);

pub fn main() void {
    _ = usrstd.write("hello from shell\n");
}
