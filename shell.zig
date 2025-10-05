const std = @import("usrstd");
comptime {
    _ = std; // make sure std.start is exported
}
pub fn main() void {
    const p = "helloisen på doisen";
    asm volatile ("mv a0, %[p]"
        :
        : [p] "r" (p),
    );
    while (true) asm volatile ("nop");
}
