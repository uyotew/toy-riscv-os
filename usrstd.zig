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
