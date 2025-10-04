const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .riscv32,
        .os_tag = .freestanding,
    });

    const kernel = b.addExecutable(.{
        .name = "kernel.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("kernel.zig"),
            .target = target,
            .optimize = optimize,
            .stack_protector = false,
            .strip = false,
        }),
    });

    kernel.entry = .disabled;
    kernel.setLinkerScript(b.path("kernel.ld"));

    b.installArtifact(kernel);

    const qemu = b.addSystemCommand(&.{"qemu-system-riscv32"});
    qemu.addArgs(&.{ "-machine", "virt" });
    qemu.addArgs(&.{ "-bios", "default" });
    qemu.addArgs(&.{ "-serial", "mon:stdio" });
    qemu.addArg("-nographic");
    qemu.addArg("--no-reboot");
    qemu.addArg("-kernel");
    qemu.addArtifactArg(kernel);

    const run = b.step("run", "boot the os within qemu");
    run.dependOn(&qemu.step);
}
