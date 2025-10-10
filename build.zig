const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.resolveTargetQuery(.{
        .cpu_arch = .riscv32,
        .os_tag = .freestanding,
        .abi = .none,
    });

    const usrstd = b.addModule("usrstd", .{
        .root_source_file = b.path("usrstd.zig"),
        .target = target,
        .optimize = optimize,
    });

    const shell = b.addExecutable(.{
        .name = "shell.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("shell.zig"),
            .imports = &.{.{ .name = "usrstd", .module = usrstd }},
            .target = target,
            .optimize = optimize,
            .strip = false,
        }),
    });
    shell.entry = .disabled;
    shell.setLinkerScript(b.path("user.ld"));

    const shell2bin = b.addSystemCommand(&.{"llvm-objcopy"});
    shell2bin.addArgs(&.{ "--set-section-flags", ".bss=alloc,contents" });
    shell2bin.addArgs(&.{ "-O", "binary" });
    shell2bin.addArtifactArg(shell);
    const shell_bin = shell2bin.addOutputFileArg("shell.bin");

    const kernel = b.addExecutable(.{
        .name = "kernel.elf",
        .root_module = b.createModule(.{
            .root_source_file = b.path("kernel.zig"),
            .imports = &.{
                .{ .name = "usrstd", .module = usrstd },
                .{ .name = "shell.bin", .module = b.createModule(.{ .root_source_file = shell_bin }) },
            },
            .target = target,
            .optimize = optimize,
            .stack_protector = false,
            .strip = false,
        }),
    });
    kernel.entry = .disabled;
    kernel.setLinkerScript(b.path("kernel.ld"));

    // for debugging (inspecting the files)
    b.installArtifact(shell);
    b.getInstallStep().dependOn(&b.addInstallBinFile(shell_bin, "shell.bin").step);
    b.installArtifact(kernel);

    // include timestamp in content of disk-file, so it always gets generated
    // and a fresh version is put in .zig-cache, (since the kernel modifies the file)
    const disk_file = b.addWriteFile("disk-file", b.fmt(
        "this is the content of disk_file at {}",
        .{std.time.timestamp()},
    ));

    const qemu = b.addSystemCommand(&.{"qemu-system-riscv32"});
    qemu.addArgs(&.{ "-machine", "virt" });
    qemu.addArgs(&.{ "-bios", "default" });
    qemu.addArgs(&.{ "-serial", "mon:stdio" });
    qemu.addArg("-drive");
    qemu.addDecoratedDirectoryArg("id=drive0,file=", disk_file.getDirectory(), "/disk-file,format=raw,if=none");
    qemu.addArgs(&.{ "-device", "virtio-blk-device,drive=drive0,bus=virtio-mmio-bus.0" });
    qemu.addArg("-nographic");
    qemu.addArg("--no-reboot");
    qemu.addArg("-kernel");
    qemu.addArtifactArg(kernel);

    const run = b.step("run", "boot the os within qemu");
    run.dependOn(&qemu.step);
}
