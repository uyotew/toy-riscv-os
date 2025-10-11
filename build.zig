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

    const run = b.step("run", "boot the os within qemu");

    const file_system = tarDir(b, b.path("disk"), "fs.tar");

    const qemu = b.addSystemCommand(&.{"qemu-system-riscv32"});
    qemu.addArgs(&.{ "-machine", "virt" });
    qemu.addArgs(&.{ "-bios", "default" });
    qemu.addArgs(&.{ "-serial", "mon:stdio" });
    qemu.addArgs(&.{ "-drive", b.fmt("id=drive0,file={s},format=raw,if=none", .{b.getInstallPath(.prefix, "fs.tar")}) });
    qemu.addArgs(&.{ "-device", "virtio-blk-device,drive=drive0,bus=virtio-mmio-bus.0" });
    qemu.addArg("-nographic");
    qemu.addArg("--no-reboot");
    qemu.addArg("-kernel");
    qemu.addArtifactArg(kernel);

    qemu.step.dependOn(&b.addInstallFile(file_system, "fs.tar").step);

    run.dependOn(&qemu.step);
}

fn tarDir(b: *std.Build, dir: std.Build.LazyPath, name: []const u8) std.Build.LazyPath {
    const list_disk_files = b.addSystemCommand(&.{ "ls", "--zero" });
    list_disk_files.addDirectoryArg(dir);
    const disk_files = list_disk_files.captureStdOut();

    const tar_disk = b.addSystemCommand(&.{ "tar", "cfv" });
    tar_disk.setCwd(dir);
    const file_system = tar_disk.addOutputFileArg(name);
    tar_disk.addArgs(&.{ "--format=ustar", "--null", "-T" });
    tar_disk.addFileArg(disk_files);

    return file_system;
}
