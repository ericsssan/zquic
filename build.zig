const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Public module: consumers import this as @import("zquic")
    const zquic_mod = b.addModule("zquic", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Static library artifact
    const lib = b.addLibrary(.{
        .name = "zquic",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(lib);

    // Interop server
    const server_mod = b.createModule(.{
        .root_source_file = b.path("tools/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_mod.addImport("zquic", zquic_mod);
    const server = b.addExecutable(.{
        .name = "server",
        .root_module = server_mod,
    });
    b.installArtifact(server);
    const run_server = b.addRunArtifact(server);
    if (b.args) |args| run_server.addArgs(args);
    const server_step = b.step("run-server", "Run interop server (default port 4433)");
    server_step.dependOn(&run_server.step);

    // Key rotation verification tool
    const verify_mod = b.createModule(.{
        .root_source_file = b.path("tools/verify_key_rotation.zig"),
        .target = target,
        .optimize = optimize,
    });
    verify_mod.addImport("zquic", zquic_mod);
    const verify = b.addExecutable(.{
        .name = "verify-key-rotation",
        .root_module = verify_mod,
    });
    b.installArtifact(verify);
    const run_verify = b.addRunArtifact(verify);
    const verify_step = b.step("verify-key-rotation", "Run key rotation verification");
    verify_step.dependOn(&run_verify.step);

    // Per-module unit tests
    const test_step = b.step("test", "Run unit tests");
    const test_files = [_][]const u8{
        "src/quic/varint.zig",
        "src/quic/pool.zig",
        "src/quic/crypto.zig",
        "src/quic/packet.zig",
        "src/quic/frame.zig",
        "src/quic/connection_id.zig",
        "src/quic/stream.zig",
        "src/quic/flow_control.zig",
        "src/quic/congestion/cubic.zig",
        "src/quic/transport_params.zig",
        "src/quic/loss_recovery.zig",
        "src/quic/tls.zig",
        "src/quic/connection.zig",
        "src/quic/fuzz.zig",
        "tools/pem.zig",
    };

    for (test_files) |path| {
        const mod = b.createModule(.{
            .root_source_file = b.path(path),
            .target = target,
            .optimize = optimize,
        });
        const t = b.addTest(.{ .root_module = mod });
        const run = b.addRunArtifact(t);
        test_step.dependOn(&run.step);
    }
}
