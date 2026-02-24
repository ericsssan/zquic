const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Public module: consumers import this as @import("zquic")
    _ = b.addModule("zquic", .{
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
        "src/quic/tls.zig",
        "src/quic/connection.zig",
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
