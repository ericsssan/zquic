const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Congestion control algorithm selection: bbr (default) or cubic.
    const Algorithm = enum { bbr, cubic };
    const congestion = b.option(Algorithm, "congestion", "Congestion control algorithm: bbr (default) or cubic") orelse .bbr;
    const congestion_cubic = congestion == .cubic;

    const build_options = b.addOptions();
    build_options.addOption(bool, "congestion_cubic", congestion_cubic);
    const build_options_mod = build_options.createModule();

    // Public module: consumers import this as @import("zquic")
    const zquic_mod = b.addModule("zquic", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "build_options", .module = build_options_mod },
        },
    });

    // Static library artifact
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_mod.addImport("build_options", build_options_mod);
    const lib = b.addLibrary(.{
        .name = "zquic",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    // zhttp3 dependency (HTTP/3 + QPACK)
    const zhttp3_dep = b.dependency("zhttp3", .{ .target = target, .optimize = optimize });
    const qpack_mod = b.createModule(.{
        .root_source_file = zhttp3_dep.path("src/qpack/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const http3_mod = b.createModule(.{
        .root_source_file = zhttp3_dep.path("src/http3/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    http3_mod.addImport("qpack", qpack_mod);

    // Interop server
    const server_mod = b.createModule(.{
        .root_source_file = b.path("tools/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_mod.addImport("zquic", zquic_mod);
    server_mod.addImport("http3", http3_mod);
    server_mod.addImport("qpack", qpack_mod);
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

    // Throughput benchmark
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("tools/bench.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    bench_mod.addImport("zquic", zquic_mod);
    const bench = b.addExecutable(.{
        .name = "bench",
        .root_module = bench_mod,
    });
    b.installArtifact(bench);
    const run_bench = b.addRunArtifact(bench);
    const bench_step = b.step("bench", "Run throughput benchmark");
    bench_step.dependOn(&run_bench.step);

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
        "src/quic/congestion/bbr.zig",
        "src/quic/congestion/common.zig",
        "src/quic/transport_params.zig",
        "src/quic/loss_recovery.zig",
        "src/quic/tls.zig",
        "src/quic/connection.zig",
        "src/quic/connection_test_basic.zig",
        "src/quic/connection_test_frames.zig",
        "src/quic/connection_test_pmtud.zig",
        "src/quic/connection_test_crypto.zig",
        "src/quic/connection_test_corruption.zig",
        "src/quic/connection_test_handshakecorruption.zig",
        "src/quic/fuzz.zig",
        "src/quic/connection_test_resumption.zig",
        "src/quic/tls_client.zig",
        "src/quic/test_harness.zig",
        "src/quic/netsim.zig",
        "src/quic/integration_test.zig",
        "tools/pem.zig",
    };

    for (test_files) |path| {
        const mod = b.createModule(.{
            .root_source_file = b.path(path),
            .target = target,
            .optimize = optimize,
        });
        mod.addImport("build_options", build_options_mod);
        const t = b.addTest(.{ .root_module = mod });
        // Connection(16) is ~2.2 MB; Debug mode disables copy elision, creating
        // ~16 MB of stack frames in accept() + test.  64 MB gives enough headroom.
        t.stack_size = 64 * 1024 * 1024;
        const run = b.addRunArtifact(t);
        test_step.dependOn(&run.step);
    }

    // tools/server.zig needs the zquic import
    const server_test_mod = b.createModule(.{
        .root_source_file = b.path("tools/server.zig"),
        .target = target,
        .optimize = optimize,
    });
    server_test_mod.addImport("zquic", zquic_mod);
    server_test_mod.addImport("http3", http3_mod);
    server_test_mod.addImport("qpack", qpack_mod);
    const server_test = b.addTest(.{ .root_module = server_test_mod });
    server_test.stack_size = 64 * 1024 * 1024;
    test_step.dependOn(&b.addRunArtifact(server_test).step);
}
