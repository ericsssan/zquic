const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const http3_mod = b.createModule(.{
        .root_source_file = b.path("src/http3/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const qpack_mod = b.createModule(.{
        .root_source_file = b.path("src/qpack/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const server_mod = b.createModule(.{
        .root_source_file = b.path("src/server/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // connection.zig (within http3_mod) imports qpack and server_types by name.
    http3_mod.addImport("qpack", qpack_mod);
    http3_mod.addImport("server_types", b.createModule(.{
        .root_source_file = b.path("src/server/types.zig"),
        .target = target,
        .optimize = optimize,
    }));

    const lib = b.addLibrary(.{
        .name = "zhttp3",
        .root_module = http3_mod,
        .linkage = .static,
    });
    b.installArtifact(lib);

    // Individual test modules — each pulls in its transitive imports.
    const varint_mod = b.createModule(.{
        .root_source_file = b.path("src/http3/varint.zig"),
        .target = target,
        .optimize = optimize,
    });
    const frame_mod = b.createModule(.{
        .root_source_file = b.path("src/http3/frame.zig"),
        .target = target,
        .optimize = optimize,
    });
    const settings_mod = b.createModule(.{
        .root_source_file = b.path("src/http3/settings.zig"),
        .target = target,
        .optimize = optimize,
    });
    const stream_h3_mod = b.createModule(.{
        .root_source_file = b.path("src/http3/stream.zig"),
        .target = target,
        .optimize = optimize,
    });
    const push_mod = b.createModule(.{
        .root_source_file = b.path("src/http3/push.zig"),
        .target = target,
        .optimize = optimize,
    });
    const shutdown_mod = b.createModule(.{
        .root_source_file = b.path("src/http3/shutdown.zig"),
        .target = target,
        .optimize = optimize,
    });

    const test_step = b.step("test", "Run unit tests");

    const http3_tests = b.addTest(.{ .root_module = http3_mod });
    test_step.dependOn(&b.addRunArtifact(http3_tests).step);

    const varint_tests = b.addTest(.{ .root_module = varint_mod });
    test_step.dependOn(&b.addRunArtifact(varint_tests).step);

    const frame_tests = b.addTest(.{ .root_module = frame_mod });
    test_step.dependOn(&b.addRunArtifact(frame_tests).step);

    const settings_tests = b.addTest(.{ .root_module = settings_mod });
    test_step.dependOn(&b.addRunArtifact(settings_tests).step);

    const stream_h3_tests = b.addTest(.{ .root_module = stream_h3_mod });
    test_step.dependOn(&b.addRunArtifact(stream_h3_tests).step);

    const qpack_tests = b.addTest(.{ .root_module = qpack_mod });
    test_step.dependOn(&b.addRunArtifact(qpack_tests).step);

    const push_tests = b.addTest(.{ .root_module = push_mod });
    test_step.dependOn(&b.addRunArtifact(push_tests).step);

    const shutdown_tests = b.addTest(.{ .root_module = shutdown_mod });
    test_step.dependOn(&b.addRunArtifact(shutdown_tests).step);

    // connection.zig as standalone test module — needs named imports.
    const connection_mod = b.createModule(.{
        .root_source_file = b.path("src/http3/connection.zig"),
        .target = target,
        .optimize = optimize,
    });
    connection_mod.addImport("qpack", qpack_mod);
    connection_mod.addImport("server_types", b.createModule(.{
        .root_source_file = b.path("src/server/types.zig"),
        .target = target,
        .optimize = optimize,
    }));
    const connection_tests = b.addTest(.{ .root_module = connection_mod });
    test_step.dependOn(&b.addRunArtifact(connection_tests).step);

    // Server layer modules.
    const types_mod = b.createModule(.{
        .root_source_file = b.path("src/server/types.zig"),
        .target = target,
        .optimize = optimize,
    });
    const router_mod = b.createModule(.{
        .root_source_file = b.path("src/server/router.zig"),
        .target = target,
        .optimize = optimize,
    });
    const middleware_mod = b.createModule(.{
        .root_source_file = b.path("src/server/middleware.zig"),
        .target = target,
        .optimize = optimize,
    });
    // server_mod (root: src/server/root.zig) pulls in all server submodules
    // transitively, including handlers/kv.zig.  Run all server tests via a
    // single step; individual module steps cover types, router, middleware.
    const server_tests = b.addTest(.{ .root_module = server_mod });
    test_step.dependOn(&b.addRunArtifact(server_tests).step);

    const types_tests = b.addTest(.{ .root_module = types_mod });
    test_step.dependOn(&b.addRunArtifact(types_tests).step);

    const router_tests = b.addTest(.{ .root_module = router_mod });
    test_step.dependOn(&b.addRunArtifact(router_tests).step);

    const middleware_tests = b.addTest(.{ .root_module = middleware_mod });
    test_step.dependOn(&b.addRunArtifact(middleware_tests).step);
}
