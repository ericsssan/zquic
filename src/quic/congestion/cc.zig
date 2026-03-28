//! Congestion control algorithm abstraction layer.
//!
//! Provides a comptime switch between BBR v3 and CUBIC. The active algorithm
//! is selected at build time via `-Dcongestion=cubic` (default: bbr).
//! Both algorithms expose the same public API, so the rest of the stack
//! uses `cc.CongestionControl` without knowing which is active.

const build_options = @import("build_options");
const cubic = @import("cubic.zig");
const bbr = @import("bbr.zig");

pub const DeliveryRateSample = @import("common.zig").DeliveryRateSample;

pub const Algorithm = enum { cubic, bbr };

/// Selected at build time via `-Dcongestion=cubic` (default: bbr).
pub const selected: Algorithm = if (build_options.congestion_cubic) .cubic else .bbr;

pub const CongestionControl = switch (selected) {
    .cubic => cubic.Cubic,
    .bbr => bbr.Bbr,
};
