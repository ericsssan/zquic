// Shared QPACK types.

/// A single HTTP header field (name + value).
/// Slices may point into the original wire buffer or a Huffman scratch buffer —
/// callers must keep both alive for as long as the Field is used.
pub const Field = struct {
    name: []const u8,
    value: []const u8,
};
