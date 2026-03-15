// QPACK/HPACK Huffman coding — RFC 7541 Appendix B
// Static Huffman code table: 256 byte symbols + EOS (symbol 256).

const std = @import("std");

pub const Entry = struct {
    code: u32,
    bits: u5, // code length in bits (5–30 for valid symbols)
};

/// Symbol index 256 is EOS. Appearing in a header string value is an error.
pub const EOS: usize = 256;

/// RFC 7541 Appendix B: Huffman code table, indexed by symbol (0–256).
pub const encode_table: [257]Entry = .{
    .{ .code = 0x1ff8, .bits = 13 },     // sym 0
    .{ .code = 0x7fffd8, .bits = 23 },   // sym 1
    .{ .code = 0xfffffe2, .bits = 28 },  // sym 2
    .{ .code = 0xfffffe3, .bits = 28 },  // sym 3
    .{ .code = 0xfffffe4, .bits = 28 },  // sym 4
    .{ .code = 0xfffffe5, .bits = 28 },  // sym 5
    .{ .code = 0xfffffe6, .bits = 28 },  // sym 6
    .{ .code = 0xfffffe7, .bits = 28 },  // sym 7
    .{ .code = 0xfffffe8, .bits = 28 },  // sym 8
    .{ .code = 0xffffea, .bits = 24 },   // sym 9  (\t)
    .{ .code = 0x3ffffffc, .bits = 30 }, // sym 10 (\n)
    .{ .code = 0xfffffe9, .bits = 28 },  // sym 11
    .{ .code = 0xfffffea, .bits = 28 },  // sym 12
    .{ .code = 0x3ffffffd, .bits = 30 }, // sym 13 (\r)
    .{ .code = 0xfffffeb, .bits = 28 },  // sym 14
    .{ .code = 0xfffffec, .bits = 28 },  // sym 15
    .{ .code = 0xfffffed, .bits = 28 },  // sym 16
    .{ .code = 0xfffffee, .bits = 28 },  // sym 17
    .{ .code = 0xfffffef, .bits = 28 },  // sym 18
    .{ .code = 0xffffff0, .bits = 28 },  // sym 19
    .{ .code = 0xffffff1, .bits = 28 },  // sym 20
    .{ .code = 0xffffff2, .bits = 28 },  // sym 21
    .{ .code = 0x3ffffffe, .bits = 30 }, // sym 22
    .{ .code = 0xffffff3, .bits = 28 },  // sym 23
    .{ .code = 0xffffff4, .bits = 28 },  // sym 24
    .{ .code = 0xffffff5, .bits = 28 },  // sym 25
    .{ .code = 0xffffff6, .bits = 28 },  // sym 26
    .{ .code = 0xffffff7, .bits = 28 },  // sym 27
    .{ .code = 0xffffff8, .bits = 28 },  // sym 28
    .{ .code = 0xffffff9, .bits = 28 },  // sym 29
    .{ .code = 0xffffffa, .bits = 28 },  // sym 30
    .{ .code = 0xffffffb, .bits = 28 },  // sym 31
    .{ .code = 0x14, .bits = 6 },        // sym 32 ' '
    .{ .code = 0x3f8, .bits = 10 },      // sym 33 '!'
    .{ .code = 0x3f9, .bits = 10 },      // sym 34 '"'
    .{ .code = 0xffa, .bits = 12 },      // sym 35 '#'
    .{ .code = 0x1ff9, .bits = 13 },     // sym 36 '$'
    .{ .code = 0x15, .bits = 6 },        // sym 37 '%'
    .{ .code = 0xf8, .bits = 8 },        // sym 38 '&'
    .{ .code = 0x7fa, .bits = 11 },      // sym 39 '\''
    .{ .code = 0x3fa, .bits = 10 },      // sym 40 '('
    .{ .code = 0x3fb, .bits = 10 },      // sym 41 ')'
    .{ .code = 0xf9, .bits = 8 },        // sym 42 '*'
    .{ .code = 0x7fb, .bits = 11 },      // sym 43 '+'
    .{ .code = 0xfa, .bits = 8 },        // sym 44 ','
    .{ .code = 0x16, .bits = 6 },        // sym 45 '-'
    .{ .code = 0x17, .bits = 6 },        // sym 46 '.'
    .{ .code = 0x18, .bits = 6 },        // sym 47 '/'
    .{ .code = 0x0, .bits = 5 },         // sym 48 '0'
    .{ .code = 0x1, .bits = 5 },         // sym 49 '1'
    .{ .code = 0x2, .bits = 5 },         // sym 50 '2'
    .{ .code = 0x19, .bits = 6 },        // sym 51 '3'
    .{ .code = 0x1a, .bits = 6 },        // sym 52 '4'
    .{ .code = 0x1b, .bits = 6 },        // sym 53 '5'
    .{ .code = 0x1c, .bits = 6 },        // sym 54 '6'
    .{ .code = 0x1d, .bits = 6 },        // sym 55 '7'
    .{ .code = 0x1e, .bits = 6 },        // sym 56 '8'
    .{ .code = 0x1f, .bits = 6 },        // sym 57 '9'
    .{ .code = 0x5c, .bits = 7 },        // sym 58 ':'
    .{ .code = 0xfb, .bits = 8 },        // sym 59 ';'
    .{ .code = 0x7ffc, .bits = 15 },     // sym 60 '<'
    .{ .code = 0x20, .bits = 6 },        // sym 61 '='
    .{ .code = 0xffb, .bits = 12 },      // sym 62 '>'
    .{ .code = 0x3fc, .bits = 10 },      // sym 63 '?'
    .{ .code = 0x1ffa, .bits = 13 },     // sym 64 '@'
    .{ .code = 0x21, .bits = 6 },        // sym 65 'A'
    .{ .code = 0x5d, .bits = 7 },        // sym 66 'B'
    .{ .code = 0x5e, .bits = 7 },        // sym 67 'C'
    .{ .code = 0x5f, .bits = 7 },        // sym 68 'D'
    .{ .code = 0x60, .bits = 7 },        // sym 69 'E'
    .{ .code = 0x61, .bits = 7 },        // sym 70 'F'
    .{ .code = 0x62, .bits = 7 },        // sym 71 'G'
    .{ .code = 0x63, .bits = 7 },        // sym 72 'H'
    .{ .code = 0x64, .bits = 7 },        // sym 73 'I'
    .{ .code = 0x65, .bits = 7 },        // sym 74 'J'
    .{ .code = 0x66, .bits = 7 },        // sym 75 'K'
    .{ .code = 0x67, .bits = 7 },        // sym 76 'L'
    .{ .code = 0x68, .bits = 7 },        // sym 77 'M'
    .{ .code = 0x69, .bits = 7 },        // sym 78 'N'
    .{ .code = 0x6a, .bits = 7 },        // sym 79 'O'
    .{ .code = 0x6b, .bits = 7 },        // sym 80 'P'
    .{ .code = 0x6c, .bits = 7 },        // sym 81 'Q'
    .{ .code = 0x6d, .bits = 7 },        // sym 82 'R'
    .{ .code = 0x6e, .bits = 7 },        // sym 83 'S'
    .{ .code = 0x6f, .bits = 7 },        // sym 84 'T'
    .{ .code = 0x70, .bits = 7 },        // sym 85 'U'
    .{ .code = 0x71, .bits = 7 },        // sym 86 'V'
    .{ .code = 0x72, .bits = 7 },        // sym 87 'W'
    .{ .code = 0xfc, .bits = 8 },        // sym 88 'X'
    .{ .code = 0x73, .bits = 7 },        // sym 89 'Y'
    .{ .code = 0xfd, .bits = 8 },        // sym 90 'Z'
    .{ .code = 0x1ffb, .bits = 13 },     // sym 91 '['
    .{ .code = 0x7fff0, .bits = 19 },    // sym 92 '\\'
    .{ .code = 0x1ffc, .bits = 13 },     // sym 93 ']'
    .{ .code = 0x3ffc, .bits = 14 },     // sym 94 '^'
    .{ .code = 0x22, .bits = 6 },        // sym 95 '_'
    .{ .code = 0x7ffd, .bits = 15 },     // sym 96 '`'
    .{ .code = 0x3, .bits = 5 },         // sym 97 'a'
    .{ .code = 0x23, .bits = 6 },        // sym 98 'b'
    .{ .code = 0x4, .bits = 5 },         // sym 99 'c'
    .{ .code = 0x24, .bits = 6 },        // sym 100 'd'
    .{ .code = 0x5, .bits = 5 },         // sym 101 'e'
    .{ .code = 0x25, .bits = 6 },        // sym 102 'f'
    .{ .code = 0x26, .bits = 6 },        // sym 103 'g'
    .{ .code = 0x27, .bits = 6 },        // sym 104 'h'
    .{ .code = 0x6, .bits = 5 },         // sym 105 'i'
    .{ .code = 0x74, .bits = 7 },        // sym 106 'j'
    .{ .code = 0x75, .bits = 7 },        // sym 107 'k'
    .{ .code = 0x28, .bits = 6 },        // sym 108 'l'
    .{ .code = 0x29, .bits = 6 },        // sym 109 'm'
    .{ .code = 0x2a, .bits = 6 },        // sym 110 'n'
    .{ .code = 0x7, .bits = 5 },         // sym 111 'o'
    .{ .code = 0x2b, .bits = 6 },        // sym 112 'p'
    .{ .code = 0x76, .bits = 7 },        // sym 113 'q'
    .{ .code = 0x2c, .bits = 6 },        // sym 114 'r'
    .{ .code = 0x8, .bits = 5 },         // sym 115 's'
    .{ .code = 0x9, .bits = 5 },         // sym 116 't'
    .{ .code = 0x2d, .bits = 6 },        // sym 117 'u'
    .{ .code = 0x77, .bits = 7 },        // sym 118 'v'
    .{ .code = 0x78, .bits = 7 },        // sym 119 'w'
    .{ .code = 0x79, .bits = 7 },        // sym 120 'x'
    .{ .code = 0x7a, .bits = 7 },        // sym 121 'y'
    .{ .code = 0x7b, .bits = 7 },        // sym 122 'z'
    .{ .code = 0x7ffe, .bits = 15 },     // sym 123 '{'
    .{ .code = 0x7fc, .bits = 11 },      // sym 124 '|'
    .{ .code = 0x3ffd, .bits = 14 },     // sym 125 '}'
    .{ .code = 0x1ffd, .bits = 13 },     // sym 126 '~'
    .{ .code = 0xffffffc, .bits = 28 },  // sym 127
    .{ .code = 0xfffe6, .bits = 20 },    // sym 128
    .{ .code = 0x3fffd2, .bits = 22 },   // sym 129
    .{ .code = 0xfffe7, .bits = 20 },    // sym 130
    .{ .code = 0xfffe8, .bits = 20 },    // sym 131
    .{ .code = 0x3fffd3, .bits = 22 },   // sym 132
    .{ .code = 0x3fffd4, .bits = 22 },   // sym 133
    .{ .code = 0x3fffd5, .bits = 22 },   // sym 134
    .{ .code = 0x7fffd9, .bits = 23 },   // sym 135
    .{ .code = 0x3fffd6, .bits = 22 },   // sym 136
    .{ .code = 0x7fffda, .bits = 23 },   // sym 137
    .{ .code = 0x7fffdb, .bits = 23 },   // sym 138
    .{ .code = 0x7fffdc, .bits = 23 },   // sym 139
    .{ .code = 0x7fffdd, .bits = 23 },   // sym 140
    .{ .code = 0x7fffde, .bits = 23 },   // sym 141
    .{ .code = 0xffffeb, .bits = 24 },   // sym 142
    .{ .code = 0x7fffdf, .bits = 23 },   // sym 143
    .{ .code = 0xffffec, .bits = 24 },   // sym 144
    .{ .code = 0xffffed, .bits = 24 },   // sym 145
    .{ .code = 0x3fffd7, .bits = 22 },   // sym 146
    .{ .code = 0x7fffe0, .bits = 23 },   // sym 147
    .{ .code = 0xffffee, .bits = 24 },   // sym 148
    .{ .code = 0x7fffe1, .bits = 23 },   // sym 149
    .{ .code = 0x7fffe2, .bits = 23 },   // sym 150
    .{ .code = 0x7fffe3, .bits = 23 },   // sym 151
    .{ .code = 0x7fffe4, .bits = 23 },   // sym 152
    .{ .code = 0x1fffdc, .bits = 21 },   // sym 153
    .{ .code = 0x3fffd8, .bits = 22 },   // sym 154
    .{ .code = 0x7fffe5, .bits = 23 },   // sym 155
    .{ .code = 0x3fffd9, .bits = 22 },   // sym 156
    .{ .code = 0x7fffe6, .bits = 23 },   // sym 157
    .{ .code = 0x7fffe7, .bits = 23 },   // sym 158
    .{ .code = 0xffffef, .bits = 24 },   // sym 159
    .{ .code = 0x3fffda, .bits = 22 },   // sym 160
    .{ .code = 0x1fffdd, .bits = 21 },   // sym 161
    .{ .code = 0xfffe9, .bits = 20 },    // sym 162
    .{ .code = 0x3fffdb, .bits = 22 },   // sym 163
    .{ .code = 0x3fffdc, .bits = 22 },   // sym 164
    .{ .code = 0x7fffe8, .bits = 23 },   // sym 165
    .{ .code = 0x7fffe9, .bits = 23 },   // sym 166
    .{ .code = 0x1fffde, .bits = 21 },   // sym 167
    .{ .code = 0x7fffea, .bits = 23 },   // sym 168
    .{ .code = 0x3fffdd, .bits = 22 },   // sym 169
    .{ .code = 0x3fffde, .bits = 22 },   // sym 170
    .{ .code = 0xfffff0, .bits = 24 },   // sym 171
    .{ .code = 0x1fffdf, .bits = 21 },   // sym 172
    .{ .code = 0x3fffdf, .bits = 22 },   // sym 173
    .{ .code = 0x7fffeb, .bits = 23 },   // sym 174
    .{ .code = 0x7fffec, .bits = 23 },   // sym 175
    .{ .code = 0x1fffe0, .bits = 21 },   // sym 176
    .{ .code = 0x1fffe1, .bits = 21 },   // sym 177
    .{ .code = 0x3fffe0, .bits = 22 },   // sym 178
    .{ .code = 0x1fffe2, .bits = 21 },   // sym 179
    .{ .code = 0x7fffed, .bits = 23 },   // sym 180
    .{ .code = 0x3fffe1, .bits = 22 },   // sym 181
    .{ .code = 0x7fffee, .bits = 23 },   // sym 182
    .{ .code = 0x7fffef, .bits = 23 },   // sym 183
    .{ .code = 0xfffea, .bits = 20 },    // sym 184
    .{ .code = 0x3fffe2, .bits = 22 },   // sym 185
    .{ .code = 0x3fffe3, .bits = 22 },   // sym 186
    .{ .code = 0x3fffe4, .bits = 22 },   // sym 187
    .{ .code = 0x7ffff0, .bits = 23 },   // sym 188
    .{ .code = 0x3fffe5, .bits = 22 },   // sym 189
    .{ .code = 0x3fffe6, .bits = 22 },   // sym 190
    .{ .code = 0x7ffff1, .bits = 23 },   // sym 191
    .{ .code = 0x3ffffe0, .bits = 26 },  // sym 192
    .{ .code = 0x3ffffe1, .bits = 26 },  // sym 193
    .{ .code = 0xfffeb, .bits = 20 },    // sym 194
    .{ .code = 0x7fff1, .bits = 19 },    // sym 195
    .{ .code = 0x3fffe7, .bits = 22 },   // sym 196
    .{ .code = 0x7ffff2, .bits = 23 },   // sym 197
    .{ .code = 0x3fffe8, .bits = 22 },   // sym 198
    .{ .code = 0x1ffffec, .bits = 25 },  // sym 199
    .{ .code = 0x3ffffe2, .bits = 26 },  // sym 200
    .{ .code = 0x3ffffe3, .bits = 26 },  // sym 201
    .{ .code = 0x3ffffe4, .bits = 26 },  // sym 202
    .{ .code = 0x7ffffde, .bits = 27 },  // sym 203
    .{ .code = 0x7ffffdf, .bits = 27 },  // sym 204
    .{ .code = 0x3ffffe5, .bits = 26 },  // sym 205
    .{ .code = 0xfffff1, .bits = 24 },   // sym 206
    .{ .code = 0x1ffffed, .bits = 25 },  // sym 207
    .{ .code = 0x7fff2, .bits = 19 },    // sym 208
    .{ .code = 0x1fffe3, .bits = 21 },   // sym 209
    .{ .code = 0x3ffffe6, .bits = 26 },  // sym 210
    .{ .code = 0x7ffffe0, .bits = 27 },  // sym 211
    .{ .code = 0x7ffffe1, .bits = 27 },  // sym 212
    .{ .code = 0x3ffffe7, .bits = 26 },  // sym 213
    .{ .code = 0x7ffffe2, .bits = 27 },  // sym 214
    .{ .code = 0xfffff2, .bits = 24 },   // sym 215
    .{ .code = 0x1fffe4, .bits = 21 },   // sym 216
    .{ .code = 0x1fffe5, .bits = 21 },   // sym 217
    .{ .code = 0x3ffffe8, .bits = 26 },  // sym 218
    .{ .code = 0x3ffffe9, .bits = 26 },  // sym 219
    .{ .code = 0xffffffd, .bits = 28 },  // sym 220
    .{ .code = 0x7ffffe3, .bits = 27 },  // sym 221
    .{ .code = 0x7ffffe4, .bits = 27 },  // sym 222
    .{ .code = 0x7ffffe5, .bits = 27 },  // sym 223
    .{ .code = 0xfffec, .bits = 20 },    // sym 224
    .{ .code = 0xfffff3, .bits = 24 },   // sym 225
    .{ .code = 0xfffed, .bits = 20 },    // sym 226
    .{ .code = 0x1fffe6, .bits = 21 },   // sym 227
    .{ .code = 0x3fffe9, .bits = 22 },   // sym 228
    .{ .code = 0x1fffe7, .bits = 21 },   // sym 229
    .{ .code = 0x1fffe8, .bits = 21 },   // sym 230
    .{ .code = 0x7ffff3, .bits = 23 },   // sym 231
    .{ .code = 0x3fffea, .bits = 22 },   // sym 232
    .{ .code = 0x3fffeb, .bits = 22 },   // sym 233
    .{ .code = 0x1ffffee, .bits = 25 },  // sym 234
    .{ .code = 0x1ffffef, .bits = 25 },  // sym 235
    .{ .code = 0xfffff4, .bits = 24 },   // sym 236
    .{ .code = 0xfffff5, .bits = 24 },   // sym 237
    .{ .code = 0x3ffffea, .bits = 26 },  // sym 238
    .{ .code = 0x7ffff4, .bits = 23 },   // sym 239
    .{ .code = 0x3ffffeb, .bits = 26 },  // sym 240
    .{ .code = 0x7ffffe6, .bits = 27 },  // sym 241
    .{ .code = 0x3ffffec, .bits = 26 },  // sym 242
    .{ .code = 0x3ffffed, .bits = 26 },  // sym 243
    .{ .code = 0x7ffffe7, .bits = 27 },  // sym 244
    .{ .code = 0x7ffffe8, .bits = 27 },  // sym 245
    .{ .code = 0x7ffffe9, .bits = 27 },  // sym 246
    .{ .code = 0x7ffffea, .bits = 27 },  // sym 247
    .{ .code = 0x7ffffeb, .bits = 27 },  // sym 248
    .{ .code = 0xffffffe, .bits = 28 },  // sym 249
    .{ .code = 0x7ffffec, .bits = 27 },  // sym 250
    .{ .code = 0x7ffffed, .bits = 27 },  // sym 251
    .{ .code = 0x7ffffee, .bits = 27 },  // sym 252
    .{ .code = 0x7ffffef, .bits = 27 },  // sym 253
    .{ .code = 0x7fffff0, .bits = 27 },  // sym 254
    .{ .code = 0x3ffffee, .bits = 26 },  // sym 255
    .{ .code = 0x3fffffff, .bits = 30 }, // sym 256 (EOS)
};

comptime {
    std.debug.assert(encode_table.len == 257);
    // EOS is the longest code (30 bits).
    std.debug.assert(encode_table[EOS].bits == 30);
}

/// Returns the number of bytes needed to Huffman-encode `str`.
pub fn encodedLen(str: []const u8) usize {
    var bits: usize = 0;
    for (str) |c| bits += encode_table[c].bits;
    return (bits + 7) / 8;
}

/// Huffman-encodes `str` into `dst`.
/// `dst` must be at least `encodedLen(str)` bytes long.
/// Returns bytes written.
pub fn encode(str: []const u8, dst: []u8) error{BufferTooSmall}!usize {
    const needed = encodedLen(str);
    if (dst.len < needed) return error.BufferTooSmall;

    var bit_buf: u64 = 0;
    var bit_count: u6 = 0;
    var out: usize = 0;

    for (str) |c| {
        const entry = encode_table[c];
        // Accumulate bits (codes are MSB-first, packed left to right).
        bit_buf = (bit_buf << @as(u6, entry.bits)) | @as(u64, entry.code);
        bit_count += @as(u6, entry.bits);

        // Flush complete bytes from the top of bit_buf.
        while (bit_count >= 8) {
            bit_count -= 8;
            dst[out] = @as(u8, @truncate(bit_buf >> bit_count));
            out += 1;
        }

        // Keep only the remaining valid bits (clear garbage above them).
        if (bit_count > 0) {
            bit_buf &= (@as(u64, 1) << bit_count) - 1;
        } else {
            bit_buf = 0;
        }
    }

    // Pad the final partial byte with 1s (RFC 7541 §5.2).
    if (bit_count > 0) {
        const pad: u6 = 8 - bit_count;
        dst[out] = @as(u8, @truncate((bit_buf << pad) | ((@as(u64, 1) << pad) - 1)));
        out += 1;
    }

    return out;
}

/// Huffman-decodes `src` into `dst`.
/// Returns the number of bytes written to `dst`.
pub fn decode(src: []const u8, dst: []u8) error{ InvalidCode, BufferTooSmall, EosInValue }!usize {
    var bit_buf: u64 = 0;
    var bit_count: u6 = 0; // number of valid bits in bit_buf (0-56)
    var src_pos: usize = 0;
    var out: usize = 0;

    while (true) {
        // Refill: keep at least 48 bits available when input remains.
        while (@as(u7, bit_count) <= 48 and src_pos < src.len) {
            bit_buf = (bit_buf << 8) | src[src_pos];
            bit_count += 8;
            src_pos += 1;
        }

        if (bit_count == 0) break;

        // Scan for a matching Huffman symbol.
        var matched = false;
        for (encode_table, 0..) |entry, sym| {
            if (@as(u7, entry.bits) > @as(u7, bit_count)) continue;
            const shift: u6 = bit_count - @as(u6, entry.bits);
            const mask: u64 = (@as(u64, 1) << @as(u6, entry.bits)) - 1;
            if ((bit_buf >> shift) & mask == entry.code) {
                if (sym == EOS) return error.EosInValue;
                if (out >= dst.len) return error.BufferTooSmall;
                dst[out] = @intCast(sym);
                out += 1;
                bit_count -= @as(u6, entry.bits);
                bit_buf = if (bit_count > 0)
                    bit_buf & ((@as(u64, 1) << bit_count) - 1)
                else
                    0;
                matched = true;
                break;
            }
        }

        if (!matched) {
            // Valid end: remaining bits are all-1s padding (≤ 7 bits, src exhausted).
            if (src_pos >= src.len and @as(u7, bit_count) <= 7) {
                const mask: u64 = (@as(u64, 1) << bit_count) - 1;
                if (bit_buf & mask == mask) break;
            }
            return error.InvalidCode;
        }
    }

    return out;
}

// ----------------------------------------------------------------------------
// Tests — RFC 7541 §C.4 Huffman examples
// ----------------------------------------------------------------------------

test "encode table has 257 entries" {
    try std.testing.expectEqual(@as(usize, 257), encode_table.len);
}

test "encodedLen: www.example.com" {
    // RFC 7541 §C.4.1: "www.example.com" → 12 bytes Huffman
    try std.testing.expectEqual(@as(usize, 12), encodedLen("www.example.com"));
}

test "encode: www.example.com matches RFC 7541 §C.4.1" {
    // Expected: f1 e3 c2 e5 f2 3a 6b a0 ab 90 f4 ff
    var buf: [64]u8 = undefined;
    const n = try encode("www.example.com", &buf);
    const expected = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    try std.testing.expectEqual(@as(usize, 12), n);
    try std.testing.expectEqualSlices(u8, &expected, buf[0..n]);
}

test "encode: no-cache matches RFC 7541 §C.4.2" {
    // "no-cache" → a8 eb 10 64 9c bf
    var buf: [64]u8 = undefined;
    const n = try encode("no-cache", &buf);
    const expected = [_]u8{ 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
    try std.testing.expectEqual(@as(usize, 6), n);
    try std.testing.expectEqualSlices(u8, &expected, buf[0..n]);
}

test "encode: custom-key matches RFC 7541 §C.4.3" {
    // "custom-key" → 25 a8 49 e9 5b a9 7d 7f
    var buf: [64]u8 = undefined;
    const n = try encode("custom-key", &buf);
    const expected = [_]u8{ 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f };
    try std.testing.expectEqual(@as(usize, 8), n);
    try std.testing.expectEqualSlices(u8, &expected, buf[0..n]);
}

test "encode: custom-value matches RFC 7541 §C.4.3" {
    // "custom-value" → 25 a8 49 e9 5b b8 e8 b4 bf
    var buf: [64]u8 = undefined;
    const n = try encode("custom-value", &buf);
    const expected = [_]u8{ 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf };
    try std.testing.expectEqual(@as(usize, 9), n);
    try std.testing.expectEqualSlices(u8, &expected, buf[0..n]);
}

test "decode: www.example.com" {
    const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var dst: [64]u8 = undefined;
    const n = try decode(&encoded, &dst);
    try std.testing.expectEqualStrings("www.example.com", dst[0..n]);
}

test "encode/decode round-trip" {
    const strings = [_][]const u8{
        "GET",
        "https",
        "/index.html",
        "application/json",
        "text/html; charset=utf-8",
        "no-cache",
        "max-age=3600",
    };
    var enc_buf: [256]u8 = undefined;
    var dec_buf: [256]u8 = undefined;
    for (strings) |s| {
        const enc_len = try encode(s, &enc_buf);
        const dec_len = try decode(enc_buf[0..enc_len], &dec_buf);
        try std.testing.expectEqualStrings(s, dec_buf[0..dec_len]);
    }
}
