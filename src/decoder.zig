const std = @import("std");
const io = std.io;

const constants = @import("constants.zig");
const Tag = @import("tag.zig").Tag;

pub fn Decoder(comptime ReaderType: type) type {
    return struct {
        reader: ReaderType,

        pub fn init(reader: ReaderType) @This() {
            return .{ .reader = reader };
        }

        pub fn parse(self: @This(), comptime T: type) !?T {
            const version = try self.reader.readByte();

            if (version != constants.VersionNumber) {
                return error.InvalidVersionNumber;
            }

            const tag: Tag = @enumFromInt(try self.reader.readByte());

            std.debug.print("TAG: {}, {}\n", .{ tag, @intFromEnum(tag) });

            return switch (tag) {
                .small_integer_ext, .integer_ext => {
                    if (comptime @typeInfo(T) != .int) unreachable;
                    const size = comptime @sizeOf(T);
                    var bytes: [size]u8 = undefined;
                    _ = try self.reader.read(&bytes);
                    return std.mem.readInt(T, bytes[0..size], .big);
                },
                .float_ext => unreachable,
                .port_ext => unreachable,
                .new_port_ext => unreachable,
                .v4_port_ext => unreachable,
                .pid_ext => unreachable,
                .new_pid_ext => unreachable,
                .small_tuple_ext => unreachable,
                .large_tuple_ext => unreachable,
                .map_ext => unreachable,
                .nil_ext => return null,
                .string_ext => unreachable,
                .list_ext => unreachable,
                .binary_ext => {
                    if (comptime @typeInfo(T) != .pointer) unreachable;
                    return try self.parseBinaryData();
                },
                .small_big_ext => unreachable,
                .large_big_ext => unreachable,
                .reference_ext => unreachable,
                .new_reference_ext => unreachable,
                .newer_reference_ext => unreachable,
                .new_fun_ext => unreachable,
                .export_ext => unreachable,
                .bit_binary_ext => unreachable,
                .new_float_ext => {
                    if (comptime @typeInfo(T) != .float) unreachable;
                    const size = comptime @sizeOf(T);
                    var bytes: [size]u8 = undefined;
                    _ = try self.reader.read(&bytes);
                    return @bitCast(@byteSwap(std.mem.bytesToValue(u64, bytes[0..size])));
                },
                .atom_utf8_ext => unreachable,
                .small_atom_utf8_ext => unreachable,
                .atom_ext => unreachable,
                .small_atom_ext => unreachable,
                // else => error.UnknownTag,
            };
        }

        fn parseBinaryData(self: @This()) ![]u8 {
            var lengthBuf: [4]u8 = undefined;
            _ = try self.reader.read(&lengthBuf);
            const length = std.mem.readInt(u32, lengthBuf[0..4], .big);
            var data: [length]u8 = undefined;
            _ = try self.reader.read(&data);

            return data;
        }
    };
}

test "SMALL_INTEGER_EXT" {
    var stream = io.fixedBufferStream(&[_]u8{ 0x83, 0x61, 0xFF });
    const reader = stream.reader();
    const decoder = Decoder(@TypeOf(reader)).init(reader);

    const parsed = try decoder.parse(u8);
    try std.testing.expectEqual(std.math.maxInt(u8), parsed);
}

test "INTEGER_EXT" {
    var stream = io.fixedBufferStream(&[_]u8{ 0x83, 0x62, 0x7F, 0xFF, 0xFF, 0xFF });
    const reader = stream.reader();
    const decoder = Decoder(@TypeOf(reader)).init(reader);

    const parsed = try decoder.parse(i32);
    try std.testing.expectEqual(std.math.maxInt(i32), parsed);
}

test "FLOAT_EXT" {
    var stream = io.fixedBufferStream(&[_]u8{ 0x83, 0x63, 0x33, 0x2E, 0x31, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x32, 0x34, 0x33, 0x34, 0x65, 0x2B, 0x30, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0 });
    const reader = stream.reader();
    const decoder = Decoder(@TypeOf(reader)).init(reader);

    const parsed = try decoder.parse(f64);
    _ = parsed;
}

test "NEW_FLOAT_EXT" {
    var stream = io.fixedBufferStream(&[_]u8{ 0x83, 0x46, 0x40, 0x9, 0x1E, 0xB8, 0x51, 0xEB, 0x85, 0x1F });
    const reader = stream.reader();
    const decoder = Decoder(@TypeOf(reader)).init(reader);

    const parsed = try decoder.parse(f64);
    try std.testing.expectEqual(3.14, parsed);
}

test "BINARY_EXT" {
    var stream = io.fixedBufferStream(&[_]u8{ 0x83, 0x6D, 0x0, 0x0, 0x0, 0xB, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x20, 0x77, 0x6F, 0x72, 0x6C, 0x64 });
    const reader = stream.reader();
    const decoder = Decoder(@TypeOf(reader)).init(reader);

    const parsed = try decoder.parse([]u8);

    std.debug.print("parsed: {s}\n", .{parsed});
}
