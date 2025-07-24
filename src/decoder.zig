const std = @import("std");
const io = std.io;
const mem = std.mem;

const constants = @import("constants.zig");
const Tag = @import("tag.zig").Tag;

pub fn Decoder(comptime ReaderType: type) type {
    return struct {
        reader: ReaderType,

        pub fn init(reader: ReaderType) @This() {
            return .{ .reader = reader };
        }

        pub fn parse(self: @This(), comptime T: type, allocator: mem.Allocator) !?T {
            const version = try self.reader.readByte();

            if (version != constants.VersionNumber) {
                return error.InvalidVersionNumber;
            }

            const tag: Tag = @enumFromInt(try self.reader.readByte());

            std.debug.print("TAG: {}, {}\n", .{ tag, @intFromEnum(tag) });

            return switch (tag) {
                .small_integer_ext, .integer_ext => {
                    const info = comptime @typeInfo(T);
                    if (comptime (info == .int or info == .comptime_int) == false) unreachable;
                    const size = comptime @sizeOf(T);
                    var bytes: [size]u8 = undefined;
                    _ = try self.reader.read(&bytes);
                    return std.mem.readInt(T, bytes[0..size], .big);
                },
                .float_ext => {
                    if (comptime T != f32) unreachable;
                    return try self.parseFloat32(allocator);
                },
                .port_ext => unreachable,
                .new_port_ext => unreachable,
                .v4_port_ext => {
                    const node = try self.parseAtom(allocator);
                    std.debug.print("{s}\n", .{node});
                    unreachable;
                },
                .pid_ext => unreachable,
                .new_pid_ext => unreachable,
                .small_tuple_ext => unreachable,
                .large_tuple_ext => unreachable,
                .map_ext => unreachable,
                .nil_ext => return null,
                .string_ext => {
                    if (comptime (T == []const u8 or T == []u8) == false) unreachable;
                    var buf: [2]u8 = undefined;
                    _ = try self.reader.read(&buf);
                    const length = std.mem.readInt(u16, buf[0..2], .big);
                    return try self.parseString(T, allocator, length);
                },
                .list_ext => unreachable,
                .binary_ext => {
                    if (comptime (T == []const u8 or T == []u8) == false) unreachable;
                    var buf: [4]u8 = undefined;
                    _ = try self.reader.read(&buf);
                    const length = std.mem.readInt(u32, buf[0..4], .big);
                    return try self.parseBinaryData(T, allocator, length);
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
                    if (comptime T != f64) unreachable;
                    return try self.parseFloat64();
                },
                .atom_utf8_ext => unreachable,
                .small_atom_utf8_ext => unreachable,
                .atom_ext => unreachable,
                .small_atom_ext => unreachable,
                // else => error.UnknownTag,
            };
        }

        fn parseFloat32(self: @This(), allocator: mem.Allocator) !f32 {
            const floatString = try self.parseString([]const u8, allocator, 31);
            defer allocator.free(floatString);
            const trimmed = std.mem.trimRight(u8, floatString, &[_]u8{0});
            return try std.fmt.parseFloat(f32, trimmed);
        }

        fn parseFloat64(self: @This()) !f64 {
            var buf: [8]u8 = undefined;
            _ = try self.reader.read(&buf);
            return @bitCast(@byteSwap(std.mem.bytesToValue(u64, buf[0..8])));
        }

        fn parseBinaryData(self: @This(), comptime T: type, allocator: mem.Allocator, len: usize) !T {
            const data = try allocator.alloc(u8, len);
            _ = try self.reader.read(data);
            return data;
        }

        fn parseString(self: @This(), comptime T: type, allocator: mem.Allocator, len: usize) !T {
            const data = try allocator.alloc(u8, len);
            _ = try self.reader.read(data);
            return data;
        }

        fn parseAtom(self: @This(), allocator: mem.Allocator) ![]const u8 {
            _ = try self.reader.readByte();
            const length: u8 = try self.reader.readByte();
            std.debug.print("length: {}\n", .{length});
            return self.parseString([]const u8, allocator, length);
        }
    };
}

test "SMALL_INTEGER_EXT" {
    const allocator = std.testing.allocator;
    var stream = io.fixedBufferStream(&[_]u8{ 0x83, 0x61, 0xFF });
    const reader = stream.reader();
    const decoder = Decoder(@TypeOf(reader)).init(reader);

    const parsed = try decoder.parse(u8, allocator);
    try std.testing.expectEqual(std.math.maxInt(u8), parsed.?);
}

test "INTEGER_EXT" {
    const allocator = std.testing.allocator;
    var stream = io.fixedBufferStream(&[_]u8{ 0x83, 0x62, 0x7F, 0xFF, 0xFF, 0xFF });
    const reader = stream.reader();
    const decoder = Decoder(@TypeOf(reader)).init(reader);

    const parsed = try decoder.parse(i32, allocator);
    try std.testing.expectEqual(std.math.maxInt(i32), parsed.?);
}

test "FLOAT_EXT" {
    const allocator = std.testing.allocator;
    var stream = io.fixedBufferStream(&[_]u8{ 0x83, 0x63, 0x33, 0x2E, 0x31, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31, 0x32, 0x34, 0x33, 0x34, 0x65, 0x2B, 0x30, 0x30, 0x0, 0x0, 0x0, 0x0, 0x0 });
    const reader = stream.reader();
    const decoder = Decoder(@TypeOf(reader)).init(reader);

    const parsed = try decoder.parse(f32, allocator);
    if (parsed) |p| {
        try std.testing.expectEqual(3.14, p);
    }
}

test "NEW_FLOAT_EXT" {
    const allocator = std.testing.allocator;
    var stream = io.fixedBufferStream(&[_]u8{ 0x83, 0x46, 0x40, 0x9, 0x1E, 0xB8, 0x51, 0xEB, 0x85, 0x1F });
    const reader = stream.reader();
    const decoder = Decoder(@TypeOf(reader)).init(reader);

    const parsed = try decoder.parse(f64, allocator);
    try std.testing.expectEqual(3.14, parsed.?);
}

test "BINARY_EXT" {
    const allocator = std.testing.allocator;
    var stream = io.fixedBufferStream(&[_]u8{ 0x83, 0x6D, 0x0, 0x0, 0x0, 0x3, 0x7A, 0x69, 0x67 });
    const reader = stream.reader();
    const decoder = Decoder(@TypeOf(reader)).init(reader);

    const parsed = try decoder.parse([]u8, allocator);
    if (parsed) |p| {
        defer allocator.free(p);

        try std.testing.expectEqualStrings("zig", p);
    }
}

test "V4_PORT_EX" {
    const allocator = std.testing.allocator;
    var stream = io.fixedBufferStream(&[_]u8{ 0x83, 0x78, 0x77, 0x0D, 0x6E, 0x6F, 0x6E, 0x6F, 0x64, 0x65, 0x40, 0x6E, 0x6F, 0x68, 0x6F, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 });
    const reader = stream.reader();
    const decoder = Decoder(@TypeOf(reader)).init(reader);

    const V4PortExt = struct {};
    const parsed = try decoder.parse(V4PortExt, allocator);

    if (parsed) |p| {
        std.debug.print("{any}\n", .{p});
    }
}
