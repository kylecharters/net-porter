const std = @import("std");
const json = std.json;
const log = std.log.scoped(.responser);
const Responser = @This();

io: std.Io,
stream: *std.Io.net.Stream,
log_response: bool = false,
done: bool = false,
is_error: bool = false,

const stringify_options = json.Stringify.Options{
    .whitespace = .indent_2,
};

pub fn writeError(self: *Responser, comptime fmt: []const u8, args: anytype) void {
    if (self.done) {
        log.info("Response already sent, ignoring error: {s}", .{fmt});
        return;
    }

    var buf: [1024]u8 = undefined;

    const error_msg = std.fmt.bufPrint(&buf, fmt, args) catch
        "error: internal error message too long";

    log.warn("{s}", .{error_msg});

    var write_buffer: [4096]u8 = undefined;
    var stream_writer = self.stream.writer(self.io, &write_buffer);
    json.Stringify.value(
        .{ .@"error" = error_msg },
        stringify_options,
        &stream_writer.interface,
    ) catch |err| {
        log.warn("Failed to send error message: {s}", .{@errorName(err)});
        return;
    };
    stream_writer.interface.flush() catch |err| {
        log.warn("Failed to flush error message: {s}", .{@errorName(err)});
    };

    self.is_error = true;
    self.done = true;
}

pub fn write(self: *Responser, response: anytype) void {
    if (self.done) {
        log.warn("Response already sent, ignoring new response", .{});
        return;
    }

    if (@TypeOf(response) == []const u8) {
        var write_buffer: [4096]u8 = undefined;
        var stream_writer = self.stream.writer(self.io, &write_buffer);
        stream_writer.interface.writeAll(response) catch |err| {
            self.writeError("Failed to send response: {s}", .{@errorName(err)});
        };
        stream_writer.interface.flush() catch |err| {
            log.warn("Failed to flush response: {s}", .{@errorName(err)});
        };
        self.done = true;
        return;
    }

    var write_buffer: [4096]u8 = undefined;
    var stream_writer = self.stream.writer(self.io, &write_buffer);
    json.Stringify.value(
        response,
        stringify_options,
        &stream_writer.interface,
    ) catch |err| {
        self.writeError("Failed to format response: {s}", .{@errorName(err)});
        return;
    };
    stream_writer.interface.flush() catch |err| {
        log.warn("Failed to flush response: {s}", .{@errorName(err)});
    };

    self.done = true;

    if (self.log_response) {
        var log_buffer: [4096]u8 = undefined;
        var file_writer = std.Io.File.stdout().writer(self.io, &log_buffer);
        json.Stringify.value(
            response,
            stringify_options,
            &file_writer.interface,
        ) catch {};
        file_writer.end() catch {};
    }
}

// === flush-failure tests ===
//
// write() must always converge to `done == true` even when the underlying
// stream is broken (peer closed). A flush failure on the bytes path is
// logged and suppressed; on the JSON path it is also logged and suppressed.
// Neither path may panic or leave `done == false`, otherwise Handler.handle
// would emit a spurious second response.

/// Create a connected AF_UNIX socketpair. Returns error.SkipZigTest if the
/// kernel rejects the call. Caller owns both fds and must close them.
fn openTestSocketpair(fds: *[2]std.os.linux.fd_t) !void {
    const rc = std.os.linux.socketpair(
        std.os.linux.AF.UNIX,
        std.os.linux.SOCK.STREAM | std.os.linux.SOCK.CLOEXEC,
        0,
        fds,
    );
    if (std.os.linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
}

test "Responser write bytes handles flush failure" {
    var fds: [2]std.os.linux.fd_t = undefined;
    try openTestSocketpair(&fds);
    defer _ = std.os.linux.close(fds[0]);

    // Close the peer so the subsequent flush on fds[0] fails (EPIPE /
    // ECONNRESET). write() must not panic and must mark itself done.
    _ = std.os.linux.close(fds[1]);

    var stream: std.Io.net.Stream = .{
        .socket = .{
            .handle = fds[0],
            .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        },
    };
    var responser = Responser{ .io = std.testing.io, .stream = &stream };

    responser.write("some success response");

    try std.testing.expect(responser.done);
}

test "Responser write json handles flush failure" {
    var fds: [2]std.os.linux.fd_t = undefined;
    try openTestSocketpair(&fds);
    defer _ = std.os.linux.close(fds[0]);
    _ = std.os.linux.close(fds[1]);

    var stream: std.Io.net.Stream = .{
        .socket = .{
            .handle = fds[0],
            .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        },
    };
    var responser = Responser{ .io = std.testing.io, .stream = &stream };

    // A small JSON value: stringify fills the buffer, flush fails because
    // the peer was closed. done must be set so Handler does not re-emit.
    responser.write(json.Value{ .string = "ok" });

    try std.testing.expect(responser.done);
    // Flush failure on the success path is logged, not promoted to an
    // error response — is_error must stay false.
    try std.testing.expect(!responser.is_error);
}
