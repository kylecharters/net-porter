//! Server-side ACL scanner.
//!
//! Scans acl.d/ for <username>.json files and resolves to UIDs.
//! Used by Server to determine which UIDs need workers.
//!
//! File naming convention:
//!   User:           acl.d/<username>.json   — scanned for UID resolution
//!   Rule collection: acl.d/@<name>.json     — ignored by scanner (not a user)
//!
//! The server does NOT parse ACL grants or watch for changes.
//! Workers handle their own ACL loading and hot-reloading.

const std = @import("std");
const log = std.log.scoped(.acl_manager);
const Allocator = std.mem.Allocator;
const user_mod = @import("../user.zig");
const AclScanner = @This();

allocator: Allocator,
acl_dir: []const u8,

pub fn init(allocator: Allocator, acl_dir: []const u8) AclScanner {
    return .{
        .allocator = allocator,
        .acl_dir = acl_dir,
    };
}

/// Result of an ACL scan: resolved UIDs plus usernames that could not be
/// resolved to a UID (the user did not exist in NSS at scan time).
///
/// Ownership:
///   - `uids` is caller-owned; pass to `UidTracker.updateAllowedUids` or
///     deinit via `ScanResult.deinit`.
///   - `unresolved` holds allocator-owned strings. Free via `ScanResult.deinit`
///     (which frees both lists) or manually if `uids` ownership is transferred.
pub const ScanResult = struct {
    uids: std.ArrayList(u32),
    unresolved: std.ArrayList([]const u8),

    pub fn deinit(self: *ScanResult, allocator: Allocator) void {
        self.uids.deinit(allocator);
        for (self.unresolved.items) |name| allocator.free(name);
        self.unresolved.deinit(allocator);
    }
};

/// Scan acl.d/ for <username>.json files and resolve to UIDs.
/// Skips files starting with '@' (rule collection files, not users).
/// Returns a list of deduplicated UIDs.
pub fn scanUids(self: AclScanner, io: std.Io) std.ArrayList(u32) {
    var uid_set = std.AutoHashMap(u32, void).init(self.allocator);
    defer uid_set.deinit();

    var dir = std.Io.Dir.cwd().openDir(io, self.acl_dir, .{ .iterate = true }) catch |err| {
        log.warn("Failed to open ACL directory '{s}': {s}", .{ self.acl_dir, @errorName(err) });
        return .empty;
    };
    defer dir.close(io);

    var iter = dir.iterate();
    while (iter.next(io) catch |err| blk: {
        log.warn("Failed to read entry from ACL directory '{s}': {s}", .{ self.acl_dir, @errorName(err) });
        break :blk null;
    }) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".json")) continue;
        // Skip rule collection files (@<name>.json)
        if (entry.name.len > 0 and entry.name[0] == '@') continue;

        // Extract username: <name>.json → <name>
        const name = entry.name[0 .. entry.name.len - ".json".len];

        if (!user_mod.isValidUsername(name)) {
            log.warn("Skipping ACL file with invalid username '{s}'", .{name});
            continue;
        }

        // Resolve username to UID
        const name_z = self.allocator.dupeZ(u8, name) catch continue;
        defer self.allocator.free(name_z);

        if (user_mod.getUid(name_z)) |uid| {
            uid_set.put(uid, {}) catch {};
        } else {
            log.warn("Failed to resolve username '{s}' to UID, skipping", .{name});
        }
    }

    var result = std.ArrayList(u32).initCapacity(self.allocator, uid_set.count()) catch return .empty;
    var it = uid_set.keyIterator();
    while (it.next()) |uid| {
        result.appendAssumeCapacity(uid.*);
    }
    return result;
}

/// Like `scanUids` but also returns usernames that could not be resolved to a
/// UID. The server tracks unresolved usernames so it can recover when the user
/// is later (re)created and a `/run/user/<uid>` directory appears.
///
/// Both `uids` and `unresolved` are deduplicated. The `unresolved` list holds
/// allocator-owned strings (see `ScanResult` ownership notes).
pub fn scanUidsWithUnresolved(self: AclScanner, io: std.Io) ScanResult {
    var uid_set = std.AutoHashMap(u32, void).init(self.allocator);
    defer uid_set.deinit();

    var unresolved_set = std.StringHashMap(void).init(self.allocator);
    defer unresolved_set.deinit();

    var dir = std.Io.Dir.cwd().openDir(io, self.acl_dir, .{ .iterate = true }) catch |err| {
        log.warn("Failed to open ACL directory '{s}': {s}", .{ self.acl_dir, @errorName(err) });
        return .{ .uids = .empty, .unresolved = .empty };
    };
    defer dir.close(io);

    var iter = dir.iterate();
    while (iter.next(io) catch |err| blk: {
        log.warn("Failed to read entry from ACL directory '{s}': {s}", .{ self.acl_dir, @errorName(err) });
        break :blk null;
    }) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.name, ".json")) continue;
        // Skip rule collection files (@<name>.json)
        if (entry.name.len > 0 and entry.name[0] == '@') continue;

        // Extract username: <name>.json → <name>
        const name = entry.name[0 .. entry.name.len - ".json".len];

        if (!user_mod.isValidUsername(name)) {
            log.warn("Skipping ACL file with invalid username '{s}'", .{name});
            continue;
        }

        // Resolve username to UID
        const name_z = self.allocator.dupeZ(u8, name) catch continue;
        defer self.allocator.free(name_z);

        if (user_mod.getUid(name_z)) |uid| {
            uid_set.put(uid, {}) catch {};
        } else {
            // Username could not be resolved (user may not exist yet). Track
            // the name so the server can recover when the user is created.
            const owned = self.allocator.dupe(u8, name) catch continue;
            unresolved_set.put(owned, {}) catch {
                self.allocator.free(owned);
            };
        }
    }

    var uids = std.ArrayList(u32).initCapacity(self.allocator, uid_set.count()) catch {
        freeUnresolvedKeys(&unresolved_set, self.allocator);
        return .{ .uids = .empty, .unresolved = .empty };
    };
    var uid_it = uid_set.keyIterator();
    while (uid_it.next()) |uid| {
        uids.appendAssumeCapacity(uid.*);
    }

    var unresolved = std.ArrayList([]const u8).initCapacity(self.allocator, unresolved_set.count()) catch {
        freeUnresolvedKeys(&unresolved_set, self.allocator);
        uids.deinit(self.allocator);
        return .{ .uids = .empty, .unresolved = .empty };
    };
    // Transfer ownership of the duplicated strings from the set to the list.
    var unres_it = unresolved_set.keyIterator();
    while (unres_it.next()) |key| {
        unresolved.appendAssumeCapacity(key.*);
    }

    return .{ .uids = uids, .unresolved = unresolved };
}

/// Free the owned key strings of an unresolved-name set without freeing the
/// keys' backing storage elsewhere. `std.StringHashMap.deinit` only releases
/// the map's internal entries, not the key strings themselves.
fn freeUnresolvedKeys(set: *std.StringHashMap(void), allocator: Allocator) void {
    var it = set.keyIterator();
    while (it.next()) |key| allocator.free(key.*);
}

// ============================================================
// Tests
// ============================================================

test "AclScanner: scanUids with no directory returns empty" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var manager = init(allocator, "/nonexistent/acl/directory");

    var uids = manager.scanUids(io);
    defer uids.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), uids.items.len);
}

/// Helper to create a temporary directory for ACL testing.
pub const TestAclDir = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    dir_path: []const u8,

    pub fn create(io: std.Io, allocator: std.mem.Allocator) !TestAclDir {
        const seed: u64 = seed: {
            var seed_bytes: [8]u8 = undefined;
            io.random(&seed_bytes);
            break :seed std.mem.readInt(u64, &seed_bytes, .little);
        };
        var prng = std.Random.DefaultPrng.init(seed);
        const rand = prng.random().int(u64);
        const dir_path = try std.fmt.allocPrint(allocator, "/tmp/acl-scan-test-{x:0>16}", .{rand});
        try std.Io.Dir.cwd().createDirPath(io, dir_path);
        return TestAclDir{ .io = io, .allocator = allocator, .dir_path = dir_path };
    }

    pub fn deinit(self: TestAclDir) void {
        var dir = std.Io.Dir.cwd().openDir(self.io, self.dir_path, .{ .iterate = true }) catch return;
        defer dir.close(self.io);
        var iter = dir.iterate();
        while (iter.next(self.io) catch null) |entry| {
            dir.deleteFile(self.io, entry.name) catch {};
        }
        std.Io.Dir.cwd().deleteDir(self.io, self.dir_path) catch {};
        self.allocator.free(self.dir_path);
    }

    pub fn writeFile(self: TestAclDir, filename: []const u8, content: []const u8) !void {
        var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const file_path = std.fmt.bufPrint(&buf, "{s}/{s}", .{ self.dir_path, filename }) catch return;
        const file = try std.Io.Dir.cwd().createFile(self.io, file_path, .{});
        defer file.close(self.io);
        var write_buffer: [4096]u8 = undefined;
        var writer = file.writer(self.io, &write_buffer);
        writer.interface.writeAll(content) catch return;
        writer.end() catch return;
    }
};

test "AclScanner: scanUids skips group files and non-json files" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var test_dir = try TestAclDir.create(io, allocator);
    defer test_dir.deinit();

    // Create files — only root.json should resolve (uid 0)
    try test_dir.writeFile("root.json", "{}");
    try test_dir.writeFile("@group.json", "{}");
    try test_dir.writeFile("readme.txt", "ignored");

    var manager = init(allocator, test_dir.dir_path);

    var uids = manager.scanUids(io);
    defer uids.deinit(allocator);

    // root should resolve to uid 0
    try std.testing.expectEqual(@as(usize, 1), uids.items.len);
    try std.testing.expect(uids.items[0] == 0);
}

test "AclScanner: scanUids with empty directory returns empty" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var test_dir = try TestAclDir.create(io, allocator);
    defer test_dir.deinit();

    var manager = init(allocator, test_dir.dir_path);

    var uids = manager.scanUids(io);
    defer uids.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), uids.items.len);
}

test "AclScanner: scanUidsWithUnresolved returns resolved UIDs and empty unresolved for resolvable users" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var test_dir = try TestAclDir.create(io, allocator);
    defer test_dir.deinit();

    try test_dir.writeFile("root.json", "{}");
    try test_dir.writeFile("@group.json", "{}");

    var manager = init(allocator, test_dir.dir_path);

    var scan_result = manager.scanUidsWithUnresolved(io);
    defer scan_result.deinit(allocator);

    // root resolves to uid 0
    try std.testing.expectEqual(@as(usize, 1), scan_result.uids.items.len);
    try std.testing.expect(scan_result.uids.items[0] == 0);
    // No unresolved usernames since root resolves
    try std.testing.expectEqual(@as(usize, 0), scan_result.unresolved.items.len);
}

test "AclScanner: scanUidsWithUnresolved tracks unresolvable usernames" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var test_dir = try TestAclDir.create(io, allocator);
    defer test_dir.deinit();

    // root resolves; this fake username does not exist in NSS so it should be
    // reported as unresolved.
    try test_dir.writeFile("root.json", "{}");
    try test_dir.writeFile("definitelynotauser_xyz.json", "{}");

    var manager = init(allocator, test_dir.dir_path);

    var scan_result = manager.scanUidsWithUnresolved(io);
    defer scan_result.deinit(allocator);

    // Only root resolves to a UID
    try std.testing.expectEqual(@as(usize, 1), scan_result.uids.items.len);
    try std.testing.expect(scan_result.uids.items[0] == 0);

    // The fake username should appear in unresolved
    try std.testing.expectEqual(@as(usize, 1), scan_result.unresolved.items.len);
    try std.testing.expectEqualStrings("definitelynotauser_xyz", scan_result.unresolved.items[0]);
}

test "AclScanner: scanUidsWithUnresolved deduplicates unresolved usernames" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var test_dir = try TestAclDir.create(io, allocator);
    defer test_dir.deinit();

    // Two files with the same unresolvable username cannot coexist (same path),
    // but a single unresolvable name should appear exactly once.
    try test_dir.writeFile("definitelynotauser_abc.json", "{}");

    var manager = init(allocator, test_dir.dir_path);

    var scan_result = manager.scanUidsWithUnresolved(io);
    defer scan_result.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 0), scan_result.uids.items.len);
    try std.testing.expectEqual(@as(usize, 1), scan_result.unresolved.items.len);
}
