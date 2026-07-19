const std = @import("std");
const log = std.log.scoped(.server);
const config_mod = @import("../config.zig");
const version = @import("build_options").version;
const AclScanner = @import("AclScanner.zig");
const AclWatcher = @import("AclWatcher.zig");
const WorkerManager = @import("../worker/WorkerManager.zig");
const UidTracker = @import("UidTracker.zig");
const user_mod = @import("../user.zig");

const Server = @This();

config: config_mod.Config,
io: std.Io,
acl_manager: AclScanner,
acl_watcher: AclWatcher,
worker_manager: WorkerManager,
uid_tracker: UidTracker,
managed_config: config_mod.ManagedConfig,
/// Usernames from ACL files that could not be resolved to a UID at the last
/// scan (the user did not exist in NSS). Used to recover workers when a user
/// is (re)created and its `/run/user/<uid>` appears. Keys are owned by the
/// map and freed in `deinit` / replaced in `handleAclChange`.
unresolved_usernames: std.StringHashMap(void),

pub const Opts = struct {
    config_path: ?[]const u8 = null,
    io: ?std.Io = null,
    /// Root allocator for all server-owned allocations. When null, falls back
    /// to std.heap.page_allocator (no leak detection). Callers should pass a
    /// DebugAllocator in Debug/ReleaseSafe builds for memory safety checks.
    allocator: ?std.mem.Allocator = null,
};

pub fn new(opts: Opts) !Server {
    const io = opts.io orelse return error.IoNotInitialized;
    // Use caller-provided allocator (typically DebugAllocator for leak detection),
    // falling back to page_allocator when unset (e.g., legacy callers).
    const allocator = opts.allocator orelse std.heap.page_allocator;

    var managed_config = config_mod.ManagedConfig.load(
        io,
        allocator,
        opts.config_path,
    ) catch |e| {
        log.err(
            "Failed to read config file: {s}, error: {s}",
            .{ opts.config_path orelse "", @errorName(e) },
        );
        return e;
    };

    const conf = managed_config.config;
    @import("root").logger.log_settings = conf.log;
    errdefer managed_config.deinit();

    // Scan ACL directory for allowed UIDs (username → UID resolution)
    var acl_manager = AclScanner.init(allocator, conf.acl_dir);

    var initial_scan = acl_manager.scanUidsWithUnresolved(io);
    log.info("ACL scan: {} allowed UIDs, {} unresolved usernames", .{ initial_scan.uids.items.len, initial_scan.unresolved.items.len });

    // UidTracker.init takes ownership of initial_scan.uids on success. Use
    // errdefer (not defer) so the list is freed only on the error path — if
    // init succeeds, ownership transfers to the tracker and a defer would
    // double-free when the server is later deinit'd.
    errdefer initial_scan.uids.deinit(allocator);

    // Seed unresolved_usernames from the initial scan so pending-UID recovery
    // works before the first ACL-directory change event. Keys are owned by
    // the map (duped from the scan's owned strings).
    var unresolved_usernames = std.StringHashMap(void).init(allocator);
    errdefer {
        var it = unresolved_usernames.keyIterator();
        while (it.next()) |key| allocator.free(key.*);
        unresolved_usernames.deinit();
    }
    for (initial_scan.unresolved.items) |name| {
        const owned = allocator.dupe(u8, name) catch continue;
        unresolved_usernames.put(owned, {}) catch {
            allocator.free(owned);
        };
    }
    // The scan's unresolved strings are no longer needed; the map holds its
    // own copies now.
    for (initial_scan.unresolved.items) |name| allocator.free(name);
    initial_scan.unresolved.deinit(allocator);

    var uid_tracker = try UidTracker.init(io, allocator, initial_scan.uids);

    uid_tracker.scanExisting(io);

    // Watch acl.d/ for dynamic ACL changes (graceful: null if setup fails)
    const acl_watcher = AclWatcher.init(allocator, io, conf.acl_dir) orelse acl_watcher: {
        log.warn("ACL directory watcher not available, dynamic ACL updates disabled", .{});
        break :acl_watcher AclWatcher{
            .allocator = allocator,
            .io = io,
            .acl_dir = conf.acl_dir,
            .inotify_fd = null,
        };
    };

    // Initialize worker manager for per-UID worker processes
    const worker_manager = WorkerManager.init(io, allocator, opts.config_path, WorkerManager.production_workers_dir);

    return Server{
        .config = conf,
        .io = io,
        .acl_manager = acl_manager,
        .acl_watcher = acl_watcher,
        .worker_manager = worker_manager,
        .uid_tracker = uid_tracker,
        .managed_config = managed_config,
        .unresolved_usernames = unresolved_usernames,
    };
}

pub fn deinit(self: *Server) void {
    log.info("Server shutting down...", .{});
    self.acl_watcher.deinit();
    self.worker_manager.deinit();
    // Free unresolved_usernames keys then deinit the map. Done before
    // uid_tracker.deinit for clarity (the allocator itself is not owned by the
    // tracker, so accessing self.uid_tracker.allocator here is still valid).
    var it = self.unresolved_usernames.keyIterator();
    while (it.next()) |key| self.uid_tracker.allocator.free(key.*);
    self.unresolved_usernames.deinit();
    self.uid_tracker.deinit();
    self.managed_config.deinit();
}

/// Optional controls for `run()`. All fields default to "disabled".
pub const RunOpts = struct {
    /// Atomic flag set by an external signal handler to request graceful
    /// shutdown. When set, the event loop exits after the current iteration
    /// and `run()` returns normally so that `defer server.deinit()` runs.
    /// Null disables graceful shutdown (loop runs forever, matching prior
    /// behavior).
    shutdown_flag: ?*const std.atomic.Value(bool) = null,
    /// Read end of a self-pipe included in the poll set. When the external
    /// signal handler writes to the pipe, poll() returns immediately instead
    /// of blocking until the next event. Negative value disables wake-up.
    wake_fd: std.posix.fd_t = -1,
};

pub fn run(self: *Server, opts: RunOpts) !void {
    log.info("net-porter {s} started, monitoring /run/user/", .{version});
    self.syncWorkers();

    var event_buf: [UidTracker.event_buffer_size]u8 = undefined;
    const has_wake = opts.wake_fd >= 0;

    while (true) {
        // Check for shutdown at the top of each iteration so we exit promptly
        // when the signal handler flips the flag (whether before entering poll
        // or after being woken up via the self-pipe).
        if (opts.shutdown_flag) |f| {
            if (f.load(.acquire)) break;
        }

        // Build poll set:
        //   [0]          : wake_fd (optional, for signal-driven wake-up)
        //   [next]       : uid tracker inotify (always)
        //   [next]       : acl watcher inotify (optional)
        //   [rest]       : worker manager pidfds
        const wm_fds = self.worker_manager.pollFdSlice();
        const has_acl_watch = self.acl_watcher.getInotifyFd() != null;
        const fixed_fds: usize = 1 + @as(usize, @intFromBool(has_acl_watch)) + @as(usize, @intFromBool(has_wake));
        const total_fds = fixed_fds + wm_fds.len;

        // Dynamically allocate the pollfd slice sized to the actual worker
        // count plus fixed fds. The previous fixed [256]pollfd cap killed the
        // server once total_fds exceeded 256 (~120 UIDs since each worker
        // contributes 2 pidfds). Allocation per loop iteration is cheap
        // relative to the poll() syscall itself and avoids a stale capacity
        // if the worker set shrinks.
        const allocator = self.worker_manager.allocator;
        const poll_buf = allocator.alloc(std.posix.pollfd, total_fds) catch |err| {
            log.err("Failed to allocate {d} pollfds: {s}", .{ total_fds, @errorName(err) });
            return err;
        };
        defer allocator.free(poll_buf);

        var slot: usize = 0;

        // Wake fd at index 0 (if provided) so the drain check below is cheap.
        if (has_wake) {
            poll_buf[slot] = .{
                .fd = opts.wake_fd,
                .events = std.posix.POLL.IN,
                .revents = 0,
            };
            slot += 1;
        }

        poll_buf[slot] = .{
            .fd = self.uid_tracker.inotify_fd,
            .events = std.posix.POLL.IN,
            .revents = 0,
        };
        const uid_fd_index: usize = slot;
        slot += 1;

        const acl_fd_index: ?usize = blk: {
            if (has_acl_watch) {
                poll_buf[slot] = .{
                    .fd = self.acl_watcher.getInotifyFd().?,
                    .events = std.posix.POLL.IN,
                    .revents = 0,
                };
                const idx = slot;
                slot += 1;
                break :blk idx;
            }
            break :blk null;
        };

        // `slot` now equals `fixed_fds`. Append worker pidfds.
        const wm_start: usize = slot;
        for (wm_fds, 0..) |pfd, i| {
            poll_buf[slot + i] = pfd;
        }

        const timeout = self.worker_manager.nextRetryTimeoutMs() orelse -1;

        const n = std.posix.poll(poll_buf[0..total_fds], timeout) catch |err| {
            log.err("poll failed: {s}", .{@errorName(err)});
            return err;
        };

        // Drain wake fd if it fired. We don't act on the data — its sole
        // purpose is to wake poll() so the loop iterates and re-checks the
        // shutdown flag above.
        if (has_wake and (poll_buf[0].revents & std.posix.POLL.IN != 0)) {
            var drain_buf: [64]u8 = undefined;
            while (true) {
                const rc = std.os.linux.read(opts.wake_fd, &drain_buf, drain_buf.len);
                // Negative return means EAGAIN (non-blocking pipe drained) or error.
                if (@as(isize, @bitCast(rc)) <= 0) break;
            }
        }

        if (wm_fds.len > 0) {
            self.worker_manager.processPollEvents(poll_buf[wm_start .. wm_start + wm_fds.len]);
        }

        if (acl_fd_index) |idx| {
            if (poll_buf[idx].revents & std.posix.POLL.IN != 0) {
                if (self.acl_watcher.processInotifyEvents(&event_buf)) {
                    self.handleAclChange();
                }
            }
        }

        if (poll_buf[uid_fd_index].revents & std.posix.POLL.IN != 0) {
            var uid_events = self.uid_tracker.processInotifyEvents(&event_buf);
            if (uid_events.created.items.len > 0) {
                self.worker_manager.ensureWorkers(uid_events.created.items);
            }
            for (uid_events.removed.items) |uid| {
                self.worker_manager.stopWorker(uid);
            }
            // Pending UIDs: `/run/user/<uid>` appeared while the UID was not in
            // the allowed list. Always re-scan ACLs so the UID is re-evaluated
            // for inclusion in the allowed list. We must not gate on whether
            // the UID's username is currently in unresolved_usernames: a
            // previous ACL scan may have resolved the name (clearing the set)
            // before the user actually existed in NSS, which would silently
            // drop the pending UID and leave its worker unstarted forever.
            if (uid_events.pending.items.len > 0) {
                self.handlePendingUids(uid_events.pending.items);
            }
            // IN_Q_OVERFLOW: kernel dropped events, so created/removed may be
            // incomplete. Reconcile by re-scanning /run/user/ for allowed UIDs
            // (picks up missed additions) and re-syncing the worker set with
            // the tracker's active UID list.
            if (uid_events.rescan_needed) {
                log.warn("inotify overflow detected on /run/user/, performing full rescan to reconcile UIDs", .{});
                self.uid_tracker.scanExisting(self.io);
                self.syncWorkers();
            }
            uid_events.deinit(self.uid_tracker.allocator);
        }

        if (n == 0) {
            self.worker_manager.retryPending();
        }
    }

    log.info("Shutdown requested, exiting event loop", .{});
}

/// Synchronize workers with current /run/user/ state.
fn syncWorkers(self: *Server) void {
    var active_uids = self.uid_tracker.getActiveUids() catch |err| {
        log.warn("Failed to get active UIDs: {s}, skipping worker sync", .{@errorName(err)});
        return;
    };
    defer active_uids.deinit(self.uid_tracker.allocator);

    log.info("syncWorkers: {} active UIDs", .{active_uids.items.len});

    self.worker_manager.ensureWorkers(active_uids.items);
}

/// Free the owned key strings of `unresolved_usernames` and clear the map
/// without releasing its allocated capacity (the map is about to be repopulated
/// or torn down by the caller).
fn clearUnresolvedUsernames(self: *Server) void {
    var it = self.unresolved_usernames.keyIterator();
    while (it.next()) |key| self.uid_tracker.allocator.free(key.*);
    self.unresolved_usernames.clearRetainingCapacity();
}

/// Process pending UIDs detected by UidTracker.
///
/// Always triggers an ACL re-scan when there are pending UIDs. The previous
/// implementation only re-scanned when a pending UID's username matched an
/// entry in `unresolved_usernames`, but that set can be empty even when
/// recovery is needed: if a prior ACL scan resolved the username (clearing
/// the set) before the user actually existed in NSS, the subsequent
/// `/run/user/<uid>` event would find an empty set, return false, and the
/// worker would never start. Always re-scanning fixes this without affecting
/// the happy path — the re-scan is a cheap directory read plus one
/// `getpwnam_r` per ACL file and is idempotent.
pub fn handlePendingUids(self: *Server, pending: []const u32) void {
    if (pending.len == 0) return;
    self.handleAclChange();
}

/// Inspect pending UIDs (whose `/run/user/<uid>` appeared while the UID was not
/// yet allowed) and check whether any resolves to a username we previously
/// failed to resolve from an ACL file. Returns true when at least one pending
/// UID matches.
///
/// Not currently called from the event loop (which uses `handlePendingUids`
/// for unconditional recovery), but retained as a utility for callers that
/// want the selective matching behavior.
fn processPendingUids(self: *Server, pending: []const u32) bool {
    for (pending) |uid| {
        const maybe_name = user_mod.getUsername(self.uid_tracker.allocator, uid) catch continue;
        const username = maybe_name orelse continue;
        defer self.uid_tracker.allocator.free(username);
        if (self.unresolved_usernames.contains(username)) {
            log.info("UID {d} ('{s}') matches unresolved ACL entry, triggering ACL re-scan", .{ uid, username });
            return true;
        }
    }
    return false;
}

/// Handle a detected change in the ACL directory.
/// Re-scans UIDs, updates the allowed list, and starts/stops workers as needed.
/// Detects UID reuse: if a username-to-UID mapping changed, stops the old worker
/// so it gets respawned with the correct username and ACL.
fn handleAclChange(self: *Server) void {
    var scan_result = self.acl_manager.scanUidsWithUnresolved(self.io);

    // Guard: if scan returns empty but old list was non-empty, assume
    // transient failure (e.g. ACL directory temporarily unavailable).
    // This prevents wiping all workers due to a fleeting I/O error.
    if (scan_result.uids.items.len == 0 and self.uid_tracker.allowed_uids.items.len > 0) {
        log.warn("ACL scan returned empty but {} UIDs were allowed, skipping update (possible transient failure)", .{self.uid_tracker.allowed_uids.items.len});
        scan_result.deinit(self.uid_tracker.allocator);
        return;
    }

    // Refresh unresolved_usernames from this scan: free old keys, store the new
    // set (duped so the map owns its own copies independent of scan_result).
    self.clearUnresolvedUsernames();
    for (scan_result.unresolved.items) |name| {
        const owned = self.uid_tracker.allocator.dupe(u8, name) catch continue;
        self.unresolved_usernames.put(owned, {}) catch {
            self.uid_tracker.allocator.free(owned);
        };
    }
    // The scan's unresolved strings are no longer needed; the map holds copies.
    for (scan_result.unresolved.items) |name| self.uid_tracker.allocator.free(name);
    scan_result.unresolved.deinit(self.uid_tracker.allocator);

    // updateAllowedUids takes ownership of scan_result.uids.
    var delta = self.uid_tracker.updateAllowedUids(scan_result.uids);
    defer delta.deinit(self.uid_tracker.allocator);

    // Reconcile active entries with /run/user/: a newly-allowed UID may already
    // have a /run/user/<uid> directory (created while the UID was not yet
    // allowed, e.g. during the undeploy/redeploy window). scanExisting adds
    // such UIDs to the active set so the worker-start logic below picks them up.
    self.uid_tracker.scanExisting(self.io);

    // Stop workers for removed UIDs
    for (delta.removed.items) |uid| {
        self.worker_manager.stopWorker(uid);
    }

    // Detect username changes for unchanged UIDs (UID reuse attack prevention).
    // If a user was deleted and a new user assigned the same UID, the existing
    // worker still runs with the old username's ACL. Stop it so it respawns
    // with the correct username.
    var mismatched_uids = std.ArrayList(u32).initCapacity(self.uid_tracker.allocator, self.uid_tracker.allowed_uids.items.len) catch return;
    defer mismatched_uids.deinit(self.uid_tracker.allocator);

    for (self.uid_tracker.allowed_uids.items) |uid| {
        // Skip newly added UIDs — they'll get fresh workers with correct usernames
        var is_added = false;
        for (delta.added.items) |added_uid| {
            if (added_uid == uid) {
                is_added = true;
                break;
            }
        }
        if (is_added) continue;

        const stored_username = self.worker_manager.getWorkerUsername(uid) orelse continue;
        // Distinguish NSS lookup errors (transient — e.g. NSCD hiccup) from a
        // genuine "user no longer exists" null result. On error, log and skip;
        // the next ACL change will retry the lookup. Treating an error as
        // "unchanged" would silently mask a UID-reuse attack.
        const current_username = user_mod.getUsername(self.uid_tracker.allocator, uid) catch |err| {
            log.warn("Transient NSS lookup failure for uid={d}: {s}, deferring UID-reuse check to next ACL change", .{ uid, @errorName(err) });
            continue;
        } orelse continue;

        if (!user_mod.isValidUsername(current_username)) {
            log.warn("Username '{s}' for uid={d} failed validation, skipping", .{ current_username, uid });
            self.uid_tracker.allocator.free(current_username);
            continue;
        }

        if (!std.mem.eql(u8, stored_username, current_username)) {
            log.warn("Username changed for uid={d}: '{s}' -> '{s}', restarting worker", .{ uid, stored_username, current_username });
            self.uid_tracker.allocator.free(current_username);
            self.worker_manager.stopWorker(uid);
            mismatched_uids.appendAssumeCapacity(uid);
        } else {
            self.uid_tracker.allocator.free(current_username);
        }
    }

    // Start workers for added UIDs that are currently active
    if (delta.added.items.len > 0) {
        var active_added = std.ArrayList(u32).initCapacity(self.uid_tracker.allocator, delta.added.items.len) catch return;
        defer active_added.deinit(self.uid_tracker.allocator);

        for (delta.added.items) |uid| {
            if (self.uid_tracker.isUidActive(uid)) {
                active_added.appendAssumeCapacity(uid);
            }
        }
        if (active_added.items.len > 0) {
            self.worker_manager.ensureWorkers(active_added.items);
        }
    }

    // Re-spawn workers for mismatched UIDs that are still active
    if (mismatched_uids.items.len > 0) {
        var active_mismatched = std.ArrayList(u32).initCapacity(self.uid_tracker.allocator, mismatched_uids.items.len) catch return;
        defer active_mismatched.deinit(self.uid_tracker.allocator);

        for (mismatched_uids.items) |uid| {
            if (self.uid_tracker.isUidActive(uid)) {
                active_mismatched.appendAssumeCapacity(uid);
            }
        }
        if (active_mismatched.items.len > 0) {
            self.worker_manager.ensureWorkers(active_mismatched.items);
        }
    }
}

test "handleAclChange updates allowed UIDs from ACL scan" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const test_utils = @import("../test_utils.zig");

    var test_dir = try AclScanner.TestAclDir.create(io, allocator);
    defer test_dir.deinit();

    // Use a temporary workers_dir so the test never touches the production
    // /run/net-porter/workers path. tfr.deinit() runs after server.deinit()
    // (LIFO defer order); WorkerManager.deinit() only frees memory and does
    // not access workers_dir, so the directory remains valid for its lifetime.
    var tfr = try test_utils.newTempFileManager(io, allocator, "srv-wm-");
    tfr.should_clean_file = true;
    defer tfr.deinit();

    // Create root.json which resolves as uid 0
    try test_dir.writeFile("root.json", "{}");

    // Start with a different allowed UID
    var allowed_uids = std.ArrayList(u32).initCapacity(allocator, 1) catch return error.Unexpected;
    allowed_uids.appendAssumeCapacity(9999);

    // Add an active entry for root (uid 0)
    var entries = std.ArrayList(UidTracker.UidEntry).initCapacity(allocator, 1) catch return error.Unexpected;
    entries.appendAssumeCapacity(.{ .uid = 0 });

    var server = Server{
        .config = config_mod.Config{ .acl_dir = test_dir.dir_path },
        .io = io,
        .acl_manager = AclScanner.init(allocator, test_dir.dir_path),
        .acl_watcher = AclWatcher{
            .allocator = allocator,
            .io = io,
            .acl_dir = test_dir.dir_path,
            .inotify_fd = null,
        },
        .worker_manager = WorkerManager.init(io, allocator, null, tfr.temp_dir_path),
        .uid_tracker = UidTracker{
            .allocator = allocator,
            .io = io,
            .allowed_uids = allowed_uids,
            .entries = entries,
            .inotify_fd = -1,
        },
        .managed_config = config_mod.ManagedConfig{ .config = config_mod.Config{} },
        .unresolved_usernames = std.StringHashMap(void).init(allocator),
    };
    defer server.deinit();

    // Before: 9999 is allowed, 0 is active but not allowed
    try std.testing.expect(server.uid_tracker.isUidAllowed(9999));
    try std.testing.expect(!server.uid_tracker.isUidAllowed(0));
    try std.testing.expect(server.uid_tracker.isUidActive(0));

    // Re-scan ACLs
    server.handleAclChange();

    // After: 0 should be allowed, 9999 removed
    try std.testing.expect(!server.uid_tracker.isUidAllowed(9999));
    try std.testing.expect(server.uid_tracker.isUidAllowed(0));
    try std.testing.expect(server.uid_tracker.isUidActive(0));
}

test "handleAclChange preserves UIDs on empty scan result" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const test_utils = @import("../test_utils.zig");

    var test_dir = try AclScanner.TestAclDir.create(io, allocator);
    defer test_dir.deinit();

    // Avoid touching the production /run/net-porter/workers path. See the
    // first handleAclChange test for the lifetime rationale (tfr.outlives the
    // server via LIFO defer order).
    var tfr = try test_utils.newTempFileManager(io, allocator, "srv-wm-");
    tfr.should_clean_file = true;
    defer tfr.deinit();

    // No ACL files - directory is empty

    var allowed_uids = std.ArrayList(u32).initCapacity(allocator, 2) catch return error.Unexpected;
    allowed_uids.appendAssumeCapacity(1000);
    allowed_uids.appendAssumeCapacity(2000);

    var server = Server{
        .config = config_mod.Config{ .acl_dir = test_dir.dir_path },
        .io = io,
        .acl_manager = AclScanner.init(allocator, test_dir.dir_path),
        .acl_watcher = AclWatcher{
            .allocator = allocator,
            .io = io,
            .acl_dir = test_dir.dir_path,
            .inotify_fd = null,
        },
        .worker_manager = WorkerManager.init(io, allocator, null, tfr.temp_dir_path),
        .uid_tracker = UidTracker{
            .allocator = allocator,
            .io = io,
            .allowed_uids = allowed_uids,
            .entries = std.ArrayList(UidTracker.UidEntry).empty,
            .inotify_fd = -1,
        },
        .managed_config = config_mod.ManagedConfig{ .config = config_mod.Config{} },
        .unresolved_usernames = std.StringHashMap(void).init(allocator),
    };
    defer server.deinit();

    try std.testing.expect(server.uid_tracker.isUidAllowed(1000));
    try std.testing.expect(server.uid_tracker.isUidAllowed(2000));

    server.handleAclChange();

    // Empty scan with existing UIDs: guard kicks in, UIDs preserved
    try std.testing.expect(server.uid_tracker.isUidAllowed(1000));
    try std.testing.expect(server.uid_tracker.isUidAllowed(2000));
}

test "handleAclChange detects username mismatch and stops worker" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const test_utils = @import("../test_utils.zig");

    var test_dir = try AclScanner.TestAclDir.create(io, allocator);
    defer test_dir.deinit();

    // Avoid touching the production /run/net-porter/workers path. The injected
    // worker is stopped via handleAclChange → stopService → removeEnvFile, which
    // builds paths under workers_dir. tfr.outlives the server via LIFO defer
    // order, and WorkerManager.deinit() does not access workers_dir.
    var tfr = try test_utils.newTempFileManager(io, allocator, "srv-wm-");
    tfr.should_clean_file = true;
    defer tfr.deinit();

    // Create root.json which resolves to uid 0
    try test_dir.writeFile("root.json", "{}");

    var allowed_uids = std.ArrayList(u32).initCapacity(allocator, 1) catch return error.Unexpected;
    allowed_uids.appendAssumeCapacity(0);

    var entries = std.ArrayList(UidTracker.UidEntry).initCapacity(allocator, 1) catch return error.Unexpected;
    entries.appendAssumeCapacity(.{ .uid = 0 });

    var worker_manager = WorkerManager.init(io, allocator, null, tfr.temp_dir_path);
    const hacker_username = try allocator.dupe(u8, "hacker");
    try worker_manager.injectTestWorker(0, hacker_username);

    try std.testing.expect(worker_manager.getWorkerUsername(0) != null);
    try std.testing.expectEqualStrings("hacker", worker_manager.getWorkerUsername(0).?);

    var server = Server{
        .config = config_mod.Config{ .acl_dir = test_dir.dir_path },
        .io = io,
        .acl_manager = AclScanner.init(allocator, test_dir.dir_path),
        .acl_watcher = AclWatcher{
            .allocator = allocator,
            .io = io,
            .acl_dir = test_dir.dir_path,
            .inotify_fd = null,
        },
        .worker_manager = worker_manager,
        .uid_tracker = UidTracker{
            .allocator = allocator,
            .io = io,
            .allowed_uids = allowed_uids,
            .entries = entries,
            .inotify_fd = -1,
        },
        .managed_config = config_mod.ManagedConfig{ .config = config_mod.Config{} },
        .unresolved_usernames = std.StringHashMap(void).init(allocator),
    };
    defer server.deinit();

    // Re-scan ACLs — should detect that uid 0's username changed from "hacker" to "root"
    server.handleAclChange();

    // Worker should have been stopped due to username mismatch
    try std.testing.expect(server.worker_manager.getWorkerUsername(0) == null);
}

/// Helper for pending-UID tests: build a minimal Server whose
/// `unresolved_usernames` is seeded with the provided names. The server uses
/// throwaway static paths (none of the ACL/worker paths are accessed by
/// `processPendingUids`). Caller must `deinit` the returned server.
fn newPendingTestServer(allocator: std.mem.Allocator, io: std.Io, unresolved_names: []const []const u8) !Server {
    var unresolved = std.StringHashMap(void).init(allocator);
    errdefer {
        var it = unresolved.keyIterator();
        while (it.next()) |key| allocator.free(key.*);
        unresolved.deinit();
    }
    for (unresolved_names) |name| {
        const owned = try allocator.dupe(u8, name);
        try unresolved.put(owned, {});
    }

    return Server{
        .config = config_mod.Config{ .acl_dir = "/tmp/net-porter-pending-unused" },
        .io = io,
        .acl_manager = AclScanner.init(allocator, "/tmp/net-porter-pending-unused"),
        .acl_watcher = AclWatcher{
            .allocator = allocator,
            .io = io,
            .acl_dir = "/tmp/net-porter-pending-unused",
            .inotify_fd = null,
        },
        .worker_manager = WorkerManager.init(io, allocator, null, "/tmp/net-porter-pending-workers"),
        .uid_tracker = UidTracker{
            .allocator = allocator,
            .io = io,
            .allowed_uids = .empty,
            .entries = std.ArrayList(UidTracker.UidEntry).empty,
            .inotify_fd = -1,
        },
        .managed_config = config_mod.ManagedConfig{ .config = config_mod.Config{} },
        .unresolved_usernames = unresolved,
    };
}

test "processPendingUids triggers rescan when UID matches unresolved username" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Seed an unresolved ACL username "root". UID 0 resolves to "root" via NSS,
    // so a pending event for uid 0 should match and request an ACL re-scan.
    const names = [_][]const u8{"root"};
    var server = try newPendingTestServer(allocator, io, &names);
    defer server.deinit();

    try std.testing.expect(server.unresolved_usernames.contains("root"));

    const pending = [_]u32{0};
    try std.testing.expect(server.processPendingUids(&pending));
}

test "processPendingUids returns false when no UID matches unresolved username" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    // Seed an unresolved name that no real UID maps to. A pending uid 0
    // resolves to "root", which is not in the set, so no rescan is requested.
    const names = [_][]const u8{"definitelynotauser_xyz"};
    var server = try newPendingTestServer(allocator, io, &names);
    defer server.deinit();

    const pending = [_]u32{0};
    try std.testing.expect(!server.processPendingUids(&pending));
}

test "processPendingUids returns false on empty pending list" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const names = [_][]const u8{"root"};
    var server = try newPendingTestServer(allocator, io, &names);
    defer server.deinit();

    const pending = [_]u32{};
    try std.testing.expect(!server.processPendingUids(&pending));
}

test "UidEvents.pending is populated and freed via deinit" {
    const allocator = std.testing.allocator;

    // Construct a UidEvents with all three lists and verify deinit frees them
    // without leaking (std.testing.allocator detects leaks).
    var created = try std.ArrayList(u32).initCapacity(allocator, 1);
    created.appendAssumeCapacity(1000);

    var removed = try std.ArrayList(u32).initCapacity(allocator, 1);
    removed.appendAssumeCapacity(2000);

    var pending = try std.ArrayList(u32).initCapacity(allocator, 1);
    pending.appendAssumeCapacity(3000);

    var events = UidTracker.UidEvents{
        .created = created,
        .removed = removed,
        .pending = pending,
    };
    events.deinit(allocator);
}

test "handlePendingUids always rescans even when username not unresolved" {
    // Regression: pending UIDs whose username was not in unresolved_usernames
    // were silently dropped by the event loop's old `processPendingUids`-based
    // guard. When a user is created after its ACL file, a previous ACL scan
    // resolves the name (clearing unresolved_usernames) before the pending
    // /run/user/<uid> event fires — so the selective check returned false and
    // the worker never started. handlePendingUids must always re-scan.
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const test_utils = @import("../test_utils.zig");

    var test_dir = try AclScanner.TestAclDir.create(io, allocator);
    defer test_dir.deinit();

    var tfr = try test_utils.newTempFileManager(io, allocator, "srv-pending-");
    tfr.should_clean_file = true;
    defer tfr.deinit();

    // root.json resolves to uid 0 via NSS on the test host.
    try test_dir.writeFile("root.json", "{}");

    // Pretend /run/user/0 already exists: uid 0 is active.
    var entries = std.ArrayList(UidTracker.UidEntry).initCapacity(allocator, 1) catch return error.Unexpected;
    entries.appendAssumeCapacity(.{ .uid = 0 });

    // allowed_uids is EMPTY — root not yet allowed.
    const allowed_uids: std.ArrayList(u32) = .empty;

    // unresolved_usernames is EMPTY — simulates the bug scenario where a
    // previous ACL scan resolved root (or the list was cleared), so the old
    // selective check would have returned false and skipped the re-scan.
    var server = Server{
        .config = config_mod.Config{ .acl_dir = test_dir.dir_path },
        .io = io,
        .acl_manager = AclScanner.init(allocator, test_dir.dir_path),
        .acl_watcher = AclWatcher{
            .allocator = allocator,
            .io = io,
            .acl_dir = test_dir.dir_path,
            .inotify_fd = null,
        },
        .worker_manager = WorkerManager.init(io, allocator, null, tfr.temp_dir_path),
        .uid_tracker = UidTracker{
            .allocator = allocator,
            .io = io,
            .allowed_uids = allowed_uids,
            .entries = entries,
            .inotify_fd = -1,
        },
        .managed_config = config_mod.ManagedConfig{ .config = config_mod.Config{} },
        .unresolved_usernames = std.StringHashMap(void).init(allocator),
    };
    defer server.deinit();

    // Precondition: root is active but not allowed.
    try std.testing.expect(server.uid_tracker.isUidActive(0));
    try std.testing.expect(!server.uid_tracker.isUidAllowed(0));

    // A pending event for uid 0 must trigger an ACL re-scan unconditionally.
    server.handlePendingUids(&[_]u32{0});

    // After: root should be allowed (ACL re-scan resolved root -> uid 0).
    try std.testing.expect(server.uid_tracker.isUidAllowed(0));
    try std.testing.expect(server.uid_tracker.isUidActive(0));
}
