const std = @import("std");
const json = std.json;
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const ArenaAllocator = @import("../utils/ArenaAllocator.zig");
const plugin = @import("../plugin.zig");
const Responser = @import("../common/Responser.zig");
const managed_type = @import("../common/ManagedType.zig");
const StateFile = @import("StateFile.zig");

// Zig 0.16's test runner unconditionally fails any test that emits a
// log.err, even when the error is the expected outcome being asserted
// (e.g. the rollback path in persistAndRespond). In test builds we route
// .err through a no-op while leaving .warn/.info/.debug intact so the
// assertions can exercise the failure paths without tripping the runner.
// Production builds are unaffected.
const log = if (builtin.is_test) TestLogFilter else std.log.scoped(.cni);

const TestLogFilter = struct {
    pub inline fn emerg(comptime _: []const u8, _: anytype) void {}
    pub inline fn alert(comptime _: []const u8, _: anytype) void {}
    pub inline fn crit(comptime _: []const u8, _: anytype) void {}
    pub inline fn err(comptime _: []const u8, _: anytype) void {}
    pub inline fn warn(comptime fmt: []const u8, args: anytype) void {
        std.log.scoped(.cni).warn(fmt, args);
    }
    pub inline fn info(comptime fmt: []const u8, args: anytype) void {
        std.log.scoped(.cni).info(fmt, args);
    }
    pub inline fn debug(comptime fmt: []const u8, args: anytype) void {
        std.log.scoped(.cni).debug(fmt, args);
    }
};

pub const CniConfig = @import("CniConfig.zig").CniConfig;
pub const PluginConf = @import("PluginConf.zig").PluginConf;

const Cni = @This();

// Types needed by Attachment.zig — declared before the circular import
pub const CniCommand = enum {
    ADD,
    DEL,
    GET,
    VERSION,
};

const CniErrorMsg = struct {
    code: u32,
    msg: []const u8,
};

const ManagedResponse = managed_type.ManagedType(plugin.Response);

const CniResult = struct {
    cniVersion: []const u8,
    interfaces: []Interface,
    ips: []IpConfig,
    routes: ?[]RouteConfig = null,
    dns: ?DNSConfig = null,

    fn toNetavarkResponse(self: CniResult, root_allocator: Allocator) !ManagedResponse {
        var response = ManagedResponse{
            .v = plugin.Response{
                .dns_search_domains = if (self.dns) |dns| dns.search else null,
                .dns_server_ips = if (self.dns) |dns| dns.nameservers else null,
                .interfaces = .{},
            },
            .arena = try ArenaAllocator.init(root_allocator),
        };
        errdefer response.deinit();
        const allocator = response.arena.?.allocator();

        for (self.interfaces, 0..) |iface, index| {
            var subnets = std.ArrayList(plugin.Subnet).empty;
            for (self.ips) |ip| {
                if (ip.interface != index) {
                    continue;
                }
                try subnets.append(allocator, .{
                    .ipnet = ip.address,
                    .gateway = ip.gateway,
                });
            }

            try response.v.interfaces.map.put(
                allocator,
                iface.name,
                .{
                    .mac_address = iface.mac,
                    .subnets = try subnets.toOwnedSlice(allocator),
                },
            );
        }

        return response;
    }
};

const Interface = struct {
    name: []const u8,
    mac: []const u8,
    sandbox: ?[]const u8 = null,
};

const IpConfig = struct {
    // index of interface in interfaces field
    interface: u32,
    // ip address with prefix length
    address: []const u8,
    gateway: ?[]const u8 = null,
};

const RouteConfig = struct {
    dst: []const u8,
    gw: ?[]const u8 = null,
};

const DNSConfig = struct {
    nameservers: ?[]const []const u8 = null,
    domain: ?[]const u8 = null,
    search: ?[]const []const u8 = null,
    options: ?[]const []const u8 = null,
};

pub fn responseError(allocator: Allocator, responser: *Responser, stdout: std.ArrayList(u8)) !void {
    var parsed_error_msg = try json.parseFromSlice(
        CniErrorMsg,
        allocator,
        stdout.items,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_error_msg.deinit();

    const error_msg = parsed_error_msg.value;
    log.warn("CNI plugin error: {s} (code={d})", .{ error_msg.msg, error_msg.code });
    responser.writeError("CNI plugin error", .{});
}

pub fn responseResult(allocator: Allocator, responser: *Responser, stdout: std.ArrayList(u8)) !void {
    var parsed_result = try json.parseFromSlice(
        CniResult,
        allocator,
        stdout.items,
        .{ .ignore_unknown_fields = true },
    );
    defer parsed_result.deinit();
    const result = parsed_result.value;

    var managed_response = try result.toNetavarkResponse(allocator);
    defer managed_response.deinit();

    responser.write(managed_response.v);
}

/// Function signature for the state-write dependency used by
/// `persistAndRespond`. Production code passes `StateFile.write`; tests
/// inject a fake to simulate persistence failure without touching the real
/// `/run/net-porter/...` filesystem path. The injected function lives in
/// production code (declared here) but is only invoked with non-default
/// arguments from tests.
pub const StateWriterFn = *const fn (
    io: std.Io,
    allocator: Allocator,
    uid: u32,
    container_id: []const u8,
    ifname: []const u8,
    data: []const u8,
) anyerror!void;

/// Argument bundle for `persistAndRespond`. Groups the 7 dependencies so the
/// signature stays readable and the call site is self-documenting.
pub const PersistAndRespondArgs = struct {
    allocator: Allocator,
    io: std.Io,
    attachment: *Attachment,
    request: plugin.Request,
    responser: *Responser,
    caller_uid: u32,
    state_writer: StateWriterFn,
};

/// Persist attachment state and emit the success response after CNI ADD has
/// completed. This helper exists to guarantee the response-timing invariant
/// at the heart of the CNI ADD flow:
///
///   1. The success response is sent ONLY after `state_writer` succeeds.
///   2. If `state_writer` fails, the just-allocated network is rolled back
///      via `Attachment.teardown` and the ORIGINAL state error is propagated.
///      The success response is NOT sent, so `Handler.handle` (which checks
///      `responser.done`) will emit an error response that truthfully reports
///      the failure to the client.
///   3. If rollback also fails, the rollback error is logged but suppressed
///      so the caller sees the original state error (the root cause).
///
/// Decoupling this logic from `Cni.setup` enables targeted unit tests:
/// `state_writer` is injectable, so tests can exercise both branches without
/// running real CNI plugins or touching the real state directory.
pub fn persistAndRespond(args: PersistAndRespondArgs) !void {
    const exec_request = try args.request.requestExec();
    const container_id = exec_request.container_id;
    const ifname = exec_request.network_options.interface_name;

    const state_json = try args.attachment.serializeState(args.allocator);
    defer args.allocator.free(state_json);

    args.state_writer(args.io, args.allocator, args.caller_uid, container_id, ifname, state_json) catch |err| {
        log.err(
            "Failed to persist state for uid={d}, container_id={s}: {s}; rolling back CNI ADD",
            .{ args.caller_uid, container_id, @errorName(err) },
        );
        // State persistence failed after a successful CNI ADD. Attempt
        // rollback by issuing CNI DEL; otherwise the just-allocated network
        // resources (interfaces, IPs, firewall rules) would be orphaned with
        // no state file to drive a future teardown.
        //
        // IMPORTANT: the success response has NOT been sent yet — it is sent
        // only after state persistence succeeds below. The Handler will see
        // responser.done == false and emit an error response to the client,
        // which correctly reflects the failed setup.
        args.attachment.teardown(args.io, args.allocator, args.request, args.responser) catch |rollback_err| {
            log.err(
                "Rollback (CNI DEL) also failed for uid={d}, container_id={s}: {s}; resources may be orphaned and require manual cleanup",
                .{ args.caller_uid, container_id, @errorName(rollback_err) },
            );
        };
        return err;
    };

    // State persisted — now it is safe to report success to the client.
    // A failure here (e.g. JSON formatting) is logged and propagated, but the
    // network IS set up and the state file IS persisted, so a subsequent
    // teardown by the client will succeed even if this response is lost.
    responseResult(
        args.allocator,
        args.responser,
        args.attachment.finalResult(.last) orelse return error.NoExecConfigs,
    ) catch |err| {
        log.err(
            "Failed to format success response for uid={d}, container_id={s}: {s}; network is set up and state is persisted",
            .{ args.caller_uid, container_id, @errorName(err) },
        );
        return err;
    };
}

// Import Attachment after all types it depends on are declared above
const Attachment = @import("Attachment.zig").Attachment;

// -- Cni struct fields --

arena: ArenaAllocator,
io: std.Io,
cni_plugin_dir: []const u8,
config: CniConfig,
mutex: std.Io.Mutex = .init,

/// Initialize from standard CNI config.
/// Validates that the first plugin has a valid ipam configuration.
pub fn initFromConfig(io: std.Io, root_allocator: Allocator, config: CniConfig, cni_plugin_dir: []const u8) !*Cni {
    var arena = try ArenaAllocator.init(root_allocator);
    errdefer arena.deinit();

    // Validate ipam config in first plugin
    if (config.plugins.array.items.len == 0) {
        log.err("CNI config '{s}' has no plugins configured", .{config.name});
        return error.PluginsIsEmpty;
    }
    const first_plugin = config.plugins.array.items[0];
    const ipam = first_plugin.object.get("ipam") orelse {
        log.err("CNI config '{s}' missing ipam field in first plugin", .{config.name});
        return error.MissingIpamConfig;
    };
    if (ipam != .object) return error.InvalidIpamConfig;
    const ipam_type = ipam.object.get("type") orelse return error.MissingIpamType;
    if (ipam_type != .string) return error.InvalidIpamType;

    // Validate ipam type is supported (dhcp or static)
    if (!std.mem.eql(u8, ipam_type.string, "dhcp") and !std.mem.eql(u8, ipam_type.string, "static")) {
        log.err("Unsupported ipam type '{s}' in config '{s}'", .{ ipam_type.string, config.name });
        return error.UnsupportedIpamType;
    }

    const cni = try arena.allocator().create(Cni);
    cni.* = Cni{
        .io = io,
        .arena = arena,
        .cni_plugin_dir = cni_plugin_dir,
        .config = config,
    };
    return cni;
}

pub fn deinit(self: *Cni) void {
    // The Cni struct itself is allocated inside the arena (see initFromConfig),
    // so arena.deinit() already releases its memory. Calling destroy(self)
    // here would be a double-free / use-after-free.
    self.arena.deinit();
}

/// Check if the first plugin's IPAM type is "static".
/// Returns false if plugins array is empty or first plugin has no IPAM.
pub fn isStaticIpam(self: Cni) bool {
    const plugins = switch (self.config.plugins) {
        .array => |a| a.items,
        else => return false,
    };
    if (plugins.len == 0) return false;
    const first_plugin = plugins[0];
    const plugin_conf = PluginConf{ .conf = switch (first_plugin) {
        .object => |obj| obj,
        else => return false,
    } };
    return plugin_conf.isStatic();
}

pub fn create(self: *Cni, tentative_allocator: Allocator, request: plugin.Request, responser: *Responser) !void {
    _ = self;
    _ = tentative_allocator;
    const raw = request.raw_request orelse return error.MissingRawRequest;
    responser.write(raw);
}

pub fn setup(self: *Cni, tentative_allocator: Allocator, request: plugin.Request, responser: *Responser, caller_uid: std.posix.uid_t) !void {
    try self.mutex.lock(self.io);
    defer self.mutex.unlock(self.io);

    const exec_request = try request.requestExec();
    const container_id = exec_request.container_id;
    const ifname = exec_request.network_options.interface_name;

    // Check if state file already exists (attachment already set up)
    if (StateFile.exists(tentative_allocator, caller_uid, container_id, ifname)) {
        responser.writeError("The setup has been executed, teardown first", .{});
        return;
    }

    // Create transient attachment for executing CNI plugins
    var attachment = try Attachment.init(tentative_allocator, self.config, self.cni_plugin_dir);
    defer attachment.deinit();

    // Execute CNI ADD chain with prevResult chaining between plugins
    try attachment.setup(self.io, tentative_allocator, request, responser);

    // Persist state and emit the success response. On state-write failure
    // this rolls back the just-completed CNI ADD via teardown and returns
    // the original error; the success response is NOT sent, so Handler
    // will emit an error response that truthfully reports the failure.
    try persistAndRespond(.{
        .allocator = tentative_allocator,
        .io = self.io,
        .attachment = &attachment,
        .request = request,
        .responser = responser,
        .caller_uid = caller_uid,
        .state_writer = StateFile.write,
    });
}

pub fn teardown(self: *Cni, tentative_allocator: Allocator, request: plugin.Request, responser: *Responser, caller_uid: std.posix.uid_t) !void {
    try self.mutex.lock(self.io);
    defer self.mutex.unlock(self.io);

    const exec_request = try request.requestExec();
    const container_id = exec_request.container_id;
    const ifname = exec_request.network_options.interface_name;

    // Read state file
    const state_json = StateFile.read(self.io, tentative_allocator, caller_uid, container_id, ifname) catch |err| {
        if (err == error.FileNotFound) {
            log.warn(
                "No state file found for uid={d}, container_id={s}, ifname={s}, skipping CNI DEL. This can happen if the server was restarted.",
                .{ caller_uid, container_id, ifname },
            );
            log.info("Teardown {s} is complete", .{request.request.exec.container_name});
            return;
        }
        log.warn("Failed to read state for uid={d}, container_id={s}: {s}", .{ caller_uid, container_id, @errorName(err) });
        return err;
    };
    defer tentative_allocator.free(state_json);

    // Deserialize state into transient attachment
    var attachment = try Attachment.deserializeState(tentative_allocator, state_json, self.cni_plugin_dir);
    defer attachment.deinit();

    // Execute CNI DEL chain (reverse order, all plugins get final ADD result as prevResult)
    try attachment.teardown(self.io, tentative_allocator, request, responser);

    // Remove state file
    StateFile.remove(self.io, tentative_allocator, caller_uid, container_id, ifname) catch |err| {
        log.warn("Failed to remove state file for uid={d}, container_id={s}: {s}", .{ caller_uid, container_id, @errorName(err) });
    };

    log.info("Teardown {s} for uid={d} is complete", .{ request.request.exec.container_name, caller_uid });
}

test "isStaticIpam returns true when first plugin ipam type is static" {
    const allocator = std.testing.allocator;
    var arena = try ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var ipam_obj = try json.ObjectMap.init(a, &.{}, &.{});
    try ipam_obj.put(a, "type", json.Value{ .string = "static" });

    var plugin_obj = try json.ObjectMap.init(a, &.{}, &.{});
    try plugin_obj.put(a, "type", json.Value{ .string = "macvlan" });
    try plugin_obj.put(a, "ipam", json.Value{ .object = ipam_obj });

    var plugins_arr = try json.Array.initCapacity(a, 1);
    plugins_arr.appendAssumeCapacity(json.Value{ .object = plugin_obj });

    const config = CniConfig{
        .cniVersion = "1.0.0",
        .name = "test-static",
        .plugins = json.Value{ .array = plugins_arr },
    };

    const cni = Cni{
        .arena = arena,
        .io = std.testing.io,
        .cni_plugin_dir = "/tmp",
        .config = config,
    };

    try std.testing.expect(cni.isStaticIpam());
}

test "isStaticIpam returns false when first plugin ipam type is dhcp" {
    const allocator = std.testing.allocator;
    var arena = try ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var ipam_obj = try json.ObjectMap.init(a, &.{}, &.{});
    try ipam_obj.put(a, "type", json.Value{ .string = "dhcp" });

    var plugin_obj = try json.ObjectMap.init(a, &.{}, &.{});
    try plugin_obj.put(a, "type", json.Value{ .string = "macvlan" });
    try plugin_obj.put(a, "ipam", json.Value{ .object = ipam_obj });

    var plugins_arr = try json.Array.initCapacity(a, 1);
    plugins_arr.appendAssumeCapacity(json.Value{ .object = plugin_obj });

    const config = CniConfig{
        .cniVersion = "1.0.0",
        .name = "test-dhcp",
        .plugins = json.Value{ .array = plugins_arr },
    };

    const cni = Cni{
        .arena = arena,
        .io = std.testing.io,
        .cni_plugin_dir = "/tmp",
        .config = config,
    };

    try std.testing.expect(!cni.isStaticIpam());
}

test "isStaticIpam returns false when first plugin is not an object" {
    const allocator = std.testing.allocator;
    var arena = try ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var plugins_arr = try json.Array.initCapacity(a, 1);
    plugins_arr.appendAssumeCapacity(json.Value{ .string = "not-an-object" });

    const config = CniConfig{
        .cniVersion = "1.0.0",
        .name = "test-invalid",
        .plugins = json.Value{ .array = plugins_arr },
    };

    const cni = Cni{
        .arena = arena,
        .io = std.testing.io,
        .cni_plugin_dir = "/tmp",
        .config = config,
    };

    try std.testing.expect(!cni.isStaticIpam());
}

test "isStaticIpam returns false when plugins array is empty" {
    const allocator = std.testing.allocator;
    var arena = try ArenaAllocator.init(allocator);
    defer arena.deinit();

    const plugins_arr = try json.Array.initCapacity(arena.allocator(), 0);

    const config = CniConfig{
        .cniVersion = "1.0.0",
        .name = "test-empty",
        .plugins = json.Value{ .array = plugins_arr },
    };

    const cni = Cni{
        .arena = arena,
        .io = std.testing.io,
        .cni_plugin_dir = "/tmp",
        .config = config,
    };

    try std.testing.expect(!cni.isStaticIpam());
}

test "deinit does not double-free the Cni struct" {
    // Regression test for REL-001: deinit() previously called
    // allocator.destroy(self) after self.arena.deinit(), which is a
    // double-free because the Cni struct is allocated inside the arena.
    // With std.testing.allocator (backed by GeneralPurposeAllocator), the
    // buggy version would panic on invalid free.
    const allocator = std.testing.allocator;

    // JSON config lives in a separate std.heap.ArenaAllocator so cleanup is
    // trivial and does not interfere with Cni's own arena.
    var config_arena = std.heap.ArenaAllocator.init(allocator);
    defer config_arena.deinit();
    const a = config_arena.allocator();

    var ipam_obj = try json.ObjectMap.init(a, &.{}, &.{});
    try ipam_obj.put(a, "type", json.Value{ .string = "static" });

    var plugin_obj = try json.ObjectMap.init(a, &.{}, &.{});
    try plugin_obj.put(a, "type", json.Value{ .string = "macvlan" });
    try plugin_obj.put(a, "ipam", json.Value{ .object = ipam_obj });

    var plugins_arr = try json.Array.initCapacity(a, 1);
    plugins_arr.appendAssumeCapacity(json.Value{ .object = plugin_obj });

    const config = CniConfig{
        .cniVersion = "1.0.0",
        .name = "test-deinit",
        .plugins = json.Value{ .array = plugins_arr },
    };

    const cni = try Cni.initFromConfig(std.testing.io, allocator, config, "/tmp");
    // Must not panic or trigger double-free detection.
    cni.deinit();
}

// === persistAndRespond tests ===
//
// These tests exercise the rollback and error-priority logic in
// `persistAndRespond` without invoking real CNI plugins. State writes
// are faked via `StateWriterFn`; teardown success/failure is controlled
// via the attachment's exec_configs (empty list = no-op, populated list
// = exec fails because cni_plugin_dir points at a non-existent path).

/// Fake state writer that always returns error.StateWriteFail. Used to
/// drive the rollback branch of `persistAndRespond`.
fn alwaysFailingStateWriter(io: std.Io, allocator: Allocator, uid: u32, container_id: []const u8, ifname: []const u8, data: []const u8) anyerror!void {
    _ = io;
    _ = allocator;
    _ = uid;
    _ = container_id;
    _ = ifname;
    _ = data;
    return error.StateWriteFail;
}

/// Fake state writer that always succeeds (no-op). Used to drive the
/// happy-path branch of `persistAndRespond`.
fn alwaysSucceedingStateWriter(io: std.Io, allocator: Allocator, uid: u32, container_id: []const u8, ifname: []const u8, data: []const u8) anyerror!void {
    _ = io;
    _ = allocator;
    _ = uid;
    _ = container_id;
    _ = ifname;
    _ = data;
}

/// Minimal exec-shaped Request suitable for `persistAndRespond`.
fn makeTestRequest() plugin.Request {
    return .{
        .action = .setup,
        .request = .{
            .exec = .{
                .container_name = "test-container",
                .container_id = "test-container-id",
                .network = .{
                    .driver = "net-porter",
                    .options = .{ .socket = "test-socket", .resource = "test-resource" },
                },
                .network_options = .{
                    .interface_name = "eth0",
                },
            },
        },
    };
}

/// Build an Attachment whose single exec_config carries a valid CNI
/// result. `cni_plugin_dir` controls where teardown would look for the
/// plugin binary; pointing it at a non-existent path makes any exec
/// attempt inside teardown fail.
fn makeTestAttachment(allocator: std.mem.Allocator, cni_plugin_dir: []const u8) !Attachment {
    var arena = try ArenaAllocator.init(allocator);
    const arena_alloc = arena.allocator();

    var plugin_arena = try ArenaAllocator.init(allocator);
    const plugin_alloc = plugin_arena.allocator();

    var conf = try json.ObjectMap.init(plugin_alloc, &.{}, &.{});
    try conf.put(plugin_alloc, "type", json.Value{ .string = "macvlan" });
    try conf.put(plugin_alloc, "name", json.Value{ .string = "test" });
    try conf.put(plugin_alloc, "cniVersion", json.Value{ .string = "1.0.0" });

    const cni_result =
        \\{"cniVersion":"1.0.0","interfaces":[{"name":"eth0","mac":"02:42:c0:a8:01:64"}],"ips":[{"interface":0,"address":"10.0.0.1/24"}]}
    ;
    const result_copy = try plugin_alloc.dupe(u8, cni_result);

    const plugin_conf = PluginConf{
        .arena = plugin_arena,
        .conf = conf,
        .result = std.ArrayList(u8).fromOwnedSlice(result_copy),
    };

    var attachment = Attachment{
        .arena = arena,
        .cni_plugin_dir = cni_plugin_dir,
        .exec_configs = std.ArrayList(PluginConf).empty,
    };
    try attachment.exec_configs.append(arena_alloc, plugin_conf);
    return attachment;
}

/// Build an Attachment with no exec_configs. teardown over an empty
/// config list is a no-op, so it always succeeds — useful for isolating
/// the rollback-skip path from teardown-failure noise.
fn makeEmptyAttachment(allocator: std.mem.Allocator, cni_plugin_dir: []const u8) !Attachment {
    const arena = try ArenaAllocator.init(allocator);
    return Attachment{
        .arena = arena,
        .cni_plugin_dir = cni_plugin_dir,
        .exec_configs = std.ArrayList(PluginConf).empty,
    };
}

/// Create a connected AF_UNIX socketpair for backing a test Responser.
/// Returns error.SkipZigTest if the kernel rejects the call (should not
/// happen on Linux). Caller owns both fds and must close them.
fn openTestSocketpair(fds: *[2]std.os.linux.fd_t) !void {
    const rc = std.os.linux.socketpair(
        std.os.linux.AF.UNIX,
        std.os.linux.SOCK.STREAM | std.os.linux.SOCK.CLOEXEC,
        0,
        fds,
    );
    if (std.os.linux.errno(rc) != .SUCCESS) return error.SkipZigTest;
}

test "persistAndRespond sends success response when state write succeeds" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const tentative = arena.allocator();

    var attachment = try makeTestAttachment(allocator, "/nonexistent-cni-path-for-test");
    defer attachment.deinit();

    var fds: [2]std.os.linux.fd_t = undefined;
    try openTestSocketpair(&fds);
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var stream: std.Io.net.Stream = .{
        .socket = .{
            .handle = fds[0],
            .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        },
    };
    var responser = Responser{ .io = std.testing.io, .stream = &stream };

    try persistAndRespond(.{
        .allocator = tentative,
        .io = std.testing.io,
        .attachment = &attachment,
        .request = makeTestRequest(),
        .responser = &responser,
        .caller_uid = 1000,
        .state_writer = alwaysSucceedingStateWriter,
    });

    try std.testing.expect(responser.done);
}

test "persistAndRespond rolls back and skips response when state write fails" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const tentative = arena.allocator();

    // Empty configs: teardown is a no-op, so the only observable effect
    // is that persistAndRespond returns the original StateWriteFail and
    // the success response is never written.
    var attachment = try makeEmptyAttachment(allocator, "/nonexistent-cni-path-for-test");
    defer attachment.deinit();

    var fds: [2]std.os.linux.fd_t = undefined;
    try openTestSocketpair(&fds);
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var stream: std.Io.net.Stream = .{
        .socket = .{
            .handle = fds[0],
            .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        },
    };
    var responser = Responser{ .io = std.testing.io, .stream = &stream };

    try std.testing.expectError(
        error.StateWriteFail,
        persistAndRespond(.{
            .allocator = tentative,
            .io = std.testing.io,
            .attachment = &attachment,
            .request = makeTestRequest(),
            .responser = &responser,
            .caller_uid = 1000,
            .state_writer = alwaysFailingStateWriter,
        }),
    );

    // The success response must NOT have been sent on the rollback path.
    try std.testing.expect(!responser.done);
}

test "persistAndRespond returns original error when both state write and teardown fail" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const tentative = arena.allocator();

    // Populated attachment: teardown will attempt to exec the plugin
    // binary at /nonexistent-cni-path-for-test/macvlan, which does not
    // exist. Whatever teardown returns must be swallowed so the original
    // state error (StateWriteFail) reaches the caller.
    var attachment = try makeTestAttachment(allocator, "/nonexistent-cni-path-for-test");
    defer attachment.deinit();

    var fds: [2]std.os.linux.fd_t = undefined;
    try openTestSocketpair(&fds);
    defer _ = std.os.linux.close(fds[0]);
    defer _ = std.os.linux.close(fds[1]);

    var stream: std.Io.net.Stream = .{
        .socket = .{
            .handle = fds[0],
            .address = .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        },
    };
    var responser = Responser{ .io = std.testing.io, .stream = &stream };

    try std.testing.expectError(
        error.StateWriteFail,
        persistAndRespond(.{
            .allocator = tentative,
            .io = std.testing.io,
            .attachment = &attachment,
            .request = makeTestRequest(),
            .responser = &responser,
            .caller_uid = 1000,
            .state_writer = alwaysFailingStateWriter,
        }),
    );
}

test {
    _ = CniConfig;
    _ = Attachment;
    _ = PluginConf;
}
