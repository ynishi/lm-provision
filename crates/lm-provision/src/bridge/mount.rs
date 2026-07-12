//! `mount.bind` / `mount.umount` bridges (04-bridge.md §Outputs
//! `mount.bind` / `mount.umount`; milestone M3-4).
//!
//! Two separate `KNOWN_CAPABILITIES` entries
//! (05-sandbox-layer-contract.md §L4), so
//! [`crate::sandbox::wire_sandboxed_profile`] registers each with its
//! own [`crate::sandbox::capgate::register_if_granted`] call
//! (registration order step 8) — 04 §Outputs `mount.umount`: "Separate
//! capability from `mount.bind` — declaring bind does not grant
//! umount."
//!
//! Linux only: on other platforms **registration still succeeds** ("so
//! profiles remain loadable everywhere", 04 §Outputs), but the call
//! itself returns `{ ok = false, error = "not supported on this
//! platform (...)" }` at call time without attempting any syscall. Path
//! policy checks (`src` / `dst` / the umount target must lie under a
//! declared `paths` root) still run on every platform before that
//! not-supported short-circuit — they are precondition Lua errors (04
//! §Common conventions), independent of whether the effect itself can
//! run here. The Linux syscall path itself
//! ([`perform_bind`] / [`perform_umount`], `#[cfg(target_os =
//! "linux")]`) is exercised only in Linux CI / on-pod runs; this crate's
//! own test suite gates those cases accordingly (see
//! `tests/m3_fs_mount.rs`).

use mlua::{Lua, Table};

use crate::sandbox::capgate::CapabilityGate;
use crate::sandbox::policy::PathPolicy;

/// The capability name `mount.bind` installs under
/// (05-sandbox-layer-contract.md §L4 `KNOWN_CAPABILITIES`).
pub const CAPABILITY_BIND: &str = "mount.bind";
/// The capability name `mount.umount` installs under.
pub const CAPABILITY_UMOUNT: &str = "mount.umount";

/// Map any `Display`-able error (`CapGateError`, `PathPolicyError`) onto
/// the Lua-error convention 04-bridge.md §Common conventions requires
/// for "usage, policy, and secret errors" (the same helper
/// [`crate::bridge::net`], [`crate::bridge::sh`], and
/// [`crate::bridge::fs`] each already define for their own bridge
/// functions).
fn cap_error(err: impl std::fmt::Display) -> mlua::Error {
    mlua::Error::RuntimeError(err.to_string())
}

/// Get-or-create the profile-visible `mount` global table. Both
/// operations share one table, so whichever installs first (declaration
/// order is a `HashSet` iteration in
/// [`crate::sandbox::wire_sandboxed_profile`], so no operation can rely
/// on installing before the other) must not clobber a sibling that
/// already created it — the same pattern [`crate::bridge::net::net_table`]
/// documents for `net.http_get` / `net.http_post` / `net.transfer`.
fn mount_table(lua: &Lua) -> mlua::Result<Table> {
    match lua.globals().get::<Option<Table>>("mount")? {
        Some(table) => Ok(table),
        None => {
            let table = lua.create_table()?;
            lua.globals().set("mount", table.clone())?;
            Ok(table)
        }
    }
}

/// Register `mount.bind` on `lua`'s `mount` global table.
///
/// Callers are expected to reach this only through
/// [`crate::sandbox::capgate::register_if_granted`] (the register-skip
/// half of 04-bridge.md §Registration order step 8) — `gate` is
/// re-checked on every call anyway, as defence in depth over the
/// register skip (04 §Common conventions).
pub fn install_bind(lua: &Lua, gate: CapabilityGate, path_policy: PathPolicy) -> mlua::Result<()> {
    let bind_fn = lua.create_function(
        move |lua, (src, dst, opts): (String, String, Option<Table>)| -> mlua::Result<Table> {
            gate.require(CAPABILITY_BIND).map_err(cap_error)?;
            bind_entry(lua, &src, &dst, opts, &path_policy)
        },
    )?;
    mount_table(lua)?.set("bind", bind_fn)?;
    Ok(())
}

/// Register `mount.umount` on `lua`'s `mount` global table (see
/// [`install_bind`] for the registration-order contract).
pub fn install_umount(
    lua: &Lua,
    gate: CapabilityGate,
    path_policy: PathPolicy,
) -> mlua::Result<()> {
    let umount_fn = lua.create_function(
        move |lua, (path, opts): (String, Option<Table>)| -> mlua::Result<Table> {
            gate.require(CAPABILITY_UMOUNT).map_err(cap_error)?;
            umount_entry(lua, &path, opts, &path_policy)
        },
    )?;
    mount_table(lua)?.set("umount", umount_fn)?;
    Ok(())
}

/// Decoded `mount.bind` `opts` (04-bridge.md §Outputs `mount.bind`).
///
/// `recursive` / `read_only` are read only by the Linux
/// `#[cfg(target_os = "linux")]` [`perform_bind`] — the non-Linux stub
/// never touches either field (04 §Outputs: the platform-agnostic
/// not-supported path performs no effect at all), so both are dead code
/// on every other target.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct BindOpts {
    recursive: bool,
    read_only: bool,
    dry_run: bool,
}

fn decode_bind_opts(opts: &Option<Table>) -> mlua::Result<BindOpts> {
    let Some(opts) = opts else {
        return Ok(BindOpts {
            recursive: false,
            read_only: false,
            dry_run: false,
        });
    };
    Ok(BindOpts {
        recursive: opts.get::<Option<bool>>("recursive")?.unwrap_or(false),
        read_only: opts.get::<Option<bool>>("read_only")?.unwrap_or(false),
        dry_run: opts.get::<Option<bool>>("dry_run")?.unwrap_or(false),
    })
}

/// Decoded `mount.umount` `opts` (04-bridge.md §Outputs `mount.umount`).
///
/// `lazy` / `force` are read only by the Linux `#[cfg(target_os =
/// "linux")]` [`perform_umount`] — see [`BindOpts`]'s doc comment for
/// why the non-Linux stub leaves both fields unread.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct UmountOpts {
    lazy: bool,
    force: bool,
    dry_run: bool,
}

fn decode_umount_opts(opts: &Option<Table>) -> mlua::Result<UmountOpts> {
    let Some(opts) = opts else {
        return Ok(UmountOpts {
            lazy: false,
            force: false,
            dry_run: false,
        });
    };
    Ok(UmountOpts {
        lazy: opts.get::<Option<bool>>("lazy")?.unwrap_or(false),
        force: opts.get::<Option<bool>>("force")?.unwrap_or(false),
        dry_run: opts.get::<Option<bool>>("dry_run")?.unwrap_or(false),
    })
}

/// `mount.bind(src, dst, opts) -> result` (04-bridge.md §Outputs
/// `mount.bind`).
fn bind_entry(
    lua: &Lua,
    src: &str,
    dst: &str,
    opts: Option<Table>,
    path_policy: &PathPolicy,
) -> mlua::Result<Table> {
    // 04 §Outputs `mount.bind`: "Both paths ... must be under declared
    // paths roots" — a policy precondition Lua error, independent of
    // platform or `dry_run`.
    path_policy.check(src).map_err(cap_error)?;
    path_policy.check(dst).map_err(cap_error)?;
    let opts = decode_bind_opts(&opts)?;

    // Audit line before the effect (interpretive extension of
    // 09-apply-report-and-ledger.md §Audit log, see `crate::audit`'s own
    // module doc comment: neither `src` nor `dst` is a secret-shaped
    // value here).
    crate::audit::mount_bind(src, dst);

    if opts.dry_run {
        return build_bind_result(lua, true, src, dst, true, None);
    }

    perform_bind(lua, src, dst, &opts)
}

/// `mount.umount(path, opts) -> result` (04-bridge.md §Outputs
/// `mount.umount`).
fn umount_entry(
    lua: &Lua,
    path: &str,
    opts: Option<Table>,
    path_policy: &PathPolicy,
) -> mlua::Result<Table> {
    path_policy.check(path).map_err(cap_error)?;
    let opts = decode_umount_opts(&opts)?;

    // Audit line before the effect (interpretive extension, see
    // `bind_entry`'s own comment above).
    crate::audit::mount_umount(path);

    if opts.dry_run {
        return build_umount_result(lua, true, path, true, None);
    }

    perform_umount(lua, path, &opts)
}

/// `{ ok, dry_run, src, dst, error? }` (04-bridge.md §Outputs
/// `mount.bind` "Result").
fn build_bind_result(
    lua: &Lua,
    ok: bool,
    src: &str,
    dst: &str,
    dry_run: bool,
    error: Option<String>,
) -> mlua::Result<Table> {
    let result = lua.create_table()?;
    result.set("ok", ok)?;
    result.set("dry_run", dry_run)?;
    result.set("src", src)?;
    result.set("dst", dst)?;
    if let Some(error) = error {
        result.set("error", error)?;
    }
    Ok(result)
}

/// `{ ok, dry_run, path, error? }` (04-bridge.md §Outputs
/// `mount.umount` "Result").
fn build_umount_result(
    lua: &Lua,
    ok: bool,
    path: &str,
    dry_run: bool,
    error: Option<String>,
) -> mlua::Result<Table> {
    let result = lua.create_table()?;
    result.set("ok", ok)?;
    result.set("dry_run", dry_run)?;
    result.set("path", path)?;
    if let Some(error) = error {
        result.set("error", error)?;
    }
    Ok(result)
}

/// The literal 04-bridge.md §Outputs not-supported message: "`{ ok =
/// false, error = "not supported on this platform (...)" }`" —
/// `not_supported_message`'s `(...)` fill-in names the reason (Linux
/// only) rather than leaving it as a literal ellipsis.
fn not_supported_message(op: &str) -> String {
    format!("{op}: not supported on this platform (mount requires Linux)")
}

#[cfg(target_os = "linux")]
fn perform_bind(lua: &Lua, src: &str, dst: &str, opts: &BindOpts) -> mlua::Result<Table> {
    use nix::mount::{mount, umount, MsFlags};

    let mut flags = MsFlags::MS_BIND;
    if opts.recursive {
        flags |= MsFlags::MS_REC;
    }
    if let Err(err) = mount(Some(src), dst, None::<&str>, flags, None::<&str>) {
        return build_bind_result(
            lua,
            false,
            src,
            dst,
            false,
            Some(format!("mount.bind: {err}")),
        );
    }

    if opts.read_only {
        // 04 §Outputs `mount.bind`: "on remount failure the initial bind
        // is undone so the caller never observes a writable mount they
        // asked to be read-only."
        let remount_flags = MsFlags::MS_REMOUNT | MsFlags::MS_BIND | MsFlags::MS_RDONLY;
        if let Err(err) = mount(None::<&str>, dst, None::<&str>, remount_flags, None::<&str>) {
            let _ = umount(dst);
            return build_bind_result(
                lua,
                false,
                src,
                dst,
                false,
                Some(format!(
                    "mount.bind: read_only remount failed, bind undone: {err}"
                )),
            );
        }
    }

    build_bind_result(lua, true, src, dst, false, None)
}

#[cfg(not(target_os = "linux"))]
fn perform_bind(lua: &Lua, src: &str, dst: &str, _opts: &BindOpts) -> mlua::Result<Table> {
    build_bind_result(
        lua,
        false,
        src,
        dst,
        false,
        Some(not_supported_message(CAPABILITY_BIND)),
    )
}

#[cfg(target_os = "linux")]
fn perform_umount(lua: &Lua, path: &str, opts: &UmountOpts) -> mlua::Result<Table> {
    use nix::mount::{umount, umount2, MntFlags};

    let result = if opts.lazy || opts.force {
        let mut flags = MntFlags::empty();
        if opts.lazy {
            flags |= MntFlags::MNT_DETACH;
        }
        if opts.force {
            flags |= MntFlags::MNT_FORCE;
        }
        umount2(path, flags)
    } else {
        umount(path)
    };

    match result {
        Ok(()) => build_umount_result(lua, true, path, false, None),
        Err(err) => build_umount_result(
            lua,
            false,
            path,
            false,
            Some(format!("mount.umount: {err}")),
        ),
    }
}

#[cfg(not(target_os = "linux"))]
fn perform_umount(lua: &Lua, path: &str, _opts: &UmountOpts) -> mlua::Result<Table> {
    build_umount_result(
        lua,
        false,
        path,
        false,
        Some(not_supported_message(CAPABILITY_UMOUNT)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_supported_message_names_the_operation_and_the_platform_reason() {
        let message = not_supported_message("mount.bind");
        assert!(message.contains("not supported on this platform"));
        assert!(message.contains("mount.bind"));
    }
}
