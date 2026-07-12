//! Bridge primitives (04-bridge.md).
//!
//! M1-3 registered only the `env.ref` factory ([`env_ref`],
//! registration order step 3, 04 §Registration order). Milestone M3-2
//! added the first cap-gated bridge, [`sh`] (`sh.exec`); milestone M3-3
//! added [`net`] (`net.http_get` / `net.http_post` / `net.transfer`);
//! milestone M3-4 adds [`fs`] (`fs.write`) and [`mount`] (`mount.bind` /
//! `mount.umount`) — all installed the same way by
//! [`crate::sandbox::wire_sandboxed_profile`] via
//! [`crate::sandbox::capgate::register_if_granted`] (registration order
//! step 8).

pub mod env_ref;
pub mod fs;
pub mod mount;
pub mod net;
pub mod sh;
