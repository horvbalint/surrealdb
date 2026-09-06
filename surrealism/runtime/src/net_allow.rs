//! Resolve `allow_net` strings once at module load time.
//!
//! DNS lookups run here (sync, on the thread loading the module — typically not on a Tokio
//! worker). Used to build the outbound socket allowlist for WASI (`parse_filters`).

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use ipnet::IpNet;

use crate::capabilities::NetTargets;

/// One resolved allow-net rule, aligned with [`crate::wasi_context`] socket filtering.
#[derive(Debug, Clone)]
pub enum ResolvedNetAllow {
	/// IP or CIDR — any port.
	Net(IpNet),
	/// Specific IP and port (from e.g. `host:443` or resolved hostname with port).
	IpPort(IpAddr, u16),
}

impl ResolvedNetAllow {
	/// Same semantics as the WASI `socket_addr_check` filter for outbound connections.
	pub fn matches_socket_addr(&self, addr: &SocketAddr) -> bool {
		match self {
			Self::Net(net) => net.contains(&addr.ip()),
			Self::IpPort(ip, port) => addr.ip() == *ip && addr.port() == *port,
		}
	}

	fn push_from_socket_addr(port: Option<u16>, addr: SocketAddr, out: &mut Vec<Self>) {
		if let Some(port) = port {
			out.push(Self::IpPort(addr.ip(), port));
		} else {
			out.push(Self::Net(IpNet::from(addr.ip())));
		}
	}
}

/// Returns `true` for IP addresses that belong to private, loopback, link-local,
/// or other special-use ranges. Kept in sync with `is_private_ip` in
/// `surrealdb-core`'s `net` module (surrealism-runtime does not depend on core).
pub(crate) fn is_private_ip(ip: IpAddr) -> bool {
	match ip.to_canonical() {
		IpAddr::V4(v4) => {
			v4.is_loopback()      // 127.0.0.0/8
				|| v4.is_private()    // 10/8, 172.16/12, 192.168/16
				|| v4.is_link_local() // 169.254.0.0/16
				|| v4.is_broadcast()  // 255.255.255.255
				|| v4.is_unspecified() // 0.0.0.0
				// Shared address space (RFC 6598): 100.64.0.0/10
				|| (u32::from(v4) & 0xFFC0_0000) == 0x6440_0000
		}
		IpAddr::V6(v6) => {
			v6.is_loopback()       // ::1
				|| v6.is_unspecified() // ::
				// Unique local (fc00::/7)
				|| (v6.segments()[0] & 0xFE00) == 0xFC00
				// Link-local (fe80::/10)
				|| (v6.segments()[0] & 0xFFC0) == 0xFE80
		}
	}
}

/// Resolved form of a module's `allow_net` declaration, shared by WASI socket
/// filtering and (indirectly) core capability scoping.
#[derive(Debug, Clone)]
pub enum ResolvedAllowNet {
	/// Deny all networking.
	None,
	/// Allow any public host. Private/special-use ranges stay blocked — see
	/// [`is_private_ip`].
	AllPublic,
	/// Allow only these resolved rules.
	Some(Vec<ResolvedNetAllow>),
}

impl ResolvedAllowNet {
	/// Same semantics as the WASI `socket_addr_check` filter for outbound connections.
	pub fn matches_socket_addr(&self, addr: &SocketAddr) -> bool {
		match self {
			Self::None => false,
			Self::AllPublic => !is_private_ip(addr.ip()),
			Self::Some(filters) => filters.iter().any(|f| f.matches_socket_addr(addr)),
		}
	}
}

/// Resolve a module's `allow_net` declaration the same way as SurrealDB
/// `NetTarget::from_str` ordering:
/// 1. `IpNet` (CIDR)
/// 2. `IpAddr` → `/32` or `/128`
/// 3. URL-style host, optional port; hostnames → DNS to IPs (blocking).
///
/// Returns an error if any entry fails to parse or any hostname fails to resolve,
/// aligning with the core pattern where DNS failures propagate rather than being
/// silently swallowed.
pub fn resolve_allow_net(targets: &NetTargets) -> anyhow::Result<Arc<ResolvedAllowNet>> {
	match targets {
		NetTargets::None => Ok(Arc::new(ResolvedAllowNet::None)),
		NetTargets::All => Ok(Arc::new(ResolvedAllowNet::AllPublic)),
		NetTargets::Some(entries) => {
			let mut out = Vec::new();
			for entry in entries {
				resolve_one(entry, &mut out)?;
			}
			Ok(Arc::new(ResolvedAllowNet::Some(out)))
		}
	}
}

fn resolve_one(entry: &str, out: &mut Vec<ResolvedNetAllow>) -> anyhow::Result<()> {
	if let Ok(net) = entry.parse::<IpNet>() {
		out.push(ResolvedNetAllow::Net(net));
		return Ok(());
	}
	if let Ok(ip) = entry.parse::<IpAddr>() {
		out.push(ResolvedNetAllow::Net(IpNet::from(ip)));
		return Ok(());
	}
	let url = url::Url::parse(&format!("http://{entry}"))
		.map_err(|e| anyhow::anyhow!("failed to parse allow_net entry '{entry}': {e}"))?;
	let host =
		url.host().ok_or_else(|| anyhow::anyhow!("allow_net entry '{entry}' has no host"))?;

	let port: Option<u16> = entry.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok());

	match host {
		url::Host::Ipv4(ip) => {
			let ip: IpAddr = ip.into();
			if let Some(port) = port {
				out.push(ResolvedNetAllow::IpPort(ip, port));
			} else {
				out.push(ResolvedNetAllow::Net(IpNet::from(ip)));
			}
		}
		url::Host::Ipv6(ip) => {
			let ip: IpAddr = ip.into();
			if let Some(port) = port {
				out.push(ResolvedNetAllow::IpPort(ip, port));
			} else {
				out.push(ResolvedNetAllow::Net(IpNet::from(ip)));
			}
		}
		url::Host::Domain(domain) => {
			resolve_hostname(domain, port, out)?;
		}
	}
	Ok(())
}

/// Blocking DNS — only call from module load / `Runtime::new`, not from async request paths.
fn resolve_hostname(
	hostname: &str,
	port: Option<u16>,
	out: &mut Vec<ResolvedNetAllow>,
) -> anyhow::Result<()> {
	let addrs = (hostname, port.unwrap_or(80))
		.to_socket_addrs()
		.map_err(|e| anyhow::anyhow!("failed to resolve allow_net hostname '{hostname}': {e}"))?;
	for addr in addrs {
		ResolvedNetAllow::push_from_socket_addr(port, addr, out);
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use std::net::SocketAddr;

	use super::*;

	fn some_entries(r: &ResolvedAllowNet) -> &[ResolvedNetAllow] {
		match r {
			ResolvedAllowNet::Some(entries) => entries,
			other => panic!("expected ResolvedAllowNet::Some, got {other:?}"),
		}
	}

	#[test]
	fn parses_ip_and_cidr() {
		let targets = NetTargets::Some(vec!["192.168.1.1".into(), "10.0.0.0/8".into()]);
		let r = resolve_allow_net(&targets).unwrap();
		let entries = some_entries(&r);
		assert_eq!(entries.len(), 2);
		let a: SocketAddr = "192.168.1.1:8080".parse().unwrap();
		assert!(entries[0].matches_socket_addr(&a));
		let inside: SocketAddr = "10.1.2.3:443".parse().unwrap();
		assert!(entries[1].matches_socket_addr(&inside));
	}

	#[test]
	fn parses_ip_with_port() {
		let targets = NetTargets::Some(vec!["192.168.1.1:80".into()]);
		let r = resolve_allow_net(&targets).unwrap();
		let entries = some_entries(&r);
		assert_eq!(entries.len(), 1);
		let ok: SocketAddr = "192.168.1.1:80".parse().unwrap();
		assert!(entries[0].matches_socket_addr(&ok));
		let wrong: SocketAddr = "192.168.1.1:443".parse().unwrap();
		assert!(!entries[0].matches_socket_addr(&wrong));
	}

	#[test]
	fn none_denies_everything() {
		let r = resolve_allow_net(&NetTargets::None).unwrap();
		assert!(matches!(*r, ResolvedAllowNet::None));
		let addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
		assert!(!r.matches_socket_addr(&addr));
	}

	#[test]
	fn all_public_allows_public_and_blocks_private() {
		let r = resolve_allow_net(&NetTargets::All).unwrap();
		assert!(matches!(*r, ResolvedAllowNet::AllPublic));

		// A public address (TEST-NET-1, RFC 5737, used for docs/examples).
		let public: SocketAddr = "192.0.2.1:443".parse().unwrap();
		assert!(r.matches_socket_addr(&public));

		// Loopback, RFC1918, link-local (incl. cloud metadata), and IPv6
		// loopback must all stay blocked under `*`.
		for blocked in ["127.0.0.1:80", "10.0.0.1:80", "169.254.169.254:80", "[::1]:80"] {
			let addr: SocketAddr = blocked.parse().unwrap();
			assert!(
				!r.matches_socket_addr(&addr),
				"expected {blocked} to be blocked under allow_net = *"
			);
		}
	}
}
