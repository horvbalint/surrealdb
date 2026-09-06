use anyhow::Result;
use http::Method;
#[cfg(not(target_family = "wasm"))]
use reqwest::redirect::{Action, Attempt};
use reqwest::{Client, RequestBuilder};
use url::Url;

use crate::cnf::CommonConfig;
use crate::dbs::capabilities::{NetTarget, Targets};

pub struct HttpClient {
	client: Client,
}

impl HttpClient {
	#[cfg(not(target_family = "wasm"))]
	pub fn new(
		allow: Targets<NetTarget>,
		deny: Targets<NetTarget>,
		config: &CommonConfig,
	) -> Result<Self> {
		Self::new_with_redirect_policy(allow, deny, config, |policy| policy.follow())
	}

	/// Like [`Self::new`], but never lifts the private-IP guard, even when
	/// `allow` is `Targets::All`.
	///
	/// Used for Surrealism modules declaring `allow_net = ["*"]`: unlike the
	/// operator's own `--allow-net all` (an explicit, first-party "trust me"),
	/// `*` in a module manifest means "any public host" for third-party code,
	/// not reach into the server's internal network (loopback, RFC1918,
	/// link-local, cloud metadata, ...).
	#[cfg(not(target_family = "wasm"))]
	pub fn new_for_module_wildcard(
		allow: Targets<NetTarget>,
		deny: Targets<NetTarget>,
		config: &CommonConfig,
	) -> Result<Self> {
		Self::new_with_redirect_policy_and_guard(
			allow,
			deny,
			config,
			|policy| policy.follow(),
			false,
		)
	}

	#[cfg(not(target_family = "wasm"))]
	pub fn new_with_redirect_policy<F>(
		allow: Targets<NetTarget>,
		deny: Targets<NetTarget>,
		config: &CommonConfig,
		policy: F,
	) -> Result<Self>
	where
		F: Fn(Attempt) -> Action + Send + Sync + 'static,
	{
		let permit_private_ips = matches!(allow, Targets::All);
		Self::new_with_redirect_policy_and_guard(allow, deny, config, policy, permit_private_ips)
	}

	#[cfg(not(target_family = "wasm"))]
	fn new_with_redirect_policy_and_guard<F>(
		allow: Targets<NetTarget>,
		deny: Targets<NetTarget>,
		config: &CommonConfig,
		policy: F,
		permit_private_ips: bool,
	) -> Result<Self>
	where
		F: Fn(Attempt) -> Action + Send + Sync + 'static,
	{
		use std::sync::Arc;
		use std::time::Duration;

		use anyhow::Context as _;
		use http::header::USER_AGENT;
		use http::{HeaderMap, HeaderValue};
		use reqwest::redirect::{Attempt, Policy};

		use crate::dbs::capabilities::NetTarget;
		use crate::net::{FilteringResolver, NetFilter};

		let filter = Arc::new(NetFilter {
			allow,
			deny,
			permit_private_ips,
		});

		let filter_clone = Arc::clone(&filter);
		let max_redirects = config.max_http_redirects;
		let redirect_function = move |attempt: Attempt| {
			if attempt.previous().len() >= max_redirects {
				return attempt.stop();
			}

			// Re-validate the redirect target against allow/deny rules using the
			// same port-aware logic as `check_allowed_net`, so that port-specific
			// rules (e.g. `deny_net = ["example.com:6379"]`) are enforced on every
			// hop in the redirect chain.
			let url = attempt.url();
			let host = match url.host() {
				Some(h) => h,
				None => {
					let url_str = url.to_string();
					return attempt.error(crate::err::Error::InvalidUrl(url_str));
				}
			};
			let port = url.port_or_known_default();
			let target = NetTarget::Host(host.to_owned(), port);

			if !filter_clone.allow.matches(&target) || filter_clone.deny.matches(&target) {
				return attempt.error(crate::err::Error::NetTargetNotAllowed(target.to_string()));
			}

			policy(attempt)
		};

		let value = HeaderValue::from_str(&config.surrealdb_user_agent)
			.context("Invalid user agent string")?;

		let mut headers = HeaderMap::new();
		headers.insert(USER_AGENT, value);

		let client = Client::builder()
			.pool_idle_timeout(Duration::from_secs(config.http_idle_timeout_secs))
			.pool_max_idle_per_host(config.max_http_idle_connections_per_host)
			.connect_timeout(Duration::from_secs(config.http_connect_timeout_secs))
			.tcp_keepalive(Some(Duration::from_secs(60)))
			.http2_keep_alive_interval(Some(Duration::from_secs(30)))
			.http2_keep_alive_timeout(Duration::from_secs(10))
			.redirect(Policy::custom(redirect_function))
			.dns_resolver(FilteringResolver::from_net_filter(filter))
			.default_headers(headers)
			.build()?;

		Ok(HttpClient {
			client,
		})
	}

	#[cfg(target_family = "wasm")]
	pub fn new(
		allow: Targets<NetTarget>,
		deny: Targets<NetTarget>,
		_config: &CommonConfig,
	) -> Result<Self> {
		let _ = allow;
		let _ = deny;
		let client = Client::builder().build()?;
		Ok(HttpClient {
			client,
		})
	}

	pub fn request(&self, method: Method, url: Url) -> RequestBuilder {
		self.client.request(method, url)
	}
}
