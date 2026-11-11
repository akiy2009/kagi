//! OIDC Back-Channel Logout 1.0 delivery.
//!
//! When a browser session ends, every client that received a token from that
//! session and registered `backchannel_logout_uri` is sent a signed logout
//! token. Delivery is best-effort and deliberately hardened against SSRF:
//! only HTTPS (or loopback HTTP in development), no redirects, short
//! timeouts, and no private/link-local destinations.

use crate::db;
use crate::util::*;
use crate::AppState;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::time::Duration;

const LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// Fire-and-forget notification for a user whose session just ended.
///
/// The caller has already revoked the server-side tokens. Delivery happens on
/// a blocking worker so a slow relying party cannot delay the logout response.
pub fn notify(st: &AppState, user_id: &str, session_id: Option<&str>) {
    let clients = match st
        .db
        .with(|c| db::backchannel_clients_for_user(c, user_id, session_id))
    {
        Ok(clients) => clients,
        Err(error) => {
            eprintln!("[kagi] back-channel client lookup failed: {error:#}");
            return;
        }
    };

    for client in clients {
        let Some(url) = client.backchannel_logout_uri.clone() else {
            continue;
        };
        if client.backchannel_logout_session_required && session_id.is_none() {
            continue;
        }
        let Some(token) = mint_logout_token(st, &client, user_id, session_id) else {
            continue;
        };
        // Never log the token itself: it is a bearer credential for the RP's
        // logout endpoint until it expires.
        let production = st.cfg.production;
        tokio::spawn(async move {
            let _ = tokio::task::spawn_blocking(move || deliver(production, &url, &token)).await;
        });
    }
}

fn mint_logout_token(
    st: &AppState,
    client: &db::Client,
    user_id: &str,
    session_id: Option<&str>,
) -> Option<String> {
    let mut claims = json!({
        "iss": st.cfg.issuer,
        "aud": client.id,
        "iat": now(),
        "exp": now() + 120,
        "jti": random_token(16),
        "sub": user_id,
        "events": { LOGOUT_EVENT: {} },
    });
    if let Some(sid) = session_id {
        claims["sid"] = json!(sid);
    }
    st.keys
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .current()
        .sign(Some("logout+jwt"), &claims)
        .map_err(|error| eprintln!("[kagi] logout-token signing failed: {error:#}"))
        .ok()
}

fn deliver(production: bool, url: &str, token: &str) -> Result<(), String> {
    let addresses = validate_destination(url, production)
        .map_err(|reason| format!("back-channel destination rejected: {reason}"))?;
    // Pin the validated addresses so a second DNS answer cannot rebind the
    // hostname to a private address between validation and connection.
    let pinned = addresses.clone();
    let resolver =
        move |_netloc: &str| -> std::io::Result<Vec<std::net::SocketAddr>> { Ok(pinned.clone()) };
    let body = format!("logout_token={}", urlenc(token));
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(3))
        .timeout_read(Duration::from_secs(5))
        .timeout_write(Duration::from_secs(5))
        .redirects(0)
        .resolver(resolver)
        .build();
    match agent
        .post(url)
        .set("Content-Type", "application/x-www-form-urlencoded")
        .set("Cache-Control", "no-store")
        .send_string(&body)
    {
        Ok(response) => {
            let status = response.status();
            if !(200..300).contains(&status) {
                return Err(format!("back-channel endpoint returned HTTP {status}"));
            }
            Ok(())
        }
        Err(error) => Err(format!("back-channel delivery failed: {error}")),
    }
}

/// Reject destinations that could reach loopback, link-local, private or
/// otherwise non-public networks. The hostname is resolved here; every
/// returned address must be public. The caller pins these addresses for the
/// actual connection. Outside production, loopback is allowed so developers
/// can run a relying party on the same machine.
fn validate_destination(url: &str, production: bool) -> Result<Vec<SocketAddr>, &'static str> {
    let uri: axum::http::Uri = url.parse().map_err(|_| "invalid URI")?;
    let scheme = uri.scheme_str().ok_or("missing scheme")?;
    if scheme != "https" && scheme != "http" {
        return Err("scheme must be https (or http for loopback development)");
    }
    let authority = uri.authority().ok_or("missing host")?;
    if authority.as_str().contains('@') {
        return Err("credentials are not allowed");
    }
    if uri
        .path_and_query()
        .is_some_and(|value| value.as_str().contains('#'))
    {
        return Err("fragments are not allowed");
    }
    let host = authority.host();
    if host.is_empty() {
        return Err("missing host");
    }
    // `http::uri::Authority::host` keeps the brackets around an IPv6 literal,
    // which `IpAddr::from_str` does not accept.
    let literal = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(host);
    let port = authority
        .port_u16()
        .unwrap_or(if scheme == "https" { 443 } else { 80 });

    let addresses: Vec<SocketAddr> = match literal.parse::<IpAddr>() {
        Ok(ip) => vec![SocketAddr::new(ip, port)],
        Err(_) => (host, port)
            .to_socket_addrs()
            .map_err(|_| "hostname did not resolve")?
            .collect(),
    };
    if addresses.is_empty() {
        return Err("hostname did not resolve");
    }
    if addresses
        .iter()
        .any(|address| !is_allowed_ip(address.ip(), production))
    {
        return Err("destination resolves to a non-public address");
    }
    Ok(addresses)
}

fn is_allowed_ip(ip: IpAddr, production: bool) -> bool {
    if !production && ip.is_loopback() {
        return true;
    }
    is_public_ip(ip)
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_public_v4(mapped);
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || is_documentation_v6(v6))
        }
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_unspecified()
        || ip.is_multicast()
        || octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 100 && (64..128).contains(&octets[1]))
        || (octets[0] == 198 && matches!(octets[1], 18 | 19))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0))
}

fn is_documentation_v6(ip: Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}

#[cfg(test)]
mod tests {
    use super::{is_allowed_ip, validate_destination};
    use std::net::IpAddr;

    #[test]
    fn rejects_private_and_link_local_destinations() {
        for url in [
            "https://10.0.0.1/hook",
            "https://192.168.1.5/hook",
            "https://169.254.169.254/latest/meta-data",
            "https://[fd00::1]/hook",
            "https://[fe80::1]/hook",
        ] {
            assert!(
                validate_destination(url, true).is_err(),
                "{url} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_credentials_and_non_http_schemes() {
        assert!(validate_destination("https://user:pass@example.com/hook", true).is_err());
        assert!(validate_destination("ftp://example.com/hook", true).is_err());
        assert!(validate_destination("file:///etc/passwd", true).is_err());
    }

    #[test]
    fn loopback_is_dev_only() {
        assert!(validate_destination("http://127.0.0.1:9000/hook", false).is_ok());
        assert!(validate_destination("http://[::1]:9000/hook", false).is_ok());
        assert!(validate_destination("http://127.0.0.1:9000/hook", true).is_err());
    }

    #[test]
    fn public_addresses_are_accepted() {
        assert!(is_allowed_ip("8.8.8.8".parse::<IpAddr>().unwrap(), true));
        assert!(is_allowed_ip(
            "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
            true
        ));
        assert!(!is_allowed_ip("127.0.0.1".parse::<IpAddr>().unwrap(), true));
        assert!(!is_allowed_ip("::1".parse::<IpAddr>().unwrap(), true));
        assert!(!is_allowed_ip("240.0.0.1".parse::<IpAddr>().unwrap(), true));
    }

    #[test]
    fn returns_pinned_socket_addresses() {
        use std::net::SocketAddr;
        let addresses =
            validate_destination("https://8.8.8.8:8443/hook", true).expect("public literal");
        assert_eq!(
            addresses,
            vec!["8.8.8.8:8443".parse::<SocketAddr>().unwrap()]
        );
    }
}
