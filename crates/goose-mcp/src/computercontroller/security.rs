use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;

/// Checks if a URL is safe from SSRF attacks.
/// This version is async and performs DNS resolution for domains.
pub async fn is_url_safe(url: &Url) -> bool {
    // 1. Scheme check: only allow http and https
    if url.scheme() != "http" && url.scheme() != "https" {
        return false;
    }

    // 2. Host check
    let host = match url.host() {
        Some(h) => h,
        None => return false,
    };

    match host {
        url::Host::Ipv4(ip) => {
            if is_private_v4(&ip) {
                return false;
            }
        }
        url::Host::Ipv6(ip) => {
            if is_private_v6(&ip) {
                return false;
            }
        }
        url::Host::Domain(domain) => {
            let domain_lower = domain.to_lowercase();
            // Block localhost and subdomains
            if domain_lower == "localhost" || domain_lower.ends_with(".localhost") {
                return false;
            }

            // Resolve domain and check resulting IPs to prevent DNS rebinding
            let port = url.port_or_known_default().unwrap_or(80);
            match tokio::net::lookup_host(format!("{}:{}", domain, port)).await {
                Ok(addrs) => {
                    let mut found = false;
                    for addr in addrs {
                        found = true;
                        if is_private_ip(addr.ip()) {
                            return false;
                        }
                    }
                    if !found {
                        return false; // Fail closed if no addresses found
                    }
                }
                Err(_) => {
                    return false; // Fail closed if lookup fails
                }
            }
        }
    }

    true
}

/// A synchronous version of is_url_safe that does not perform DNS resolution.
/// Useful for redirect policies where async is not supported.
pub fn is_url_safe_sync(url: &Url) -> bool {
    // 1. Scheme check: only allow http and https
    if url.scheme() != "http" && url.scheme() != "https" {
        return false;
    }

    // 2. Host check
    let host = match url.host() {
        Some(h) => h,
        None => return false,
    };

    match host {
        url::Host::Ipv4(ip) => !is_private_v4(&ip),
        url::Host::Ipv6(ip) => !is_private_v6(&ip),
        url::Host::Domain(domain) => {
            let domain_lower = domain.to_lowercase();
            !(domain_lower == "localhost" || domain_lower.ends_with(".localhost"))
        }
    }
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(&v4),
        IpAddr::V6(v6) => is_private_v6(&v6),
    }
}

fn is_private_v4(ip: &Ipv4Addr) -> bool {
    ip.is_loopback() || ip.is_private() || ip.is_link_local() || ip.is_unspecified() || ip.is_broadcast()
}

fn is_private_v6(ip: &Ipv6Addr) -> bool {
    // Check if it's an IPv4-mapped or IPv4-compatible address
    if let Some(v4) = ip.to_ipv4() {
        return is_private_v4(&v4);
    }

    ip.is_loopback() || ip.is_unspecified() ||
    (ip.segments()[0] & 0xfe00) == 0xfc00 || // Unique Local Address (fc00::/7)
    (ip.segments()[0] & 0xffc0) == 0xfe80    // Link-Local Unicast (fe80::/10)
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[tokio::test]
    async fn test_is_url_safe() {
        // Allowed
        assert!(is_url_safe(&Url::parse("https://google.com").unwrap()).await);
        assert!(is_url_safe(&Url::parse("http://example.org/path").unwrap()).await);

        // Blocked schemes
        assert!(!is_url_safe(&Url::parse("file:///etc/passwd").unwrap()).await);
        assert!(!is_url_safe(&Url::parse("ftp://example.com").unwrap()).await);

        // Blocked IPv4
        assert!(!is_url_safe(&Url::parse("http://127.0.0.1").unwrap()).await);
        assert!(!is_url_safe(&Url::parse("http://10.0.0.1").unwrap()).await);
        assert!(!is_url_safe(&Url::parse("http://192.168.1.1").unwrap()).await);
        assert!(!is_url_safe(&Url::parse("http://169.254.169.254").unwrap()).await);

        // Blocked IPv6
        assert!(!is_url_safe(&Url::parse("http://[::1]").unwrap()).await);
        assert!(!is_url_safe(&Url::parse("http://[fc00::1]").unwrap()).await);
        assert!(!is_url_safe(&Url::parse("http://[fe80::1]").unwrap()).await);

        // IPv4-mapped IPv6
        assert!(!is_url_safe(&Url::parse("http://[::ffff:127.0.0.1]").unwrap()).await);

        // Blocked Domains
        assert!(!is_url_safe(&Url::parse("http://localhost").unwrap()).await);
        assert!(!is_url_safe(&Url::parse("http://test.localhost").unwrap()).await);
    }

    #[test]
    fn test_is_url_safe_sync() {
        assert!(is_url_safe_sync(&Url::parse("https://google.com").unwrap()));
        assert!(!is_url_safe_sync(&Url::parse("http://localhost").unwrap()));
        assert!(!is_url_safe_sync(&Url::parse("http://127.0.0.1").unwrap()));
    }
}
