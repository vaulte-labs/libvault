//! Deciding whether a saved login belongs on a page. This is the anti-phishing check, so it
//! compares parsed origins and never strings: a lookalike must fail here, however it is spelled.

/// Where a page came from. The browser supplies this, not the page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub scheme: String,
    pub host: String,
    pub port: u16,
}

impl Origin {
    /// Parses an origin out of a URL. Rejects anything that is not plainly web content.
    pub fn parse(url: &str) -> Option<Self> {
        let (scheme, rest) = url.trim().split_once("://")?;
        let scheme = scheme.to_ascii_lowercase();
        let default_port = match scheme.as_str() {
            "https" => 443,
            "http" => 80,
            _ => return None,
        };
        // A browser reads a backslash as a slash.
        let authority = rest.split(['/', '\\', '?', '#']).next()?;
        // `https://github.com@evil.com` is a page on evil.com.
        let host_and_port = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
        if host_and_port.starts_with('[') || host_and_port.contains(' ') {
            return None;
        }
        let (host, port) = match host_and_port.rsplit_once(':') {
            Some((host, port)) => (host, port.parse().ok()?),
            None => (host_and_port, default_port),
        };
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() { None } else { Some(Self { scheme, host, port }) }
    }

    pub(crate) fn is_loopback(&self) -> bool {
        self.host == "localhost" || self.host == "127.0.0.1"
    }
}

/// The origin as a browser writes it, with the port only where it is not the scheme's own.
impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.scheme.as_str(), self.port) {
            ("https", 443) | ("http", 80) => write!(f, "{}://{}", self.scheme, self.host),
            _ => write!(f, "{}://{}:{}", self.scheme, self.host, self.port),
        }
    }
}

/// Whether a login saved for `saved` may fill on `page`. The page may be the saved host or a
/// subdomain of it, on the same scheme and port. Plain HTTP is allowed only on this machine.
pub fn matches(saved: &str, page: &Origin) -> bool {
    let Some(saved) = Origin::parse(saved) else { return false };
    if saved.scheme != page.scheme || saved.port != page.port {
        return false;
    }
    if page.scheme != "https" && !page.is_loopback() {
        return false;
    }
    if saved.host == page.host {
        return true;
    }
    is_registrable(&saved.host) && page.host.ends_with(&format!(".{}", saved.host))
}

/// Whether `host` is one site's own, so what lies under it is that site's too. A suffix many sites
/// share, such as `com`, `co.uk` or `github.io`, belongs to none of them, and neither does an
/// address.
pub(crate) fn is_registrable(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_err() && psl::domain_str(host).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(url: &str) -> Origin {
        Origin::parse(url).unwrap()
    }

    #[test]
    fn the_real_site_and_its_subdomains_match() {
        assert!(matches("https://github.com", &page("https://github.com/login")));
        assert!(matches("https://github.com/login", &page("https://GitHub.com/other?x=1")));
        assert!(matches("https://google.com", &page("https://accounts.google.com/signin")));
    }

    #[test]
    fn lookalikes_never_match() {
        for phishing in [
            "https://github.com.evil.com/login",
            "https://evil.com/github.com",
            "https://githubXcom.evil.com",
            "https://notgithub.com",
            "https://github.co",
            "https://github.com@evil.com/",
            "https://evil.com#https://github.com",
            "https://evil.com?https://github.com",
            "https://github.com:443@evil.com",
        ] {
            assert!(!matches("https://github.com", &page(phishing)), "{phishing}");
        }
    }

    #[test]
    fn a_downgrade_or_another_port_never_matches() {
        assert!(!matches("https://github.com", &page("http://github.com")));
        assert!(!matches("https://github.com", &page("https://github.com:8443")));
        assert!(!matches("http://github.com", &page("http://github.com")), "plain HTTP is only for this machine");
    }

    #[test]
    fn plain_http_works_on_this_machine_for_development() {
        assert!(matches("http://localhost:3000", &page("http://localhost:3000/login")));
        assert!(matches("http://127.0.0.1:8080", &page("http://127.0.0.1:8080/")));
        assert!(!matches("http://localhost:3000", &page("http://localhost:3001/login")));
    }

    #[test]
    fn a_suffix_many_sites_share_matches_none_of_them() {
        assert!(!matches("https://github.io", &page("https://evil.github.io")));
        assert!(!matches("https://co.uk", &page("https://evil.co.uk")));
        assert!(matches("https://alice.github.io", &page("https://www.alice.github.io")));
        assert!(matches("https://example.co.uk", &page("https://www.example.co.uk")));
    }

    #[test]
    fn a_bare_suffix_or_address_matches_only_itself() {
        assert!(!matches("https://com", &page("https://github.com")));
        assert!(!matches("https://127.0.0.1", &page("https://1.127.0.0.1")));
    }

    #[test]
    fn only_web_content_has_an_origin() {
        for url in ["file:///etc/passwd", "javascript:alert(1)", "data:text/html,x", "about:blank", "chrome://settings", "https://", "nonsense"] {
            assert_eq!(Origin::parse(url), None, "{url}");
        }
    }

    #[test]
    fn a_backslash_ends_the_host_as_it_does_in_a_browser() {
        assert_eq!(Origin::parse("https://evil.example\\@github.com/").unwrap().host, "evil.example");
    }

    #[test]
    fn a_trailing_dot_is_the_same_host() {
        assert!(matches("https://github.com", &page("https://github.com./")));
    }
}
