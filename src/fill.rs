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

/// Whether a login saved for `saved` may fill on `page`: the same site, on the same scheme and
/// port. A site is a registrable domain and every host under it, so a login saved for
/// `www.example.com` fills on `login.example.com` and on `example.com`. Under a suffix many owners
/// share, such as `github.io`, each name is its own site, and an address or a bare suffix is only
/// itself. Plain HTTP is allowed only on this machine.
pub fn matches(saved: &str, page: &Origin) -> bool {
    let Some(saved) = Origin::parse(saved) else { return false };
    if saved.scheme != page.scheme || saved.port != page.port {
        return false;
    }
    if page.scheme != "https" && !page.is_loopback() {
        return false;
    }
    saved.host == page.host || registrable_domain(&saved.host).is_some_and(|site| registrable_domain(&page.host) == Some(site))
}

/// The part of `host` one owner registered, by the public suffix list: `example.com` for
/// `login.example.com`, `alice.github.io` for `www.alice.github.io`. None for an address or a bare
/// suffix such as `com`, `co.uk` or `github.io`, which belong to nobody.
fn registrable_domain(host: &str) -> Option<&str> {
    if host.parse::<std::net::IpAddr>().is_ok() { None } else { psl::domain_str(host) }
}

/// Whether `host` is one site's own, so what lies under it is that site's too.
pub(crate) fn is_registrable(host: &str) -> bool {
    registrable_domain(host).is_some()
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
    fn any_host_of_one_site_fills_on_any_other() {
        for (saved, page_url) in [
            ("https://www.example.com", "https://login.example.com/"),
            ("https://example.com", "https://login.example.com/"),
            ("https://login.example.com", "https://example.com/"),
            ("https://login.example.com", "https://www.example.com/"),
            ("https://shop.example.co.uk", "https://account.example.co.uk/"),
            ("https://alice.github.io", "https://www.alice.github.io/"),
            ("https://www.alice.github.io", "https://alice.github.io/"),
        ] {
            assert!(matches(saved, &page(page_url)), "{saved} on {page_url}");
        }
    }

    #[test]
    fn another_site_under_a_shared_suffix_or_another_scheme_or_port_does_not() {
        for (saved, page_url) in [
            ("https://a.github.io", "https://b.github.io/"),
            ("https://www.a.github.io", "https://b.github.io/"),
            ("https://example.co.uk", "https://other.co.uk/"),
            ("https://www.example.com", "https://login.example.com.evil.com/"),
            ("https://www.example.com", "https://login.examp1e.com/"),
            ("https://www.example.com", "http://login.example.com/"),
            ("https://www.example.com", "https://login.example.com:8443/"),
            ("https://10.0.0.1", "https://10.0.0.2/"),
        ] {
            assert!(!matches(saved, &page(page_url)), "{saved} on {page_url}");
        }
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
