pub fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "<redacted>".to_string();
    };

    let host = rest.split('/').next().unwrap_or_default();
    if host.is_empty() {
        return format!("{scheme}://<redacted>");
    }

    format!("{scheme}://{host}/<redacted>")
}
