use base64::{engine::general_purpose, Engine};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionFormat {
    Base64UriList,
    UriList,
    ClashYaml,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionUserInfo {
    pub upload_bytes: Option<u64>,
    pub download_bytes: Option<u64>,
    pub total_bytes: Option<u64>,
    pub expire_at: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionBodySummary {
    pub format: SubscriptionFormat,
    pub node_count: usize,
    pub decoded_size_bytes: usize,
}

pub fn decode_header_value(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if let Some(encoded) = value.strip_prefix("base64:") {
        let decoded = general_purpose::STANDARD.decode(encoded).ok()?;
        return String::from_utf8(decoded).ok();
    }

    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

pub fn parse_subscription_userinfo(value: Option<&str>) -> SubscriptionUserInfo {
    let mut info = SubscriptionUserInfo::default();
    let Some(value) = value else {
        return info;
    };

    for part in value.split(';') {
        let Some((key, raw_value)) = part.trim().split_once('=') else {
            continue;
        };
        let parsed = raw_value.trim().parse::<u64>().ok();
        match key.trim().to_ascii_lowercase().as_str() {
            "upload" => info.upload_bytes = parsed,
            "download" => info.download_bytes = parsed,
            "total" => info.total_bytes = parsed,
            "expire" => info.expire_at = parsed,
            _ => {}
        }
    }

    info
}

pub fn summarize_subscription_body(body: &str) -> SubscriptionBodySummary {
    if let Some(decoded) = subscription_body_to_text(body) {
        let node_count = count_uri_nodes(&decoded);
        if node_count > 0 {
            return SubscriptionBodySummary {
                format: SubscriptionFormat::Base64UriList,
                node_count,
                decoded_size_bytes: decoded.len(),
            };
        }
    }

    let direct_uri_count = count_uri_nodes(body);
    if direct_uri_count > 0 {
        return SubscriptionBodySummary {
            format: SubscriptionFormat::UriList,
            node_count: direct_uri_count,
            decoded_size_bytes: body.len(),
        };
    }

    let yaml_proxy_count = count_yaml_proxies(body);
    if yaml_proxy_count > 0 {
        return SubscriptionBodySummary {
            format: SubscriptionFormat::ClashYaml,
            node_count: yaml_proxy_count,
            decoded_size_bytes: body.len(),
        };
    }

    SubscriptionBodySummary {
        format: SubscriptionFormat::Unknown,
        node_count: 0,
        decoded_size_bytes: body.len(),
    }
}

pub fn subscription_body_to_text(body: &str) -> Option<String> {
    let compact: String = body.chars().filter(|ch| !ch.is_whitespace()).collect();
    if compact.is_empty() {
        return None;
    }

    let decoded = general_purpose::STANDARD.decode(compact).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    if count_uri_nodes(&decoded) > 0 {
        Some(decoded)
    } else {
        None
    }
}

fn count_uri_nodes(body: &str) -> usize {
    body.lines()
        .map(str::trim)
        .filter(|line| {
            line.starts_with("vless://")
                || line.starts_with("vmess://")
                || line.starts_with("trojan://")
                || line.starts_with("ss://")
                || line.starts_with("ssr://")
                || line.starts_with("hysteria2://")
                || line.starts_with("hy2://")
        })
        .count()
}

fn count_yaml_proxies(body: &str) -> usize {
    let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(body) else {
        return 0;
    };

    value
        .get("proxies")
        .and_then(serde_yaml::Value::as_sequence)
        .map_or(0, Vec::len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base64_headers() {
        let decoded = decode_header_value(Some("base64:0JIg0YHQu9GD0YfQsNC1INC90LDQttC80LjRgtC1"));

        assert_eq!(decoded.as_deref(), Some("В случае нажмите"));
    }

    #[test]
    fn parses_subscription_userinfo() {
        let info = parse_subscription_userinfo(Some(
            "upload=10; download=20; total=100; expire=1893456000",
        ));

        assert_eq!(info.upload_bytes, Some(10));
        assert_eq!(info.download_bytes, Some(20));
        assert_eq!(info.total_bytes, Some(100));
        assert_eq!(info.expire_at, Some(1_893_456_000));
    }

    #[test]
    fn summarizes_base64_uri_list() {
        let body = base64::engine::general_purpose::STANDARD
            .encode("vless://id@example.com:443#Example\nvmess://encoded\n");
        let summary = summarize_subscription_body(&body);

        assert_eq!(summary.format, SubscriptionFormat::Base64UriList);
        assert_eq!(summary.node_count, 2);
    }

    #[test]
    fn summarizes_clash_yaml() {
        let summary = summarize_subscription_body(
            r#"
proxies:
  - name: Germany
    type: vless
  - name: Sweden
    type: vless
"#,
        );

        assert_eq!(summary.format, SubscriptionFormat::ClashYaml);
        assert_eq!(summary.node_count, 2);
    }
}
