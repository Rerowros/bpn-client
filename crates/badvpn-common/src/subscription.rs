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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionFailureKind {
    HwidLimit,
    Expired,
    TrafficExhausted,
    Unauthorized,
    RateLimited,
    NotFound,
    ProviderMaintenance,
    ProviderError,
    InvalidFormat,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionFailure {
    pub kind: SubscriptionFailureKind,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionProviderHint {
    Remnawave,
    Pasarguard,
    GenericPanel,
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

pub fn classify_subscription_failure(
    status_code: Option<u16>,
    body: &str,
) -> Option<SubscriptionFailure> {
    let text = normalized_failure_text(body);
    let lower = text.to_lowercase();

    let kind = if contains_any(
        &lower,
        &[
            "hwid",
            "hardware id",
            "device limit",
            "devices limit",
            "maximum devices",
            "max devices",
            "too many devices",
            "limit devices",
            "device count",
            "лимит устройств",
            "превышен лимит устройств",
            "слишком много устройств",
            "устройств",
        ],
    ) {
        SubscriptionFailureKind::HwidLimit
    } else if contains_any(
        &lower,
        &[
            "expired",
            "subscription expired",
            "user expired",
            "account expired",
            "expire time",
            "срок действия",
            "истек",
            "истёк",
            "просроч",
            "законч",
        ],
    ) {
        SubscriptionFailureKind::Expired
    } else if contains_any(
        &lower,
        &[
            "traffic exhausted",
            "traffic limit",
            "quota exceeded",
            "bandwidth exhausted",
            "data limit",
            "no traffic",
            "трафик",
            "квота",
            "лимит трафика",
        ],
    ) {
        SubscriptionFailureKind::TrafficExhausted
    } else if contains_any(
        &lower,
        &[
            "maintenance",
            "temporarily unavailable",
            "service unavailable",
            "panel unavailable",
            "технические работы",
            "обслуживание",
        ],
    ) || matches!(status_code, Some(502 | 503 | 504))
    {
        SubscriptionFailureKind::ProviderMaintenance
    } else if matches!(status_code, Some(429))
        || contains_any(
            &lower,
            &["rate limit", "too many requests", "слишком много запросов"],
        )
    {
        SubscriptionFailureKind::RateLimited
    } else if matches!(status_code, Some(404 | 410))
        || contains_any(
            &lower,
            &[
                "not found",
                "user not found",
                "profile not found",
                "subscription not found",
            ],
        )
    {
        SubscriptionFailureKind::NotFound
    } else if matches!(status_code, Some(401 | 403))
        || contains_any(
            &lower,
            &[
                "unauthorized",
                "forbidden",
                "invalid token",
                "invalid subscription",
                "access denied",
                "token not valid",
                "неверный токен",
                "доступ запрещ",
            ],
        )
    {
        SubscriptionFailureKind::Unauthorized
    } else if !body.trim().is_empty() && count_uri_nodes(body) == 0 && count_yaml_proxies(body) == 0
    {
        SubscriptionFailureKind::InvalidFormat
    } else {
        return None;
    };

    Some(SubscriptionFailure {
        kind,
        message: subscription_failure_message(kind),
    })
}

pub fn detect_subscription_provider_hint(
    headers: &[(&str, &str)],
    body: &str,
) -> Option<SubscriptionProviderHint> {
    let mut evidence = String::new();
    for (key, value) in headers {
        evidence.push_str(&key.to_lowercase());
        evidence.push(' ');
        evidence.push_str(&value.to_lowercase());
        evidence.push(' ');
    }
    evidence.push_str(&normalized_failure_text(body).to_lowercase());

    if contains_any(
        &evidence,
        &[
            "remnawave",
            "x-remnawave",
            "hwid_device_limit",
            "device_limit_reached",
        ],
    ) {
        Some(SubscriptionProviderHint::Remnawave)
    } else if contains_any(
        &evidence,
        &[
            "pasarguard",
            "x-pasarguard",
            "subscription_expired",
            "user_subscription_expired",
        ],
    ) {
        Some(SubscriptionProviderHint::Pasarguard)
    } else if contains_any(
        &evidence,
        &[
            "profile-title",
            "subscription-userinfo",
            "profile-web-page-url",
            "support-url",
        ],
    ) {
        Some(SubscriptionProviderHint::GenericPanel)
    } else {
        None
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

fn normalized_failure_text(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        let mut parts = Vec::new();
        collect_json_strings(&value, &mut parts);
        if !parts.is_empty() {
            return parts.join(" ");
        }
    }

    trimmed.chars().take(4096).collect()
}

fn collect_json_strings(value: &serde_json::Value, parts: &mut Vec<String>) {
    match value {
        serde_json::Value::String(value) => parts.push(value.clone()),
        serde_json::Value::Array(values) => {
            for value in values {
                collect_json_strings(value, parts);
            }
        }
        serde_json::Value::Object(map) => {
            for key in ["error", "message", "detail", "details", "code", "status"] {
                if let Some(value) = map.get(key) {
                    collect_json_strings(value, parts);
                }
            }
        }
        _ => {}
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn subscription_failure_message(kind: SubscriptionFailureKind) -> String {
    match kind {
        SubscriptionFailureKind::HwidLimit => {
            "Provider rejected the subscription because the device/HWID limit appears to be reached. Open the provider panel or contact support to reset allowed devices.".to_string()
        }
        SubscriptionFailureKind::Expired => {
            "Provider reports that the subscription has expired. Renew the profile in the provider panel, then refresh the subscription.".to_string()
        }
        SubscriptionFailureKind::TrafficExhausted => {
            "Provider reports that the traffic quota is exhausted. Top up or renew the subscription, then refresh the profile.".to_string()
        }
        SubscriptionFailureKind::Unauthorized => {
            "Provider rejected the subscription token. Check that the link is current and was copied from the provider panel.".to_string()
        }
        SubscriptionFailureKind::RateLimited => {
            "Provider rate-limited subscription refresh. Wait a few minutes before trying again.".to_string()
        }
        SubscriptionFailureKind::NotFound => {
            "Provider could not find this subscription profile. Generate a fresh subscription link from the provider panel.".to_string()
        }
        SubscriptionFailureKind::ProviderMaintenance => {
            "Provider panel is temporarily unavailable. Keep the last working profile and try refreshing later.".to_string()
        }
        SubscriptionFailureKind::ProviderError => {
            "Provider returned an unexpected subscription error. Keep the last working profile and contact support if it repeats.".to_string()
        }
        SubscriptionFailureKind::InvalidFormat => {
            "Subscription response is not a supported Clash/Mihomo profile or URI list. Check the provider panel export format.".to_string()
        }
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

    #[test]
    fn classifies_hwid_limit_from_panel_json() {
        let failure = classify_subscription_failure(
            Some(403),
            r#"{"error":"HWID limit exceeded","message":"too many devices"}"#,
        )
        .unwrap();

        assert_eq!(failure.kind, SubscriptionFailureKind::HwidLimit);
        assert!(failure.message.contains("HWID"));
    }

    #[test]
    fn classifies_expired_and_traffic_errors() {
        let expired = classify_subscription_failure(Some(200), "Subscription expired").unwrap();
        assert_eq!(expired.kind, SubscriptionFailureKind::Expired);

        let exhausted = classify_subscription_failure(None, "traffic limit exceeded").unwrap();
        assert_eq!(exhausted.kind, SubscriptionFailureKind::TrafficExhausted);
    }

    #[test]
    fn classifies_invalid_non_profile_body() {
        let failure = classify_subscription_failure(None, "<html>login required</html>").unwrap();

        assert_eq!(failure.kind, SubscriptionFailureKind::InvalidFormat);
    }

    #[test]
    fn classifies_sanitized_remnawave_hwid_fixture() {
        let body = include_str!("../tests/fixtures/subscription_panels/remnawave_hwid_limit.json");
        let failure = classify_subscription_failure(Some(403), body).unwrap();

        assert_eq!(failure.kind, SubscriptionFailureKind::HwidLimit);
        assert_eq!(
            detect_subscription_provider_hint(&[("x-remnawave-panel", "true")], body),
            Some(SubscriptionProviderHint::Remnawave)
        );
    }

    #[test]
    fn classifies_sanitized_pasarguard_expired_fixture() {
        let body = include_str!("../tests/fixtures/subscription_panels/pasarguard_expired.json");
        let failure = classify_subscription_failure(Some(410), body).unwrap();

        assert_eq!(failure.kind, SubscriptionFailureKind::Expired);
        assert_eq!(
            detect_subscription_provider_hint(&[("x-panel-type", "pasarguard")], body),
            Some(SubscriptionProviderHint::Pasarguard)
        );
    }

    #[test]
    fn classifies_nested_quota_fixture() {
        let body =
            include_str!("../tests/fixtures/subscription_panels/generic_quota_exhausted.json");
        let failure = classify_subscription_failure(Some(402), body).unwrap();

        assert_eq!(failure.kind, SubscriptionFailureKind::TrafficExhausted);
    }

    #[test]
    fn detects_generic_panel_from_sanitized_header_fixture() {
        let headers = include_str!("../tests/fixtures/subscription_panels/remnawave_headers.txt");
        let header_pairs = headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.trim(), value.trim()))
            .collect::<Vec<_>>();

        assert_eq!(
            detect_subscription_provider_hint(&header_pairs, ""),
            Some(SubscriptionProviderHint::Remnawave)
        );
        assert_eq!(
            decode_header_value(
                header_pairs
                    .iter()
                    .find(|(key, _)| *key == "profile-title")
                    .map(|(_, value)| *value)
            )
            .as_deref(),
            Some("Remnawave Sanitized Profile")
        );
        assert_eq!(
            parse_subscription_userinfo(
                header_pairs
                    .iter()
                    .find(|(key, _)| *key == "subscription-userinfo")
                    .map(|(_, value)| *value)
            )
            .total_bytes,
            Some(1_048_576)
        );
    }
}
