use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::{
    compile_policy, subscription_body_to_text, AppRouteMode, CompiledPolicy, PolicyCompileInput,
    ProxyGroupInfo, RouteMode, RoutingPolicySettings, RuntimeFacts, SubscriptionFormat,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GeneratedMihomoConfig {
    pub yaml: String,
    pub proxy_count: usize,
    pub direct_rule_count: usize,
    pub format: SubscriptionFormat,
    pub policy: CompiledPolicy,
}

#[cfg(test)]
mod architecture_fix_tests {
    use super::*;

    #[test]
    fn overlay_preserves_provider_geo_rules() {
        let generated = overlay_mihomo_config_yaml(
            r#"
proxies:
  - name: Turkey
    type: vless
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - Turkey
rules:
  - GEOSITE,category-ads-all,REJECT
  - GEOIP,telegram,PROXY,no-resolve
  - MATCH,PROXY
"#,
            "secret",
            &MihomoConfigOptions::default(),
        )
        .unwrap();

        assert!(generated.contains("GEOSITE,category-ads-all,REJECT"));
        assert!(generated.contains("GEOIP,telegram,PROXY,no-resolve"));
    }

    #[test]
    fn overlay_deduplicates_private_cidr_rules() {
        let generated = overlay_mihomo_config_yaml(
            r#"
proxies:
  - name: Turkey
    type: vless
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - Turkey
rules:
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - GEOSITE,PRIVATE,DIRECT
  - MATCH,PROXY
"#,
            "secret",
            &MihomoConfigOptions::default(),
        )
        .unwrap();

        assert_eq!(
            generated
                .matches("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")
                .count(),
            1
        );
    }

    #[test]
    fn overlay_adds_game_process_direct_rules() {
        let options = MihomoConfigOptions {
            zapret_direct_processes: vec!["REPO.exe".to_string()],
            zapret_direct_udp_ports: vec!["50000-50100".to_string()],
            ..MihomoConfigOptions::default()
        };
        let generated = overlay_mihomo_config_yaml(
            r#"
proxies:
  - name: Turkey
    type: vless
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - Turkey
rules:
  - MATCH,PROXY
"#,
            "secret",
            &options,
        )
        .unwrap();

        assert!(generated.contains("PROCESS-NAME,REPO.exe,DIRECT"));
        assert!(generated.contains("AND,((NETWORK,UDP),(DST-PORT,50000-50100)),DIRECT"));
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MihomoConfigOptions {
    pub route_mode: RouteMode,
    pub log_level: String,
    pub mixed_port: u16,
    pub controller_port: u16,
    pub allow_lan: bool,
    pub ipv6: bool,
    pub tun_enabled: bool,
    pub tun_stack: String,
    pub tun_strict_route: bool,
    pub tun_auto_route: bool,
    pub tun_auto_detect_interface: bool,
    pub dns_mode: String,
    pub dns_nameservers: Vec<String>,
    pub zapret_direct_domains: Vec<String>,
    pub zapret_direct_cidrs: Vec<String>,
    pub zapret_direct_processes: Vec<String>,
    pub zapret_direct_tcp_ports: Vec<String>,
    pub zapret_direct_udp_ports: Vec<String>,
    pub selected_proxies: BTreeMap<String, String>,
    pub routing_policy: RoutingPolicySettings,
}

impl Default for MihomoConfigOptions {
    fn default() -> Self {
        Self {
            route_mode: RouteMode::Smart,
            log_level: "info".to_string(),
            mixed_port: 7890,
            controller_port: 9090,
            allow_lan: false,
            ipv6: false,
            tun_enabled: true,
            tun_stack: "mixed".to_string(),
            tun_strict_route: true,
            tun_auto_route: true,
            tun_auto_detect_interface: true,
            dns_mode: "fake-ip".to_string(),
            dns_nameservers: vec![
                "https://1.1.1.1/dns-query".to_string(),
                "https://8.8.8.8/dns-query".to_string(),
            ],
            zapret_direct_domains: Vec::new(),
            zapret_direct_cidrs: Vec::new(),
            zapret_direct_processes: Vec::new(),
            zapret_direct_tcp_ports: Vec::new(),
            zapret_direct_udp_ports: Vec::new(),
            selected_proxies: BTreeMap::new(),
            routing_policy: RoutingPolicySettings::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct VlessProxy {
    name: String,
    server: String,
    port: u16,
    uuid: String,
    encryption: Option<String>,
    flow: Option<String>,
    servername: Option<String>,
    fingerprint: Option<String>,
    public_key: Option<String>,
    short_id: Option<String>,
    network: Option<String>,
    path: Option<String>,
    host: Option<String>,
    mode: Option<String>,
    service_name: Option<String>,
}

pub fn generate_mihomo_config_from_subscription(
    subscription_body: &str,
    secret: &str,
) -> Result<GeneratedMihomoConfig, String> {
    generate_mihomo_config_from_subscription_with_options(
        subscription_body,
        secret,
        &MihomoConfigOptions::default(),
    )
}

pub fn generate_mihomo_config_from_subscription_with_options(
    subscription_body: &str,
    secret: &str,
    options: &MihomoConfigOptions,
) -> Result<GeneratedMihomoConfig, String> {
    if let Ok(value) = serde_yaml::from_str::<serde_yaml::Value>(subscription_body) {
        if value.get("proxies").is_some() {
            let (yaml, policy) =
                overlay_mihomo_config_yaml_with_policy(subscription_body, secret, options)?;
            return Ok(GeneratedMihomoConfig {
                direct_rule_count: policy.zapret_hostlist.len(),
                yaml,
                proxy_count: count_yaml_proxies(&value),
                format: SubscriptionFormat::ClashYaml,
                policy,
            });
        }
    }

    let decoded = subscription_body_to_text(subscription_body)
        .unwrap_or_else(|| subscription_body.trim().to_string());
    let proxies = decoded
        .lines()
        .filter_map(|line| parse_vless_uri(line.trim()).ok())
        .collect::<Vec<_>>();

    if proxies.is_empty() {
        return Err("No supported VLESS nodes found for Mihomo config generation.".to_string());
    }

    let (yaml, policy) = build_vless_config_yaml(&proxies, secret, options)?;
    Ok(GeneratedMihomoConfig {
        direct_rule_count: policy.zapret_hostlist.len(),
        yaml,
        proxy_count: proxies.len(),
        format: if decoded == subscription_body.trim() {
            SubscriptionFormat::UriList
        } else {
            SubscriptionFormat::Base64UriList
        },
        policy,
    })
}

pub fn smart_hybrid_direct_rules() -> Vec<String> {
    smart_hybrid_direct_rules_for_domains(&zapret_direct_domains_for_options(
        &MihomoConfigOptions::default(),
    ))
}

pub fn flowseal_general_hostlist() -> Vec<&'static str> {
    vec![
        "cloudflare-ech.com",
        "encryptedsni.com",
        "cloudflareaccess.com",
        "cloudflareapps.com",
        "cloudflarebolt.com",
        "cloudflareclient.com",
        "cloudflareinsights.com",
        "cloudflareok.com",
        "cloudflarepartners.com",
        "cloudflareportal.com",
        "cloudflarepreview.com",
        "cloudflareresolve.com",
        "cloudflaressl.com",
        "cloudflarestatus.com",
        "cloudflarestorage.com",
        "cloudflarestream.com",
        "cloudflaretest.com",
        "dis.gd",
        "discord-attachments-uploads-prd.storage.googleapis.com",
        "discord.app",
        "discord.co",
        "discord.com",
        "discord.design",
        "discord.dev",
        "discord.gift",
        "discord.gifts",
        "discord.gg",
        "discord.media",
        "discord.new",
        "discord.store",
        "discord.status",
        "discord-activities.com",
        "discordactivities.com",
        "discordapp.com",
        "discordapp.net",
        "discordcdn.com",
        "discordmerch.com",
        "discordpartygames.com",
        "discordsays.com",
        "discordsez.com",
        "discordstatus.com",
        "frankerfacez.com",
        "ffzap.com",
        "betterttv.net",
        "7tv.app",
        "7tv.io",
        "localizeapi.com",
        "klipy.com",
    ]
}

pub fn flowseal_google_hostlist() -> Vec<&'static str> {
    vec![
        "yt3.ggpht.com",
        "yt4.ggpht.com",
        "yt3.googleusercontent.com",
        "googlevideo.com",
        "jnn-pa.googleapis.com",
        "stable.dl2.discordapp.net",
        "wide-youtube.l.google.com",
        "youtube-nocookie.com",
        "youtube-ui.l.google.com",
        "youtube.com",
        "youtubeembeddedplayer.googleapis.com",
        "youtubekids.com",
        "youtubei.googleapis.com",
        "youtu.be",
        "yt-video-upload.l.google.com",
        "ytimg.com",
        "ytimg.l.google.com",
        "play.google.com",
    ]
}

pub fn flowseal_exclude_hostlist() -> Vec<&'static str> {
    vec![
        "pusher.com",
        "live-video.net",
        "ttvnw.net",
        "twitch.tv",
        "mail.ru",
        "citilink.ru",
        "yandex.com",
        "nvidia.com",
        "donationalerts.com",
        "vk.com",
        "yandex.kz",
        "mts.ru",
        "multimc.org",
        "ya.ru",
        "dns-shop.ru",
        "habr.com",
        "3dnews.ru",
        "sberbank.ru",
        "ozon.ru",
        "wildberries.ru",
        "microsoft.com",
        "microsoftonline.com",
        "live.com",
        "minecraft.net",
        "xboxlive.com",
        "akamaitechnologies.com",
        "msi.com",
        "2ip.ru",
        "yandex.ru",
        "boosty.to",
        "tanki.su",
        "lesta.ru",
        "korabli.su",
        "tanksblitz.ru",
        "reg.ru",
        "epicgames.dev",
        "epicgames.com",
        "unrealengine.com",
        "riotgames.com",
        "riotcdn.net",
        "leagueoflegends.com",
        "playvalorant.com",
        "marketplace.visualstudio.com",
    ]
}

pub fn flowseal_ipset_exclude() -> Vec<&'static str> {
    vec![
        "0.0.0.0/8",
        "10.0.0.0/8",
        "127.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "100.64.0.0/10",
        "::1",
        "fc00::/7",
        "fe80::/10",
    ]
}

pub fn flowseal_target_hostlist() -> Vec<&'static str> {
    flowseal_general_hostlist()
        .into_iter()
        .chain(flowseal_google_hostlist())
        .collect()
}

pub fn zapret_default_hostlist() -> Vec<&'static str> {
    flowseal_target_hostlist()
}

pub fn zapret_user_placeholder_hostlist() -> Vec<&'static str> {
    vec!["domain.example.abc"]
}

pub fn zapret_default_ipset() -> Vec<&'static str> {
    vec!["203.0.113.113/32"]
}

fn parse_vless_uri(raw: &str) -> Result<VlessProxy, String> {
    if raw.is_empty() || !raw.starts_with("vless://") {
        return Err("not a VLESS URI".to_string());
    }

    let url = Url::parse(raw).map_err(|error| format!("invalid VLESS URI: {error}"))?;
    let uuid = url.username();
    if uuid.is_empty() {
        return Err("VLESS URI has no UUID".to_string());
    }

    let server = url
        .host_str()
        .ok_or_else(|| "VLESS URI has no host".to_string())?
        .to_string();
    let port = url
        .port()
        .ok_or_else(|| "VLESS URI has no port".to_string())?;
    let query = url.query_pairs().collect::<Vec<_>>();
    let value = |name: &str| {
        query
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.to_string())
            .filter(|value| !value.is_empty())
    };
    let fragment = url
        .fragment()
        .map(percent_decode)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| server.clone());

    Ok(VlessProxy {
        name: fragment,
        server,
        port,
        uuid: uuid.to_string(),
        encryption: value("encryption").and_then(|value| {
            if value.eq_ignore_ascii_case("none") {
                None
            } else {
                Some(value)
            }
        }),
        flow: value("flow"),
        servername: value("sni").or_else(|| value("servername")),
        fingerprint: value("fp").or_else(|| value("fingerprint")),
        public_key: value("pbk").or_else(|| value("public-key")),
        short_id: value("sid").or_else(|| value("short-id")),
        network: value("type").map(|value| value.to_ascii_lowercase()),
        path: value("path"),
        host: value("host"),
        mode: value("mode"),
        service_name: value("serviceName").or_else(|| value("service_name")),
    })
}

fn build_vless_config_yaml(
    proxies: &[VlessProxy],
    secret: &str,
    options: &MihomoConfigOptions,
) -> Result<(String, CompiledPolicy), String> {
    let policy = compile_policy(PolicyCompileInput {
        mode: app_route_mode(options.route_mode),
        provider_rules: Vec::new(),
        proxy_groups: vec![
            ProxyGroupInfo {
                name: "PROXY".to_string(),
                group_type: Some("select".to_string()),
                proxies: proxies.iter().map(|proxy| proxy.name.clone()).collect(),
            },
            ProxyGroupInfo {
                name: "Auto (best ping)".to_string(),
                group_type: Some("url-test".to_string()),
                proxies: proxies.iter().map(|proxy| proxy.name.clone()).collect(),
            },
        ],
        proxy_count: proxies.len(),
        routing: routing_policy_for_options(options),
        runtime_facts: RuntimeFacts::default(),
    })?;
    let mut yaml = base_config_yaml(secret, options);
    yaml.push_str("\nproxies:\n");
    for proxy in proxies {
        yaml.push_str(&format!(
            "  - name: {}\n    type: vless\n    server: {}\n    port: {}\n    uuid: {}\n    udp: true\n    tls: true\n    skip-cert-verify: false\n",
            yaml_string(&proxy.name),
            yaml_string(&proxy.server),
            proxy.port,
            yaml_string(&proxy.uuid)
        ));

        if let Some(network) = &proxy.network {
            yaml.push_str(&format!("    network: {}\n", yaml_string(network)));
        }
        if let Some(encryption) = &proxy.encryption {
            yaml.push_str(&format!("    encryption: {}\n", yaml_string(encryption)));
        }
        if let Some(flow) = &proxy.flow {
            yaml.push_str(&format!("    flow: {}\n", yaml_string(flow)));
        }
        if let Some(servername) = &proxy.servername {
            yaml.push_str(&format!("    servername: {}\n", yaml_string(servername)));
        }
        if let Some(fingerprint) = &proxy.fingerprint {
            yaml.push_str(&format!(
                "    client-fingerprint: {}\n",
                yaml_string(fingerprint)
            ));
        }
        if proxy.public_key.is_some() || proxy.short_id.is_some() {
            yaml.push_str("    reality-opts:\n");
            if let Some(public_key) = &proxy.public_key {
                yaml.push_str(&format!("      public-key: {}\n", yaml_string(public_key)));
            }
            if let Some(short_id) = &proxy.short_id {
                yaml.push_str(&format!("      short-id: {}\n", yaml_string(short_id)));
            }
        }
        push_transport_opts(&mut yaml, proxy);
    }

    yaml.push_str("\nproxy-groups:\n");
    yaml.push_str("  - name: PROXY\n    type: select\n    proxies:\n");
    let proxy_names = proxies
        .iter()
        .map(|proxy| proxy.name.clone())
        .collect::<Vec<_>>();
    for name in ordered_select_group_items(
        "PROXY",
        &["Auto (best ping)".to_string()],
        &proxy_names,
        &options.selected_proxies,
    ) {
        yaml.push_str(&format!("      - {}\n", yaml_string(&name)));
    }
    yaml.push_str("  - name: Auto (best ping)\n    type: url-test\n    url: https://www.gstatic.com/generate_204\n    interval: 300\n    tolerance: 50\n    proxies:\n");
    for proxy in proxies {
        yaml.push_str(&format!("      - {}\n", yaml_string(&proxy.name)));
    }

    yaml.push_str("\nrules:\n");
    for rule in &policy.mihomo_rules {
        yaml.push_str(&format!("  - {rule}\n"));
    }

    Ok((yaml, policy))
}

fn ordered_select_group_items(
    group: &str,
    leading_items: &[String],
    proxy_names: &[String],
    selected_proxies: &BTreeMap<String, String>,
) -> Vec<String> {
    let selected = selected_proxies.get(group);
    let mut items = leading_items
        .iter()
        .chain(proxy_names.iter())
        .cloned()
        .collect::<Vec<_>>();
    if let Some(selected) = selected {
        if let Some(index) = items.iter().position(|item| item == selected) {
            let item = items.remove(index);
            items.insert(0, item);
        }
    }
    items
}

fn push_transport_opts(yaml: &mut String, proxy: &VlessProxy) {
    let network = proxy.network.as_deref().unwrap_or("tcp");
    match network {
        "ws" | "websocket" => {
            yaml.push_str("    ws-opts:\n");
            yaml.push_str(&format!(
                "      path: {}\n",
                yaml_string(proxy.path.as_deref().unwrap_or("/"))
            ));
            if let Some(host) = &proxy.host {
                yaml.push_str("      headers:\n");
                yaml.push_str(&format!("        Host: {}\n", yaml_string(host)));
            }
        }
        "xhttp" => {
            yaml.push_str("    xhttp-opts:\n");
            yaml.push_str(&format!(
                "      path: {}\n",
                yaml_string(proxy.path.as_deref().unwrap_or("/"))
            ));
            if let Some(mode) = &proxy.mode {
                yaml.push_str(&format!("      mode: {}\n", yaml_string(mode)));
            }
            if let Some(host) = &proxy.host {
                yaml.push_str("      headers:\n");
                yaml.push_str(&format!("        Host: {}\n", yaml_string(host)));
            }
        }
        "grpc" => {
            if let Some(service_name) = &proxy.service_name {
                yaml.push_str("    grpc-opts:\n");
                yaml.push_str(&format!(
                    "      grpc-service-name: {}\n",
                    yaml_string(service_name)
                ));
            }
        }
        "http" | "h2" => {
            yaml.push_str("    h2-opts:\n");
            if let Some(host) = &proxy.host {
                yaml.push_str("      host:\n");
                yaml.push_str(&format!("        - {}\n", yaml_string(host)));
            }
            if let Some(path) = &proxy.path {
                yaml.push_str(&format!("      path: {}\n", yaml_string(path)));
            }
        }
        _ => {}
    }
}

pub fn overlay_mihomo_config_yaml(
    subscription_body: &str,
    secret: &str,
    options: &MihomoConfigOptions,
) -> Result<String, String> {
    overlay_mihomo_config_yaml_with_policy(subscription_body, secret, options)
        .map(|(yaml, _policy)| yaml)
}

fn overlay_mihomo_config_yaml_with_policy(
    subscription_body: &str,
    secret: &str,
    options: &MihomoConfigOptions,
) -> Result<(String, CompiledPolicy), String> {
    let mut value = serde_yaml::from_str::<serde_yaml::Value>(subscription_body)
        .map_err(|error| format!("Invalid Clash YAML: {error}"))?;
    let proxy_count = count_yaml_proxies(&value);
    let map = value
        .as_mapping_mut()
        .ok_or_else(|| "Clash YAML root must be a mapping".to_string())?;
    let provider_rules = extract_provider_rules(map);
    let proxy_groups = extract_proxy_groups(map);
    let existing_dns = map
        .get(serde_yaml::Value::String("dns".to_string()))
        .cloned();
    let policy = compile_policy(PolicyCompileInput {
        mode: app_route_mode(options.route_mode),
        provider_rules,
        proxy_groups,
        proxy_count,
        routing: routing_policy_for_options(options),
        runtime_facts: RuntimeFacts::default(),
    })?;

    insert_yaml(
        map,
        "mixed-port",
        serde_yaml::Value::Number(options.mixed_port.into()),
    );
    insert_yaml(map, "allow-lan", serde_yaml::Value::Bool(options.allow_lan));
    insert_yaml(map, "mode", serde_yaml::Value::String("rule".to_string()));
    insert_yaml(
        map,
        "log-level",
        serde_yaml::Value::String(options.log_level.clone()),
    );
    insert_yaml(map, "ipv6", serde_yaml::Value::Bool(options.ipv6));
    insert_yaml(map, "geo-auto-update", serde_yaml::Value::Bool(false));
    insert_yaml(
        map,
        "external-controller",
        serde_yaml::Value::String(format!("127.0.0.1:{}", options.controller_port)),
    );
    insert_yaml(map, "secret", serde_yaml::Value::String(secret.to_string()));
    insert_yaml(map, "profile", profile_yaml());
    insert_yaml(map, "tun", tun_yaml(options));
    insert_yaml(
        map,
        "dns",
        dns_yaml_with_policy(options, existing_dns.as_ref(), &policy),
    );

    ensure_canonical_proxy_group(map, &policy);
    let rules = policy
        .mihomo_rules
        .iter()
        .cloned()
        .map(serde_yaml::Value::String)
        .collect::<Vec<_>>();
    insert_yaml(map, "rules", serde_yaml::Value::Sequence(rules));
    apply_selected_proxies(map, &options.selected_proxies);

    Ok((
        serde_yaml::to_string(&value)
            .map_err(|error| format!("Failed to render Mihomo YAML: {error}"))?,
        policy,
    ))
}

fn extract_provider_rules(map: &serde_yaml::Mapping) -> Vec<String> {
    map.get(serde_yaml::Value::String("rules".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(|rule| rule.as_str().map(|value| value.trim().to_string()))
        .filter(|rule| !rule.is_empty())
        .collect()
}

fn extract_proxy_groups(map: &serde_yaml::Mapping) -> Vec<ProxyGroupInfo> {
    map.get(serde_yaml::Value::String("proxy-groups".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(|group| {
            let group_map = group.as_mapping()?;
            let name = group_map
                .get(serde_yaml::Value::String("name".to_string()))
                .and_then(serde_yaml::Value::as_str)?
                .to_string();
            let group_type = group_map
                .get(serde_yaml::Value::String("type".to_string()))
                .and_then(serde_yaml::Value::as_str)
                .map(ToOwned::to_owned);
            let proxies = group_map
                .get(serde_yaml::Value::String("proxies".to_string()))
                .and_then(serde_yaml::Value::as_sequence)
                .into_iter()
                .flatten()
                .filter_map(|proxy| proxy.as_str().map(ToOwned::to_owned))
                .collect::<Vec<_>>();
            Some(ProxyGroupInfo {
                name,
                group_type,
                proxies,
            })
        })
        .collect()
}

fn ensure_canonical_proxy_group(map: &mut serde_yaml::Mapping, policy: &CompiledPolicy) {
    ensure_managed_proxy_groups(map, policy);

    if !policy.should_create_canonical_proxy_group {
        return;
    }
    if map
        .get(serde_yaml::Value::String("proxy-groups".to_string()))
        .is_some()
    {
        return;
    }
    let proxies = map
        .get(serde_yaml::Value::String("proxies".to_string()))
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(|proxy| {
            proxy
                .get("name")
                .and_then(serde_yaml::Value::as_str)
                .map(|name| serde_yaml::Value::String(name.to_string()))
        })
        .collect::<Vec<_>>();
    if proxies.is_empty() {
        return;
    }

    let mut group = serde_yaml::Mapping::new();
    insert_yaml(
        &mut group,
        "name",
        serde_yaml::Value::String(policy.main_proxy_group.clone()),
    );
    insert_yaml(
        &mut group,
        "type",
        serde_yaml::Value::String("select".to_string()),
    );
    insert_yaml(&mut group, "proxies", serde_yaml::Value::Sequence(proxies));
    insert_yaml(
        map,
        "proxy-groups",
        serde_yaml::Value::Sequence(vec![serde_yaml::Value::Mapping(group)]),
    );
}

fn ensure_managed_proxy_groups(map: &mut serde_yaml::Mapping, policy: &CompiledPolicy) {
    if policy.managed_proxy_groups.is_empty() {
        return;
    }

    let key = serde_yaml::Value::String("proxy-groups".to_string());
    if !map.contains_key(&key) {
        insert_yaml(map, "proxy-groups", serde_yaml::Value::Sequence(Vec::new()));
    }
    let Some(groups) = map
        .get_mut(&key)
        .and_then(serde_yaml::Value::as_sequence_mut)
    else {
        return;
    };

    for managed in &policy.managed_proxy_groups {
        let group_value = managed_proxy_group_yaml(&managed.name, &managed.proxies);
        if let Some(existing) = groups.iter_mut().find(|group| {
            group.get("name").and_then(serde_yaml::Value::as_str) == Some(managed.name.as_str())
        }) {
            *existing = group_value;
        } else {
            groups.push(group_value);
        }
    }
}

fn managed_proxy_group_yaml(name: &str, proxies: &[String]) -> serde_yaml::Value {
    let mut group = serde_yaml::Mapping::new();
    insert_yaml(
        &mut group,
        "name",
        serde_yaml::Value::String(name.to_string()),
    );
    insert_yaml(
        &mut group,
        "type",
        serde_yaml::Value::String("select".to_string()),
    );
    insert_yaml(
        &mut group,
        "proxies",
        serde_yaml::Value::Sequence(
            proxies
                .iter()
                .cloned()
                .map(serde_yaml::Value::String)
                .collect(),
        ),
    );
    serde_yaml::Value::Mapping(group)
}

fn apply_selected_proxies(
    map: &mut serde_yaml::Mapping,
    selected_proxies: &BTreeMap<String, String>,
) {
    if selected_proxies.is_empty() {
        return;
    }

    let Some(groups) = map
        .get_mut(serde_yaml::Value::String("proxy-groups".to_string()))
        .and_then(serde_yaml::Value::as_sequence_mut)
    else {
        return;
    };

    for group in groups {
        let Some(group_map) = group.as_mapping_mut() else {
            continue;
        };
        let Some(group_name) = group_map
            .get(serde_yaml::Value::String("name".to_string()))
            .and_then(serde_yaml::Value::as_str)
        else {
            continue;
        };
        let Some(selected) = selected_proxies.get(group_name) else {
            continue;
        };
        let Some(proxies) = group_map
            .get_mut(serde_yaml::Value::String("proxies".to_string()))
            .and_then(serde_yaml::Value::as_sequence_mut)
        else {
            continue;
        };
        let Some(index) = proxies
            .iter()
            .position(|value| value.as_str() == Some(selected.as_str()))
        else {
            continue;
        };
        let selected_proxy = proxies.remove(index);
        proxies.insert(0, selected_proxy);
    }
}

fn app_route_mode(mode: RouteMode) -> AppRouteMode {
    match mode {
        RouteMode::Smart => AppRouteMode::Smart,
        RouteMode::VpnOnly => AppRouteMode::VpnOnly,
    }
}

fn routing_policy_for_options(options: &MihomoConfigOptions) -> RoutingPolicySettings {
    let mut routing = options.routing_policy.clone();
    routing
        .force_zapret_domains
        .extend(options.zapret_direct_domains.iter().cloned());
    routing
        .force_zapret_cidrs
        .extend(options.zapret_direct_cidrs.iter().cloned());
    routing
        .force_zapret_processes
        .extend(options.zapret_direct_processes.iter().cloned());
    routing
        .force_zapret_tcp_ports
        .extend(options.zapret_direct_tcp_ports.iter().cloned());
    routing
        .force_zapret_udp_ports
        .extend(options.zapret_direct_udp_ports.iter().cloned());
    routing
}

fn zapret_direct_domains_for_options(options: &MihomoConfigOptions) -> Vec<String> {
    let mut domains = flowseal_target_hostlist()
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    domains.extend(options.zapret_direct_domains.iter().cloned());
    normalize_domain_list(domains)
}

fn smart_hybrid_direct_rules_for_domains(domains: &[String]) -> Vec<String> {
    domains
        .iter()
        .map(|domain| format!("DOMAIN-SUFFIX,{domain},DIRECT"))
        .collect()
}

fn normalize_domain_list(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .filter_map(|value| {
            let value = value
                .trim()
                .trim_start_matches('.')
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if value.is_empty()
                || value.starts_with('#')
                || value.contains('/')
                || value.contains('*')
            {
                None
            } else {
                Some(value)
            }
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn tun_yaml(options: &MihomoConfigOptions) -> serde_yaml::Value {
    let mut map = serde_yaml::Mapping::new();
    insert_yaml(
        &mut map,
        "enable",
        serde_yaml::Value::Bool(options.tun_enabled),
    );
    insert_yaml(
        &mut map,
        "stack",
        serde_yaml::Value::String(options.tun_stack.clone()),
    );
    insert_yaml(
        &mut map,
        "device",
        serde_yaml::Value::String("BadVpn".to_string()),
    );
    insert_yaml(
        &mut map,
        "auto-route",
        serde_yaml::Value::Bool(options.tun_auto_route),
    );
    insert_yaml(
        &mut map,
        "auto-detect-interface",
        serde_yaml::Value::Bool(options.tun_auto_detect_interface),
    );
    insert_yaml(
        &mut map,
        "strict-route",
        serde_yaml::Value::Bool(options.tun_strict_route),
    );
    insert_yaml(
        &mut map,
        "dns-hijack",
        serde_yaml::Value::Sequence(vec![
            serde_yaml::Value::String("any:53".to_string()),
            serde_yaml::Value::String("tcp://any:53".to_string()),
        ]),
    );
    insert_yaml(&mut map, "mtu", serde_yaml::Value::Number(1500.into()));
    insert_yaml(
        &mut map,
        "udp-timeout",
        serde_yaml::Value::Number(300.into()),
    );
    serde_yaml::Value::Mapping(map)
}

fn dns_yaml(options: &MihomoConfigOptions) -> serde_yaml::Value {
    dns_yaml_base(options, None, &[], &[], true)
}

fn dns_yaml_with_policy(
    options: &MihomoConfigOptions,
    existing: Option<&serde_yaml::Value>,
    policy: &CompiledPolicy,
) -> serde_yaml::Value {
    let fake_ip_filter_domains = if policy.mode == AppRouteMode::Smart {
        policy.zapret_hostlist.as_slice()
    } else {
        &[]
    };
    dns_yaml_base(
        options,
        existing,
        &policy.dns_nameserver_policy,
        fake_ip_filter_domains,
        policy.mode == AppRouteMode::Smart,
    )
}

fn dns_yaml_base(
    options: &MihomoConfigOptions,
    existing: Option<&serde_yaml::Value>,
    policy_rules: &[crate::DnsPolicyRule],
    fake_ip_filter_domains: &[String],
    preserve_existing_nameserver_policy: bool,
) -> serde_yaml::Value {
    let mut map = existing
        .and_then(serde_yaml::Value::as_mapping)
        .cloned()
        .unwrap_or_else(serde_yaml::Mapping::new);
    insert_yaml(&mut map, "enable", serde_yaml::Value::Bool(true));
    insert_yaml(
        &mut map,
        "listen",
        serde_yaml::Value::String("127.0.0.1:1053".to_string()),
    );
    insert_yaml(
        &mut map,
        "enhanced-mode",
        serde_yaml::Value::String(options.dns_mode.clone()),
    );
    if options.dns_mode == "fake-ip" {
        insert_yaml(
            &mut map,
            "fake-ip-range",
            serde_yaml::Value::String("198.18.0.1/16".to_string()),
        );
        insert_yaml(
            &mut map,
            "fake-ip-filter",
            fake_ip_filter_sequence(existing, fake_ip_filter_domains),
        );
    }
    insert_yaml(&mut map, "respect-rules", serde_yaml::Value::Bool(true));
    insert_yaml(
        &mut map,
        "nameserver",
        nameserver_sequence(&options.dns_nameservers),
    );
    insert_yaml(
        &mut map,
        "proxy-server-nameserver",
        nameserver_sequence(&options.dns_nameservers),
    );
    let mut nameserver_policy = if preserve_existing_nameserver_policy {
        existing
            .and_then(|value| value.get("nameserver-policy"))
            .and_then(serde_yaml::Value::as_mapping)
            .cloned()
            .unwrap_or_else(serde_yaml::Mapping::new)
    } else {
        serde_yaml::Mapping::new()
    };
    for rule in policy_rules {
        insert_yaml(
            &mut nameserver_policy,
            &rule.pattern,
            nameserver_sequence(&rule.nameservers),
        );
    }
    if !nameserver_policy.is_empty() {
        insert_yaml(
            &mut map,
            "nameserver-policy",
            serde_yaml::Value::Mapping(nameserver_policy),
        );
    }
    serde_yaml::Value::Mapping(map)
}

fn nameserver_sequence(values: &[String]) -> serde_yaml::Value {
    serde_yaml::Value::Sequence(
        values
            .iter()
            .map(|server| serde_yaml::Value::String(server.clone()))
            .collect(),
    )
}

fn fake_ip_filter_sequence(
    existing: Option<&serde_yaml::Value>,
    zapret_domains: &[String],
) -> serde_yaml::Value {
    let mut filters = existing
        .and_then(|value| value.get("fake-ip-filter"))
        .and_then(serde_yaml::Value::as_sequence)
        .into_iter()
        .flatten()
        .filter_map(serde_yaml::Value::as_str)
        .map(ToOwned::to_owned)
        .collect::<std::collections::BTreeSet<_>>();

    for domain in zapret_domains {
        let domain = domain
            .trim()
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if domain.is_empty() || domain.contains('/') || domain.contains('*') {
            continue;
        }
        filters.insert(format!("+.{domain}"));
    }

    serde_yaml::Value::Sequence(filters.into_iter().map(serde_yaml::Value::String).collect())
}

fn base_config_yaml(secret: &str, options: &MihomoConfigOptions) -> String {
    let mut map = serde_yaml::Mapping::new();
    insert_yaml(
        &mut map,
        "mixed-port",
        serde_yaml::Value::Number(options.mixed_port.into()),
    );
    insert_yaml(
        &mut map,
        "allow-lan",
        serde_yaml::Value::Bool(options.allow_lan),
    );
    insert_yaml(
        &mut map,
        "mode",
        serde_yaml::Value::String("rule".to_string()),
    );
    insert_yaml(
        &mut map,
        "log-level",
        serde_yaml::Value::String(options.log_level.clone()),
    );
    insert_yaml(&mut map, "ipv6", serde_yaml::Value::Bool(options.ipv6));
    insert_yaml(
        &mut map,
        "external-controller",
        serde_yaml::Value::String(format!("127.0.0.1:{}", options.controller_port)),
    );
    insert_yaml(
        &mut map,
        "secret",
        serde_yaml::Value::String(secret.to_string()),
    );

    insert_yaml(&mut map, "profile", profile_yaml());
    insert_yaml(&mut map, "tun", tun_yaml(options));
    insert_yaml(&mut map, "dns", dns_yaml(options));

    serde_yaml::to_string(&serde_yaml::Value::Mapping(map)).unwrap_or_else(|_| {
        format!(
            "mixed-port: {}\nallow-lan: false\nmode: rule\nlog-level: info\nexternal-controller: 127.0.0.1:{}\nsecret: {}\n",
            options.mixed_port,
            options.controller_port,
            yaml_string(secret)
        )
    })
}

fn profile_yaml() -> serde_yaml::Value {
    let mut profile = serde_yaml::Mapping::new();
    insert_yaml(
        &mut profile,
        "store-selected",
        serde_yaml::Value::Bool(true),
    );
    insert_yaml(&mut profile, "store-fake-ip", serde_yaml::Value::Bool(true));
    serde_yaml::Value::Mapping(profile)
}

fn count_yaml_proxies(value: &serde_yaml::Value) -> usize {
    value
        .get("proxies")
        .and_then(serde_yaml::Value::as_sequence)
        .map_or(0, Vec::len)
}

fn insert_yaml(
    map: &mut serde_yaml::Mapping,
    key: &str,
    value: serde_yaml::Value,
) -> Option<serde_yaml::Value> {
    map.insert(serde_yaml::Value::String(key.to_string()), value)
}

fn yaml_string(value: &str) -> String {
    serde_yaml::to_string(value)
        .unwrap_or_else(|_| format!("{value:?}"))
        .trim()
        .trim_start_matches("---")
        .trim()
        .to_string()
}

fn percent_decode(value: &str) -> String {
    let replaced = value.replace('+', "%20");
    match url::form_urlencoded::parse(replaced.as_bytes()).next() {
        Some((decoded, _)) => decoded.into_owned(),
        None => value.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose, Engine};

    use super::*;

    #[test]
    fn generates_vless_reality_config_from_base64_subscription() {
        let uri = "vless://00000000-0000-0000-0000-000000000000@example.com:443?encryption=none&security=reality&type=tcp&flow=xtls-rprx-vision&sni=www.google.com&fp=chrome&pbk=abc&sid=123#Germany";
        let body = general_purpose::STANDARD.encode(uri);
        let generated = generate_mihomo_config_from_subscription(&body, "secret").unwrap();

        assert_eq!(generated.proxy_count, 1);
        assert!(generated.yaml.contains("type: vless"));
        assert!(generated.yaml.contains("reality-opts:"));
        assert!(generated.yaml.contains("DOMAIN-SUFFIX,discord.com,DIRECT"));
        assert!(generated.yaml.contains("DOMAIN-SUFFIX,youtube.com,DIRECT"));
        assert!(generated
            .yaml
            .contains("DOMAIN-SUFFIX,googlevideo.com,DIRECT"));
        assert!(generated.yaml.contains("MATCH,PROXY"));
    }

    #[test]
    fn generates_vless_xhttp_transport_options() {
        let uri = "vless://00000000-0000-0000-0000-000000000000@example.com:2053?encryption=none&security=reality&type=xhttp&path=%2F&mode=auto&sni=www.microsoft.com&fp=chrome&pbk=abc&sid=123#Germany%20xHTTP";
        let body = general_purpose::STANDARD.encode(uri);
        let generated = generate_mihomo_config_from_subscription(&body, "secret").unwrap();

        assert!(generated.yaml.contains("network: xhttp"));
        assert!(generated.yaml.contains("xhttp-opts:"));
        assert!(generated.yaml.contains("path: /"));
        assert!(generated.yaml.contains("mode: auto"));
        assert!(!generated.yaml.contains("ws-opts:"));
    }

    #[test]
    fn generated_yaml_reflects_mihomo_options() {
        let uri = "vless://00000000-0000-0000-0000-000000000000@example.com:443?encryption=none&security=reality&type=tcp&sni=www.google.com&fp=chrome&pbk=abc&sid=123#Germany";
        let body = general_purpose::STANDARD.encode(uri);
        let options = MihomoConfigOptions {
            mixed_port: 7888,
            controller_port: 9088,
            log_level: "debug".to_string(),
            allow_lan: true,
            ipv6: true,
            tun_enabled: false,
            tun_stack: "gvisor".to_string(),
            tun_strict_route: false,
            tun_auto_route: false,
            tun_auto_detect_interface: false,
            dns_mode: "redir-host".to_string(),
            dns_nameservers: vec!["https://9.9.9.9/dns-query".to_string()],
            ..MihomoConfigOptions::default()
        };
        let generated =
            generate_mihomo_config_from_subscription_with_options(&body, "secret", &options)
                .unwrap();

        assert!(generated.yaml.contains("mixed-port: 7888"));
        assert!(generated
            .yaml
            .contains("external-controller: 127.0.0.1:9088"));
        assert!(generated.yaml.contains("log-level: debug"));
        assert!(generated.yaml.contains("allow-lan: true"));
        assert!(generated.yaml.contains("ipv6: true"));
        assert!(generated.yaml.contains("enable: false"));
        assert!(generated.yaml.contains("stack: gvisor"));
        assert!(generated.yaml.contains("device: BadVpn"));
        assert!(generated.yaml.contains("tcp://any:53"));
        assert!(generated.yaml.contains("mtu: 1500"));
        assert!(generated.yaml.contains("udp-timeout: 300"));
        assert!(generated.yaml.contains("profile:"));
        assert!(generated.yaml.contains("store-fake-ip: true"));
        assert!(generated.yaml.contains("enhanced-mode: redir-host"));
        assert!(generated.yaml.contains("https://9.9.9.9/dns-query"));
    }

    #[test]
    fn vpn_all_removes_flowseal_direct_rules() {
        let uri = "vless://00000000-0000-0000-0000-000000000000@example.com:443?encryption=none&security=reality&type=tcp&sni=www.google.com&fp=chrome&pbk=abc&sid=123#Germany";
        let body = general_purpose::STANDARD.encode(uri);
        let options = MihomoConfigOptions {
            route_mode: RouteMode::VpnOnly,
            ..MihomoConfigOptions::default()
        };
        let generated =
            generate_mihomo_config_from_subscription_with_options(&body, "secret", &options)
                .unwrap();

        assert!(!generated.yaml.contains("DOMAIN-SUFFIX,discord.com,DIRECT"));
        assert!(!generated.yaml.contains("DOMAIN-SUFFIX,youtube.com,DIRECT"));
        assert_eq!(generated.direct_rule_count, 0);
        assert!(generated.yaml.contains("MATCH,PROXY"));
    }

    #[test]
    fn clash_yaml_overlay_overrides_provider_flowseal_rules_in_smart() {
        let body = r#"
proxies:
  - name: Germany
    type: vless
    server: germany.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
proxy-groups:
  - name: Manual
    type: select
    proxies:
      - Germany
  - name: YouTube Group
    type: select
    proxies:
      - Germany
rules:
  - DOMAIN-SUFFIX,googlevideo.com,YouTube Group
  - DOMAIN,youtube.com,YouTube Group
  - DOMAIN-KEYWORD,discord,YouTube Group
  - MATCH,Manual
"#;

        let generated = generate_mihomo_config_from_subscription_with_options(
            body,
            "secret",
            &MihomoConfigOptions::default(),
        )
        .unwrap();

        assert!(generated
            .yaml
            .contains("DOMAIN-SUFFIX,googlevideo.com,DIRECT"));
        assert!(generated.yaml.contains("DOMAIN-SUFFIX,youtube.com,DIRECT"));
        assert!(generated.yaml.contains("DOMAIN-SUFFIX,discord.com,DIRECT"));
        assert!(!generated
            .yaml
            .contains("DOMAIN-SUFFIX,googlevideo.com,YouTube Group"));
        assert!(!generated.yaml.contains("DOMAIN,youtube.com,YouTube Group"));
        assert!(!generated
            .yaml
            .contains("DOMAIN-KEYWORD,discord,YouTube Group"));
        assert!(generated.yaml.contains("MATCH,Manual"));
        assert!(!generated.yaml.contains("MATCH,DIRECT"));
    }

    #[test]
    fn vpn_all_overlay_removes_provider_flowseal_rules() {
        let body = r#"
proxies:
  - name: Germany
    type: vless
    server: germany.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
proxy-groups:
  - name: Manual
    type: select
    proxies:
      - Germany
  - name: YouTube Group
    type: select
    proxies:
      - Germany
rules:
  - DOMAIN-SUFFIX,googlevideo.com,YouTube Group
  - DOMAIN-SUFFIX,youtu.be,YouTube Group
  - DOMAIN-SUFFIX,example.com,Manual
  - MATCH,Manual
"#;
        let options = MihomoConfigOptions {
            route_mode: RouteMode::VpnOnly,
            ..MihomoConfigOptions::default()
        };

        let generated =
            generate_mihomo_config_from_subscription_with_options(body, "secret", &options)
                .unwrap();

        assert!(!generated
            .yaml
            .contains("DOMAIN-SUFFIX,googlevideo.com,DIRECT"));
        assert!(!generated.yaml.contains("DOMAIN-SUFFIX,youtube.com,DIRECT"));
        assert!(generated
            .yaml
            .contains("DOMAIN-SUFFIX,googlevideo.com,YouTube Group"));
        assert!(generated
            .yaml
            .contains("DOMAIN-SUFFIX,youtu.be,YouTube Group"));
        assert!(generated.yaml.contains("DOMAIN-SUFFIX,example.com,Manual"));
        assert!(generated.yaml.contains("MATCH,Manual"));
    }

    #[test]
    fn vpn_only_overlay_is_fresh_policy_without_smart_direct_rules() {
        let body = r#"
proxies:
  - name: Germany
    type: vless
    server: germany.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
proxy-groups:
  - name: Выбор сервера
    type: select
    proxies:
      - Germany
  - name: 🤖 AI
    type: select
    proxies:
      - Germany
  - name: 📺 YouTube и Discord
    type: select
    proxies:
      - Germany
rules:
  - GEOSITE,category-ads-all,REJECT
  - GEOSITE,youtube,📺 YouTube и Discord
  - DOMAIN-SUFFIX,googlevideo.com,📺 YouTube и Discord
  - DOMAIN-SUFFIX,youtu.be,📺 YouTube и Discord
  - GEOSITE,discord,📺 YouTube и Discord
  - GEOSITE,openai,🤖 AI
  - GEOSITE,telegram,Выбор сервера
  - DOMAIN-KEYWORD,sberbank,DIRECT
  - GEOSITE,yandex,DIRECT
  - DOMAIN-SUFFIX,vk.com,DIRECT
  - DOMAIN-SUFFIX,ru,DIRECT
  - GEOIP,ru,DIRECT,no-resolve
  - MATCH,Выбор сервера
"#;
        let options = MihomoConfigOptions {
            route_mode: RouteMode::VpnOnly,
            ..MihomoConfigOptions::default()
        };

        let generated =
            generate_mihomo_config_from_subscription_with_options(body, "secret", &options)
                .unwrap();

        assert!(generated.yaml.contains("GEOSITE,category-ads-all,REJECT"));
        assert!(generated
            .yaml
            .contains("GEOSITE,youtube,📺 YouTube и Discord"));
        assert!(generated
            .yaml
            .contains("GEOSITE,discord,📺 YouTube и Discord"));
        assert!(generated.yaml.contains("GEOSITE,openai,🤖 AI"));
        assert!(generated.yaml.contains("GEOSITE,telegram,Выбор сервера"));
        assert!(generated.yaml.contains("MATCH,Выбор сервера"));
        assert!(!generated.yaml.contains("MATCH,DIRECT"));
        assert!(!generated.yaml.contains("GEOSITE,youtube,DIRECT"));
        assert!(!generated.yaml.contains("GEOSITE,discord,DIRECT"));
        assert!(!generated
            .yaml
            .contains("DOMAIN-SUFFIX,googlevideo.com,DIRECT"));
        assert!(!generated.yaml.contains("DOMAIN-SUFFIX,ru,DIRECT"));
        assert!(!generated.yaml.contains("GEOIP,ru,DIRECT,no-resolve"));
        assert!(generated.policy.zapret_hostlist.is_empty());
        assert!(generated.policy.zapret_ipset.is_empty());
    }

    #[test]
    fn vpn_only_does_not_preserve_ru_direct_dns_policy_as_route_hint() {
        let body = r#"
dns:
  nameserver-policy:
    +.ru:
      - https://common.dot.dns.yandex.net/dns-query
      - https://1.1.1.1/dns-query
proxies:
  - name: Germany
    type: vless
    server: germany.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
proxy-groups:
  - name: Выбор сервера
    type: select
    proxies:
      - Germany
rules:
  - DOMAIN-SUFFIX,ru,DIRECT
  - MATCH,Выбор сервера
"#;
        let options = MihomoConfigOptions {
            route_mode: RouteMode::VpnOnly,
            ..MihomoConfigOptions::default()
        };

        let generated =
            generate_mihomo_config_from_subscription_with_options(body, "secret", &options)
                .unwrap();
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&generated.yaml).unwrap();
        let dns = yaml.get("dns").unwrap();
        assert_eq!(
            dns.get("respect-rules")
                .and_then(serde_yaml::Value::as_bool),
            Some(true)
        );
        let nameserver_policy = dns
            .get("nameserver-policy")
            .and_then(serde_yaml::Value::as_mapping)
            .unwrap();
        assert!(!nameserver_policy.contains_key(serde_yaml::Value::String("+.ru".to_string())));
        assert!(
            nameserver_policy.contains_key(serde_yaml::Value::String("+.badvpn.pro".to_string()))
        );
    }

    #[test]
    fn vpn_only_rendered_yaml_uses_managed_group_when_main_group_contains_direct() {
        let body = r#"
proxies:
  - name: Germany
    type: vless
    server: germany.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
proxy-groups:
  - name: Выбор сервера
    type: select
    proxies:
      - DIRECT
      - Germany
rules:
  - GEOSITE,telegram,Выбор сервера
  - MATCH,Выбор сервера
"#;
        let options = MihomoConfigOptions {
            route_mode: RouteMode::VpnOnly,
            ..MihomoConfigOptions::default()
        };

        let generated =
            generate_mihomo_config_from_subscription_with_options(body, "secret", &options)
                .unwrap();
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&generated.yaml).unwrap();
        let groups = yaml
            .get("proxy-groups")
            .and_then(serde_yaml::Value::as_sequence)
            .unwrap();
        let managed = groups
            .iter()
            .find(|group| {
                group.get("name").and_then(serde_yaml::Value::as_str) == Some("__BADVPN_VPN_ONLY__")
            })
            .expect("managed group exists");
        let proxies = managed
            .get("proxies")
            .and_then(serde_yaml::Value::as_sequence)
            .unwrap();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].as_str(), Some("Germany"));
        assert!(generated
            .yaml
            .contains("GEOSITE,telegram,__BADVPN_VPN_ONLY__"));
        assert!(generated.yaml.contains("MATCH,__BADVPN_VPN_ONLY__"));
    }

    #[test]
    fn smart_and_vpn_only_rendered_yaml_reparse() {
        let body = r#"
proxies:
  - name: Germany
    type: vless
    server: germany.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
proxy-groups:
  - name: Выбор сервера
    type: select
    proxies:
      - Germany
  - name: 📺 YouTube и Discord
    type: select
    proxies:
      - Germany
rules:
  - GEOSITE,youtube,📺 YouTube и Discord
  - GEOSITE,discord,📺 YouTube и Discord
  - MATCH,Выбор сервера
"#;

        for route_mode in [RouteMode::Smart, RouteMode::VpnOnly] {
            let options = MihomoConfigOptions {
                route_mode,
                ..MihomoConfigOptions::default()
            };
            let generated =
                generate_mihomo_config_from_subscription_with_options(body, "secret", &options)
                    .unwrap();
            serde_yaml::from_str::<serde_yaml::Value>(&generated.yaml).unwrap();
        }
    }

    #[test]
    fn clash_yaml_overlay_enables_fake_ip_cache_persistence() {
        let generated = overlay_mihomo_config_yaml(
            "proxies:\n  - name: Test\n    type: direct\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n      - Test\nrules:\n  - MATCH,PROXY\n",
            "secret",
            &MihomoConfigOptions::default(),
        )
        .unwrap();

        assert!(generated.contains("profile:"));
        assert!(generated.contains("store-selected: true"));
        assert!(generated.contains("store-fake-ip: true"));
    }

    #[test]
    fn clash_yaml_overlay_excludes_zapret_domains_from_fake_ip() {
        let generated = overlay_mihomo_config_yaml(
            "dns:\n  fake-ip-filter:\n    - +.existing.example\nproxies:\n  - name: Test\n    type: direct\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n      - Test\nrules:\n  - MATCH,PROXY\n",
            "secret",
            &MihomoConfigOptions::default(),
        )
        .unwrap();
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&generated).unwrap();
        let filters = yaml
            .get("dns")
            .and_then(|dns| dns.get("fake-ip-filter"))
            .and_then(serde_yaml::Value::as_sequence)
            .unwrap()
            .iter()
            .filter_map(serde_yaml::Value::as_str)
            .collect::<std::collections::BTreeSet<_>>();

        assert!(filters.contains("+.existing.example"));
        assert!(filters.contains("+.discord.com"));
        assert!(filters.contains("+.discord.gg"));
        assert!(filters.contains("+.googlevideo.com"));
        assert!(filters.contains("+.youtube.com"));
    }

    #[test]
    fn clash_yaml_overlay_preserves_provider_proxy_groups() {
        let body = r#"
mode: rule
proxies:
  - name: Germany
    type: vless
    server: germany.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000000
  - name: Sweden
    type: vless
    server: sweden.example.com
    port: 443
    uuid: 00000000-0000-0000-0000-000000000001
proxy-groups:
  - name: Manual
    type: select
    proxies:
      - Germany
      - Sweden
  - name: Auto
    type: url-test
    proxies:
      - Germany
      - Sweden
rules:
  - DOMAIN-SUFFIX,discord.com,DIRECT
  - MATCH,Manual
"#;

        let generated = generate_mihomo_config_from_subscription_with_options(
            body,
            "secret",
            &MihomoConfigOptions::default(),
        )
        .unwrap();

        assert_eq!(generated.format, SubscriptionFormat::ClashYaml);
        assert_eq!(generated.proxy_count, 2);
        assert!(generated.yaml.contains("name: Manual"));
        assert!(generated.yaml.contains("name: Auto"));
        assert!(generated.yaml.contains("MATCH,Manual"));
        assert!(generated.yaml.contains("DOMAIN-SUFFIX,discord.com,DIRECT"));
        assert!(generated.yaml.contains("DOMAIN-SUFFIX,youtube.com,DIRECT"));
        assert!(generated
            .yaml
            .contains("DOMAIN-SUFFIX,googlevideo.com,DIRECT"));
    }

    #[test]
    fn clash_yaml_overlay_preserves_geodata_rules() {
        let generated = generate_mihomo_config_from_subscription_with_options(
            r#"
proxies:
  - name: Turkey
    type: vless
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - Turkey
rules:
  - GEOSITE,telegram,PROXY
  - GEOIP,telegram,PROXY,no-resolve
  - MATCH,PROXY
"#,
            "secret",
            &MihomoConfigOptions::default(),
        )
        .unwrap();

        assert!(generated.yaml.contains("GEOSITE,telegram,PROXY"));
        assert!(generated.yaml.contains("GEOIP,telegram,PROXY,no-resolve"));
    }

    #[test]
    fn clash_yaml_overlay_restores_selected_proxy_to_group_front() {
        let body = r#"
proxies:
  - name: Germany
    type: direct
  - name: Turkey
    type: direct
proxy-groups:
  - name: Выбор сервера
    type: select
    proxies:
      - Germany
      - Turkey
rules:
  - MATCH,Выбор сервера
"#;
        let mut options = MihomoConfigOptions::default();
        options
            .selected_proxies
            .insert("Выбор сервера".to_string(), "Turkey".to_string());

        let generated =
            generate_mihomo_config_from_subscription_with_options(body, "secret", &options)
                .unwrap();
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&generated.yaml).unwrap();
        let group = yaml
            .get("proxy-groups")
            .and_then(serde_yaml::Value::as_sequence)
            .unwrap()
            .iter()
            .find(|group| {
                group.get("name").and_then(serde_yaml::Value::as_str) == Some("Выбор сервера")
            })
            .unwrap();
        let proxies = group
            .get("proxies")
            .and_then(serde_yaml::Value::as_sequence)
            .unwrap();

        assert_eq!(proxies[0].as_str(), Some("Turkey"));
    }

    #[test]
    fn generated_uri_config_restores_selected_proxy_to_proxy_group_front() {
        let body = general_purpose::STANDARD.encode(
            "vless://00000000-0000-0000-0000-000000000000@germany.example.com:443?encryption=none&security=reality&type=tcp&sni=www.google.com&fp=chrome&pbk=abc&sid=123#Germany\n\
vless://00000000-0000-0000-0000-000000000001@turkey.example.com:443?encryption=none&security=reality&type=tcp&sni=www.google.com&fp=chrome&pbk=abc&sid=123#Turkey",
        );
        let mut options = MihomoConfigOptions::default();
        options
            .selected_proxies
            .insert("PROXY".to_string(), "Turkey".to_string());

        let generated =
            generate_mihomo_config_from_subscription_with_options(&body, "secret", &options)
                .unwrap();
        let yaml = serde_yaml::from_str::<serde_yaml::Value>(&generated.yaml).unwrap();
        let group = yaml
            .get("proxy-groups")
            .and_then(serde_yaml::Value::as_sequence)
            .unwrap()
            .iter()
            .find(|group| group.get("name").and_then(serde_yaml::Value::as_str) == Some("PROXY"))
            .unwrap();
        let proxies = group
            .get("proxies")
            .and_then(serde_yaml::Value::as_sequence)
            .unwrap();

        assert_eq!(proxies[0].as_str(), Some("Turkey"));
    }
}
