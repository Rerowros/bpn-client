use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppRouteMode {
    #[serde(alias = "smart_hybrid", alias = "zapret_first")]
    Smart,
    #[serde(
        alias = "vpn_all",
        alias = "dpi_only",
        alias = "manual",
        alias = "unknown"
    )]
    VpnOnly,
}

impl Default for AppRouteMode {
    fn default() -> Self {
        Self::Smart
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPath {
    DirectSafe,
    ZapretDirect,
    VpnProxy { group: String },
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicySource {
    Safety,
    Runtime,
    LocalUserOverride,
    BadVpnPreset,
    ProviderSubscription,
    GameProfile,
    Default,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyTargetKind {
    Domain,
    DomainSuffix,
    DomainKeyword,
    DomainWildcard,
    DomainRegex,
    GeoSite,
    GeoIp,
    Cidr,
    Cidr6,
    IpSuffix,
    IpAsn,
    SrcGeoIp,
    SrcIpAsn,
    SrcCidr,
    SrcIpSuffix,
    DstPort,
    SrcPort,
    InPort,
    InType,
    InUser,
    InName,
    ProcessPath,
    ProcessPathWildcard,
    ProcessPathRegex,
    ProcessName,
    ProcessNameWildcard,
    ProcessNameRegex,
    TcpPort,
    UdpPort,
    Uid,
    Network,
    Dscp,
    RuleSet,
    And,
    Or,
    Not,
    SubRule,
    Match,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PolicyTarget {
    pub kind: PolicyTargetKind,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub target: PolicyTarget,
    pub path: PolicyPath,
    pub source: PolicySource,
    pub priority: u16,
    pub original_rule: Option<String>,
    pub tags: Vec<String>,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressedRule {
    pub original_rule: String,
    pub chosen_rule: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsPolicyRule {
    pub pattern: String,
    pub nameservers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteExpectation {
    pub target: String,
    pub expected_path: PolicyPath,
    pub expected_mihomo_action: String,
    pub expected_zapret: bool,
    pub source: PolicySource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledPolicy {
    pub mode: AppRouteMode,
    pub mihomo_rules: Vec<String>,
    pub zapret_hostlist: Vec<String>,
    pub zapret_hostlist_exclude: Vec<String>,
    pub zapret_ipset: Vec<String>,
    pub zapret_ipset_exclude: Vec<String>,
    pub dns_nameserver_policy: Vec<DnsPolicyRule>,
    pub diagnostics_expectations: Vec<RouteExpectation>,
    pub diagnostics_messages: Vec<String>,
    pub suppressed_rules: Vec<SuppressedRule>,
    pub main_proxy_group: String,
    pub policy_rules: Vec<PolicyRule>,
    pub should_create_canonical_proxy_group: bool,
    pub managed_proxy_groups: Vec<ManagedProxyGroup>,
}

impl CompiledPolicy {
    pub fn validate_invariants(&self) -> Result<(), String> {
        match self.mode {
            AppRouteMode::Smart => {
                if self.mihomo_rules.last().map(String::as_str) != Some("MATCH,DIRECT") {
                    return Err("Smart policy must end with MATCH,DIRECT.".to_string());
                }
            }
            AppRouteMode::VpnOnly => {
                let expected_final = format!("MATCH,{}", self.main_proxy_group);
                if self.mihomo_rules.last().map(String::as_str) != Some(expected_final.as_str()) {
                    return Err(format!("VPN Only policy must end with {expected_final}."));
                }
                if self.main_proxy_group.eq_ignore_ascii_case("DIRECT") {
                    return Err("VPN Only main proxy group must not be DIRECT.".to_string());
                }
                if !self.zapret_hostlist.is_empty()
                    || !self.zapret_hostlist_exclude.is_empty()
                    || !self.zapret_ipset.is_empty()
                    || !self.zapret_ipset_exclude.is_empty()
                {
                    return Err("VPN Only policy must not emit zapret artifacts.".to_string());
                }
                for rule in &self.policy_rules {
                    if rule.path == PolicyPath::DirectSafe
                        && !matches!(
                            rule.source,
                            PolicySource::Safety | PolicySource::LocalUserOverride
                        )
                        && !is_safety_target(&rule.target)
                    {
                        return Err(format!(
                            "VPN Only policy kept provider DIRECT rule {}.",
                            route_expectation_target(&rule.target)
                        ));
                    }
                }
                if self.mihomo_rules.iter().any(|rule| rule == "MATCH,DIRECT") {
                    return Err("VPN Only policy must not contain MATCH,DIRECT.".to_string());
                }
            }
        }

        validate_zapret_artifacts("zapret_hostlist", &self.zapret_hostlist)?;
        validate_zapret_artifacts("zapret_hostlist_exclude", &self.zapret_hostlist_exclude)?;
        validate_zapret_artifacts("zapret_ipset", &self.zapret_ipset)?;
        validate_zapret_artifacts("zapret_ipset_exclude", &self.zapret_ipset_exclude)?;
        Ok(())
    }
}

fn validate_zapret_artifacts(name: &str, values: &[String]) -> Result<(), String> {
    const FORBIDDEN_PREFIXES: &[&str] = &[
        "GEOSITE,",
        "GEOIP,",
        "RULE-SET,",
        "PROCESS-NAME,",
        "DOMAIN-KEYWORD,",
        "AND,",
        "OR,",
        "MATCH,",
        "FINAL,",
    ];
    const FORBIDDEN_EXACT: &[&str] = &["DIRECT", "REJECT"];

    for value in values {
        let trimmed = value.trim();
        let uppercase = trimmed.to_ascii_uppercase();
        if trimmed.is_empty()
            || FORBIDDEN_PREFIXES
                .iter()
                .any(|prefix| uppercase.starts_with(prefix))
            || FORBIDDEN_EXACT.iter().any(|exact| uppercase == *exact)
        {
            return Err(format!(
                "{name} contains non-zapret artifact value: {value}"
            ));
        }
        let valid = if name.contains("ipset") {
            is_valid_zapret_ip_or_cidr(trimmed)
        } else {
            is_valid_zapret_domain(trimmed)
        };
        if !valid {
            return Err(format!("{name} contains invalid zapret value: {value}"));
        }
    }
    Ok(())
}

fn is_valid_zapret_domain(value: &str) -> bool {
    if value.contains(',')
        || value.contains('/')
        || value.split_whitespace().count() > 1
        || value.starts_with('.')
        || value.ends_with('.')
    {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    })
}

fn is_valid_zapret_ip_or_cidr(value: &str) -> bool {
    let Some((ip, prefix)) = value.split_once('/') else {
        return value.parse::<std::net::IpAddr>().is_ok();
    };
    let Ok(ip) = ip.parse::<std::net::IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.parse::<u8>() else {
        return false;
    };
    match ip {
        std::net::IpAddr::V4(_) => prefix <= 32,
        std::net::IpAddr::V6(_) => prefix <= 128,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RoutingPolicySettings {
    pub force_vpn_domains: Vec<String>,
    pub force_vpn_cidrs: Vec<String>,
    pub force_zapret_domains: Vec<String>,
    pub force_zapret_cidrs: Vec<String>,
    pub force_zapret_processes: Vec<String>,
    pub force_zapret_tcp_ports: Vec<String>,
    pub force_zapret_udp_ports: Vec<String>,
    pub force_direct_domains: Vec<String>,
    pub force_direct_cidrs: Vec<String>,
    pub force_direct_processes: Vec<String>,
    pub smart_presets: SmartPresetSettings,
    pub coverage: ZapretCoverage,
}

impl Default for RoutingPolicySettings {
    fn default() -> Self {
        Self {
            force_vpn_domains: Vec::new(),
            force_vpn_cidrs: Vec::new(),
            force_zapret_domains: Vec::new(),
            force_zapret_cidrs: Vec::new(),
            force_zapret_processes: Vec::new(),
            force_zapret_tcp_ports: Vec::new(),
            force_zapret_udp_ports: Vec::new(),
            force_direct_domains: Vec::new(),
            force_direct_cidrs: Vec::new(),
            force_direct_processes: Vec::new(),
            smart_presets: SmartPresetSettings::default(),
            coverage: ZapretCoverage::Curated,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SmartPresetSettings {
    pub youtube_discord_zapret: bool,
    pub games_zapret: bool,
    pub ai_vpn: bool,
    pub social_vpn: bool,
    pub telegram_vpn_from_provider: bool,
}

impl Default for SmartPresetSettings {
    fn default() -> Self {
        Self {
            youtube_discord_zapret: true,
            games_zapret: true,
            ai_vpn: true,
            social_vpn: true,
            telegram_vpn_from_provider: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZapretCoverage {
    Curated,
    Broad,
}

impl Default for ZapretCoverage {
    fn default() -> Self {
        Self::Curated
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RuntimeFacts {
    pub selected_proxy_group: Option<String>,
    pub selected_proxy_nodes: Vec<ProxyNode>,
    pub resolved_proxy_ips: Vec<String>,
}

impl Default for RuntimeFacts {
    fn default() -> Self {
        Self {
            selected_proxy_group: None,
            selected_proxy_nodes: Vec::new(),
            resolved_proxy_ips: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyNode {
    pub name: String,
    pub server: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyGroupInfo {
    pub name: String,
    pub group_type: Option<String>,
    pub proxies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedProxyGroup {
    pub name: String,
    pub proxies: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyGroupResolution {
    pub main_proxy_group: String,
    pub available_groups: BTreeSet<String>,
    pub should_create_canonical_proxy_group: bool,
    pub managed_proxy_groups: Vec<ManagedProxyGroup>,
    pub group_rewrites: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct PolicyCompileInput {
    pub mode: AppRouteMode,
    pub provider_rules: Vec<String>,
    pub proxy_groups: Vec<ProxyGroupInfo>,
    pub proxy_count: usize,
    pub routing: RoutingPolicySettings,
    pub runtime_facts: RuntimeFacts,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderRule {
    kind_raw: String,
    target: PolicyTarget,
    action: String,
    options: Vec<String>,
    original_rule: String,
}

#[derive(Debug)]
struct CompileContext {
    mode: AppRouteMode,
    coverage: ZapretCoverage,
    main_proxy_group: String,
    dns_nameservers: Vec<String>,
    mihomo_rules: Vec<String>,
    policy_rules: Vec<PolicyRule>,
    suppressed_rules: Vec<SuppressedRule>,
    diagnostics_expectations: Vec<RouteExpectation>,
    diagnostics_messages: Vec<String>,
    zapret_hostlist: BTreeSet<String>,
    zapret_hostlist_exclude: BTreeSet<String>,
    zapret_ipset: BTreeSet<String>,
    zapret_ipset_exclude: BTreeSet<String>,
    dns_nameserver_policy: BTreeMap<String, Vec<String>>,
    seen_targets: BTreeMap<String, String>,
}

pub fn compile_policy(input: PolicyCompileInput) -> Result<CompiledPolicy, String> {
    let provider_rules = input
        .provider_rules
        .iter()
        .filter_map(|rule| parse_provider_rule(rule))
        .collect::<Vec<_>>();
    let resolution = resolve_proxy_groups(
        input.mode,
        &provider_rules,
        &input.proxy_groups,
        input.proxy_count,
    )?;
    let dns_nameservers = trusted_dns_nameservers();
    let mut ctx = CompileContext {
        mode: input.mode,
        coverage: input.routing.coverage,
        main_proxy_group: resolution.main_proxy_group.clone(),
        dns_nameservers: dns_nameservers.clone(),
        mihomo_rules: Vec::new(),
        policy_rules: Vec::new(),
        suppressed_rules: Vec::new(),
        diagnostics_expectations: Vec::new(),
        diagnostics_messages: Vec::new(),
        zapret_hostlist: BTreeSet::new(),
        zapret_hostlist_exclude: BTreeSet::new(),
        zapret_ipset: BTreeSet::new(),
        zapret_ipset_exclude: BTreeSet::new(),
        dns_nameserver_policy: BTreeMap::new(),
        seen_targets: BTreeMap::new(),
    };
    if input.mode == AppRouteMode::Smart && input.routing.coverage == ZapretCoverage::Broad {
        ctx.diagnostics_messages.push(
            "Broad coverage is experimental; VPN proxy targets are excluded via hostlist-exclude/ipset-exclude where concrete domains or CIDRs are available."
                .to_string(),
        );
    }

    emit_safety_rules(&mut ctx);
    emit_user_overrides(&mut ctx, &input.routing);
    if input.mode == AppRouteMode::Smart {
        emit_smart_presets(&mut ctx, &input.routing.smart_presets, &resolution);
    }
    emit_provider_rules(&mut ctx, &provider_rules, &input.routing, &resolution);
    emit_runtime_excludes(&mut ctx, &input.runtime_facts);
    ctx.dns_nameserver_policy
        .entry("+.badvpn.pro".to_string())
        .or_insert_with(|| dns_nameservers.clone());

    let final_action = match input.mode {
        AppRouteMode::Smart => "DIRECT".to_string(),
        AppRouteMode::VpnOnly => resolution.main_proxy_group.clone(),
    };
    ctx.mihomo_rules.push(format!("MATCH,{final_action}"));

    if input.mode == AppRouteMode::VpnOnly {
        ctx.zapret_hostlist.clear();
        ctx.zapret_hostlist_exclude.clear();
        ctx.zapret_ipset.clear();
        ctx.zapret_ipset_exclude.clear();
    }

    let policy = CompiledPolicy {
        mode: input.mode,
        mihomo_rules: ctx.mihomo_rules,
        zapret_hostlist: ctx.zapret_hostlist.into_iter().collect(),
        zapret_hostlist_exclude: ctx.zapret_hostlist_exclude.into_iter().collect(),
        zapret_ipset: ctx.zapret_ipset.into_iter().collect(),
        zapret_ipset_exclude: ctx.zapret_ipset_exclude.into_iter().collect(),
        dns_nameserver_policy: ctx
            .dns_nameserver_policy
            .into_iter()
            .map(|(pattern, nameservers)| DnsPolicyRule {
                pattern,
                nameservers,
            })
            .collect(),
        diagnostics_expectations: ctx.diagnostics_expectations,
        diagnostics_messages: ctx.diagnostics_messages,
        suppressed_rules: ctx.suppressed_rules,
        main_proxy_group: resolution.main_proxy_group,
        policy_rules: ctx.policy_rules,
        should_create_canonical_proxy_group: resolution.should_create_canonical_proxy_group,
        managed_proxy_groups: resolution.managed_proxy_groups,
    };
    policy.validate_invariants()?;
    Ok(policy)
}

fn resolve_proxy_groups(
    mode: AppRouteMode,
    provider_rules: &[ProviderRule],
    proxy_groups: &[ProxyGroupInfo],
    proxy_count: usize,
) -> Result<ProxyGroupResolution, String> {
    let available_groups = proxy_groups
        .iter()
        .map(|group| group.name.clone())
        .collect::<BTreeSet<_>>();
    let group_type = proxy_groups
        .iter()
        .map(|group| {
            (
                group.name.clone(),
                group
                    .group_type
                    .as_deref()
                    .unwrap_or_default()
                    .to_ascii_lowercase(),
            )
        })
        .collect::<BTreeMap<_, _>>();

    for rule in provider_rules {
        if rule.target.kind == PolicyTargetKind::Match && available_groups.contains(&rule.action) {
            return finalize_proxy_group_resolution(
                mode,
                rule.action.clone(),
                available_groups,
                false,
                proxy_groups,
            );
        }
    }

    for candidate in ["Выбор сервера", "PROXY"] {
        if available_groups.contains(candidate) {
            return finalize_proxy_group_resolution(
                mode,
                candidate.to_string(),
                available_groups,
                false,
                proxy_groups,
            );
        }
    }

    if let Some(group) = proxy_groups.iter().find(|group| {
        group_type
            .get(&group.name)
            .is_some_and(|kind| kind == "select")
    }) {
        return finalize_proxy_group_resolution(
            mode,
            group.name.clone(),
            available_groups,
            false,
            proxy_groups,
        );
    }

    if let Some(group) = proxy_groups.iter().find(|group| {
        group_type
            .get(&group.name)
            .is_some_and(|kind| matches!(kind.as_str(), "url-test" | "fallback" | "load-balance"))
    }) {
        return finalize_proxy_group_resolution(
            mode,
            group.name.clone(),
            available_groups,
            false,
            proxy_groups,
        );
    }

    if proxy_count > 0 {
        return Ok(ProxyGroupResolution {
            main_proxy_group: "PROXY".to_string(),
            available_groups,
            should_create_canonical_proxy_group: true,
            managed_proxy_groups: Vec::new(),
            group_rewrites: BTreeMap::new(),
        });
    }

    Err("Subscription has no proxy groups or proxies for VPN routing.".to_string())
}

fn finalize_proxy_group_resolution(
    mode: AppRouteMode,
    main_proxy_group: String,
    mut available_groups: BTreeSet<String>,
    should_create_canonical_proxy_group: bool,
    proxy_groups: &[ProxyGroupInfo],
) -> Result<ProxyGroupResolution, String> {
    let mut managed_proxy_groups = Vec::new();
    let mut group_rewrites = BTreeMap::new();
    let group_map = proxy_groups
        .iter()
        .map(|group| (group.name.as_str(), group))
        .collect::<BTreeMap<_, _>>();

    if mode == AppRouteMode::VpnOnly {
        if let Some(group) = proxy_groups
            .iter()
            .find(|group| group.name == main_proxy_group)
            .filter(|group| group_transitively_contains_direct(group, &group_map))
        {
            let proxies = safe_leaf_proxy_names(group, &group_map);
            if proxies.is_empty() {
                return Err(
                    "VPN Only cannot start: no non-DIRECT proxy nodes are available in subscription."
                        .to_string(),
                );
            }
            let managed_name = managed_vpn_only_group_name(&available_groups);
            available_groups.insert(managed_name.clone());
            group_rewrites.insert(group.name.clone(), managed_name.clone());
            managed_proxy_groups.push(ManagedProxyGroup {
                name: managed_name.clone(),
                proxies,
            });
            return Ok(ProxyGroupResolution {
                main_proxy_group: managed_name,
                available_groups,
                should_create_canonical_proxy_group,
                managed_proxy_groups,
                group_rewrites,
            });
        }
    }

    Ok(ProxyGroupResolution {
        main_proxy_group,
        available_groups,
        should_create_canonical_proxy_group,
        managed_proxy_groups,
        group_rewrites,
    })
}

fn managed_vpn_only_group_name(available_groups: &BTreeSet<String>) -> String {
    const BASE: &str = "__BADVPN_VPN_ONLY__";
    if !available_groups.contains(BASE) {
        return BASE.to_string();
    }
    for index in 2.. {
        let candidate = format!("__BADVPN_VPN_ONLY_{index}__");
        if !available_groups.contains(&candidate) {
            return candidate;
        }
    }
    unreachable!("infinite suffix search should always find a managed group name")
}

fn group_transitively_contains_direct(
    group: &ProxyGroupInfo,
    group_map: &BTreeMap<&str, &ProxyGroupInfo>,
) -> bool {
    let mut seen = BTreeSet::new();
    group_transitively_contains_direct_inner(group, group_map, &mut seen)
}

fn group_transitively_contains_direct_inner(
    group: &ProxyGroupInfo,
    group_map: &BTreeMap<&str, &ProxyGroupInfo>,
    seen: &mut BTreeSet<String>,
) -> bool {
    if !seen.insert(group.name.clone()) {
        return false;
    }
    group.proxies.iter().any(|proxy| {
        proxy.eq_ignore_ascii_case("DIRECT")
            || group_map.get(proxy.as_str()).is_some_and(|nested| {
                group_transitively_contains_direct_inner(nested, group_map, seen)
            })
    })
}

fn safe_leaf_proxy_names(
    group: &ProxyGroupInfo,
    group_map: &BTreeMap<&str, &ProxyGroupInfo>,
) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut leaves = BTreeSet::new();
    collect_safe_leaf_proxy_names(group, group_map, &mut seen, &mut leaves);
    leaves.into_iter().collect()
}

fn collect_safe_leaf_proxy_names(
    group: &ProxyGroupInfo,
    group_map: &BTreeMap<&str, &ProxyGroupInfo>,
    seen: &mut BTreeSet<String>,
    leaves: &mut BTreeSet<String>,
) {
    if !seen.insert(group.name.clone()) {
        return;
    }
    for proxy in &group.proxies {
        if proxy.eq_ignore_ascii_case("DIRECT") {
            continue;
        }
        if let Some(nested) = group_map.get(proxy.as_str()) {
            if !group_transitively_contains_direct(nested, group_map) {
                collect_safe_leaf_proxy_names(nested, group_map, seen, leaves);
            }
            continue;
        }
        leaves.insert(proxy.clone());
    }
}

fn emit_safety_rules(ctx: &mut CompileContext) {
    for target in private_safety_targets() {
        emit_rule(
            ctx,
            PolicyRule {
                target,
                path: PolicyPath::DirectSafe,
                source: PolicySource::Safety,
                priority: 1000,
                original_rule: None,
                tags: vec!["safety".to_string()],
                options: vec!["no-resolve".to_string()],
            },
            None,
        );
    }
    emit_rule(
        ctx,
        PolicyRule {
            target: PolicyTarget {
                kind: PolicyTargetKind::GeoSite,
                value: "private".to_string(),
            },
            path: PolicyPath::DirectSafe,
            source: PolicySource::Safety,
            priority: 1000,
            original_rule: None,
            tags: vec!["safety".to_string()],
            options: Vec::new(),
        },
        None,
    );
}

fn emit_user_overrides(ctx: &mut CompileContext, settings: &RoutingPolicySettings) {
    for domain in normalize_domain_list(settings.force_vpn_domains.iter().cloned()) {
        emit_domain_override(
            ctx,
            domain,
            PolicyPath::VpnProxy {
                group: ctx.main_proxy_group.clone(),
            },
        );
    }
    for cidr in normalize_cidr_list(settings.force_vpn_cidrs.iter().cloned()) {
        emit_cidr_override(
            ctx,
            cidr,
            PolicyPath::VpnProxy {
                group: ctx.main_proxy_group.clone(),
            },
        );
    }

    for domain in normalize_domain_list(settings.force_zapret_domains.iter().cloned()) {
        let path = if ctx.mode == AppRouteMode::Smart {
            PolicyPath::ZapretDirect
        } else {
            PolicyPath::VpnProxy {
                group: ctx.main_proxy_group.clone(),
            }
        };
        emit_domain_override(ctx, domain, path);
    }
    for cidr in normalize_cidr_list(settings.force_zapret_cidrs.iter().cloned()) {
        let path = if ctx.mode == AppRouteMode::Smart {
            PolicyPath::ZapretDirect
        } else {
            PolicyPath::VpnProxy {
                group: ctx.main_proxy_group.clone(),
            }
        };
        emit_cidr_override(ctx, cidr, path);
    }
    for process in normalize_process_list(settings.force_zapret_processes.iter().cloned()) {
        let path = if ctx.mode == AppRouteMode::Smart {
            PolicyPath::ZapretDirect
        } else {
            PolicyPath::VpnProxy {
                group: ctx.main_proxy_group.clone(),
            }
        };
        emit_rule(
            ctx,
            PolicyRule {
                target: PolicyTarget {
                    kind: PolicyTargetKind::ProcessName,
                    value: process,
                },
                path,
                source: PolicySource::LocalUserOverride,
                priority: 900,
                original_rule: None,
                tags: vec!["force_zapret".to_string()],
                options: Vec::new(),
            },
            None,
        );
    }
    for port in normalize_port_list(settings.force_zapret_tcp_ports.iter().cloned()) {
        let path = if ctx.mode == AppRouteMode::Smart {
            PolicyPath::ZapretDirect
        } else {
            PolicyPath::VpnProxy {
                group: ctx.main_proxy_group.clone(),
            }
        };
        emit_rule(
            ctx,
            PolicyRule {
                target: PolicyTarget {
                    kind: PolicyTargetKind::TcpPort,
                    value: port,
                },
                path,
                source: PolicySource::LocalUserOverride,
                priority: 900,
                original_rule: None,
                tags: vec!["force_zapret".to_string()],
                options: Vec::new(),
            },
            None,
        );
    }
    for port in normalize_port_list(settings.force_zapret_udp_ports.iter().cloned()) {
        let path = if ctx.mode == AppRouteMode::Smart {
            PolicyPath::ZapretDirect
        } else {
            PolicyPath::VpnProxy {
                group: ctx.main_proxy_group.clone(),
            }
        };
        emit_rule(
            ctx,
            PolicyRule {
                target: PolicyTarget {
                    kind: PolicyTargetKind::UdpPort,
                    value: port,
                },
                path,
                source: PolicySource::LocalUserOverride,
                priority: 900,
                original_rule: None,
                tags: vec!["force_zapret".to_string()],
                options: Vec::new(),
            },
            None,
        );
    }

    for domain in normalize_domain_list(settings.force_direct_domains.iter().cloned()) {
        emit_domain_override(ctx, domain, PolicyPath::DirectSafe);
    }
    for cidr in normalize_cidr_list(settings.force_direct_cidrs.iter().cloned()) {
        emit_cidr_override(ctx, cidr, PolicyPath::DirectSafe);
    }
    for process in normalize_process_list(settings.force_direct_processes.iter().cloned()) {
        emit_rule(
            ctx,
            PolicyRule {
                target: PolicyTarget {
                    kind: PolicyTargetKind::ProcessName,
                    value: process,
                },
                path: PolicyPath::DirectSafe,
                source: PolicySource::LocalUserOverride,
                priority: 900,
                original_rule: None,
                tags: vec!["force_direct".to_string()],
                options: Vec::new(),
            },
            None,
        );
    }
}

fn emit_domain_override(ctx: &mut CompileContext, domain: String, path: PolicyPath) {
    emit_rule(
        ctx,
        PolicyRule {
            target: PolicyTarget {
                kind: PolicyTargetKind::DomainSuffix,
                value: domain,
            },
            path,
            source: PolicySource::LocalUserOverride,
            priority: 900,
            original_rule: None,
            tags: Vec::new(),
            options: Vec::new(),
        },
        None,
    );
}

fn emit_cidr_override(ctx: &mut CompileContext, cidr: String, path: PolicyPath) {
    let kind = if cidr.contains(':') {
        PolicyTargetKind::Cidr6
    } else {
        PolicyTargetKind::Cidr
    };
    emit_rule(
        ctx,
        PolicyRule {
            target: PolicyTarget { kind, value: cidr },
            path,
            source: PolicySource::LocalUserOverride,
            priority: 900,
            original_rule: None,
            tags: Vec::new(),
            options: vec!["no-resolve".to_string()],
        },
        None,
    );
}

fn emit_smart_presets(
    ctx: &mut CompileContext,
    presets: &SmartPresetSettings,
    resolution: &ProxyGroupResolution,
) {
    if presets.ai_vpn {
        let group = if resolution.available_groups.contains("🤖 AI") {
            "🤖 AI".to_string()
        } else {
            ctx.main_proxy_group.clone()
        };
        for domain in ai_vpn_domains() {
            emit_preset_domain(
                ctx,
                domain,
                PolicyPath::VpnProxy {
                    group: group.clone(),
                },
                "ai",
            );
        }
    }
    if presets.social_vpn {
        for domain in social_vpn_domains() {
            emit_preset_domain(
                ctx,
                domain,
                PolicyPath::VpnProxy {
                    group: ctx.main_proxy_group.clone(),
                },
                "social",
            );
        }
    }
    if presets.youtube_discord_zapret {
        for domain in youtube_discord_zapret_domains() {
            emit_preset_domain(ctx, domain, PolicyPath::ZapretDirect, "youtube_discord");
        }
    }
}

fn emit_preset_domain(ctx: &mut CompileContext, domain: &str, path: PolicyPath, tag: &str) {
    emit_rule(
        ctx,
        PolicyRule {
            target: PolicyTarget {
                kind: PolicyTargetKind::DomainSuffix,
                value: domain.to_string(),
            },
            path,
            source: PolicySource::BadVpnPreset,
            priority: 800,
            original_rule: None,
            tags: vec![tag.to_string()],
            options: Vec::new(),
        },
        None,
    );
}

fn emit_provider_rules(
    ctx: &mut CompileContext,
    provider_rules: &[ProviderRule],
    settings: &RoutingPolicySettings,
    resolution: &ProxyGroupResolution,
) {
    for provider in provider_rules {
        if provider.target.kind == PolicyTargetKind::Match {
            let chosen = if ctx.mode == AppRouteMode::Smart {
                "MATCH,DIRECT".to_string()
            } else {
                format!("MATCH,{}", ctx.main_proxy_group)
            };
            if provider.original_rule.trim() != chosen {
                ctx.suppressed_rules.push(SuppressedRule {
                    original_rule: provider.original_rule.clone(),
                    chosen_rule: chosen,
                    reason: match ctx.mode {
                        AppRouteMode::Smart => {
                            "Provider final route is replaced by Smart default DIRECT.".to_string()
                        }
                        AppRouteMode::VpnOnly => {
                            "Provider final route is normalized to VPN Only default proxy group."
                                .to_string()
                        }
                    },
                });
            }
            continue;
        }

        if action_is_reject(&provider.action) {
            emit_provider_path(ctx, provider, PolicyPath::Reject, 700, None);
            continue;
        }

        match ctx.mode {
            AppRouteMode::Smart => emit_smart_provider_rule(ctx, provider, settings, resolution),
            AppRouteMode::VpnOnly => emit_vpn_only_provider_rule(ctx, provider, resolution),
        }
    }
}

fn emit_smart_provider_rule(
    ctx: &mut CompileContext,
    provider: &ProviderRule,
    settings: &RoutingPolicySettings,
    resolution: &ProxyGroupResolution,
) {
    if settings.smart_presets.youtube_discord_zapret && is_youtube_discord_target(&provider.target)
    {
        emit_provider_path(
            ctx,
            provider,
            PolicyPath::ZapretDirect,
            800,
            Some("Smart policy routes YouTube/Discord through DIRECT + zapret.".to_string()),
        );
        return;
    }

    if action_is_direct(&provider.action) {
        emit_provider_path(ctx, provider, PolicyPath::DirectSafe, 500, None);
        return;
    }

    if provider_action_is_group(&provider.action, resolution) {
        emit_provider_path(
            ctx,
            provider,
            PolicyPath::VpnProxy {
                group: provider.action.clone(),
            },
            600,
            None,
        );
        return;
    }

    let path = PolicyPath::VpnProxy {
        group: ctx.main_proxy_group.clone(),
    };
    emit_provider_path(ctx, provider, path, 600, None);
}

fn emit_vpn_only_provider_rule(
    ctx: &mut CompileContext,
    provider: &ProviderRule,
    resolution: &ProxyGroupResolution,
) {
    if action_is_direct(&provider.action) {
        if is_safety_target(&provider.target) {
            emit_provider_path(ctx, provider, PolicyPath::DirectSafe, 1000, None);
        } else {
            ctx.suppressed_rules.push(SuppressedRule {
                original_rule: provider.original_rule.clone(),
                chosen_rule: format!("MATCH,{}", ctx.main_proxy_group),
                reason:
                    "VPN Only suppresses external provider DIRECT rules unless Force DIRECT is set."
                        .to_string(),
            });
        }
        return;
    }

    let group = resolution
        .group_rewrites
        .get(&provider.action)
        .cloned()
        .unwrap_or_else(|| provider.action.clone());
    let reason = resolution
        .group_rewrites
        .get(&provider.action)
        .map(|_| "VPN Only routes provider group through a managed no-DIRECT group.".to_string());
    emit_provider_path(ctx, provider, PolicyPath::VpnProxy { group }, 600, reason);
}

fn emit_provider_path(
    ctx: &mut CompileContext,
    provider: &ProviderRule,
    path: PolicyPath,
    priority: u16,
    reason: Option<String>,
) {
    emit_rule(
        ctx,
        PolicyRule {
            target: provider.target.clone(),
            path,
            source: if priority == 800 {
                PolicySource::BadVpnPreset
            } else {
                PolicySource::ProviderSubscription
            },
            priority,
            original_rule: Some(provider.original_rule.clone()),
            tags: Vec::new(),
            options: provider.options.clone(),
        },
        reason,
    );
}

fn emit_runtime_excludes(ctx: &mut CompileContext, facts: &RuntimeFacts) {
    for ip in normalize_cidr_list(facts.resolved_proxy_ips.iter().cloned()) {
        ctx.zapret_ipset_exclude.insert(ip);
    }
    for node in &facts.selected_proxy_nodes {
        if let Some(server) = &node.server {
            if server.parse::<std::net::IpAddr>().is_ok() {
                ctx.zapret_ipset_exclude.insert(server.clone());
            }
        }
    }
}

fn emit_rule(ctx: &mut CompileContext, rule: PolicyRule, reason: Option<String>) {
    let rendered = render_policy_rule(&rule);
    let key = target_key(&rule.target);
    if let Some(chosen) = ctx.seen_targets.get(&key) {
        if let Some(original_rule) = rule.original_rule.clone() {
            ctx.suppressed_rules.push(SuppressedRule {
                original_rule,
                chosen_rule: chosen.clone(),
                reason: reason.unwrap_or_else(|| {
                    "Higher-priority BadVPN policy rule already covers this target.".to_string()
                }),
            });
        }
        return;
    }

    if let Some(original_rule) = rule.original_rule.as_deref() {
        if original_rule.trim() != rendered {
            ctx.suppressed_rules.push(SuppressedRule {
                original_rule: original_rule.to_string(),
                chosen_rule: rendered.clone(),
                reason: reason.unwrap_or_else(|| {
                    "Provider rule was normalized by the effective BadVPN policy.".to_string()
                }),
            });
        }
    }

    collect_artifacts(ctx, &rule);
    if rule.path == PolicyPath::ZapretDirect && rule.target.kind == PolicyTargetKind::ProcessName {
        ctx.diagnostics_messages.push(format!(
            "Process-only DIRECT rule {} is routed through Mihomo DIRECT only; zapret coverage depends on domain/CIDR/port data or Broad coverage.",
            route_expectation_target(&rule.target)
        ));
    }
    ctx.diagnostics_expectations.push(RouteExpectation {
        target: route_expectation_target(&rule.target),
        expected_path: rule.path.clone(),
        expected_mihomo_action: policy_mihomo_action(&rule.path),
        expected_zapret: expected_zapret_for_rule(&rule),
        source: rule.source,
    });
    ctx.seen_targets.insert(key, rendered.clone());
    ctx.mihomo_rules.push(rendered);
    ctx.policy_rules.push(rule);
}

fn collect_artifacts(ctx: &mut CompileContext, rule: &PolicyRule) {
    match &rule.path {
        PolicyPath::ZapretDirect => {
            for host in hostlist_values_for_target(&rule.target) {
                ctx.zapret_hostlist.insert(host);
            }
            if matches!(
                rule.target.kind,
                PolicyTargetKind::Cidr | PolicyTargetKind::Cidr6
            ) {
                ctx.zapret_ipset.insert(rule.target.value.clone());
            }
        }
        PolicyPath::VpnProxy { .. } => {
            let hosts = hostlist_values_for_target(&rule.target);
            if ctx.mode == AppRouteMode::Smart
                && ctx.coverage == ZapretCoverage::Broad
                && hosts.is_empty()
                && !matches!(
                    rule.target.kind,
                    PolicyTargetKind::Cidr | PolicyTargetKind::Cidr6
                )
            {
                ctx.diagnostics_messages.push(format!(
                    "{} cannot be represented in zapret exclude; Broad coverage may affect this target.",
                    route_expectation_target(&rule.target)
                ));
            }
            for host in hosts {
                ctx.zapret_hostlist_exclude.insert(host);
                if let Some(pattern) = dns_policy_pattern_for_target(&rule.target) {
                    ctx.dns_nameserver_policy
                        .entry(pattern)
                        .or_insert_with(|| ctx.dns_nameservers.clone());
                }
            }
            if matches!(
                rule.target.kind,
                PolicyTargetKind::Cidr | PolicyTargetKind::Cidr6
            ) {
                ctx.zapret_ipset_exclude.insert(rule.target.value.clone());
            }
        }
        PolicyPath::DirectSafe => {
            for host in hostlist_values_for_target(&rule.target) {
                ctx.zapret_hostlist_exclude.insert(host);
            }
            if matches!(
                rule.target.kind,
                PolicyTargetKind::Cidr | PolicyTargetKind::Cidr6
            ) {
                ctx.zapret_ipset_exclude.insert(rule.target.value.clone());
            }
        }
        PolicyPath::Reject => {}
    }
}

fn render_policy_rule(rule: &PolicyRule) -> String {
    if rule.target.kind == PolicyTargetKind::Match {
        return format!("MATCH,{}", policy_mihomo_action(&rule.path));
    }
    if rule.target.kind == PolicyTargetKind::TcpPort {
        return format!(
            "AND,((NETWORK,TCP),(DST-PORT,{})),{}",
            rule.target.value,
            policy_mihomo_action(&rule.path)
        );
    }
    if rule.target.kind == PolicyTargetKind::UdpPort {
        return format!(
            "AND,((NETWORK,UDP),(DST-PORT,{})),{}",
            rule.target.value,
            policy_mihomo_action(&rule.path)
        );
    }
    let mut rendered = format!(
        "{},{},{}",
        mihomo_kind(rule.target.kind),
        rule.target.value,
        policy_mihomo_action(&rule.path)
    );
    for option in &rule.options {
        rendered.push(',');
        rendered.push_str(option);
    }
    rendered
}

fn policy_mihomo_action(path: &PolicyPath) -> String {
    match path {
        PolicyPath::DirectSafe | PolicyPath::ZapretDirect => "DIRECT".to_string(),
        PolicyPath::VpnProxy { group } => group.clone(),
        PolicyPath::Reject => "REJECT".to_string(),
    }
}

fn parse_provider_rule(rule: &str) -> Option<ProviderRule> {
    let parts = split_top_level_rule_fields(rule);
    if parts.len() < 2 {
        return None;
    }
    let kind_raw = parts[0].to_ascii_uppercase();
    if matches!(kind_raw.as_str(), "MATCH" | "FINAL") {
        return Some(ProviderRule {
            kind_raw: "MATCH".to_string(),
            target: PolicyTarget {
                kind: PolicyTargetKind::Match,
                value: "*".to_string(),
            },
            action: parts[1].clone(),
            options: parts.iter().skip(2).cloned().collect(),
            original_rule: rule.trim().to_string(),
        });
    }
    if parts.len() < 3 {
        return None;
    }
    Some(ProviderRule {
        target: PolicyTarget {
            kind: provider_target_kind(&kind_raw),
            value: parts[1].clone(),
        },
        kind_raw,
        action: parts[2].clone(),
        options: parts.iter().skip(3).cloned().collect(),
        original_rule: rule.trim().to_string(),
    })
}

fn split_top_level_rule_fields(rule: &str) -> Vec<String> {
    let trimmed = rule.trim();
    let mut fields = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;

    for (index, ch) in trimmed.char_indices() {
        match ch {
            '(' => depth = depth.saturating_add(1),
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                fields.push(trimmed[start..index].trim().to_string());
                start = index + ch.len_utf8();
            }
            _ => {}
        }
    }

    fields.push(trimmed[start..].trim().to_string());
    fields
}

fn provider_target_kind(kind: &str) -> PolicyTargetKind {
    match kind {
        "DOMAIN" => PolicyTargetKind::Domain,
        "DOMAIN-SUFFIX" => PolicyTargetKind::DomainSuffix,
        "DOMAIN-KEYWORD" => PolicyTargetKind::DomainKeyword,
        "DOMAIN-WILDCARD" => PolicyTargetKind::DomainWildcard,
        "DOMAIN-REGEX" => PolicyTargetKind::DomainRegex,
        "GEOSITE" => PolicyTargetKind::GeoSite,
        "GEOIP" => PolicyTargetKind::GeoIp,
        "IP-CIDR" => PolicyTargetKind::Cidr,
        "IP-CIDR6" => PolicyTargetKind::Cidr6,
        "IP-SUFFIX" => PolicyTargetKind::IpSuffix,
        "IP-ASN" => PolicyTargetKind::IpAsn,
        "SRC-GEOIP" => PolicyTargetKind::SrcGeoIp,
        "SRC-IP-ASN" => PolicyTargetKind::SrcIpAsn,
        "SRC-IP-CIDR" => PolicyTargetKind::SrcCidr,
        "SRC-IP-SUFFIX" => PolicyTargetKind::SrcIpSuffix,
        "DST-PORT" => PolicyTargetKind::DstPort,
        "SRC-PORT" => PolicyTargetKind::SrcPort,
        "IN-PORT" => PolicyTargetKind::InPort,
        "IN-TYPE" => PolicyTargetKind::InType,
        "IN-USER" => PolicyTargetKind::InUser,
        "IN-NAME" => PolicyTargetKind::InName,
        "PROCESS-PATH" => PolicyTargetKind::ProcessPath,
        "PROCESS-PATH-WILDCARD" => PolicyTargetKind::ProcessPathWildcard,
        "PROCESS-PATH-REGEX" => PolicyTargetKind::ProcessPathRegex,
        "PROCESS-NAME" => PolicyTargetKind::ProcessName,
        "PROCESS-NAME-WILDCARD" => PolicyTargetKind::ProcessNameWildcard,
        "PROCESS-NAME-REGEX" => PolicyTargetKind::ProcessNameRegex,
        "UID" => PolicyTargetKind::Uid,
        "NETWORK" => PolicyTargetKind::Network,
        "DSCP" => PolicyTargetKind::Dscp,
        "RULE-SET" => PolicyTargetKind::RuleSet,
        "AND" => PolicyTargetKind::And,
        "OR" => PolicyTargetKind::Or,
        "NOT" => PolicyTargetKind::Not,
        "SUB-RULE" => PolicyTargetKind::SubRule,
        _ => PolicyTargetKind::RuleSet,
    }
}

fn mihomo_kind(kind: PolicyTargetKind) -> &'static str {
    match kind {
        PolicyTargetKind::Domain => "DOMAIN",
        PolicyTargetKind::DomainSuffix => "DOMAIN-SUFFIX",
        PolicyTargetKind::DomainKeyword => "DOMAIN-KEYWORD",
        PolicyTargetKind::DomainWildcard => "DOMAIN-WILDCARD",
        PolicyTargetKind::DomainRegex => "DOMAIN-REGEX",
        PolicyTargetKind::GeoSite => "GEOSITE",
        PolicyTargetKind::GeoIp => "GEOIP",
        PolicyTargetKind::Cidr => "IP-CIDR",
        PolicyTargetKind::Cidr6 => "IP-CIDR6",
        PolicyTargetKind::IpSuffix => "IP-SUFFIX",
        PolicyTargetKind::IpAsn => "IP-ASN",
        PolicyTargetKind::SrcGeoIp => "SRC-GEOIP",
        PolicyTargetKind::SrcIpAsn => "SRC-IP-ASN",
        PolicyTargetKind::SrcCidr => "SRC-IP-CIDR",
        PolicyTargetKind::SrcIpSuffix => "SRC-IP-SUFFIX",
        PolicyTargetKind::DstPort => "DST-PORT",
        PolicyTargetKind::SrcPort => "SRC-PORT",
        PolicyTargetKind::InPort => "IN-PORT",
        PolicyTargetKind::InType => "IN-TYPE",
        PolicyTargetKind::InUser => "IN-USER",
        PolicyTargetKind::InName => "IN-NAME",
        PolicyTargetKind::ProcessPath => "PROCESS-PATH",
        PolicyTargetKind::ProcessPathWildcard => "PROCESS-PATH-WILDCARD",
        PolicyTargetKind::ProcessPathRegex => "PROCESS-PATH-REGEX",
        PolicyTargetKind::ProcessName => "PROCESS-NAME",
        PolicyTargetKind::ProcessNameWildcard => "PROCESS-NAME-WILDCARD",
        PolicyTargetKind::ProcessNameRegex => "PROCESS-NAME-REGEX",
        PolicyTargetKind::TcpPort => "DST-PORT",
        PolicyTargetKind::UdpPort => "DST-PORT",
        PolicyTargetKind::Uid => "UID",
        PolicyTargetKind::Network => "NETWORK",
        PolicyTargetKind::Dscp => "DSCP",
        PolicyTargetKind::RuleSet => "RULE-SET",
        PolicyTargetKind::And => "AND",
        PolicyTargetKind::Or => "OR",
        PolicyTargetKind::Not => "NOT",
        PolicyTargetKind::SubRule => "SUB-RULE",
        PolicyTargetKind::Match => "MATCH",
    }
}

fn action_is_direct(action: &str) -> bool {
    action.eq_ignore_ascii_case("DIRECT")
}

fn action_is_reject(action: &str) -> bool {
    matches!(
        action.to_ascii_uppercase().as_str(),
        "REJECT" | "REJECT-DROP" | "REJECT-TINYGIF"
    )
}

fn provider_action_is_group(action: &str, resolution: &ProxyGroupResolution) -> bool {
    resolution.available_groups.contains(action)
}

fn is_youtube_discord_target(target: &PolicyTarget) -> bool {
    let value = target.value.to_ascii_lowercase();
    match target.kind {
        PolicyTargetKind::GeoSite => matches!(value.as_str(), "youtube" | "discord"),
        PolicyTargetKind::Domain | PolicyTargetKind::DomainSuffix => {
            youtube_discord_zapret_domains()
                .iter()
                .any(|domain| domain_matches(&value, domain))
        }
        PolicyTargetKind::DomainKeyword => {
            value.contains("youtube")
                || value.contains("youtu")
                || value.contains("googlevideo")
                || value.contains("discord")
        }
        _ => false,
    }
}

fn is_safety_target(target: &PolicyTarget) -> bool {
    let value = target.value.to_ascii_lowercase();
    match target.kind {
        PolicyTargetKind::GeoSite | PolicyTargetKind::GeoIp => value == "private",
        PolicyTargetKind::Cidr | PolicyTargetKind::Cidr6 => is_private_cidr_value(&value),
        PolicyTargetKind::Domain | PolicyTargetKind::DomainSuffix => {
            matches!(value.as_str(), "localhost" | "local") || value.ends_with(".local")
        }
        _ => false,
    }
}

fn private_safety_targets() -> Vec<PolicyTarget> {
    [
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
    ]
    .into_iter()
    .map(|value| PolicyTarget {
        kind: PolicyTargetKind::Cidr,
        value: value.to_string(),
    })
    .chain(
        ["::1/128", "fc00::/7", "fe80::/10"]
            .into_iter()
            .map(|value| PolicyTarget {
                kind: PolicyTargetKind::Cidr6,
                value: value.to_string(),
            }),
    )
    .collect()
}

fn is_private_cidr_value(value: &str) -> bool {
    matches!(
        value,
        "0.0.0.0/8"
            | "10.0.0.0/8"
            | "100.64.0.0/10"
            | "127.0.0.0/8"
            | "169.254.0.0/16"
            | "172.16.0.0/12"
            | "192.168.0.0/16"
            | "224.0.0.0/4"
            | "::1/128"
            | "fc00::/7"
            | "fe80::/10"
    )
}

fn target_key(target: &PolicyTarget) -> String {
    format!("{:?}:{}", target.kind, target.value.to_ascii_lowercase())
}

fn route_expectation_target(target: &PolicyTarget) -> String {
    if target.kind == PolicyTargetKind::Match {
        "MATCH".to_string()
    } else {
        format!("{},{}", mihomo_kind(target.kind), target.value)
    }
}

fn expected_zapret_for_rule(rule: &PolicyRule) -> bool {
    if rule.path != PolicyPath::ZapretDirect {
        return false;
    }

    match rule.target.kind {
        PolicyTargetKind::Domain | PolicyTargetKind::DomainSuffix => true,
        PolicyTargetKind::GeoSite => !hostlist_values_for_target(&rule.target).is_empty(),
        PolicyTargetKind::Cidr | PolicyTargetKind::Cidr6 => true,
        _ => false,
    }
}

fn hostlist_values_for_target(target: &PolicyTarget) -> Vec<String> {
    let value = target
        .value
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase();
    match target.kind {
        PolicyTargetKind::Domain | PolicyTargetKind::DomainSuffix => vec![value],
        PolicyTargetKind::GeoSite if value == "youtube" => youtube_hostlist_domains()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
        PolicyTargetKind::GeoSite if value == "discord" => discord_hostlist_domains()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn dns_policy_pattern_for_target(target: &PolicyTarget) -> Option<String> {
    match target.kind {
        PolicyTargetKind::Domain | PolicyTargetKind::DomainSuffix => {
            Some(format!("+.{}", target.value.trim_start_matches('.')))
        }
        _ => None,
    }
}

fn domain_matches(value: &str, domain: &str) -> bool {
    value == domain || value.ends_with(&format!(".{domain}"))
}

fn trusted_dns_nameservers() -> Vec<String> {
    vec![
        "https://1.1.1.1/dns-query".to_string(),
        "https://8.8.8.8/dns-query".to_string(),
    ]
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
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalize_cidr_list(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .filter_map(|value| normalize_ip_or_cidr(&value))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalize_ip_or_cidr(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.starts_with('#') {
        return None;
    }

    if let Some((ip, prefix)) = value.split_once('/') {
        if prefix.contains('/') {
            return None;
        }
        let ip = ip.trim().parse::<IpAddr>().ok()?;
        let prefix = prefix.trim().parse::<u8>().ok()?;
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        return (prefix <= max_prefix).then(|| format!("{ip}/{prefix}"));
    }

    let ip = value.parse::<IpAddr>().ok()?;
    let prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    Some(format!("{ip}/{prefix}"))
}

fn normalize_process_list(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .filter_map(|value| {
            let value = value.trim().trim_matches('"').to_string();
            if value.is_empty()
                || value.contains(',')
                || value.contains('/')
                || value.contains('\\')
            {
                None
            } else {
                Some(value)
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn normalize_port_list(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values
        .into_iter()
        .filter_map(|value| {
            let value = value.trim().to_string();
            if valid_port_rule_value(&value) {
                Some(value)
            } else {
                None
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn valid_port_rule_value(value: &str) -> bool {
    if value.is_empty() || value.contains(',') {
        return false;
    }
    let mut parts = value.split('-');
    let Some(start) = parts.next().and_then(|part| part.parse::<u16>().ok()) else {
        return false;
    };
    let end = parts
        .next()
        .and_then(|part| part.parse::<u16>().ok())
        .unwrap_or(start);
    parts.next().is_none() && start > 0 && end >= start
}

fn youtube_discord_zapret_domains() -> Vec<&'static str> {
    youtube_hostlist_domains()
        .into_iter()
        .chain(discord_hostlist_domains())
        .collect()
}

fn youtube_hostlist_domains() -> Vec<&'static str> {
    vec![
        "youtube.com",
        "youtu.be",
        "googlevideo.com",
        "ytimg.com",
        "youtubei.googleapis.com",
        "youtube-nocookie.com",
    ]
}

fn discord_hostlist_domains() -> Vec<&'static str> {
    vec![
        "discord.com",
        "discord.gg",
        "discordapp.com",
        "discordapp.net",
        "discordcdn.com",
        "discord.media",
        "discordstatus.com",
    ]
}

fn ai_vpn_domains() -> Vec<&'static str> {
    vec![
        "chatgpt.com",
        "openai.com",
        "oaistatic.com",
        "oaiusercontent.com",
        "claude.ai",
        "anthropic.com",
        "perplexity.ai",
    ]
}

fn social_vpn_domains() -> Vec<&'static str> {
    vec![
        "instagram.com",
        "cdninstagram.com",
        "facebook.com",
        "fbcdn.net",
        "meta.com",
        "x.com",
        "twitter.com",
        "twimg.com",
        "linkedin.com",
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_rules() -> Vec<String> {
        vec![
            "GEOSITE,category-ads-all,REJECT".to_string(),
            "GEOSITE,youtube,📺 YouTube и Discord".to_string(),
            "DOMAIN-SUFFIX,googlevideo.com,📺 YouTube и Discord".to_string(),
            "DOMAIN-SUFFIX,youtu.be,📺 YouTube и Discord".to_string(),
            "GEOSITE,discord,📺 YouTube и Discord".to_string(),
            "DOMAIN-SUFFIX,generativelanguage.googleapis.com,🤖 AI".to_string(),
            "GEOSITE,openai,🤖 AI".to_string(),
            "GEOSITE,anthropic,🤖 AI".to_string(),
            "DOMAIN-SUFFIX,perplexity.ai,🤖 AI".to_string(),
            "GEOSITE,telegram,Выбор сервера".to_string(),
            "IP-CIDR,149.154.160.0/20,Выбор сервера,no-resolve".to_string(),
            "DOMAIN-KEYWORD,sberbank,DIRECT".to_string(),
            "DOMAIN-SUFFIX,yandex.com,DIRECT".to_string(),
            "GEOSITE,yandex,DIRECT".to_string(),
            "DOMAIN-SUFFIX,vk.com,DIRECT".to_string(),
            "DOMAIN-SUFFIX,ru,DIRECT".to_string(),
            "GEOIP,ru,DIRECT,no-resolve".to_string(),
            "MATCH,Выбор сервера".to_string(),
        ]
    }

    fn groups() -> Vec<ProxyGroupInfo> {
        vec![
            ProxyGroupInfo {
                name: "Выбор сервера".to_string(),
                group_type: Some("select".to_string()),
                proxies: vec!["Germany".to_string()],
            },
            ProxyGroupInfo {
                name: "🤖 AI".to_string(),
                group_type: Some("select".to_string()),
                proxies: vec!["Выбор сервера".to_string()],
            },
            ProxyGroupInfo {
                name: "📺 YouTube и Discord".to_string(),
                group_type: Some("select".to_string()),
                proxies: vec!["Выбор сервера".to_string()],
            },
        ]
    }

    fn compile(mode: AppRouteMode) -> CompiledPolicy {
        compile_policy(PolicyCompileInput {
            mode,
            provider_rules: fixture_rules(),
            proxy_groups: groups(),
            proxy_count: 2,
            routing: RoutingPolicySettings::default(),
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap()
    }

    fn assert_no_zapret_artifact_contains_non_zapret_token(policy: &CompiledPolicy) {
        policy.validate_invariants().unwrap();
        for value in policy
            .zapret_hostlist
            .iter()
            .chain(policy.zapret_hostlist_exclude.iter())
            .chain(policy.zapret_ipset.iter())
            .chain(policy.zapret_ipset_exclude.iter())
        {
            let upper = value.to_ascii_uppercase();
            assert!(!value.contains(','), "{value}");
            assert!(!upper.starts_with("GEOSITE"), "{value}");
            assert!(!upper.starts_with("GEOIP"), "{value}");
            assert!(!upper.starts_with("RULE-SET"), "{value}");
            assert!(!upper.starts_with("PROCESS-NAME"), "{value}");
            assert!(!upper.starts_with("DOMAIN-KEYWORD"), "{value}");
            assert!(!upper.starts_with("MATCH"), "{value}");
            assert!(!upper.starts_with("FINAL"), "{value}");
            assert!(!upper.starts_with("DIRECT"), "{value}");
            assert!(!upper.starts_with("REJECT"), "{value}");
        }
    }

    #[test]
    fn smart_overrides_provider_youtube_proxy_to_zapret_direct() {
        let policy = compile(AppRouteMode::Smart);
        assert!(policy
            .mihomo_rules
            .contains(&"GEOSITE,youtube,DIRECT".to_string()));
        assert!(policy
            .mihomo_rules
            .contains(&"DOMAIN-SUFFIX,googlevideo.com,DIRECT".to_string()));
        assert!(policy
            .suppressed_rules
            .iter()
            .any(|rule| rule.original_rule.contains("GEOSITE,youtube")));
    }

    #[test]
    fn smart_keeps_ai_provider_group_as_vpn_proxy() {
        let policy = compile(AppRouteMode::Smart);
        assert!(policy
            .mihomo_rules
            .contains(&"GEOSITE,openai,🤖 AI".to_string()));
        assert!(policy
            .zapret_hostlist_exclude
            .contains(&"perplexity.ai".to_string()));
    }

    #[test]
    fn smart_keeps_telegram_provider_group_as_vpn_proxy() {
        let policy = compile(AppRouteMode::Smart);
        assert!(policy
            .mihomo_rules
            .contains(&"GEOSITE,telegram,Выбор сервера".to_string()));
    }

    #[test]
    fn smart_keeps_ru_direct_as_direct_safe() {
        let policy = compile(AppRouteMode::Smart);
        assert!(policy
            .mihomo_rules
            .contains(&"GEOSITE,yandex,DIRECT".to_string()));
        assert!(policy
            .mihomo_rules
            .contains(&"GEOIP,ru,DIRECT,no-resolve".to_string()));
    }

    #[test]
    fn smart_replaces_provider_match_with_direct() {
        let policy = compile(AppRouteMode::Smart);
        assert_eq!(
            policy.mihomo_rules.last().map(String::as_str),
            Some("MATCH,DIRECT")
        );
        assert!(!policy
            .mihomo_rules
            .iter()
            .any(|rule| rule == "MATCH,Выбор сервера"));
    }

    #[test]
    fn smart_generates_zapret_hostlist_for_youtube_discord() {
        let policy = compile(AppRouteMode::Smart);
        assert_no_zapret_artifact_contains_non_zapret_token(&policy);
        assert!(policy.zapret_hostlist.contains(&"youtube.com".to_string()));
        assert!(policy
            .zapret_hostlist
            .contains(&"googlevideo.com".to_string()));
        assert!(policy.zapret_hostlist.contains(&"youtu.be".to_string()));
        assert!(policy.zapret_hostlist.contains(&"discord.com".to_string()));
        assert!(policy.zapret_hostlist.contains(&"discord.gg".to_string()));
        assert!(policy
            .zapret_hostlist
            .contains(&"discordcdn.com".to_string()));
        assert!(!policy
            .zapret_hostlist
            .contains(&"GEOSITE,youtube".to_string()));
        assert!(!policy
            .zapret_hostlist
            .contains(&"GEOSITE,discord".to_string()));
        assert!(!policy.zapret_hostlist.contains(&"🤖 AI".to_string()));
        assert!(!policy
            .zapret_hostlist
            .contains(&"Выбор сервера".to_string()));
    }

    #[test]
    fn zapret_artifact_validation_is_token_aware() {
        validate_zapret_artifacts("zapret_hostlist", &["direct.example.com".to_string()]).unwrap();
        validate_zapret_artifacts("zapret_hostlist", &["reject.example.com".to_string()]).unwrap();
        assert!(validate_zapret_artifacts("zapret_hostlist", &["DIRECT".to_string()]).is_err());
        assert!(
            validate_zapret_artifacts("zapret_hostlist", &["GEOSITE,youtube".to_string()]).is_err()
        );
        validate_zapret_artifacts("zapret_ipset", &["203.0.113.0/24".to_string()]).unwrap();
        assert!(
            validate_zapret_artifacts("zapret_ipset", &["203.0.113.0/99".to_string()]).is_err()
        );
    }

    #[test]
    fn smart_generates_zapret_exclude_for_ai_and_social() {
        let policy = compile(AppRouteMode::Smart);
        assert_no_zapret_artifact_contains_non_zapret_token(&policy);
        assert!(policy
            .zapret_hostlist_exclude
            .contains(&"chatgpt.com".to_string()));
        assert!(policy
            .zapret_hostlist_exclude
            .contains(&"instagram.com".to_string()));
    }

    #[test]
    fn smart_ai_geosite_does_not_enter_zapret_exclude_as_geosite() {
        let policy = compile(AppRouteMode::Smart);
        assert_no_zapret_artifact_contains_non_zapret_token(&policy);
        assert!(!policy
            .zapret_hostlist_exclude
            .contains(&"GEOSITE,openai".to_string()));
        assert!(!policy
            .zapret_hostlist_exclude
            .contains(&"GEOSITE,anthropic".to_string()));
    }

    #[test]
    fn vpn_only_suppresses_provider_direct_external_rules() {
        let policy = compile(AppRouteMode::VpnOnly);
        assert!(!policy
            .mihomo_rules
            .contains(&"GEOSITE,yandex,DIRECT".to_string()));
        assert!(policy
            .suppressed_rules
            .iter()
            .any(|rule| rule.original_rule == "GEOSITE,yandex,DIRECT"));
    }

    #[test]
    fn vpn_only_suppresses_ru_yandex_vk_bank_direct_rules() {
        let policy = compile(AppRouteMode::VpnOnly);
        for rule in [
            "DOMAIN-KEYWORD,sberbank,DIRECT",
            "DOMAIN-SUFFIX,yandex.com,DIRECT",
            "GEOSITE,yandex,DIRECT",
            "DOMAIN-SUFFIX,vk.com,DIRECT",
            "DOMAIN-SUFFIX,ru,DIRECT",
            "GEOIP,ru,DIRECT,no-resolve",
        ] {
            assert!(
                !policy.mihomo_rules.iter().any(|actual| actual == rule),
                "{rule} leaked into VPN Only rules"
            );
            assert!(
                policy
                    .suppressed_rules
                    .iter()
                    .any(|suppressed| suppressed.original_rule == rule),
                "{rule} was not recorded as suppressed"
            );
        }
    }

    #[test]
    fn vpn_only_preserves_private_direct() {
        let mut rules = fixture_rules();
        rules.insert(0, "GEOIP,private,DIRECT,no-resolve".to_string());
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::VpnOnly,
            provider_rules: rules,
            proxy_groups: groups(),
            proxy_count: 2,
            routing: RoutingPolicySettings::default(),
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();
        assert!(policy
            .mihomo_rules
            .iter()
            .any(|rule| rule.contains("10.0.0.0/8,DIRECT")));
    }

    #[test]
    fn vpn_only_preserves_reject() {
        let policy = compile(AppRouteMode::VpnOnly);
        assert!(policy
            .mihomo_rules
            .contains(&"GEOSITE,category-ads-all,REJECT".to_string()));
    }

    #[test]
    fn provider_rule_parser_keeps_nested_payload_commas() {
        let logical = parse_provider_rule("AND,((DOMAIN,example.com),(NETWORK,UDP)),DIRECT")
            .expect("logical rule parses");
        assert_eq!(logical.target.kind, PolicyTargetKind::And);
        assert_eq!(logical.target.value, "((DOMAIN,example.com),(NETWORK,UDP))");
        assert_eq!(logical.action, "DIRECT");

        let sub_rule =
            parse_provider_rule("SUB-RULE,(NETWORK,tcp),sub-rule").expect("sub-rule parses");
        assert_eq!(sub_rule.target.kind, PolicyTargetKind::SubRule);
        assert_eq!(sub_rule.target.value, "(NETWORK,tcp)");
        assert_eq!(sub_rule.action, "sub-rule");
    }

    #[test]
    fn provider_rule_renderer_preserves_supported_mihomo_kinds() {
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::Smart,
            provider_rules: vec![
                "DST-PORT,443,PROXY".to_string(),
                "SRC-IP-CIDR,192.168.1.201/32,PROXY".to_string(),
                "NETWORK,UDP,PROXY".to_string(),
                "AND,((DOMAIN,example.com),(NETWORK,UDP)),PROXY".to_string(),
                "MATCH,PROXY".to_string(),
            ],
            proxy_groups: vec![ProxyGroupInfo {
                name: "PROXY".to_string(),
                group_type: Some("select".to_string()),
                proxies: vec!["Germany".to_string()],
            }],
            proxy_count: 1,
            routing: RoutingPolicySettings::default(),
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();

        for expected in [
            "DST-PORT,443,PROXY",
            "SRC-IP-CIDR,192.168.1.201/32,PROXY",
            "NETWORK,UDP,PROXY",
            "AND,((DOMAIN,example.com),(NETWORK,UDP)),PROXY",
        ] {
            assert!(
                policy.mihomo_rules.iter().any(|rule| rule == expected),
                "{expected} was not preserved"
            );
        }
    }

    #[test]
    fn cidr_overrides_normalize_ips_and_drop_invalid_values() {
        let mut routing = RoutingPolicySettings::default();
        routing.force_direct_cidrs = vec![
            "1.2.3.4".to_string(),
            "2001:db8::1".to_string(),
            "10.0.0.0/99".to_string(),
            "not-a-cidr".to_string(),
        ];
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::Smart,
            provider_rules: vec!["MATCH,PROXY".to_string()],
            proxy_groups: vec![ProxyGroupInfo {
                name: "PROXY".to_string(),
                group_type: Some("select".to_string()),
                proxies: vec!["Germany".to_string()],
            }],
            proxy_count: 1,
            routing,
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();

        assert!(policy
            .mihomo_rules
            .contains(&"IP-CIDR,1.2.3.4/32,DIRECT,no-resolve".to_string()));
        assert!(policy
            .mihomo_rules
            .contains(&"IP-CIDR6,2001:db8::1/128,DIRECT,no-resolve".to_string()));
        assert!(!policy
            .mihomo_rules
            .iter()
            .any(|rule| rule.contains("10.0.0.0/99") || rule.contains("not-a-cidr")));
    }

    #[test]
    fn vpn_only_uses_provider_match_group_as_default() {
        let policy = compile(AppRouteMode::VpnOnly);
        assert_eq!(
            policy.mihomo_rules.last().map(String::as_str),
            Some("MATCH,Выбор сервера")
        );
    }

    #[test]
    fn vpn_only_preserves_provider_youtube_discord_group_rules() {
        let policy = compile(AppRouteMode::VpnOnly);
        assert!(policy
            .mihomo_rules
            .contains(&"GEOSITE,youtube,📺 YouTube и Discord".to_string()));
        assert!(policy
            .mihomo_rules
            .contains(&"GEOSITE,discord,📺 YouTube и Discord".to_string()));
        assert!(!policy
            .mihomo_rules
            .contains(&"GEOSITE,youtube,DIRECT".to_string()));
        assert!(!policy
            .mihomo_rules
            .contains(&"GEOSITE,discord,DIRECT".to_string()));
        assert!(policy.zapret_hostlist.is_empty());
        assert!(policy.zapret_ipset.is_empty());
    }

    #[test]
    fn vpn_only_does_not_use_group_with_direct_member_as_default() {
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::VpnOnly,
            provider_rules: vec![
                "GEOSITE,telegram,Выбор сервера".to_string(),
                "MATCH,Выбор сервера".to_string(),
            ],
            proxy_groups: vec![ProxyGroupInfo {
                name: "Выбор сервера".to_string(),
                group_type: Some("select".to_string()),
                proxies: vec!["DIRECT".to_string(), "Germany".to_string()],
            }],
            proxy_count: 1,
            routing: RoutingPolicySettings::default(),
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();

        assert_eq!(policy.main_proxy_group, "__BADVPN_VPN_ONLY__");
        assert_eq!(
            policy.mihomo_rules.last().map(String::as_str),
            Some("MATCH,__BADVPN_VPN_ONLY__")
        );
        assert!(policy
            .mihomo_rules
            .contains(&"GEOSITE,telegram,__BADVPN_VPN_ONLY__".to_string()));
        let managed = policy
            .managed_proxy_groups
            .iter()
            .find(|group| group.name == "__BADVPN_VPN_ONLY__")
            .expect("managed no-DIRECT group is created");
        assert_eq!(managed.proxies, vec!["Germany".to_string()]);
        assert!(!managed
            .proxies
            .iter()
            .any(|proxy| proxy.eq_ignore_ascii_case("DIRECT")));
    }

    #[test]
    fn vpn_only_detects_nested_direct_in_proxy_group() {
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::VpnOnly,
            provider_rules: vec!["MATCH,Выбор сервера".to_string()],
            proxy_groups: vec![
                ProxyGroupInfo {
                    name: "Выбор сервера".to_string(),
                    group_type: Some("select".to_string()),
                    proxies: vec!["⚡ Авто".to_string(), "Germany".to_string()],
                },
                ProxyGroupInfo {
                    name: "⚡ Авто".to_string(),
                    group_type: Some("url-test".to_string()),
                    proxies: vec!["DIRECT".to_string(), "Turkey".to_string()],
                },
            ],
            proxy_count: 2,
            routing: RoutingPolicySettings::default(),
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();

        assert_eq!(policy.main_proxy_group, "__BADVPN_VPN_ONLY__");
        let managed = policy
            .managed_proxy_groups
            .iter()
            .find(|group| group.name == "__BADVPN_VPN_ONLY__")
            .expect("managed no-DIRECT group is created");
        assert_eq!(managed.proxies, vec!["Germany".to_string()]);
        assert!(!managed.proxies.contains(&"Turkey".to_string()));
    }

    #[test]
    fn vpn_only_managed_group_name_collision_uses_suffix() {
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::VpnOnly,
            provider_rules: vec!["MATCH,Выбор сервера".to_string()],
            proxy_groups: vec![
                ProxyGroupInfo {
                    name: "Выбор сервера".to_string(),
                    group_type: Some("select".to_string()),
                    proxies: vec!["DIRECT".to_string(), "Germany".to_string()],
                },
                ProxyGroupInfo {
                    name: "__BADVPN_VPN_ONLY__".to_string(),
                    group_type: Some("select".to_string()),
                    proxies: vec!["DIRECT".to_string()],
                },
            ],
            proxy_count: 1,
            routing: RoutingPolicySettings::default(),
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();

        assert_eq!(policy.main_proxy_group, "__BADVPN_VPN_ONLY_2__");
        assert_eq!(
            policy.mihomo_rules.last().map(String::as_str),
            Some("MATCH,__BADVPN_VPN_ONLY_2__")
        );
    }

    #[test]
    fn vpn_only_empty_managed_group_fails_cleanly() {
        let error = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::VpnOnly,
            provider_rules: vec!["MATCH,Выбор сервера".to_string()],
            proxy_groups: vec![ProxyGroupInfo {
                name: "Выбор сервера".to_string(),
                group_type: Some("select".to_string()),
                proxies: vec!["DIRECT".to_string()],
            }],
            proxy_count: 0,
            routing: RoutingPolicySettings::default(),
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap_err();

        assert!(error.contains("no non-DIRECT proxy nodes"));
    }

    #[test]
    fn broad_coverage_adds_runtime_diagnostics() {
        let mut routing = RoutingPolicySettings::default();
        routing.coverage = ZapretCoverage::Broad;
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::Smart,
            provider_rules: fixture_rules(),
            proxy_groups: groups(),
            proxy_count: 2,
            routing,
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();

        assert!(policy
            .diagnostics_messages
            .iter()
            .any(|message| message.contains("Broad coverage is experimental")));
        assert!(policy.diagnostics_messages.iter().any(|message| {
            message.contains("GEOSITE,openai")
                && message.contains("cannot be represented in zapret exclude")
        }));
    }

    #[test]
    fn process_only_zapret_rule_warns_and_is_not_expected_zapret() {
        let mut routing = RoutingPolicySettings::default();
        routing.force_zapret_processes = vec!["FortniteClient-Win64-Shipping.exe".to_string()];
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::Smart,
            provider_rules: fixture_rules(),
            proxy_groups: groups(),
            proxy_count: 2,
            routing,
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();

        assert!(policy
            .mihomo_rules
            .contains(&"PROCESS-NAME,FortniteClient-Win64-Shipping.exe,DIRECT".to_string()));
        assert!(!policy
            .zapret_hostlist
            .contains(&"FortniteClient-Win64-Shipping.exe".to_string()));
        assert!(!policy
            .zapret_ipset
            .contains(&"FortniteClient-Win64-Shipping.exe".to_string()));
        let expectation = policy
            .diagnostics_expectations
            .iter()
            .find(|expectation| {
                expectation.target == "PROCESS-NAME,FortniteClient-Win64-Shipping.exe"
            })
            .expect("process expectation is recorded");
        assert_eq!(expectation.expected_path, PolicyPath::ZapretDirect);
        assert!(!expectation.expected_zapret);
        assert!(policy.diagnostics_messages.iter().any(|message| {
            message.contains("Process-only DIRECT rule")
                && message.contains("Mihomo DIRECT only")
                && message.contains("FortniteClient-Win64-Shipping.exe")
        }));
    }

    #[test]
    fn local_force_vpn_overrides_smart_zapret() {
        let mut routing = RoutingPolicySettings::default();
        routing.force_vpn_domains = vec!["googlevideo.com".to_string()];
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::Smart,
            provider_rules: fixture_rules(),
            proxy_groups: groups(),
            proxy_count: 2,
            routing,
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();
        assert!(policy
            .mihomo_rules
            .contains(&"DOMAIN-SUFFIX,googlevideo.com,Выбор сервера".to_string()));
        assert!(!policy
            .mihomo_rules
            .contains(&"DOMAIN-SUFFIX,googlevideo.com,DIRECT".to_string()));
    }

    #[test]
    fn local_force_zapret_overrides_provider_proxy() {
        let mut routing = RoutingPolicySettings::default();
        routing.force_zapret_domains = vec!["perplexity.ai".to_string()];
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::Smart,
            provider_rules: fixture_rules(),
            proxy_groups: groups(),
            proxy_count: 2,
            routing,
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();
        assert!(policy
            .mihomo_rules
            .contains(&"DOMAIN-SUFFIX,perplexity.ai,DIRECT".to_string()));
    }

    #[test]
    fn local_force_zapret_overrides_ai_vpn_preset() {
        let mut routing = RoutingPolicySettings::default();
        routing.force_zapret_domains = vec!["chatgpt.com".to_string()];
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::Smart,
            provider_rules: fixture_rules(),
            proxy_groups: groups(),
            proxy_count: 2,
            routing,
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();

        assert!(policy
            .mihomo_rules
            .contains(&"DOMAIN-SUFFIX,chatgpt.com,DIRECT".to_string()));
        assert!(!policy
            .mihomo_rules
            .contains(&"DOMAIN-SUFFIX,chatgpt.com,🤖 AI".to_string()));
        assert!(policy.zapret_hostlist.contains(&"chatgpt.com".to_string()));
    }

    #[test]
    fn local_force_direct_overrides_provider_proxy() {
        let mut routing = RoutingPolicySettings::default();
        routing.force_direct_domains = vec!["perplexity.ai".to_string()];
        let policy = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::Smart,
            provider_rules: fixture_rules(),
            proxy_groups: groups(),
            proxy_count: 2,
            routing,
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap();
        assert!(policy
            .mihomo_rules
            .contains(&"DOMAIN-SUFFIX,perplexity.ai,DIRECT".to_string()));
    }

    // ---------------------------------------------------------------
    // A1: Policy invariant validation tests
    //
    // These tests call validate_invariants() directly on manually
    // constructed CompiledPolicy objects to prove each guard works
    // independently of compile_policy logic.
    // ---------------------------------------------------------------

    fn empty_policy(mode: AppRouteMode) -> CompiledPolicy {
        CompiledPolicy {
            mode,
            mihomo_rules: Vec::new(),
            zapret_hostlist: Vec::new(),
            zapret_hostlist_exclude: Vec::new(),
            zapret_ipset: Vec::new(),
            zapret_ipset_exclude: Vec::new(),
            dns_nameserver_policy: Vec::new(),
            diagnostics_expectations: Vec::new(),
            diagnostics_messages: Vec::new(),
            suppressed_rules: Vec::new(),
            main_proxy_group: "PROXY".to_string(),
            policy_rules: Vec::new(),
            should_create_canonical_proxy_group: false,
            managed_proxy_groups: Vec::new(),
        }
    }

    #[test]
    fn compiled_policy_validate_smart_tail() {
        // Smart policy with correct MATCH,DIRECT passes.
        let mut policy = empty_policy(AppRouteMode::Smart);
        policy.mihomo_rules = vec![
            "GEOSITE,private,DIRECT".to_string(),
            "MATCH,DIRECT".to_string(),
        ];
        assert!(policy.validate_invariants().is_ok());

        // Smart policy without MATCH,DIRECT fails.
        let mut bad_policy = empty_policy(AppRouteMode::Smart);
        bad_policy.mihomo_rules = vec!["GEOSITE,private,DIRECT".to_string()];
        let err = bad_policy.validate_invariants().unwrap_err();
        assert!(
            err.contains("Smart policy must end with MATCH,DIRECT"),
            "unexpected error: {err}"
        );

        // Smart policy ending with MATCH,PROXY fails.
        let mut wrong_tail = empty_policy(AppRouteMode::Smart);
        wrong_tail.mihomo_rules = vec![
            "GEOSITE,private,DIRECT".to_string(),
            "MATCH,PROXY".to_string(),
        ];
        let err = wrong_tail.validate_invariants().unwrap_err();
        assert!(
            err.contains("Smart policy must end with MATCH,DIRECT"),
            "unexpected error: {err}"
        );

        // Smart policy with empty rules fails.
        let empty = empty_policy(AppRouteMode::Smart);
        assert!(empty.validate_invariants().is_err());
    }

    #[test]
    fn compiled_policy_validate_vpn_only_tail() {
        // VPN Only with correct MATCH,PROXY passes.
        let mut policy = empty_policy(AppRouteMode::VpnOnly);
        policy.mihomo_rules = vec![
            "GEOSITE,private,DIRECT".to_string(),
            "MATCH,PROXY".to_string(),
        ];
        assert!(policy.validate_invariants().is_ok());

        // VPN Only without MATCH,<group> fails.
        let mut bad = empty_policy(AppRouteMode::VpnOnly);
        bad.mihomo_rules = vec!["GEOSITE,private,DIRECT".to_string()];
        let err = bad.validate_invariants().unwrap_err();
        assert!(
            err.contains("VPN Only policy must end with MATCH,PROXY"),
            "unexpected error: {err}"
        );

        // VPN Only ending with MATCH,DIRECT fails.
        let mut direct_tail = empty_policy(AppRouteMode::VpnOnly);
        direct_tail.mihomo_rules = vec![
            "GEOSITE,private,DIRECT".to_string(),
            "MATCH,DIRECT".to_string(),
        ];
        let err = direct_tail.validate_invariants().unwrap_err();
        assert!(err.contains("VPN Only"), "unexpected error: {err}");

        // VPN Only with main_proxy_group = "DIRECT" fails.
        let mut direct_group = empty_policy(AppRouteMode::VpnOnly);
        direct_group.main_proxy_group = "DIRECT".to_string();
        direct_group.mihomo_rules = vec!["MATCH,DIRECT".to_string()];
        let err = direct_group.validate_invariants().unwrap_err();
        assert!(
            err.contains("must not be DIRECT"),
            "unexpected error: {err}"
        );

        // VPN Only with empty rules fails.
        let empty = empty_policy(AppRouteMode::VpnOnly);
        assert!(empty.validate_invariants().is_err());
    }

    #[test]
    fn compiled_policy_vpn_only_rejects_match_direct_anywhere() {
        // VPN Only fails if MATCH,DIRECT appears anywhere (even not as tail).
        let mut policy = empty_policy(AppRouteMode::VpnOnly);
        policy.mihomo_rules = vec!["MATCH,DIRECT".to_string(), "MATCH,PROXY".to_string()];
        let err = policy.validate_invariants().unwrap_err();
        assert!(
            err.contains("must not contain MATCH,DIRECT"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn compiled_policy_rejects_zapret_artifact_geosite() {
        // zapret_hostlist with GEOSITE entry fails.
        let mut policy = empty_policy(AppRouteMode::Smart);
        policy.mihomo_rules = vec!["MATCH,DIRECT".to_string()];
        policy.zapret_hostlist = vec!["GEOSITE,youtube".to_string()];
        let err = policy.validate_invariants().unwrap_err();
        assert!(
            err.contains("non-zapret artifact value"),
            "unexpected error: {err}"
        );

        // zapret_hostlist with GEOIP entry fails.
        let mut policy2 = empty_policy(AppRouteMode::Smart);
        policy2.mihomo_rules = vec!["MATCH,DIRECT".to_string()];
        policy2.zapret_hostlist = vec!["GEOIP,ru".to_string()];
        let err = policy2.validate_invariants().unwrap_err();
        assert!(
            err.contains("non-zapret artifact value"),
            "unexpected error: {err}"
        );

        // zapret_hostlist with RULE-SET entry fails.
        let mut policy3 = empty_policy(AppRouteMode::Smart);
        policy3.mihomo_rules = vec!["MATCH,DIRECT".to_string()];
        policy3.zapret_hostlist = vec!["RULE-SET,openai".to_string()];
        let err = policy3.validate_invariants().unwrap_err();
        assert!(
            err.contains("non-zapret artifact value"),
            "unexpected error: {err}"
        );

        // zapret_hostlist with bare DIRECT fails.
        let mut policy4 = empty_policy(AppRouteMode::Smart);
        policy4.mihomo_rules = vec!["MATCH,DIRECT".to_string()];
        policy4.zapret_hostlist = vec!["DIRECT".to_string()];
        let err = policy4.validate_invariants().unwrap_err();
        assert!(
            err.contains("non-zapret artifact value"),
            "unexpected error: {err}"
        );

        // zapret_hostlist with bare REJECT fails.
        let mut policy5 = empty_policy(AppRouteMode::Smart);
        policy5.mihomo_rules = vec!["MATCH,DIRECT".to_string()];
        policy5.zapret_hostlist = vec!["REJECT".to_string()];
        let err = policy5.validate_invariants().unwrap_err();
        assert!(
            err.contains("non-zapret artifact value"),
            "unexpected error: {err}"
        );

        // zapret_hostlist with PROCESS-NAME fails.
        let mut policy6 = empty_policy(AppRouteMode::Smart);
        policy6.mihomo_rules = vec!["MATCH,DIRECT".to_string()];
        policy6.zapret_hostlist = vec!["PROCESS-NAME,game.exe".to_string()];
        let err = policy6.validate_invariants().unwrap_err();
        assert!(
            err.contains("non-zapret artifact value"),
            "unexpected error: {err}"
        );

        // zapret_hostlist with MATCH fails.
        let mut policy7 = empty_policy(AppRouteMode::Smart);
        policy7.mihomo_rules = vec!["MATCH,DIRECT".to_string()];
        policy7.zapret_hostlist = vec!["MATCH,DIRECT".to_string()];
        let err = policy7.validate_invariants().unwrap_err();
        assert!(
            err.contains("non-zapret artifact value"),
            "unexpected error: {err}"
        );

        // Valid zapret hostlist entries pass.
        let mut valid = empty_policy(AppRouteMode::Smart);
        valid.mihomo_rules = vec!["MATCH,DIRECT".to_string()];
        valid.zapret_hostlist = vec![
            "youtube.com".to_string(),
            "discord.gg".to_string(),
            "googlevideo.com".to_string(),
        ];
        assert!(valid.validate_invariants().is_ok());
    }

    #[test]
    fn compiled_policy_rejects_zapret_ipset_non_ip() {
        // zapret_ipset with domain-like value fails.
        let mut policy = empty_policy(AppRouteMode::Smart);
        policy.mihomo_rules = vec!["MATCH,DIRECT".to_string()];
        policy.zapret_ipset = vec!["youtube.com".to_string()];
        let err = policy.validate_invariants().unwrap_err();
        assert!(
            err.contains("invalid zapret value"),
            "unexpected error: {err}"
        );

        // Valid CIDR passes.
        let mut valid = empty_policy(AppRouteMode::Smart);
        valid.mihomo_rules = vec!["MATCH,DIRECT".to_string()];
        valid.zapret_ipset = vec!["149.154.160.0/20".to_string(), "2001:db8::/32".to_string()];
        assert!(valid.validate_invariants().is_ok());
    }

    #[test]
    fn compiled_policy_rejects_vpn_only_zapret_artifacts() {
        // VPN Only with zapret_hostlist fails.
        let mut policy = empty_policy(AppRouteMode::VpnOnly);
        policy.mihomo_rules = vec!["MATCH,PROXY".to_string()];
        policy.zapret_hostlist = vec!["youtube.com".to_string()];
        let err = policy.validate_invariants().unwrap_err();
        assert!(
            err.contains("must not emit zapret artifacts"),
            "unexpected error: {err}"
        );

        // VPN Only with zapret_ipset fails.
        let mut policy2 = empty_policy(AppRouteMode::VpnOnly);
        policy2.mihomo_rules = vec!["MATCH,PROXY".to_string()];
        policy2.zapret_ipset = vec!["149.154.160.0/20".to_string()];
        let err = policy2.validate_invariants().unwrap_err();
        assert!(
            err.contains("must not emit zapret artifacts"),
            "unexpected error: {err}"
        );

        // VPN Only with zapret_hostlist_exclude fails.
        let mut policy3 = empty_policy(AppRouteMode::VpnOnly);
        policy3.mihomo_rules = vec!["MATCH,PROXY".to_string()];
        policy3.zapret_hostlist_exclude = vec!["chatgpt.com".to_string()];
        let err = policy3.validate_invariants().unwrap_err();
        assert!(
            err.contains("must not emit zapret artifacts"),
            "unexpected error: {err}"
        );

        // VPN Only with zapret_ipset_exclude fails.
        let mut policy4 = empty_policy(AppRouteMode::VpnOnly);
        policy4.mihomo_rules = vec!["MATCH,PROXY".to_string()];
        policy4.zapret_ipset_exclude = vec!["1.2.3.4".to_string()];
        let err = policy4.validate_invariants().unwrap_err();
        assert!(
            err.contains("must not emit zapret artifacts"),
            "unexpected error: {err}"
        );

        // VPN Only with no zapret artifacts passes.
        let mut clean = empty_policy(AppRouteMode::VpnOnly);
        clean.mihomo_rules = vec!["MATCH,PROXY".to_string()];
        assert!(clean.validate_invariants().is_ok());
    }

    #[test]
    fn compiled_policy_vpn_only_rejects_provider_direct() {
        // VPN Only fails if a non-safety, non-user-override DIRECT rule is present.
        let mut policy = empty_policy(AppRouteMode::VpnOnly);
        policy.mihomo_rules = vec!["MATCH,PROXY".to_string()];
        policy.policy_rules = vec![PolicyRule {
            target: PolicyTarget {
                kind: PolicyTargetKind::GeoSite,
                value: "yandex".to_string(),
            },
            path: PolicyPath::DirectSafe,
            source: PolicySource::ProviderSubscription,
            priority: 500,
            original_rule: Some("GEOSITE,yandex,DIRECT".to_string()),
            tags: Vec::new(),
            options: Vec::new(),
        }];
        let err = policy.validate_invariants().unwrap_err();
        assert!(
            err.contains("kept provider DIRECT rule"),
            "unexpected error: {err}"
        );

        // Safety-sourced DIRECT rule passes.
        let mut safe = empty_policy(AppRouteMode::VpnOnly);
        safe.mihomo_rules = vec!["MATCH,PROXY".to_string()];
        safe.policy_rules = vec![PolicyRule {
            target: PolicyTarget {
                kind: PolicyTargetKind::Cidr,
                value: "10.0.0.0/8".to_string(),
            },
            path: PolicyPath::DirectSafe,
            source: PolicySource::Safety,
            priority: 1000,
            original_rule: None,
            tags: vec!["safety".to_string()],
            options: vec!["no-resolve".to_string()],
        }];
        assert!(safe.validate_invariants().is_ok());

        // User override DIRECT rule passes.
        let mut user = empty_policy(AppRouteMode::VpnOnly);
        user.mihomo_rules = vec!["MATCH,PROXY".to_string()];
        user.policy_rules = vec![PolicyRule {
            target: PolicyTarget {
                kind: PolicyTargetKind::DomainSuffix,
                value: "custom.local".to_string(),
            },
            path: PolicyPath::DirectSafe,
            source: PolicySource::LocalUserOverride,
            priority: 900,
            original_rule: None,
            tags: Vec::new(),
            options: Vec::new(),
        }];
        assert!(user.validate_invariants().is_ok());
    }

    #[test]
    fn compiled_policy_invalid_compile_returns_clear_error() {
        // compile_policy fails with clear error when no proxy groups or proxies exist.
        let err = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::Smart,
            provider_rules: vec!["MATCH,PROXY".to_string()],
            proxy_groups: Vec::new(),
            proxy_count: 0,
            routing: RoutingPolicySettings::default(),
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap_err();
        assert!(
            err.contains("no proxy groups or proxies"),
            "unexpected error: {err}"
        );

        // VPN Only with only-DIRECT proxy nodes fails cleanly.
        let err = compile_policy(PolicyCompileInput {
            mode: AppRouteMode::VpnOnly,
            provider_rules: vec!["MATCH,\u{0412}\u{044b}\u{0431}\u{043e}\u{0440} \u{0441}\u{0435}\u{0440}\u{0432}\u{0435}\u{0440}\u{0430}".to_string()],
            proxy_groups: vec![ProxyGroupInfo {
                name: "\u{0412}\u{044b}\u{0431}\u{043e}\u{0440} \u{0441}\u{0435}\u{0440}\u{0432}\u{0435}\u{0440}\u{0430}".to_string(),
                group_type: Some("select".to_string()),
                proxies: vec!["DIRECT".to_string()],
            }],
            proxy_count: 0,
            routing: RoutingPolicySettings::default(),
            runtime_facts: RuntimeFacts::default(),
        })
        .unwrap_err();
        assert!(
            err.contains("no non-DIRECT proxy nodes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn compiled_policy_validate_invariants_called_on_every_compile() {
        // Ensure a valid Smart compile passes invariants.
        let policy = compile(AppRouteMode::Smart);
        assert!(policy.validate_invariants().is_ok());

        // Ensure a valid VPN Only compile passes invariants.
        let policy = compile(AppRouteMode::VpnOnly);
        assert!(policy.validate_invariants().is_ok());
    }
}
