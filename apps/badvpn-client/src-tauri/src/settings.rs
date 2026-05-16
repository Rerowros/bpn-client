use badvpn_common::{MihomoConfigOptions, RouteMode, RoutingPolicySettings};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AppSettings {
    pub core: CoreSettings,
    pub tun: TunSettings,
    pub dns: DnsSettings,
    pub sniffer: SnifferSettings,
    pub zapret: ZapretSettings,
    pub routing_policy: RoutingPolicySettings,
    pub updates: UpdateSettings,
    pub diagnostics: DiagnosticsSettings,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            core: CoreSettings::default(),
            tun: TunSettings::default(),
            dns: DnsSettings::default(),
            sniffer: SnifferSettings::default(),
            zapret: ZapretSettings::default(),
            routing_policy: RoutingPolicySettings::default(),
            updates: UpdateSettings::default(),
            diagnostics: DiagnosticsSettings::default(),
        }
    }
}

impl AppSettings {
    pub fn migrate_legacy_local_overrides(&mut self) {
        self.routing_policy.migrate_legacy_local_overrides();
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.core.route_mode == RouteMode::Smart && !self.zapret.enabled {
            return Err("Smart requires zapret; disable zapret by using VPN Only.".into());
        }
        validate_port("mixed proxy port", self.core.mixed_port)?;
        validate_port("controller port", self.core.controller_port)?;
        if self.tun.enabled {
            if !(1280..=9000).contains(&self.tun.mtu) {
                return Err("TUN MTU must be between 1280 and 9000.".into());
            }
            if self.tun.dns_hijack.is_empty() {
                return Err(
                    "At least one DNS hijack target is required when TUN is enabled.".into(),
                );
            }
        }
        if self.dns.mode == DnsMode::FakeIp && self.dns.fake_ip_range.trim().is_empty() {
            return Err("Fake-IP range is required.".into());
        }
        if self.core.mixed_port == self.core.controller_port {
            return Err("Mixed proxy port and controller port must be different.".into());
        }
        if self.core.mixed_port == 1053 || self.core.controller_port == 1053 {
            return Err(
                "Ports 7890/9090 can be changed, but 1053 is reserved for BadVpn DNS.".into(),
            );
        }
        Ok(())
    }

    pub fn effective_route_mode(&self) -> RouteMode {
        if self.core.route_mode == RouteMode::Smart && self.zapret.enabled {
            RouteMode::Smart
        } else {
            RouteMode::VpnOnly
        }
    }

    pub fn mihomo_options(&self) -> MihomoConfigOptions {
        MihomoConfigOptions {
            route_mode: self.effective_route_mode(),
            log_level: self.core.log_level.as_mihomo_str().to_string(),
            mixed_port: self.core.mixed_port,
            controller_port: self.core.controller_port,
            allow_lan: self.core.allow_lan,
            ipv6: self.core.ipv6,
            tun_enabled: self.tun.enabled,
            tun_stack: self.tun.stack.as_mihomo_str().to_string(),
            tun_strict_route: self.tun.strict_route,
            tun_auto_route: self.tun.auto_route,
            tun_auto_detect_interface: self.tun.auto_detect_interface,
            tun_mtu: self.tun.mtu,
            tun_dns_hijack: self.tun.dns_hijack.clone(),
            tun_excluded_routes: self.tun.excluded_routes.clone(),
            dns_mode: self.dns.mode.as_mihomo_str().to_string(),
            dns_nameservers: self.dns.preset.nameservers(),
            dns_fake_ip_range: self.dns.fake_ip_range.clone(),
            dns_fake_ip_filter: self.dns.fake_ip_filter.clone(),
            dns_nameserver_policy: self.dns.nameserver_policy_map(),
            sniffer_enabled: self.sniffer.enabled,
            sniffer_protocols: self.sniffer.enabled_protocols(),
            sniffer_force_domains: self.sniffer.force_domains.clone(),
            sniffer_skip_domains: self.sniffer.skip_domains.clone(),
            sniffer_skip_src_cidrs: self.sniffer.skip_src_cidrs.clone(),
            sniffer_skip_dst_cidrs: self.sniffer.skip_dst_cidrs.clone(),
            zapret_direct_domains: Vec::new(),
            zapret_direct_cidrs: Vec::new(),
            zapret_direct_processes: Vec::new(),
            zapret_direct_tcp_ports: Vec::new(),
            zapret_direct_udp_ports: Vec::new(),
            selected_proxies: std::collections::BTreeMap::new(),
            routing_policy: self.routing_policy.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CoreSettings {
    pub route_mode: RouteMode,
    pub log_level: LogLevel,
    pub mixed_port: u16,
    pub controller_port: u16,
    pub allow_lan: bool,
    pub ipv6: bool,
}

impl Default for CoreSettings {
    fn default() -> Self {
        Self {
            route_mode: RouteMode::Smart,
            log_level: LogLevel::Info,
            mixed_port: 7890,
            controller_port: 9090,
            allow_lan: false,
            ipv6: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogLevel {
    Error,
    Warning,
    Info,
    Debug,
}

impl Default for LogLevel {
    fn default() -> Self {
        Self::Info
    }
}

impl LogLevel {
    fn as_mihomo_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warning => "warning",
            Self::Info => "info",
            Self::Debug => "debug",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TunSettings {
    pub enabled: bool,
    pub stack: TunStack,
    pub strict_route: bool,
    pub auto_route: bool,
    pub auto_detect_interface: bool,
    pub mtu: u16,
    pub dns_hijack: Vec<String>,
    pub excluded_routes: Vec<String>,
}

impl Default for TunSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            stack: TunStack::Mixed,
            strict_route: true,
            auto_route: true,
            auto_detect_interface: true,
            mtu: 1500,
            dns_hijack: vec!["any:53".to_string(), "tcp://any:53".to_string()],
            excluded_routes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunStack {
    Mixed,
    Gvisor,
    System,
}

impl Default for TunStack {
    fn default() -> Self {
        Self::Mixed
    }
}

impl TunStack {
    fn as_mihomo_str(self) -> &'static str {
        match self {
            Self::Mixed => "mixed",
            Self::Gvisor => "gvisor",
            Self::System => "system",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsSettings {
    pub mode: DnsMode,
    pub preset: DnsPreset,
    pub fake_ip_range: String,
    pub fake_ip_filter: Vec<String>,
    pub nameserver_policy: Vec<NameServerPolicySetting>,
}

impl Default for DnsSettings {
    fn default() -> Self {
        Self {
            mode: DnsMode::FakeIp,
            preset: DnsPreset::CloudflareGoogle,
            fake_ip_range: "198.18.0.1/16".to_string(),
            fake_ip_filter: vec![
                "+.lan".to_string(),
                "+.local".to_string(),
                "localhost.ptlogin2.qq.com".to_string(),
            ],
            nameserver_policy: Vec::new(),
        }
    }
}

impl DnsSettings {
    fn nameserver_policy_map(&self) -> BTreeMap<String, Vec<String>> {
        self.nameserver_policy
            .iter()
            .filter(|rule| !rule.pattern.trim().is_empty() && !rule.nameservers.is_empty())
            .map(|rule| (rule.pattern.trim().to_string(), rule.nameservers.clone()))
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NameServerPolicySetting {
    pub pattern: String,
    pub nameservers: Vec<String>,
}

impl Default for NameServerPolicySetting {
    fn default() -> Self {
        Self {
            pattern: String::new(),
            nameservers: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SnifferSettings {
    pub enabled: bool,
    pub http: bool,
    pub tls: bool,
    pub quic: bool,
    pub force_domains: Vec<String>,
    pub skip_domains: Vec<String>,
    pub skip_src_cidrs: Vec<String>,
    pub skip_dst_cidrs: Vec<String>,
}

impl Default for SnifferSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            http: true,
            tls: true,
            quic: true,
            force_domains: Vec::new(),
            skip_domains: Vec::new(),
            skip_src_cidrs: Vec::new(),
            skip_dst_cidrs: Vec::new(),
        }
    }
}

impl SnifferSettings {
    fn enabled_protocols(&self) -> Vec<String> {
        let mut protocols = Vec::new();
        if self.http {
            protocols.push("HTTP".to_string());
        }
        if self.tls {
            protocols.push("TLS".to_string());
        }
        if self.quic {
            protocols.push("QUIC".to_string());
        }
        protocols
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DnsMode {
    FakeIp,
    RedirHost,
}

impl Default for DnsMode {
    fn default() -> Self {
        Self::FakeIp
    }
}

impl DnsMode {
    fn as_mihomo_str(self) -> &'static str {
        match self {
            Self::FakeIp => "fake-ip",
            Self::RedirHost => "redir-host",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsPreset {
    CloudflareGoogle,
    Cloudflare,
    Google,
    Quad9,
}

impl Default for DnsPreset {
    fn default() -> Self {
        Self::CloudflareGoogle
    }
}

impl DnsPreset {
    fn nameservers(self) -> Vec<String> {
        match self {
            Self::CloudflareGoogle => vec![
                "https://1.1.1.1/dns-query".to_string(),
                "https://8.8.8.8/dns-query".to_string(),
            ],
            Self::Cloudflare => vec![
                "https://1.1.1.1/dns-query".to_string(),
                "https://1.0.0.1/dns-query".to_string(),
            ],
            Self::Google => vec![
                "https://8.8.8.8/dns-query".to_string(),
                "https://8.8.4.4/dns-query".to_string(),
            ],
            Self::Quad9 => vec![
                "https://9.9.9.9/dns-query".to_string(),
                "https://149.112.112.112/dns-query".to_string(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ZapretSettings {
    pub enabled: bool,
    pub run_mode: ZapretRunMode,
    pub strategy: ZapretStrategy,
    pub game_filter: ZapretGameFilter,
    pub game_bypass_mode: GameBypassMode,
    pub game_filter_mode: GameFilterMode,
    pub learned_game_profiles: Vec<GameProfileSettings>,
    pub ipset_filter: ZapretIpSetFilter,
    pub auto_profile_fallback: bool,
    pub fallback_to_vpn_on_failed_probe: bool,
}

impl Default for ZapretSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            run_mode: ZapretRunMode::Service,
            strategy: ZapretStrategy::Auto,
            game_filter: ZapretGameFilter::Off,
            game_bypass_mode: GameBypassMode::Auto,
            game_filter_mode: GameFilterMode::UdpFirst,
            learned_game_profiles: Vec::new(),
            ipset_filter: ZapretIpSetFilter::None,
            auto_profile_fallback: true,
            fallback_to_vpn_on_failed_probe: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZapretRunMode {
    Service,
    Process,
}

impl Default for ZapretRunMode {
    fn default() -> Self {
        Self::Service
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZapretStrategy {
    Auto,
    General,
    Alt,
    Alt2,
    Alt3,
    Alt4,
    Alt5,
    Alt6,
    Alt7,
    Alt8,
    Alt9,
    Alt10,
    Alt11,
    FakeTlsAuto,
    FakeTlsAutoAlt,
    FakeTlsAutoAlt2,
    FakeTlsAutoAlt3,
    SimpleFake,
    SimpleFakeAlt,
    SimpleFakeAlt2,
}

impl Default for ZapretStrategy {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZapretGameFilter {
    Off,
    TcpUdp,
    Tcp,
    Udp,
}

impl Default for ZapretGameFilter {
    fn default() -> Self {
        Self::Off
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GameBypassMode {
    Off,
    Auto,
    Manual,
}

impl Default for GameBypassMode {
    fn default() -> Self {
        Self::Auto
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GameFilterMode {
    UdpFirst,
    TcpUdp,
    Aggressive,
}

impl Default for GameFilterMode {
    fn default() -> Self {
        Self::UdpFirst
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GameProfileSettings {
    pub id: String,
    pub title: String,
    pub process_names: Vec<String>,
    pub domains: Vec<String>,
    pub cidrs: Vec<String>,
    pub tcp_ports: Vec<String>,
    pub udp_ports: Vec<String>,
    pub filter_mode: GameFilterMode,
    pub risk_level: String,
    pub detected: bool,
    pub enabled: bool,
}

impl Default for GameProfileSettings {
    fn default() -> Self {
        Self {
            id: String::new(),
            title: String::new(),
            process_names: Vec::new(),
            domains: Vec::new(),
            cidrs: Vec::new(),
            tcp_ports: Vec::new(),
            udp_ports: Vec::new(),
            filter_mode: GameFilterMode::UdpFirst,
            risk_level: "normal".to_string(),
            detected: false,
            enabled: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZapretIpSetFilter {
    None,
    Any,
    Loaded,
}

impl Default for ZapretIpSetFilter {
    fn default() -> Self {
        Self::None
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UpdateSettings {
    pub auto_flowseal_list_refresh: bool,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            auto_flowseal_list_refresh: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DiagnosticsSettings {
    pub runtime_checks_after_connect: bool,
    pub discord_youtube_probes: bool,
}

impl Default for DiagnosticsSettings {
    fn default() -> Self {
        Self {
            runtime_checks_after_connect: true,
            discord_youtube_probes: true,
        }
    }
}

pub fn read_settings_from_path(path: &Path) -> AppSettings {
    let Ok(content) = fs::read_to_string(path) else {
        return AppSettings::default();
    };
    let mut settings = serde_json::from_str::<AppSettings>(&content).unwrap_or_default();
    settings.migrate_legacy_local_overrides();
    if settings.validate().is_ok() {
        settings
    } else {
        AppSettings::default()
    }
}

pub fn write_settings_to_path(path: &Path, settings: &AppSettings) -> Result<(), String> {
    let mut settings = settings.clone();
    settings.migrate_legacy_local_overrides();
    settings.validate()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create settings directory: {error}"))?;
    }
    let content = serde_json::to_string_pretty(&settings)
        .map_err(|error| format!("Failed to serialize settings: {error}"))?;
    fs::write(path, content).map_err(|error| format!("Failed to write settings: {error}"))
}

pub fn settings_require_restart(previous: &AppSettings, next: &AppSettings) -> bool {
    previous.core != next.core
        || previous.tun != next.tun
        || previous.dns != next.dns
        || previous.sniffer != next.sniffer
        || previous.zapret != next.zapret
        || previous.routing_policy != next.routing_policy
}

fn validate_port(label: &str, port: u16) -> Result<(), String> {
    if port == 0 {
        Err(format!("{label} must be between 1 and 65535."))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_when_settings_file_is_absent() {
        let path = std::env::temp_dir().join("badvpn-missing-settings-test.json");
        let _ = fs::remove_file(&path);
        assert_eq!(read_settings_from_path(&path), AppSettings::default());
    }

    #[test]
    fn corrupt_settings_file_falls_back_to_default() {
        let path = std::env::temp_dir().join("badvpn-corrupt-settings-test.json");
        fs::write(&path, "{not-json").unwrap();
        assert_eq!(read_settings_from_path(&path), AppSettings::default());
        let _ = fs::remove_file(path);
    }

    #[test]
    fn port_validation_rejects_duplicates_and_reserved_dns_port() {
        let mut settings = AppSettings::default();
        settings.core.controller_port = settings.core.mixed_port;
        assert!(settings.validate().is_err());

        settings = AppSettings::default();
        settings.core.mixed_port = 1053;
        assert!(settings.validate().is_err());
    }

    #[test]
    fn route_mode_deserializes_old_values() {
        for value in ["smart_hybrid", "zapret_first"] {
            let settings = serde_json::from_str::<AppSettings>(&format!(
                r#"{{"core":{{"route_mode":"{value}"}}}}"#
            ))
            .unwrap();
            assert_eq!(settings.core.route_mode, RouteMode::Smart);
        }

        for value in ["vpn_all", "dpi_only", "manual", "unknown"] {
            let settings = serde_json::from_str::<AppSettings>(&format!(
                r#"{{"core":{{"route_mode":"{value}"}}}}"#
            ))
            .unwrap();
            assert_eq!(settings.core.route_mode, RouteMode::VpnOnly);
        }
    }

    #[test]
    fn old_routing_policy_defaults_local_overrides_enabled() {
        let settings = serde_json::from_str::<AppSettings>(
            r#"{
                "routing_policy": {
                    "force_direct_processes": ["Game.exe"],
                    "force_zapret_tcp_ports": ["443"]
                }
            }"#,
        )
        .unwrap();

        assert!(settings.routing_policy.local_overrides_enabled);
        let mut migrated = settings.clone();
        migrated.migrate_legacy_local_overrides();
        assert_eq!(migrated.routing_policy.local_overrides.version, 1);
        assert_eq!(migrated.routing_policy.local_overrides.rules.len(), 2);
        assert_eq!(
            settings.routing_policy.force_direct_processes,
            vec!["Game.exe".to_string()]
        );
        assert_eq!(
            settings.routing_policy.force_zapret_tcp_ports,
            vec!["443".to_string()]
        );
    }

    #[test]
    fn smart_requires_zapret_enabled_and_vpn_only_allows_disabled_zapret() {
        let mut settings = AppSettings::default();
        settings.core.route_mode = RouteMode::Smart;
        settings.zapret.enabled = false;
        assert!(settings.validate().is_err());
        assert_eq!(settings.effective_route_mode(), RouteMode::VpnOnly);

        settings.core.route_mode = RouteMode::VpnOnly;
        assert!(settings.validate().is_ok());
        assert_eq!(settings.effective_route_mode(), RouteMode::VpnOnly);
    }

    #[test]
    fn tun_and_fake_ip_validation_follow_enabled_modes() {
        let mut settings = AppSettings::default();
        settings.tun.enabled = false;
        settings.tun.mtu = 1000;
        settings.tun.dns_hijack.clear();
        settings.dns.mode = DnsMode::RedirHost;
        settings.dns.fake_ip_range.clear();
        assert!(settings.validate().is_ok());

        settings.tun.enabled = true;
        assert!(settings.validate().is_err());

        settings = AppSettings::default();
        settings.dns.fake_ip_range.clear();
        assert!(settings.validate().is_err());
    }
}
