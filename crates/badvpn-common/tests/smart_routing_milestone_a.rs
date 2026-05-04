use badvpn_common::{
    generate_mihomo_config_from_subscription_with_options, CompiledPolicy, GeneratedMihomoConfig,
    MihomoConfigOptions, PolicyPath, RouteMode,
};

struct ProviderFixture {
    name: &'static str,
    body: &'static str,
    smart_error: Option<&'static str>,
    vpn_only_error: Option<&'static str>,
}

const PROVIDER_FIXTURES: &[ProviderFixture] = &[
    ProviderFixture {
        name: "provider_full_ru_split.yaml",
        body: include_str!("fixtures/provider_full_ru_split.yaml"),
        smart_error: None,
        vpn_only_error: None,
    },
    ProviderFixture {
        name: "provider_group_with_direct.yaml",
        body: include_str!("fixtures/provider_group_with_direct.yaml"),
        smart_error: None,
        vpn_only_error: None,
    },
    ProviderFixture {
        name: "provider_nested_group_with_direct.yaml",
        body: include_str!("fixtures/provider_nested_group_with_direct.yaml"),
        smart_error: None,
        vpn_only_error: None,
    },
    ProviderFixture {
        name: "provider_only_direct.yaml",
        body: include_str!("fixtures/provider_only_direct.yaml"),
        smart_error: Some("no non-DIRECT proxy nodes"),
        vpn_only_error: Some("no non-DIRECT proxy nodes"),
    },
    ProviderFixture {
        name: "provider_no_match.yaml",
        body: include_str!("fixtures/provider_no_match.yaml"),
        smart_error: None,
        vpn_only_error: None,
    },
    ProviderFixture {
        name: "provider_no_groups_with_proxies.yaml",
        body: include_str!("fixtures/provider_no_groups_with_proxies.yaml"),
        smart_error: None,
        vpn_only_error: None,
    },
    ProviderFixture {
        name: "provider_complex_rules.yaml",
        body: include_str!("fixtures/provider_complex_rules.yaml"),
        smart_error: None,
        vpn_only_error: None,
    },
    ProviderFixture {
        name: "provider_geosite_ai_youtube_discord.yaml",
        body: include_str!("fixtures/provider_geosite_ai_youtube_discord.yaml"),
        smart_error: None,
        vpn_only_error: None,
    },
];

fn options(route_mode: RouteMode) -> MihomoConfigOptions {
    MihomoConfigOptions {
        route_mode,
        ..MihomoConfigOptions::default()
    }
}

fn generate(body: &str, route_mode: RouteMode) -> Result<GeneratedMihomoConfig, String> {
    generate_mihomo_config_from_subscription_with_options(
        body,
        "fixture-secret",
        &options(route_mode),
    )
}

fn generate_ok(
    name: &str,
    body: &str,
    route_mode: RouteMode,
) -> Result<GeneratedMihomoConfig, String> {
    generate(body, route_mode).map_err(|error| format!("{name} {route_mode:?}: {error}"))
}

fn assert_yaml_reparses(name: &str, yaml: &str) -> Result<(), String> {
    serde_yaml::from_str::<serde_yaml::Value>(yaml)
        .map(|_| ())
        .map_err(|error| format!("{name} rendered YAML did not reparse: {error}"))
}

fn assert_rule(policy: &CompiledPolicy, expected: &str) {
    assert!(
        policy.mihomo_rules.iter().any(|rule| rule == expected),
        "missing rule {expected}; rules: {:#?}",
        policy.mihomo_rules
    );
}

fn assert_no_rule(policy: &CompiledPolicy, unexpected: &str) {
    assert!(
        !policy.mihomo_rules.iter().any(|rule| rule == unexpected),
        "unexpected rule {unexpected}; rules: {:#?}",
        policy.mihomo_rules
    );
}

#[test]
fn sanitized_provider_fixtures_have_no_credentials_or_real_node_tokens() {
    for fixture in PROVIDER_FIXTURES {
        let lowercase = fixture.body.to_ascii_lowercase();
        for forbidden in [
            "uuid",
            "password",
            "passwd",
            "token",
            "subscription",
            "alterid",
            "cipher",
            "private-key",
            "public-key",
            "://",
        ] {
            assert!(
                !lowercase.contains(forbidden),
                "{} contains forbidden sanitized-fixture token {forbidden}",
                fixture.name
            );
        }
    }
}

#[test]
fn provider_fixtures_compile_or_fail_expectedly_in_smart_and_vpn_only() -> Result<(), String> {
    for fixture in PROVIDER_FIXTURES {
        match generate(fixture.body, RouteMode::Smart) {
            Ok(smart) => {
                if let Some(expected_error) = fixture.smart_error {
                    return Err(format!(
                        "{} Smart unexpectedly compiled; expected {expected_error}",
                        fixture.name
                    ));
                }
                smart.policy.validate_invariants()?;
                assert_yaml_reparses(fixture.name, &smart.yaml)?;
                let expected_smart_final = format!("MATCH,{}", smart.policy.main_proxy_group);
                assert_eq!(
                    smart.policy.mihomo_rules.last().map(String::as_str),
                    Some(expected_smart_final.as_str()),
                    "{} Smart final rule",
                    fixture.name
                );
                assert_no_rule(&smart.policy, "MATCH,DIRECT");
            }
            Err(error) => {
                let Some(expected_error) = fixture.smart_error else {
                    return Err(format!("{} Smart failed: {error}", fixture.name));
                };
                assert!(
                    error.contains(expected_error),
                    "{} Smart error mismatch: {error}",
                    fixture.name
                );
            }
        }

        match generate(fixture.body, RouteMode::VpnOnly) {
            Ok(vpn_only) => {
                if let Some(expected_error) = fixture.vpn_only_error {
                    return Err(format!(
                        "{} VPN Only unexpectedly compiled; expected {expected_error}",
                        fixture.name
                    ));
                }
                vpn_only.policy.validate_invariants()?;
                assert_yaml_reparses(fixture.name, &vpn_only.yaml)?;
                assert!(
                    vpn_only.policy.zapret_hostlist.is_empty()
                        && vpn_only.policy.zapret_hostlist_exclude.is_empty()
                        && vpn_only.policy.zapret_ipset.is_empty()
                        && vpn_only.policy.zapret_ipset_exclude.is_empty(),
                    "{} VPN Only emitted zapret artifacts",
                    fixture.name
                );
                assert_no_rule(&vpn_only.policy, "MATCH,DIRECT");
            }
            Err(error) => {
                let Some(expected_error) = fixture.vpn_only_error else {
                    return Err(format!("{} VPN Only failed: {error}", fixture.name));
                };
                assert!(
                    error.contains(expected_error),
                    "{} VPN Only error mismatch: {error}",
                    fixture.name
                );
            }
        }
    }
    Ok(())
}

#[test]
fn smart_fixture_routes_youtube_discord_direct_and_keeps_other_provider_groups(
) -> Result<(), String> {
    let generated = generate_ok(
        "provider_full_ru_split.yaml",
        include_str!("fixtures/provider_full_ru_split.yaml"),
        RouteMode::Smart,
    )?;
    let policy = generated.policy;

    assert_rule(&policy, "GEOSITE,youtube,DIRECT");
    assert_rule(&policy, "DOMAIN-SUFFIX,googlevideo.com,DIRECT");
    assert_rule(&policy, "DOMAIN-SUFFIX,youtu.be,DIRECT");
    assert_rule(&policy, "GEOSITE,discord,DIRECT");
    for host in [
        "youtube.com",
        "googlevideo.com",
        "youtu.be",
        "discord.com",
        "discord.gg",
        "discordcdn.com",
    ] {
        assert!(
            policy.zapret_hostlist.iter().any(|value| value == host),
            "missing zapret host {host}: {:#?}",
            policy.zapret_hostlist
        );
    }
    assert!(policy
        .zapret_hostlist
        .iter()
        .all(|value| !value.contains(',')));

    assert_rule(&policy, "GEOSITE,openai,AI");
    assert_rule(&policy, "DOMAIN-SUFFIX,chatgpt.com,MainProxy");
    assert_rule(&policy, "GEOSITE,category-social,Social");
    assert_rule(&policy, "DOMAIN-SUFFIX,instagram.com,MainProxy");
    assert_rule(&policy, "GEOSITE,telegram,Telegram");
    assert_rule(&policy, "IP-CIDR,149.154.160.0/20,Telegram,no-resolve");
    assert_rule(&policy, "DOMAIN-KEYWORD,sberbank,DIRECT");
    assert_rule(&policy, "DOMAIN-SUFFIX,yandex.com,DIRECT");
    assert_rule(&policy, "GEOSITE,yandex,DIRECT");
    assert_rule(&policy, "DOMAIN-SUFFIX,vk.com,DIRECT");
    assert_rule(&policy, "DOMAIN-SUFFIX,ru,DIRECT");
    assert_rule(&policy, "GEOIP,ru,DIRECT,no-resolve");
    assert_eq!(
        policy.mihomo_rules.last().map(String::as_str),
        Some("MATCH,MainProxy")
    );
    assert!(policy.suppressed_rules.iter().any(|rule| {
        rule.original_rule == "GEOSITE,youtube,Streaming"
            && rule.chosen_rule == "GEOSITE,youtube,DIRECT"
            && !rule.reason.is_empty()
    }));
    assert!(policy
        .suppressed_rules
        .iter()
        .all(|rule| !rule.reason.trim().is_empty()));

    Ok(())
}

#[test]
fn vpn_only_fixture_suppresses_external_direct_and_keeps_proxy_paths() -> Result<(), String> {
    let generated = generate_ok(
        "provider_full_ru_split.yaml",
        include_str!("fixtures/provider_full_ru_split.yaml"),
        RouteMode::VpnOnly,
    )?;
    let policy = generated.policy;

    for external_direct in [
        "DOMAIN-KEYWORD,sberbank,DIRECT",
        "DOMAIN-SUFFIX,yandex.com,DIRECT",
        "GEOSITE,yandex,DIRECT",
        "DOMAIN-SUFFIX,vk.com,DIRECT",
        "DOMAIN-SUFFIX,ru,DIRECT",
        "GEOIP,ru,DIRECT,no-resolve",
    ] {
        assert_no_rule(&policy, external_direct);
        assert!(
            policy
                .suppressed_rules
                .iter()
                .any(|rule| rule.original_rule == external_direct && !rule.reason.is_empty()),
            "missing suppression for {external_direct}"
        );
    }

    assert_rule(&policy, "GEOSITE,category-ads-all,REJECT");
    assert_rule(&policy, "GEOSITE,private,DIRECT");
    assert_rule(&policy, "IP-CIDR,10.0.0.0/8,DIRECT,no-resolve");
    assert_rule(&policy, "GEOSITE,youtube,Streaming");
    assert_rule(&policy, "DOMAIN-SUFFIX,googlevideo.com,Streaming");
    assert_rule(&policy, "GEOSITE,discord,Streaming");
    assert_rule(&policy, "GEOSITE,openai,AI");
    assert_rule(&policy, "GEOSITE,telegram,Telegram");
    assert_eq!(
        policy.mihomo_rules.last().map(String::as_str),
        Some("MATCH,MainProxy")
    );
    assert_no_rule(&policy, "MATCH,DIRECT");
    assert!(policy.zapret_hostlist.is_empty());
    assert!(policy.zapret_hostlist_exclude.is_empty());
    assert!(policy.zapret_ipset.is_empty());
    assert!(policy.zapret_ipset_exclude.is_empty());

    Ok(())
}

#[test]
fn smart_manages_provider_groups_that_contain_direct() -> Result<(), String> {
    let direct_group = generate_ok(
        "provider_group_with_direct.yaml",
        include_str!("fixtures/provider_group_with_direct.yaml"),
        RouteMode::Smart,
    )?;
    assert_eq!(direct_group.policy.main_proxy_group, "__BADVPN_VPN_ONLY__");
    let managed = direct_group
        .policy
        .managed_proxy_groups
        .iter()
        .find(|group| group.name == "__BADVPN_VPN_ONLY__")
        .expect("managed no-DIRECT group");
    assert_eq!(managed.proxies, vec!["Node-DE", "Node-FR"]);
    assert!(managed
        .proxies
        .iter()
        .all(|proxy| !proxy.eq_ignore_ascii_case("DIRECT")));
    assert_rule(&direct_group.policy, "GEOSITE,telegram,__BADVPN_VPN_ONLY__");
    assert_no_rule(&direct_group.policy, "GEOSITE,telegram,MainProxy");
    assert_eq!(
        direct_group.policy.mihomo_rules.last().map(String::as_str),
        Some("MATCH,__BADVPN_VPN_ONLY__")
    );

    let nested_group = generate_ok(
        "provider_nested_group_with_direct.yaml",
        include_str!("fixtures/provider_nested_group_with_direct.yaml"),
        RouteMode::Smart,
    )?;
    assert_eq!(nested_group.policy.main_proxy_group, "__BADVPN_VPN_ONLY__");
    let managed = nested_group
        .policy
        .managed_proxy_groups
        .iter()
        .find(|group| group.name == "__BADVPN_VPN_ONLY__")
        .expect("managed no-DIRECT group");
    assert_eq!(managed.proxies, vec!["Node-US"]);
    assert!(!managed.proxies.contains(&"Node-DE".to_string()));
    assert_rule(&nested_group.policy, "GEOSITE,telegram,__BADVPN_VPN_ONLY__");
    assert_no_rule(&nested_group.policy, "GEOSITE,telegram,MainProxy");

    Ok(())
}

#[test]
fn vpn_only_manages_groups_that_contain_direct() -> Result<(), String> {
    let direct_group = generate_ok(
        "provider_group_with_direct.yaml",
        include_str!("fixtures/provider_group_with_direct.yaml"),
        RouteMode::VpnOnly,
    )?;
    assert_eq!(direct_group.policy.main_proxy_group, "__BADVPN_VPN_ONLY__");
    let managed = direct_group
        .policy
        .managed_proxy_groups
        .iter()
        .find(|group| group.name == "__BADVPN_VPN_ONLY__")
        .expect("managed no-DIRECT group");
    assert_eq!(managed.proxies, vec!["Node-DE", "Node-FR"]);
    assert!(managed
        .proxies
        .iter()
        .all(|proxy| !proxy.eq_ignore_ascii_case("DIRECT")));
    assert_rule(&direct_group.policy, "GEOSITE,telegram,__BADVPN_VPN_ONLY__");
    assert_eq!(
        direct_group.policy.mihomo_rules.last().map(String::as_str),
        Some("MATCH,__BADVPN_VPN_ONLY__")
    );

    let nested_group = generate_ok(
        "provider_nested_group_with_direct.yaml",
        include_str!("fixtures/provider_nested_group_with_direct.yaml"),
        RouteMode::VpnOnly,
    )?;
    assert_eq!(nested_group.policy.main_proxy_group, "__BADVPN_VPN_ONLY__");
    let managed = nested_group
        .policy
        .managed_proxy_groups
        .iter()
        .find(|group| group.name == "__BADVPN_VPN_ONLY__")
        .expect("managed no-DIRECT group");
    assert_eq!(managed.proxies, vec!["Node-US"]);
    assert!(!managed.proxies.contains(&"Node-DE".to_string()));
    assert_rule(&nested_group.policy, "GEOSITE,telegram,__BADVPN_VPN_ONLY__");

    Ok(())
}

#[test]
fn provider_only_direct_fails_cleanly_in_vpn_only() {
    let error = generate(
        include_str!("fixtures/provider_only_direct.yaml"),
        RouteMode::VpnOnly,
    )
    .unwrap_err();
    assert!(
        error.contains("no non-DIRECT proxy nodes"),
        "unexpected error: {error}"
    );
}

#[test]
fn no_groups_fixture_gets_canonical_proxy_group() -> Result<(), String> {
    let smart = generate_ok(
        "provider_no_groups_with_proxies.yaml",
        include_str!("fixtures/provider_no_groups_with_proxies.yaml"),
        RouteMode::Smart,
    )?;
    assert!(smart.policy.should_create_canonical_proxy_group);
    assert_yaml_reparses("provider_no_groups_with_proxies.yaml", &smart.yaml)?;
    assert!(smart.yaml.contains("proxy-groups:"));
    assert_eq!(
        smart.policy.mihomo_rules.last().map(String::as_str),
        Some("MATCH,PROXY")
    );

    let vpn_only = generate_ok(
        "provider_no_groups_with_proxies.yaml",
        include_str!("fixtures/provider_no_groups_with_proxies.yaml"),
        RouteMode::VpnOnly,
    )?;
    assert!(vpn_only.policy.should_create_canonical_proxy_group);
    assert_eq!(
        vpn_only.policy.mihomo_rules.last().map(String::as_str),
        Some("MATCH,PROXY")
    );

    Ok(())
}

#[test]
fn no_match_fixture_gets_mode_specific_final_rule() -> Result<(), String> {
    let smart = generate_ok(
        "provider_no_match.yaml",
        include_str!("fixtures/provider_no_match.yaml"),
        RouteMode::Smart,
    )?;
    assert_eq!(
        smart.policy.mihomo_rules.last().map(String::as_str),
        Some("MATCH,MainProxy")
    );

    let vpn_only = generate_ok(
        "provider_no_match.yaml",
        include_str!("fixtures/provider_no_match.yaml"),
        RouteMode::VpnOnly,
    )?;
    assert_eq!(
        vpn_only.policy.mihomo_rules.last().map(String::as_str),
        Some("MATCH,MainProxy")
    );

    Ok(())
}

#[test]
fn complex_fixture_preserves_supported_provider_rule_kinds() -> Result<(), String> {
    let smart = generate_ok(
        "provider_complex_rules.yaml",
        include_str!("fixtures/provider_complex_rules.yaml"),
        RouteMode::Smart,
    )?;
    for expected in [
        "DOMAIN,exact.example.test,MainProxy",
        "DOMAIN-SUFFIX,cdn.example.test,MainProxy",
        "DST-PORT,443,MainProxy",
        "NETWORK,UDP,MainProxy",
        "AND,((DOMAIN,voice.example.test),(NETWORK,UDP)),MainProxy",
        "SRC-IP-CIDR,192.0.2.10/32,MainProxy",
        "DOMAIN-SUFFIX,local-direct.example,DIRECT",
        "GEOSITE,category-ads-all,REJECT",
    ] {
        assert_rule(&smart.policy, expected);
    }
    assert_yaml_reparses("provider_complex_rules.yaml", &smart.yaml)?;

    let vpn_only = generate_ok(
        "provider_complex_rules.yaml",
        include_str!("fixtures/provider_complex_rules.yaml"),
        RouteMode::VpnOnly,
    )?;
    assert_no_rule(
        &vpn_only.policy,
        "DOMAIN-SUFFIX,local-direct.example,DIRECT",
    );
    assert!(vpn_only.policy.suppressed_rules.iter().any(|rule| {
        rule.original_rule == "DOMAIN-SUFFIX,local-direct.example,DIRECT" && !rule.reason.is_empty()
    }));

    Ok(())
}

#[test]
fn geosite_fixture_keeps_ai_proxy_and_directs_youtube_discord() -> Result<(), String> {
    let smart = generate_ok(
        "provider_geosite_ai_youtube_discord.yaml",
        include_str!("fixtures/provider_geosite_ai_youtube_discord.yaml"),
        RouteMode::Smart,
    )?;
    assert_rule(&smart.policy, "GEOSITE,openai,AI");
    assert_rule(&smart.policy, "GEOSITE,anthropic,AI");
    assert_rule(&smart.policy, "GEOSITE,youtube,DIRECT");
    assert_rule(&smart.policy, "DOMAIN-SUFFIX,googlevideo.com,DIRECT");
    assert_rule(&smart.policy, "GEOSITE,discord,DIRECT");
    assert!(smart
        .policy
        .zapret_hostlist
        .iter()
        .all(|value| !value.to_ascii_uppercase().starts_with("GEOSITE,")));
    assert!(smart
        .policy
        .policy_rules
        .iter()
        .any(|rule| rule.path == PolicyPath::ZapretDirect));

    Ok(())
}
