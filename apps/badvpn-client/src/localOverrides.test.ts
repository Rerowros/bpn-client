import { describe, expect, it } from "vitest";

import {
  buildLocalOverridePatch,
  buildLocalOverrideRule,
  localOverrideExists,
  normalizeLocalOverrideValue,
  previewLocalOverride,
} from "./localOverrides";
import type { AppSettings } from "./services/agentClient";

function routingPolicy(overrides: Partial<AppSettings["routing_policy"]> = {}): AppSettings["routing_policy"] {
  return {
    local_overrides_enabled: true,
    local_overrides: { version: 1, rules: [] },
    force_vpn_domains: [],
    force_vpn_cidrs: [],
    force_zapret_domains: [],
    force_zapret_cidrs: [],
    force_zapret_processes: [],
    force_zapret_tcp_ports: [],
    force_zapret_udp_ports: [],
    force_direct_domains: [],
    force_direct_cidrs: [],
    force_direct_processes: [],
    smart_presets: {
      youtube_discord_zapret: true,
      games_zapret: true,
      ai_vpn: true,
      social_vpn: true,
      telegram_vpn_from_provider: true,
    },
    coverage: "curated",
    ...overrides,
  };
}

describe("local override normalization", () => {
  it("normalizes URLs and wildcard domains to a domain suffix", () => {
    expect(normalizeLocalOverrideValue("domain", " https://*.Example.COM/path?q=1 ")).toBe("example.com");
    expect(previewLocalOverride("zapret", "domain", "https://discord.com/channels").preview).toBe(
      "DOMAIN-SUFFIX,discord.com -> DIRECT + zapret",
    );
  });

  it("normalizes executable paths to process names while preserving source path in rules", () => {
    const rule = buildLocalOverrideRule("direct", "process", '"C:\\Games\\Repo\\REPO.exe"');

    expect(rule.target_kind).toBe("app");
    expect(rule.value).toBe("REPO.exe");
    expect(rule.process_name).toBe("REPO.exe");
    expect(rule.executable_path).toBe("C:\\Games\\Repo\\REPO.exe");
  });

  it("detects duplicates across legacy lists and structured local override rules", () => {
    const policy = routingPolicy({
      force_zapret_domains: ["youtube.com"],
      local_overrides: {
        version: 1,
        rules: [buildLocalOverrideRule("direct", "process", "Game.exe", "Game.exe")],
      },
    });

    expect(localOverrideExists(policy, "zapret", "domain", "HTTPS://YOUTUBE.COM/watch")).toBe(true);
    expect(localOverrideExists(policy, "direct", "process", "C:\\Games\\Game.exe")).toBe(true);
    expect(localOverrideExists(policy, "vpn", "domain", "example.com")).toBe(false);
  });

  it("builds deduplicated patches for zapret port overrides", () => {
    const policy = routingPolicy({ force_zapret_udp_ports: ["443"] });

    const patch = buildLocalOverridePatch(policy, "zapret", "udp_port", "443");

    expect(patch?.force_zapret_udp_ports).toEqual(["443"]);
    expect(patch?.local_overrides?.rules).toHaveLength(1);
    expect(patch?.local_overrides?.rules[0]?.target_kind).toBe("udp_port");
  });
});
