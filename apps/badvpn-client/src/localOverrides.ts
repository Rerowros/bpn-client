import type { AppSettings, LocalOverrideRule } from "./services/agentClient";

export type LocalOverrideRoute = "vpn" | "zapret" | "direct";
export type LocalOverrideTargetKind = "domain" | "cidr" | "process" | "tcp_port" | "udp_port";

export function localOverrideTargetKindsForRoute(route: LocalOverrideRoute): LocalOverrideTargetKind[] {
  if (route === "vpn") {
    return ["domain", "cidr"];
  }
  if (route === "zapret") {
    return ["domain", "cidr", "process", "tcp_port", "udp_port"];
  }
  return ["domain", "cidr", "process"];
}

export function formatLocalOverrideKind(kind: LocalOverrideTargetKind) {
  switch (kind) {
    case "cidr":
      return "CIDR";
    case "process":
      return ".exe / process";
    case "tcp_port":
      return "TCP port";
    case "udp_port":
      return "UDP port";
    default:
      return "Domain";
  }
}

export function localOverridePlaceholder(kind: LocalOverrideTargetKind) {
  switch (kind) {
    case "cidr":
      return "203.0.113.0/24";
    case "process":
      return "C:\\Games\\Game\\Game.exe";
    case "tcp_port":
    case "udp_port":
      return "443 or 50000-50100";
    default:
      return "example.com";
  }
}

export function previewLocalOverride(route: LocalOverrideRoute, kind: LocalOverrideTargetKind, rawValue: string) {
  const normalized = normalizeLocalOverrideValue(kind, rawValue);
  if (!normalized) {
    return { normalized: "", preview: "" };
  }
  const action = route === "vpn" ? "PROXY" : route === "zapret" ? "DIRECT + zapret" : "DIRECT";
  const target =
    kind === "domain"
      ? `DOMAIN-SUFFIX,${normalized}`
      : kind === "cidr"
        ? `IP-CIDR,${normalized}`
        : kind === "process"
          ? `PROCESS-NAME,${normalized}`
          : `${kind === "tcp_port" ? "DST-PORT/TCP" : "DST-PORT/UDP"},${normalized}`;
  return { normalized, preview: `${target} -> ${action}` };
}

export function localOverrideExists(policy: AppSettings["routing_policy"], route: LocalOverrideRoute, kind: LocalOverrideTargetKind, rawValue: string) {
  const normalized = normalizeLocalOverrideValue(kind, rawValue).toLocaleLowerCase();
  if (!normalized) {
    return false;
  }
  const values = valuesForLocalOverride(policy, route, kind);
  return values.some((value) => value.toLocaleLowerCase() === normalized) || (policy.local_overrides?.rules ?? []).some((rule) => {
    const ruleKind = rule.target_kind === "app" ? "process" : rule.target_kind;
    const value = (rule.process_name ?? rule.value).toLocaleLowerCase();
    return rule.enabled && rule.path === route && ruleKind === kind && value === normalized;
  });
}

export function buildLocalOverridePatch(
  policy: AppSettings["routing_policy"],
  route: LocalOverrideRoute,
  kind: LocalOverrideTargetKind,
  rawValue: string,
): Partial<AppSettings["routing_policy"]> | null {
  const normalized = normalizeLocalOverrideValue(kind, rawValue);
  if (!normalized) {
    return null;
  }
  const nextRule = buildLocalOverrideRule(route, kind, rawValue, normalized);

  const append = (values: string[]) => (values.some((value) => value.toLocaleLowerCase() === normalized.toLocaleLowerCase()) ? values : [...values, normalized]);
  const appendRule = () => ({
    local_overrides: {
      version: policy.local_overrides?.version ?? 1,
      rules: [...(policy.local_overrides?.rules ?? []), nextRule].filter((rule, index, rules) => {
        const key = `${rule.path}:${rule.target_kind}:${(rule.process_name ?? rule.value).toLocaleLowerCase()}`;
        return rules.findIndex((candidate) => `${candidate.path}:${candidate.target_kind}:${(candidate.process_name ?? candidate.value).toLocaleLowerCase()}` === key) === index;
      }),
    },
  });

  if (route === "vpn") {
    if (kind === "domain") return { force_vpn_domains: append(policy.force_vpn_domains), ...appendRule() };
    if (kind === "cidr") return { force_vpn_cidrs: append(policy.force_vpn_cidrs), ...appendRule() };
    return null;
  }
  if (route === "zapret") {
    if (kind === "domain") return { force_zapret_domains: append(policy.force_zapret_domains), ...appendRule() };
    if (kind === "cidr") return { force_zapret_cidrs: append(policy.force_zapret_cidrs), ...appendRule() };
    if (kind === "process") return { force_zapret_processes: append(policy.force_zapret_processes), ...appendRule() };
    if (kind === "tcp_port") return { force_zapret_tcp_ports: append(policy.force_zapret_tcp_ports), ...appendRule() };
    if (kind === "udp_port") return { force_zapret_udp_ports: append(policy.force_zapret_udp_ports), ...appendRule() };
  }
  if (kind === "domain") return { force_direct_domains: append(policy.force_direct_domains), ...appendRule() };
  if (kind === "cidr") return { force_direct_cidrs: append(policy.force_direct_cidrs), ...appendRule() };
  if (kind === "process") return { force_direct_processes: append(policy.force_direct_processes), ...appendRule() };
  return null;
}

export function buildLocalOverrideRule(route: LocalOverrideRoute, kind: LocalOverrideTargetKind, rawValue: string, normalized = normalizeLocalOverrideValue(kind, rawValue)): LocalOverrideRule {
  const now = Math.floor(Date.now() / 1000);
  const processName = kind === "process" ? normalized : null;
  const rawTrimmed = rawValue.trim().replace(/^["']|["']$/g, "");
  return {
    id: `local-${route}-${kind}-${normalized.toLocaleLowerCase().replace(/[^a-z0-9]+/g, "-")}-${now}`,
    enabled: true,
    title: `${route.toUpperCase()} ${formatLocalOverrideKind(kind)} ${normalized}`,
    path: route,
    target_kind: kind === "process" && rawTrimmed.toLocaleLowerCase().endsWith(".exe") ? "app" : kind,
    value: normalized,
    executable_path: kind === "process" && /[\\/]/.test(rawTrimmed) ? rawTrimmed : null,
    process_name: processName,
    source: "user",
    created_at: now,
    updated_at: now,
    last_applied_at: null,
    last_policy_trace_id: null,
  };
}

function valuesForLocalOverride(policy: AppSettings["routing_policy"], route: LocalOverrideRoute, kind: LocalOverrideTargetKind) {
  if (route === "vpn") {
    if (kind === "domain") return policy.force_vpn_domains;
    if (kind === "cidr") return policy.force_vpn_cidrs;
    return [];
  }
  if (route === "zapret") {
    if (kind === "domain") return policy.force_zapret_domains;
    if (kind === "cidr") return policy.force_zapret_cidrs;
    if (kind === "process") return policy.force_zapret_processes;
    if (kind === "tcp_port") return policy.force_zapret_tcp_ports;
    if (kind === "udp_port") return policy.force_zapret_udp_ports;
    return [];
  }
  if (kind === "domain") return policy.force_direct_domains;
  if (kind === "cidr") return policy.force_direct_cidrs;
  if (kind === "process") return policy.force_direct_processes;
  return [];
}

export function normalizeLocalOverrideValue(kind: LocalOverrideTargetKind, rawValue: string) {
  const trimmed = rawValue.trim().replace(/^["']|["']$/g, "");
  if (!trimmed) {
    return "";
  }
  if (kind === "domain") {
    return trimmed.replace(/^https?:\/\//i, "").split(/[/?#]/)[0].replace(/^\*\./, "").toLocaleLowerCase();
  }
  if (kind === "process") {
    return trimmed.split(/[\\/]/).filter(Boolean).pop()?.trim() ?? "";
  }
  return trimmed;
}
