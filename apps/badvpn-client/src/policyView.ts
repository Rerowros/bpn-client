import type { PolicyRuleView, SuppressedRuleView } from "./services/agentClient";

export type PolicyPathFilter = "all" | "vpn" | "zapret" | "direct" | "reject";

export const policyPathOptions: Array<[PolicyPathFilter, string]> = [
  ["all", "All"],
  ["vpn", "VPN"],
  ["zapret", "zapret"],
  ["direct", "DIRECT"],
  ["reject", "Reject"],
];

export function policyPathTone(path: string): string {
  if (path.startsWith("VpnProxy")) return "vpn";
  if (path === "ZapretDirect") return "zapret";
  if (path === "Reject") return "reject";
  return "direct";
}

export function policyRuleSearchText(rule: PolicyRuleView) {
  return [
    rule.target_kind,
    rule.target_value,
    rule.path,
    rule.path_group ?? "",
    rule.source,
    String(rule.priority),
    rule.original_rule ?? "",
    rule.tags.join(" "),
    rule.mihomo_rule,
    rule.zapret_effect,
    rule.dns_effect,
  ]
    .join(" ")
    .toLocaleLowerCase();
}

export function countPolicySources(rules: PolicyRuleView[], compareText: (left: string, right: string) => number, formatLabel: (value: string) => string): Array<[string, number]> {
  const counts = new Map<string, number>();
  for (const rule of rules) {
    counts.set(rule.source, (counts.get(rule.source) ?? 0) + 1);
  }
  return Array.from(counts.entries()).sort(([left], [right]) => compareText(formatLabel(left), formatLabel(right)));
}

export function suppressedRuleSearchText(rule: SuppressedRuleView) {
  return [rule.original_rule, rule.chosen_rule, rule.reason].join(" ").toLocaleLowerCase();
}

export function formatPolicyRuleForCopy(rule: PolicyRuleView) {
  return [
    `target=${rule.target_kind},${rule.target_value}`,
    `path=${rule.path}`,
    rule.path_group ? `group=${rule.path_group}` : null,
    `source=${rule.source}`,
    `priority=${rule.priority}`,
    rule.tags.length ? `tags=${rule.tags.join("|")}` : null,
    `mihomo=${rule.mihomo_rule}`,
    `zapret=${rule.zapret_effect}`,
    `dns=${rule.dns_effect}`,
  ]
    .filter(Boolean)
    .join("; ");
}
