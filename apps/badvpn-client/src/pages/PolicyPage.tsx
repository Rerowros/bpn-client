import { AlertTriangle, BookOpen, Copy, Plus, RefreshCw, SlidersHorizontal } from "lucide-react";
import {
  countPolicySources,
  formatPolicyRuleForCopy,
  policyPathOptions,
  policyPathTone,
  policyRuleSearchText,
  suppressedRuleSearchText,
} from "../policyView";
import type { PolicyPathFilter } from "../policyView";
import type { LocalOverrideRoute, LocalOverrideTargetKind } from "../localOverrides";
import type { PolicyRuleView, PolicySummaryResponse } from "../services/agentClient";
import { compareText, formatRouteMode } from "../lib/format";
import { formatPolicyPathLabel, ROUTE_PATH_LABELS } from "../lib/routeLabels";
import { EmptyList, TruncatedText } from "../ui/primitives";

export function PolicyPage({
  policySummary,
  policySearch,
  setPolicySearch,
  policyPathFilter,
  setPolicyPathFilter,
  policySourceFilter,
  setPolicySourceFilter,
  copyText,
  createOverride,
  refresh,
  busy,
}: {
  policySummary: PolicySummaryResponse | null;
  policySearch: string;
  setPolicySearch: (value: string) => void;
  policyPathFilter: PolicyPathFilter;
  setPolicyPathFilter: (filter: PolicyPathFilter) => void;
  policySourceFilter: string;
  setPolicySourceFilter: (source: string) => void;
  copyText: (label: string, text: string) => void;
  createOverride: (rule: PolicyRuleView) => void;
  refresh: () => void;
  busy: boolean;
}) {
  const policy = policySummary;
  const notAvailable = !policy || !policy.available;
  const policyQuery = policySearch.trim().toLocaleLowerCase();
  const pathCounts = policyPathOptions.map(([path]) => [
    path,
    !policy
      ? 0
      : path === "all"
        ? policy.policy_rules.length
        : policy.policy_rules.filter((rule) => policyPathTone(rule.path) === path).length,
  ] as const);
  const sourceCounts = policy ? countPolicySources(policy.policy_rules, compareText, formatRouteMode) : [];
  const filteredPolicyRules = policy
    ? policy.policy_rules.filter((rule) => {
        const tone = policyPathTone(rule.path) as PolicyPathFilter;
        return (
          (policyPathFilter === "all" || tone === policyPathFilter) &&
          (policySourceFilter === "all" || rule.source === policySourceFilter) &&
          (!policyQuery || policyRuleSearchText(rule).includes(policyQuery))
        );
      })
    : [];
  const filteredMihomoRules = policy
    ? policyQuery
      ? policy.mihomo_rules.filter((rule) => rule.toLocaleLowerCase().includes(policyQuery))
      : policy.mihomo_rules
    : [];
  const filteredSuppressedRules = policy
    ? policyQuery
      ? policy.suppressed_rules.filter((rule) => suppressedRuleSearchText(rule).includes(policyQuery))
      : policy.suppressed_rules
    : [];

  return (
    <div className="workspace pageWorkspace">
      <section className="pagePanel policyPanel">
        <div className="pageHeader">
          <div>
            <h1>Effective policy</h1>
            <p>Read-only view of the compiled routing policy. Reflects last subscription import or connect.</p>
          </div>
          <button className="subtleButton" type="button" onClick={refresh} disabled={busy}>
            <RefreshCw size={15} aria-hidden="true" />
            Refresh
          </button>
        </div>

        {notAvailable ? (
          <EmptyList
            icon={<BookOpen size={24} />}
            title="No policy compiled yet"
            text="Import a subscription and connect at least once to see the effective routing policy."
          />
        ) : (
          <>
            <div className="policySummaryCards">
              <div className="policySummaryCard">
                <span className="policySummaryLabel">Mode</span>
                <strong className="policySummaryValue">{formatRouteMode(policy.mode)}</strong>
              </div>
              <div className="policySummaryCard">
                <span className="policySummaryLabel">Main proxy group</span>
                <TruncatedText text={policy.main_proxy_group || "—"} className="policySummaryValue" lines={2} />
              </div>
              <div className="policySummaryCard">
                <span className="policySummaryLabel">Rules</span>
                <strong className="policySummaryValue">{policy.rule_count}</strong>
              </div>
              <div className="policySummaryCard">
                <span className="policySummaryLabel">Suppressed</span>
                <strong className={policy.suppressed_count > 0 ? "policySummaryValue warn" : "policySummaryValue"}>
                  {policy.suppressed_count}
                </strong>
              </div>
              <div className="policySummaryCard">
                <span className="policySummaryLabel">zapret domains</span>
                <strong className="policySummaryValue">{policy.zapret_domain_count}</strong>
              </div>
              <div className="policySummaryCard">
                <span className="policySummaryLabel">Warnings</span>
                <strong className={policy.warnings_count > 0 ? "policySummaryValue warn" : "policySummaryValue"}>
                  {policy.warnings_count}
                </strong>
              </div>
              <div className="policySummaryCard span2">
                <span className="policySummaryLabel">Final rule</span>
                <TruncatedText text={policy.final_rule || "—"} className="policySummaryValue mono" lines={2} />
              </div>
            </div>

            {policy.policy_rules.length > 0 ? (
              <div className="policyToolbar">
                <label className="searchField">
                  <span>Search rules</span>
                  <input
                    type="search"
                    value={policySearch}
                    placeholder="Domain, CIDR, process, source, generated rule"
                    spellCheck={false}
                    onChange={(event) => setPolicySearch(event.currentTarget.value)}
                  />
                </label>
                <label className="compactField">
                  <span>Source</span>
                  <select value={policySourceFilter} onChange={(event) => setPolicySourceFilter(event.currentTarget.value)}>
                    <option value="all">All sources ({policy.policy_rules.length})</option>
                    {sourceCounts.map(([source, count]) => (
                      <option key={source} value={source}>
                        {formatRouteMode(source)} ({count})
                      </option>
                    ))}
                  </select>
                </label>
                <div className="pathFilter policyPathFilter" aria-label="Policy path filter">
                  {policyPathOptions.map(([path, label]) => {
                    const count = pathCounts.find(([countPath]) => countPath === path)?.[1] ?? 0;
                    return (
                      <button
                        key={path}
                        className={policyPathFilter === path ? `active ${path}` : path}
                        type="button"
                        onClick={() => setPolicyPathFilter(path)}
                        title={`Show ${label} policy rules`}
                      >
                        {label}
                        <span>{count}</span>
                      </button>
                    );
                  })}
                </div>
              </div>
            ) : null}

            {policy.policy_rules.length > 0 ? (
              <div className="policyQuickStats">
                {pathCounts
                  .filter(([path, count]) => path !== "all" && count > 0)
                  .map(([path, count]) => (
                    <span key={path} className={path}>
                      {path === "reject" ? ROUTE_PATH_LABELS.reject : ROUTE_PATH_LABELS[path as keyof typeof ROUTE_PATH_LABELS]} {count}
                    </span>
                  ))}
                {sourceCounts.map(([source, count]) => (
                  <span key={source}>
                    {formatRouteMode(source)} {count}
                  </span>
                ))}
              </div>
            ) : null}

            {policy.policy_rules.length > 0 ? (
              <div className="policySection">
                <h2>
                  Policy rules <span className="policyCount">{filteredPolicyRules.length}</span>
                  <span className="policyCount muted">{policy.policy_rules.length} total</span>
                </h2>
                {filteredPolicyRules.length === 0 ? (
                  <EmptyList icon={<SlidersHorizontal size={24} />} title="No matching policy rules" text="Change search or path filter to show hidden rules." />
                ) : (
                  <div className="policyTableWrap">
                    <table className="policyTable" id="policy-rules-table">
                      <thead>
                        <tr>
                          <th>Target</th>
                          <th>Value</th>
                          <th>Path</th>
                          <th>Source</th>
                          <th>Mihomo rule</th>
                          <th>zapret</th>
                          <th>DNS</th>
                          <th>Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredPolicyRules.map((rule, index) => (
                          <tr key={`${rule.priority}-${rule.target_kind}-${rule.target_value}-${index}`} className={policyPathTone(rule.path)}>
                            <td className="mono">{rule.target_kind}</td>
                            <td className="mono wrap">{rule.target_value}</td>
                            <td>
                              <span className={`policyPathBadge ${policyPathTone(rule.path)}`} title={rule.path}>
                                {formatPolicyPathLabel(rule.path)}
                              </span>
                            </td>
                            <td>{rule.source}</td>
                            <td className="mono wrap">{rule.mihomo_rule}</td>
                            <td>{rule.zapret_effect}</td>
                            <td>{rule.dns_effect}</td>
                            <td className="policyActions">
                              <button className="iconSmall" type="button" onClick={() => copyText("Policy rule", formatPolicyRuleForCopy(rule))} title="Copy policy rule details">
                                <Copy size={13} aria-hidden="true" />
                              </button>
                              {localOverrideDraftFromPolicyRule(rule) ? (
                                <button className="iconSmall" type="button" onClick={() => createOverride(rule)} title="Create local override from this policy rule">
                                  <Plus size={13} aria-hidden="true" />
                                </button>
                              ) : null}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ) : null}

            {policy.suppressed_rules.length > 0 ? (
              <div className="policySection">
                <h2>
                  Suppressed rules <span className="policyCount">{filteredSuppressedRules.length}</span>
                  <span className="policyCount muted">{policy.suppressed_rules.length} total</span>
                </h2>
                {filteredSuppressedRules.length === 0 ? (
                  <EmptyList icon={<SlidersHorizontal size={24} />} title="No matching suppressed rules" text="Clear search to inspect all suppressed provider rules." />
                ) : (
                  <div className="policyTableWrap">
                    <table className="policyTable" id="policy-suppressed-table">
                      <thead>
                        <tr>
                          <th>Original rule</th>
                          <th>Chosen rule</th>
                          <th>Reason</th>
                          <th>Copy</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredSuppressedRules.map((rule, index) => (
                          <tr key={`${rule.original_rule}-${index}`}>
                            <td className="mono wrap">{rule.original_rule}</td>
                            <td className="mono wrap">{rule.chosen_rule}</td>
                            <td>{rule.reason}</td>
                            <td>
                              <button className="iconSmall" type="button" onClick={() => copyText("Suppressed rule", rule.chosen_rule)} title="Copy chosen rule">
                                <Copy size={13} aria-hidden="true" />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            ) : null}

            {policy.mihomo_rules.length > 0 ? (
              <div className="policySection">
                <h2>
                  Mihomo rules <span className="policyCount">{filteredMihomoRules.length}</span>
                  <span className="policyCount muted">{policy.mihomo_rules.length} total</span>
                </h2>
                {filteredMihomoRules.length === 0 ? (
                  <EmptyList icon={<SlidersHorizontal size={24} />} title="No matching Mihomo rules" text="Clear search to show the generated rules." />
                ) : (
                  <div className="policyRuleList" id="policy-mihomo-rules">
                    {filteredMihomoRules.map((rule, index) => (
                      <div key={`${rule}-${index}`} className="policyRuleLine">
                        <span className="policyRuleIndex">{index + 1}</span>
                        <code>{rule}</code>
                        <button className="iconSmall" type="button" onClick={() => copyText("Mihomo rule", rule)} title="Copy Mihomo rule">
                          <Copy size={13} aria-hidden="true" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : null}

            {policy.diagnostics_expectations.length > 0 ? (
              <div className="policySection">
                <h2>Route expectations <span className="policyCount">{policy.diagnostics_expectations.length}</span></h2>
                <div className="policyTableWrap">
                  <table className="policyTable" id="policy-expectations-table">
                    <thead>
                      <tr>
                        <th>Target</th>
                        <th>Expected path</th>
                        <th>Mihomo action</th>
                        <th>zapret expected</th>
                        <th>Source</th>
                      </tr>
                    </thead>
                    <tbody>
                      {policy.diagnostics_expectations.map((exp, index) => (
                        <tr key={index}>
                          <td className="mono">{exp.target}</td>
                          <td>
                            <span className={`policyPathBadge ${policyPathTone(exp.expected_path)}`} title={exp.expected_path}>
                              {formatPolicyPathLabel(exp.expected_path)}
                            </span>
                          </td>
                          <td className="mono">{exp.expected_mihomo_action}</td>
                          <td>{exp.expected_zapret ? "Yes" : "—"}</td>
                          <td>{exp.source}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}

            {policy.zapret_hostlist.length > 0 || policy.zapret_ipset.length > 0 ? (
              <div className="policySection">
                <h2>zapret artifacts</h2>
                <div className="policyArtifactGrid">
                  {policy.zapret_hostlist.length > 0 ? (
                    <div className="policyArtifact">
                      <h3>Hostlist <span className="policyCount">{policy.zapret_hostlist.length}</span></h3>
                      <div className="policyRuleList compact">
                        {policy.zapret_hostlist.map((host, index) => (
                          <code key={index}>{host}</code>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {policy.zapret_hostlist_exclude.length > 0 ? (
                    <div className="policyArtifact">
                      <h3>Hostlist exclude <span className="policyCount">{policy.zapret_hostlist_exclude.length}</span></h3>
                      <div className="policyRuleList compact">
                        {policy.zapret_hostlist_exclude.map((host, index) => (
                          <code key={index}>{host}</code>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {policy.zapret_ipset.length > 0 ? (
                    <div className="policyArtifact">
                      <h3>IPSet <span className="policyCount">{policy.zapret_ipset.length}</span></h3>
                      <div className="policyRuleList compact">
                        {policy.zapret_ipset.map((cidr, index) => (
                          <code key={index}>{cidr}</code>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {policy.zapret_ipset_exclude.length > 0 ? (
                    <div className="policyArtifact">
                      <h3>IPSet exclude <span className="policyCount">{policy.zapret_ipset_exclude.length}</span></h3>
                      <div className="policyRuleList compact">
                        {policy.zapret_ipset_exclude.map((cidr, index) => (
                          <code key={index}>{cidr}</code>
                        ))}
                      </div>
                    </div>
                  ) : null}
                </div>
              </div>
            ) : null}

            {policy.dns_nameserver_policy.length > 0 ? (
              <div className="policySection">
                <h2>DNS policy <span className="policyCount">{policy.dns_nameserver_policy.length}</span></h2>
                <div className="policyTableWrap">
                  <table className="policyTable" id="policy-dns-table">
                    <thead>
                      <tr>
                        <th>Pattern</th>
                        <th>Nameservers</th>
                      </tr>
                    </thead>
                    <tbody>
                      {policy.dns_nameserver_policy.map((rule, index) => (
                        <tr key={index}>
                          <td className="mono">{rule.pattern}</td>
                          <td className="mono wrap">{rule.nameservers.join(", ")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}

            {policy.managed_proxy_groups.length > 0 ? (
              <div className="policySection">
                <h2>Managed proxy groups <span className="policyCount">{policy.managed_proxy_groups.length}</span></h2>
                {policy.managed_proxy_groups.map((group, index) => (
                  <div key={index} className="policyManagedGroup">
                    <strong>{group.name}</strong>
                    <span>{group.proxies.join(", ") || "No proxies"}</span>
                  </div>
                ))}
              </div>
            ) : null}

            {policy.diagnostics_messages.length > 0 ? (
              <div className="policySection">
                <h2>Warnings <span className="policyCount warn">{policy.diagnostics_messages.length}</span></h2>
                <div className="policyWarningList">
                  {policy.diagnostics_messages.map((message, index) => (
                    <div key={index} className="policyWarning">
                      <AlertTriangle size={14} aria-hidden="true" />
                      <span>{message}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
          </>
        )}
      </section>
    </div>
  );
}


function localOverrideDraftFromPolicyRule(rule: PolicyRuleView): {
  route: LocalOverrideRoute;
  kind: LocalOverrideTargetKind;
  value: string;
} | null {
  const targetKind = rule.target_kind.toLocaleLowerCase();
  const route = policyPathToLocalOverrideRoute(rule.path);
  if (targetKind === "tcpport" || targetKind === "tcp_port") {
    return { route: "zapret", kind: "tcp_port", value: rule.target_value };
  }
  if (targetKind === "udpport" || targetKind === "udp_port") {
    return { route: "zapret", kind: "udp_port", value: rule.target_value };
  }
  if (targetKind.includes("processname")) {
    return route === "vpn" ? null : { route, kind: "process", value: rule.target_value };
  }
  if (targetKind.includes("cidr") || targetKind.includes("ipsuffix")) {
    return { route, kind: "cidr", value: rule.target_value };
  }
  if (targetKind.includes("domain")) {
    return { route, kind: "domain", value: rule.target_value };
  }
  return null;
}

function policyPathToLocalOverrideRoute(path: string): LocalOverrideRoute {
  if (path.includes("VpnProxy")) {
    return "vpn";
  }
  if (path.includes("ZapretDirect")) {
    return "zapret";
  }
  return "direct";
}
