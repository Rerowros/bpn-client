import { Check, ListTree, RefreshCw, Server, SlidersHorizontal } from "lucide-react";
import type { ServerNodeSort } from "../appTypes";
import type { ProxyCatalog, ProxyGroupView, ProxyNodeView } from "../services/agentClient";
import { EmptyList, IdentityBadge } from "../ui/primitives";
import {
  parseServerIdentity,
  proxyGroupMatchesSearch,
  proxyGroupText,
  proxyNodeMatchesSearch,
  sortProxyNodes,
} from "../lib/serverCatalog";

const serverNodeSortOptions: Array<[ServerNodeSort, string]> = [
  ["profile", "Profile order"],
  ["selected", "Selected first"],
  ["latency", "Lowest latency"],
  ["alive", "Alive first"],
  ["name", "Name"],
];

export function ServersPage({
  catalog,
  selectedGroup,
  setSelectedGroup,
  serverSearch,
  setServerSearch,
  serverNodeSort,
  setServerNodeSort,
  refresh,
  select,
  busy,
}: {
  catalog: ProxyCatalog | null;
  selectedGroup: string | null;
  setSelectedGroup: (group: string) => void;
  serverSearch: string;
  setServerSearch: (value: string) => void;
  serverNodeSort: ServerNodeSort;
  setServerNodeSort: (value: ServerNodeSort) => void;
  refresh: () => void;
  select: (group: string, proxy: string) => void;
  busy: boolean;
}) {
  const groups = catalog?.groups ?? [];
  const query = serverSearch.trim().toLocaleLowerCase();
  const filteredGroups = query ? groups.filter((group) => proxyGroupMatchesSearch(group, query)) : groups;
  const activeGroup = filteredGroups.find((group) => group.name === selectedGroup) ?? filteredGroups[0] ?? null;
  const visibleNodesForGroup = (group: ProxyGroupView) => {
    const groupMatchesQuery = proxyGroupText(group).includes(query);
    return sortProxyNodes(
      group.nodes.filter((node) => !query || groupMatchesQuery || proxyNodeMatchesSearch(node, query)),
      serverNodeSort,
      group.selected,
    );
  };

  return (
    <div className="workspace pageWorkspace">
      <section className="pagePanel serverPanel">
        <div className="pageHeader">
          <div>
            <h1>Servers</h1>
            <p>Proxy groups from the generated Mihomo profile.</p>
          </div>
          <button className="subtleButton" type="button" onClick={refresh} disabled={busy}>
            <RefreshCw size={15} aria-hidden="true" />
            Refresh
          </button>
        </div>

        <div className="serverToolbar">
          <label className="searchField">
            <span>Search</span>
            <input
              value={serverSearch}
              onChange={(event) => setServerSearch(event.currentTarget.value)}
              placeholder="Group, node, host..."
              spellCheck={false}
            />
          </label>
          <label className="selectField compactField">
            <span>Sort nodes</span>
            <select value={serverNodeSort} onChange={(event) => setServerNodeSort(event.currentTarget.value as ServerNodeSort)}>
              {serverNodeSortOptions.map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
        </div>

        {groups.length === 0 ? (
          <EmptyList icon={<Server size={24} />} title="No server groups" text="Import a valid subscription to view Mihomo groups." />
        ) : filteredGroups.length === 0 ? (
          <EmptyList icon={<SlidersHorizontal size={24} />} title="No matching servers" text="Clear search to show all proxy groups and nodes." />
        ) : (
          <div className="serverDeckList">
            {filteredGroups.map((group) => {
              const expanded = activeGroup?.name === group.name;
              const visibleNodes = expanded ? visibleNodesForGroup(group) : [];
              return (
                <section className={expanded ? "serverGroupPanel active" : "serverGroupPanel"} key={group.name}>
                  <ServerGroupHeader
                    group={group}
                    active={expanded}
                    onClick={() => setSelectedGroup(group.name)}
                  />
                  {expanded ? (
                    visibleNodes.length > 0 ? (
                      <div className="serverNodeList">
                        {visibleNodes.map((node) => (
                          <NodeRow key={node.name} group={group.api_name ?? group.name} node={node} busy={busy} select={select} />
                        ))}
                      </div>
                    ) : (
                      <EmptyList icon={<Server size={22} />} title="No matching nodes" text="Change search or sorting to inspect this group." />
                    )
                  ) : null}
                </section>
              );
            })}
          </div>
        )}
      </section>
    </div>
  );
}

function ServerGroupHeader({ group, active, onClick }: { group: ProxyGroupView; active: boolean; onClick: () => void }) {
  const identity = parseServerIdentity(group.name);
  const selected = group.selected ? parseServerIdentity(group.selected).label : "No runtime selection";
  const groupType = group.group_type || "Group";
  return (
    <button className="serverGroupHead" type="button" onClick={onClick} aria-expanded={active}>
      <IdentityBadge identity={identity} className="groupEmoji" size={18} fallback={<ListTree size={18} aria-hidden="true" />} />
      <span className="serverGroupTitle">
        <span>
          <strong>{identity.label}</strong>
          <em className={`groupTypeBadge ${proxyGroupToneClass(groupType)}`}>{groupType}</em>
        </span>
        <small>{selected}</small>
      </span>
      <span className="groupCountBadge">{group.nodes.length}</span>
      <span className="groupChevron" aria-hidden="true">
        {active ? "⌃" : "⌄"}
      </span>
    </button>
  );
}

function NodeRow({ group, node, busy, select }: { group: string; node: ProxyNodeView; busy: boolean; select: (group: string, proxy: string) => void }) {
  const identity = parseServerIdentity(node.name);
  const selected = node.selected;
  return (
    <button
      className={`${selected ? "nodeRow selected" : "nodeRow"}${node.alive === false ? " offline" : ""}`}
      type="button"
      onClick={() => {
        if (!selected) {
          select(group, node.name);
        }
      }}
      disabled={busy}
      title={node.name}
    >
      <div className="nodeIdentity">
        <IdentityBadge identity={identity} className="nodeFlag" size={17} />
        <div>
          <strong>{identity.label}</strong>
          <span>{node.server ?? node.proxy_type ?? "proxy"}</span>
        </div>
      </div>
      <div className="nodeMeta">
        <span className={delayToneClass(node.delay_ms, node.alive)}>{node.delay_ms !== null ? `${node.delay_ms} ms` : "No ping"}</span>
        <span className="nodeTypeChip">{node.proxy_type ?? (node.is_group ? "group" : "proxy")}</span>
        {node.alive === false ? <span className="bad">Down</span> : null}
        {selected ? (
          <span className="selectedMark"><Check size={14} /> Selected</span>
        ) : (
          <span className="nodeUseCue">Use</span>
        )}
      </div>
    </button>
  );
}

function proxyGroupToneClass(groupType: string) {
  const normalized = groupType.replace(/[\s_-]+/g, "").toLocaleLowerCase();
  if (normalized.includes("urltest") || normalized.includes("loadbalance")) {
    return "auto";
  }
  if (normalized.includes("fallback")) {
    return "fallback";
  }
  if (normalized.includes("relay")) {
    return "relay";
  }
  return "selector";
}

function delayToneClass(delay: number | null, alive: boolean | null) {
  if (alive === false || delay === 0) {
    return "nodeDelay bad";
  }
  if (delay !== null && delay < 250) {
    return "nodeDelay good";
  }
  if (delay !== null && delay < 800) {
    return "nodeDelay warn";
  }
  return "nodeDelay";
}
