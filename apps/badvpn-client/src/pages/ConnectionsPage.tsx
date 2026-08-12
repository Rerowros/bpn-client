import { Activity, History, Plus, RefreshCw, SlidersHorizontal, X } from "lucide-react";
import type { CSSProperties } from "react";
import type { ConnectionGroupMode, ConnectionPathFilter, ConnectionTab } from "../appTypes";
import type { ConnectionPath, ConnectionsSnapshot, TrackedConnection } from "../services/agentClient";
import { DetailItem, EmptyList, LegendItem, PathBadge } from "../ui/primitives";
import { compareText, formatBytes, formatConnectionTime, formatPathLabel, formatTimestamp } from "../lib/format";
import { ROUTE_PATH_LABELS, ROUTE_PATH_SUBTITLES } from "../lib/routeLabels";

const connectionPathOptions: Array<[ConnectionPathFilter, string]> = [
  ["all", "All"],
  ["vpn", ROUTE_PATH_LABELS.vpn],
  ["zapret", ROUTE_PATH_LABELS.zapret],
  ["direct", ROUTE_PATH_LABELS.direct],
  ["blocked", ROUTE_PATH_LABELS.blocked],
  ["unknown", ROUTE_PATH_LABELS.unknown],
];

export function ConnectionsPage({
  connections,
  connectionTab,
  setConnectionTab,
  connectionPathFilter,
  setConnectionPathFilter,
  connectionGroupMode,
  setConnectionGroupMode,
  connectionSearch,
  setConnectionSearch,
  refresh,
  closeOne,
  closeMany,
  createOverride,
  closeAll,
  clearClosed,
  busy,
}: {
  connections: ConnectionsSnapshot | null;
  connectionTab: ConnectionTab;
  setConnectionTab: (tab: ConnectionTab) => void;
  connectionPathFilter: ConnectionPathFilter;
  setConnectionPathFilter: (filter: ConnectionPathFilter) => void;
  connectionGroupMode: ConnectionGroupMode;
  setConnectionGroupMode: (mode: ConnectionGroupMode) => void;
  connectionSearch: string;
  setConnectionSearch: (value: string) => void;
  refresh: () => void;
  closeOne: (id: string) => void;
  closeMany: (ids: string[]) => void;
  createOverride: (connection: TrackedConnection) => void;
  closeAll: () => void;
  clearClosed: () => void;
  busy: boolean;
}) {
  const active = connections?.active ?? [];
  const closed = connections?.closed ?? [];
  const rows = connectionTab === "active" ? active : closed;
  const pathCounts = connectionPathOptions.map(([path]) => [
    path,
    path === "all" ? rows.length : rows.filter((connection) => connection.path === path).length,
  ] as const);
  const connectionQuery = connectionSearch.trim().toLocaleLowerCase();
  const visibleRows = rows.filter((connection) => {
    return (
      (connectionPathFilter === "all" || connection.path === connectionPathFilter) &&
      (!connectionQuery || connectionMatchesSearch(connection, connectionQuery))
    );
  });
  const processGroups = groupConnectionsByProcess(visibleRows);
  const visibleActiveIds = visibleRows.filter((connection) => connection.state === "active").map((connection) => connection.id);

  return (
    <div className="workspace pageWorkspace">
      <section className="pagePanel connectionsPanel">
        <div className="pageHeader">
          <div>
            <h1>Connections</h1>
            <p>Live Mihomo flows plus closed-session history tracked by BPN Client.</p>
          </div>
          <div className="buttonRow">
            <button className="subtleButton" type="button" onClick={refresh} disabled={busy}>
              <RefreshCw size={15} aria-hidden="true" />
              Refresh
            </button>
            {connectionTab === "active" ? (
              <button className="subtleButton danger" type="button" onClick={closeAll} disabled={busy || active.length === 0}>
                <X size={15} aria-hidden="true" />
                Close all
              </button>
            ) : (
              <button className="subtleButton" type="button" onClick={clearClosed} disabled={closed.length === 0}>
                <History size={15} aria-hidden="true" />
                Clear
              </button>
            )}
          </div>
        </div>

        <div className="pathLegend">
          <LegendItem tone="vpn" title={ROUTE_PATH_LABELS.vpn} text={ROUTE_PATH_SUBTITLES.vpn} />
          <LegendItem tone="zapret" title={ROUTE_PATH_LABELS.zapret} text={ROUTE_PATH_SUBTITLES.zapret} />
          <LegendItem tone="direct" title={ROUTE_PATH_LABELS.direct} text={ROUTE_PATH_SUBTITLES.direct} />
        </div>

        <div className="connectionToolbar">
          <label className="searchField connectionSearchField">
            <span>Search</span>
            <input
              type="search"
              value={connectionSearch}
              placeholder="Host, process, rule, chain"
              spellCheck={false}
              onChange={(event) => setConnectionSearch(event.currentTarget.value)}
            />
          </label>
          <div
            className="segmented fluidSegmented connectionTabs"
            style={{ "--segment-count": 2, "--segment-index": connectionTab === "active" ? 0 : 1 } as CSSProperties}
          >
            <button className={connectionTab === "active" ? "active" : ""} type="button" onClick={() => setConnectionTab("active")}>
              Current <span>{active.length}</span>
            </button>
            <button className={connectionTab === "closed" ? "active" : ""} type="button" onClick={() => setConnectionTab("closed")}>
              Closed <span>{closed.length}</span>
            </button>
          </div>
          <div className="pathFilter" aria-label="Connection route filter">
            {connectionPathOptions.map(([path, label]) => {
              const count = pathCounts.find(([countPath]) => countPath === path)?.[1] ?? 0;
              return (
                <button
                  key={path}
                  className={connectionPathFilter === path ? `active ${path}` : path}
                  type="button"
                  onClick={() => setConnectionPathFilter(path)}
                  title={`Show ${label} connections`}
                >
                  {label}
                  <span>{count}</span>
                </button>
              );
            })}
          </div>
          {connectionTab === "active" && connectionPathFilter !== "all" && visibleActiveIds.length > 0 ? (
            <button className="subtleButton danger" type="button" onClick={() => closeMany(visibleActiveIds)} disabled={busy}>
              <X size={15} aria-hidden="true" />
              Close filtered
            </button>
          ) : null}
          <div
            className="segmented compactSegmented"
            style={{ "--segment-count": 2, "--segment-index": connectionGroupMode === "flows" ? 0 : 1 } as CSSProperties}
          >
            <button className={connectionGroupMode === "flows" ? "active" : ""} type="button" onClick={() => setConnectionGroupMode("flows")}>
              Flows
            </button>
            <button className={connectionGroupMode === "processes" ? "active" : ""} type="button" onClick={() => setConnectionGroupMode("processes")}>
              Processes
            </button>
          </div>
        </div>

        <div className="connectionList">
          {rows.length === 0 ? (
            <EmptyList icon={<Activity size={24} />} title="No connections" text="Start the VPN and open an app to see live routes here." />
          ) : visibleRows.length === 0 ? (
            <EmptyList icon={<SlidersHorizontal size={24} />} title="No matching connections" text="Change search or route filter to show hidden flows." />
          ) : connectionGroupMode === "processes" ? (
            processGroups.map((group) => (
              <ConnectionProcessGroup key={group.key} group={group} closeOne={closeOne} closeMany={closeMany} createOverride={createOverride} />
            ))
          ) : (
            visibleRows.map((connection) => (
              <ConnectionRow
                key={`${connection.state}-${connection.id}-${connection.closed_at ?? "open"}`}
                connection={connection}
                closeOne={closeOne}
                createOverride={createOverride}
              />
            ))
          )}
        </div>
      </section>
    </div>
  );
}

interface ConnectionProcessGroupView {
  key: string;
  label: string;
  rows: TrackedConnection[];
  uploadBytes: number;
  downloadBytes: number;
  activeCount: number;
  paths: Array<[ConnectionPath, number]>;
}

function groupConnectionsByProcess(rows: TrackedConnection[]): ConnectionProcessGroupView[] {
  const groups = new Map<string, ConnectionProcessGroupView>();
  for (const connection of rows) {
    const label = getConnectionProcessLabel(connection);
    const key = label.toLocaleLowerCase();
    const existing = groups.get(key);
    if (existing) {
      existing.rows.push(connection);
      existing.uploadBytes += connection.upload_bytes;
      existing.downloadBytes += connection.download_bytes;
      existing.activeCount += connection.state === "active" ? 1 : 0;
      continue;
    }

    groups.set(key, {
      key,
      label,
      rows: [connection],
      uploadBytes: connection.upload_bytes,
      downloadBytes: connection.download_bytes,
      activeCount: connection.state === "active" ? 1 : 0,
      paths: [],
    });
  }

  return Array.from(groups.values())
    .map((group) => ({
      ...group,
      paths: connectionPathOptions
        .filter(([path]) => path !== "all")
        .map(([path]) => [path, group.rows.filter((connection) => connection.path === path).length] as [ConnectionPath, number])
        .filter(([, count]) => count > 0),
    }))
    .sort((left, right) => right.rows.length - left.rows.length || compareText(left.label, right.label));
}

function getConnectionProcessLabel(connection: TrackedConnection) {
  return connection.process?.trim() || "Unknown process";
}

function connectionMatchesSearch(connection: TrackedConnection, query: string) {
  return [
    connection.host,
    connection.destination,
    connection.network,
    connection.connection_type,
    connection.process ?? "",
    connection.rule ?? "",
    connection.rule_payload ?? "",
    connection.path,
    connection.path_label,
    connection.path_note,
    connection.chains.join(" "),
  ]
    .join(" ")
    .toLocaleLowerCase()
    .includes(query);
}

function ConnectionProcessGroup({
  group,
  closeOne,
  closeMany,
  createOverride,
}: {
  group: ConnectionProcessGroupView;
  closeOne: (id: string) => void;
  closeMany: (ids: string[]) => void;
  createOverride: (connection: TrackedConnection) => void;
}) {
  const activeIds = group.rows.filter((connection) => connection.state === "active").map((connection) => connection.id);
  return (
    <section className="connectionProcessGroup">
      <div className="connectionProcessHeader">
        <div>
          <strong>{group.label}</strong>
          <span>
            {group.rows.length} flows{group.activeCount ? ` / ${group.activeCount} active` : ""} / {formatBytes(group.uploadBytes)} up /{" "}
            {formatBytes(group.downloadBytes)} down
          </span>
        </div>
        <div className="processPathCounts">
          {group.paths.map(([path, count]) => (
            <PathBadge key={path} path={path} label={`${formatPathLabel(path)} ${count}`} />
          ))}
          {activeIds.length ? (
            <button className="iconSmall danger" type="button" onClick={() => closeMany(activeIds)} title="Close active flows in this process">
              <X size={14} aria-hidden="true" />
            </button>
          ) : null}
        </div>
      </div>
      <div className="connectionProcessRows">
        {group.rows.map((connection) => (
          <ConnectionRow
            key={`${connection.state}-${connection.id}-${connection.closed_at ?? "open"}`}
            connection={connection}
            closeOne={closeOne}
            createOverride={createOverride}
          />
        ))}
      </div>
    </section>
  );
}

function ConnectionRow({
  connection,
  closeOne,
  createOverride,
}: {
  connection: TrackedConnection;
  closeOne: (id: string) => void;
  createOverride: (connection: TrackedConnection) => void;
}) {
  const isActive = connection.state === "active";
  const processLabel = getConnectionProcessLabel(connection);
  return (
    <div className="connectionRow">
      <div className="connectionMain">
        <PathBadge
          path={connection.path}
          label={formatPathLabel(connection.path)}
          subtitle={connection.path_note || ROUTE_PATH_SUBTITLES[connection.path]}
        />
        <div>
          <strong title={connection.host || connection.destination}>{connection.host || connection.destination}</strong>
          <span title={connection.destination}>{connection.destination}</span>
          <span className="connectionProcessLine" title={processLabel}>
            {processLabel}
          </span>
        </div>
      </div>
      <div className="connectionMeta">
        <span>{connection.network}</span>
        <span>{formatBytes(connection.upload_bytes)} up</span>
        <span>{formatBytes(connection.download_bytes)} down</span>
      </div>
      <div className="chainLine" title={connection.path_note}>
        {connection.chains.length ? connection.chains.join("  >  ") : connection.path_note}
      </div>
      <div className="connectionTraceLine">
        <span>{connection.rule ?? "rule unknown"}{connection.rule_payload ? ` / ${connection.rule_payload}` : ""}</span>
        <strong>{connection.path_note}</strong>
      </div>
      <details className="connectionDetails">
        <summary>Details</summary>
        <div className="connectionDetailsGrid">
          <DetailItem label="Flow ID" value={connection.id} />
          <DetailItem label="State" value={connection.state} />
          <DetailItem label="Host" value={connection.host || "unknown"} />
          <DetailItem label="Destination" value={connection.destination} />
          <DetailItem label="Process" value={processLabel} />
          <DetailItem label="Process path" value={connection.process_path ?? "not exposed"} />
          <DetailItem label="Network" value={`${connection.network} / ${connection.connection_type}`} />
          <DetailItem label="Route" value={`${connection.path_label} / ${connection.path_note}`} />
          <DetailItem label="Rule source" value={connection.rule_source ?? "unknown"} />
          <DetailItem label="Rule" value={connection.rule ?? "unknown"} />
          <DetailItem label="Payload" value={connection.rule_payload ?? "none"} />
          <DetailItem label="Chain" value={connection.chains.length ? connection.chains.join(" > ") : "none"} />
          <DetailItem label="Traffic" value={`${formatBytes(connection.upload_bytes)} up / ${formatBytes(connection.download_bytes)} down`} />
          <DetailItem label="Started" value={formatConnectionTime(connection.started_at)} />
          <DetailItem label="Closed" value={connection.closed_at ? formatTimestamp(connection.closed_at) : "not closed"} />
        </div>
      </details>
      <div className="connectionTail">
        <span>{isActive ? "Active" : "Closed"}</span>
        <button className="iconSmall" type="button" onClick={() => createOverride(connection)} title="Create local override from this connection">
          <Plus size={14} aria-hidden="true" />
        </button>
        {isActive ? (
          <button className="iconSmall danger" type="button" onClick={() => closeOne(connection.id)} title="Close connection">
            <X size={14} aria-hidden="true" />
          </button>
        ) : (
          <span>{connection.closed_at ? formatTimestamp(connection.closed_at) : "Closed"}</span>
        )}
      </div>
    </div>
  );
}
