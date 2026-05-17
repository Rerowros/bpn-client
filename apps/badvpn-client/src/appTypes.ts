import type { ConnectionPath } from "./services/agentClient";

export type AppView = "overview" | "connections" | "servers" | "policy" | "settings";
export type ConnectionTab = "active" | "closed";
export type ConnectionPathFilter = "all" | ConnectionPath;
export type ConnectionGroupMode = "flows" | "processes";
export type SettingsSection = "basic" | "advanced" | "operator" | "updates";
export type ConnectionAttempt = { action: "connect" | "disconnect"; startedAt: number };
export type ServerNodeSort = "profile" | "name" | "latency" | "alive" | "selected";
export type TrafficSample = { at: number; upload: number; download: number };

export type LocalOverrideSummaryItem = {
  id?: string;
  enabled?: boolean;
  route: string;
  kind: string;
  value: string;
};

export type ConnectionProgressModel = {
  label: string;
  steps: Array<{ label: string; state: "done" | "active" | "pending" }>;
};

export type ServerIdentity = {
  countryCode: string | null;
  flag: string | null;
  label: string;
  raw: string;
};
