import type { ConnectionPath } from "../services/agentClient";

export type RoutePathKey = ConnectionPath | "reject";

export const ROUTE_PATH_LABELS: Record<RoutePathKey, string> = {
  vpn: "VPN",
  zapret: "zapret",
  direct: "DIRECT",
  blocked: "Blocked",
  unknown: "Unknown",
  reject: "Blocked",
};

export const ROUTE_PATH_SUBTITLES: Record<ConnectionPath, string> = {
  vpn: "Mihomo proxy chain; traffic exits through selected server.",
  zapret: "DIRECT in Mihomo plus local winws DPI bypass.",
  direct: "No VPN proxy and not matched by zapret policy.",
  blocked: "Rejected by routing policy.",
  unknown: "Runtime could not classify this flow.",
};

export function formatConnectionPathLabel(path: ConnectionPath): string {
  return ROUTE_PATH_LABELS[path];
}

export function formatPolicyPathLabel(path: string): string {
  const normalized = path.toLocaleLowerCase();
  if (normalized === "vpn" || path.startsWith("VpnProxy")) {
    return ROUTE_PATH_LABELS.vpn;
  }
  if (normalized === "zapret" || path === "ZapretDirect") {
    return ROUTE_PATH_LABELS.zapret;
  }
  if (normalized === "reject" || path === "Reject") {
    return ROUTE_PATH_LABELS.reject;
  }
  if (normalized === "direct" || path === "DirectSafe" || path.includes("Direct")) {
    return ROUTE_PATH_LABELS.direct;
  }
  return path;
}

export function policyPathToRouteKey(path: string): ConnectionPath | "reject" {
  const normalized = path.toLocaleLowerCase();
  if (normalized === "vpn" || path.startsWith("VpnProxy")) {
    return "vpn";
  }
  if (normalized === "zapret" || path === "ZapretDirect") {
    return "zapret";
  }
  if (normalized === "reject" || path === "Reject") {
    return "reject";
  }
  if (normalized === "blocked") {
    return "blocked";
  }
  if (normalized === "unknown") {
    return "unknown";
  }
  return "direct";
}
