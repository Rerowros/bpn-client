import type { ServerIdentity, ServerNodeSort } from "../appTypes";
import type { ProxyCatalog, ProxyGroupView, ProxyNodeView } from "../services/agentClient";
import { compareText } from "./format";

export function getSelectedCatalogNode(catalog: ProxyCatalog | null) {
  for (const group of catalog?.groups ?? []) {
    const selected = group.nodes.find((node) => node.selected || node.name === group.selected);
    if (selected) {
      return selected;
    }
  }
  return null;
}

export function getActiveHomeGroup(catalog: ProxyCatalog | null, selectedGroup: string | null) {
  const groups = catalog?.groups ?? [];
  return (
    groups.find((group) => group.name === selectedGroup) ??
    groups.find((group) => group.name === "Выбор сервера") ??
    groups.find((group) => group.group_type === "select") ??
    groups[0] ??
    null
  );
}

export function parseServerIdentity(name: string): ServerIdentity {
  const flag = name.match(/[\u{1F1E6}-\u{1F1FF}]{2}/u)?.[0] ?? null;
  const emoji = flag ?? name.match(/[\p{Emoji_Presentation}\u{2600}-\u{27BF}]/u)?.[0] ?? null;
  const label = name
    .replace(/[\u{1F1E6}-\u{1F1FF}]{2}/gu, "")
    .replace(/[\p{Emoji_Presentation}\u{2600}-\u{27BF}]/gu, "")
    .replace(/\s+/g, " ")
    .trim();
  return {
    countryCode: detectCountryCode(name, flag),
    flag: emoji,
    label: label || name,
    raw: name,
  };
}

function detectCountryCode(name: string, flag: string | null) {
  const codeFromFlag = flag ? countryCodeFromRegionalFlag(flag) : null;
  if (codeFromFlag) {
    return codeFromFlag;
  }
  const normalized = name.toLocaleLowerCase();
  const countryPatterns: Array<[RegExp, string]> = [
    [/\b(?:nl|nld|netherlands)\b|нидерланд|голланд/, "NL"],
    [/\b(?:de|deu|germany)\b|герман/, "DE"],
    [/\b(?:us|usa|united states|dallas)\b|сша|америк/, "US"],
    [/\b(?:se|swe|sweden)\b|швец/, "SE"],
    [/\b(?:ch|che|switzerland)\b|швейцар/, "CH"],
    [/\b(?:tr|tur|turkey)\b|турц/, "TR"],
    [/\b(?:ru|rus|russia|spb|moscow)\b|росси|москв|спб/, "RU"],
    [/\b(?:fi|fin|finland)\b|финлянд/, "FI"],
    [/\b(?:fr|fra|france)\b|франц/, "FR"],
    [/\b(?:gb|uk|gbr|united kingdom|london)\b|британ|англи/, "GB"],
    [/\b(?:pl|pol|poland)\b|польш/, "PL"],
    [/\b(?:jp|jpn|japan|tokyo)\b|япон/, "JP"],
    [/\b(?:sg|sgp|singapore)\b|сингапур/, "SG"],
    [/\b(?:ca|can|canada)\b|канад/, "CA"],
  ];
  return countryPatterns.find(([pattern]) => pattern.test(normalized))?.[1] ?? null;
}

function countryCodeFromRegionalFlag(flag: string) {
  const chars = Array.from(flag);
  if (chars.length !== 2) {
    return null;
  }
  const code = chars
    .map((char) => {
      const point = char.codePointAt(0);
      return point ? String.fromCharCode(point - 0x1f1e6 + 65) : "";
    })
    .join("");
  return /^[A-Z]{2}$/.test(code) ? code : null;
}

export function formatNodeMeta(node: ProxyNodeView) {
  const parts = [node.proxy_type ?? (node.is_group ? "group" : "proxy")];
  if (node.server) {
    parts.push(node.server);
  }
  if (node.alive === false) {
    parts.push("offline");
  }
  return parts.join(" / ");
}

export function proxyGroupMatchesSearch(group: ProxyGroupView, query: string) {
  return proxyGroupText(group).includes(query) || group.nodes.some((node) => proxyNodeMatchesSearch(node, query));
}

export function proxyGroupText(group: ProxyGroupView) {
  return [group.name, group.group_type, group.selected ?? ""].join(" ").toLocaleLowerCase();
}

export function proxyNodeMatchesSearch(node: ProxyNodeView, query: string) {
  return [node.name, node.proxy_type ?? "", node.server ?? "", node.alive === false ? "down" : node.alive === true ? "alive" : ""]
    .join(" ")
    .toLocaleLowerCase()
    .includes(query);
}

export function sortProxyNodes(nodes: ProxyNodeView[], sort: ServerNodeSort, selected: string | null) {
  const indexed = nodes.map((node, index) => ({ node, index }));
  indexed.sort((left, right) => {
    switch (sort) {
      case "name":
        return compareText(left.node.name, right.node.name) || left.index - right.index;
      case "latency":
        return compareLatency(left.node.delay_ms, right.node.delay_ms) || compareText(left.node.name, right.node.name) || left.index - right.index;
      case "alive":
        return compareAlive(left.node.alive, right.node.alive) || compareText(left.node.name, right.node.name) || left.index - right.index;
      case "selected":
        return compareSelected(left.node, right.node, selected) || left.index - right.index;
      default:
        return left.index - right.index;
    }
  });
  return indexed.map((item) => item.node);
}

function compareLatency(left: number | null, right: number | null) {
  if (left === right) {
    return 0;
  }
  if (left === null) {
    return 1;
  }
  if (right === null) {
    return -1;
  }
  return left - right;
}

function compareAlive(left: boolean | null, right: boolean | null) {
  const rank = (value: boolean | null) => (value === true ? 0 : value === null ? 1 : 2);
  return rank(left) - rank(right);
}

function compareSelected(left: ProxyNodeView, right: ProxyNodeView, selected: string | null) {
  const isLeftSelected = left.selected || left.name === selected;
  const isRightSelected = right.selected || right.name === selected;
  if (isLeftSelected === isRightSelected) {
    return compareText(left.name, right.name);
  }
  return isLeftSelected ? -1 : 1;
}
