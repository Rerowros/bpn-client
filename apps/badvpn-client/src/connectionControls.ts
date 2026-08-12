export type PrimaryConnectionAction = "connect" | "disconnect";

export function primaryConnectionAction(
  connected: boolean,
  status: string,
): PrimaryConnectionAction {
  return connected || status === "starting" ? "disconnect" : "connect";
}

export function primaryConnectionActionDisabled(busy: boolean, status: string): boolean {
  return busy || status === "stopping";
}
