import { invoke } from "@tauri-apps/api/core";

export type AppUpdateStatus =
  | { state: "idle" }
  | { state: "checking" }
  | { state: "available"; version: string; date: string | null; body: string | null }
  | { state: "not_available" }
  | { state: "downloading"; progress: number | null }
  | { state: "installed" }
  | { state: "error"; message: string };

interface AppReleaseUpdate {
  current_version: string;
  latest_version: string | null;
  update_available: boolean;
  notes: string | null;
  release_url: string;
  error: string | null;
}

export async function checkAppUpdate(): Promise<AppUpdateStatus> {
  try {
    const update = await invoke<AppReleaseUpdate>("check_app_release_update");
    if (update.error) {
      return { state: "error", message: update.error };
    }
    if (!update.update_available || !update.latest_version) {
      return { state: "not_available" };
    }

    return {
      state: "available",
      version: update.latest_version,
      date: null,
      body: update.notes,
    };
  } catch (error) {
    return {
      state: "error",
      message: error instanceof Error ? error.message : String(error),
    };
  }
}

export async function installAppUpdate(onProgress: (progress: number | null) => void): Promise<AppUpdateStatus> {
  onProgress(null);
  return {
    state: "error",
    message: "Signed self-update is disabled until a Tauri updater key is configured in CI.",
  };
}
