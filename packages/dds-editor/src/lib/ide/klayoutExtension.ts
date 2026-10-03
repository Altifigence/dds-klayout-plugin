/** Fixed optional external viewer. Its state grants no engine/job qualification. */
export const KLAYOUT_EXTENSION_ID = 'org.klayout.viewer';
export const KLAYOUT_EXTENSION_VERSION = '0.30.12';
export interface KLayoutExtensionState {
  schema: 'altifigence.klayout-extension.v1';
  version: '0.30.12';
  target: 'windows-x86_64' | 'ubuntu24-x86_64' | 'unsupported';
  installationScope: 'device' | 'wsl' | 'linux-user';
  distribution: string | null;
  supported: boolean;
  installed: boolean;
  ready: boolean;
  code: 'missing' | 'ready' | 'unsupported' | 'dependencies-missing' | 'display-missing' | 'integrity-failed' | 'version-failed';
  dependencies: readonly string[];
}
export interface KLayoutExtensionHost {
  read(): Promise<KLayoutExtensionState>;
  setInstalled(installed: boolean): Promise<KLayoutExtensionState>;
  /** Cancels this host's active opaque native reservation only. */
  cancel(): Promise<void>;
  /** Native file picker grants the saved layout; the renderer supplies no path. */
  open(): Promise<boolean>;
}
