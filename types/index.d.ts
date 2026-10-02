export type Guard = {
  /** Values masked in tool results this session. */
  masked: number
  /** Epoch ms until which the next push skips the scan; 0 when no pass is active. */
  passUntil: number
}

declare module 'claude-code' {
  interface PluginState {
    'secret-guard': { guard: Guard }
  }
}
