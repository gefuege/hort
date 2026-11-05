export type SecretRequest = {
  name: string
  description: string
  env?: string
  context?: string
}

declare module 'claude-code' {
  interface PluginState {
    'hort-secrets': { pending: SecretRequest[] }
  }
}
