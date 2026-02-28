import type { Config } from 'payload'

import { RefreshTokens } from './collections/refreshTokens'
import { loginEndpoint } from './endpoints/login'
import { logoutEndpoint } from './endpoints/logout'
import { refreshEndpoint } from './endpoints/refresh'

export type AuthRefreshPluginOptions = {
  entity_slug: string
  identifier_field: string
  pepper: string
  refreshTokenTTL: number
}

export const authRefreshPlugin =
  ({
    entity_slug = 'users',
    identifier_field = 'email',
    pepper = 'default-pepper',
    refreshTokenTTL = 30,
  }: AuthRefreshPluginOptions): ((config: Config) => Config) =>
  (config) => {
    return {
      ...config,
      collections: [...(config.collections || []), RefreshTokens({ entity_slug })],
      endpoints: [
        ...(config.endpoints || []),
        loginEndpoint({ entity_slug, identifier_field, pepper, refreshTokenTTL }),
        refreshEndpoint({ entity_slug, identifier_field, pepper, refreshTokenTTL }),
        logoutEndpoint({ entity_slug, pepper }),
      ],
    }
  }
