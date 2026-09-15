import type { PayloadRequest } from 'payload'

import { createRefreshToken } from './crypto'
import { getRequestMeta } from './getRequestMeta'

interface AuthenticateOptions {
  deviceId?: string
  entity_slug: string
  identifier: string
  identifier_field: string
  password: string
  pepper: string
  refreshTokenTTL: number
}

export const authenticate = async (req: PayloadRequest, options: AuthenticateOptions) => {
  const { deviceId, entity_slug, identifier, identifier_field, password, pepper, refreshTokenTTL } =
    options

  const login = await req.payload.login({
    collection: entity_slug,
    data: {
      [identifier_field]: identifier,
      password,
    } as { email: string; password: string },
  })

  const { token, tokenHash } = createRefreshToken(pepper)

  await req.payload.create({
    collection: 'refresh-tokens',
    data: {
      deviceId,
      entity: login.user.id,
      expiresAt: new Date(Date.now() + refreshTokenTTL * 24 * 60 * 60 * 1000),
      lastUsedAt: new Date(),
      tokenHash,
      ...getRequestMeta(req),
    },
  })

  return {
    // Shape must match the refresh endpoint, which returns jwtSign's
    // { exp, token }. Returning a bare string here left clients reading
    // `access_token.token` with undefined after every login.
    access_token: {
      exp: login.exp,
      token: login.token,
    },
    refresh_token: token,
    user: login.user,
  }
}
