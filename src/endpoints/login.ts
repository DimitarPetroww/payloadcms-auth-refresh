import type { Endpoint } from 'payload'

import type { AuthRefreshPluginOptions } from '../index'

import { createRefreshToken } from '../utils/crypto'
import { getRequestMeta } from '../utils/getRequestMeta'

type LoginEndpointOptions = Pick<
  AuthRefreshPluginOptions,
  'entity_slug' | 'identifier_field' | 'pepper' | 'refreshTokenTTL'
>

export const loginEndpoint = (options: LoginEndpointOptions): Endpoint => ({
  handler: async (req) => {
    const { deviceId, identifier, password } = (await req.json?.()) || {}

    if (!identifier || !password) {
      return Response.json({ message: 'Identifier and password are required.' }, { status: 400 })
    }

    const login = await req.payload.login({
      collection: options.entity_slug,
      data: {
        [options.identifier_field]: identifier,
        password,
      } as any,
    })

    const { token, tokenHash } = createRefreshToken(options.pepper)

    await req.payload.create({
      collection: 'refresh-tokens',
      data: {
        deviceId,
        entity: login.user.id,
        expiresAt: new Date(Date.now() + options.refreshTokenTTL * 24 * 60 * 60 * 1000),
        lastUsedAt: new Date(),
        tokenHash,
        ...getRequestMeta(req),
      },
    })

    return Response.json({
      access_token: login.token,
      refresh_token: token,
      user: login.user,
    })
  },
  method: 'post',
  path: `/auth/login`,
})
