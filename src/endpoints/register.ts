import type { Endpoint } from 'payload'

import type { AuthRefreshPluginOptions } from '../index'

import { authenticate } from '../utils/authenticate'

type RegisterEndpointOptions = Pick<
  AuthRefreshPluginOptions,
  'entity_slug' | 'identifier_field' | 'pepper' | 'refreshTokenTTL'
>

export const registerEndpoint = (options: RegisterEndpointOptions): Endpoint => ({
  handler: async (req) => {
    const { deviceId, identifier, password, ...otherFields } = (await req.json?.()) || {}

    if (!identifier || !password) {
      return Response.json({ message: 'Identifier and password are required.' }, { status: 400 })
    }

    await req.payload.create({
      collection: options.entity_slug,
      data: {
        [options.identifier_field]: identifier,
        password,
        ...otherFields,
      },
    })

    const result = await authenticate(req, {
      deviceId,
      entity_slug: options.entity_slug,
      identifier,
      identifier_field: options.identifier_field,
      password,
      pepper: options.pepper,
      refreshTokenTTL: options.refreshTokenTTL,
    })

    return Response.json(result)
  },
  method: 'post',
  path: `/auth/register`,
})
