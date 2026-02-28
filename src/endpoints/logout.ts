import type { Endpoint } from 'payload'

import type { AuthRefreshPluginOptions } from '../index'

import { RevocationReason } from '../collections/refreshTokens'
import { hashToken } from '../utils/crypto'

type LogoutEndpointOptions = Pick<AuthRefreshPluginOptions, 'entity_slug' | 'pepper'>

export const logoutEndpoint = (options: LogoutEndpointOptions): Endpoint => ({
  handler: async (req) => {
    const { refresh_token } = (await req.json?.()) || {}

    if (!refresh_token) {
      return Response.json({ message: 'refreshToken is required to logout.' }, { status: 400 })
    }

    const tokenHash = hashToken(refresh_token, options.pepper)
    const result = await req.payload.find({
      collection: 'refresh-tokens',
      where: { tokenHash: { equals: tokenHash } },
    })

    if (!result?.docs?.length) {
      return new Response(null, { status: 204 })
    }

    const session = result.docs[0]

    await req.payload.update({
      id: session.id,
      collection: 'refresh-tokens',
      data: {
        revocationReason: RevocationReason.UserLogout,
        revokedAt: new Date(),
      },
    })

    return new Response(null, { status: 204 })
  },
  method: 'post',
  path: `/auth/logout`,
})
