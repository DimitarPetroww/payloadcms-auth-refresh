import type { Endpoint, Field } from 'payload'

import { jwtSign } from 'payload'
import { fieldAffectsData, fieldHasSubFields } from 'payload/shared'

import type { AuthRefreshPluginOptions } from '../index'

import { RevocationReason } from '../collections/refreshTokens'
import { createRefreshToken, hashToken } from '../utils/crypto'
import { getRequestMeta } from '../utils/getRequestMeta'

type RefreshEndpointOptions = Pick<
  AuthRefreshPluginOptions,
  'entity_slug' | 'identifier_field' | 'pepper' | 'refreshTokenTTL'
>

export const refreshEndpoint = (options: RefreshEndpointOptions): Endpoint => ({
  handler: async (req) => {
    const { deviceId, refresh_token } = (await req.json?.()) || {}

    if (!refresh_token || !deviceId) {
      return Response.json(
        { message: 'Refresh token and device ID are required.' },
        { status: 400 },
      )
    }

    const result = await req.payload.find({
      collection: 'refresh-tokens',
      where: {
        tokenHash: {
          equals: hashToken(refresh_token, options.pepper),
        },
      },
    })

    if (!result?.docs?.length) {
      return Response.json({ message: 'Unauthorized.' }, { status: 401 })
    }

    const session = result.docs[0]

    if (session.deviceId !== deviceId || session.expiresAt < new Date() || session.revokedAt) {
      return Response.json({ message: 'Unauthorized.' }, { status: 401 })
    }

    if (session.rotatedAt) {
      await req.payload.update({
        id: session.id,
        collection: 'refresh-tokens',
        data: { revocationReason: RevocationReason.SuspiciousActivity, revokedAt: new Date() },
      })
      return Response.json({ message: 'Unauthorized.' }, { status: 401 })
    }

    const { token, tokenHash } = createRefreshToken(options.pepper)
    const now = new Date()

    const newSession = await req.payload.create({
      collection: 'refresh-tokens',
      data: {
        deviceId,
        entity: session.entity,
        expiresAt: new Date(now.getTime() + options.refreshTokenTTL * 24 * 60 * 60 * 1000),
        lastUsedAt: now,
        tokenHash,
        ...getRequestMeta(req),
      },
    })

    await req.payload.update({
      id: session.id,
      collection: 'refresh-tokens',
      data: {
        lastUsedAt: now,
        replacedBy: newSession.id,
        revocationReason: RevocationReason.TokenRotation,
        rotatedAt: now,
      },
    })

    const collectionConfig = req.payload.collections[options.entity_slug].config

    const user = await req.payload.findByID({
      id: session.entity.id,
      collection: options.entity_slug,
      depth: 0,
    })

    const fieldsToSign = collectionConfig.fields.reduce(
      (signedFields: Record<string, number | string>, field: Field) => {
        const result = { ...signedFields }

        if (!fieldAffectsData(field) && fieldHasSubFields(field)) {
          field.fields.forEach((subField) => {
            if (fieldAffectsData(subField) && subField.saveToJWT) {
              result[subField.name] = user[subField.name]
            }
          })
        }

        if (fieldAffectsData(field) && field.saveToJWT) {
          result[field.name] = user[field.name]
        }

        return result
      },
      {
        id: user.id,
        collection: collectionConfig.slug,
        email: user.email,
      },
    )

    const accessJWT = await jwtSign({
      fieldsToSign,
      secret: req.payload.secret,
      tokenExpiration: collectionConfig.auth?.tokenExpiration,
    })

    return Response.json({
      access_token: accessJWT,
      refresh_token: token,
      user,
    })
  },
  method: 'post',
  path: `/auth/refresh`,
})
