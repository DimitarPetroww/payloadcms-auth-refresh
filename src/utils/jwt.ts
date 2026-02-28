import type { Secret, SignOptions } from 'jsonwebtoken'
import type { Field } from 'payload'

import crypto from 'crypto'
import jwt from 'jsonwebtoken'
import { fieldAffectsData, fieldHasSubFields } from 'payload/shared'

const derivePayloadJWTSecret = (secret: string) => {
  const hash = crypto.createHash('sha256').update(secret).digest('hex')
  return hash.slice(0, 32)
}

type SignJWTOptions = {
  collectionId: string
  collectionSlug: string
  expiresIn: number | string
  rawSecret: string
}

export const signJWT = ({ collectionId, collectionSlug, expiresIn, rawSecret }: SignJWTOptions) => {
  const signingKey = derivePayloadJWTSecret(rawSecret)

  const token = jwt.sign(
    {
      id: collectionId,
      collection: collectionSlug,
    },
    rawSecret,
    { expiresIn } as SignOptions,
  )

  return token
}
