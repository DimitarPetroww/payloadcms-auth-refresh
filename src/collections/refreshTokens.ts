import type { CollectionConfig } from 'payload'

import type { AuthRefreshPluginOptions } from '../index'

type RefreshTokensOptions = Pick<AuthRefreshPluginOptions, 'entity_slug'>

export enum RevocationReason {
  SuspiciousActivity = 'suspicious_activity',
  TokenRotation = 'token_rotation',
  UserLogout = 'user_logout',
}

export const RefreshTokens = (options: RefreshTokensOptions): CollectionConfig => ({
  slug: 'refresh-tokens',
  fields: [
    {
      name: 'entity',
      type: 'relationship',
      relationTo: options.entity_slug,
      required: true,
    },
    {
      name: 'tokenHash',
      type: 'text',
      index: true,
      required: true,
      unique: true,
    },
    {
      name: 'expiresAt',
      type: 'date',
      required: true,
    },
    {
      name: 'lastUsedAt',
      type: 'date',
    },
    {
      name: 'rotatedAt',
      type: 'date',
    },
    {
      name: 'revokedAt',
      type: 'date',
    },
    {
      name: 'deviceId',
      type: 'text',
      required: true,
    },
    {
      name: 'userAgent',
      type: 'text',
    },
    {
      name: 'ipAddress',
      type: 'text',
    },
    {
      name: 'revocationReason',
      type: 'select',
      options: Object.entries(RevocationReason).map(([key, value]) => ({
        label: key,
        value,
      })),
    },
  ],
})
