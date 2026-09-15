import type { CollectionSlug, PayloadRequest, Where } from 'payload'

import { lottery } from './lottery'

export type GarbageCollectionOptions = {
  /**
   * Rows deleted per sweep. Bounded so a large backlog drains over several
   * runs rather than blocking one request with a huge delete.
   *
   * @default 1000
   */
  batchSize?: number
  /** @default true */
  enabled?: boolean
  /**
   * Odds of sweeping on any given call, as [wins, total].
   *
   * @default [1, 20]
   */
  lottery?: [number, number]
}

/**
 * Occasionally deletes rows matching `where`.
 *
 * Refresh tokens accumulate without bound — every login creates a row and
 * every refresh creates another while revoking the old one — so they need
 * sweeping. Running inline on a lottery keeps the plugin self-contained: no
 * cron, no job runner required from the host app.
 *
 * Safe to call as `void garbageCollect(...)`: it resolves rather than rejects,
 * so a failed sweep can never surface as an unhandled rejection or fail the
 * request that triggered it.
 */
export const garbageCollect = async (
  req: PayloadRequest,
  collection: CollectionSlug,
  where: Where,
  options: GarbageCollectionOptions = {},
): Promise<void> => {
  const { batchSize = 1000, enabled = true, lottery: odds = [1, 20] } = options

  if (!enabled || !lottery(odds[0], odds[1])) {
    return
  }

  const { payload } = req

  try {
    // Select first, then delete by id: `limit` bounds the work, which a bare
    // `delete({ where })` would not.
    const { docs } = await payload.find({
      collection,
      depth: 0,
      limit: batchSize,
      pagination: false,
      select: {},
      where,
    })

    if (!docs.length) {
      return
    }

    await payload.delete({
      collection,
      where: { id: { in: docs.map((doc) => doc.id) } },
    })

    payload.logger.info(`[refresh-auth] garbage collected ${docs.length} row(s) from ${collection}`)
  } catch (error) {
    // Housekeeping must never fail the request that triggered it.
    payload.logger.error({
      err: error,
      msg: `[refresh-auth] garbage collection failed for ${collection}`,
    })
  }
}
