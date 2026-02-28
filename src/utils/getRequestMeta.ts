import type { PayloadRequest } from 'payload'

export const getRequestMeta = (req: PayloadRequest) => {
  const userAgent = req.headers.get('user-agent') || undefined

  return { userAgent }
}
