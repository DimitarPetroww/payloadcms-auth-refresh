import crypto from 'crypto'

export const createRefreshToken = (pepper: string) => {
  const token = crypto.randomBytes(32).toString('base64url')
  const tokenHash = hashToken(token, pepper)

  return { token, tokenHash }
}

export const hashToken = (token: string, pepper: string) => {
  return crypto.createHmac('sha256', pepper).update(token).digest('base64')
}
