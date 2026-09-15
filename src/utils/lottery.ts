/**
 * Returns true with probability `wins / total`.
 *
 * Used to run occasional maintenance inline on a request rather than on a
 * schedule, so the plugin needs no cron or job runner to keep itself tidy.
 */
export function lottery(wins: number, total: number, rng: () => number = Math.random): boolean {
  if (!Number.isInteger(wins) || !Number.isInteger(total)) {
    throw new TypeError('wins and total must be integers')
  }

  if (wins < 0 || total <= 0 || wins > total) {
    throw new Error('invalid lottery configuration')
  }

  return Math.floor(rng() * total) < wins
}
