/**
 * Format a number into a compact human-readable string.
 * Examples: 1000 → "1K", 1500 → "1.5K", 1000000 → "1M"
 * Non-finite values are returned as-is.
 */
export function formatNumber(n) {
  if (!Number.isFinite(n)) return n
  if (n >= 1_000_000_000) {
    return (n / 1_000_000_000).toFixed(1).replace(/\.0$/, '') + 'B'
  }
  if (n >= 1_000_000) {
    return (n / 1_000_000).toFixed(1).replace(/\.0$/, '') + 'M'
  }
  if (n >= 1_000) {
    return (n / 1_000).toFixed(1).replace(/\.0$/, '') + 'K'
  }
  return String(n)
}
