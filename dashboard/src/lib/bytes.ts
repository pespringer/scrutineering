const UNITS = ["B", "KB", "MB", "GB", "TB"];

/** A size as registries and Docker show it, in powers of 1000: `53.3 MB`. */
export function formatBytes(bytes: number): string {
  let value = bytes;
  let unit = 0;
  while (value >= 999.95 && unit < UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return unit === 0 ? `${value} B` : `${value.toFixed(1)} ${UNITS[unit]}`;
}
