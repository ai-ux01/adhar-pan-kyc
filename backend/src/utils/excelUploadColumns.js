/**
 * Match an uploaded sheet's first-row header key to one of the allowed aliases
 * (exact key first, then case-insensitive).
 */
function resolveUploadedColumnKey(firstRow, possibleNames) {
  if (!firstRow || typeof firstRow !== 'object') return null;
  for (const possibleName of possibleNames) {
    if (Object.prototype.hasOwnProperty.call(firstRow, possibleName)) {
      return possibleName;
    }
  }
  const keys = Object.keys(firstRow);
  const lowerToActual = new Map(keys.map((k) => [k.toLowerCase(), k]));
  for (const possibleName of possibleNames) {
    const hit = lowerToActual.get(String(possibleName).toLowerCase());
    if (hit) return hit;
  }
  return null;
}

module.exports = { resolveUploadedColumnKey };
