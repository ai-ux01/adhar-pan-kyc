/**
 * Match an uploaded sheet's first-row header key to one of the allowed aliases
 * (handling leading BOM characters like \ufeff, whitespace, and case-insensitivity).
 */
function resolveUploadedColumnKey(firstRow, possibleNames) {
  if (!firstRow || typeof firstRow !== 'object') return null;

  // Map keys to original and cleaned representations
  const cleanKeys = Object.keys(firstRow).map((k) => ({
    original: k,
    cleaned: k.replace(/^\uFEFF/, '').trim()
  }));

  for (const possibleName of possibleNames) {
    const target = String(possibleName).toLowerCase().trim();
    const match = cleanKeys.find((ck) => ck.cleaned.toLowerCase() === target);
    if (match) {
      return match.original;
    }
  }

  return null;
}

module.exports = { resolveUploadedColumnKey };
