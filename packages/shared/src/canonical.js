/**
 * Deterministic JSON encoding used for Ed25519 signatures.
 * Object keys are sorted; unsupported values are rejected instead of silently
 * producing ambiguous serializations.
 */
export function canonicalize(value) {
  if (value === null) return 'null';
  const type = typeof value;
  if (type === 'string' || type === 'boolean') return JSON.stringify(value);
  if (type === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('Non-finite number in canonical JSON');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalize(item)).join(',')}]`;
  }
  if (type === 'object') {
    const keys = Object.keys(value).sort();
    const parts = [];
    for (const key of keys) {
      const item = value[key];
      if (item === undefined) throw new TypeError(`Undefined value for key ${key}`);
      parts.push(`${JSON.stringify(key)}:${canonicalize(item)}`);
    }
    return `{${parts.join(',')}}`;
  }
  throw new TypeError(`Unsupported value type in canonical JSON: ${type}`);
}
