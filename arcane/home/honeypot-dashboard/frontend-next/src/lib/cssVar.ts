// Reads a CSS custom property off the document root, falling back when
// unset or during SSR (no document).
export function cssVar(name: string, fallback = ''): string {
  if (typeof document === 'undefined') return fallback
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback
}
