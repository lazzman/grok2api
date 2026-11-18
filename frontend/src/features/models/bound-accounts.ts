export function applyBoundAccountSelection(current: readonly string[], ids: readonly string[], checked: boolean): string[] {
  if (checked) return [...new Set([...current, ...ids])];
  const targets = new Set(ids);
  return current.filter((value) => !targets.has(value));
}
