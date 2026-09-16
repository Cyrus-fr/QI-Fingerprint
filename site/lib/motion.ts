/**
 * Motion policy.
 *
 * `prefers-reduced-motion: reduce` is treated as a hard switch, not a dial: no
 * Lenis, no ScrollTrigger, no reveals. Every animated component's *resolved* state
 * is what the server already rendered, so honouring the preference means doing
 * nothing rather than substituting a lesser animation.
 */

export function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/** Maps a value from one range to another, clamped to [0, 1] of the output. */
export function progressBetween(p: number, start: number, end: number): number {
  if (end <= start) return p >= end ? 1 : 0;
  return Math.min(1, Math.max(0, (p - start) / (end - start)));
}
