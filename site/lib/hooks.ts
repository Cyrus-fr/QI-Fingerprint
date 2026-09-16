"use client";

import { useEffect, useRef, useState, type RefObject } from "react";
import { prefersReducedMotion } from "./motion";

/**
 * Fires once when an element first enters the viewport.
 *
 * Deliberately one-shot: a number that re-counts every time it scrolls past is a
 * toy, and it re-animates data the reader may be mid-way through reading.
 */
export function useInView<T extends Element>(
  ref: RefObject<T | null>,
  { rootMargin = "-12% 0px -12% 0px" } = {},
): boolean {
  const [seen, setSeen] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el || seen) return;
    // No IntersectionObserver (or reduced motion) means the resolved state is the
    // only state -- report visible immediately rather than animating nothing.
    if (typeof IntersectionObserver === "undefined") {
      setSeen(true);
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setSeen(true);
          io.disconnect();
        }
      },
      { rootMargin },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [ref, rootMargin, seen]);

  return seen;
}

/**
 * Counts to `value` once the host element is in view.
 *
 * Returns the resolved value immediately under reduced motion or before mount, so
 * the server-rendered figure is never replaced by a zero that then animates -- a
 * data page must not flash a wrong number, even for 600ms.
 */
export function useCountUp(
  value: number,
  ref: RefObject<Element | null>,
  { duration = 900, from = 0 }: { duration?: number; from?: number } = {},
): number {
  const inView = useInView(ref);
  const [display, setDisplay] = useState(value);
  const started = useRef(false);

  useEffect(() => {
    if (!inView || started.current) return;
    if (prefersReducedMotion()) return;
    started.current = true;

    let raf = 0;
    const t0 = performance.now();
    const tick = (now: number) => {
      const p = Math.min(1, (now - t0) / duration);
      // easeOutExpo: fast commit, long settle -- reads as a value arriving rather
      // than a slot machine spinning.
      const eased = p === 1 ? 1 : 1 - Math.pow(2, -10 * p);
      setDisplay(Math.round(from + (value - from) * eased));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    setDisplay(from);
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [inView, value, duration, from]);

  return display;
}

/**
 * Pointer position within an element, in 0..1, for spotlight and tilt effects.
 * Null until the pointer actually enters, so nothing renders a hover state that
 * a touch reader can never dismiss.
 */
export function usePointerWithin<T extends HTMLElement>(ref: RefObject<T | null>) {
  const [pos, setPos] = useState<{ x: number; y: number } | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el || prefersReducedMotion()) return;
    // Coarse pointers have no hover; a sticky spotlight left behind by a tap is
    // worse than no spotlight.
    if (window.matchMedia?.("(hover: none)").matches) return;

    const onMove = (e: PointerEvent) => {
      const r = el.getBoundingClientRect();
      setPos({ x: (e.clientX - r.left) / r.width, y: (e.clientY - r.top) / r.height });
    };
    const onLeave = () => setPos(null);

    el.addEventListener("pointermove", onMove);
    el.addEventListener("pointerleave", onLeave);
    return () => {
      el.removeEventListener("pointermove", onMove);
      el.removeEventListener("pointerleave", onLeave);
    };
  }, [ref]);

  return pos;
}
