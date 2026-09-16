"use client";

import { useCallback, useEffect, useRef, useState } from "react";

/**
 * The depth rail: the page's only navigation.
 *
 * You move by descending the section. There is no menu, no tab bar and no second
 * way through, because a log has one axis and pretending otherwise would be a
 * web habit imposed on the form. The rail is a scale, not a progress bar: its
 * ticks are the logged intervals, spaced by their true extent, and clicking one
 * is how you jump.
 *
 * It stays out of the collar. At the top of the hole there is no depth to report,
 * and the ticks would sit on top of the section drawing.
 */

interface Tick {
  id: string;
  label: string;
  top: number;
  height: number;
}

export function DepthRail() {
  const [ticks, setTicks] = useState<Tick[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [descended, setDescended] = useState(false);
  const [pct, setPct] = useState(0);
  const frame = useRef(0);
  const known = useRef<Tick[]>([]);

  const measure = useCallback(() => {
    const doc = document.body.scrollHeight;
    const found = [...document.querySelectorAll<HTMLElement>("section[data-interval]")].map(
      (el) => {
        const r = el.getBoundingClientRect();
        return {
          id: el.id,
          label: el.dataset.interval ?? el.id,
          top: (r.top + window.scrollY) / doc,
          height: r.height / doc,
        };
      },
    );
    known.current = found;
    setTicks((prev) =>
      prev.length === found.length && prev.every((p, i) => p.id === found[i].id) ? prev : found,
    );
  }, []);

  useEffect(() => {
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(document.body);

    const onScroll = () => {
      cancelAnimationFrame(frame.current);
      frame.current = requestAnimationFrame(() => {
        const max = document.body.scrollHeight - window.innerHeight;
        const d = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 0;
        setPct(d);
        setDescended(window.scrollY > window.innerHeight * 0.65);
        const probe = window.scrollY + window.innerHeight * 0.3;
        const doc = document.body.scrollHeight;
        let current: string | null = null;
        for (const t of known.current) if (probe / doc >= t.top) current = t.id;
        setActive(current);
      });
    };
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      cancelAnimationFrame(frame.current);
      ro.disconnect();
      window.removeEventListener("scroll", onScroll);
    };
  }, [measure]);

  if (ticks.length === 0) return null;

  return (
    <nav
      aria-label="Log intervals"
      aria-hidden={descended ? undefined : true}
      className={`pointer-events-none fixed top-0 left-0 z-30 hidden h-full w-32 transition-opacity duration-500 lg:block ${
        descended ? "opacity-100" : "opacity-0"
      }`}
    >
      {/* the scale itself */}
      <div className="absolute top-0 left-[3.25rem] h-full w-px bg-rule" aria-hidden="true" />
      {/* how far down the hole the reader is */}
      <div
        aria-hidden="true"
        className="absolute top-0 left-[3.25rem] w-px origin-top bg-field"
        style={{ height: "100%", transform: `scaleY(${pct})` }}
      />

      <ul className="relative h-full">
        {ticks.map((t) => {
          const on = active === t.id;
          return (
            <li
              key={t.id}
              className="pointer-events-auto absolute left-0 w-32"
              style={{ top: `${t.top * 100}%` }}
            >
              <a
                href={`#${t.id}`}
                aria-current={on ? "true" : undefined}
                tabIndex={descended ? undefined : -1}
                className="group flex items-center gap-2"
              >
                <span
                  aria-hidden="true"
                  className={`block h-px transition-all duration-300 ${
                    on
                      ? "ml-[2.25rem] w-6 bg-field"
                      : "ml-[3rem] w-2 bg-rule-strong group-hover:ml-[2.5rem] group-hover:w-4 group-hover:bg-ink-3"
                  }`}
                />
                <span
                  className={`reading text-[0.62rem] whitespace-nowrap transition-colors duration-300 ${
                    on ? "text-field" : "text-ink-3 opacity-0 group-hover:opacity-100"
                  }`}
                >
                  {t.label}
                </span>
              </a>
            </li>
          );
        })}
      </ul>

      <div
        aria-hidden="true"
        className="reading absolute bottom-5 left-3 text-[0.62rem] text-ink-3"
      >
        {String(Math.round(pct * 100)).padStart(2, "0")}
      </div>
    </nav>
  );
}
