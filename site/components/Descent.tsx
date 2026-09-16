"use client";

import { useEffect } from "react";
import Lenis from "lenis";

/**
 * The descent: the page's only motion system.
 *
 * One authored moment, expressed continuously. Readings arrive as the reader
 * passes their depth, and nothing else on the page animates. There is no
 * per-section entrance, because a log does not introduce each interval; it just
 * keeps going down.
 *
 * Everything opts in with `data-reading`. The controller writes `--in` on those
 * elements, and every animated property in globals.css reads from that one
 * variable, so the whole sheet moves on a single clock.
 *
 * RESOLVED BY DEFAULT, and this is the load-bearing part: `--in` initialises to
 * 1, so the server-rendered sheet is already finished. The controller sets it to
 * 0 only for elements it can prove are below the fold, and only once it knows JS
 * is running and motion is wanted. A reader with scripting off or reduced motion
 * on gets every reading immediately -- never a blank column that was waiting for
 * an observer that never fired.
 */
export function Descent() {
  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // --- the live depth value, read by the rail and the title block ---------
    let frame = 0;
    const writeDepth = () => {
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const max = document.body.scrollHeight - window.innerHeight;
        const d = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 0;
        document.documentElement.style.setProperty("--depth", d.toFixed(5));
        document.documentElement.dataset.descended = d > 0.012 ? "true" : "false";
      });
    };
    writeDepth();
    window.addEventListener("scroll", writeDepth, { passive: true });
    window.addEventListener("resize", writeDepth);

    if (reduced) {
      return () => {
        cancelAnimationFrame(frame);
        window.removeEventListener("scroll", writeDepth);
        window.removeEventListener("resize", writeDepth);
      };
    }

    // --- arm the readings --------------------------------------------------
    // Only what is genuinely below the fold is armed. Arming something already on
    // screen would blink it out and back in, which is worse than not animating it.
    const readings = [...document.querySelectorAll<HTMLElement>("[data-reading]")];
    const armed = new Set<HTMLElement>();
    for (const el of readings) {
      if (el.getBoundingClientRect().top > window.innerHeight * 0.92) {
        el.style.setProperty("--in", "0");
        armed.add(el);
      }
    }

    const io = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (!entry.isIntersecting) continue;
          const el = entry.target as HTMLElement;
          // A reading's own stagger, in its own group, so a column of tracks
          // arrives in depth order rather than all at once.
          const delay = Number(el.dataset.reading) || 0;
          window.setTimeout(() => el.style.setProperty("--in", "1"), delay);
          io.unobserve(el);
          armed.delete(el);
        }
      },
      { rootMargin: "0px 0px -14% 0px" },
    );
    armed.forEach((el) => io.observe(el));

    // --- the descent itself ------------------------------------------------
    // Lenis gives the scroll the weight of a drill string rather than a mouse
    // wheel. Touch keeps its native physics; smoothing it fights the platform.
    const lenis = new Lenis({
      duration: 1.1,
      easing: (t: number) => Math.min(1, 1.001 - Math.pow(2, -10 * t)),
      smoothWheel: true,
      syncTouch: false,
    });
    let raf = 0;
    const tick = (time: number) => {
      lenis.raf(time);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    lenis.on("scroll", writeDepth);

    return () => {
      cancelAnimationFrame(frame);
      cancelAnimationFrame(raf);
      io.disconnect();
      lenis.destroy();
      window.removeEventListener("scroll", writeDepth);
      window.removeEventListener("resize", writeDepth);
    };
  }, []);

  return null;
}
