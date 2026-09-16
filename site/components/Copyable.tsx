"use client";

import { useEffect, useRef, useState } from "react";

/**
 * A repro command you can take with you.
 *
 * Every claim on this page carries the command that reproduces it, which is only
 * true in practice if the command is easy to get into a terminal. The button is
 * revealed on hover and focus rather than sitting there permanently, so the
 * command itself stays the thing you look at.
 *
 * The label changes to what happened -- "Copied" -- because a button that says
 * "Copy" after copying leaves you guessing whether it worked.
 */
export function CopyButton({
  value,
  label = "command",
  onStock = false,
}: {
  value: string;
  label?: string;
  onStock?: boolean;
}) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      // Clipboard is permission-gated and unavailable over plain http on some
      // browsers. Say so rather than silently doing nothing; the line is
      // select-all either way.
      setState("failed");
    }
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setState("idle"), 1800);
  };

  const resting = onStock
    ? "border-stock-rule text-stock-ink/50 hover:border-field-deep hover:text-field-deep"
    : "border-rule-strong text-ink-3 hover:border-field hover:text-field";
  const done = onStock ? "border-field-deep text-field-deep" : "border-field text-field";

  return (
    <button
      type="button"
      onClick={copy}
      aria-label={`Copy ${label} to clipboard`}
      className={`reading shrink-0 border px-2 py-1 text-[0.68rem] transition-all duration-200 ${
        state === "idle"
          ? `${resting} opacity-0 group-hover:opacity-100 focus-visible:opacity-100`
          : `${done} opacity-100`
      }`}
    >
      {state === "copied" ? "copied" : state === "failed" ? "select it" : "copy"}
    </button>
  );
}
