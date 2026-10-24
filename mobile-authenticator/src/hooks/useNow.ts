import { useEffect, useState } from "react";

/**
 * Current time in ms, refreshed every `intervalMs`.
 *
 * Codes are always recomputed from the wall clock rather than from a 30 s
 * timer, so they stay correct after the app is backgrounded or the JS thread
 * stalls, and they roll over within `intervalMs` of the real boundary.
 */
export function useNow(intervalMs = 250): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}
