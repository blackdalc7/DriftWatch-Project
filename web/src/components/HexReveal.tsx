// Text that arrives as hex noise and resolves left to right: used when an evidence bundle loads.
// Uses the shared scramble frame generator; honours reduced motion.
import { HEX, rng, scrambleFrame } from "@portfolio/aegis-ui";
import { useReducedMotion } from "motion/react";
import { useEffect, useState } from "react";

export function HexReveal({ text, duration = 900, delay = 0, className }: { text: string; duration?: number; delay?: number; className?: string }) {
  const reduced = useReducedMotion();
  const [shown, setShown] = useState(reduced ? text : scrambleFrame(text, 0, rng(7), HEX));
  useEffect(() => {
    if (reduced) { setShown(text); return; }
    const rand = rng(text.length * 31 + 7);
    let raf = 0;
    const t0 = performance.now() + delay;
    const tick = (now: number) => {
      const p = Math.min(1, Math.max(0, (now - t0) / duration));
      setShown(scrambleFrame(text, p, rand, HEX));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [text, duration, delay, reduced]);
  return <span className={className} aria-label={text}><span aria-hidden="true">{shown}</span></span>;
}
