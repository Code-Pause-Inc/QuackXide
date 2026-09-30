type ChipTone = "active" | "pending" | "declined" | "own";

const CHIP_TONES: Record<ChipTone, string> = {
  active: "bg-teal-50 text-teal-700 ring-teal-200",
  pending: "bg-amber-50 text-amber-700 ring-amber-200",
  declined: "bg-rose-50 text-rose-600 ring-rose-200",
  own: "bg-slate-50 text-slate-500 ring-slate-200",
};

export function StatusChip({ tone, label }: { tone: ChipTone; label: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-[11px] font-medium uppercase tracking-wide ring-1 ${CHIP_TONES[tone]}`}
    >
      {label}
    </span>
  );
}

export function SectionLabel({ children }: { children: string }) {
  return (
    <h2 className="text-[11px] font-semibold uppercase tracking-[0.18em] text-teal-700">
      {children}
    </h2>
  );
}

/** Remaining-allowance bar. */
export function Meter({ spent, limit }: { spent: number; limit: number }) {
  const usedPct = limit > 0 ? Math.min(100, Math.round((spent / limit) * 100)) : 100;
  return (
    <div className="h-1 overflow-hidden rounded-full bg-slate-100">
      <div className="h-full rounded-full bg-teal-600" style={{ width: `${100 - usedPct}%` }} />
    </div>
  );
}
