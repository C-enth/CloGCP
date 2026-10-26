// Explicit truncation banner: one line per capped view or analysis budget, with shown/total
// counts from the API (provenance/truncation.py). Renders nothing when no record exists.
type Entry = {
  budget: string;
  scope: string;
  shown: number;
  total: number;
  dropped: number;
  total_basis: string;
  effect: string;
};

export function TruncationBanner({ entries }: { entries?: Entry[] }) {
  if (!entries || !entries.length) return null;
  return (
    <div role="alert" className="truncation-banner">
      <strong>
        Incomplete view: {entries.length} limit
        {entries.length === 1 ? " was" : "s were"} reached. The listed items are
        not a complete assessment.
      </strong>
      <ul>
        {entries.map((e, i) => (
          <li key={i}>
            {e.budget}: {e.shown.toLocaleString()} of {e.total.toLocaleString()}{" "}
            shown
            {e.total_basis !== "exact" ? ` (${e.total_basis})` : ""} for{" "}
            {e.scope}; {e.effect}.
          </li>
        ))}
      </ul>
    </div>
  );
}
