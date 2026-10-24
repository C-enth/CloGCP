import { useEffect, useState } from "react";
import { api, type Row } from "./api";

export function useRecordChoices(
  run: string,
  kind: string,
  provider: string,
  epoch = 0,
) {
  const [data, setData] = useState<Row>();
  useEffect(() => {
    let live = true;
    setData(undefined);
    api(
      `/runs/${run}/record-facets/${kind}?provider=${provider === "Consolidated" ? "" : provider}`,
    )
      .then((d) => {
        if (live) setData(d);
      })
      .catch((e) => {
        if (live) setData({ choices: {}, error: e.message });
      });
    return () => {
      live = false;
    };
  }, [run, kind, provider, epoch]);
  return data;
}

export function ChoiceFilter({
  label,
  value,
  options,
  onChange,
  all = "All",
  disabled = false,
}: {
  label: string;
  value: string;
  options?: string[];
  onChange: (v: string) => void;
  all?: string;
  disabled?: boolean;
}) {
  const choices = [
    ...new Set([...(options || []), ...(value ? [value] : [])]),
  ].sort();
  return (
    <select
      aria-label={label}
      value={value}
      disabled={disabled}
      onChange={(e) => onChange(e.target.value)}
    >
      <option value="">{all}</option>
      {choices.map((v) => (
        <option key={v} value={v}>
          {v.length > 110 ? v.slice(0, 107) + "…" : v}
        </option>
      ))}
    </select>
  );
}

export function ChoiceNotice({ data }: { data?: Row }) {
  if (data?.error)
    return <p role="alert">Filter choices unavailable: {data.error}</p>;
  if (data?.truncated || data?.truncated_fields?.length)
    return (
      <p role="note">
        Choice list is bounded. Narrow the cloud or record scope to see
        additional values. Values longer than 200 characters are omitted.
      </p>
    );
  return null;
}
