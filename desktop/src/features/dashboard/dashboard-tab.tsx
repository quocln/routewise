"use client";

import { useState, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { SystemStatsSample } from "@/lib/native/native-commands";
import { MetricLineChart } from "./metric-line-chart";
import {
  diskLevel,
  formatDisk,
  formatMemory,
  formatPercent,
  formatRate,
  niceRateScale,
  useSystemStats,
  type DiskLevel,
} from "./system-stats";

const UNKNOWN = "—";
const TABLE_ROWS = 30;
const SERIES_1 = "var(--viz-series-1)";
const SERIES_2 = "var(--viz-series-2)";

function Tile({ title, value, detail, children }: { title: string; value: ReactNode; detail?: ReactNode; children: ReactNode }) {
  return (
    <section className="grid min-w-0 grid-cols-[minmax(0,1fr)] content-start gap-2 rounded-lg border bg-card p-3 text-card-foreground" aria-label={title}>
      <div className="flex flex-wrap items-baseline justify-between gap-x-3">
        <h2 className="text-sm text-muted-foreground">{title}</h2>
        {detail ? <p className="text-xs text-muted-foreground tabular-nums">{detail}</p> : null}
      </div>
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
      {children}
    </section>
  );
}

function percentTicks(value: number): string {
  return formatPercent(value);
}

function usedOfTotal(used: number | null | undefined, total: number | null | undefined, format: (bytes: number) => string) {
  return used === null || used === undefined || !total ? null : `${format(used)} of ${format(total)}`;
}

const DISK_NOTE: Record<DiskLevel, { text: string; color: string } | null> = {
  ok: null,
  warning: { text: "Getting full", color: "var(--viz-warning)" },
  critical: { text: "Almost full", color: "var(--viz-critical)" },
};

function DiskMeter({ latest }: { latest: SystemStatsSample | undefined }) {
  const percent = latest?.diskPercent;
  if (percent === null || percent === undefined) return <p className="text-xs text-muted-foreground">Could not read the system disk.</p>;
  const note = DISK_NOTE[diskLevel(percent)];
  const fill = note?.color ?? SERIES_1;
  const free =
    latest?.diskUsedBytes != null && latest.diskTotalBytes != null ? formatDisk(latest.diskTotalBytes - latest.diskUsedBytes) : null;
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-2 self-start">
      <div
        role="meter"
        aria-label="Disk used"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent}
        className="h-2 overflow-hidden rounded-full"
        style={{ backgroundColor: `color-mix(in oklab, ${fill} 18%, var(--card))` }}>
        <div className="h-full rounded-full" style={{ width: `${percent}%`, backgroundColor: fill }} />
      </div>
      <div className="flex flex-wrap items-center justify-between gap-x-3 text-xs text-muted-foreground">
        {free ? <span className="tabular-nums">{free} free</span> : <span />}
        {note ? (
          <span className="flex items-center gap-1 text-foreground">
            <AlertTriangle className="size-3.5" style={{ color: note.color }} aria-hidden />
            {note.text}
          </span>
        ) : null}
      </div>
    </div>
  );
}

function RateKey({ color, label, value }: { color: string; label: string; value: string }) {
  return (
    <span className="flex items-center gap-1.5">
      <span className="h-0.5 w-3 rounded-full" style={{ backgroundColor: color }} aria-hidden />
      <span>{value}</span>
      <span className="text-xs font-normal text-muted-foreground">{label}</span>
    </span>
  );
}

function RecentTable({ samples }: { samples: readonly SystemStatsSample[] }) {
  const percent = (value: number | null | undefined) => (value === null || value === undefined ? UNKNOWN : formatPercent(value));
  return (
    <div className="overflow-x-auto rounded-lg border">
      <table className="w-full text-xs tabular-nums">
        <caption className="sr-only">The latest samples, newest first</caption>
        <thead className="text-left text-muted-foreground">
          <tr className="border-b">
            {["Time", "CPU", "Memory", "Disk", "Download", "Upload"].map((heading) => (
              <th key={heading} scope="col" className="px-3 py-2 font-medium">
                {heading}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {samples
            .slice(-TABLE_ROWS)
            .reverse()
            .map((sample) => (
              <tr key={sample.timeMs} className="border-b last:border-0">
                <td className="px-3 py-1.5">{new Date(sample.timeMs).toLocaleTimeString()}</td>
                <td className="px-3 py-1.5">{percent(sample.cpuPercent)}</td>
                <td className="px-3 py-1.5">{percent(sample.memoryPercent)}</td>
                <td className="px-3 py-1.5">{percent(sample.diskPercent)}</td>
                <td className="px-3 py-1.5">{sample.network ? formatRate(sample.network.down) : UNKNOWN}</td>
                <td className="px-3 py-1.5">{sample.network ? formatRate(sample.network.up) : UNKNOWN}</td>
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}

/** This computer's CPU, memory, disk and network. It needs neither the helper nor a VPN. */
export function DashboardTab() {
  const { data, error, isPending } = useSystemStats();
  const [showTable, setShowTable] = useState(false);
  const samples = data ?? [];
  const latest = samples[samples.length - 1];
  const times = samples.map((s) => s.timeMs);
  const downloads = samples.map((s) => s.network?.down ?? null);
  const uploads = samples.map((s) => s.network?.up ?? null);
  const rateScale = niceRateScale(Math.max(0, ...downloads.map((v) => v ?? 0), ...uploads.map((v) => v ?? 0)));
  const percentOf = (value: number | null | undefined) => (value === null || value === undefined ? UNKNOWN : formatPercent(value));

  return (
    <div className="h-full overflow-y-auto" data-testid="dashboard-tab">
      <div className="mx-auto grid max-w-5xl grid-cols-[minmax(0,1fr)] gap-3 p-4">
        <div className="flex items-center justify-between gap-3">
          <p className="text-xs text-muted-foreground">This computer, last 5 minutes. Updates every 2 seconds.</p>
          <Button variant="outline" size="sm" aria-pressed={showTable} onClick={() => setShowTable((shown) => !shown)}>
            {showTable ? "Show charts" : "Show table"}
          </Button>
        </div>
        {error ? (
          <p role="alert" className="text-xs text-destructive">
            Could not read the system figures: {error.message}
          </p>
        ) : null}
        {isPending ? <p className="text-xs text-muted-foreground">Reading the system figures…</p> : null}
        {showTable ? (
          <RecentTable samples={samples} />
        ) : (
          <div className="grid grid-cols-[minmax(0,1fr)] gap-3 md:grid-cols-2">
            <Tile title="CPU" value={percentOf(latest?.cpuPercent)}>
              <MetricLineChart
                label={`CPU use, now ${percentOf(latest?.cpuPercent)}`}
                times={times}
                series={[{ label: "CPU", color: SERIES_1, values: samples.map((s) => s.cpuPercent ?? null) }]}
                scaleMax={100}
                formatValue={formatPercent}
                formatTick={percentTicks}
              />
            </Tile>
            <Tile
              title="Memory"
              value={percentOf(latest?.memoryPercent)}
              detail={usedOfTotal(latest?.memoryUsedBytes, latest?.memoryTotalBytes, formatMemory)}>
              <MetricLineChart
                label={`Memory use, now ${percentOf(latest?.memoryPercent)}`}
                times={times}
                series={[{ label: "Memory", color: SERIES_1, values: samples.map((s) => s.memoryPercent ?? null) }]}
                scaleMax={100}
                formatValue={formatPercent}
                formatTick={percentTicks}
              />
            </Tile>
            <Tile title="Disk" value={percentOf(latest?.diskPercent)} detail={usedOfTotal(latest?.diskUsedBytes, latest?.diskTotalBytes, formatDisk)}>
              <DiskMeter latest={latest} />
            </Tile>
            <Tile
              title="Network"
              value={
                <span className="flex flex-wrap gap-x-4 text-lg">
                  <RateKey color={SERIES_1} label="Download" value={latest?.network ? formatRate(latest.network.down) : UNKNOWN} />
                  <RateKey color={SERIES_2} label="Upload" value={latest?.network ? formatRate(latest.network.up) : UNKNOWN} />
                </span>
              }>
              <MetricLineChart
                label={`Network traffic, now ${latest?.network ? `${formatRate(latest.network.down)} down, ${formatRate(latest.network.up)} up` : "unknown"}`}
                times={times}
                series={[
                  { label: "Download", color: SERIES_1, values: downloads },
                  { label: "Upload", color: SERIES_2, values: uploads },
                ]}
                scaleMax={rateScale}
                formatValue={formatRate}
                formatTick={formatRate}
              />
            </Tile>
          </div>
        )}
      </div>
    </div>
  );
}
