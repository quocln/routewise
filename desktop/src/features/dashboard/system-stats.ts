import { useEffect } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { systemStatsHistory, type SystemStatsSample } from "@/lib/native/native-commands";
import { listenSystemStats } from "@/lib/native/shell-feeds";

/** How often the shell reads the figures. */
export const SAMPLE_MS = 2_000;
/** How many samples make up the window, which is what the shell keeps. */
const WINDOW_SAMPLES = 150;
/** The shell pushes each sample, so this only catches what a lost event would leave out. */
const RESYNC_MS = 30_000;
/** The span the charts draw, which is what the shell keeps. */
export const WINDOW_MS = 5 * 60_000;
/** A longer pause between samples means the Mac slept, so the line breaks there. */
const GAP_MS = 3 * SAMPLE_MS;
/** A network chart never scales below this, or idle noise would fill the plot. */
const MIN_RATE_SCALE = 1_000;

const STATS_KEY = ["system.stats"] as const;

/** Adds a sample to the window. One the window already has changes nothing. */
export function withSample(samples: readonly SystemStatsSample[] | undefined, sample: SystemStatsSample): SystemStatsSample[] {
  const current = samples ?? [];
  const last = current[current.length - 1];
  if (last && sample.timeMs <= last.timeMs) return current as SystemStatsSample[];
  return [...current.slice(-(WINDOW_SAMPLES - 1)), sample];
}

/** The shell's recent samples, oldest first, kept current while the tab is open. */
export function useSystemStats() {
  const queryClient = useQueryClient();
  useEffect(() => {
    let stopped = false;
    let unlisten: (() => void) | undefined;
    void listenSystemStats((sample) => {
      queryClient.setQueryData<SystemStatsSample[]>(STATS_KEY, (samples) => withSample(samples, sample));
    }).then((stop) => {
      if (stopped) stop();
      else unlisten = stop;
    });
    return () => {
      stopped = true;
      unlisten?.();
    };
  }, [queryClient]);
  return useQuery<SystemStatsSample[], Error>({
    queryKey: STATS_KEY,
    queryFn: systemStatsHistory,
    refetchInterval: RESYNC_MS,
    refetchIntervalInBackground: false,
  });
}

function scaled(value: number, base: number, units: readonly string[]): string {
  let amount = value;
  let unit = 0;
  while (amount >= base && unit < units.length - 1) {
    amount /= base;
    unit += 1;
  }
  const digits = unit === 0 || amount >= 100 ? 0 : 1;
  return `${amount.toFixed(digits)} ${units[unit]}`;
}

/** A rate in powers of 1000, as the tray menu spells it. */
export function formatRate(bytesPerSecond: number): string {
  return scaled(bytesPerSecond, 1000, ["B/s", "KB/s", "MB/s", "GB/s"]);
}

/** Memory in powers of 1024, which is how macOS and every RAM label count it. */
export function formatMemory(bytes: number): string {
  return scaled(bytes, 1024, ["B", "KB", "MB", "GB", "TB"]);
}

/** Disk space in powers of 1000, which is how Finder and every drive label count it. */
export function formatDisk(bytes: number): string {
  return scaled(bytes, 1000, ["B", "KB", "MB", "GB", "TB"]);
}

export function formatPercent(value: number): string {
  return `${Math.round(value)}%`;
}

/** The smallest of 1, 2 or 5 times a power of ten that holds `max`, so axis ticks read clean. */
export function niceRateScale(max: number): number {
  const target = Math.max(max, MIN_RATE_SCALE);
  const power = 10 ** Math.floor(Math.log10(target));
  const step = [1, 2, 5, 10].find((multiple) => multiple * power >= target) ?? 10;
  return step * power;
}

export interface LinePoint {
  timeMs: number;
  value: number;
}

/**
 * Splits a series into the runs a line may join: an unread value or a pause longer
 * than a few samples ends a run, because drawing across it would invent readings.
 */
export function lineRuns(times: readonly number[], values: readonly (number | null)[]): LinePoint[][] {
  const runs: LinePoint[][] = [];
  let run: LinePoint[] = [];
  times.forEach((timeMs, i) => {
    const value = values[i];
    if (value === null || value === undefined) {
      if (run.length > 0) runs.push(run);
      run = [];
      return;
    }
    const last = run[run.length - 1];
    if (last && timeMs - last.timeMs > GAP_MS) {
      runs.push(run);
      run = [];
    }
    run.push({ timeMs, value });
  });
  if (run.length > 0) runs.push(run);
  return runs;
}

export type DiskLevel = "ok" | "warning" | "critical";

/** How worrying a disk this full is. */
export function diskLevel(percent: number): DiskLevel {
  if (percent >= 95) return "critical";
  if (percent >= 85) return "warning";
  return "ok";
}
