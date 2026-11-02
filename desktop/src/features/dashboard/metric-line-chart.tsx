"use client";

import { useEffect, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";
import { lineRuns, WINDOW_MS, type LinePoint } from "./system-stats";

export interface ChartSeries {
  label: string;
  /** A CSS color; the same one marks this series wherever it appears. */
  color: string;
  values: readonly (number | null)[];
}

const HEIGHT = 128;
const MARGIN = { top: 8, right: 10, bottom: 20, left: 54 };
const DEFAULT_WIDTH = 360;

function timeText(timeMs: number): string {
  return new Date(timeMs).toLocaleTimeString();
}

function nearestIndex(times: readonly number[], timeMs: number): number {
  let best = 0;
  times.forEach((candidate, i) => {
    if (Math.abs(candidate - timeMs) < Math.abs(times[best] - timeMs)) best = i;
  });
  return best;
}

/**
 * One metric over the last five minutes, on one axis. A crosshair snaps to the nearest
 * sample and reads out every series; the arrow keys do the same from the keyboard. The
 * time, not the position, is what stays selected, because the window keeps moving.
 */
export function MetricLineChart({
  label,
  times,
  series,
  scaleMax,
  formatValue,
  formatTick,
}: {
  /** What the chart shows, for a screen reader. */
  label: string;
  times: readonly number[];
  series: readonly ChartSeries[];
  scaleMax: number;
  formatValue: (value: number) => string;
  formatTick: (value: number) => string;
}) {
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(DEFAULT_WIDTH);
  const [selected, setSelected] = useState<number | null>(null);

  useEffect(() => {
    const element = box.current;
    if (!element || typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(([entry]) => {
      if (entry.contentRect.width > 0) setWidth(entry.contentRect.width);
    });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  const end = times[times.length - 1] ?? 0;
  const start = end - WINDOW_MS;
  const plotWidth = Math.max(width - MARGIN.left - MARGIN.right, 1);
  const plotHeight = HEIGHT - MARGIN.top - MARGIN.bottom;
  const x = (timeMs: number) => MARGIN.left + ((timeMs - start) / WINDOW_MS) * plotWidth;
  const y = (value: number) => MARGIN.top + (1 - Math.min(value, scaleMax) / scaleMax) * plotHeight;
  const baseline = MARGIN.top + plotHeight;
  const ticks = [0, scaleMax / 2, scaleMax];

  const linePath = (run: readonly LinePoint[]) =>
    run.map((point, i) => `${i === 0 ? "M" : "L"}${x(point.timeMs).toFixed(1)},${y(point.value).toFixed(1)}`).join("");
  const areaPath = (run: readonly LinePoint[]) =>
    `${linePath(run)}L${x(run[run.length - 1].timeMs).toFixed(1)},${baseline}L${x(run[0].timeMs).toFixed(1)},${baseline}Z`;

  const selectedIndex = selected === null || times.length === 0 ? null : nearestIndex(times, selected);
  const selectedTime = selectedIndex === null ? null : times[selectedIndex];
  const selectedX = selectedTime === null ? 0 : x(selectedTime);

  const onPointerMove = (event: PointerEvent<HTMLDivElement>) => {
    if (times.length === 0) return;
    const left = event.currentTarget.getBoundingClientRect().left;
    const timeMs = start + ((event.clientX - left - MARGIN.left) / plotWidth) * WINDOW_MS;
    setSelected(times[nearestIndex(times, timeMs)]);
  };
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (times.length === 0) return;
    if (event.key === "Escape") {
      setSelected(null);
      return;
    }
    const step = event.key === "ArrowLeft" ? -1 : event.key === "ArrowRight" ? 1 : 0;
    if (step === 0) return;
    event.preventDefault();
    const from = selected === null ? times.length - 1 : nearestIndex(times, selected);
    setSelected(times[Math.min(Math.max(from + step, 0), times.length - 1)]);
  };

  return (
    <div
      ref={box}
      className="relative outline-none focus-visible:ring-2 focus-visible:ring-ring"
      role="group"
      tabIndex={0}
      aria-label={`${label}. Use the left and right arrow keys to read earlier samples.`}
      onPointerMove={onPointerMove}
      onPointerLeave={() => setSelected(null)}
      onFocus={() => setSelected(times[times.length - 1] ?? null)}
      onBlur={() => setSelected(null)}
      onKeyDown={onKeyDown}>
      <svg width={width} height={HEIGHT} className="block" aria-hidden>
        {ticks.map((tick) => (
          <g key={tick}>
            <line x1={MARGIN.left} x2={width - MARGIN.right} y1={y(tick)} y2={y(tick)} stroke="var(--border)" strokeWidth={1} />
            <text x={MARGIN.left - 6} y={y(tick)} dy="0.32em" textAnchor="end" fill="var(--muted-foreground)" fontSize={11}>
              {formatTick(tick)}
            </text>
          </g>
        ))}
        <text x={MARGIN.left} y={HEIGHT - 5} fill="var(--muted-foreground)" fontSize={11}>
          5 min ago
        </text>
        <text x={width - MARGIN.right} y={HEIGHT - 5} textAnchor="end" fill="var(--muted-foreground)" fontSize={11}>
          now
        </text>
        {series.map((s) => {
          const runs = lineRuns(times, s.values);
          const last = runs[runs.length - 1]?.[runs[runs.length - 1].length - 1];
          return (
            <g key={s.label}>
              {series.length === 1
                ? runs.map((run) => <path key={run[0].timeMs} d={areaPath(run)} fill={s.color} fillOpacity={0.1} />)
                : null}
              {runs.map((run) => (
                <path
                  key={run[0].timeMs}
                  data-testid="chart-line"
                  d={linePath(run)}
                  fill="none"
                  stroke={s.color}
                  strokeWidth={2}
                  strokeLinecap="round"
                  strokeLinejoin="round"
                />
              ))}
              {last && selectedIndex === null ? (
                <circle cx={x(last.timeMs)} cy={y(last.value)} r={4} fill={s.color} stroke="var(--card)" strokeWidth={2} />
              ) : null}
            </g>
          );
        })}
        {selectedIndex !== null ? (
          <g>
            <line x1={selectedX} x2={selectedX} y1={MARGIN.top} y2={baseline} stroke="var(--muted-foreground)" strokeWidth={1} />
            {series.map((s) => {
              const value = s.values[selectedIndex];
              return value === null || value === undefined ? null : (
                <circle key={s.label} cx={selectedX} cy={y(value)} r={4} fill={s.color} stroke="var(--card)" strokeWidth={2} />
              );
            })}
          </g>
        ) : null}
      </svg>
      {selectedIndex !== null && selectedTime !== null ? (
        <div
          role="status"
          className="pointer-events-none absolute top-1 z-10 rounded-md border bg-popover px-2 py-1.5 text-xs whitespace-nowrap text-popover-foreground shadow-sm"
          style={
            selectedX > width / 2
              ? { right: width - selectedX + 8 }
              : { left: selectedX + 8 }
          }>
          <p className="mb-1 text-muted-foreground">{timeText(selectedTime)}</p>
          {series.map((s) => {
            const value = s.values[selectedIndex];
            return (
              <p key={s.label} className="flex items-center gap-1.5">
                <span className="h-0.5 w-3 rounded-full" style={{ backgroundColor: s.color }} aria-hidden />
                <span className="font-semibold tabular-nums">{value === null || value === undefined ? "—" : formatValue(value)}</span>
                <span className="text-muted-foreground">{s.label}</span>
              </p>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}
